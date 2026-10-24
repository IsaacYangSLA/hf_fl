package provision

import (
	"context"
	"net/url"
	"path/filepath"
	"strings"

	buildworker "github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/build"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/resources"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func (p *Provisioner) builtArtifacts(ctx context.Context, jid string, spec domain.JobSpec) (map[string]any, error) {
	rows, e := p.Ledger.Resources(ctx, jid, resources.ResourceFilter{Kind: "build_products"})
	if e != nil {
		return nil, e
	}
	live := []map[string]any{}
	for _, row := range rows {
		if row["state"] != "deleted" {
			live = append(live, row)
		}
	}
	if len(live) == 0 {
		return map[string]any{}, nil
	}
	if len(live) != 1 {
		return nil, refused("multiple_build_product_directories")
	}
	row := live[0]
	path := filepath.Join(p.Root, jid, "build-products")
	d := details(row)
	if row["external_id"] != path || ownership(row)["job_id"] != jid || d["spec_digest"] != mustDigest(spec) {
		return nil, refused("foreign_build_products")
	}
	if !exists(path) {
		return map[string]any{}, nil
	}
	manifest := obj(d["artifacts"])
	if len(manifest) == 0 || len(manifest) > 1024 {
		return nil, refused("missing_build_manifest")
	}
	parsed, e := buildworker.ParseManifest(manifest, buildworker.MaxBuildBytes)
	if e != nil {
		return nil, e
	}
	if e = buildworker.VerifyProducts(path, parsed); e != nil {
		return nil, e
	}
	return buildworker.ProductManifestMap(parsed), nil
}
func (p *Provisioner) BuildManifest(ctx context.Context, job map[string]any) (map[string]any, error) {
	spec, e := JobSpec(job)
	if e != nil {
		return nil, e
	}
	manifest, e := p.builtArtifacts(ctx, idOf(job), spec)
	if e != nil {
		return nil, e
	}
	for _, c := range spec.Components {
		if c.Role == "build" && len(manifest) == 0 {
			return nil, refused("build_products_not_ready")
		}
	}
	return manifest, nil
}
func (p *Provisioner) PreparedComponent(ctx context.Context, job, attempt map[string]any, cid string) (map[string]any, error) {
	jid, aid, spec, e := identity(job, attempt)
	if e != nil {
		return nil, e
	}
	var component *domain.ComponentSpec
	for i := range spec.Components {
		if spec.Components[i].ComponentID == cid {
			component = &spec.Components[i]
		}
	}
	if component == nil {
		return nil, refused("unknown_component")
	}
	parent := filepath.Join(p.Root, jid, "attempts", aid, cid)
	bytes, e := safeRead(parent, "runtime.json", 2*1024*1024)
	if e != nil {
		return nil, e
	}
	doc, e := decodeMap(bytes)
	if e != nil {
		return nil, e
	}
	epoch, e := strictInteger(doc["epoch"])
	if e != nil || doc["job_id"] != jid || doc["attempt_id"] != aid || doc["component_id"] != cid || epoch != num(attempt["epoch"]) || doc["spec_digest"] != mustDigest(spec) || !same(doc["spec"], spec.Map()) {
		return nil, refused("foreign_runtime_payload")
	}
	if component.Role == "build" {
		cfg, e := buildworker.DecodeConfig(bytes)
		if e != nil {
			return nil, e
		}
		return cfg.Map(), nil
	}
	return NormalizeRuntimeConfig(doc)
}
func (p *Provisioner) ReadBuildProduct(ctx context.Context, job map[string]any, filename string, maxBytes int64) ([]byte, error) {
	if !wheelPattern.MatchString(filename) || maxBytes <= 0 || maxBytes > buildworker.MaxBuildBytes {
		return nil, refused("invalid_build_product_request")
	}
	manifest, e := p.BuildManifest(ctx, job)
	if e != nil {
		return nil, e
	}
	expected := obj(manifest[filename])
	size, e := strictInteger(expected["size_bytes"])
	if e != nil || size > maxBytes {
		return nil, refused("build_product_not_owned")
	}
	bytes, e := safeRead(filepath.Join(p.Root, idOf(job), "build-products"), filename, maxBytes)
	if e != nil {
		return nil, e
	}
	if int64(len(bytes)) != size || checksum(bytes) != str(expected["sha256"]) {
		return nil, refused("build_product_changed")
	}
	return bytes, nil
}
func (p *Provisioner) PreparedBuildProducts(ctx context.Context, job, attempt map[string]any, cid string) (map[string][]byte, error) {
	jid, _, spec, e := identity(job, attempt)
	if e != nil {
		return nil, e
	}
	var component *domain.ComponentSpec
	for i := range spec.Components {
		if spec.Components[i].ComponentID == cid {
			component = &spec.Components[i]
		}
	}
	if component == nil {
		return nil, refused("unknown_component")
	}
	configuration, e := p.PreparedComponent(ctx, job, attempt, cid)
	if e != nil {
		return nil, e
	}
	declared := obj(configuration["built_artifacts"])
	if len(declared) == 0 {
		return map[string][]byte{}, nil
	}
	owned, e := p.builtArtifacts(ctx, jid, spec)
	if e != nil {
		return nil, e
	}
	if component.Role == "build" || !same(declared, owned) {
		return nil, refused("build_transport_mismatch")
	}
	limit := component.Resources.DiskBytes
	if limit > buildworker.MaxBuildBytes {
		limit = buildworker.MaxBuildBytes
	}
	var total int64
	for _, value := range declared {
		n, e := strictInteger(obj(value)["size_bytes"])
		if e != nil || n > limit-total {
			return nil, refused("build_transport_disk_limit")
		}
		total += n
	}
	payloads := map[string][]byte{}
	for _, name := range sortedKeys(declared) {
		bytes, e := p.ReadBuildProduct(ctx, job, name, num(obj(declared[name])["size_bytes"]))
		if e != nil {
			return nil, e
		}
		payloads[name] = bytes
	}
	return payloads, nil
}
func (p *Provisioner) artifactBytes(ctx context.Context, identity executor.ExecutionIdentity, file buildworker.RetainedFile, maxBytes int64) ([]byte, error) {
	if !validRelative(file.Path) || file.SizeBytes < 0 || file.SizeBytes > maxBytes || !shaPattern.MatchString(file.SHA256) {
		return nil, refused("invalid_build_artifact_descriptor")
	}
	var data []byte
	var e error
	if p.ArtifactReader != nil {
		if file.Locator == "" {
			return nil, refused("untrusted_artifact_locator")
		}
		if strings.HasPrefix(file.Locator, "hf2l-node://") {
			u, e := url.Parse(file.Locator)
			if e != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.Path != "/"+identity.Key()+"/"+file.Path {
				return nil, refused("foreign_remote_artifact")
			}
		}
		data, e = p.ArtifactReader(ctx, identity, file.Path, maxBytes)
	} else {
		target := file.Locator
		suffix := filepath.FromSlash(file.Path)
		if !filepath.IsAbs(target) || filepath.Clean(target) != target || !strings.HasSuffix(target, string(filepath.Separator)+suffix) {
			return nil, refused("foreign_local_artifact")
		}
		root := strings.TrimSuffix(target, string(filepath.Separator)+suffix)
		if filepath.Base(root) != identity.Key() || filepath.Base(filepath.Dir(root)) != "retained" {
			return nil, refused("foreign_local_artifact")
		}
		data, e = safeRead(root, file.Path, maxBytes)
	}
	if e != nil {
		return nil, e
	}
	if int64(len(data)) != file.SizeBytes || checksum(data) != file.SHA256 {
		return nil, refused("build_artifact_changed")
	}
	return data, nil
}
func (p *Provisioner) PrepareBuildOutputs(ctx context.Context, job, attempt map[string]any, outputs map[string][]executor.CollectedArtifact) (bool, error) {
	jid, aid, spec, e := identity(job, attempt)
	if e != nil {
		return false, e
	}
	configs := map[string]buildworker.Config{}
	converted := map[string][]buildworker.RetainedFile{}
	for _, c := range spec.Components {
		if c.Role == "build" {
			prepared, e := p.PreparedComponent(ctx, job, attempt, c.ComponentID)
			if e != nil {
				return false, e
			}
			b, e := domain.CanonicalJSON(prepared)
			if e != nil {
				return false, e
			}
			config, e := buildworker.DecodeConfig(b)
			if e != nil {
				return false, e
			}
			configs[c.ComponentID] = config
		}
	}
	for cid, files := range outputs {
		for _, file := range files {
			converted[cid] = append(converted[cid], buildworker.RetainedFile{Path: file.Path, Locator: file.Locator, SHA256: file.SHA256, SizeBytes: file.SizeBytes})
		}
	}
	products, e := buildworker.CollectProducts(ctx, configs, converted, func(ctx context.Context, id buildworker.Identity, file buildworker.RetainedFile, maximum int64) ([]byte, error) {
		return p.artifactBytes(ctx, executor.ExecutionIdentity{JobID: id.JobID, AttemptID: id.AttemptID, ComponentID: id.ComponentID, Epoch: id.Epoch}, file, maximum)
	})
	if e != nil {
		return false, e
	}
	dirs, e := resources.NewOwnedDirectories(p.Root)
	if e != nil {
		return false, e
	}
	defer dirs.Close()
	root, e := dirs.ValidateJob(jid, mustDigest(spec))
	if e != nil {
		return false, e
	}
	destination := filepath.Join(root, "build-products")
	manifest := buildworker.ProductManifestMap(products.Manifest)
	existing, e := p.builtArtifacts(ctx, jid, spec)
	if e != nil {
		return false, e
	}
	if len(existing) > 0 && !same(existing, manifest) {
		return false, refused("immutable_build_products_changed")
	}
	rows, e := p.Ledger.Resources(ctx, jid, resources.ResourceFilter{Kind: "build_products"})
	if e != nil {
		return false, e
	}
	for _, row := range rows {
		if row["state"] != "deleted" {
			if v := details(row)["artifacts"]; v != nil && !same(v, manifest) {
				return false, refused("immutable_build_manifest_changed")
			}
		}
	}
	owner := ownerComponent(spec)
	rid, e := p.Ledger.Own(ctx, resources.Ownership{JobID: jid, AttemptID: aid, ComponentID: owner.ComponentID, Kind: "build_products", ExternalID: destination, Retained: true, Details: map[string]any{"size_bytes": products.LogicalBytes, "logical_bytes": products.LogicalBytes, "artifacts": manifest, "spec_digest": mustDigest(spec), "pool_id": p.storagePool(spec)}})
	if e != nil {
		return false, e
	}
	maximum := buildStorageCap(spec)
	e = p.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		row, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?"+tx.ForUpdate(), rid)
		if e != nil {
			return e
		}
		if row == nil || !same(ownership(row), map[string]any{"job_id": jid, "component_id": owner.ComponentID, "kind": "build_products"}) {
			return refused("foreign_build_budget")
		}
		d := details(row)
		if old := d["artifacts"]; old != nil && !same(old, manifest) {
			return refused("immutable_build_manifest_changed")
		}
		if old, ok := d["retention_reservation_bytes"]; ok {
			maximum = num(old)
		}
		d["artifacts"] = manifest
		d["spec_digest"] = mustDigest(spec)
		d["pool_id"] = p.storagePool(spec)
		d["size_bytes"] = products.LogicalBytes
		d["logical_bytes"] = products.LogicalBytes
		return tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": rid}, map[string]any{"details_json": d})
	})
	if e != nil {
		return false, e
	}
	if _, e = p.Retention.ReserveResource(ctx, rid, jid, maximum); e != nil {
		return false, e
	}
	physical, e := buildworker.StageProducts(destination, products)
	if e != nil {
		return false, e
	}
	if _, e = p.Retention.SettleResource(ctx, rid, jid, physical); e != nil {
		return false, e
	}
	for _, c := range spec.Components {
		if c.Role != "build" {
			config, e := p.PreparedComponent(ctx, job, attempt, c.ComponentID)
			if e != nil {
				return false, e
			}
			config["built_artifacts"] = manifest
			config["build_dir"] = "/job/build"
			if e = ValidateRuntimeConfig(config); e != nil {
				return false, e
			}
			if e = writeWorkerConfig(filepath.Join(root, "attempts", aid, c.ComponentID, "runtime.json"), config); e != nil {
				return false, e
			}
		}
	}
	e = p.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		return tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": rid}, map[string]any{"state": "ready", "updated_at": p.Clock()})
	})
	return e == nil, e
}
