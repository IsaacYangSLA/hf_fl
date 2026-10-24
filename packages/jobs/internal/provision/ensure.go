package provision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	buildworker "github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/build"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/resources"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/source"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func safeRead(root, relative string, maximum int64) ([]byte, error) {
	c, e := newCollector(root, maximum)
	if e != nil {
		return nil, e
	}
	defer c.Close()
	return c.Read(relative, maximum)
}
func decodeMap(data []byte) (map[string]any, error) {
	v, e := domain.DecodeJSON(data)
	if e != nil {
		return nil, e
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, refused("object_required")
	}
	return m, nil
}
func strManifest(value any) (map[string]string, error) {
	m := map[string]string{}
	switch x := value.(type) {
	case map[string]string:
		return x, nil
	case map[string]any:
		for k, v := range x {
			s, ok := v.(string)
			if !ok {
				return nil, refused("invalid_source_manifest")
			}
			m[k] = s
		}
	default:
		return nil, refused("invalid_source_manifest")
	}
	return m, nil
}
func exists(path string) bool { _, e := os.Lstat(path); return e == nil }
func physical(path string) (int64, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return 0, e
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return 0, refused("unsafe_resource")
	}
	v, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, refused("physical_accounting_unavailable")
	}
	return v.Blocks * 512, nil
}
func (p *Provisioner) sourceSnapshot(ctx context.Context, jid, aid string, spec domain.JobSpec, dirs *resources.OwnedDirectories) (map[string]any, error) {
	root, e := dirs.ValidateJob(jid, mustDigest(spec))
	if e != nil {
		return nil, e
	}
	path := filepath.Join(root, "source")
	metadata := filepath.Join(root, ".source.json")
	registry, _, e := p.validateCatalog(ctx, spec)
	if e != nil {
		return nil, e
	}
	approval, e := registry.Authorize(spec.ProjectID, spec.SourceID, spec.SourceCommit)
	if e != nil {
		return nil, e
	}
	owner := ownerComponent(spec)
	maximum := approval.MaxBytes + source.MetadataPeakBytes(approval)
	resourceID, e := p.Ledger.Own(ctx, resources.Ownership{JobID: jid, AttemptID: aid, ComponentID: owner.ComponentID, Kind: "source", ExternalID: path, Retained: true, Details: map[string]any{"source_id": spec.SourceID, "commit": spec.SourceCommit, "pool_id": p.storagePool(spec), "reservation_max_bytes": maximum, "spec_digest": mustDigest(spec)}})
	if e != nil {
		return nil, e
	}
	if _, e = p.Retention.ReserveResource(ctx, resourceID, jid, maximum); e != nil {
		return nil, e
	}
	workspace, workspaceID := "", ""
	if !exists(path) {
		attempt, e := p.DB.One(ctx, "SELECT * FROM jm_attempts WHERE id = ? AND job_id = ?", aid, jid)
		if e != nil {
			return nil, e
		}
		if attempt == nil {
			return nil, refused("foreign_attempt")
		}
		workspace = filepath.Join(root, "source-fetch", fmt.Sprint(num(attempt["number"])))
		workspaceID, e = p.Ledger.Own(ctx, resources.Ownership{JobID: jid, AttemptID: aid, ComponentID: owner.ComponentID, Kind: "source_fetch_workspace", ExternalID: workspace, Retained: true, Details: map[string]any{"pool_id": p.storagePool(spec), "spec_digest": mustDigest(spec), "reservation_max_bytes": source.GitPeakBytes(approval)}})
		if e != nil {
			return nil, e
		}
		if _, e = p.Retention.ReserveResource(ctx, workspaceID, jid, source.GitPeakBytes(approval)); e != nil {
			return nil, e
		}
		if e = source.EnsurePrivateDirectory(workspace); e != nil {
			return nil, e
		}
	}
	desired := map[string]any{"source_id": spec.SourceID, "commit": spec.SourceCommit, "path": path}
	document, e := p.run(ctx, jid, aid, owner.ComponentID, "source", desired, false, func(ctx context.Context, key string) (map[string]any, error) {
		current, _, e := p.validateCatalog(ctx, spec)
		if e != nil {
			return nil, e
		}
		var doc map[string]any
		if exists(path) {
			bytes, e := safeRead(root, ".source.json", maximum)
			if e != nil {
				return nil, e
			}
			doc, e = decodeMap(bytes)
			if e != nil {
				return nil, e
			}
			if doc["source_id"] != spec.SourceID || doc["commit"] != spec.SourceCommit {
				return nil, refused("source_commit_changed")
			}
			manifest, e := strManifest(doc["manifest"])
			if e != nil {
				return nil, e
			}
			if e = source.VerifySnapshot(path, manifest, approval.MaxBytes, approval.MaxFiles); e != nil {
				return nil, e
			}
			return doc, nil
		}
		stage := filepath.Join(root, "source-stage-"+resources.StableKey(jid, spec.SourceCommit)[:16])
		if exists(stage) {
			bytes, e := safeRead(root, ".source.json", maximum)
			if e != nil {
				return nil, e
			}
			doc, e = decodeMap(bytes)
			if e != nil {
				return nil, e
			}
			if doc["source_id"] != spec.SourceID || doc["commit"] != spec.SourceCommit {
				return nil, refused("source_commit_changed")
			}
			manifest, e := strManifest(doc["manifest"])
			if e != nil {
				return nil, e
			}
			if e = source.VerifySnapshot(stage, manifest, approval.MaxBytes, approval.MaxFiles); e != nil {
				return nil, e
			}
		} else {
			snapshot, e := current.Materialize(ctx, spec.ProjectID, spec.SourceID, spec.SourceCommit, stage, workspace)
			if e != nil {
				return nil, e
			}
			doc = map[string]any{"source_id": spec.SourceID, "commit": spec.SourceCommit, "path": path, "manifest": snapshot.Manifest, "digest": snapshot.Digest, "bytes": snapshot.Bytes}
			if e = resources.AtomicJSON(metadata, doc, 0600); e != nil {
				return nil, e
			}
		}
		if e = os.Chmod(stage, 0700); e != nil {
			return nil, e
		}
		if e = source.PublishDirectory(stage, path); e != nil {
			return nil, e
		}
		if e = os.Chmod(path, 0555); e != nil {
			return nil, e
		}
		return doc, nil
	})
	// A failed operation keeps bytes charged until authoritative cleanup.
	if workspace != "" {
		entries, x := os.ReadDir(workspace)
		if x == nil && len(entries) == 0 {
			if x = os.Remove(workspace); x == nil {
				_ = os.Remove(filepath.Dir(workspace))
				if x = p.Ledger.Deleted(ctx, workspaceID, jid); x == nil {
					_, x = p.Retention.ConfirmResourceDeleted(ctx, workspaceID, jid)
				}
			}
			if e == nil && x != nil {
				e = x
			}
		}
	}
	if e != nil {
		return nil, e
	}
	manifest, e := strManifest(document["manifest"])
	if e != nil {
		return nil, e
	}
	if e = source.VerifySnapshot(path, manifest, approval.MaxBytes, approval.MaxFiles); e != nil {
		return nil, e
	}
	bytes, e := source.PhysicalBytes(path, approval)
	if e != nil {
		return nil, e
	}
	for _, m := range []string{metadata, filepath.Join(root, ".owner.json"), root} {
		n, e := physical(m)
		if e != nil {
			return nil, e
		}
		bytes += n
	}
	if _, e = p.Retention.SettleResource(ctx, resourceID, jid, bytes); e != nil {
		return nil, e
	}
	e = p.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		row, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?"+tx.ForUpdate(), resourceID)
		if e != nil {
			return e
		}
		if row == nil || row["job_id"] != jid || ownership(row)["job_id"] != jid {
			return refused("foreign_source_resource")
		}
		d := details(row)
		if old := str(d["sha256"]); old != "" && old != document["digest"] {
			return refused("immutable_source_changed")
		}
		d["sha256"] = document["digest"]
		d["size_bytes"] = document["bytes"]
		d["logical_bytes"] = document["bytes"]
		if e = tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": resourceID}, map[string]any{"details_json": d, "state": "ready", "updated_at": p.Clock()}); e != nil {
			return e
		}
		_, e = source.PublishArtifacts(ctx, tx, jid, resourceID, root, manifest, str(document["digest"]), approval.MaxFiles, approval.MaxBytes)
		return e
	})
	return document, e
}
func mustDigest(spec domain.JobSpec) string {
	v, e := spec.Digest()
	if e != nil {
		panic("validated immutable specification cannot be encoded")
	}
	return v
}
func (p *Provisioner) provisionSpace(ctx context.Context, job map[string]any, aid string, forCleanup bool) (string, error) {
	jid := idOf(job)
	prepaid, e := p.requireBlobBudget(ctx, job, forCleanup)
	if e != nil {
		return "", e
	}
	desired := map[string]any{"name": "hf2l-" + jid, "profile": "fedavg.v1", "quota_bytes": prepaid["quota_bytes"], "principal_quota_bytes": prepaid["principal_quota_bytes"]}
	doc, e := p.run(ctx, jid, aid, "owner", "exchange_space", desired, false, func(ctx context.Context, key string) (map[string]any, error) {
		current, e := p.requireBlobBudget(ctx, job, forCleanup)
		if e != nil {
			return nil, e
		}
		if !same(current["quota_bytes"], desired["quota_bytes"]) || !same(current["principal_quota_bytes"], desired["principal_quota_bytes"]) {
			return nil, refused("namespace_allowance_changed")
		}
		result, e := p.Exchange.CreateSpace(ctx, str(desired["name"]), "fedavg.v1", key, map[string]any{"quota_bytes": desired["quota_bytes"], "principal_quota_bytes": desired["principal_quota_bytes"]})
		if e != nil {
			return nil, e
		}
		sid := str(result["id"])
		if sid == "" {
			sid = str(result["space_id"])
		}
		if e = domain.ValidateIdentifier(sid); e != nil {
			return nil, e
		}
		return map[string]any{"space_id": sid}, nil
	})
	if e != nil {
		return "", e
	}
	space := str(doc["space_id"])
	if _, e = p.Ledger.Own(ctx, resources.Ownership{JobID: jid, AttemptID: aid, ComponentID: "owner", Kind: "exchange_space", ExternalID: space, Retained: true, Details: map[string]any{"job_id": jid, "profile": "fedavg.v1"}}); e != nil {
		return "", e
	}
	policy, e := p.Exchange.GetSpace(ctx, space)
	if e != nil {
		return "", e
	}
	if e = p.bindBlobSpace(ctx, job, space, policy, forCleanup); e != nil {
		return "", e
	}
	managed, e := p.run(ctx, jid, aid, "owner", "managed_space", map[string]any{"space_id": space, "job_id": jid}, false, func(ctx context.Context, key string) (map[string]any, error) {
		return p.request(ctx, "PUT", spacePath(space, "/managed"), map[string]any{"job_id": jid}, key)
	})
	if e != nil {
		return "", e
	}
	if managed["space_id"] != space || managed["job_id"] != jid {
		return "", refused("foreign_managed_namespace_receipt")
	}
	return space, nil
}
func (p *Provisioner) Ensure(ctx context.Context, job, attempt map[string]any, remaining int64) error {
	jid, aid, spec, e := identity(job, attempt)
	if e != nil {
		return e
	}
	if _, e = p.requireBlobBudget(ctx, job, false); e != nil {
		return e
	}
	_, image, e := p.validateCatalog(ctx, spec)
	if e != nil {
		return e
	}
	dirs, e := resources.NewOwnedDirectories(p.Root)
	if e != nil {
		return e
	}
	defer dirs.Close()
	root, e := dirs.EnsureJob(jid, mustDigest(spec))
	if e != nil {
		return e
	}
	if _, e = p.Ledger.Own(ctx, resources.Ownership{JobID: jid, AttemptID: aid, ComponentID: "owner", Kind: "job_directory", ExternalID: root, Retained: true, Details: map[string]any{"spec_digest": mustDigest(spec)}}); e != nil {
		return e
	}
	snapshot, e := p.sourceSnapshot(ctx, jid, aid, spec, dirs)
	if e != nil {
		return e
	}
	paths, e := dirs.Components(jid, componentIDs(spec))
	if e != nil {
		return e
	}
	for cid, path := range paths {
		if _, e = p.Ledger.Own(ctx, resources.Ownership{JobID: jid, AttemptID: aid, ComponentID: cid, Kind: "component_state", ExternalID: path.State, Retained: true, Details: map[string]any{"spec_digest": mustDigest(spec)}}); e != nil {
			return e
		}
	}
	space, e := p.provisionSpace(ctx, job, aid, false)
	if e != nil {
		return e
	}
	schemas := map[string]map[string]any{
		"model.global":    {"type": "object", "properties": map[string]any{"hf2l_files": map[string]any{"type": "object"}, "inputs": map[string]any{"type": "array"}, "base_record_id": map[string]any{"type": "string"}}, "required": []string{"hf2l_files", "inputs"}},
		"training.update": {"type": "object", "properties": map[string]any{"hf2l_files": map[string]any{"type": "object"}, "sample_count": map[string]any{"type": "integer"}, "base_record_id": map[string]any{"type": "string"}}, "required": []string{"hf2l_files", "sample_count", "base_record_id"}},
	}
	for _, kind := range sortedKeys(schemas) {
		schema := schemas[kind]
		desired := map[string]any{"space_id": space, "kind": kind, "schema": schema}
		_, e = p.run(ctx, jid, aid, "owner", "type_"+kind, desired, false, func(ctx context.Context, key string) (map[string]any, error) {
			// The route and body are the existing immutable type-revision contract.
			result, e := p.request(ctx, "POST", spacePath(space, "/types/"+url.PathEscape(kind)+"/revisions"), map[string]any{"schema": schema}, key)
			if e != nil {
				return nil, e
			}
			revision := str(result["id"])
			if revision == "" {
				revision = str(result["revision_id"])
			}
			if revision == "" {
				return nil, refused("invalid_type_revision_receipt")
			}
			return map[string]any{"revision_id": revision}, nil
		})
		if e != nil {
			return e
		}
	}
	principals := map[string]string{}
	participants := map[string]string{}
	type member struct {
		ComponentID, Role string
		ParticipantID     *string
	}
	members := []member{}
	for _, c := range spec.Components {
		if c.Role != "build" {
			members = append(members, member{c.ComponentID, c.Role, c.ParticipantID})
		}
	}
	for _, participant := range spec.Participants {
		if participant.Mode == "external" {
			pid := participant.ParticipantID
			members = append(members, member{ExternalComponent(pid), "participant", &pid})
		}
	}
	for _, m := range members {
		principal := p.Principal(jid, m.ComponentID, m.ParticipantID)
		principals[m.ComponentID] = principal
		roles := []string{"reader", "contributor"}
		if m.Role == "owner" {
			roles = append(roles, "publisher")
		}
		bindings := map[string]any{}
		if m.ParticipantID != nil {
			bindings["participant"] = *m.ParticipantID
			participants[*m.ParticipantID] = principal
		}
		desired := map[string]any{"space_id": space, "principal_id": principal, "roles": roles, "bindings": bindings}
		_, e = p.run(ctx, jid, aid, m.ComponentID, "membership", desired, false, func(ctx context.Context, key string) (map[string]any, error) {
			result, e := p.request(ctx, "PUT", spacePath(space, "/members/"+url.PathEscape(principal)), map[string]any{"roles": roles, "bindings": bindings}, key)
			if e != nil {
				return nil, e
			}
			if result["principal_id"] != principal {
				return nil, refused("foreign_membership_receipt")
			}
			return map[string]any{"principal_id": principal}, nil
		})
		if e != nil {
			return e
		}
		if _, e = p.Ledger.Own(ctx, resources.Ownership{JobID: jid, AttemptID: aid, ComponentID: m.ComponentID, Kind: "exchange_member", ExternalID: space + ":" + principal, Retained: true, Details: desired}); e != nil {
			return e
		}
	}
	if p.ExecutionBindings == nil {
		return refused("execution_bindings_unconfigured")
	}
	deadline, hasDeadline := store.Time(job["deadline_at"])
	expiry := deadline
	if !hasDeadline {
		created, ok := store.Time(attempt["created_at"])
		if !ok {
			created = p.Clock()
		}
		expiry = created.Add(time.Duration(spec.MaxDurationSeconds) * time.Second)
	}
	execution := map[string]map[string]any{}
	for _, component := range spec.Components {
		cid := component.ComponentID
		identity := executor.ExecutionIdentity{JobID: jid, AttemptID: aid, ComponentID: cid, Epoch: num(attempt["epoch"])}
		configuration := map[string]any{}
		if component.Role == "build" {
			if p.WorkerSpecBuilder != nil {
				continue
			}
			approval := p.BuildApprovals[cid]
			if approval == nil || approval["approved_dependencies"] == nil {
				return refused("build_inputs_not_approved")
			}
			for key := range approval {
				if key != "approved_dependencies" && key != "project_subdir" {
					return refused("forbidden_build_override")
				}
			}
			configuration = map[string]any{"schema_version": int64(1), "role": "build", "job_id": jid, "attempt_id": aid, "component_id": cid, "epoch": identity.Epoch, "spec": spec.Map(), "spec_digest": mustDigest(spec), "source_manifest": snapshot["manifest"], "source_dir": "/job/source", "state_dir": "/job/state"}
			for k, v := range approval {
				configuration[k] = v
			}
			if e = validateBuildMap(configuration); e != nil {
				return e
			}
		} else {
			binding, e := p.ExecutionBindings(ctx, job, attempt, component, space, principals[cid])
			if e != nil {
				return e
			}
			if binding["proxy_endpoint"] != p.proxy(identity) {
				return refused("proxy_reservation_mismatch")
			}
			execution[cid] = binding
			thumb := str(binding["certificate_thumbprint"])
			if thumb == "" {
				thumb = str(binding["cert_thumbprint"])
			}
			if thumb == "" {
				return refused("missing_certificate_binding")
			}
			roles := []string{"reader", "contributor"}
			if component.Role == "owner" {
				roles = append(roles, "publisher")
			}
			bindings := map[string]any{}
			if component.ParticipantID != nil {
				bindings["participant"] = *component.ParticipantID
			}
			body := map[string]any{"subject": workloadSubject(jid, cid, component.ParticipantID), "job_id": jid, "attempt_id": aid, "component_id": cid, "epoch": identity.Epoch, "expires_at": float64(expiry.UnixMicro()) / 1e6, "certificate_thumbprint": thumb, "roles": roles, "bindings": bindings}
			desired := map[string]any{"space_id": space}
			for k, v := range body {
				desired[k] = v
			}
			grant, e := p.run(ctx, jid, aid, cid, "workload_grant", desired, true, func(ctx context.Context, key string) (map[string]any, error) {
				return p.request(ctx, "POST", spacePath(space, "/workload-grants"), body, key)
			})
			if e != nil {
				return e
			}
			if grant["principal_id"] != principals[cid] || grant["space_id"] != space || str(grant["grant_id"]) == "" {
				return refused("foreign_workload_grant")
			}
			if _, e = p.Ledger.Own(ctx, resources.Ownership{JobID: jid, AttemptID: aid, ComponentID: cid, Kind: "workload_grant", ExternalID: str(grant["grant_id"]), Details: grant}); e != nil {
				return e
			}
			role := "owner"
			if component.Role == "participant" {
				role = "client"
			}
			directives, e := p.directives(ctx, jid, cid, identity.Epoch)
			if e != nil {
				return e
			}
			configuration = map[string]any{"schema_version": int64(1), "role": role, "job_id": jid, "attempt_id": aid, "component_id": cid, "space_id": space, "epoch": identity.Epoch, "spec": spec.Map(), "spec_digest": mustDigest(spec), "source_dir": "/job/source", "state_dir": "/job/state", "exchange_endpoint": "http://proxy", "proxy_socket": "/run/hf2l/proxy.sock", "source_manifest": snapshot["manifest"], "participant_principals": participants, "dataset_bindings": obj(binding["dataset_bindings"]), "deadline_at": nil, "reconciliation": directives}
			if hasDeadline {
				configuration["deadline_at"] = float64(deadline.UnixMicro()) / 1e6
			}
			if p.SecretResolver != nil {
				resolved, e := p.SecretResolver.Resolve(ctx, job, attempt, component)
				if e != nil {
					return e
				}
				if resolved.PrivatePath != "" {
					configuration["secret_options_file"] = "/run/hf2l/secrets.json"
					configuration["secret_option_names"] = resolved.OptionNames
					if _, e = p.Ledger.Own(ctx, resources.Ownership{JobID: jid, AttemptID: aid, ComponentID: cid, Kind: "runtime_secret", ExternalID: resolved.PrivatePath, Details: map[string]any{"epoch": identity.Epoch}}); e != nil {
						return e
					}
				}
			}
			if component.ParticipantID != nil {
				configuration["participant_id"] = *component.ParticipantID
			}
			built, e := p.builtArtifacts(ctx, jid, spec)
			if e != nil {
				return e
			}
			if len(built) > 0 {
				configuration["built_artifacts"] = built
				configuration["build_dir"] = "/job/build"
			}
			if e = ValidateRuntimeConfig(configuration); e != nil {
				return e
			}
		}
		parent := filepath.Join(root, "attempts", aid, cid)
		if e = source.EnsurePrivateDirectory(parent); e != nil {
			return e
		}
		path := filepath.Join(parent, "runtime.json")
		if e = writeWorkerConfig(path, configuration); e != nil {
			return e
		}
		if _, e = p.Ledger.Own(ctx, resources.Ownership{JobID: jid, AttemptID: aid, ComponentID: cid, Kind: "runtime_config", ExternalID: path, Details: map[string]any{"spec_digest": mustDigest(spec)}}); e != nil {
			return e
		}
	}
	_, e = p.specs(ctx, job, attempt, spec, image, paths, execution)
	return e
}
func writeWorkerConfig(path string, configuration map[string]any) error {
	b, e := domain.CanonicalJSON(configuration)
	if e != nil {
		return e
	}
	if len(b) > 2*1024*1024 {
		return refused("worker_configuration_too_large")
	}
	return resources.AtomicJSON(path, configuration, 0400)
}
func validateBuildMap(configuration map[string]any) error {
	data, e := domain.CanonicalJSON(configuration)
	if e != nil {
		return e
	}
	var cfg buildworker.Config
	if e = json.Unmarshal(data, &cfg); e != nil {
		return e
	}
	return cfg.Validate()
}
func checksum(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func (p *Provisioner) Snapshot(ctx context.Context, job map[string]any) (source.Snapshot, error) {
	spec, e := JobSpec(job)
	if e != nil {
		return source.Snapshot{}, e
	}
	registry, _, e := p.validateCatalog(ctx, spec)
	if e != nil {
		return source.Snapshot{}, e
	}
	approval, e := registry.Authorize(spec.ProjectID, spec.SourceID, spec.SourceCommit)
	if e != nil {
		return source.Snapshot{}, e
	}
	jid := idOf(job)
	dirs, e := resources.NewOwnedDirectories(p.Root)
	if e != nil {
		return source.Snapshot{}, e
	}
	defer dirs.Close()
	root, e := dirs.ValidateJob(jid, mustDigest(spec))
	if e != nil {
		return source.Snapshot{}, e
	}
	data, e := safeRead(root, ".source.json", approval.MaxBytes+source.MetadataPeakBytes(approval))
	if e != nil {
		return source.Snapshot{}, e
	}
	doc, e := decodeMap(data)
	if e != nil {
		return source.Snapshot{}, e
	}
	if doc["source_id"] != spec.SourceID || doc["commit"] != spec.SourceCommit {
		return source.Snapshot{}, refused("foreign_source_snapshot")
	}
	manifest, e := strManifest(doc["manifest"])
	if e != nil {
		return source.Snapshot{}, e
	}
	path := filepath.Join(root, "source")
	if e = source.VerifySnapshot(path, manifest, approval.MaxBytes, approval.MaxFiles); e != nil {
		return source.Snapshot{}, e
	}
	digest, e := source.ManifestDigest(manifest)
	if e != nil || digest != str(doc["digest"]) {
		return source.Snapshot{}, refused("source_manifest_changed")
	}
	return source.Snapshot{SourceID: spec.SourceID, Commit: spec.SourceCommit, Path: path, Manifest: manifest, Digest: digest, Bytes: num(doc["bytes"])}, nil
}
func (p *Provisioner) Image(ctx context.Context, spec domain.JobSpec) (string, error) {
	_, image, e := p.validateCatalog(ctx, spec)
	return image, e
}
func (p *Provisioner) ExchangeGrant(ctx context.Context, space, grant string) (map[string]any, error) {
	if e := domain.ValidateIdentifier(space); e != nil {
		return nil, e
	}
	if e := domain.ValidateIdentifier(grant); e != nil {
		return nil, e
	}
	return p.request(ctx, "GET", spacePath(space, "/workload-grants/"+url.PathEscape(grant)), nil, "")
}
func (p *Provisioner) ReconciliationDirectives(ctx context.Context, jid, cid string, epoch int64) ([]any, error) {
	return p.directives(ctx, jid, cid, epoch)
}
