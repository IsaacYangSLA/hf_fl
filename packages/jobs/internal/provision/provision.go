// Package provision reconciles immutable job inputs with durable owned resources.
package provision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/artifacts"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/controller"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/resources"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/secrets"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/source"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

type Exchange interface {
	Request(context.Context, string, string, any, map[string]string, url.Values) (map[string]any, error)
	CreateSpace(context.Context, string, string, string, map[string]any) (map[string]any, error)
	GetSpace(context.Context, string) (map[string]any, error)
}
type Config struct {
	DB                                                         *store.DB
	Exchange                                                   Exchange
	Root, WorkloadIssuer, StoragePoolID, ExchangeStoragePoolID string
	Registry                                                   *source.Registry
	ExecutionBindings                                          func(context.Context, map[string]any, map[string]any, domain.ComponentSpec, string, string) (map[string]any, error)
	WorkerSpecBuilder                                          func(context.Context, map[string]any, map[string]any, domain.ComponentSpec, resources.ComponentPaths) (executor.ExecutionSpec, error)
	ProxyEndpoint                                              func(executor.ExecutionIdentity) string
	SecretResolver                                             *secrets.Resolver
	BuildApprovals                                             map[string]map[string]any
	ArtifactReader                                             func(context.Context, executor.ExecutionIdentity, string, int64) ([]byte, error)
	ExternalCleanup                                            func(context.Context, map[string]any) (bool, error)
	AuxiliaryStorage                                           func(context.Context, map[string]any) ([]map[string]any, error)
	AuxiliaryStorageTx                                         func(context.Context, *store.Tx, map[string]any) ([]map[string]any, error)
	RemoteAuxiliaryCleanup                                     func(context.Context, map[string]any, []map[string]any) (map[string][]map[string]any, error)
	PublicationObserver                                        func(context.Context, map[string]any, map[string]any, string) (controller.PublicationObservation, error)
	ProxyRestorer                                              func(context.Context, map[string]any, map[string]any) (bool, error)
	ProxyStopper                                               func(context.Context, executor.ExecutionIdentity, bool) (bool, error)
	ArtifactFenceRevoker                                       func(context.Context, string) (bool, error)
	Clock                                                      func() time.Time
}
type Provisioner struct {
	Config
	Ledger    *resources.Ledger
	Retention *artifacts.Retention
}

func New(config Config) (*Provisioner, error) {
	if config.DB == nil || config.Exchange == nil || config.WorkloadIssuer == "" || !filepath.IsAbs(config.Root) || filepath.Clean(config.Root) != config.Root || config.Root == "/" {
		return nil, refused("invalid_provisioner_configuration")
	}
	for _, id := range []string{config.StoragePoolID, config.ExchangeStoragePoolID} {
		if id != "" {
			if err := domain.ValidateIdentifier(id); err != nil {
				return nil, err
			}
		}
	}
	if config.StoragePoolID != "" && config.StoragePoolID == config.ExchangeStoragePoolID {
		return nil, refused("object_storage_pool_not_distinct")
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	if config.BuildApprovals == nil {
		config.BuildApprovals = map[string]map[string]any{}
	}
	p := &Provisioner{Config: config, Ledger: resources.NewLedger(config.DB), Retention: artifacts.NewRetention(config.DB)}
	p.Ledger.Clock = config.Clock
	p.Retention.Clock = config.Clock
	return p, nil
}
func refused(code string) error { return domain.Err(409, code) }
func str(v any) string          { s, _ := v.(string); return s }
func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}
func stringsOf(v any) []string {
	var result []string
	switch a := v.(type) {
	case []string:
		return append([]string{}, a...)
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok {
				result = append(result, s)
			}
		}
	}
	return result
}
func num(v any) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	case int32:
		return int64(x)
	case json.Number:
		n, _ := x.Int64()
		return n
	}
	return 0
}
func truth(v any) bool { b, _ := v.(bool); return b }
func details(row map[string]any) map[string]any {
	if v, ok := row["details"]; ok {
		return obj(v)
	}
	return obj(row["details_json"])
}
func ownership(row map[string]any) map[string]any {
	if v, ok := row["ownership"]; ok {
		return obj(v)
	}
	return obj(row["ownership_json"])
}
func same(a, b any) bool {
	x, e := domain.CanonicalJSON(a)
	if e != nil {
		return false
	}
	y, e := domain.CanonicalJSON(b)
	return e == nil && string(x) == string(y)
}
func idOf(row map[string]any) string { return str(row["id"]) }
func digestMap(v any) (string, error) {
	b, e := domain.CanonicalJSON(v)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func JobSpec(job map[string]any) (domain.JobSpec, error) {
	raw := job["spec_json"]
	if raw == nil {
		raw = job["spec"]
	}
	b, e := domain.CanonicalJSON(raw)
	if e != nil {
		return domain.JobSpec{}, e
	}
	spec, e := domain.DecodeJobSpec(b)
	if e != nil {
		return spec, e
	}
	d, e := spec.Digest()
	if e != nil {
		return spec, e
	}
	if v, ok := job["spec_hash"]; ok && v != d {
		return spec, refused("immutable_specification_changed")
	}
	return spec, nil
}
func identity(job, attempt map[string]any) (string, string, domain.JobSpec, error) {
	spec, e := JobSpec(job)
	if e != nil {
		return "", "", spec, e
	}
	jid, aid := idOf(job), idOf(attempt)
	if jid == "" || aid == "" || str(attempt["job_id"]) != jid || num(attempt["epoch"]) < 1 {
		return "", "", spec, refused("foreign_attempt")
	}
	for _, v := range []string{jid, aid} {
		if e = domain.ValidateIdentifier(v); e != nil {
			return "", "", spec, e
		}
	}
	return jid, aid, spec, nil
}
func ExternalComponent(participant string) string {
	return "participant-" + resources.StableKey(participant)[:40]
}
func workloadSubject(jobID, componentID string, participant *string) string {
	var p any
	if participant != nil {
		p = *participant
	}
	b, _ := domain.CanonicalJSON([]any{jobID, componentID, p})
	h := sha256.Sum256(b)
	return "job:" + hex.EncodeToString(h[:])
}
func (p *Provisioner) Principal(jobID, componentID string, participant *string) string {
	return domain.PrincipalID(p.WorkloadIssuer, workloadSubject(jobID, componentID, participant))
}
func (p *Provisioner) proxy(identity executor.ExecutionIdentity) string {
	if p.ProxyEndpoint != nil {
		return p.ProxyEndpoint(identity)
	}
	return filepath.Join(p.Root, identity.JobID, "attempts", identity.AttemptID, identity.ComponentID, "proxy.sock")
}
func spacePath(space, suffix string) string { return "/v2/spaces/" + url.PathEscape(space) + suffix }
func (p *Provisioner) request(ctx context.Context, method, path string, body any, key string) (map[string]any, error) {
	headers := map[string]string{}
	if key != "" {
		headers["Idempotency-Key"] = key
	}
	return p.Exchange.Request(ctx, method, path, body, headers, nil)
}
func (p *Provisioner) run(ctx context.Context, jid, aid, cid, operation string, desired map[string]any, attemptScoped bool, action func(context.Context, string) (map[string]any, error)) (map[string]any, error) {
	scope := ""
	if attemptScoped {
		scope = aid
	}
	key := resources.StableKey("hf2l", jid, scope, cid, operation)
	return p.Ledger.Run(ctx, resources.OperationRequest{JobID: jid, AttemptID: aid, ComponentID: cid, Operation: operation, Key: key, Desired: desired}, func(ctx context.Context) (map[string]any, error) { return action(ctx, key) })
}
func (p *Provisioner) storagePool(spec domain.JobSpec) string {
	if p.StoragePoolID != "" {
		return p.StoragePoolID
	}
	for _, c := range spec.Components {
		if c.Role == "owner" {
			return c.Resources.PoolID
		}
	}
	return ""
}
func (p *Provisioner) paths(jid string, spec domain.JobSpec) map[string]resources.ComponentPaths {
	result := map[string]resources.ComponentPaths{}
	for _, c := range spec.Components {
		state := filepath.Join(p.Root, jid, "components", c.ComponentID, "state")
		result[c.ComponentID] = resources.ComponentPaths{Source: filepath.Join(p.Root, jid, "source"), State: state, Cache: filepath.Join(state, "cache"), Logs: filepath.Join(state, "logs"), Artifacts: filepath.Join(state, "artifacts")}
	}
	return result
}
func (p *Provisioner) validateCatalog(ctx context.Context, spec domain.JobSpec) (*source.Registry, string, error) {
	var registry *source.Registry
	var image string
	err := p.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		var e error
		registry, image, e = p.validateCatalogTx(ctx, tx, spec)
		return e
	})
	return registry, image, err
}

func (p *Provisioner) validateCatalogTx(ctx context.Context, tx *store.Tx, spec domain.JobSpec) (*source.Registry, string, error) {
	var registry *source.Registry
	if p.Registry != nil {
		if _, e := p.Registry.Authorize(spec.ProjectID, spec.SourceID, spec.SourceCommit); e != nil {
			return nil, "", e
		}
		registry = p.Registry
	}
	var image string
	err := func() error {
		if registry == nil {
			projects, e := tx.All(ctx, "SELECT id FROM jm_projects")
			if e != nil {
				return e
			}
			allProjects := []string{}
			for _, row := range projects {
				allProjects = append(allProjects, str(row["id"]))
			}
			rows, e := tx.All(ctx, "SELECT * FROM jm_approved_sources WHERE enabled = ? AND status = ?", true, "approved")
			if e != nil {
				return e
			}
			approvals := []source.Approval{}
			hosts := []string{}
			for _, row := range rows {
				d := obj(row["details_json"])
				projects := allProjects
				if v := str(row["project_id"]); v != "" {
					projects = []string{v}
				}
				approval := source.Approval{SourceID: idOf(row), Projects: projects, URL: str(row["url"]), MirrorPath: str(d["mirror_path"]), Commits: stringsOf(row["allowed_commits"]), MaxBytes: 256 * 1024 * 1024, MaxFiles: 100000, MaxGitBytes: 256 * 1024 * 1024, MaxGitFiles: 100000}
				if approval.MirrorPath != "" {
					approval.URL = ""
				}
				for name, target := range map[string]*int64{"max_bytes": &approval.MaxBytes, "max_files": &approval.MaxFiles, "max_git_bytes": &approval.MaxGitBytes, "max_git_files": &approval.MaxGitFiles} {
					if v, ok := d[name]; ok {
						*target = num(v)
					}
				}
				approvals = append(approvals, approval)
				hosts = append(hosts, stringsOf(row["allowed_hosts"])...)
			}
			registry, e = source.NewRegistry(approvals, hosts)
			if e != nil {
				return e
			}
		}
		if _, e := registry.Authorize(spec.ProjectID, spec.SourceID, spec.SourceCommit); e != nil {
			return e
		}
		rows, e := tx.All(ctx, "SELECT * FROM jm_runtime_images WHERE enabled = ? AND approved = ? AND status = ?", true, true, "approved")
		if e != nil {
			return e
		}
		for _, row := range rows {
			if (str(row["project_id"]) == "" || row["project_id"] == spec.ProjectID) && (row["id"] == spec.RuntimeImage || row["digest"] == spec.RuntimeImage) {
				image = str(row["digest"])
				break
			}
		}
		if image == "" {
			return refused("runtime_image_not_approved")
		}
		for _, participant := range spec.Participants {
			row, e := tx.One(ctx, "SELECT * FROM jm_participant_bindings WHERE id = ?", participant.DatasetBinding)
			if e != nil {
				return e
			}
			if row == nil || !truth(row["enabled"]) || row["project_id"] != spec.ProjectID || row["participant_id"] != participant.ParticipantID {
				return refused("participant_binding_not_approved")
			}
		}
		for _, ref := range spec.SecretRefs {
			row, e := tx.One(ctx, "SELECT * FROM jm_secret_references WHERE id = ?", ref)
			if e != nil {
				return e
			}
			if row == nil || !truth(row["enabled"]) || row["project_id"] != spec.ProjectID {
				return refused("secret_reference_not_approved")
			}
		}
		return nil
	}()
	return registry, image, err
}
func (p *Provisioner) specs(ctx context.Context, job, attempt map[string]any, spec domain.JobSpec, image string, paths map[string]resources.ComponentPaths, bindings map[string]map[string]any) (map[string]executor.ExecutionSpec, error) {
	result := map[string]executor.ExecutionSpec{}
	jid, aid := idOf(job), idOf(attempt)
	var deadline *float64
	if t, ok := store.Time(job["deadline_at"]); ok {
		x := float64(t.UnixMicro()) / 1e6
		deadline = &x
	}
	for _, c := range spec.Components {
		id := executor.ExecutionIdentity{JobID: jid, AttemptID: aid, ComponentID: c.ComponentID, Epoch: num(attempt["epoch"])}
		path := paths[c.ComponentID]
		if c.Role == "build" && p.WorkerSpecBuilder != nil {
			s, e := p.WorkerSpecBuilder(ctx, job, attempt, c, path)
			if e != nil {
				return nil, e
			}
			result[c.ComponentID] = s
			continue
		}
		if c.Role == "build" && p.BuildApprovals[c.ComponentID] == nil {
			return nil, refused("build_inputs_not_approved")
		}
		role := "owner"
		if c.Role == "participant" {
			role = "client"
		}
		if c.Role == "build" {
			role = "build"
		}
		proxy := ""
		if role != "build" {
			proxy = p.proxy(id)
			if v := str(bindings[c.ComponentID]["proxy_endpoint"]); v != "" {
				proxy = v
			}
		}
		s := executor.ExecutionSpec{Identity: id, ImageDigest: image, SourcePath: path.Source, StatePath: path.State, ProxyEndpoint: proxy, Resources: executor.ResourceLimits{CPUMillis: c.Resources.CPUMillicores, MemoryBytes: c.Resources.MemoryBytes, DiskBytes: c.Resources.DiskBytes, GPUs: c.Resources.GPUCount}, PoolID: c.Resources.PoolID, Deadline: deadline, ConfigPath: filepath.Join(p.Root, jid, "attempts", aid, c.ComponentID, "runtime.json"), Profile: c.Resources.SandboxProfile, Role: role}
		if c.ParticipantID != nil {
			s.ParticipantID = *c.ParticipantID
			for _, participant := range spec.Participants {
				if participant.ParticipantID == *c.ParticipantID {
					s.DatasetBindingID = participant.DatasetBinding
				}
			}
		}
		if p.SecretResolver != nil {
			planned, e := p.SecretResolver.Planned(ctx, job, attempt, c)
			if e != nil {
				return nil, e
			}
			s.SecretPath = planned.PrivatePath
		}
		if role != "build" {
			for _, other := range spec.Components {
				if other.Role == "build" {
					s.BuildInputPath = filepath.Join(p.Root, jid, "build-products")
					break
				}
			}
		}
		s = s.Defaults()
		if e := s.Validate(); e != nil {
			return nil, e
		}
		result[c.ComponentID] = s
	}
	return result, nil
}
func (p *Provisioner) Plan(ctx context.Context, job, attempt map[string]any, remaining int64) (map[string]executor.ExecutionSpec, error) {
	jid, _, spec, e := identity(job, attempt)
	if e != nil {
		return nil, e
	}
	_, image, e := p.validateCatalog(ctx, spec)
	if e != nil {
		return nil, e
	}
	if len(spec.SecretRefs) > 0 {
		if p.SecretResolver == nil {
			return nil, refused("secret_delivery_unconfigured")
		}
		if e = p.SecretResolver.ValidateSpec(ctx, spec); e != nil {
			return nil, e
		}
	}
	return p.specs(ctx, job, attempt, spec, image, p.paths(jid, spec), nil)
}
func (p *Provisioner) OwnedSpace(ctx context.Context, jid string) (string, error) {
	rows, e := p.Ledger.Resources(ctx, jid, resources.ResourceFilter{Kind: "exchange_space"})
	if e != nil {
		return "", e
	}
	var live []map[string]any
	for _, row := range rows {
		if row["state"] != "deleted" {
			live = append(live, row)
		}
	}
	if len(live) > 1 {
		return "", refused("multiple_owned_namespaces")
	}
	if len(live) == 0 {
		return "", nil
	}
	if ownership(live[0])["job_id"] != jid {
		return "", refused("foreign_namespace_ownership")
	}
	return str(live[0]["external_id"]), nil
}
func (p *Provisioner) CurrentRound(ctx context.Context, job map[string]any) (int64, error) {
	space, e := p.OwnedSpace(ctx, idOf(job))
	if e != nil || space == "" {
		return 0, e
	}
	ref, e := p.request(ctx, "GET", spacePath(space, "/refs/main"), nil, "")
	if e != nil {
		var d *domain.Error
		if errors.As(e, &d) && d.Code == "reference_not_found" {
			return 0, nil
		}
		return 0, e
	}
	record, e := p.request(ctx, "GET", spacePath(space, "/records/"+url.PathEscape(str(ref["record_id"]))), nil, "")
	if e != nil {
		return 0, e
	}
	meta := obj(record["metadata"])
	value := obj(obj(meta["hf2l_files"])["fedavg_round.json"])["round"]
	if value == nil {
		value = meta["round"]
	}
	n, e := strictInteger(value)
	if e != nil || n < 0 {
		return 0, refused("invalid_published_absolute_round")
	}
	return n, nil
}
func (p *Provisioner) Revoke(ctx context.Context, job, attempt map[string]any) (bool, error) {
	jid, aid, _, e := identity(job, attempt)
	if e != nil {
		return false, e
	}
	space, e := p.OwnedSpace(ctx, jid)
	if e != nil || space == "" {
		return space == "", e
	}
	result, e := p.run(ctx, jid, aid, "owner", "revoke_attempt", map[string]any{"space_id": space, "attempt_id": aid}, true, func(ctx context.Context, key string) (map[string]any, error) {
		return p.request(ctx, "POST", spacePath(space, "/workload-grants/revoke"), map[string]any{"attempt_id": aid}, key)
	})
	return result["attempt_id"] == aid && result["revoked_at"] != nil && result["revoked_at"] != "", e
}
func (p *Provisioner) Reconcile(ctx context.Context, job, attempt map[string]any) (controller.PublicationObservation, error) {
	jid, _, _, e := identity(job, attempt)
	if e != nil {
		return controller.PublicationObservation{}, e
	}
	space, e := p.OwnedSpace(ctx, jid)
	if e != nil {
		return controller.PublicationObservation{}, e
	}
	if p.PublicationObserver == nil {
		return controller.PublicationObservation{Known: false, Status: "unknown", Evidence: map[string]any{"reason": "publication_evidence_required"}}, nil
	}
	observed, e := p.PublicationObserver(ctx, job, attempt, space)
	if e == nil {
		e = observed.Validate()
	}
	return observed, e
}
func (p *Provisioner) RestoreJobProxies(ctx context.Context, job, attempt map[string]any) (bool, error) {
	if _, _, _, e := identity(job, attempt); e != nil {
		return false, e
	}
	space, e := p.OwnedSpace(ctx, idOf(job))
	if e != nil {
		return false, e
	}
	if space == "" {
		return true, nil
	}
	if p.ProxyRestorer == nil {
		return false, refused("proxy_restoration_unconfigured")
	}
	return p.ProxyRestorer(ctx, job, attempt)
}
func (p *Provisioner) directives(ctx context.Context, jid, cid string, epoch int64) ([]any, error) {
	rows, e := p.DB.All(ctx, "SELECT details_json FROM jm_attempts WHERE job_id = ? AND epoch < ? ORDER BY epoch DESC LIMIT 32", jid, epoch)
	if e != nil {
		return nil, e
	}
	for _, row := range rows {
		v := obj(obj(row["details_json"])["reconciliation_directives"])[cid]
		if a, ok := v.([]any); ok && len(a) > 0 {
			return a, nil
		}
	}
	return []any{}, nil
}
func (p *Provisioner) SourceBounds(ctx context.Context, job map[string]any) (map[string]int64, error) {
	spec, e := JobSpec(job)
	if e != nil {
		return nil, e
	}
	registry, _, e := p.validateCatalog(ctx, spec)
	if e != nil {
		return nil, e
	}
	a, e := registry.Authorize(spec.ProjectID, spec.SourceID, spec.SourceCommit)
	if e != nil {
		return nil, e
	}
	return map[string]int64{"max_bytes": a.MaxBytes, "max_files": a.MaxFiles, "max_git_bytes": a.MaxGitBytes, "max_git_files": a.MaxGitFiles}, nil
}
func (p *Provisioner) ExternalSecretOptions(ctx context.Context, job, attempt map[string]any, participantID string) ([]string, error) {
	_, _, spec, e := identity(job, attempt)
	if e != nil {
		return nil, e
	}
	for _, participant := range spec.Participants {
		if participant.ParticipantID == participantID && participant.Mode == "external" {
			if p.SecretResolver == nil {
				if len(spec.SecretRefs) > 0 {
					return nil, refused("secret_delivery_unconfigured")
				}
				return []string{}, nil
			}
			c := domain.ComponentSpec{ComponentID: ExternalComponent(participantID), Role: "participant", ParticipantID: &participantID}
			resolved, e := p.SecretResolver.Planned(ctx, job, attempt, c)
			return resolved.OptionNames, e
		}
	}
	return nil, refused("unassigned_external_participant")
}
func strictInteger(v any) (int64, error) {
	switch x := v.(type) {
	case int:
		return int64(x), nil
	case int64:
		return x, nil
	case json.Number:
		if strings.ContainsAny(string(x), ".eE") {
			return 0, fmt.Errorf("integer required")
		}
		return x.Int64()
	}
	return 0, fmt.Errorf("integer required")
}
func ownerComponent(spec domain.JobSpec) domain.ComponentSpec {
	for _, c := range spec.Components {
		if c.Role == "owner" {
			return c
		}
	}
	return domain.ComponentSpec{}
}
func componentIDs(spec domain.JobSpec) []string {
	ids := make([]string, 0, len(spec.Components))
	for _, c := range spec.Components {
		ids = append(ids, c.ComponentID)
	}
	return ids
}
func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
