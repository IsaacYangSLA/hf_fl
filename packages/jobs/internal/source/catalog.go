package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func integer(value any) (int64, bool) {
	switch v := value.(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case json.Number:
		n, e := v.Int64()
		return n, e == nil
	default:
		return 0, false
	}
}
func object(value any) map[string]any {
	m, _ := value.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}
func stringValue(value any) string { v, _ := value.(string); return v }
func stringsValue(value any) []string {
	switch values := value.(type) {
	case []string:
		return append([]string(nil), values...)
	case []any:
		result := make([]string, 0, len(values))
		for _, v := range values {
			s, ok := v.(string)
			if !ok {
				return nil
			}
			result = append(result, s)
		}
		return result
	}
	return nil
}

// PublishArtifacts adds only hash-bound metadata for the already charged source resource.
// It acquires Job before Resource and checks every file before any artifact insertion.
func PublishArtifacts(ctx context.Context, tx *store.Tx, jobID, resourceID, jobRoot string, manifest map[string]string, expectedDigest string, maxFiles, maxBytes int64) ([]string, error) {
	if maxFiles < 1 || maxFiles > 100000 || maxBytes < 1 || maxBytes > 1<<30 || !canonicalAbsolute(jobRoot) || filepath.Base(jobRoot) != jobID || int64(len(manifest)) > maxFiles {
		return nil, fmt.Errorf("%w: invalid source artifact bounds or root", ErrUnsafe)
	}
	digest, e := ManifestDigest(manifest)
	if e != nil || digest != expectedDigest {
		return nil, fmt.Errorf("%w: source artifact manifest changed", ErrUnsafe)
	}
	for name := range manifest {
		locator := domain.ArtifactLocator{Kind: "local", ResourceID: &resourceID, RelativePath: &name}
		if e := locator.Validate(); e != nil {
			return nil, e
		}
	}
	job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), jobID)
	if e != nil {
		return nil, e
	}
	resource, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id=?"+tx.ForUpdate(), resourceID)
	if e != nil {
		return nil, e
	}
	if job == nil || job["purged_at"] != nil {
		return nil, fmt.Errorf("%w: source job is absent or purged", ErrUnsafe)
	}
	if expires, ok := store.Time(job["artifacts_expire_at"]); ok && !expires.After(time.Now().UTC()) {
		return nil, fmt.Errorf("%w: source job has expired", ErrUnsafe)
	}
	ownership := object(resource["ownership_json"])
	details := object(resource["details_json"])
	state := stringValue(resource["state"])
	if resource == nil || resource["job_id"] != jobID || resource["kind"] != "source" || ownership["job_id"] != jobID || resource["external_id"] != filepath.Join(jobRoot, "source") || resource["retained"] != true || resource["deleted_at"] != nil || state == "deleted" || state == "cleanup_pending" || state == "retired" {
		return nil, fmt.Errorf("%w: source artifact resource not live and owned", ErrUnsafe)
	}
	logical, ok := integer(details["logical_bytes"])
	if !ok {
		logical, ok = integer(details["size_bytes"])
	}
	size, sizeOK := integer(resource["size_bytes"])
	charged, chargedOK := integer(details["retention_charged_bytes"])
	if details["sha256"] != expectedDigest || details["retention_charge_settled"] != true || details["retention_charge_released"] != false || !ok || logical < 0 || logical > maxBytes || !sizeOK || size < logical || !chargedOK || charged != size {
		return nil, fmt.Errorf("%w: source resource has no settled immutable charge", ErrUnsafe)
	}
	tr, e := OpenTree(filepath.Join(jobRoot, "source"), Limits{MaxFiles: maxFiles, MaxEntries: min(2000000, maxFiles*65), MaxFileBytes: maxBytes, MaxTotalBytes: maxBytes, MaxDepth: 64})
	if e != nil {
		return nil, e
	}
	defer tr.Close()
	files, e := tr.List()
	if e != nil {
		return nil, e
	}
	var total int64
	if len(files) != len(manifest) {
		return nil, fmt.Errorf("%w: source file set changed", ErrUnsafe)
	}
	for _, f := range files {
		if manifest[f.Path] != f.SHA256 {
			return nil, fmt.Errorf("%w: source file changed", ErrUnsafe)
		}
		total += f.SizeBytes
	}
	if total != logical {
		return nil, fmt.Errorf("%w: source logical bytes changed", ErrUnsafe)
	}
	type pendingArtifact struct {
		id     string
		values map[string]any
	}
	var pending []pendingArtifact
	ids := make([]string, 0, len(files))
	for _, f := range files {
		encoded, e := domain.CanonicalJSON([]string{"source-artifact", jobID, resourceID, f.Path})
		if e != nil {
			return nil, e
		}
		h := sha256.Sum256(encoded)
		id := hex.EncodeToString(h[:])[:32]
		locator := map[string]any{"kind": "local", "resource_id": resourceID, "relative_path": f.Path}
		storageKey := "source-artifact:" + id
		existing, e := tx.One(ctx, "SELECT * FROM jm_artifacts WHERE id=?", id)
		if e != nil {
			return nil, e
		}
		if existing != nil {
			existingSize, ok := integer(existing["size_bytes"])
			existingState := stringValue(existing["state"])
			if existing["job_id"] != jobID || existing["kind"] != "source" || existing["attempt_number"] != nil || existing["name"] != filepath.Base(f.Path) || !ok || existingSize != f.SizeBytes || existing["sha256"] != f.SHA256 || existing["storage_key"] != storageKey || !reflect.DeepEqual(object(existing["locator_json"]), locator) || (existingState != "available" && existingState != "retained") || existing["deleted_at"] != nil {
				return nil, fmt.Errorf("%w: immutable source artifact conflict", ErrUnsafe)
			}
		} else {
			pending = append(pending, pendingArtifact{id, map[string]any{"id": id, "job_id": jobID, "attempt_number": nil, "kind": "source", "name": filepath.Base(f.Path), "size_bytes": f.SizeBytes, "sha256": f.SHA256, "storage_key": storageKey, "locator_json": locator, "state": "available", "expires_at": job["artifacts_expire_at"]}})
		}
		ids = append(ids, id)
	}
	for _, item := range pending {
		if e = tx.Insert(ctx, "jm_artifacts", item.values); e != nil {
			return nil, e
		}
	}
	return ids, nil
}

// Catalog is a current trusted approval set; database-backed validation refreshes on every call.
type Catalog struct {
	Registry        *Registry
	RuntimeImages   map[string]string
	DatasetBindings map[string][]string
	SecretRefs      map[string]bool
	RuntimeProjects map[string]string
	DatasetProjects map[string]string
	SecretProjects  map[string]string
	Database        *store.DB
}

func NewCatalog(registry *Registry, images map[string]string, datasets map[string][]string, secrets []string) (*Catalog, error) {
	if registry == nil {
		return nil, fmt.Errorf("%w: source registry required", ErrUnsafe)
	}
	c := &Catalog{Registry: registry, RuntimeImages: map[string]string{}, DatasetBindings: map[string][]string{}, SecretRefs: map[string]bool{}, RuntimeProjects: map[string]string{}, DatasetProjects: map[string]string{}, SecretProjects: map[string]string{}}
	for k, v := range images {
		if len(v) != 71 || v[:7] != "sha256:" || !digestID.MatchString(v[7:]) {
			return nil, fmt.Errorf("%w: approved image must have immutable digest", ErrUnsafe)
		}
		c.RuntimeImages[k] = v
	}
	for k, v := range datasets {
		c.DatasetBindings[k] = append([]string(nil), v...)
	}
	for _, v := range secrets {
		c.SecretRefs[v] = true
	}
	return c, nil
}
func FromDatabase(ctx context.Context, db *store.DB) (*Catalog, error) {
	var catalog *Catalog
	e := db.WithTx(ctx, false, func(tx *store.Tx) error {
		projects, e := tx.All(ctx, "SELECT id FROM jm_projects")
		if e != nil {
			return e
		}
		projectIDs := make([]string, 0, len(projects))
		for _, p := range projects {
			projectIDs = append(projectIDs, stringValue(p["id"]))
		}
		sources, e := tx.All(ctx, "SELECT * FROM jm_approved_sources WHERE enabled=? AND status=?", true, "approved")
		if e != nil {
			return e
		}
		var approvals []Approval
		var hosts []string
		for _, s := range sources {
			details := object(s["details_json"])
			allowedProjects := projectIDs
			if p := stringValue(s["project_id"]); p != "" {
				allowedProjects = []string{p}
			}
			approval := Approval{SourceID: stringValue(s["id"]), Projects: allowedProjects, URL: stringValue(s["url"]), MirrorPath: stringValue(details["mirror_path"]), Commits: stringsValue(s["allowed_commits"])}
			if approval.MirrorPath != "" {
				approval.URL = ""
			}
			limits := []struct {
				key    string
				target *int64
			}{{"max_bytes", &approval.MaxBytes}, {"max_files", &approval.MaxFiles}, {"max_git_bytes", &approval.MaxGitBytes}, {"max_git_files", &approval.MaxGitFiles}}
			for _, entry := range limits {
				if v, exists := details[entry.key]; exists {
					n, ok := integer(v)
					if !ok || n < 1 {
						return fmt.Errorf("%w: invalid source bound", ErrUnsafe)
					}
					*entry.target = n
				}
			}
			approvals = append(approvals, approval)
			hosts = append(hosts, stringsValue(s["allowed_hosts"])...)
		}
		registry, e := NewRegistry(approvals, hosts)
		if e != nil {
			return e
		}
		images, e := tx.All(ctx, "SELECT * FROM jm_runtime_images WHERE enabled=? AND approved=? AND status=?", true, true, "approved")
		if e != nil {
			return e
		}
		datasets, e := tx.All(ctx, "SELECT * FROM jm_participant_bindings WHERE enabled=?", true)
		if e != nil {
			return e
		}
		secrets, e := tx.All(ctx, "SELECT * FROM jm_secret_references WHERE enabled=?", true)
		if e != nil {
			return e
		}
		imageMap := map[string]string{}
		datasetMap := map[string][]string{}
		var secretIDs []string
		for _, v := range images {
			imageMap[stringValue(v["id"])] = stringValue(v["digest"])
		}
		for _, v := range datasets {
			datasetMap[stringValue(v["id"])] = []string{stringValue(v["participant_id"])}
		}
		for _, v := range secrets {
			secretIDs = append(secretIDs, stringValue(v["id"]))
		}
		catalog, e = NewCatalog(registry, imageMap, datasetMap, secretIDs)
		if e != nil {
			return e
		}
		for _, v := range images {
			catalog.RuntimeProjects[stringValue(v["id"])] = stringValue(v["project_id"])
		}
		for _, v := range datasets {
			catalog.DatasetProjects[stringValue(v["id"])] = stringValue(v["project_id"])
		}
		for _, v := range secrets {
			catalog.SecretProjects[stringValue(v["id"])] = stringValue(v["project_id"])
		}
		catalog.Database = db
		return nil
	})
	return catalog, e
}
func (c *Catalog) Refresh(ctx context.Context) (*Catalog, error) {
	if c.Database != nil {
		return FromDatabase(ctx, c.Database)
	}
	return c, nil
}
func (c *Catalog) Validate(ctx context.Context, spec domain.JobSpec) (string, error) {
	if c.Database != nil {
		current, e := c.Refresh(ctx)
		if e != nil {
			return "", e
		}
		current.Database = nil
		return current.Validate(ctx, spec)
	}
	if _, e := c.Registry.Authorize(spec.ProjectID, spec.SourceID, spec.SourceCommit); e != nil {
		return "", e
	}
	digest, ok := c.RuntimeImages[spec.RuntimeImage]
	if !ok {
		for _, v := range c.RuntimeImages {
			if v == spec.RuntimeImage {
				digest = v
				ok = true
				break
			}
		}
	}
	if !ok {
		return "", fmt.Errorf("%w: runtime image not approved", ErrUnsafe)
	}
	projectAllowed := false
	for id, v := range c.RuntimeImages {
		if v == digest && (c.RuntimeProjects[id] == "" || c.RuntimeProjects[id] == spec.ProjectID) {
			projectAllowed = true
		}
	}
	if !projectAllowed {
		return "", fmt.Errorf("%w: runtime image not approved for project", ErrUnsafe)
	}
	for _, p := range spec.Participants {
		if !contains(c.DatasetBindings[p.DatasetBinding], p.ParticipantID) || (c.DatasetProjects[p.DatasetBinding] != "" && c.DatasetProjects[p.DatasetBinding] != spec.ProjectID) {
			return "", fmt.Errorf("%w: participant dataset not approved", ErrUnsafe)
		}
	}
	for _, ref := range spec.SecretRefs {
		if !c.SecretRefs[ref] || (c.SecretProjects[ref] != "" && c.SecretProjects[ref] != spec.ProjectID) {
			return "", fmt.Errorf("%w: secret reference not approved", ErrUnsafe)
		}
	}
	return digest, nil
}
