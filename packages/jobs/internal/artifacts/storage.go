package artifacts

import (
	"context"
	"math"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

// Storage supplies the controller's durable collection and retention boundary.
// Its effects are separate from executor termination and physical purge proofs.
type Storage struct {
	DB           *store.DB
	Retention    *Retention
	Logs         *LogService
	ExecutorRoot string
	Clock        func() time.Time
}

func NewStorage(db *store.DB, reader LogReader) *Storage {
	return &Storage{DB: db, Retention: NewRetention(db), Logs: &LogService{DB: db, ReadLogs: reader}}
}
func (s *Storage) now() time.Time {
	if s.Clock != nil {
		return s.Clock().UTC()
	}
	return time.Now().UTC()
}
func (s *Storage) retention() *Retention {
	clock := s.Clock
	if s.Retention != nil {
		if clock == nil {
			clock = s.Retention.Clock
		}
		return &Retention{DB: s.Retention.DB, Clock: clock}
	}
	return &Retention{DB: s.DB, Clock: clock}
}

func (s *Storage) RequestExpiry(ctx context.Context) error {
	_, e := s.retention().RequestExpiry(ctx)
	return e
}
func storageStableKey(parts ...string) string {
	values := make([]any, len(parts))
	for i, p := range parts {
		values[i] = p
	}
	raw, _ := domain.CanonicalJSON(values)
	return digest(raw)
}
func storageLocks(ctx context.Context, tx *store.Tx, job, attempt, allocation map[string]any) (pool, project, storedJob, stored map[string]any, err error) {
	pool, err = tx.One(ctx, "SELECT * FROM jm_pools WHERE id = ?"+tx.ForUpdate(), allocation["pool_id"])
	if err != nil {
		return
	}
	project, err = tx.One(ctx, "SELECT * FROM jm_projects WHERE id = ?"+tx.ForUpdate(), job["project_id"])
	if err != nil {
		return
	}
	storedJob, err = tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?"+tx.ForUpdate(), job["id"])
	if err != nil {
		return
	}
	stored, err = tx.One(ctx, "SELECT * FROM jm_allocations WHERE id = ?"+tx.ForUpdate(), allocation["id"])
	if err != nil {
		return
	}
	if pool == nil || project == nil || storedJob == nil || stored == nil || stored["job_id"] != job["id"] || stored["attempt_id"] != attempt["id"] || stored["component_id"] != allocation["component_id"] || integer(storedJob["epoch"]) != integer(attempt["epoch"]) || integer(storedJob["current_attempt"]) != integer(attempt["number"]) || integer(stored["epoch"]) != integer(attempt["epoch"]) {
		err = domain.Err(409, "stale_epoch")
	}
	return
}
func (s *Storage) ReserveCollection(ctx context.Context, job, attempt, allocation map[string]any) error {
	disk := integer(allocation["disk_bytes"])
	if disk < 0 || disk > math.MaxInt64-4<<20 {
		return domain.Err(422, "unsafe_output")
	}
	cap := disk + 4<<20
	return s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		pool, project, _, stored, e := storageLocks(ctx, tx, job, attempt, allocation)
		if e != nil {
			return e
		}
		details := copyMap(stored["details_json"])
		var resource map[string]any
		if id := text(details["collection_resource_id"]); id != "" {
			resource, e = tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?"+tx.ForUpdate(), id)
		} else {
			resource, e = tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE kind = ? AND external_id = ?"+tx.ForUpdate(), "collection_budget", allocation["id"])
		}
		if e != nil {
			return e
		}
		if resource != nil && (resource["job_id"] != job["id"] || text(resource["kind"]) != "collection_budget" || resource["component_id"] != allocation["component_id"] || mapping(resource["details_json"])["pool_id"] != allocation["pool_id"]) {
			return domain.Err(409, "unsafe_output")
		}
		if resource == nil {
			resource = map[string]any{"id": storageStableKey("collection-budget", text(allocation["id"]))[:32], "job_id": job["id"], "attempt_id": attempt["id"], "component_id": allocation["component_id"], "kind": "collection_budget", "external_id": allocation["id"], "ownership_json": map[string]any{"job_id": job["id"], "attempt_id": attempt["id"], "component_id": allocation["component_id"], "epoch": allocation["epoch"]}, "details_json": map[string]any{"pool_id": allocation["pool_id"], "node_id": mapping(allocation["details_json"])["node_id"]}, "state": "planned", "retained": true, "size_bytes": int64(0), "created_at": s.now(), "updated_at": s.now()}
			if e = tx.Insert(ctx, "jm_provisioning_resources", resource); e != nil {
				return e
			}
		}
		if _, e = ReserveInTransaction(ctx, tx, resource, project, pool, cap); e != nil {
			return e
		}
		details["collection_resource_id"] = resource["id"]
		if e = tx.Update(ctx, "jm_allocations", map[string]any{"id": allocation["id"]}, map[string]any{"details_json": details}); e != nil {
			return e
		}
		allocation["details_json"] = details
		return nil
	})
}
func (s *Storage) RetainExecutionState(ctx context.Context, job, attempt, allocation map[string]any) error {
	return s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		_, project, _, stored, e := storageLocks(ctx, tx, job, attempt, allocation)
		if e != nil {
			return e
		}
		details := copyMap(stored["details_json"])
		var resource map[string]any
		if id := text(details["retained_resource_id"]); id != "" {
			resource, e = tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?"+tx.ForUpdate(), id)
		} else {
			resource, e = tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE kind = ? AND external_id = ?"+tx.ForUpdate(), "execution_state", allocation["id"])
		}
		if e != nil {
			return e
		}
		if resource != nil && (resource["job_id"] != job["id"] || resource["attempt_id"] != attempt["id"] || text(resource["kind"]) != "execution_state" || resource["component_id"] != allocation["component_id"] || (mapping(resource["details_json"])["pool_id"] != nil && mapping(resource["details_json"])["pool_id"] != allocation["pool_id"])) {
			return domain.Err(409, "unsafe_output")
		}
		if resource == nil {
			resource = map[string]any{"id": domain.NewID(), "job_id": job["id"], "attempt_id": attempt["id"], "component_id": allocation["component_id"], "kind": "execution_state", "external_id": allocation["id"], "ownership_json": map[string]any{"job_id": job["id"], "attempt_id": attempt["id"], "component_id": allocation["component_id"], "epoch": allocation["epoch"]}, "details_json": map[string]any{"pool_id": allocation["pool_id"]}, "state": "retained", "retained": true, "size_bytes": int64(0), "created_at": s.now(), "updated_at": s.now()}
			if e = tx.Insert(ctx, "jm_provisioning_resources", resource); e != nil {
				return e
			}
		}
		if _, e = ChargeInTransaction(ctx, tx, resource, project, integer(allocation["disk_bytes"])); e != nil {
			return e
		}
		if e = tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": resource["id"]}, map[string]any{"state": "retained"}); e != nil {
			return e
		}
		details["retained_disk_charged"] = true
		details["retained_resource_id"] = resource["id"]
		details["storage_deleted"] = false
		if e = tx.Update(ctx, "jm_allocations", map[string]any{"id": allocation["id"]}, map[string]any{"details_json": details}); e != nil {
			return e
		}
		allocation["details_json"] = details
		return nil
	})
}
func collectedRoot(item domain.CollectedArtifact, identity LogIdentity, nodeID, executorRoot string) (string, error) {
	fake := &SafeCollector{fd: 0, Options: CollectorOptions{MaxDepth: 64}}
	if _, e := fake.parts(item.Path); e != nil {
		return "", domain.Err(422, "unsafe_output")
	}
	if item.Locator == "" || len(item.Locator) > 1024 || item.SizeBytes < 0 || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(item.SHA256) {
		return "", domain.Err(422, "unsafe_output")
	}
	u, e := url.Parse(item.Locator)
	if e != nil {
		return "", domain.Err(422, "unsafe_output")
	}
	if u.Scheme == "hf2l-node" {
		segments := strings.Split(item.Path, "/")
		for i, part := range segments {
			segments[i] = url.PathEscape(part)
		}
		expected := "/" + identity.Key() + "/" + strings.Join(segments, "/")
		if nodeID == "" || u.Host != nodeID || u.EscapedPath() != expected || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return "", domain.Err(422, "unsafe_output")
		}
		return "hf2l-node://" + nodeID + "/" + identity.Key(), nil
	}
	if u.Scheme != "" || !filepath.IsAbs(item.Locator) || strings.ContainsAny(item.Locator, "\x00\\") {
		return "", domain.Err(422, "unsafe_output")
	}
	parts := strings.Split(item.Path, "/")
	root := item.Locator
	for range parts {
		root = filepath.Dir(root)
	}
	if filepath.Join(root, filepath.FromSlash(item.Path)) != item.Locator {
		return "", domain.Err(422, "unsafe_output")
	}
	if executorRoot != "" {
		base := filepath.Join(executorRoot, identity.Key(), "retained")
		allowed := root == filepath.Join(base, "state") || root == filepath.Join(base, "runtime") || (root == base && (strings.HasPrefix(item.Path, "state/") || strings.HasPrefix(item.Path, "runtime/")))
		if !allowed {
			return "", domain.Err(422, "unsafe_output")
		}
	}
	return root, nil
}
func (s *Storage) StoreCollected(ctx context.Context, job, attempt, allocation map[string]any, files []domain.CollectedArtifact) error {
	if len(files) > 1000 {
		return domain.Err(422, "unsafe_output")
	}
	identity := LogIdentity{text(job["id"]), text(attempt["id"]), text(allocation["component_id"]), integer(allocation["epoch"])}
	if e := identity.Validate(); e != nil {
		return e
	}
	return s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		pool, project, storedJob, stored, e := storageLocks(ctx, tx, job, attempt, allocation)
		if e != nil {
			return e
		}
		d := mapping(stored["details_json"])
		var reservation map[string]any
		if id := text(d["collection_resource_id"]); id != "" {
			reservation, e = tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?"+tx.ForUpdate(), id)
		} else {
			reservation, e = tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE kind = ? AND external_id = ?"+tx.ForUpdate(), "collection_budget", allocation["id"])
		}
		if e != nil {
			return e
		}
		if reservation == nil {
			return domain.Err(409, "retained_resource_reservation_required")
		}
		nodeID := text(d["node_id"])
		if nodeID == "" {
			nodeID = text(pool["node_id"])
		}
		ownership := map[string]any{"job_id": job["id"], "attempt_id": attempt["id"], "component_id": allocation["component_id"], "epoch": allocation["epoch"]}
		children := []map[string]any{}
		seen := map[string]bool{}
		for _, item := range files {
			if item.Locator == "" {
				continue
			}
			if seen[item.Locator] {
				return domain.Err(422, "unsafe_output")
			}
			seen[item.Locator] = true
			root, e := collectedRoot(item, identity, nodeID, s.ExecutorRoot)
			if e != nil {
				return e
			}
			rootResource, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE kind = ? AND external_id = ?", "retained_artifact_root", root)
			if e != nil {
				return e
			}
			if rootResource == nil {
				rootResource = map[string]any{"id": domain.NewID(), "job_id": job["id"], "attempt_id": attempt["id"], "component_id": allocation["component_id"], "kind": "retained_artifact_root", "external_id": root, "ownership_json": ownership, "details_json": map[string]any{"root": root, "pool_id": allocation["pool_id"], "node_id": d["node_id"]}, "state": "retained", "retained": true, "size_bytes": int64(0), "created_at": s.now(), "updated_at": s.now()}
				if e = tx.Insert(ctx, "jm_provisioning_resources", rootResource); e != nil {
					return e
				}
			}
			if !sameJSON(rootResource["ownership_json"], ownership) || rootResource["job_id"] != job["id"] || rootResource["component_id"] != allocation["component_id"] {
				return domain.Err(409, "unsafe_output")
			}
			existing, e := tx.One(ctx, "SELECT * FROM jm_artifacts WHERE job_id = ? AND storage_key = ?", job["id"], item.Locator)
			if e != nil {
				return e
			}
			resource, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE kind = ? AND external_id = ?", "retained_output", item.Locator)
			if e != nil {
				return e
			}
			if existing != nil {
				if text(existing["sha256"]) != item.SHA256 || integer(existing["size_bytes"]) != item.SizeBytes {
					return domain.Err(409, "unsafe_output")
				}
				if resource == nil {
					return domain.Err(409, "retained_storage_ledger_inconsistent")
				}
			}
			if resource == nil {
				resource = map[string]any{"id": domain.NewID(), "job_id": job["id"], "attempt_id": attempt["id"], "component_id": allocation["component_id"], "kind": "retained_output", "external_id": item.Locator, "ownership_json": ownership, "state": "retained", "retained": true, "size_bytes": item.SizeBytes, "details_json": map[string]any{"pool_id": allocation["pool_id"], "node_id": d["node_id"]}, "created_at": s.now(), "updated_at": s.now()}
				if e = tx.Insert(ctx, "jm_provisioning_resources", resource); e != nil {
					return e
				}
			}
			if integer(resource["size_bytes"]) != item.SizeBytes || !sameJSON(resource["ownership_json"], ownership) {
				return domain.Err(409, "retained_resource_charge_conflict")
			}
			children = append(children, resource)
			if existing != nil {
				continue
			}
			kind := "output"
			if strings.HasSuffix(item.Path, ".bin") || strings.HasSuffix(item.Path, ".pt") || strings.HasSuffix(item.Path, ".safetensors") {
				kind = "checkpoint"
			} else if item.Kind == "log" {
				kind = "log"
			}
			name := text(allocation["component_id"]) + "/" + item.Path
			runes := []rune(name)
			if len(runes) > 256 {
				name = string(runes[:256])
			}
			locator := map[string]any{"kind": "local", "resource_id": rootResource["id"], "relative_path": item.Path}
			if e = tx.Insert(ctx, "jm_artifacts", map[string]any{"id": domain.NewID(), "job_id": job["id"], "attempt_number": attempt["number"], "kind": kind, "name": name, "size_bytes": item.SizeBytes, "sha256": item.SHA256, "storage_key": item.Locator, "locator_json": locator, "state": "retained", "created_at": s.now(), "expires_at": storedJob["artifacts_expire_at"]}); e != nil {
				return e
			}
		}
		_, e = TransferReservedInTransaction(ctx, tx, reservation, project, children, true)
		return e
	})
}
func (s *Storage) IngestLogs(ctx context.Context, allocation map[string]any, terminal bool) error {
	if s.Logs == nil {
		return domain.Err(503, "log_storage_unavailable")
	}
	logs := *s.Logs
	if s.Clock != nil {
		logs.Clock = s.Clock
	}
	max := 1
	if terminal {
		max = 32
	}
	_, e := logs.IngestComponentLogs(ctx, text(allocation["id"]), terminal, max)
	return e
}
func (s *Storage) ConfirmJobDataDeleted(ctx context.Context, jobID string) error {
	_, e := s.retention().ConfirmJobDataDeleted(ctx, jobID)
	return e
}
func (s *Storage) AppendLogsInTransaction(ctx context.Context, tx *store.Tx, job, attempt, allocation map[string]any, data string) error {
	if len(data) > 65536 || !utf8.ValidString(data) {
		return domain.Err(422, "log_chunk_exceeds_bound")
	}
	project, e := tx.One(ctx, "SELECT * FROM jm_projects WHERE id = ?"+tx.ForUpdate(), job["project_id"])
	if e != nil {
		return e
	}
	if project == nil {
		return domain.Err(404, "job_not_found")
	}
	_, e = appendLogInTx(ctx, tx, project, job, attempt, allocation, data, s.now())
	return e
}
