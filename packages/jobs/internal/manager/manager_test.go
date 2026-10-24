package manager

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/scheduler"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

type mgrFixture struct {
	t   *testing.T
	db  *store.DB
	m   *Manager
	now time.Time
}

func newMgrFixture(t *testing.T) *mgrFixture {
	t.Helper()
	ctx := context.Background()
	db, e := store.Open(ctx, "sqlite:///"+filepath.Join(t.TempDir(), "manager.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if _, e = db.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	return populateMgrFixture(t, db)
}

func populateMgrFixture(t *testing.T, db *store.DB) *mgrFixture {
	t.Helper()
	m, e := New(db, []byte(strings.Repeat("s", 32)))
	if e != nil {
		t.Fatal(e)
	}
	f := &mgrFixture{t: t, db: db, m: m, now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	m.Clock = func() time.Time { return f.now }
	f.insert("jm_projects", Object{"id": "research", "name": "Research", "quotas_json": Object{"cpu_millicores": int64(10000), "memory_bytes": int64(1000000), "disk_bytes": int64(1000000)}})
	f.insert("jm_project_members", Object{"project_id": "research", "principal_id": "owner", "role": "submitter"})
	f.insert("jm_approved_sources", Object{"id": "source", "project_id": "research", "name": "Source", "url": "https://example.com/model.git", "allowed_hosts": []string{"example.com"}, "allowed_commits": []string{strings.Repeat("a", 40)}})
	f.insert("jm_runtime_images", Object{"id": "image", "project_id": "research", "name": "CPU image", "digest": "sha256:" + strings.Repeat("b", 64)})
	f.insert("jm_pools", Object{"id": "cpu", "name": "CPU", "node_id": "node", "cpu_millicores": int64(10000), "memory_bytes": int64(1000000), "disk_bytes": int64(1000000), "sandbox_profiles": []string{"runsc-cpu-v1"}, "healthy": true})
	for _, pid := range []string{"alice", "bob"} {
		f.insert("jm_participant_bindings", Object{"id": pid + "-data", "project_id": "research", "participant_id": pid, "node_id": "node-" + pid, "dataset_label": pid + " data"})
	}
	return f
}
func (f *mgrFixture) insert(table string, row Object) {
	f.t.Helper()
	if e := f.db.WithTx(context.Background(), true, func(tx *store.Tx) error { return tx.Insert(context.Background(), table, row) }); e != nil {
		f.t.Fatalf("insert %s: %v", table, e)
	}
}
func (f *mgrFixture) update(table, id string, changes Object) {
	f.t.Helper()
	if e := f.db.WithTx(context.Background(), true, func(tx *store.Tx) error { return tx.Update(context.Background(), table, Object{"id": id}, changes) }); e != nil {
		f.t.Fatal(e)
	}
}
func mgrSpec() domain.JobSpec {
	return domain.JobSpec{ProjectID: "research", Name: "Federated classifier", SourceID: "source", SourceCommit: strings.Repeat("a", 40), RuntimeImage: "image", Plugin: "lenet", Options: Object{"batch_size": int64(8)}, SecretRefs: map[string]string{}, Participants: []domain.ParticipantSpec{{ParticipantID: "alice", DatasetBinding: "alice-data", Mode: "external"}, {ParticipantID: "bob", DatasetBinding: "bob-data", Mode: "external"}}, Components: []domain.ComponentSpec{{ComponentID: "owner", Role: "owner", Resources: domain.ResourceRequest{PoolID: "cpu", CPUMillicores: 1000, MemoryBytes: 1000, DiskBytes: 1000, SandboxProfile: "runsc-cpu-v1"}}}, TargetRound: 2, MaxDurationSeconds: 600}
}
func (f *mgrFixture) create(k string) Object {
	f.t.Helper()
	r, e := f.m.CreateJob(context.Background(), "owner", mgrSpec(), k)
	if e != nil {
		f.t.Fatal(e)
	}
	return r
}
func mgrError(t *testing.T, e error, status int, code string) {
	t.Helper()
	var known *domain.Error
	if !errors.As(e, &known) || known.Status != status || known.Code != code {
		t.Fatalf("error %v want %d %s", e, status, code)
	}
}
func TestManagerCreatePermissionPinningAndIdempotency(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	_, e := f.m.CreateJob(ctx, "outsider", mgrSpec(), "denied")
	mgrError(t, e, 403, "project_submitter_required")
	job := f.create("once")
	if job["role"] != "admin" || job["state"] != "QUEUED" {
		t.Fatal(job)
	}
	if obj(job["spec"])["runtime_image"] != "sha256:"+strings.Repeat("b", 64) {
		t.Fatal("image alias not pinned", job)
	}
	if _, ok := obj(job["spec"])["secret_refs"]; ok {
		t.Fatal("secret references in public view")
	}
	again, e := f.m.CreateJob(ctx, "owner", mgrSpec(), "once")
	if e != nil || again["id"] != job["id"] {
		t.Fatal(again, e)
	}
	changed := mgrSpec()
	changed.Name = "Changed"
	_, e = f.m.CreateJob(ctx, "owner", changed, "once")
	mgrError(t, e, 409, "idempotency_conflict")
	f.update("jm_runtime_images", "image", Object{"digest": "sha256:" + strings.Repeat("c", 64)})
	again, e = f.m.CreateJob(ctx, "owner", mgrSpec(), "once")
	if e != nil || obj(again["spec"])["runtime_image"] != obj(job["spec"])["runtime_image"] {
		t.Fatal("replay reresoled mutable alias", again, e)
	}
}
func TestManagerConcurrentCreationUsesOneOperationIdentity(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	results := make(chan string, 8)
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := f.m.CreateJob(ctx, "owner", mgrSpec(), "concurrent")
			if e != nil {
				failures <- e
			} else {
				results <- text(r["id"])
			}
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for e := range failures {
		t.Fatal(e)
	}
	one := ""
	for id := range results {
		if one == "" {
			one = id
		}
		if id != one {
			t.Fatal("duplicate jobs", one, id)
		}
	}
	r, e := f.db.One(ctx, "SELECT COUNT(*) AS n FROM jm_jobs")
	if e != nil || number(r["n"]) != 1 {
		t.Fatal(r, e)
	}
}
func TestManagerProjectMembershipDoesNotGrantExistingJobVisibility(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	job := f.create("private")
	f.insert("jm_project_members", Object{"project_id": "research", "principal_id": "colleague", "role": "admin"})
	f.m.PlatformOperatorIDs["platform"] = true
	for _, actor := range []string{"colleague", "platform"} {
		_, e := f.m.GetJob(ctx, actor, text(job["id"]))
		mgrError(t, e, 404, "job_not_found")
		page, e := f.m.ListJobs(ctx, actor, Object{}, 50, "")
		if e != nil || len(arr(page["items"])) != 0 {
			t.Fatal(page, e)
		}
	}
	catalog, e := f.m.Catalog(ctx, "colleague")
	if e != nil || len(arr(catalog["projects"])) != 1 {
		t.Fatal(catalog, e)
	}
}
func TestManagerCurrentRolesRevocationAndLastAdministrator(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	job := f.create("roles")
	id := text(job["id"])
	_, e := f.m.DeleteMember(ctx, "owner", id, "owner", number(job["version"]), "last")
	mgrError(t, e, 409, "last_job_admin_required")
	job, e = f.m.PutMember(ctx, "owner", id, "reader", "reader", number(job["version"]), "reader")
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.m.Cancel(ctx, "reader", id, number(job["version"]), "reader-cancel")
	mgrError(t, e, 403, "job_role_required")
	job, e = f.m.PutMember(ctx, "owner", id, "admin2", "admin", number(job["version"]), "second")
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.m.DeleteMember(ctx, "admin2", id, "owner", number(job["version"]), "revoke-owner")
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.m.GetJob(ctx, "owner", id)
	mgrError(t, e, 404, "job_not_found")
	_, e = f.m.CreateJob(ctx, "owner", mgrSpec(), "roles")
	mgrError(t, e, 404, "job_not_found")
}
func TestManagerCancelQueuesFencingAndPreservesReservations(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	job := f.create("cancel")
	id := text(job["id"])
	job, e := f.m.Cancel(ctx, "owner", id, number(job["version"]), "cancel-once")
	if e != nil {
		t.Fatal(e)
	}
	if job["state"] != "CANCELLING" || job["phase"] != "fencing" {
		t.Fatal(job)
	}
	out, e := f.db.All(ctx, "SELECT * FROM jm_outbox WHERE job_id = ?", id)
	if e != nil || len(out) != 1 || out[0]["topic"] != "fence_stop" {
		t.Fatal(out, e)
	}
	replay, e := f.m.Cancel(ctx, "owner", id, 1, "cancel-once")
	if e != nil || number(replay["version"]) != number(job["version"]) {
		t.Fatal(replay, e)
	}
	_, e = f.m.Cancel(ctx, "owner", id, 1, "stale")
	mgrError(t, e, 409, "job_version_conflict")
}
func TestManagerRetryReconcilePurgeGuards(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	job := f.create("lifecycle")
	id := text(job["id"])
	_, e := f.m.Retry(ctx, "owner", id, 1, "not-failed")
	mgrError(t, e, 409, "job_retry_requires_failed")
	f.update("jm_jobs", id, Object{"state": "FAILED", "deadline_at": f.now.Add(-time.Second)})
	_, e = f.m.Retry(ctx, "owner", id, 1, "deadline")
	mgrError(t, e, 409, "job_deadline_expired")
	f.update("jm_jobs", id, Object{"deadline_at": nil, "cleanup_status": "expiry_pending"})
	_, e = f.m.Retry(ctx, "owner", id, 1, "expired")
	mgrError(t, e, 409, "job_artifacts_expired")
	f.update("jm_jobs", id, Object{"cleanup_status": "none", "state": "NEEDS_ATTENTION"})
	_, e = f.m.Reconcile(ctx, "owner", id, 1, "bad", Object{"outcome": "published"})
	mgrError(t, e, 422, "reconciliation_evidence_required")
	job, e = f.m.Reconcile(ctx, "owner", id, 1, "evidence", Object{"publication_id": "publication", "outcome": "published", "evidence_ref": "verified-receipt"})
	if e != nil || job["state"] != "RECONCILING" {
		t.Fatal(job, e)
	}
	f.update("jm_jobs", id, Object{"state": "SUCCEEDED"})
	attempt, e := f.db.One(ctx, "SELECT id FROM jm_attempts WHERE job_id = ?", id)
	if e != nil {
		t.Fatal(e)
	}
	f.insert("jm_allocations", Object{"job_id": id, "attempt_id": attempt["id"], "component_id": "owner", "pool_id": "cpu", "cpu_millicores": 1000, "memory_bytes": 1000, "disk_bytes": 1000, "epoch": 1})
	_, e = f.m.Purge(ctx, "owner", id, number(job["version"]), "active")
	mgrError(t, e, 409, "job_runtime_not_confirmed_stopped")
	_, e = f.db.Exec(ctx, "UPDATE jm_allocations SET released_at = ? WHERE job_id = ?", f.now, id)
	if e != nil {
		t.Fatal(e)
	}
	job, e = f.m.Purge(ctx, "owner", id, number(job["version"]), "purge")
	if e != nil || obj(job["retention"])["cleanup_status"] != "purge_pending" {
		t.Fatal(job, e)
	}
	raw, e := f.db.One(ctx, "SELECT purged_at FROM jm_jobs WHERE id = ?", id)
	if e != nil || raw["purged_at"] != nil {
		t.Fatal("purge prematurely deleted bytes", raw, e)
	}
}
func TestManagerPaginationCursorScopesExpiryAndLiteralSearch(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	for _, name := range []string{"100% useful", "ordinary", "last"} {
		f.now = f.now.Add(time.Second)
		s := mgrSpec()
		s.Name = name
		if _, e := f.m.CreateJob(ctx, "owner", s, name); e != nil {
			t.Fatal(e)
		}
	}
	p, e := f.m.ListJobs(ctx, "owner", Object{"view": "queued"}, 1, "")
	if e != nil || number(p["total"]) != 3 || text(p["next_cursor"]) == "" {
		t.Fatal(p, e)
	}
	cursor := text(p["next_cursor"])
	next, e := f.m.ListJobs(ctx, "owner", Object{"view": "queued"}, 1, cursor)
	if e != nil || arr(next["items"])[0].(map[string]any)["id"] == arr(p["items"])[0].(map[string]any)["id"] {
		t.Fatal(next, e)
	}
	_, e = f.m.ListJobs(ctx, "foreign", Object{"view": "queued"}, 1, cursor)
	mgrError(t, e, 422, "invalid_cursor")
	_, e = f.m.ListJobs(ctx, "owner", Object{"view": "history"}, 1, cursor)
	mgrError(t, e, 422, "invalid_cursor")
	p, e = f.m.ListJobs(ctx, "owner", Object{"search": "100%"}, 50, "")
	if e != nil || len(arr(p["items"])) != 1 {
		t.Fatal(p, e)
	}
	f.now = f.now.Add(time.Hour + time.Second)
	_, e = f.m.ListJobs(ctx, "owner", Object{"view": "queued"}, 1, cursor)
	mgrError(t, e, 409, "cursor_expired")
}
func TestManagerAdmissionRejectsInvalidDependenciesWithoutPartialJobs(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	s := mgrSpec()
	s.Components[0].Resources.CPUMillicores = 10001
	_, e := f.m.CreateJob(ctx, "owner", s, "oversize")
	mgrError(t, e, 422, "resource_request_exceeds_project_quota")
	f.update("jm_runtime_images", "image", Object{"enabled": false})
	_, e = f.m.CreateJob(ctx, "owner", mgrSpec(), "unapproved")
	mgrError(t, e, 422, "runtime_image_not_approved")
	row, e := f.db.One(ctx, "SELECT COUNT(*) AS n FROM jm_jobs")
	if e != nil || number(row["n"]) != 0 {
		t.Fatal("partial rejected job", row, e)
	}
}
func TestManagerStoragePlanningCountsEveryOwnedCopy(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	f.m.StoragePlanner = func(context.Context, Object) ([]scheduler.StoragePlan, error) {
		return []scheduler.StoragePlan{{Kind: "source", ComponentID: "owner", PoolID: "cpu", ExternalID: "source-snapshot", MaxBytes: 1000001}}, nil
	}
	_, e := f.m.CreateJob(ctx, "owner", mgrSpec(), "space")
	mgrError(t, e, 422, "resource_request_exceeds_pool")
	f.m.StoragePlanner = func(context.Context, Object) ([]scheduler.StoragePlan, error) {
		return []scheduler.StoragePlan{{Kind: "source", ComponentID: "owner", PoolID: "cpu", ExternalID: "same", MaxBytes: 1}, {Kind: "source", ComponentID: "owner", PoolID: "cpu", ExternalID: "same", MaxBytes: 1}}, nil
	}
	_, e = f.m.CreateJob(ctx, "owner", mgrSpec(), "duplicate")
	mgrError(t, e, 422, "storage_plan_unavailable")
}
func TestManagerArtifactMetadataAndOwnedLocatorChecks(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	job := f.create("artifacts")
	id := text(job["id"])
	f.insert("jm_provisioning_resources", Object{"id": "resource", "job_id": id, "kind": "execution_state", "external_id": "owned-state", "ownership_json": Object{"job_id": id}})
	f.insert("jm_artifacts", Object{"id": "artifact", "job_id": id, "kind": "checkpoint", "name": "model.safetensors", "size_bytes": int64(8), "sha256": strings.Repeat("a", 64), "storage_key": "not-public", "locator_json": Object{"kind": "local", "resource_id": "resource", "relative_path": "outputs/model.safetensors"}})
	descriptor, e := f.m.ArtifactStorage(ctx, "owner", id, "artifact")
	if e != nil || obj(descriptor["locator"])["resource_id"] != "resource" {
		t.Fatal(descriptor, e)
	}
	meta, e := f.m.GetArtifact(ctx, "owner", id, "artifact")
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := meta["storage_key"]; ok {
		t.Fatal("storage key exposed")
	}
	if _, ok := meta["locator"]; ok {
		t.Fatal("private locator exposed")
	}
	f.update("jm_provisioning_resources", "resource", Object{"ownership_json": Object{"job_id": "foreign"}})
	_, e = f.m.ArtifactStorage(ctx, "owner", id, "artifact")
	mgrError(t, e, 503, "invalid_artifact_locator")
	f.update("jm_jobs", id, Object{"artifacts_expire_at": f.now})
	_, e = f.m.ArtifactStorage(ctx, "owner", id, "artifact")
	mgrError(t, e, 410, "artifact_expired")
	meta, e = f.m.GetArtifact(ctx, "owner", id, "artifact")
	if e != nil || meta["download_available"] != false {
		t.Fatal(meta, e)
	}
}
func TestManagerLogBoundedPaginationAndExpiration(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	job := f.create("logs")
	id := text(job["id"])
	for i := int64(1); i <= 17; i++ {
		f.insert("jm_log_chunks", Object{"job_id": id, "component": "owner", "attempt_number": 1, "sequence": i, "data": strings.Repeat("x", 65536), "created_at": f.now.Add(time.Duration(i) * time.Second)})
	}
	p, e := f.m.ListLogs(ctx, "owner", id, 100, "", "", nil)
	if e != nil || len(arr(p["items"])) != 16 || number(p["bytes_returned"]) != 1048576 || text(p["next_cursor"]) == "" {
		t.Fatal("log cap", p, e)
	}
	next, e := f.m.ListLogs(ctx, "owner", id, 100, text(p["next_cursor"]), "", nil)
	if e != nil || len(arr(next["items"])) != 1 {
		t.Fatal(next, e)
	}
	f.update("jm_jobs", id, Object{"artifacts_expire_at": f.now})
	p, e = f.m.ListLogs(ctx, "owner", id, 100, "", "", nil)
	if e != nil || number(p["bytes_returned"]) != 0 || len(arr(p["items"])) != 17 {
		t.Fatal(p, e)
	}
	for _, v := range arr(p["items"]) {
		r := obj(v)
		if r["data"] != "" || r["expired"] != true {
			t.Fatal(r)
		}
	}
}
func TestManagerPoolQualificationAccountingAndAdminVisibility(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	f.m.PlatformOperatorIDs["platform"] = true
	_, e := f.m.ListPools(ctx, "owner")
	mgrError(t, e, 403, "platform_operator_required")
	_, e = f.m.PutPool(ctx, "platform", "new", Object{"name": "New", "node_id": "new-node", "healthy": true, "cpu_millicores": int64(1000)})
	mgrError(t, e, 409, "pool_qualification_required")
	f.m.PoolQualifier = func(context.Context, Object) (bool, error) { return true, nil }
	pool, e := f.m.PutPool(ctx, "platform", "new", Object{"name": "New", "node_id": "new-node", "healthy": true, "cpu_millicores": int64(1000)})
	if e != nil || number(pool["version"]) != 2 {
		t.Fatal(pool, e)
	}
	f.insert("jm_provisioning_resources", Object{"id": "retained", "job_id": text(f.create("pool")["id"]), "kind": "source", "external_id": "retained-source", "retained": true, "size_bytes": int64(500), "details_json": Object{"pool_id": "new"}})
	_, e = f.m.PutPool(ctx, "platform", "new", Object{"disk_bytes": int64(499)})
	mgrError(t, e, 409, "pool_capacity_below_retained_storage")
	f.update("jm_pools", "new", Object{"details_json": Object{"manager_storage": true}})
	_, e = f.m.PutPool(ctx, "platform", "new", Object{"healthy": false})
	mgrError(t, e, 409, "manager_storage_pool_requires_trusted_cli")
}
func TestManagerVisibleRevisionChangesOnlyAuthorizedContent(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	job := f.create("revision")
	id := text(job["id"])
	first, e := f.m.VisibleRevision(ctx, "outsider")
	if e != nil {
		t.Fatal(e)
	}
	f.insert("jm_log_chunks", Object{"job_id": id, "component": "owner", "attempt_number": 1, "sequence": 1, "data": "private", "created_at": f.now})
	second, e := f.m.VisibleRevision(ctx, "outsider")
	if e != nil || first != second {
		t.Fatal("foreign content invalidates outsider stream", first, second, e)
	}
	visible, e := f.m.VisibleRevision(ctx, "owner")
	if e != nil {
		t.Fatal(e)
	}
	f.insert("jm_log_chunks", Object{"job_id": id, "component": "owner", "attempt_number": 1, "sequence": 2, "data": "next", "created_at": f.now.Add(time.Second)})
	newer, e := f.m.VisibleRevision(ctx, "owner")
	if e != nil || visible == newer {
		t.Fatal("visible content not invalidated", visible, newer, e)
	}
}

func TestManagerTransactionalStoragePlannerUsesOwningTransaction(t *testing.T) {
	f := newMgrFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	called := false
	f.m.StoragePlanner = func(context.Context, Object) ([]scheduler.StoragePlan, error) {
		panic("pure fallback used instead of transaction")
	}
	f.m.StoragePlannerTx = func(ctx context.Context, tx *store.Tx, job Object) ([]scheduler.StoragePlan, error) {
		called = true
		project, e := tx.One(ctx, "SELECT id FROM jm_projects WHERE id = ?", obj(job["spec_json"])["project_id"])
		if e != nil {
			return nil, e
		}
		if project == nil {
			return nil, errors.New("project not visible")
		}
		return []scheduler.StoragePlan{{Kind: "source", ComponentID: "owner", PoolID: "cpu", ExternalID: "source-snapshot", MaxBytes: 10}}, nil
	}
	if _, e := f.m.CreateJob(ctx, "owner", mgrSpec(), "tx-storage"); e != nil || !called {
		t.Fatal(called, e)
	}
}
func TestManagerPythonCursorCompatibility(t *testing.T) {
	raw, e := os.ReadFile("testdata/python-cursors.json")
	if e != nil {
		t.Fatal(e)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var fixture Object
	if e = decoder.Decode(&fixture); e != nil {
		t.Fatal(e)
	}
	for _, v := range arr(fixture["cases"]) {
		test := obj(v)
		now := number(test["now"])
		m := &Manager{CursorSecret: []byte(text(fixture["secret"])), Clock: func() time.Time { return time.Unix(now, 0) }}
		encoded, e := m.encodeCursor(text(test["principal"]), text(test["kind"]), test["filters"], test["position"])
		if e != nil || encoded != test["cursor"] {
			t.Fatalf("Python cursor mismatch %s: %s != %s (%v)", text(test["kind"]), encoded, test["cursor"], e)
		}
		got, e := m.decodeCursor(encoded, text(test["principal"]), text(test["kind"]), test["filters"])
		if e != nil {
			t.Fatal(e)
		}
		want, e := domain.CanonicalJSON(test["position"])
		if e != nil {
			t.Fatal(e)
		}
		actual, e := domain.CanonicalJSON(got)
		if e != nil || string(actual) != string(want) {
			t.Fatal(string(actual), string(want), e)
		}
	}
}

func TestManagerSelfDemotionReturnsCurrentPermissions(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	job := f.create("self-demote")
	id := text(job["id"])
	job, e := f.m.PutMember(ctx, "owner", id, "admin2", "admin", number(job["version"]), "second-admin")
	if e != nil {
		t.Fatal(e)
	}
	job, e = f.m.PutMember(ctx, "owner", id, "owner", "reader", number(job["version"]), "self-demote")
	if e != nil {
		t.Fatal(e)
	}
	if job["role"] != "reader" || len(arr(job["allowed_actions"])) != 0 {
		t.Fatal("response retained superseded administrator rights", job)
	}
	_, e = f.m.Cancel(ctx, "owner", id, number(job["version"]), "forbidden")
	mgrError(t, e, 403, "job_role_required")
}

func TestManagerObservationsRespectCurrentEpochAndResourceOwnership(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	job := f.create("observations")
	id := text(job["id"])
	attempt, e := f.db.One(ctx, "SELECT id FROM jm_attempts WHERE job_id = ?", id)
	if e != nil {
		t.Fatal(e)
	}
	f.update("jm_jobs", id, Object{"state": "RUNNING", "phase": "waiting_participants", "epoch": int64(1)})
	f.update("jm_attempts", text(attempt["id"]), Object{"state": "RUNNING", "details_json": Object{"components": Object{"owner": Object{"metrics": Object{"accuracy": json.Number("0.9"), "untrusted_text": "do not expose"}, "readiness": "ready", "observed_at": iso(f.now), "current_round": int64(1), "phase": "aggregating"}}}})
	f.insert("jm_provisioning_resources", Object{"id": "space-resource", "job_id": id, "kind": "exchange_space", "external_id": "space-owned", "ownership_json": Object{"job_id": id}})
	f.insert("jm_provisioning_resources", Object{"id": "space-foreign-owner", "job_id": id, "kind": "exchange_space", "external_id": "space-not-owned", "ownership_json": Object{"job_id": "foreign"}})
	for _, pid := range []string{"alice", "bob"} {
		owner := id
		if pid == "bob" {
			owner = "foreign"
		}
		f.insert("jm_provisioning_resources", Object{"job_id": id, "attempt_id": attempt["id"], "kind": "external_enrollment", "external_id": "enrollment-" + pid, "ownership_json": Object{"job_id": owner, "participant_id": pid}, "details_json": Object{"participant_id": pid, "dataset_binding": pid + "-data", "node_id": "node-" + pid, "epoch": int64(1), "status": "enrolled", "phase": "training", "last_heartbeat": iso(f.now)}})
	}
	view, e := f.m.GetJob(ctx, "owner", id)
	if e != nil {
		t.Fatal(e)
	}
	if len(obj(view["metrics"])) != 1 || obj(view["metrics"])["accuracy"] != json.Number("0.9") || view["space_id"] != "space-owned" {
		t.Fatal(view)
	}
	participants := arr(view["participants"])
	if obj(participants[0])["readiness"] != "training" || obj(participants[1])["readiness"] != "not_observed" {
		t.Fatal("foreign enrollment attributed", participants)
	}
	components := arr(obj(view["progress"])["components"])
	if obj(components[0])["freshness"] != "current" || number(obj(components[0])["reported_round"]) != 1 {
		t.Fatal(components)
	}
	f.now = f.now.Add(301 * time.Second)
	view, e = f.m.GetJob(ctx, "owner", id)
	if e != nil || obj(view["progress"])["freshness"] != "stale" {
		t.Fatal(view, e)
	}
	f.update("jm_jobs", id, Object{"epoch": int64(2)})
	view, e = f.m.GetJob(ctx, "owner", id)
	if e != nil || len(obj(view["metrics"])) != 0 {
		t.Fatal("stale epoch metrics shown", view, e)
	}
	history, e := f.m.ListAttempts(ctx, "owner", id)
	if e != nil {
		t.Fatal(e)
	}
	historicalComponents := arr(obj(arr(history["items"])[0])["components"])
	if len(obj(obj(historicalComponents[0])["metrics"])) != 1 {
		t.Fatal("historical report lost", history)
	}
}
