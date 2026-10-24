package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

type fixture struct {
	t           *testing.T
	db          *store.DB
	scheduler   *Scheduler
	now         time.Time
	sequence    int
	databaseURL string
}

func newFixture(t *testing.T, capacity int64) *fixture {
	t.Helper()
	ctx := context.Background()
	databaseURL := "sqlite:///" + filepath.Join(t.TempDir(), "manager.db")
	db, e := store.Open(ctx, databaseURL)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	f := &fixture{t: t, db: db, databaseURL: databaseURL, now: time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)}
	f.scheduler = New(db, WithClock(func() time.Time { return f.now.Add(time.Minute) }))
	f.insert("jm_projects", map[string]any{"id": "project", "name": "Project"})
	f.pool("cpu", capacity, 100000)
	return f
}
func (f *fixture) insert(table string, row map[string]any) {
	f.t.Helper()
	if e := f.db.WithTx(context.Background(), true, func(tx *store.Tx) error { return tx.Insert(context.Background(), table, row) }); e != nil {
		f.t.Fatalf("insert %s: %v", table, e)
	}
}
func (f *fixture) update(table string, id string, changes map[string]any) {
	f.t.Helper()
	if e := f.db.WithTx(context.Background(), true, func(tx *store.Tx) error {
		return tx.Update(context.Background(), table, map[string]any{"id": id}, changes)
	}); e != nil {
		f.t.Fatal(e)
	}
}
func (f *fixture) pool(id string, cpu, disk int64) {
	f.insert("jm_pools", map[string]any{"id": id, "name": id, "node_id": "node-" + id, "cpu_millicores": cpu, "memory_bytes": int64(100000), "disk_bytes": disk, "gpu_uuids": []string{}, "gpu_profiles": []string{}, "sandbox_profiles": []string{"runsc-cpu-v1"}, "healthy": true, "quarantined": false})
}
func standardSpec(cpu int64) domain.JobSpec {
	r := domain.ResourceRequest{PoolID: "cpu", CPUMillicores: cpu, MemoryBytes: 100, DiskBytes: 100, SandboxProfile: "runsc-cpu-v1"}
	return domain.JobSpec{ProjectID: "project", Name: "Federation", SourceID: "source", SourceCommit: strings.Repeat("a", 40), RuntimeImage: "cpu-image", Plugin: "lenet", Options: map[string]any{}, SecretRefs: map[string]string{}, Participants: []domain.ParticipantSpec{{ParticipantID: "alice", DatasetBinding: "alice-data", Mode: "external"}, {ParticipantID: "bob", DatasetBinding: "bob-data", Mode: "external"}}, Components: []domain.ComponentSpec{{ComponentID: "owner", Role: "owner", Resources: r}}, TargetRound: 2, MaxDurationSeconds: 600}
}
func (f *fixture) job(id string, cpu int64) domain.JobSpec { return f.jobSpec(id, standardSpec(cpu)) }
func (f *fixture) jobSpec(id string, spec domain.JobSpec) domain.JobSpec {
	f.t.Helper()
	digest, e := spec.Digest()
	if e != nil {
		f.t.Fatal(e)
	}
	f.sequence++
	f.insert("jm_jobs", map[string]any{"id": id, "project_id": "project", "creator_id": "creator", "name": id, "spec_json": spec.Map(), "spec_hash": digest, "state": "QUEUED", "phase": "waiting_resources", "target_round": spec.TargetRound, "current_attempt": int64(1), "attempt_count": int64(1), "created_at": f.now.Add(time.Duration(f.sequence) * time.Second), "updated_at": f.now})
	f.insert("jm_attempts", map[string]any{"id": id + "-a1", "job_id": id, "number": int64(1), "epoch": int64(1), "state": "QUEUED"})
	return spec
}
func (f *fixture) row(table, id string) map[string]any {
	f.t.Helper()
	v, e := f.db.One(context.Background(), "SELECT * FROM "+table+" WHERE id = ?", id)
	if e != nil {
		f.t.Fatal(e)
	}
	if v == nil {
		f.t.Fatalf("%s %s missing", table, id)
	}
	return v
}
func (f *fixture) rows(q string, args ...any) []map[string]any {
	f.t.Helper()
	r, e := f.db.All(context.Background(), q, args...)
	if e != nil {
		f.t.Fatal(e)
	}
	return r
}
func (f *fixture) schedule() []Admission {
	f.t.Helper()
	a, e := f.scheduler.Schedule(context.Background(), 100)
	if e != nil {
		f.t.Fatal(e)
	}
	return a
}
func (f *fixture) confirmAndRelease(jobID string) {
	f.t.Helper()
	allocations := f.rows("SELECT * FROM jm_allocations WHERE job_id = ? AND released_at IS NULL", jobID)
	for _, a := range allocations {
		f.update("jm_attempts", str(a["attempt_id"]), map[string]any{"revocation_confirmed": true, "termination_confirmed": true})
		f.update("jm_allocations", str(a["id"]), map[string]any{"termination_confirmed": true})
		if e := f.scheduler.Release(context.Background(), str(a["id"])); e != nil {
			f.t.Fatal(e)
		}
	}
}
func assertCode(t *testing.T, e error, code string) {
	t.Helper()
	var known *domain.Error
	if !errors.As(e, &known) || known.Code != code {
		t.Fatalf("error=%v; want %s", e, code)
	}
}
func queueCode(t *testing.T, f *fixture, id, code string) {
	t.Helper()
	r, e := f.scheduler.QueueReason(context.Background(), id)
	if e != nil {
		t.Fatal(e)
	}
	if r["code"] != code {
		t.Fatalf("queue %s=%v; want %s", id, r, code)
	}
}

func TestTwoConcurrentJobsAndQueuedThirdStartsAfterRelease(t *testing.T) {
	f := newFixture(t, 2000)
	f.job("first", 1000)
	f.job("second", 1000)
	f.job("third", 1000)
	admissions := f.schedule()
	if len(admissions) != 2 {
		t.Fatalf("admissions=%v", admissions)
	}
	if admissions[0].JobID != "first" || admissions[1].JobID != "second" {
		t.Fatal(admissions)
	}
	if f.row("jm_jobs", "third")["state"] != "QUEUED" {
		t.Fatal("third did not wait")
	}
	queueCode(t, f, "third", "capacity")
	if len(f.rows("SELECT * FROM jm_allocations WHERE released_at IS NULL")) != 2 {
		t.Fatal("not two allocations")
	}
	if len(f.rows("SELECT * FROM jm_outbox WHERE topic = ?", "dispatch")) != 2 {
		t.Fatal("not two durable dispatches")
	}
	f.confirmAndRelease("first")
	next := f.schedule()
	if len(next) != 1 || next[0].JobID != "third" {
		t.Fatalf("next=%v", next)
	}
	if len(f.rows("SELECT * FROM jm_allocations WHERE released_at IS NULL")) != 2 {
		t.Fatal("capacity not maintained")
	}
}
func TestGangNeverPartiallyReservesAcrossPools(t *testing.T) {
	f := newFixture(t, 1000)
	f.pool("remote", 1000, 100000)
	busy := standardSpec(1000)
	busy.Components[0].Resources.PoolID = "remote"
	f.jobSpec("busy", busy)
	f.schedule()
	gang := standardSpec(1000)
	managed := "alice-worker"
	participant := "alice"
	gang.Participants[0].Mode = "managed"
	gang.Participants[0].ComponentID = &managed
	gang.Components = append(gang.Components, domain.ComponentSpec{ComponentID: managed, Role: "participant", ParticipantID: &participant, Resources: domain.ResourceRequest{PoolID: "remote", CPUMillicores: 1000, MemoryBytes: 100, DiskBytes: 100, SandboxProfile: "runsc-cpu-v1"}})
	f.jobSpec("gang", gang)
	if a := f.schedule(); len(a) != 0 {
		t.Fatal(a)
	}
	if a := f.rows("SELECT * FROM jm_allocations WHERE job_id = ?", "gang"); len(a) != 0 {
		t.Fatal("partial gang reservation")
	}
	queueCode(t, f, "gang", "capacity")
}
func TestThreeBackfillsProtectOnlyContendedDimensions(t *testing.T) {
	f := newFixture(t, 1000)
	f.pool("other", 1000, 100000)
	f.job("holder", 500)
	f.schedule()
	f.job("oldest", 1000)
	for _, id := range []string{"small-a", "small-b", "small-c", "small-d"} {
		f.job(id, 100)
	}
	other := standardSpec(500)
	other.Components[0].Resources.PoolID = "other"
	f.jobSpec("unrelated", other)
	a := f.schedule()
	if len(a) != 4 {
		t.Fatalf("expected three backfills + unrelated pool, got %v", a)
	}
	for _, id := range []string{"small-a", "small-b", "small-c", "unrelated"} {
		if f.row("jm_jobs", id)["state"] != "PROVISIONING" {
			t.Fatal(id)
		}
	}
	if f.row("jm_jobs", "oldest")["backfill_count"] != int64(3) {
		t.Fatal(f.row("jm_jobs", "oldest"))
	}
	why, e := f.scheduler.QueueReason(context.Background(), "small-d")
	if e != nil {
		t.Fatal(e)
	}
	if why["protection"] != "older_request" {
		t.Fatalf("fourth backfill not blocked: %v", why)
	}
	f.confirmAndRelease("holder")
	for _, id := range []string{"small-a", "small-b", "small-c"} {
		f.confirmAndRelease(id)
	}
	next := f.schedule()
	if len(next) != 1 || next[0].JobID != "oldest" {
		t.Fatal(next)
	}
}
func TestMaxRunningJobsCountsGangsNotComponents(t *testing.T) {
	f := newFixture(t, 4000)
	f.update("jm_projects", "project", map[string]any{"quotas_json": map[string]any{"max_running_jobs": int64(1)}})
	gang := standardSpec(500)
	worker := "alice-worker"
	alice := "alice"
	gang.Participants[0].Mode = "managed"
	gang.Participants[0].ComponentID = &worker
	gang.Components = append(gang.Components, domain.ComponentSpec{ComponentID: worker, Role: "participant", ParticipantID: &alice, Resources: domain.ResourceRequest{PoolID: "cpu", CPUMillicores: 500, MemoryBytes: 100, DiskBytes: 100, SandboxProfile: "runsc-cpu-v1"}})
	f.jobSpec("gang", gang)
	f.job("later", 500)
	if a := f.schedule(); len(a) != 1 || a[0].JobID != "gang" || len(a[0].AllocationIDs) != 2 {
		t.Fatal(a)
	}
	queueCode(t, f, "later", "quota")
}
func TestHealthWaitsButPermanentOversizeAndProfilesAreRejected(t *testing.T) {
	f := newFixture(t, 1000)
	f.update("jm_pools", "cpu", map[string]any{"healthy": false})
	spec := f.job("queued", 1000)
	if e := f.db.WithTx(context.Background(), false, func(tx *store.Tx) error { return ValidateAdmission(context.Background(), tx, spec) }); e != nil {
		t.Fatal("health must not prevent queuing", e)
	}
	if a := f.schedule(); len(a) != 0 {
		t.Fatal(a)
	}
	queueCode(t, f, "queued", "dependencies")
	spec.Components[0].Resources.CPUMillicores = 1001
	e := f.db.WithTx(context.Background(), false, func(tx *store.Tx) error { return ValidateAdmission(context.Background(), tx, spec) })
	assertCode(t, e, "resource_request_exceeds_pool")
	spec.Components[0].Resources.CPUMillicores = 1000
	spec.Components[0].Resources.SandboxProfile = "unknown"
	e = f.db.WithTx(context.Background(), false, func(tx *store.Tx) error { return ValidateAdmission(context.Background(), tx, spec) })
	assertCode(t, e, "sandbox_profile_unavailable")
}
func TestQuotaIntersectsLegacyColumns(t *testing.T) {
	f := newFixture(t, 10000)
	f.update("jm_projects", "project", map[string]any{"quota_cpu_millicores": int64(1500), "quotas_json": map[string]any{"cpu_millicores": int64(5000)}})
	f.job("first", 1000)
	f.job("second", 1000)
	if a := f.schedule(); len(a) != 1 {
		t.Fatal(a)
	}
	queueCode(t, f, "second", "quota")
	spec := standardSpec(2000)
	e := f.db.WithTx(context.Background(), false, func(tx *store.Tx) error { return ValidateAdmission(context.Background(), tx, spec) })
	assertCode(t, e, "resource_request_exceeds_project_quota")
}
func TestGPUPlacementNeverDoubleAllocatesOverlappingPoolUUIDs(t *testing.T) {
	pools := map[string]map[string]any{
		"wide":   {"gpu_uuids": []string{"GPU-a", "GPU-b"}},
		"narrow": {"gpu_uuids": []string{"GPU-a"}},
	}
	assignment, ok := assignGPUs(map[string]Amounts{"wide": {"gpu_count": 1}, "narrow": {"gpu_count": 1}}, pools, map[string]bool{})
	if !ok || len(assignment["wide"]) != 1 || assignment["wide"][0] != "GPU-b" || assignment["narrow"][0] != "GPU-a" {
		t.Fatal(assignment)
	}
	if _, ok = assignGPUs(map[string]Amounts{"wide": {"gpu_count": 2}, "narrow": {"gpu_count": 1}}, pools, map[string]bool{}); ok {
		t.Fatal("overlapping UUID counted twice")
	}
	if _, ok = assignGPUs(map[string]Amounts{"narrow": {"gpu_count": 1}}, pools, map[string]bool{"GPU-a": true}); ok {
		t.Fatal("occupied GPU allocated")
	}
}
func TestRetainedStateAndPrepaidBudgetsStayChargedAfterComputeRelease(t *testing.T) {
	f := newFixture(t, 1000)
	f.update("jm_pools", "cpu", map[string]any{"disk_bytes": int64(350)})
	f.update("jm_projects", "project", map[string]any{"quotas_json": map[string]any{"disk_bytes": int64(1000), "retained_bytes": int64(1000)}})
	f.scheduler.AdmissionStorage = func(ctx context.Context, job map[string]any) ([]StoragePlan, error) {
		jid := str(job["id"])
		return []StoragePlan{
			{Kind: "execution_state", ExternalID: "state-" + jid, ComponentID: "owner", PoolID: "cpu", MaxBytes: 100, CoveredByAllocation: true, Details: map[string]any{"covered_by_allocation": true}},
			{Kind: "collection_budget", ExternalID: "collect-" + jid, ComponentID: "owner", PoolID: "cpu", MaxBytes: 150},
			{Kind: "log_budget", ExternalID: "logs-" + jid, ComponentID: "owner", PoolID: "cpu", MaxBytes: 100},
		}, nil
	}
	f.job("first", 1000)
	if a := f.schedule(); len(a) != 1 {
		t.Fatal(a)
	}
	project := f.row("jm_projects", "project")
	if project["retained_bytes"] != int64(350) {
		t.Fatalf("double or absent charge %v", project)
	}
	resources := f.rows("SELECT * FROM jm_provisioning_resources WHERE job_id = ?", "first")
	if len(resources) != 3 {
		t.Fatal(resources)
	}
	allocation := f.rows("SELECT * FROM jm_allocations WHERE job_id = ?", "first")[0]
	d := clone(obj(allocation["details_json"]))
	for _, key := range []string{"retained_resource_id", "collection_resource_id", "log_resource_id"} {
		if d[key] == nil {
			t.Fatal("missing prepaid pointer", key)
		}
	}
	d["retained_disk_charged"] = true
	d["storage_deleted"] = false
	f.update("jm_allocations", str(allocation["id"]), map[string]any{"details_json": d})
	f.confirmAndRelease("first")
	if f.row("jm_projects", "project")["retained_bytes"] != int64(350) {
		t.Fatal("release uncharged retained bytes")
	}
	var used int64
	if e := f.db.WithTx(context.Background(), false, func(tx *store.Tx) error {
		var e error
		used, e = PoolUsedBytes(context.Background(), tx, "cpu", "")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if used != 350 {
		t.Fatalf("retained physical pool charge=%d", used)
	}
	f.job("second", 1000)
	if a := f.schedule(); len(a) != 0 {
		t.Fatal("reused retained disk", a)
	}
	queueCode(t, f, "second", "capacity")
}
func TestForeignStorageResourceCannotBeAdopted(t *testing.T) {
	f := newFixture(t, 1000)
	f.job("foreign", 100)
	f.job("target", 100)
	f.insert("jm_provisioning_resources", map[string]any{"id": "foreign-resource", "job_id": "foreign", "component_id": "owner", "kind": "collection_budget", "external_id": "shared", "ownership_json": map[string]any{"job_id": "foreign", "component_id": "owner", "kind": "collection_budget"}, "details_json": map[string]any{"pool_id": "cpu"}})
	f.scheduler.AdmissionStorage = func(ctx context.Context, j map[string]any) ([]StoragePlan, error) {
		if j["id"] == "foreign" {
			return nil, nil
		}
		return []StoragePlan{{Kind: "collection_budget", ExternalID: "shared", ComponentID: "owner", PoolID: "cpu", MaxBytes: 100}}, nil
	}
	if _, e := f.scheduler.Schedule(context.Background(), 100); e == nil {
		t.Fatal("adopted foreign resource")
	}
	if a := f.rows("SELECT * FROM jm_allocations"); len(a) != 0 {
		t.Fatal("failed gang transaction committed allocations")
	}
}
func TestReleaseRequiresPersistedRevocationAndTermination(t *testing.T) {
	f := newFixture(t, 1000)
	f.job("job", 1000)
	a := f.schedule()[0]
	assertCode(t, f.scheduler.Release(context.Background(), a.AllocationIDs[0]), "allocation_termination_unconfirmed")
	f.update("jm_allocations", a.AllocationIDs[0], map[string]any{"termination_confirmed": true, "state": "QUARANTINED"})
	assertCode(t, f.scheduler.Release(context.Background(), a.AllocationIDs[0]), "allocation_termination_unconfirmed")
	f.job("next", 1000)
	if v := f.schedule(); len(v) != 0 {
		t.Fatal("quarantine released quota", v)
	}
	f.update("jm_attempts", a.AttemptID, map[string]any{"termination_confirmed": true, "revocation_confirmed": true})
	if e := f.scheduler.Release(context.Background(), a.AllocationIDs[0]); e != nil {
		t.Fatal(e)
	}
	if e := f.scheduler.Release(context.Background(), a.AllocationIDs[0]); e != nil {
		t.Fatal("idempotent release", e)
	}
	if v := f.schedule(); len(v) != 1 || v[0].JobID != "next" {
		t.Fatal(v)
	}
}
func TestDeadlineAndRetryDelayDoNotAllocate(t *testing.T) {
	f := newFixture(t, 1000)
	f.job("expired", 100)
	f.job("delayed", 100)
	f.update("jm_jobs", "expired", map[string]any{"deadline_at": f.now})
	f.update("jm_jobs", "delayed", map[string]any{"next_attempt_at": f.now.Add(time.Hour)})
	if a := f.schedule(); len(a) != 0 {
		t.Fatal(a)
	}
	if f.row("jm_jobs", "expired")["state"] != "CANCELLING" {
		t.Fatal("deadline not fenced")
	}
	if len(f.rows("SELECT * FROM jm_outbox WHERE topic = ?", "fence_stop")) != 1 {
		t.Fatal("missing durable fence")
	}
	f.schedule()
	if len(f.rows("SELECT * FROM jm_outbox WHERE topic = ?", "fence_stop")) != 1 {
		t.Fatal("duplicate deadline operation")
	}
	queueCode(t, f, "delayed", "dependencies")
}
func TestConcurrentSchedulersUseOneGangReservationBoundary(t *testing.T) {
	f := newFixture(t, 2000)
	for i := 0; i < 10; i++ {
		f.job(fmt.Sprintf("job-%02d", i), 1000)
	}
	// Two independent SQL pools exercise the cross-connection IMMEDIATE lock.
	db2, e := store.Open(context.Background(), f.databaseURL)
	if e != nil {
		t.Fatal(e)
	}
	defer db2.Close()
	second := New(db2, WithClock(f.scheduler.Clock))
	var wg sync.WaitGroup
	results := make(chan []Admission, 2)
	errs := make(chan error, 2)
	for _, sched := range []*Scheduler{f.scheduler, second} {
		wg.Add(1)
		go func(s *Scheduler) {
			defer wg.Done()
			a, e := s.Schedule(context.Background(), 100)
			results <- a
			errs <- e
		}(sched)
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	total := 0
	for a := range results {
		total += len(a)
	}
	if total != 2 {
		t.Fatalf("admitted %d jobs across two schedulers", total)
	}
	active := f.rows("SELECT * FROM jm_allocations WHERE released_at IS NULL")
	if len(active) != 2 {
		t.Fatal(active)
	}
	for _, a := range active {
		count := f.rows("SELECT * FROM jm_outbox WHERE job_id = ? AND topic = ?", a["job_id"], "dispatch")
		if len(count) != 1 {
			t.Fatal("duplicated dispatch")
		}
	}
}
func TestExactAccountingRejectsFractionsAndOverflow(t *testing.T) {
	for _, value := range []any{nil, true, -1, int64(-3), 1.0, "1.25", "NaN", "9223372036854775808"} {
		if _, e := ExactInteger(value); e == nil {
			t.Fatalf("accepted %#v", value)
		}
	}
	for _, value := range []any{int64(5), json.Number("5"), "5.000", []byte("500e-2")} {
		n, e := ExactInteger(value)
		if e != nil || n != 5 {
			t.Fatalf("%#v => %d,%v", value, n, e)
		}
	}
	if _, e := add(int64(^uint64(0)>>1), 1); e == nil {
		t.Fatal("overflow silently wrapped")
	}
}

// A separately owned PostgreSQL database is an explicit opt-in. Each invocation
// gets its own schema and never touches the public schema or another test run.
func TestPostgreSQLConcurrentGangAdmission(t *testing.T) {
	rawURL := os.Getenv("HF2L_GO_SCHEDULER_TEST_DATABASE_URL")
	if rawURL == "" {
		t.Skip("HF2L_GO_SCHEDULER_TEST_DATABASE_URL is required for PostgreSQL concurrency")
	}
	ctx := context.Background()
	admin, err := store.Open(ctx, rawURL)
	if err != nil {
		t.Fatal(err)
	}
	if admin.Dialect != "postgresql" {
		admin.Close()
		t.Fatal("PostgreSQL test URL must use PostgreSQL")
	}
	schema := "scheduler_" + domain.NewID()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); admin.Close() })
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	db, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err = db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, db: db, now: time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC), databaseURL: u.String()}
	f.scheduler = New(db, WithClock(func() time.Time { return f.now.Add(time.Minute) }))
	f.insert("jm_projects", map[string]any{"id": "project", "name": "Project"})
	f.pool("cpu", 2000, 100000)
	for i := 0; i < 10; i++ {
		f.job(fmt.Sprintf("pg-%02d", i), 1000)
	}
	secondDB, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer secondDB.Close()
	second := New(secondDB, WithClock(f.scheduler.Clock))
	var wg sync.WaitGroup
	admissions := make(chan []Admission, 2)
	errs := make(chan error, 2)
	for _, scheduler := range []*Scheduler{f.scheduler, second} {
		wg.Add(1)
		go func(s *Scheduler) { defer wg.Done(); a, e := s.Schedule(ctx, 100); admissions <- a; errs <- e }(scheduler)
	}
	wg.Wait()
	close(admissions)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	total := 0
	for values := range admissions {
		total += len(values)
	}
	if total != 2 {
		t.Fatalf("PostgreSQL admitted %d jobs instead of two", total)
	}
	active := f.rows("SELECT * FROM jm_allocations WHERE released_at IS NULL")
	if len(active) != 2 {
		t.Fatal("PostgreSQL overcommitted or lost allocations", active)
	}
	for _, allocation := range active {
		dispatches := f.rows("SELECT * FROM jm_outbox WHERE job_id = ? AND topic = ?", allocation["job_id"], "dispatch")
		if len(dispatches) != 1 {
			t.Fatal("PostgreSQL duplicated dispatch", dispatches)
		}
	}
	f.confirmAndRelease("pg-00")
	next := f.schedule()
	if len(next) != 1 || next[0].JobID != "pg-02" {
		t.Fatal("PostgreSQL did not advance queued job after release", next)
	}
}

func TestLifetimeBlobBudgetSurvivesRetryWithoutAnotherNamespaceCharge(t *testing.T) {
	f := newFixture(t, 1000)
	f.pool("objects", 0, 1000)
	f.update("jm_pools", "objects", map[string]any{"memory_bytes": int64(0), "details_json": map[string]any{"object_store": true}})
	spec := f.job("job", 1000)
	digest, err := spec.Digest()
	if err != nil {
		t.Fatal(err)
	}
	cap := int64(700)
	f.scheduler.AdmissionStorage = func(ctx context.Context, job map[string]any) ([]StoragePlan, error) {
		return []StoragePlan{{Kind: "exchange_blob_budget", ExternalID: "hf2l-exchange-blobs://job", ComponentID: "owner", PoolID: "objects", MaxBytes: cap, Details: map[string]any{"spec_digest": digest, "quota_bytes": int64(700), "principal_quota_bytes": int64(300), "reservation_max_bytes": int64(700), "absolute_target_round": int64(2), "participant_count": int64(2)}}}, nil
	}
	first := f.schedule()
	if len(first) != 1 {
		t.Fatal(first)
	}
	resource := f.rows("SELECT * FROM jm_provisioning_resources WHERE kind = ?", "exchange_blob_budget")[0]
	if resource["size_bytes"] != int64(700) || f.row("jm_projects", "project")["retained_bytes"] != int64(700) {
		t.Fatal("namespace not prepaid")
	}
	f.confirmAndRelease("job")
	f.update("jm_jobs", "job", map[string]any{"state": "QUEUED", "current_attempt": int64(2), "attempt_count": int64(2)})
	f.insert("jm_attempts", map[string]any{"id": "job-a2", "job_id": "job", "number": int64(2), "epoch": int64(2), "state": "QUEUED"})
	cap = 701
	if _, err = f.scheduler.Schedule(context.Background(), 100); err == nil {
		t.Fatal("changed lifetime cap accepted")
	}
	if f.row("jm_jobs", "job")["state"] != "QUEUED" {
		t.Fatal("failed reservation mutated job")
	}
	cap = 700
	second := f.schedule()
	if len(second) != 1 || second[0].AttemptID != "job-a2" || second[0].Epoch != 2 {
		t.Fatal(second)
	}
	resources := f.rows("SELECT * FROM jm_provisioning_resources WHERE kind = ?", "exchange_blob_budget")
	if len(resources) != 1 || resources[0]["id"] != resource["id"] {
		t.Fatal("retry created a second namespace allowance")
	}
	if f.row("jm_projects", "project")["retained_bytes"] != int64(700) {
		t.Fatal("retry charged allowance twice")
	}
}
func TestInvalidCoveredAndDuplicatePlansRollBackGang(t *testing.T) {
	for _, variant := range []string{"wrong-covered-size", "duplicate-copy"} {
		t.Run(variant, func(t *testing.T) {
			f := newFixture(t, 1000)
			f.job("job", 1000)
			f.scheduler.AdmissionStorage = func(ctx context.Context, job map[string]any) ([]StoragePlan, error) {
				if variant == "wrong-covered-size" {
					return []StoragePlan{{Kind: "execution_state", ExternalID: "state", ComponentID: "owner", PoolID: "cpu", MaxBytes: 99, CoveredByAllocation: true, Details: map[string]any{"covered_by_allocation": true}}}, nil
				}
				plan := StoragePlan{Kind: "collection_budget", ExternalID: "copy", ComponentID: "owner", PoolID: "cpu", MaxBytes: 100}
				return []StoragePlan{plan, plan}, nil
			}
			if _, err := f.scheduler.Schedule(context.Background(), 100); err == nil {
				t.Fatal("invalid trusted plan accepted")
			}
			if len(f.rows("SELECT * FROM jm_allocations")) != 0 || len(f.rows("SELECT * FROM jm_provisioning_resources")) != 0 {
				t.Fatal("invalid plan left resources")
			}
			if f.row("jm_projects", "project")["retained_bytes"] != int64(0) {
				t.Fatal("invalid plan leaked accounting")
			}
		})
	}
}

func TestTransactionalStoragePlannerReadsSameAdmissionTransaction(t *testing.T) {
	f := newFixture(t, 1000)
	f.job("job", 1000)
	calls := 0
	f.scheduler.AdmissionStorageTx = func(ctx context.Context, tx *store.Tx, job map[string]any) ([]StoragePlan, error) {
		calls++
		project, err := tx.One(ctx, "SELECT * FROM jm_projects WHERE id = ?", job["project_id"])
		if err != nil {
			return nil, err
		}
		if project == nil {
			return nil, errors.New("planner cannot see its project")
		}
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	admitted, err := f.scheduler.Schedule(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(admitted) != 1 || calls != 1 {
		t.Fatal(admitted, calls)
	}
}

func TestAcknowledgedExecutionCannotReleaseUnchargedPhysicalDisk(t *testing.T) {
	f := newFixture(t, 1000)
	f.job("job", 1000)
	admission := f.schedule()[0]
	f.update("jm_attempts", admission.AttemptID, map[string]any{"revocation_confirmed": true, "termination_confirmed": true})
	f.update("jm_allocations", admission.AllocationIDs[0], map[string]any{"acknowledged": true, "termination_confirmed": true})
	assertCode(t, f.scheduler.Release(context.Background(), admission.AllocationIDs[0]), "retained_resource_charge_unconfirmed")
	if f.row("jm_allocations", admission.AllocationIDs[0])["released_at"] != nil {
		t.Fatal("released unaccounted filesystem")
	}
	// A trusted physical deletion proof is an alternative to retaining a charge.
	f.update("jm_allocations", admission.AllocationIDs[0], map[string]any{"details_json": map[string]any{"storage_deleted": true}})
	if err := f.scheduler.Release(context.Background(), admission.AllocationIDs[0]); err != nil {
		t.Fatal(err)
	}
}
func TestReleasePreservesPrepaidExecutionChargeAutomatically(t *testing.T) {
	f := newFixture(t, 1000)
	f.scheduler.AdmissionStorage = func(ctx context.Context, job map[string]any) ([]StoragePlan, error) {
		return []StoragePlan{{Kind: "execution_state", ExternalID: "state", ComponentID: "owner", PoolID: "cpu", MaxBytes: 100, CoveredByAllocation: true, Details: map[string]any{"covered_by_allocation": true}}}, nil
	}
	f.job("job", 1000)
	admission := f.schedule()[0]
	f.update("jm_allocations", admission.AllocationIDs[0], map[string]any{"acknowledged": true})
	f.confirmAndRelease("job")
	allocation := f.row("jm_allocations", admission.AllocationIDs[0])
	if !yes(obj(allocation["details_json"])["retained_disk_charged"]) {
		t.Fatal("compute release lost prepaid physical charge")
	}
	var total int64
	err := f.db.WithTx(context.Background(), false, func(tx *store.Tx) error {
		var err error
		total, err = PoolUsedBytes(context.Background(), tx, "cpu", "")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if total != 100 {
		t.Fatalf("retained physical volume charge=%d", total)
	}
}

func TestTrustedResourceKindMatchesUnicodeAlphanumericContract(t *testing.T) {
	for _, kind := range []string{"source", "execution_state", "α_1"} {
		if !validKind(kind) {
			t.Fatal("rejected kind", kind)
		}
	}
	for _, kind := range []string{"", "___", "source/path", "source-key", strings.Repeat("a", 65)} {
		if validKind(kind) {
			t.Fatal("accepted invalid kind", kind)
		}
	}
}
