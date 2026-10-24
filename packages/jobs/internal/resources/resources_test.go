package resources

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	"golang.org/x/sys/unix"
)

func owned(t *testing.T) *OwnedDirectories {
	t.Helper()
	o, err := NewOwnedDirectories(filepath.Join(t.TempDir(), "owned"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { o.Close() })
	return o
}
func TestConcurrentEnsureAndImmutableOwnership(t *testing.T) {
	o := owned(t)
	digest := strings.Repeat("a", 64)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := o.EnsureJob("job", digest); errs <- err }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := o.ValidateJob("job", digest); err != nil {
		t.Fatal(err)
	}
	if _, err := o.EnsureJob("job", strings.Repeat("b", 64)); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("foreign specification accepted %v", err)
	}
	entries, err := os.ReadDir(o.Root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("staging leaked %v %v", entries, err)
	}
	marker := filepath.Join(o.Root, "job", ".owner.json")
	if _, err = os.Stat(marker); err != nil {
		t.Fatal("ownership marker lost after rename", err)
	}
}
func TestSymlinkAncestorAndMarkerHardLinkRefused(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewOwnedDirectories(filepath.Join(base, "link", "owned")); !errors.Is(err, ErrUnsafe) {
		t.Fatal("symlink ancestor accepted", err)
	}
	o := owned(t)
	if _, err := o.EnsureJob("job", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(o.Root, "job", ".owner.json")
	if err := os.Link(marker, filepath.Join(base, "marker-copy")); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ValidateJob("job"); !errors.Is(err, ErrUnsafe) {
		t.Fatal("hardlinked marker accepted", err)
	}
	if err := o.Purge("job", strings.Repeat("a", 64)); !errors.Is(err, ErrUnsafe) {
		t.Fatal("purged untrusted ownership", err)
	}
}
func TestComponentPurgeAndOutsideLinks(t *testing.T) {
	o := owned(t)
	digest := strings.Repeat("a", 64)
	if _, err := o.EnsureJob("job", digest); err != nil {
		t.Fatal(err)
	}
	paths, err := o.Components("job", []string{"alice", "bob"})
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err = os.WriteFile(outside, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, filepath.Join(paths["alice"].State, "outside")); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(paths["bob"].State, "keep"), []byte("bob"), 0600); err != nil {
		t.Fatal(err)
	}
	if removed, err := o.PurgeComponent("job", "alice", digest); err != nil || !removed {
		t.Fatalf("component purge %v %v", removed, err)
	}
	if content, err := os.ReadFile(outside); err != nil || string(content) != "keep" {
		t.Fatal("outside file changed", err)
	}
	if _, err = os.Stat(filepath.Join(paths["bob"].State, "keep")); err != nil {
		t.Fatal("sibling removed", err)
	}
	if removed, err := o.PurgeComponent("job", "alice", digest); err != nil || removed {
		t.Fatalf("repeat purge %v %v", removed, err)
	}
	if err = o.Purge("job", digest); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(o.Root, "job")); !os.IsNotExist(err) {
		t.Fatal("job remains", err)
	}
}
func TestPurgeRefusesUnknownMaterialBeforeAnyDeletion(t *testing.T) {
	o := owned(t)
	digest := strings.Repeat("a", 64)
	path, err := o.EnsureJob("job", digest)
	if err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(path, "keep")
	if err = os.WriteFile(good, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = unix.Mkfifo(filepath.Join(path, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = o.Purge("job", digest); !errors.Is(err, ErrUnsafe) {
		t.Fatal("special file accepted", err)
	}
	if data, err := os.ReadFile(good); err != nil || string(data) != "keep" {
		t.Fatal("partial deletion occurred", err)
	}
}
func TestRootReplacementAndAtomicMetadataSafety(t *testing.T) {
	o := owned(t)
	old := o.Root + "-old"
	if err := os.Rename(o.Root, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(o.Root, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := o.EnsureJob("job", strings.Repeat("a", 64)); !errors.Is(err, ErrUnsafe) {
		t.Fatal("replaced root accepted", err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "metadata")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := AtomicJSON(link, map[string]any{"overwrite": true}, 0600); !errors.Is(err, ErrUnsafe) {
		t.Fatal("symlink metadata accepted", err)
	}
	if data, _ := os.ReadFile(outside); string(data) != "keep" {
		t.Fatal("foreign bytes changed")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := AtomicJSON(link, map[string]any{"ok": true}, 0600); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(link); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("private atomic metadata mode", st, err)
	}
}
func TestEmptySkeletonRequiresEveryEntryProvenEmpty(t *testing.T) {
	o := owned(t)
	path := filepath.Join(o.Root, "job", "attempts", "attempt", "alice")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "unknown"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if removed, err := o.PurgeEmptyNeverStarted("job", "attempt", []string{"alice"}); removed || !errors.Is(err, ErrUnsafe) {
		t.Fatal("unknown material adopted", removed, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("partial skeleton removal", err)
	}
	if err := os.Remove(filepath.Join(path, "unknown")); err != nil {
		t.Fatal(err)
	}
	if removed, err := o.PurgeEmptyNeverStarted("job", "attempt", []string{"alice"}); err != nil || !removed {
		t.Fatal("valid empty skeleton not pruned", removed, err)
	}
	if removed, err := o.PurgeEmptyNeverStarted("job", "attempt", []string{"alice"}); err != nil || removed {
		t.Fatal("repeat skeleton removal", removed, err)
	}
}
func testDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(context.Background(), "sqlite:///"+filepath.Join(t.TempDir(), "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err = db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return db
}
func testSpec(t *testing.T) domain.JobSpec {
	t.Helper()
	raw := `{"project_id":"research","name":"Test","source_id":"source","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","runtime_image":"image","plugin":"lenet","participants":[{"participant_id":"alice","dataset_binding":"alice"},{"participant_id":"bob","dataset_binding":"bob"}],"components":[{"component_id":"owner","role":"owner","resources":{"pool_id":"cpu","cpu_millicores":1000,"memory_bytes":1024,"disk_bytes":64}}],"target_round":2,"max_duration_seconds":600}`
	spec, err := domain.DecodeJobSpec([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}
func seedJob(t *testing.T, db *store.DB, jobID string) map[string]any {
	t.Helper()
	ctx := context.Background()
	spec := testSpec(t)
	digest, err := spec.Digest()
	if err != nil {
		t.Fatal(err)
	}
	err = db.WithTx(ctx, true, func(tx *store.Tx) error {
		if row, e := tx.One(ctx, "SELECT id FROM jm_projects WHERE id='research'"); e != nil {
			return e
		} else if row == nil {
			if e = tx.Insert(ctx, "jm_projects", map[string]any{"id": "research", "name": "Research"}); e != nil {
				return e
			}
		}
		return tx.Insert(ctx, "jm_jobs", map[string]any{"id": jobID, "project_id": "research", "creator_id": "creator", "name": "Test", "spec_json": spec.Map(), "spec_hash": digest, "state": "RUNNING", "epoch": 1, "target_round": spec.TargetRound})
	})
	if err != nil {
		t.Fatal(err)
	}
	job, err := db.One(ctx, "SELECT * FROM jm_jobs WHERE id=?", jobID)
	if err != nil {
		t.Fatal(err)
	}
	return job
}
func TestLedgerIntentReplayAndForeignOwnership(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	seedJob(t, db, "job")
	seedJob(t, db, "other")
	ledger := NewLedger(db)
	req := OperationRequest{JobID: "job", ComponentID: "owner", Operation: "space", Key: "space-key", Desired: map[string]any{"name": "space"}}
	calls := 0
	action := func(context.Context) (map[string]any, error) {
		calls++
		row, e := db.One(ctx, "SELECT state FROM jm_provisioning_operations WHERE idempotency_key='space-key'")
		if e != nil || row["state"] != "executing" {
			t.Fatal("external effect happened without durable intent", row, e)
		}
		return map[string]any{"space": "space"}, nil
	}
	for i := 0; i < 2; i++ {
		got, err := ledger.Run(ctx, req, action)
		if err != nil || got["space"] != "space" {
			t.Fatal(got, err)
		}
	}
	if calls != 1 {
		t.Fatal("idempotent operation repeated", calls)
	}
	req.Desired = map[string]any{"name": "changed"}
	if _, err := ledger.Run(ctx, req, action); !errors.Is(err, ErrUnsafe) {
		t.Fatal("changed desired request adopted", err)
	}
	id, err := ledger.Own(ctx, Ownership{JobID: "job", ComponentID: "owner", Kind: "space", ExternalID: "shared"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ledger.Own(ctx, Ownership{JobID: "other", ComponentID: "owner", Kind: "space", ExternalID: "shared"}); !errors.Is(err, ErrUnsafe) {
		t.Fatal("foreign resource adopted", err)
	}
	if err = ledger.Deleted(ctx, id, "other"); !errors.Is(err, ErrUnsafe) {
		t.Fatal("foreign resource deleted", err)
	}
	if err = ledger.Deleted(ctx, id, "job"); err != nil {
		t.Fatal(err)
	}
}
func TestLedgerUnknownFailureBusyAndStaleClaimFencing(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	seedJob(t, db, "job")
	ledger := NewLedger(db)
	req := OperationRequest{JobID: "job", ComponentID: "owner", Operation: "space", Key: "failure", Desired: map[string]any{}}
	_, err := ledger.Run(ctx, req, func(context.Context) (map[string]any, error) { return nil, errors.New("sensitive external response") })
	if err == nil {
		t.Fatal("external failure lost")
	}
	row, err := db.One(ctx, "SELECT * FROM jm_provisioning_operations WHERE idempotency_key='failure'")
	if err != nil || row["state"] != "unknown" || row["last_error"] != "external_operation_failed" {
		t.Fatal("unsafe failure receipt", row, err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ledger.Clock = func() time.Time { return now }
	req.Key = "stale"
	entered := make(chan struct{})
	release := make(chan struct{})
	oldDone := make(chan error, 1)
	go func() {
		_, e := ledger.Run(ctx, req, func(context.Context) (map[string]any, error) {
			close(entered)
			<-release
			return map[string]any{"worker": "old"}, nil
		})
		oldDone <- e
	}()
	<-entered
	var effects atomic.Int32
	if _, err = ledger.Run(ctx, req, func(context.Context) (map[string]any, error) { effects.Add(1); return nil, nil }); !errors.Is(err, ErrBusy) || effects.Load() != 0 {
		t.Fatal("active claim stolen", err)
	}
	// Advance via a separate ledger/clock, avoiding a data race on the old claim.
	recovered := NewLedger(db)
	recovered.Clock = func() time.Time { return now.Add(6 * time.Minute) }
	result, err := recovered.Run(ctx, req, func(context.Context) (map[string]any, error) { return map[string]any{"worker": "new"}, nil })
	if err != nil || result["worker"] != "new" {
		t.Fatal(result, err)
	}
	close(release)
	if err = <-oldDone; !errors.Is(err, ErrBusy) {
		t.Fatal("stale claim overwrote successor", err)
	}
	row, err = db.One(ctx, "SELECT * FROM jm_provisioning_operations WHERE idempotency_key='stale'")
	if err != nil || object(row["observed_json"])["worker"] != "new" {
		t.Fatal(row, err)
	}
}
func seedBudget(t *testing.T, db *store.DB, job map[string]any) string {
	t.Helper()
	ctx := context.Background()
	budget, err := CheckpointBudget(testSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	err = db.WithTx(ctx, true, func(tx *store.Tx) error {
		if _, e := tx.One(ctx, "SELECT id FROM jm_pools WHERE id='objects'"); e != nil {
			return e
		}
		if row, e := tx.One(ctx, "SELECT id FROM jm_pools WHERE id='objects'"); e != nil {
			return e
		} else if row == nil {
			return tx.Insert(ctx, "jm_pools", map[string]any{"id": "objects", "name": "Objects", "node_id": "object-store", "disk_bytes": int64(1 << 30), "healthy": true, "details_json": map[string]any{"object_store": true}})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanBlobBudget(job, "objects", nil)
	if err != nil {
		t.Fatal(err)
	}
	details := object(plan["details"])
	details["retention_charged_bytes"] = budget.QuotaBytes
	details["retention_reservation_bytes"] = budget.QuotaBytes
	details["size_bytes"] = budget.QuotaBytes
	id, err := NewLedger(db).Own(ctx, Ownership{JobID: str(job["id"]), ComponentID: budget.ComponentID, Kind: BlobBudgetKind, ExternalID: str(plan["external_id"]), Details: details, Retained: true})
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func TestBlobBudgetPreservesBindingAndRejectsOverflow(t *testing.T) {
	spec := testSpec(t)
	budget, err := CheckpointBudget(spec)
	if err != nil || budget.QuotaBytes != 448 || budget.PrincipalQuotaBytes != 192 {
		t.Fatal(budget, err)
	}
	spec.Components[0].Resources.DiskBytes = 1 << 50
	spec.TargetRound = 1000000
	if _, err = CheckpointBudget(spec); !errors.Is(err, ErrUnsafe) {
		t.Fatal("overflow accepted", err)
	}
	db := testDB(t)
	job := seedJob(t, db, "job")
	id := seedBudget(t, db, job)
	rows, err := NewLedger(db).Resources(context.Background(), "job", ResourceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanBlobBudget(job, "different", rows)
	if err != nil || plan["pool_id"] != "objects" {
		t.Fatal("reservation rebound", plan, err)
	}
	if err = NewLedger(db).Deleted(context.Background(), id, "job"); err != nil {
		t.Fatal(err)
	}
	rows, _ = NewLedger(db).Resources(context.Background(), "job", ResourceFilter{})
	if _, err = PlanBlobBudget(job, "objects", rows); !errors.Is(err, ErrUnsafe) {
		t.Fatal("deleted budget resurrected", err)
	}
}
func TestBlobCleanupRequiresTerminalAndAuthoritativeOwnedRetirement(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	job := seedJob(t, db, "job")
	id := seedBudget(t, db, job)
	calls := 0
	service := NewBlobBudgetService(db, func(context.Context, string, string) (bool, error) { calls++; return true, nil })
	if _, err := service.Require(ctx, job, false); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLedger(db).Own(ctx, Ownership{JobID: "job", ComponentID: "owner", Kind: "exchange_space", ExternalID: "space"}); err != nil {
		t.Fatal(err)
	}
	if err := service.BindSpace(ctx, job, "space", map[string]any{"id": "space", "quota_bytes": int64(448), "principal_quota_bytes": int64(192)}, false); err != nil {
		t.Fatal(err)
	}
	observation := map[string]any{"job_id": "job", "space_id": "space", "status": "retired", "cleanup_pending": false}
	if _, err := service.ConfirmCleanup(ctx, job, "space", observation); !errors.Is(err, ErrUnsafe) || calls != 0 {
		t.Fatal("running job budget released", err, calls)
	}
	if _, err := db.Exec(ctx, "UPDATE jm_jobs SET state='SUCCEEDED' WHERE id='job'"); err != nil {
		t.Fatal(err)
	}
	observation["cleanup_pending"] = true
	if released, err := service.ConfirmCleanup(ctx, job, "space", observation); err != nil || released || calls != 0 {
		t.Fatal("pending provider cleanup released", released, err)
	}
	observation["cleanup_pending"] = false
	if released, err := service.ConfirmCleanup(ctx, job, "space", observation); err != nil || !released || calls != 1 {
		t.Fatal("confirmed cleanup failed", released, err, calls)
	}
	row, err := db.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id=?", id)
	if err != nil || row["state"] != "deleted" || object(row["details_json"])["blob_cleanup_confirmed"] != true {
		t.Fatal(row, err)
	}
}
func TestUnusedBudgetCannotInferAbsenceAfterAnyCreateIntent(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	job := seedJob(t, db, "job")
	seedBudget(t, db, job)
	calls := 0
	service := NewBlobBudgetService(db, func(context.Context, string, string) (bool, error) { calls++; return true, nil })
	if _, err := db.Exec(ctx, "UPDATE jm_jobs SET state='CANCELLED' WHERE id='job'"); err != nil {
		t.Fatal(err)
	}
	err := db.WithTx(ctx, true, func(tx *store.Tx) error {
		return tx.Insert(ctx, "jm_provisioning_operations", map[string]any{"id": "operation", "job_id": "job", "component_id": "owner", "operation": "exchange_space", "idempotency_key": "uncertain-create"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if released, err := service.ConfirmUnused(ctx, job); err != nil || released || calls != 0 {
		t.Fatal("uncertain namespace absence assumed", released, err, calls)
	}
}
