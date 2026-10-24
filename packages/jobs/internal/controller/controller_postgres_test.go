package controller

import (
	"context"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func ctlPostgresFixture(t *testing.T, state string) *ctlFixture {
	t.Helper()
	dsn := os.Getenv("GO_CONTROLLER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("GO_CONTROLLER_TEST_DATABASE_URL required")
	}
	source := newCtlFixture(t, state)
	admin, e := store.Open(source.ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	schema := "ctl_" + fmtNewID()
	if _, e = admin.Exec(source.ctx, "CREATE SCHEMA "+schema); e != nil {
		admin.Close()
		t.Fatal(e)
	}
	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal(e)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, e := store.Open(source.ctx, u.String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		db.Close()
		_, e := admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
		if e != nil {
			t.Errorf("owned schema cleanup: %v", e)
		}
	})
	if _, e = db.Migrate(source.ctx); e != nil {
		t.Fatal(e)
	}
	for _, table := range []string{"jm_projects", "jm_pools", "jm_jobs", "jm_attempts", "jm_allocations", "jm_provisioning_operations"} {
		rows, e := source.db.All(source.ctx, "SELECT * FROM "+table)
		if e != nil {
			t.Fatal(e)
		}
		if e = db.WithTx(source.ctx, true, func(tx *store.Tx) error {
			for _, row := range rows {
				if e := tx.Insert(source.ctx, table, row); e != nil {
					return e
				}
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	}
	source.publicationTestFixture.db = db
	source.c.DB = db
	return source
}
func TestControllerPostgreSQLConcurrentClaimsAndStaleOwner(t *testing.T) {
	f := ctlPostgresFixture(t, "RUNNING")
	topic := "claim-" + fmtNewID()
	const count = 12
	e := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
		for i := 0; i < count; i++ {
			id := fmtNewID()
			if e := tx.Insert(f.ctx, "jm_outbox", map[string]any{"id": id, "job_id": "job", "topic": topic, "idempotency_key": id, "state": "pending", "created_at": f.now}); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	claims := []Claim{}
	failures := []error{}
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := New(f.db, f.e, f.p)
			c.Clock = f.c.Clock
			claim, e := c.ClaimNext(f.ctx, []string{topic})
			mu.Lock()
			defer mu.Unlock()
			if e != nil {
				failures = append(failures, e)
			} else if claim != nil {
				claims = append(claims, *claim)
			}
		}()
	}
	wg.Wait()
	if len(failures) > 0 || len(claims) != count {
		t.Fatalf("claims %d, errors %v", len(claims), failures)
	}
	seen := map[string]bool{}
	for _, claim := range claims {
		if seen[claim.ID] {
			t.Fatal("duplicate simultaneous claim")
		}
		seen[claim.ID] = true
	}
	f.now = f.now.Add(6 * time.Minute)
	successor, e := f.c.ClaimNext(f.ctx, []string{topic})
	if e != nil || successor == nil {
		t.Fatal(e)
	}
	var old Claim
	for _, claim := range claims {
		if claim.ID == successor.ID {
			old = claim
			break
		}
	}
	if old.ID == "" {
		t.Fatal("missing expired claim")
	}
	if e = f.c.FinishClaim(f.ctx, old, true, ""); e != nil {
		t.Fatal(e)
	}
	row, e := f.db.One(f.ctx, "SELECT * FROM jm_outbox WHERE id=?", successor.ID)
	if e != nil {
		t.Fatal(e)
	}
	if str(row["state"]) != "processing" || str(row["lease_owner"]) != successor.Owner {
		t.Fatal("expired owner cleared replacement")
	}
}
func TestControllerPostgreSQLCancellationDuringStartIsFenced(t *testing.T) {
	f := ctlPostgresFixture(t, "PROVISIONING")
	f.e.startHook = func() { f.update(t, "jm_jobs", "job", map[string]any{"state": "CANCELLING", "phase": "cancelling"}) }
	done, e := f.c.processClaim(f.ctx, f.claim(t, "dispatch", map[string]any{"epoch": int64(1)}))
	if e != nil || !done {
		t.Fatal(done, e)
	}
	row, e := f.db.One(f.ctx, "SELECT * FROM jm_allocations WHERE id='allocation'")
	if e != nil {
		t.Fatal(e)
	}
	if str(f.row(t, "jm_jobs")["state"]) != "CANCELLING" || row["released_at"] != nil {
		t.Fatal("cancellation lost while start was in flight")
	}
	done, e = f.c.processClaim(f.ctx, f.claim(t, "fence_stop", map[string]any{}))
	if e != nil || !done {
		t.Fatal(done, e)
	}
	row, _ = f.db.One(f.ctx, "SELECT * FROM jm_allocations WHERE id='allocation'")
	if str(f.row(t, "jm_jobs")["state"]) != "CANCELLED" || !flag(row["termination_confirmed"]) || str(row["state"]) != "RELEASED" {
		t.Fatal("cancellation did not complete after positive stop/storage barrier")
	}
}
func TestControllerPostgreSQLUnknownStopDoesNotReleaseQuota(t *testing.T) {
	f := ctlPostgresFixture(t, "RECONCILING")
	f.reserved(t)
	f.e.stopConfirmed = false
	done, e := f.c.processClaim(f.ctx, f.claim(t, "fence_stop", map[string]any{}))
	if e != nil || done {
		t.Fatal(done, e)
	}
	row, e := f.db.One(f.ctx, "SELECT * FROM jm_allocations WHERE id='allocation'")
	if e != nil {
		t.Fatal(e)
	}
	if str(row["state"]) != "QUARANTINED" || row["released_at"] != nil {
		t.Fatal("PostgreSQL reservation released without physical proof")
	}
}

func TestControllerPostgreSQLRestoreAndConfirmationUseSameLockOrder(t *testing.T) {
	f := ctlPostgresFixture(t, "RUNNING")
	f.c.Provisioner = &ctlProxyProvisioner{ctlFakeProvisioner: f.p, restored: true}
	claim := f.claim(t, "restore_proxies", map[string]any{"epoch": int64(1)})
	if _, e := f.db.Exec(f.ctx, "UPDATE jm_outbox SET idempotency_key=? WHERE id=?", fmtRestoreKey("job", 1), claim.ID); e != nil {
		t.Fatal(e)
	}
	job, attempt, _, e := f.c.snapshot(f.ctx, "job", "attempt")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	blocker, e := f.db.SQL.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer blocker.Rollback()
	var pid int
	if e = blocker.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&pid); e != nil {
		t.Fatal(e)
	}
	if _, e = blocker.ExecContext(ctx, f.db.Rebind("SELECT id FROM jm_outbox WHERE id=? FOR UPDATE"), claim.ID); e != nil {
		t.Fatal(e)
	}
	effectReady := make(chan struct{})
	finishEffect := make(chan struct{})
	operationDone, restorationDone := make(chan error, 1), make(chan error, 1)
	go func() {
		_, e := f.c.operation(ctx, claim, job, attempt, "owner", "restore_proxies", nil, func() (any, error) {
			close(effectReady)
			select {
			case <-finishEffect:
				return true, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
		operationDone <- e
	}()
	select {
	case <-effectReady:
	case <-ctx.Done():
		t.Fatal("operation did not reach external effect")
	}
	close(finishEffect)
	// Hold the exact outbox row until confirmation has reached its final
	// lifecycle lock. Then start a second controller's restart recovery and
	// prove it waits behind the same global order rather than forming a cycle.
	waitForBlocked := func(wanted int) {
		t.Helper()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			var count int
			e := f.db.SQL.QueryRowContext(ctx, "SELECT count(*) FROM pg_stat_activity s WHERE wait_event_type='Lock' AND ($1=ANY(pg_blocking_pids(s.pid)) OR EXISTS(SELECT 1 FROM pg_stat_activity p WHERE p.pid=ANY(pg_blocking_pids(s.pid)) AND $1=ANY(pg_blocking_pids(p.pid))))", pid).Scan(&count)
			if e != nil {
				t.Fatal(e)
			}
			if count >= wanted {
				return
			}
			select {
			case <-ticker.C:
			case <-ctx.Done():
				t.Fatalf("did not observe %d row-lock waiters", wanted)
			}
		}
	}
	waitForBlocked(1)
	restarted := New(f.db, f.e, f.c.Provisioner)
	restarted.Clock = f.c.Clock
	go func() { restorationDone <- restarted.queueProxyRestoration(ctx) }()
	waitForBlocked(2)
	if e = blocker.Rollback(); e != nil {
		t.Fatal(e)
	}
	if e = <-operationDone; e != nil {
		t.Fatalf("operation confirmation: %v", e)
	}
	if e = <-restorationDone; e != nil {
		t.Fatalf("restart restoration: %v", e)
	}
	operation, e := f.db.One(ctx, "SELECT * FROM jm_provisioning_operations WHERE operation='restore_proxies'")
	if e != nil {
		t.Fatal(e)
	}
	if str(operation["state"]) != "confirmed" {
		t.Fatal("confirmation did not commit")
	}
	row, e := f.db.One(ctx, "SELECT * FROM jm_outbox WHERE id=?", claim.ID)
	if e != nil {
		t.Fatal(e)
	}
	if str(row["lease_owner"]) != claim.Owner || str(row["state"]) != "processing" {
		t.Fatal("restart stole the active claim")
	}
}
