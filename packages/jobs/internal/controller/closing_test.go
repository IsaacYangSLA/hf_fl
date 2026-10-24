package controller

import (
	"context"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/manager"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	"strings"
	"sync"
	"testing"
	"time"
)

func cancelWithRealManager(t *testing.T, f *ctlFixture) {
	t.Helper()
	if e := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
		return tx.Insert(f.ctx, "jm_job_members", map[string]any{"job_id": "job", "principal_id": "human", "role": "admin"})
	}); e != nil {
		t.Fatal(e)
	}
	m, e := manager.New(f.db, []byte(strings.Repeat("s", 32)))
	if e != nil {
		t.Fatal(e)
	}
	m.Clock = f.c.Clock
	if _, e = m.Cancel(f.ctx, "human", "job", num(f.row(t, "jm_jobs")["version"]), "cancel-through-manager"); e != nil {
		t.Fatal(e)
	}
}
func TestControllerManagerCancellationSurvivesUncertainRelease(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgresql"} {
		for _, legacy := range []bool{false, true} {
			name := backend + "/retry"
			if legacy {
				name = backend + "/legacy-consumed"
			}
			t.Run(name, func(t *testing.T) {
				var f *ctlFixture
				if backend == "postgresql" {
					f = ctlPostgresFixture(t, "RUNNING")
				} else {
					f = newCtlFixture(t, "RUNNING")
				}
				f.reserved(t)
				cancelWithRealManager(t, f)
				original, e := f.db.One(f.ctx, "SELECT * FROM jm_outbox WHERE job_id='job' AND topic='fence_stop'")
				if e != nil || original == nil {
					t.Fatal(e)
				}
				if legacy {
					// Historical fixture only: old controllers consumed this intent while
					// leaving the authenticated cancellation in CANCELLING.
					if _, e = f.db.Exec(f.ctx, "UPDATE jm_outbox SET state='done',last_error='execution_unknown' WHERE id=?", original["id"]); e != nil {
						t.Fatal(e)
					}
				} else {
					f.e.releaseErrorOnce = true
					if _, e = f.c.RunOnce(f.ctx, 20); e != nil {
						t.Fatal(e)
					}
					row, e := f.db.One(f.ctx, "SELECT * FROM jm_outbox WHERE id=?", original["id"])
					if e != nil {
						t.Fatal(e)
					}
					if str(f.row(t, "jm_jobs")["state"]) != "CANCELLING" || str(row["state"]) != "pending" || str(row["last_error"]) != "execution_unknown" {
						t.Fatal("transient release consumed cancellation intent")
					}
					allocation, e := f.db.One(f.ctx, "SELECT * FROM jm_allocations WHERE id='allocation'")
					if e != nil {
						t.Fatal(e)
					}
					if allocation["released_at"] != nil || str(allocation["state"]) != "QUARANTINED" {
						t.Fatal("transient release freed capacity")
					}
					if str(obj(f.row(t, "jm_attempts")["details_json"])["desired_terminal"]) != "CANCELLED" {
						t.Fatal("cancelled outcome lost")
					}
					next, ok := moment(row["next_attempt_at"])
					if !ok || next.Sub(f.now) != 5*time.Second {
						t.Fatal("closing retry not bounded")
					}
					f.now = f.now.Add(6 * time.Second)
				}
				if _, e = f.c.RunOnce(f.ctx, 20); e != nil {
					t.Fatal(e)
				}
				job := f.row(t, "jm_jobs")
				if str(job["state"]) != "CANCELLED" || str(job["cleanup_status"]) != "complete" {
					t.Fatal("normal closing retry did not reach cancelled/cleanup-complete")
				}
				rows, e := f.db.All(f.ctx, "SELECT * FROM jm_outbox WHERE job_id='job' AND topic='fence_stop'")
				if e != nil {
					t.Fatal(e)
				}
				wanted := 1
				if legacy {
					wanted = 2
				}
				if len(rows) != wanted {
					t.Fatal("unexpected duplicate closing intents")
				}
				if legacy {
					events, e := f.db.All(f.ctx, "SELECT id FROM jm_events WHERE kind='closing_intent_recovered'")
					if e != nil || len(events) != 1 {
						t.Fatal("missing durable recovery audit", e)
					}
				}
				for _, call := range f.e.calls {
					if strings.HasPrefix(call, "start:") {
						t.Fatal("closing recovery replayed training")
					}
				}
			})
		}
	}
}
func TestControllerPostgreSQLConcurrentClosingRecoveryIsIdempotent(t *testing.T) {
	f := ctlPostgresFixture(t, "RUNNING")
	cancelWithRealManager(t, f)
	if _, e := f.db.Exec(f.ctx, "UPDATE jm_outbox SET state='done',last_error='execution_unknown' WHERE topic='fence_stop'"); e != nil {
		t.Fatal(e)
	}
	other := New(f.db, f.e, f.p)
	other.Clock = f.c.Clock
	var wg sync.WaitGroup
	var mu sync.Mutex
	total := 0
	failures := []error{}
	for _, c := range []*Controller{f.c, other} {
		wg.Add(1)
		go func(c *Controller) {
			defer wg.Done()
			n, e := c.recoverClosingIntents(context.Background())
			mu.Lock()
			defer mu.Unlock()
			total += n
			if e != nil {
				failures = append(failures, e)
			}
		}(c)
	}
	wg.Wait()
	if total != 1 || len(failures) > 0 {
		t.Fatalf("recovered %d errors %v", total, failures)
	}
	rows, e := f.db.All(f.ctx, "SELECT * FROM jm_outbox WHERE topic='fence_stop' AND state<>'done'")
	if e != nil {
		t.Fatal(e)
	}
	if len(rows) != 1 || len(str(rows[0]["idempotency_key"])) != 64 {
		t.Fatal("concurrent repair duplicated intent or missed stable identity")
	}
}

func TestControllerPermanentClosingFailureNeedsAttentionWithQuotaHeld(t *testing.T) {
	f := newCtlFixture(t, "RUNNING")
	f.reserved(t)
	cancelWithRealManager(t, f)
	f.storage.retainError = domain.Err(409, "unsafe_output")
	if _, e := f.c.RunOnce(f.ctx, 20); e != nil {
		t.Fatal(e)
	}
	job := f.row(t, "jm_jobs")
	if str(job["state"]) != "NEEDS_ATTENTION" || str(job["error_code"]) != "unsafe_output" {
		t.Fatal("permanent closing failure was silently consumed")
	}
	allocation, e := f.db.One(f.ctx, "SELECT * FROM jm_allocations WHERE id='allocation'")
	if e != nil {
		t.Fatal(e)
	}
	if str(allocation["state"]) != "QUARANTINED" || allocation["released_at"] != nil {
		t.Fatal("attention released quota")
	}
	if str(obj(f.row(t, "jm_attempts")["details_json"])["desired_terminal"]) != "CANCELLED" {
		t.Fatal("attention lost original cancellation")
	}
	if _, e = f.c.RunOnce(f.ctx, 20); e != nil {
		t.Fatal(e)
	}
	rows, e := f.db.All(f.ctx, "SELECT * FROM jm_outbox WHERE topic='fence_stop'")
	if e != nil || len(rows) != 1 {
		t.Fatal("attention was reopened automatically", e)
	}
}
func TestControllerClosingRecoveryPreservesEvidenceAndNeverReopensAttention(t *testing.T) {
	f := newCtlFixture(t, "RECONCILING")
	evidence := map[string]any{"publication_id": "opaque-record", "outcome": "not_published", "evidence_ref": "sha256:proof"}
	original := f.claim(t, "reconcile", map[string]any{"evidence": evidence})
	if e := f.c.FinishClaim(f.ctx, original, true, "execution_unknown"); e != nil {
		t.Fatal(e)
	}
	n, e := f.c.recoverClosingIntents(f.ctx)
	if e != nil || n != 1 {
		t.Fatal(n, e)
	}
	row, e := f.db.One(f.ctx, "SELECT * FROM jm_outbox WHERE topic='reconcile' AND state='pending'")
	if e != nil {
		t.Fatal(e)
	}
	expected, _ := domain.CanonicalJSON(map[string]any{"evidence": evidence})
	actual, _ := domain.CanonicalJSON(obj(row["payload_json"]))
	if string(expected) != string(actual) {
		t.Fatal("recovery changed the original evidence")
	}
	f.update(t, "jm_jobs", "job", map[string]any{"state": "NEEDS_ATTENTION"})
	if _, e = f.db.Exec(f.ctx, "UPDATE jm_outbox SET state='done',last_error='publication_unknown' WHERE topic='reconcile'"); e != nil {
		t.Fatal(e)
	}
	if n, e = f.c.recoverClosingIntents(f.ctx); e != nil || n != 0 {
		t.Fatal("unknown publication attention was reopened", n, e)
	}
}

func TestControllerCurrentExternalStaleEpochRequiresAttention(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgresql"} {
		t.Run(backend, func(t *testing.T) {
			var f *ctlFixture
			if backend == "postgresql" {
				f = ctlPostgresFixture(t, "RUNNING")
			} else {
				f = newCtlFixture(t, "RUNNING")
			}
			f.reserved(t)
			cancelWithRealManager(t, f)
			f.storage.retainError = domain.Err(409, "stale_epoch")
			for i := 0; i < 3; i++ {
				if _, e := f.c.RunOnce(f.ctx, 20); e != nil {
					t.Fatal(e)
				}
				f.now = f.now.Add(6 * time.Second)
			}
			job := f.row(t, "jm_jobs")
			if str(job["state"]) != "NEEDS_ATTENTION" || str(job["error_code"]) != "stale_epoch" {
				t.Fatal("current external epoch refusal did not require attention")
			}
			rows, e := f.db.All(f.ctx, "SELECT * FROM jm_outbox WHERE job_id='job' AND topic='fence_stop'")
			if e != nil {
				t.Fatal(e)
			}
			if len(rows) != 1 || str(rows[0]["state"]) != "done" {
				t.Fatal("current refusal recreated closing intents")
			}
			allocation, e := f.db.One(f.ctx, "SELECT * FROM jm_allocations WHERE id='allocation'")
			if e != nil {
				t.Fatal(e)
			}
			if str(allocation["state"]) != "QUARANTINED" || allocation["released_at"] != nil {
				t.Fatal("current refusal released quota")
			}
			if str(obj(f.row(t, "jm_attempts")["details_json"])["desired_terminal"]) != "CANCELLED" {
				t.Fatal("current refusal lost requested cancellation")
			}
		})
	}
}
func TestControllerSupersededClosingClaimCannotChangeSuccessor(t *testing.T) {
	f := newCtlFixture(t, "RUNNING")
	f.reserved(t)
	cancelWithRealManager(t, f)
	f.storage.retainHook = func() error {
		e := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
			if e := tx.Insert(f.ctx, "jm_attempts", map[string]any{"id": "successor", "job_id": "job", "number": int64(2), "epoch": int64(2), "state": "RUNNING"}); e != nil {
				return e
			}
			return tx.Update(f.ctx, "jm_jobs", map[string]any{"id": "job"}, map[string]any{"current_attempt": int64(2), "attempt_count": int64(2), "epoch": int64(2), "state": "RUNNING", "phase": "training"})
		})
		if e != nil {
			return e
		}
		return domain.Err(409, "stale_epoch")
	}
	if _, e := f.c.RunOnce(f.ctx, 20); e != nil {
		t.Fatal(e)
	}
	job := f.row(t, "jm_jobs")
	if str(job["state"]) != "RUNNING" || num(job["current_attempt"]) != 2 || num(job["epoch"]) != 2 {
		t.Fatal("old closing claim changed successor")
	}
	row, e := f.db.One(f.ctx, "SELECT * FROM jm_outbox WHERE topic='fence_stop'")
	if e != nil {
		t.Fatal(e)
	}
	if str(row["state"]) != "done" || str(row["last_error"]) != "stale_epoch" {
		t.Fatal("superseded claim was not discarded")
	}
	if n, e := f.c.recoverClosingIntents(f.ctx); e != nil || n != 0 {
		t.Fatal("old intent was reconstructed into successor", n, e)
	}
}
func TestControllerRecoveryDoesNotReviveOldDurableEpoch(t *testing.T) {
	f := newCtlFixture(t, "RECONCILING")
	old := f.claim(t, "fence_stop", map[string]any{})
	f.update(t, "jm_jobs", "job", map[string]any{"epoch": int64(2)})
	done, e := f.c.processClaim(f.ctx, old)
	if e != nil || !done {
		t.Fatal(done, e)
	}
	if n, e := f.c.recoverClosingIntents(f.ctx); e != nil || n != 0 {
		t.Fatal("old durable epoch was revived", n, e)
	}
	if num(f.row(t, "jm_jobs")["epoch"]) != 2 {
		t.Fatal("fencing generation was rewritten")
	}
}
