package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func New(db *store.DB, e Executor, p Provisioner) *Controller {
	return &Controller{DB: db, Executor: e, Provisioner: p, Clock: time.Now, ControllerID: domain.NewID(), HeartbeatTimeout: 180 * time.Second, RenewInterval: 20 * time.Second}
}
func (c *Controller) RunOnce(ctx context.Context, limit int) (Stats, error) {
	c.runMu.Lock()
	defer c.runMu.Unlock()
	result := Stats{}
	if c.DB == nil || c.Executor == nil || c.Provisioner == nil {
		return result, domain.Err(503, "controller_unavailable")
	}
	if limit == 0 {
		limit = 20
	}
	if limit < 1 || limit > 1000 {
		return result, domain.Err(422, "invalid_dispatch_limit")
	}
	if c.RenewInterval <= 0 || c.RenewInterval > 30*time.Second {
		return result, domain.Err(422, "invalid_renew_interval")
	}
	if !c.restored {
		if err := c.queueProxyRestoration(ctx); err != nil {
			return result, err
		}
		c.restored = true
	}
	for i := 0; i < limit; i++ {
		item, err := c.ClaimNext(ctx, []string{"restore_proxies"})
		if err != nil {
			return result, err
		}
		if item == nil {
			break
		}
		done, err := c.processClaim(ctx, *item)
		if err != nil {
			return result, err
		}
		if done {
			result.Restored++
		}
	}
	if _, err := c.recoverClosingIntents(ctx); err != nil {
		return result, err
	}
	if c.Storage != nil {
		if err := c.Storage.RequestExpiry(ctx); err != nil {
			return result, err
		}
	}
	if c.Schedule != nil {
		admitted, err := c.Schedule(ctx)
		if err != nil {
			return result, err
		}
		result.Admitted = admitted
	}
	if err := c.Monitor(ctx); err != nil {
		return result, err
	}
	for i := 0; i < limit; i++ {
		item, err := c.ClaimNext(ctx, nil)
		if err != nil {
			return result, err
		}
		if item == nil {
			break
		}
		done, err := c.processClaim(ctx, *item)
		if err != nil {
			return result, err
		}
		if done {
			result.Dispatched++
		}
	}
	return result, nil
}
func (c *Controller) ClaimNext(ctx context.Context, topics []string) (*Claim, error) {
	var claim *Claim
	err := c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		query := "SELECT * FROM jm_outbox WHERE (state='pending' OR (state='processing' AND lease_until<=?)) AND (next_attempt_at IS NULL OR next_attempt_at<=?)"
		args := []any{c.now(), c.now()}
		if len(topics) > 0 {
			query += " AND topic IN ("
			for i, topic := range topics {
				if i > 0 {
					query += ","
				}
				query += "?"
				args = append(args, topic)
			}
			query += ")"
		}
		query += " ORDER BY created_at,id LIMIT 1"
		if tx.Dialect == "postgresql" {
			query += " FOR UPDATE SKIP LOCKED"
		}
		row, e := tx.One(ctx, query, args...)
		if e != nil || row == nil {
			return e
		}
		owner := c.ControllerID + ":" + domain.NewID()
		until := c.now().Add(5 * time.Minute)
		if e = tx.Update(ctx, "jm_outbox", map[string]any{"id": row["id"]}, map[string]any{"state": "processing", "lease_owner": owner, "lease_until": until, "attempts": num(row["attempts"]) + 1}); e != nil {
			return e
		}
		claim = &Claim{ID: str(row["id"]), JobID: str(row["job_id"]), AttemptID: str(row["attempt_id"]), Topic: str(row["topic"]), Owner: owner, AttemptNumber: num(row["attempt_number"]), Payload: obj(row["payload_json"]), LeaseUntil: until}
		return nil
	})
	return claim, err
}
func (c *Controller) FinishClaim(ctx context.Context, claim Claim, done bool, errorCode string) error {
	return c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		row, e := tx.One(ctx, "SELECT * FROM jm_outbox WHERE id=?"+tx.ForUpdate(), claim.ID)
		if e != nil || row == nil {
			return e
		}
		// A worker whose lease was replaced cannot finish its successor's claim.
		if str(row["lease_owner"]) != claim.Owner {
			return nil
		}
		state := "pending"
		var next any = c.now().Add(5 * time.Second)
		if done {
			state = "done"
			next = nil
		}
		var failure any
		if errorCode != "" {
			failure = errorCode
		}
		return tx.Update(ctx, "jm_outbox", map[string]any{"id": claim.ID}, map[string]any{"state": state, "last_error": failure, "lease_until": nil, "lease_owner": nil, "next_attempt_at": next})
	})
}
func (c *Controller) processClaim(ctx context.Context, claim Claim) (bool, error) {
	done, err := c.handle(ctx, claim)
	if err == nil {
		return done, c.FinishClaim(ctx, claim, done, "")
	}
	failure := code(err)
	if failure == "stale_claim" {
		return false, c.FinishClaim(ctx, claim, false, failure)
	}
	if failure == "stale_epoch" {
		if closingTopic(claim.Topic) {
			current, e := c.refusedCurrentClosingEpoch(ctx, claim)
			if e != nil {
				if code(e) == "stale_claim" {
					return false, c.FinishClaim(ctx, claim, false, "stale_claim")
				}
				return false, e
			}
			if current {
				return true, c.FinishClaim(ctx, claim, true, failure)
			}
		}
		// An exact superseded durable attempt belongs to its successor's
		// reconciliation; the old claim must never change the new generation.
		return false, c.FinishClaim(ctx, claim, true, failure)
	}
	// A failed physical cleanup keeps the original intent and every storage charge.
	if claim.Topic == "cleanup" || claim.Topic == "purge" || claim.Topic == "expire_artifacts" {
		return false, c.FinishClaim(ctx, claim, false, failure)
	}
	if uncertain(err) {
		failure = "execution_unknown"
	}
	if closingTopic(claim.Topic) {
		// Reconciliation and cancellation are already closing. RequestFailure
		// intentionally does not change those states, so consuming this intent
		// would strand the job permanently. Retry only these idempotent closing
		// effects; do not replay dispatch or release unconfirmed reservations.
		if uncertain(err) || transientCode(failure) {
			if e := c.quarantine(ctx, claim.JobID); e != nil {
				return false, e
			}
			return false, c.FinishClaim(ctx, claim, false, failure)
		}
		if e := c.quarantine(ctx, claim.JobID); e != nil {
			return false, e
		}
		if e := c.attention(ctx, claim.JobID, failure); e != nil {
			return false, e
		}
		return true, c.FinishClaim(ctx, claim, true, failure)
	}
	if e := c.RequestFailure(ctx, claim.JobID, failure, uncertain(err) || transientCode(failure)); e != nil {
		return false, e
	}
	if failure == "controller_error" {
		return false, c.FinishClaim(ctx, claim, false, failure)
	}
	return true, c.FinishClaim(ctx, claim, true, failure)
}
func (c *Controller) handle(ctx context.Context, claim Claim) (bool, error) {
	if err := c.requireClaim(ctx, claim); err != nil {
		return false, err
	}
	switch claim.Topic {
	case "dispatch":
		return c.withKeepalive(ctx, claim, func() (bool, error) { return c.dispatch(ctx, claim) })
	case "restore_proxies":
		return c.restoreProxies(ctx, claim)
	case "fence_stop", "prepare_retry", "reconcile":
		return c.fence(ctx, claim)
	case "cleanup", "purge", "expire_artifacts":
		return c.cleanup(ctx, claim)
	default:
		return false, domain.Err(409, "unknown_controller_operation")
	}
}
func (c *Controller) queueProxyRestoration(ctx context.Context) error {
	if _, ok := c.Provisioner.(ProxyRestorer); !ok {
		return nil
	}
	return c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		rows, e := tx.All(ctx, "SELECT * FROM jm_jobs WHERE state='RUNNING' ORDER BY id"+tx.ForUpdate())
		if e != nil {
			return e
		}
		for _, job := range rows {
			attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE job_id=? AND number=?", job["id"], job["current_attempt"])
			if e != nil {
				return e
			}
			if attempt == nil || num(attempt["epoch"]) != num(job["epoch"]) {
				continue
			}
			key := fmt.Sprintf("restore-proxies:%s:%d", str(job["id"]), num(job["epoch"]))
			item, e := tx.One(ctx, "SELECT * FROM jm_outbox WHERE idempotency_key=?"+tx.ForUpdate(), key)
			if e != nil {
				return e
			}
			if item == nil {
				e = tx.Insert(ctx, "jm_outbox", map[string]any{"id": domain.NewID(), "job_id": job["id"], "attempt_id": attempt["id"], "attempt_number": attempt["number"], "topic": "restore_proxies", "payload_json": map[string]any{"epoch": job["epoch"]}, "idempotency_key": key, "state": "pending", "created_at": c.now()})
			} else if str(item["state"]) == "done" {
				e = tx.Update(ctx, "jm_outbox", map[string]any{"id": item["id"]}, map[string]any{"state": "pending", "next_attempt_at": c.now()})
			}
			if e != nil {
				return e
			}
		}
		return nil
	})
}
func (c *Controller) restoreProxies(ctx context.Context, claim Claim) (bool, error) {
	job, attempt, _, err := c.snapshot(ctx, claim.JobID, claim.AttemptID)
	if err != nil {
		return false, err
	}
	if job == nil || str(job["state"]) != "RUNNING" || attempt == nil || num(attempt["epoch"]) != num(job["epoch"]) {
		return true, nil
	}
	restorer, ok := c.Provisioner.(ProxyRestorer)
	if !ok {
		return false, domain.Err(503, "proxy_restart_required")
	}
	value, err := c.operation(ctx, claim, job, attempt, "owner", "restore_proxies", nil, func() (any, error) { return restorer.RestoreJobProxies(ctx, job, attempt) })
	return value == true, err
}
func (c *Controller) withKeepalive(ctx context.Context, claim Claim, fn func() (bool, error)) (bool, error) {
	stopped := make(chan struct{})
	failures := make(chan error, 1)
	var worker sync.WaitGroup
	worker.Add(1)
	go func() {
		defer worker.Done()
		ticker := time.NewTicker(c.RenewInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopped:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				var ids []executor.ExecutionIdentity
				err := c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
					job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), claim.JobID)
					if e != nil || job == nil {
						return e
					}
					if str(job["state"]) != "PROVISIONING" && str(job["state"]) != "STARTING" {
						return nil
					}
					deadline, ok := moment(job["deadline_at"])
					if !ok || !c.now().Before(deadline) {
						return nil
					}
					attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id=?"+tx.ForUpdate(), claim.AttemptID)
					if e != nil || attempt == nil {
						return e
					}
					if num(job["epoch"]) != num(attempt["epoch"]) || num(job["current_attempt"]) != num(attempt["number"]) {
						return nil
					}
					if e = c.requireClaimTx(ctx, tx, claim); e != nil {
						return e
					}
					if e = tx.Update(ctx, "jm_outbox", map[string]any{"id": claim.ID}, map[string]any{"lease_until": c.now().Add(5 * time.Minute)}); e != nil {
						return e
					}
					allocations, e := tx.All(ctx, "SELECT * FROM jm_allocations WHERE attempt_id=? AND acknowledged=? AND termination_confirmed=? AND state IN "+liveSQL, attempt["id"], true, false)
					if e != nil {
						return e
					}
					for _, allocation := range allocations {
						ids = append(ids, identity(job, attempt, allocation))
					}
					return nil
				})
				if err == nil {
					for _, id := range ids {
						select {
						case <-stopped:
							return
						default:
						}
						ok, e := c.current(ctx, id.JobID, id.AttemptID, id.Epoch, "PROVISIONING", "STARTING")
						if e != nil {
							err = e
							break
						}
						if !ok {
							return
						}
						if e = c.Executor.Renew(ctx, id); e != nil {
							err = e
							break
						}
					}
				}
				if err != nil {
					select {
					case failures <- err:
					default:
					}
					return
				}
			}
		}
	}()
	done, err := fn()
	close(stopped)
	worker.Wait()
	select {
	case failure := <-failures:
		if err == nil {
			if code(failure) == "stale_claim" {
				err = failure
			} else {
				err = domain.Err(503, "execution_unknown")
			}
		}
	default:
	}
	return done, err
}
func (c *Controller) setPhase(ctx context.Context, jobID, attemptID string, epoch int64, state, phase string) (bool, error) {
	changed := false
	err := c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		hint, e := tx.One(ctx, "SELECT project_id FROM jm_jobs WHERE id=?", jobID)
		if e != nil || hint == nil {
			return e
		}
		if _, e = tx.One(ctx, "SELECT id FROM jm_projects WHERE id=?"+tx.ForUpdate(), hint["project_id"]); e != nil {
			return e
		}
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), jobID)
		if e != nil {
			return e
		}
		attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id=?", attemptID)
		if e != nil {
			return e
		}
		if job == nil || attempt == nil || num(job["epoch"]) != epoch || num(attempt["epoch"]) != epoch || num(job["current_attempt"]) != num(attempt["number"]) || terminal(str(job["state"])) || str(job["state"]) == "CANCELLING" || str(job["state"]) == "RECONCILING" || str(job["state"]) == "NEEDS_ATTENTION" {
			return nil
		}
		if e = tx.Update(ctx, "jm_jobs", map[string]any{"id": jobID}, map[string]any{"state": state, "phase": phase, "version": num(job["version"]) + 1, "updated_at": c.now()}); e != nil {
			return e
		}
		values := map[string]any{"state": state, "heartbeat_at": c.now()}
		if state == "RUNNING" && attempt["started_at"] == nil {
			values["started_at"] = c.now()
		}
		if e = tx.Update(ctx, "jm_attempts", map[string]any{"id": attemptID}, values); e != nil {
			return e
		}
		if state != "PROVISIONING" {
			if _, e = tx.Exec(ctx, "UPDATE jm_allocations SET state=? WHERE attempt_id=? AND state IN "+liveSQL, state, attemptID); e != nil {
				return e
			}
		}
		changed = true
		return c.event(ctx, tx, job, stringsLower(state), map[string]any{})
	})
	return changed, err
}
func stringsLower(s string) string {
	out := []byte(s)
	for i, b := range out {
		if b >= 'A' && b <= 'Z' {
			out[i] = b + 32
		}
	}
	return string(out)
}
