package controller

import (
	"context"
	"strconv"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func closingTopic(topic string) bool {
	return topic == "fence_stop" || topic == "prepare_retry" || topic == "reconcile"
}

// recoverClosingIntents repairs an interrupted closing state without changing
// its outcome or assuming an external effect succeeded. Historical controllers
// could consume a fencing intent after a transient error. Reconstructing the
// exact current-attempt intent repeats only idempotent fencing/reconciliation,
// never dispatches training, and leaves allocations charged until positive proof.
func (c *Controller) recoverClosingIntents(ctx context.Context) (int, error) {
	recovered := 0
	err := c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		jobs, e := tx.All(ctx, "SELECT * FROM jm_jobs WHERE state IN ('CANCELLING','RECONCILING') ORDER BY id"+tx.ForUpdate())
		if e != nil {
			return e
		}
		for _, job := range jobs {
			attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE job_id=? AND number=?", job["id"], job["current_attempt"])
			if e != nil {
				return e
			}
			if attempt == nil {
				return domain.Err(409, "attempt_not_found")
			}
			// A repair may not revive a superseded durable generation. The
			// single exception is a never-admitted queued cancellation, whose
			// prepared attempt carries the next epoch until admission.
			if num(attempt["epoch"]) != num(job["epoch"]) &&
				!(str(job["state"]) == "CANCELLING" && str(attempt["state"]) == "QUEUED" && num(attempt["epoch"]) == num(job["epoch"])+1) {
				continue
			}
			unfinished, e := tx.One(ctx, "SELECT id FROM jm_outbox WHERE job_id=? AND topic IN ('fence_stop','prepare_retry','reconcile') AND state<>'done' AND (attempt_number IS NULL OR attempt_number=?) AND (attempt_id IS NULL OR attempt_id=?) LIMIT 1", job["id"], job["current_attempt"], attempt["id"])
			if e != nil {
				return e
			}
			if unfinished != nil {
				continue
			}
			previous, e := tx.One(ctx, "SELECT * FROM jm_outbox WHERE job_id=? AND topic IN ('fence_stop','prepare_retry','reconcile') AND (attempt_number IS NULL OR attempt_number=?) AND (attempt_id IS NULL OR attempt_id=?) ORDER BY created_at DESC,id DESC LIMIT 1", job["id"], job["current_attempt"], attempt["id"])
			if e != nil {
				return e
			}
			topic := "fence_stop"
			payload := map[string]any{"desired_outcome": "CANCELLED", "grace_seconds": int64(60)}
			if str(job["state"]) == "RECONCILING" {
				if previous == nil {
					if e = tx.Update(ctx, "jm_jobs", map[string]any{"id": job["id"]}, map[string]any{"state": "NEEDS_ATTENTION", "phase": "reconciliation_required", "error_code": "reconciliation_intent_missing", "version": num(job["version"]) + 1, "updated_at": c.now()}); e != nil {
						return e
					}
					if e = c.event(ctx, tx, job, "needs_attention", map[string]any{"reason": "reconciliation_intent_missing"}); e != nil {
						return e
					}
					continue
				}
				topic = str(previous["topic"])
				payload = copyMap(obj(previous["payload_json"]))
			} else if str(job["phase"]) == "deadline_exceeded" {
				payload["reason"] = "deadline_exceeded"
			}
			origin := "missing"
			if previous != nil {
				origin = str(previous["id"])
			}
			key := stableKey("closing-recovery", str(job["id"]), str(attempt["id"]), strconv.FormatInt(num(job["epoch"]), 10), str(job["state"]), origin, topic)
			existing, e := tx.One(ctx, "SELECT * FROM jm_outbox WHERE idempotency_key=?"+tx.ForUpdate(), key)
			if e != nil {
				return e
			}
			if existing == nil {
				if e = tx.Insert(ctx, "jm_outbox", map[string]any{"id": domain.NewID(), "job_id": job["id"], "attempt_id": attempt["id"], "attempt_number": job["current_attempt"], "topic": topic, "payload_json": payload, "idempotency_key": key, "state": "pending", "created_at": c.now()}); e != nil {
					return e
				}
			} else {
				if e = tx.Update(ctx, "jm_outbox", map[string]any{"id": existing["id"]}, map[string]any{"state": "pending", "lease_owner": nil, "lease_until": nil, "next_attempt_at": c.now()}); e != nil {
					return e
				}
			}
			if e = tx.Update(ctx, "jm_jobs", map[string]any{"id": job["id"]}, map[string]any{"version": num(job["version"]) + 1, "updated_at": c.now()}); e != nil {
				return e
			}
			if e = c.event(ctx, tx, job, "closing_intent_recovered", map[string]any{"operation": topic, "attempt_number": num(job["current_attempt"])}); e != nil {
				return e
			}
			recovered++
		}
		return nil
	})
	return recovered, err
}

// refusedCurrentClosingEpoch distinguishes a superseded durable identity from
// an external stale_epoch refusal for the still-current closing attempt. Only
// the former may be discarded. The latter needs explicit operator attention,
// not an endless sequence of consumed and reconstructed cancellation intents.
func (c *Controller) refusedCurrentClosingEpoch(ctx context.Context, claim Claim) (bool, error) {
	current := false
	err := c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		hint, e := tx.One(ctx, "SELECT project_id FROM jm_jobs WHERE id=?", claim.JobID)
		if e != nil || hint == nil {
			return e
		}
		if _, e = tx.One(ctx, "SELECT id FROM jm_projects WHERE id=?"+tx.ForUpdate(), hint["project_id"]); e != nil {
			return e
		}
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), claim.JobID)
		if e != nil || job == nil {
			return e
		}
		if str(job["state"]) != "CANCELLING" && str(job["state"]) != "RECONCILING" {
			return nil
		}
		attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE job_id=? AND number=?", job["id"], job["current_attempt"])
		if e != nil || attempt == nil {
			return e
		}
		if (claim.AttemptNumber != 0 && claim.AttemptNumber != num(job["current_attempt"])) || (claim.AttemptID != "" && claim.AttemptID != str(attempt["id"])) || num(attempt["epoch"]) != num(job["epoch"]) {
			return nil
		}
		if claim.AttemptNumber == 0 && claim.AttemptID == "" {
			return nil
		}
		if _, e = tx.All(ctx, "SELECT id FROM jm_allocations WHERE job_id=? AND attempt_id=? AND state IN "+liveSQL+" ORDER BY pool_id,id"+tx.ForUpdate(), job["id"], attempt["id"]); e != nil {
			return e
		}
		if _, e = tx.One(ctx, "SELECT id FROM jm_attempts WHERE id=?"+tx.ForUpdate(), attempt["id"]); e != nil {
			return e
		}
		if e = c.requireClaimTx(ctx, tx, claim); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "UPDATE jm_allocations SET state='QUARANTINED' WHERE job_id=? AND attempt_id=? AND state IN "+liveSQL, job["id"], attempt["id"]); e != nil {
			return e
		}
		if e = tx.Update(ctx, "jm_jobs", map[string]any{"id": job["id"]}, map[string]any{"state": "NEEDS_ATTENTION", "phase": "reconciliation_required", "error_code": "stale_epoch", "version": num(job["version"]) + 1, "updated_at": c.now()}); e != nil {
			return e
		}
		current = true
		return c.event(ctx, tx, job, "needs_attention", map[string]any{"reason": "stale_epoch"})
	})
	return current, err
}
