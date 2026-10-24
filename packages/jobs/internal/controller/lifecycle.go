package controller

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func (c *Controller) RequestFailure(ctx context.Context, jobID, failure string, transient bool) error {
	if jobID == "" {
		return nil
	}
	return c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), jobID)
		if e != nil || job == nil {
			return e
		}
		state := str(job["state"])
		if terminal(state) || state == "CANCELLING" || state == "NEEDS_ATTENTION" {
			return nil
		}
		attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE job_id=? AND number=?", jobID, job["current_attempt"])
		if e != nil {
			return e
		}
		if attempt != nil && failure == "deadline_exceeded" {
			details := copyMap(obj(attempt["details_json"]))
			if _, exists := details["desired_terminal"]; !exists {
				details["desired_terminal"] = "FAILED"
				details["desired_terminal_reason"] = "deadline_exceeded"
				if e = tx.Update(ctx, "jm_attempts", map[string]any{"id": attempt["id"]}, map[string]any{"details_json": details}); e != nil {
					return e
				}
			}
		}
		if state == "RECONCILING" {
			return nil
		}
		if e = tx.Update(ctx, "jm_jobs", map[string]any{"id": jobID}, map[string]any{"state": "RECONCILING", "phase": "fencing", "error_code": failure, "version": num(job["version"]) + 1, "updated_at": c.now()}); e != nil {
			return e
		}
		aid := ""
		if attempt != nil {
			aid = str(attempt["id"])
			latest, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id=?", aid)
			if e != nil {
				return e
			}
			details := copyMap(obj(latest["details_json"]))
			details["transient"] = transient
			if e = tx.Update(ctx, "jm_attempts", map[string]any{"id": aid}, map[string]any{"error_code": failure, "details_json": details}); e != nil {
				return e
			}
		}
		if _, e = tx.Exec(ctx, "UPDATE jm_allocations SET state='QUARANTINED' WHERE job_id=? AND state IN "+liveSQL, jobID); e != nil {
			return e
		}
		if e = c.enqueue(ctx, tx, job, "fence_stop", map[string]any{"reason": failure, "transient": transient}, aid); e != nil {
			return e
		}
		return c.event(ctx, tx, job, "reconciling", map[string]any{"reason": failure})
	})
}
func (c *Controller) RequestCompletion(ctx context.Context, jobID string, currentRound int64) error {
	if currentRound < 0 {
		return domain.Err(422, "invalid_round")
	}
	return c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), jobID)
		if e != nil || job == nil {
			return e
		}
		if terminal(str(job["state"])) || str(job["state"]) == "CANCELLING" || str(job["state"]) == "NEEDS_ATTENTION" || str(job["state"]) == "RECONCILING" {
			return nil
		}
		attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE job_id=? AND number=?", jobID, job["current_attempt"])
		if e != nil {
			return e
		}
		if currentRound < num(job["current_round"]) {
			currentRound = num(job["current_round"])
		}
		if e = tx.Update(ctx, "jm_jobs", map[string]any{"id": jobID}, map[string]any{"current_round": currentRound, "state": "RECONCILING", "phase": "collecting_results", "version": num(job["version"]) + 1, "updated_at": c.now()}); e != nil {
			return e
		}
		aid := ""
		if attempt != nil {
			aid = str(attempt["id"])
		}
		return c.enqueue(ctx, tx, job, "fence_stop", map[string]any{"success": true}, aid)
	})
}
func (c *Controller) attention(ctx context.Context, jobID, reason string) error {
	return c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), jobID)
		if e != nil || job == nil || terminal(str(job["state"])) {
			return e
		}
		if e = tx.Update(ctx, "jm_jobs", map[string]any{"id": jobID}, map[string]any{"state": "NEEDS_ATTENTION", "phase": "reconciliation_required", "error_code": reason, "version": num(job["version"]) + 1, "updated_at": c.now()}); e != nil {
			return e
		}
		return c.event(ctx, tx, job, "needs_attention", map[string]any{"reason": reason})
	})
}
func (c *Controller) quarantine(ctx context.Context, jobID string) error {
	_, e := c.DB.Exec(ctx, "UPDATE jm_allocations SET state='QUARANTINED' WHERE job_id=? AND state IN "+liveSQL, jobID)
	return e
}
func (c *Controller) neverReserved(ctx context.Context, job, attempt map[string]any, componentID string) (bool, error) {
	key := fmt.Sprintf("%s:%s:%d:%s:reserve", str(job["id"]), str(attempt["id"]), num(attempt["epoch"]), componentID)
	operation, e := c.DB.One(ctx, "SELECT * FROM jm_provisioning_operations WHERE idempotency_key=?", key)
	if e != nil {
		return false, e
	}
	if operation == nil {
		return true, nil
	}
	return str(operation["state"]) == "refused" && safeRefusal(str(operation["last_error"])), nil
}
func safeRefusal(code string) bool {
	switch code {
	case "capacity", "invalid_resources", "job_deadline_expired", "unsupported_profile", "node_mismatch", "pool_mismatch", "invalid_identity":
		return true
	}
	return false
}
func (c *Controller) fence(ctx context.Context, claim Claim) (bool, error) {
	job, attempt, allocations, e := c.snapshot(ctx, claim.JobID, claim.AttemptID)
	if e != nil {
		return false, e
	}
	if job == nil {
		return true, nil
	}
	if claim.AttemptNumber != 0 && claim.AttemptNumber != num(job["current_attempt"]) {
		return true, nil
	}
	if terminal(str(job["state"])) {
		return true, nil
	}
	if attempt == nil {
		return true, c.terminal(ctx, str(job["id"]), "CANCELLED", "cancelled")
	}
	if len(allocations) == 0 && str(attempt["state"]) == "QUEUED" && str(job["state"]) == "CANCELLING" {
		proved, e := c.confirmNeverStarted(ctx, claim, str(job["id"]), str(attempt["id"]))
		if e != nil {
			return false, e
		}
		if !proved {
			return true, c.attention(ctx, str(job["id"]), "queued_cancellation_effects_unconfirmed")
		}
		state, reason := "CANCELLED", "cancelled"
		if str(job["phase"]) == "deadline_exceeded" {
			state, reason = "FAILED", "deadline_exceeded"
		}
		return true, c.terminal(ctx, str(job["id"]), state, reason)
	}
	if num(attempt["number"]) != num(job["current_attempt"]) || num(attempt["epoch"]) != num(job["epoch"]) {
		return true, nil
	}
	deadline, hasDeadline := moment(job["deadline_at"])
	if str(job["state"]) == "CANCELLING" || (hasDeadline && !c.now().Before(deadline)) {
		reason := "cancelled"
		if str(job["phase"]) == "deadline_exceeded" || str(claim.Payload["reason"]) == "deadline_exceeded" || str(job["state"]) != "CANCELLING" {
			reason = "deadline_exceeded"
		}
		if e = c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
			row, err := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id=?"+tx.ForUpdate(), attempt["id"])
			if err != nil || row == nil {
				return err
			}
			details := copyMap(obj(row["details_json"]))
			if _, exists := details["desired_terminal"]; exists {
				return nil
			}
			details["desired_terminal"] = "CANCELLED"
			if reason == "deadline_exceeded" {
				details["desired_terminal"] = "FAILED"
			}
			details["desired_terminal_reason"] = reason
			return tx.Update(ctx, "jm_attempts", map[string]any{"id": attempt["id"]}, map[string]any{"details_json": details})
		}); e != nil {
			return false, e
		}
	}
	value, e := c.operation(ctx, claim, job, attempt, "owner", "revoke", nil, func() (any, error) { return c.Provisioner.Revoke(ctx, job, attempt) })
	if e != nil {
		return false, e
	}
	if value != true {
		return true, c.attention(ctx, str(job["id"]), "grant_revocation_unknown")
	}
	if e = c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		return tx.Update(ctx, "jm_attempts", map[string]any{"id": attempt["id"]}, map[string]any{"revocation_confirmed": true})
	}); e != nil {
		return false, e
	}
	other, e := c.DB.One(ctx, "SELECT id FROM jm_outbox WHERE job_id=? AND topic='dispatch' AND state='processing' AND lease_until>? LIMIT 1", job["id"], c.now())
	if e != nil {
		return false, e
	}
	if other != nil {
		return false, nil
	}
	allStopped := true
	for _, allocation := range allocations {
		id := identity(job, attempt, allocation)
		absent, err := c.neverReserved(ctx, job, attempt, id.ComponentID)
		if err != nil {
			return false, err
		}
		confirmed := absent
		if !absent {
			value, err = c.operation(ctx, claim, job, attempt, id.ComponentID, "stop", nil, func() (any, error) { return c.Executor.Stop(ctx, id, 60) })
			if err == nil {
				observed, ok := value.(executor.RuntimeObservation)
				confirmed = ok && observed.TerminationConfirmed
			} else {
				if code(err) == "stale_claim" || code(err) == "stale_epoch" {
					return false, err
				}
				confirmed = false
			}
		}
		if confirmed {
			if _, err = c.StopConfirmation(ctx, id.JobID, id.AttemptID, id.ComponentID, id.Epoch); err != nil {
				return false, err
			}
		}
		allStopped = allStopped && confirmed
	}
	if c.Participants != nil {
		requested, err := c.Participants.RequestStop(ctx, job, attempt)
		if err != nil {
			return false, err
		}
		confirmed, err := c.Participants.AttemptTerminationConfirmed(ctx, str(job["id"]), str(attempt["id"]))
		if err != nil {
			return false, err
		}
		allStopped = allStopped && requested && confirmed
	} else {
		external, err := c.DB.All(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id=? AND kind='external_enrollment'", job["id"])
		if err != nil {
			return false, err
		}
		for _, row := range external {
			allStopped = allStopped && flag(obj(row["details_json"])["termination_confirmed"])
		}
	}
	if !allStopped {
		return false, c.quarantine(ctx, str(job["id"]))
	}
	if claim.Topic == "reconcile" && claim.Payload["evidence"] != nil {
		if e = c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
			row, err := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id=?"+tx.ForUpdate(), attempt["id"])
			if err != nil {
				return err
			}
			details := copyMap(obj(row["details_json"]))
			details["reconciliation_evidence"] = claim.Payload["evidence"]
			attempt["details_json"] = details
			return tx.Update(ctx, "jm_attempts", map[string]any{"id": attempt["id"]}, map[string]any{"details_json": details})
		}); e != nil {
			return false, e
		}
	}
	value, e = c.operation(ctx, claim, job, attempt, "owner", "reconcile", nil, func() (any, error) { return c.Provisioner.Reconcile(ctx, job, attempt) })
	if e != nil {
		return false, e
	}
	publication, ok := value.(PublicationObservation)
	if !ok || publication.Validate() != nil || !publication.Known {
		return true, c.attention(ctx, str(job["id"]), "publication_unknown")
	}
	if e = c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		locked, err := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), job["id"])
		if err != nil {
			return err
		}
		if locked == nil || num(locked["epoch"]) != num(attempt["epoch"]) || num(locked["current_attempt"]) != num(attempt["number"]) {
			return domain.Err(409, "stale_epoch")
		}
		stored, err := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id=?"+tx.ForUpdate(), attempt["id"])
		if err != nil {
			return err
		}
		if err = c.requireClaimTx(ctx, tx, claim); err != nil {
			return err
		}
		details := copyMap(obj(stored["details_json"]))
		details["publication_evidence"] = publication.Evidence
		if err = tx.Update(ctx, "jm_attempts", map[string]any{"id": attempt["id"]}, map[string]any{"publication_status": publication.Status, "termination_confirmed": true, "ended_at": c.now(), "state": "STOPPED", "details_json": details}); err != nil {
			return err
		}
		if publication.CurrentRound != nil {
			if *publication.CurrentRound > num(locked["current_round"]) {
				return tx.Update(ctx, "jm_jobs", map[string]any{"id": job["id"]}, map[string]any{"current_round": *publication.CurrentRound})
			}
		}
		return nil
	}); e != nil {
		return false, e
	}
	released, e := c.release(ctx, claim, job, attempt, allocations)
	if e != nil {
		return false, e
	}
	if !released {
		return false, c.quarantine(ctx, str(job["id"]))
	}
	job, attempt, _, e = c.snapshot(ctx, str(job["id"]), "")
	if e != nil {
		return false, e
	}
	if job == nil || attempt == nil {
		return false, domain.Err(409, "attempt_not_found")
	}
	if terminal(str(job["state"])) {
		return true, nil
	}
	details := obj(attempt["details_json"])
	if str(job["state"]) == "CANCELLING" {
		state, reason := "CANCELLED", "cancelled"
		if str(job["phase"]) == "deadline_exceeded" || str(claim.Payload["reason"]) == "deadline_exceeded" {
			state, reason = "FAILED", "deadline_exceeded"
		}
		return true, c.terminal(ctx, str(job["id"]), state, reason)
	}
	if desired := str(details["desired_terminal"]); desired == "CANCELLED" || desired == "FAILED" {
		return true, c.terminal(ctx, str(job["id"]), desired, str(details["desired_terminal_reason"]))
	}
	if str(claim.Payload["reason"]) == "deadline_exceeded" || str(job["error_code"]) == "deadline_exceeded" {
		return true, c.terminal(ctx, str(job["id"]), "FAILED", "deadline_exceeded")
	}
	if publication.CurrentRound != nil && *publication.CurrentRound >= num(job["target_round"]) {
		return true, c.terminal(ctx, str(job["id"]), "SUCCEEDED", "target_round_confirmed")
	}
	if claim.Topic == "reconcile" && !flag(claim.Payload["retry"]) {
		reason := str(job["error_code"])
		if reason == "" {
			reason = "reconciled_failure"
		}
		return true, c.terminal(ctx, str(job["id"]), "FAILED", reason)
	}
	if claim.Topic == "prepare_retry" {
		return c.retry(ctx, str(job["id"]), true)
	}
	if flag(details["transient"]) || flag(claim.Payload["transient"]) {
		return c.retry(ctx, str(job["id"]), false)
	}
	reason := str(job["error_code"])
	if reason == "" {
		reason = "execution_failed"
	}
	return true, c.terminal(ctx, str(job["id"]), "FAILED", reason)
}
func (c *Controller) release(ctx context.Context, claim Claim, job, attempt map[string]any, allocations []map[string]any) (bool, error) {
	if c.Storage == nil && len(allocations) > 0 {
		return false, domain.Err(503, "storage_unavailable")
	}
	for _, allocation := range allocations {
		id := identity(job, attempt, allocation)
		absent, e := c.neverReserved(ctx, job, attempt, id.ComponentID)
		if e != nil {
			return false, e
		}
		if !absent {
			if e = c.Storage.ReserveCollection(ctx, job, attempt, allocation); e != nil {
				return false, e
			}
			value, e := c.operation(ctx, claim, job, attempt, id.ComponentID, "collect", nil, func() (any, error) { return c.Executor.Collect(ctx, id) })
			if e != nil {
				return false, e
			}
			files, ok := value.([]executor.CollectedArtifact)
			if !ok {
				return false, domain.Err(422, "unsafe_output")
			}
			if e = c.Storage.StoreCollected(ctx, job, attempt, allocation, files); e != nil {
				return false, e
			}
			_ = c.Storage.IngestLogs(ctx, allocation, true)
			if e = c.Storage.RetainExecutionState(ctx, job, attempt, allocation); e != nil {
				return false, e
			}
			value, e = c.operation(ctx, claim, job, attempt, id.ComponentID, "release", nil, func() (any, error) { return c.Executor.Release(ctx, id) })
			if e != nil {
				return false, e
			}
			if value != true {
				return false, nil
			}
		}
		released := false
		e = c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
			if _, e := tx.One(ctx, "SELECT id FROM jm_pools WHERE id=?"+tx.ForUpdate(), allocation["pool_id"]); e != nil {
				return e
			}
			if _, e := tx.One(ctx, "SELECT id FROM jm_projects WHERE id=?"+tx.ForUpdate(), job["project_id"]); e != nil {
				return e
			}
			if _, e := tx.One(ctx, "SELECT id FROM jm_jobs WHERE id=?"+tx.ForUpdate(), job["id"]); e != nil {
				return e
			}
			stored, e := tx.One(ctx, "SELECT * FROM jm_allocations WHERE id=?"+tx.ForUpdate(), allocation["id"])
			if e != nil || stored == nil {
				return e
			}
			if !flag(stored["termination_confirmed"]) {
				return nil
			}
			if _, e = tx.All(ctx, "SELECT id FROM jm_gpu_allocations WHERE allocation_id=? AND released_at IS NULL ORDER BY gpu_uuid"+tx.ForUpdate(), allocation["id"]); e != nil {
				return e
			}
			if e = c.requireClaimTx(ctx, tx, claim); e != nil {
				return e
			}
			if e = tx.Update(ctx, "jm_allocations", map[string]any{"id": allocation["id"]}, map[string]any{"state": "RELEASED", "released_at": c.now()}); e != nil {
				return e
			}
			_, e = tx.Exec(ctx, "UPDATE jm_gpu_allocations SET released_at=? WHERE allocation_id=? AND released_at IS NULL", c.now(), allocation["id"])
			released = e == nil
			return e
		})
		if e != nil {
			return false, e
		}
		if !released {
			return false, nil
		}
	}
	return true, nil
}
func (c *Controller) retry(ctx context.Context, jobID string, manual bool) (bool, error) {
	queued := false
	err := c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), jobID)
		if e != nil || job == nil {
			return e
		}
		attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE job_id=? AND number=?", jobID, job["current_attempt"])
		if e != nil || attempt == nil {
			return e
		}
		p := PublicationObservation{Known: publicationKnown(str(attempt["publication_status"])), Status: str(attempt["publication_status"])}
		if str(job["state"]) != "RECONCILING" || !SafeToReuse(flag(attempt["revocation_confirmed"]), flag(attempt["termination_confirmed"]), p) {
			return nil
		}
		if deadline, ok := moment(job["deadline_at"]); ok && !c.now().Before(deadline) {
			_, e = c.terminalTx(ctx, tx, job, "FAILED", "deadline_exceeded")
			queued = e == nil
			return e
		}
		retries := num(obj(attempt["details_json"])["automatic_retries"])
		if !manual && retries >= 3 {
			_, e = c.terminalTx(ctx, tx, job, "FAILED", "retry_exhausted")
			queued = e == nil
			return e
		}
		retries++
		if manual {
			retries = 0
		}
		number := num(job["current_attempt"]) + 1
		if e = tx.Insert(ctx, "jm_attempts", map[string]any{"id": domain.NewID(), "job_id": jobID, "number": number, "epoch": num(job["epoch"]) + 1, "state": "QUEUED", "details_json": map[string]any{"automatic_retries": retries}, "created_at": c.now()}); e != nil {
			return e
		}
		next := c.now()
		if !manual {
			delay, _ := RetryDelay(retries)
			next = next.Add(delay)
		}
		count := num(job["attempt_count"])
		if number > count {
			count = number
		}
		values := map[string]any{"current_attempt": number, "attempt_count": count, "state": "QUEUED", "phase": "waiting_resources", "terminated_at": nil, "artifacts_expire_at": nil, "cleanup_status": "none", "next_attempt_at": next, "queue_reason": map[string]any{"code": "dependencies", "available_at": next.Format(time.RFC3339Nano)}, "error_code": nil, "version": num(job["version"]) + 1, "updated_at": c.now()}
		if e = tx.Update(ctx, "jm_jobs", map[string]any{"id": jobID}, values); e != nil {
			return e
		}
		for _, table := range []string{"jm_artifacts", "jm_log_chunks"} {
			if _, e = tx.Exec(ctx, "UPDATE "+table+" SET expires_at=NULL WHERE job_id=? AND deleted_at IS NULL", jobID); e != nil {
				return e
			}
		}
		queued = true
		return c.event(ctx, tx, job, "retry_queued", map[string]any{"manual": manual, "automatic_retries": retries})
	})
	return queued, err
}
func publicationKnown(s string) bool {
	return s == "none" || s == "absent" || s == "confirmed" || s == "published"
}
func (c *Controller) terminal(ctx context.Context, jobID, state, reason string) error {
	return c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		hint, e := tx.One(ctx, "SELECT project_id FROM jm_jobs WHERE id=?", jobID)
		if e != nil || hint == nil {
			return e
		}
		if _, e = tx.One(ctx, "SELECT id FROM jm_projects WHERE id=?"+tx.ForUpdate(), hint["project_id"]); e != nil {
			return e
		}
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), jobID)
		if e != nil || job == nil {
			return e
		}
		_, e = c.terminalTx(ctx, tx, job, state, reason)
		return e
	})
}
func (c *Controller) terminalTx(ctx context.Context, tx *store.Tx, job map[string]any, state, reason string) (bool, error) {
	if terminal(str(job["state"])) || (str(job["state"]) == "CANCELLING" && state == "SUCCEEDED") {
		return false, nil
	}
	if !terminal(state) {
		return false, domain.Err(422, "invalid_terminal_state")
	}
	project, e := tx.One(ctx, "SELECT * FROM jm_projects WHERE id=?", job["project_id"])
	if e != nil {
		return false, e
	}
	if project == nil {
		return false, domain.Err(409, "project_not_found")
	}
	expires := c.now().Add(time.Duration(num(project["retention_days"])) * 24 * time.Hour)
	var failure any
	if state == "FAILED" {
		failure = reason
	}
	values := map[string]any{"state": state, "phase": "finished", "outcome_reason": reason, "error_code": failure, "backfill_count": int64(0), "terminated_at": c.now(), "updated_at": c.now(), "artifacts_expire_at": expires, "cleanup_status": "pending", "version": num(job["version"]) + 1}
	if e = tx.Update(ctx, "jm_jobs", map[string]any{"id": job["id"]}, values); e != nil {
		return false, e
	}
	if _, e = tx.Exec(ctx, "UPDATE jm_attempts SET state=?,ended_at=? WHERE job_id=? AND number=?", state, c.now(), job["id"], job["current_attempt"]); e != nil {
		return false, e
	}
	for _, table := range []string{"jm_artifacts", "jm_log_chunks"} {
		if _, e = tx.Exec(ctx, "UPDATE "+table+" SET expires_at=? WHERE job_id=? AND deleted_at IS NULL", expires, job["id"]); e != nil {
			return false, e
		}
	}
	if e = c.event(ctx, tx, job, stringsLower(state), map[string]any{"reason": reason}); e != nil {
		return false, e
	}
	return true, c.enqueue(ctx, tx, job, "cleanup", map[string]any{}, "")
}
func (c *Controller) cleanup(ctx context.Context, claim Claim) (bool, error) {
	job, attempt, allocations, e := c.snapshot(ctx, claim.JobID, "")
	if e != nil {
		return false, e
	}
	if job == nil {
		return true, nil
	}
	if !terminal(str(job["state"])) || len(allocations) > 0 {
		return false, nil
	}
	deletes := claim.Topic == "purge" || claim.Topic == "expire_artifacts"
	status := str(job["cleanup_status"])
	if job["purged_at"] != nil || (!deletes && (status == "purge_pending" || status == "expiry_pending" || status == "expired")) || (claim.Topic == "expire_artifacts" && status == "purge_pending") {
		return true, nil
	}
	confirmed := false
	if deletes {
		retained, e := c.DB.All(ctx, "SELECT * FROM jm_allocations WHERE job_id=? AND state='RELEASED' ORDER BY pool_id,id", job["id"])
		if e != nil {
			return false, e
		}
		for _, allocation := range retained {
			details := obj(allocation["details_json"])
			if flag(details["storage_deleted"]) || !flag(details["retained_disk_charged"]) {
				continue
			}
			if e = c.requireClaim(ctx, claim); e != nil {
				return false, e
			}
			oldAttempt := map[string]any{"id": allocation["attempt_id"]}
			ok, e := c.Executor.Purge(ctx, identity(job, oldAttempt, allocation))
			if e != nil || !ok {
				return false, e
			}
		}
		if e = c.requireClaim(ctx, claim); e != nil {
			return false, e
		}
		if claim.Topic == "purge" {
			confirmed, e = c.Provisioner.PurgeJob(ctx, job)
		} else {
			confirmed, e = c.Provisioner.ExpireArtifacts(ctx, job)
		}
		if e != nil {
			return false, e
		}
		if e = c.requireClaim(ctx, claim); e != nil {
			return false, e
		}
		if confirmed {
			e = c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
				pools := map[string]bool{}
				for _, allocation := range retained {
					pools[str(allocation["pool_id"])] = true
				}
				ids := []string{}
				for id := range pools {
					ids = append(ids, id)
				}
				sort.Strings(ids)
				for _, id := range ids {
					if _, e := tx.One(ctx, "SELECT id FROM jm_pools WHERE id=?"+tx.ForUpdate(), id); e != nil {
						return e
					}
				}
				if _, e := tx.One(ctx, "SELECT id FROM jm_projects WHERE id=?"+tx.ForUpdate(), job["project_id"]); e != nil {
					return e
				}
				if _, e := tx.One(ctx, "SELECT id FROM jm_jobs WHERE id=?"+tx.ForUpdate(), job["id"]); e != nil {
					return e
				}
				rows, e := tx.All(ctx, "SELECT * FROM jm_allocations WHERE job_id=? AND state='RELEASED'"+tx.ForUpdate(), job["id"])
				if e != nil {
					return e
				}
				for _, row := range rows {
					details := copyMap(obj(row["details_json"]))
					details["storage_deleted"] = true
					if e = tx.Update(ctx, "jm_allocations", map[string]any{"id": row["id"]}, map[string]any{"details_json": details}); e != nil {
						return e
					}
				}
				resources, e := tx.All(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id=? AND kind IN ('execution_state','retained_output','retained_artifact_root','collection_budget')"+tx.ForUpdate(), job["id"])
				if e != nil {
					return e
				}
				for _, row := range resources {
					if str(obj(row["ownership_json"])["job_id"]) != str(job["id"]) {
						return domain.Err(409, "unsafe_output")
					}
					if e = tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": row["id"]}, map[string]any{"state": "deleted", "deleted_at": c.now(), "updated_at": c.now()}); e != nil {
						return e
					}
				}
				return nil
			})
			if e != nil {
				return false, e
			}
			if c.Storage == nil {
				return false, domain.Err(503, "storage_unavailable")
			}
			if e = c.Storage.ConfirmJobDataDeleted(ctx, str(job["id"])); e != nil {
				return false, e
			}
		}
	} else {
		if attempt != nil && (!flag(attempt["revocation_confirmed"]) || !flag(attempt["termination_confirmed"])) {
			proved, e := c.confirmNeverStarted(ctx, claim, str(job["id"]), str(attempt["id"]))
			if e != nil {
				return false, e
			}
			if !proved {
				return false, domain.Err(409, "cleanup_fencing_unconfirmed")
			}
			job, attempt, _, e = c.snapshot(ctx, str(job["id"]), str(attempt["id"]))
			if e != nil {
				return false, e
			}
		}
		if e = c.requireClaim(ctx, claim); e != nil {
			return false, e
		}
		confirmed, e = c.Provisioner.Cleanup(ctx, job, attempt)
		if e != nil {
			return false, e
		}
		if e = c.requireClaim(ctx, claim); e != nil {
			return false, e
		}
	}
	e = c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		stored, err := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), job["id"])
		if err != nil || stored == nil {
			return err
		}
		currentStatus := str(stored["cleanup_status"])
		if !deletes && (stored["purged_at"] != nil || currentStatus == "purge_pending" || currentStatus == "expiry_pending" || currentStatus == "expired") {
			return nil
		}
		newStatus := "failed"
		event := "cleanup"
		if deletes {
			if claim.Topic == "purge" {
				newStatus = "purge_pending"
				if confirmed {
					newStatus = "complete"
					event = "purged"
				}
			} else {
				newStatus = "expiry_pending"
				if confirmed {
					newStatus = "expired"
					event = "artifacts_expired"
				}
			}
		} else if confirmed {
			newStatus = "complete"
		}
		values := map[string]any{"cleanup_status": newStatus, "version": num(stored["version"]) + 1, "updated_at": c.now()}
		if confirmed && claim.Topic == "purge" {
			values["purged_at"] = c.now()
		}
		if err = tx.Update(ctx, "jm_jobs", map[string]any{"id": job["id"]}, values); err != nil {
			return err
		}
		return c.event(ctx, tx, stored, event, map[string]any{"confirmed": confirmed})
	})
	return confirmed, e
}
