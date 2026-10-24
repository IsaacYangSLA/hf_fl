package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

var liveStates = []string{"RESERVED", "ACKNOWLEDGED", "STARTING", "RUNNING", "QUARANTINED", "RELEASING"}

const liveSQL = "('RESERVED','ACKNOWLEDGED','STARTING','RUNNING','QUARANTINED','RELEASING')"

func str(v any) string {
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}
func num(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case json.Number:
		n, _ := x.Int64()
		return n
	case float64:
		if x == math.Trunc(x) && x <= math.MaxInt64 && x >= math.MinInt64 {
			return int64(x)
		}
	}
	return 0
}
func flag(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int64:
		return x == 1
	case int:
		return x == 1
	}
	return false
}
func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}
func array(v any) []any              { a, _ := v.([]any); return a }
func moment(v any) (time.Time, bool) { return store.Time(v) }
func copyMap(m map[string]any) map[string]any {
	n := map[string]any{}
	for k, v := range m {
		n[k] = v
	}
	return n
}
func terminal(state string) bool {
	return state == "SUCCEEDED" || state == "FAILED" || state == "CANCELLED"
}
func identity(job, attempt, allocation map[string]any) executor.ExecutionIdentity {
	return executor.ExecutionIdentity{JobID: str(job["id"]), AttemptID: str(attempt["id"]), ComponentID: str(allocation["component_id"]), Epoch: num(allocation["epoch"])}
}
func (c *Controller) now() time.Time {
	if c.Clock != nil {
		return c.Clock().UTC()
	}
	return time.Now().UTC()
}
func code(err error) string {
	if err == nil {
		return ""
	}
	var e *domain.Error
	if errors.As(err, &e) {
		return e.Code
	}
	if v := executor.ErrorCode(err); v != "" {
		return v
	}
	return "controller_error"
}
func uncertain(err error) bool {
	var network net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || errors.As(err, &network) || executor.IsUncertain(err) || code(err) == "execution_unknown"
}
func transientCode(s string) bool {
	switch s {
	case "capacity", "runtime_unhealthy", "lease_expired", "node_quarantined", "proxy_restart_required", "heartbeat_expired", "heartbeat_lost", "execution_unknown":
		return true
	}
	return false
}
func (c *Controller) event(ctx context.Context, tx *store.Tx, job map[string]any, kind string, data map[string]any) error {
	row, err := tx.One(ctx, "SELECT COALESCE(MAX(sequence),0) AS sequence FROM jm_events WHERE job_id=?", job["id"])
	if err != nil {
		return err
	}
	current, err := tx.One(ctx, "SELECT version,epoch FROM jm_jobs WHERE id=?", job["id"])
	if err != nil {
		return err
	}
	return tx.Insert(ctx, "jm_events", map[string]any{"id": domain.NewID(), "job_id": job["id"], "sequence": num(row["sequence"]) + 1, "kind": kind, "data_json": data, "version": current["version"], "epoch": current["epoch"], "created_at": c.now()})
}
func (c *Controller) enqueue(ctx context.Context, tx *store.Tx, job map[string]any, topic string, payload map[string]any, attemptID string) error {
	id := domain.NewID()
	var aid any
	if attemptID != "" {
		aid = attemptID
	}
	return tx.Insert(ctx, "jm_outbox", map[string]any{"id": id, "job_id": job["id"], "attempt_id": aid, "attempt_number": num(job["current_attempt"]), "topic": topic, "payload_json": payload, "idempotency_key": id, "state": "pending", "created_at": c.now()})
}
func (c *Controller) snapshot(ctx context.Context, jobID, attemptID string) (map[string]any, map[string]any, []map[string]any, error) {
	var job, attempt map[string]any
	var allocations []map[string]any
	err := c.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		var e error
		job, e = tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?", jobID)
		if e != nil || job == nil {
			return e
		}
		if attemptID != "" {
			attempt, e = tx.One(ctx, "SELECT * FROM jm_attempts WHERE id=? AND job_id=?", attemptID, jobID)
		} else {
			attempt, e = tx.One(ctx, "SELECT * FROM jm_attempts WHERE job_id=? AND number=?", jobID, job["current_attempt"])
		}
		if e != nil || attempt == nil {
			return e
		}
		allocations, e = tx.All(ctx, "SELECT * FROM jm_allocations WHERE job_id=? AND attempt_id=? AND state IN "+liveSQL+" ORDER BY pool_id,id", jobID, attempt["id"])
		return e
	})
	return job, attempt, allocations, err
}
func (c *Controller) current(ctx context.Context, jobID, attemptID string, epoch int64, states ...string) (bool, error) {
	job, attempt, _, err := c.snapshot(ctx, jobID, attemptID)
	if err != nil || job == nil || attempt == nil {
		return false, err
	}
	if num(job["epoch"]) != epoch || num(attempt["epoch"]) != epoch || num(attempt["number"]) != num(job["current_attempt"]) {
		return false, nil
	}
	if len(states) > 0 {
		for _, s := range states {
			if str(job["state"]) == s {
				return true, nil
			}
		}
		return false, nil
	}
	return true, nil
}
func (c *Controller) requireClaim(ctx context.Context, claim Claim) error {
	row, e := c.DB.One(ctx, "SELECT state,lease_owner,lease_until FROM jm_outbox WHERE id=?", claim.ID)
	if e != nil {
		return e
	}
	until, ok := moment(row["lease_until"])
	if row == nil || str(row["state"]) != "processing" || str(row["lease_owner"]) != claim.Owner || !ok || !c.now().Before(until) {
		return domain.Err(409, "stale_claim")
	}
	return nil
}
func observation(value any) map[string]any {
	switch x := value.(type) {
	case bool:
		return map[string]any{"confirmed": x}
	case executor.Reservation:
		return map[string]any{"state": x.State, "acknowledged": x.Acknowledged}
	case executor.RuntimeObservation:
		return map[string]any{"state": x.State, "termination_confirmed": x.TerminationConfirmed, "publication_status": x.PublicationStatus, "current_round": x.CurrentRound, "error_code": x.ErrorCode, "transient": x.Transient, "exit_code": x.ExitCode}
	case PublicationObservation:
		return map[string]any{"known": x.Known, "status": x.Status, "current_round": x.CurrentRound}
	default:
		return map[string]any{"confirmed": false}
	}
}
func (c *Controller) operation(ctx context.Context, claim Claim, job, attempt map[string]any, component, action string, desired map[string]any, effect func() (any, error)) (any, error) {
	if e := c.requireClaim(ctx, claim); e != nil {
		return nil, e
	}
	key := fmt.Sprintf("%s:%s:%d:%s:%s", str(job["id"]), str(attempt["id"]), num(attempt["epoch"]), component, action)
	operationID := ""
	err := c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		locked, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), job["id"])
		if e != nil {
			return e
		}
		if locked == nil || num(locked["epoch"]) != num(attempt["epoch"]) || num(locked["current_attempt"]) != num(attempt["number"]) {
			return domain.Err(409, "stale_epoch")
		}
		existing, e := tx.One(ctx, "SELECT * FROM jm_provisioning_operations WHERE idempotency_key=?"+tx.ForUpdate(), key)
		if e != nil {
			return e
		}
		if existing != nil {
			operationID = str(existing["id"])
			return nil
		}
		operationID = domain.NewID()
		d := copyMap(desired)
		d["epoch"] = num(attempt["epoch"])
		return tx.Insert(ctx, "jm_provisioning_operations", map[string]any{"id": operationID, "job_id": job["id"], "attempt_id": attempt["id"], "component_id": component, "operation": action, "idempotency_key": key, "desired_json": d, "state": "pending", "created_at": c.now(), "updated_at": c.now()})
	})
	if err != nil {
		return nil, err
	}
	if err = c.requireClaim(ctx, claim); err != nil {
		return nil, err
	}
	value, err := effect()
	if err == nil {
		err = c.requireClaim(ctx, claim)
	}
	if err != nil {
		if code(err) != "stale_claim" {
			_ = c.DB.WithTx(context.WithoutCancel(ctx), true, func(tx *store.Tx) error {
				op, e := tx.One(context.WithoutCancel(ctx), "SELECT * FROM jm_provisioning_operations WHERE id=?"+tx.ForUpdate(), operationID)
				if e != nil || op == nil {
					return e
				}
				values := map[string]any{"last_error": code(err), "updated_at": c.now()}
				if str(op["state"]) != "confirmed" {
					values["state"] = "unknown"
					if !uncertain(err) && code(err) != "controller_error" {
						values["state"] = "refused"
					}
				}
				return tx.Update(context.WithoutCancel(ctx), "jm_provisioning_operations", map[string]any{"id": operationID}, values)
			})
		}
		return nil, err
	}
	err = c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		// Lifecycle rows precede the claim row. Restart restoration locks
		// jobs before its outbox row, so claim-first confirmation can deadlock.
		locked, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), job["id"])
		if e != nil {
			return e
		}
		if locked == nil || num(locked["epoch"]) != num(attempt["epoch"]) || num(locked["current_attempt"]) != num(attempt["number"]) {
			return domain.Err(409, "stale_epoch")
		}
		if _, e = tx.One(ctx, "SELECT id FROM jm_provisioning_operations WHERE id=?"+tx.ForUpdate(), operationID); e != nil {
			return e
		}
		if e = c.requireClaimTx(ctx, tx, claim); e != nil {
			return e
		}
		return tx.Update(ctx, "jm_provisioning_operations", map[string]any{"id": operationID}, map[string]any{"state": "confirmed", "observed_json": observation(value), "last_error": nil, "updated_at": c.now()})
	})
	return value, err
}

// requireClaimTx is the final lifecycle row lock: pools, projects, jobs,
// attempts/allocations/operations must already be locked before calling it.
// Keeping this lock through commit makes the ownership/expiry check atomic
// with the protected mutation without introducing an outbox-to-job inversion.
func (c *Controller) requireClaimTx(ctx context.Context, tx *store.Tx, claim Claim) error {
	row, e := tx.One(ctx, "SELECT * FROM jm_outbox WHERE id=?"+tx.ForUpdate(), claim.ID)
	if e != nil {
		return e
	}
	until, ok := moment(row["lease_until"])
	if row == nil || str(row["state"]) != "processing" || str(row["lease_owner"]) != claim.Owner || !ok || !c.now().Before(until) {
		return domain.Err(409, "stale_claim")
	}
	return nil
}
func validPublication(s string) bool {
	switch s {
	case "none", "absent", "confirmed", "published", "unknown", "publishing", "ambiguous", "not_observed":
		return true
	}
	return false
}
