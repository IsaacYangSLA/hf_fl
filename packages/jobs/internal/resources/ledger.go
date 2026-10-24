package resources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

type OperationRequest struct {
	JobID, AttemptID, ComponentID, Operation, Key string
	Desired                                       map[string]any
}
type Ownership struct {
	JobID, AttemptID, ComponentID, Kind, ExternalID string
	Details                                         map[string]any
	Retained                                        bool
}
type ResourceFilter struct{ AttemptID, Kind string }
type Ledger struct {
	DB    *store.DB
	Clock func() time.Time
}

func NewLedger(db *store.DB) *Ledger {
	return &Ledger{DB: db, Clock: func() time.Time { return time.Now().UTC() }}
}
func (l *Ledger) now() time.Time {
	if l.Clock == nil {
		return time.Now().UTC()
	}
	return l.Clock().UTC()
}
func object(v any) map[string]any {
	if m, ok := v.(map[string]any); ok && m != nil {
		return m
	}
	return map[string]any{}
}
func str(v any) string { s, _ := v.(string); return s }
func integer(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int64:
		return x, true
	case int32:
		return int64(x), true
	case uint64:
		if x <= uint64(^uint64(0)>>1) {
			return int64(x), true
		}
	case json.Number:
		n, e := x.Int64()
		return n, e == nil
	}
	return 0, false
}
func equal(a, b any) bool {
	x, e := domain.CanonicalJSON(a)
	if e != nil {
		return false
	}
	y, e := domain.CanonicalJSON(b)
	return e == nil && bytes.Equal(x, y)
}
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func validateOperation(r OperationRequest) error {
	for _, s := range []string{r.JobID, r.ComponentID} {
		if identifier(s) != nil {
			return ErrUnsafe
		}
	}
	if r.AttemptID != "" && identifier(r.AttemptID) != nil {
		return ErrUnsafe
	}
	if len(r.Key) == 0 || len(r.Key) > 256 || len(r.Operation) == 0 || len(r.Operation) > 64 {
		return ErrUnsafe
	}
	raw, err := domain.CanonicalJSON(r.Desired)
	if err != nil || len(raw) > 1024*1024 {
		return ErrUnsafe
	}
	return nil
}

// Run persists intent before external effects. Its claim token also fences a
// slow worker whose lease was adopted after the five-minute recovery window.
func (l *Ledger) Run(ctx context.Context, r OperationRequest, action func(context.Context) (map[string]any, error)) (map[string]any, error) {
	if l.DB == nil || action == nil || validateOperation(r) != nil {
		return nil, ErrUnsafe
	}
	identity := StableKey("operation", r.Key)[:32]
	token := domain.NewID()
	now := l.now()
	var replay map[string]any
	err := l.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		row, e := tx.One(ctx, "SELECT * FROM jm_provisioning_operations WHERE idempotency_key=?"+tx.ForUpdate(), r.Key)
		if e != nil {
			return e
		}
		if row == nil {
			if e = tx.Insert(ctx, "jm_provisioning_operations", map[string]any{"id": identity, "job_id": r.JobID, "attempt_id": nullable(r.AttemptID), "component_id": r.ComponentID, "operation": r.Operation, "idempotency_key": r.Key, "state": "planned", "desired_json": r.Desired, "observed_json": map[string]any{}, "created_at": now, "updated_at": now}); e != nil {
				return e
			}
			row = map[string]any{"id": identity, "job_id": r.JobID, "component_id": r.ComponentID, "operation": r.Operation, "desired_json": r.Desired, "state": "planned"}
		}
		if row["job_id"] != r.JobID || row["component_id"] != r.ComponentID || row["operation"] != r.Operation || !equal(row["desired_json"], r.Desired) {
			return ErrUnsafe
		}
		identity = str(row["id"])
		if row["state"] == "ready" {
			replay = object(row["observed_json"])
			return nil
		}
		updated, ok := store.Time(row["updated_at"])
		if row["state"] == "executing" && ok && updated.Add(5*time.Minute).After(now) {
			return ErrBusy
		}
		return tx.Update(ctx, "jm_provisioning_operations", map[string]any{"id": identity}, map[string]any{"state": "executing", "observed_json": map[string]any{"__lease_token": token}, "updated_at": now})
	})
	if err != nil {
		return nil, err
	}
	if replay != nil {
		return replay, nil
	}
	var observed map[string]any
	var actionErr error
	var panicValue any
	func() { defer func() { panicValue = recover() }(); observed, actionErr = action(ctx) }()
	if panicValue != nil {
		actionErr = errors.New("provisioning action panicked")
	}
	if observed == nil && actionErr == nil {
		observed = map[string]any{}
	}
	if _, e := domain.CanonicalJSON(observed); e != nil && actionErr == nil {
		actionErr = ErrUnsafe
	}
	// Completion must be persisted even when the caller's deadline was cancelled.
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	finishErr := l.DB.WithTx(finishCtx, true, func(tx *store.Tx) error {
		row, e := tx.One(finishCtx, "SELECT * FROM jm_provisioning_operations WHERE id=?"+tx.ForUpdate(), identity)
		if e != nil {
			return e
		}
		if row == nil || row["state"] != "executing" || object(row["observed_json"])["__lease_token"] != token {
			return ErrBusy
		}
		values := map[string]any{"state": "ready", "observed_json": observed, "last_error": nil, "updated_at": l.now()}
		if actionErr != nil {
			values["state"] = "unknown"
			values["observed_json"] = map[string]any{}
			values["last_error"] = "external_operation_failed"
		}
		return tx.Update(finishCtx, "jm_provisioning_operations", map[string]any{"id": identity}, values)
	})
	if panicValue != nil {
		panic(panicValue)
	}
	if finishErr != nil {
		return nil, finishErr
	}
	if actionErr != nil {
		return nil, actionErr
	}
	return observed, nil
}
func (l *Ledger) Own(ctx context.Context, r Ownership) (string, error) {
	for _, s := range []string{r.JobID, r.ComponentID, r.Kind} {
		if identifier(s) != nil {
			return "", ErrUnsafe
		}
	}
	if r.AttemptID != "" && identifier(r.AttemptID) != nil {
		return "", ErrUnsafe
	}
	if r.ExternalID == "" || len(r.ExternalID) > 1024 {
		return "", ErrUnsafe
	}
	size := int64(0)
	if v, ok := r.Details["size_bytes"]; ok {
		var valid bool
		size, valid = integer(v)
		if !valid || size < 0 {
			return "", ErrUnsafe
		}
	}
	own := map[string]any{"job_id": r.JobID, "component_id": r.ComponentID, "kind": r.Kind}
	id := StableKey("resource", r.JobID, r.Kind, r.ExternalID)[:32]
	err := l.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		row, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE kind=? AND external_id=?"+tx.ForUpdate(), r.Kind, r.ExternalID)
		if e != nil {
			return e
		}
		if row != nil {
			if row["job_id"] != r.JobID || !equal(row["ownership_json"], own) {
				return ErrUnsafe
			}
			id = str(row["id"])
			return nil
		}
		details := r.Details
		if details == nil {
			details = map[string]any{}
		}
		return tx.Insert(ctx, "jm_provisioning_resources", map[string]any{"id": id, "job_id": r.JobID, "attempt_id": nullable(r.AttemptID), "component_id": r.ComponentID, "kind": r.Kind, "external_id": r.ExternalID, "ownership_json": own, "details_json": details, "state": "ready", "retained": r.Retained, "size_bytes": size, "created_at": l.now(), "updated_at": l.now()})
	})
	return id, err
}
func (l *Ledger) Resources(ctx context.Context, jobID string, filter ResourceFilter) ([]map[string]any, error) {
	if identifier(jobID) != nil {
		return nil, ErrUnsafe
	}
	q := "SELECT * FROM jm_provisioning_resources WHERE job_id=?"
	args := []any{jobID}
	if filter.AttemptID != "" {
		q += " AND attempt_id=?"
		args = append(args, filter.AttemptID)
	}
	if filter.Kind != "" {
		q += " AND kind=?"
		args = append(args, filter.Kind)
	}
	q += " ORDER BY id"
	rows, err := l.DB.All(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	result := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		result = append(result, map[string]any{"id": row["id"], "attempt_id": row["attempt_id"], "component_id": row["component_id"], "kind": row["kind"], "external_id": row["external_id"], "ownership": row["ownership_json"], "details": row["details_json"], "state": row["state"], "retained": row["retained"], "size_bytes": row["size_bytes"]})
	}
	return result, nil
}
func (l *Ledger) Deleted(ctx context.Context, resourceID, jobID string) error {
	return l.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		row, err := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id=?"+tx.ForUpdate(), resourceID)
		if err != nil {
			return err
		}
		if row == nil || row["job_id"] != jobID || object(row["ownership_json"])["job_id"] != jobID {
			return ErrUnsafe
		}
		return tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": resourceID}, map[string]any{"state": "deleted", "deleted_at": l.now(), "updated_at": l.now()})
	})
}
func (e *Ledger) String() string { return fmt.Sprintf("resource ledger(%s)", e.DB.Dialect) }
