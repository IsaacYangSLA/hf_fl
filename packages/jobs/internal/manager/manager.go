// Package manager implements transactional job policy independently of HTTP and executors.
package manager

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/scheduler"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

type Object = map[string]any
type Manager struct {
	DB                  *store.DB
	AdminPolicy         *AdminPolicy
	Clock               func() time.Time
	CursorSecret        []byte
	PlatformOperatorIDs map[string]bool
	PoolQualifier       func(context.Context, Object) (bool, error)
	AdmissionValidator  func(context.Context, *store.Tx, domain.JobSpec) error
	StoragePlanner      func(context.Context, Object) ([]scheduler.StoragePlan, error)
	StoragePlannerTx    func(context.Context, *store.Tx, Object) ([]scheduler.StoragePlan, error)
}

func New(db *store.DB, secret []byte) (*Manager, error) {
	if db == nil || len(secret) < 32 {
		return nil, errors.New("database and cursor secret of at least 32 bytes are required")
	}
	return &Manager{DB: db, Clock: time.Now, CursorSecret: append([]byte(nil), secret...), PlatformOperatorIDs: map[string]bool{}, AdmissionValidator: scheduler.ValidateAdmission}, nil
}
func (m *Manager) now() time.Time {
	if m.Clock != nil {
		return m.Clock().UTC()
	}
	return time.Now().UTC()
}
func text(v any) string { x, _ := v.(string); return x }
func obj(v any) Object {
	x, _ := v.(map[string]any)
	if x == nil {
		return Object{}
	}
	return x
}
func arr(v any) []any {
	if x, ok := v.([]any); ok {
		return x
	}
	if x, ok := v.([]map[string]any); ok {
		a := make([]any, len(x))
		for i := range x {
			a[i] = x[i]
		}
		return a
	}
	if x, ok := v.([]string); ok {
		a := make([]any, len(x))
		for i := range x {
			a[i] = x[i]
		}
		return a
	}
	return []any{}
}
func number(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case int32:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) || n != math.Trunc(n) || n >= 9223372036854775808 || n < -9223372036854775808 {
			return 0
		}
		return int64(n)
	}
	return 0
}
func strictInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case json.Number:
		i, e := n.Int64()
		return i, e == nil
	}
	return 0, false
}
func flag(v any) bool { x, _ := v.(bool); return x }
func copyObject(v Object) Object {
	x := Object{}
	for k, n := range v {
		x[k] = n
	}
	return x
}
func iso(v any) any {
	t, ok := store.Time(v)
	if !ok {
		return nil
	}
	return t.UTC().Format("2006-01-02T15:04:05.999999Z")
}
func expired(v any, now time.Time) bool { t, ok := store.Time(v); return ok && !t.After(now) }
func roleLevel(role string) int {
	switch role {
	case "reader":
		return 1
	case "operator":
		return 2
	case "admin":
		return 3
	}
	return 0
}
func has(list any, s string) bool {
	for _, v := range arr(list) {
		if text(v) == s {
			return true
		}
	}
	return false
}
func badText(s string, max int) bool {
	if s == "" || utf8.RuneCountInString(s) > max {
		return true
	}
	for _, c := range s {
		if c < 32 {
			return true
		}
	}
	return false
}
func principal(actor string) error {
	if badText(actor, 256) {
		return domain.Err(401, "invalid_principal")
	}
	return nil
}
func key(value string) error {
	if badText(value, 128) {
		return domain.Err(422, "idempotency_key_required")
	}
	return nil
}
func pageLimit(n int) error {
	if n < 1 || n > 100 {
		return domain.Err(422, "invalid_page_limit")
	}
	return nil
}
func hash(v any) (string, error) {
	raw, e := domain.CanonicalJSON(v)
	if e != nil {
		return "", e
	}
	d := sha256.Sum256(raw)
	return hex.EncodeToString(d[:]), nil
}
func (m *Manager) withJob(ctx context.Context, actor, id, role string, write bool, fn func(*store.Tx, Object, Object) error) error {
	if e := principal(actor); e != nil {
		return e
	}
	return m.DB.WithTx(ctx, write, func(tx *store.Tx) error {
		suffix := ""
		if write {
			suffix = tx.ForUpdate()
		}
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?"+suffix, id)
		if e != nil {
			return e
		}
		var member Object
		if job != nil {
			member, e = tx.One(ctx, "SELECT * FROM jm_job_members WHERE job_id = ? AND principal_id = ?", id, actor)
			if e != nil {
				return e
			}
		}
		if member == nil || roleLevel(text(member["role"])) == 0 {
			return domain.Err(404, "job_not_found")
		}
		if roleLevel(text(member["role"])) < roleLevel(role) {
			return domain.Err(403, "job_role_required")
		}
		return fn(tx, job, member)
	})
}
func (m *Manager) once(ctx context.Context, tx *store.Tx, actor, scope, k string, body any, action func() (Object, error), replay func(Object) (Object, error)) (Object, error) {
	if e := key(k); e != nil {
		return nil, e
	}
	if tx.Dialect == "postgresql" {
		raw, e := domain.CanonicalJSON([]any{actor, scope, k})
		if e != nil {
			return nil, e
		}
		if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", string(raw)); e != nil {
			return nil, e
		}
	}
	digest, e := hash(body)
	if e != nil {
		return nil, e
	}
	old, e := tx.One(ctx, "SELECT * FROM jm_idempotency WHERE principal_id = ? AND scope = ? AND key = ?", actor, scope, k)
	if e != nil {
		return nil, e
	}
	if old != nil {
		if text(old["request_hash"]) != digest {
			return nil, domain.Err(409, "idempotency_conflict")
		}
		result := obj(old["response_json"])
		if replay != nil {
			return replay(result)
		}
		return result, nil
	}
	result, e := action()
	if e != nil {
		return nil, e
	}
	e = tx.Insert(ctx, "jm_idempotency", Object{"principal_id": actor, "scope": scope, "key": k, "request_hash": digest, "response_json": result, "created_at": m.now()})
	return result, e
}

// AppendEvent requires the caller to hold the owning job's write lock.
func AppendEvent(ctx context.Context, tx *store.Tx, jobID, kind, actor string, data Object, now time.Time) error {
	row, e := tx.One(ctx, "SELECT COALESCE(MAX(sequence),0) AS n FROM jm_events WHERE job_id = ?", jobID)
	if e != nil {
		return e
	}
	if data == nil {
		data = Object{}
	}
	var actorValue any = actor
	if actor == "" {
		actorValue = nil
	}
	return tx.Insert(ctx, "jm_events", Object{"id": domain.NewID(), "job_id": jobID, "sequence": number(row["n"]) + 1, "kind": kind, "actor_id": actorValue, "data_json": data, "created_at": now})
}
func (m *Manager) outbox(ctx context.Context, tx *store.Tx, job Object, kind, actor string, payload Object) error {
	id := domain.NewID()
	if payload == nil {
		payload = Object{}
	}
	if e := tx.Insert(ctx, "jm_outbox", Object{"id": id, "job_id": job["id"], "attempt_number": job["current_attempt"], "topic": kind, "payload_json": payload, "state": "pending", "idempotency_key": id, "created_at": m.now()}); e != nil {
		return e
	}
	return AppendEvent(ctx, tx, text(job["id"]), "operation.requested", actor, Object{"operation_id": id, "operation": kind}, m.now())
}
func (m *Manager) cursorScope(actor, kind string, filters any) (string, error) {
	return hash([]any{actor, kind, filters})
}
func (m *Manager) encodeCursor(actor, kind string, filters, position any) (string, error) {
	scope, e := m.cursorScope(actor, kind, filters)
	if e != nil {
		return "", e
	}
	payload, e := domain.CanonicalJSON(Object{"v": int64(1), "scope": scope, "position": position, "exp": m.now().Unix() + 3600})
	if e != nil {
		return "", e
	}
	mac := hmac.New(sha256.New, m.CursorSecret)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...)), nil
}
func (m *Manager) decodeCursor(cursor, actor, kind string, filters any) (any, error) {
	invalid := func() (any, error) { return nil, domain.Err(422, "invalid_cursor") }
	if cursor == "" || len(cursor) > 4096 {
		return invalid()
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(strings.TrimRight(cursor, "="))
	if e != nil || len(raw) < 33 {
		return invalid()
	}
	payload, sig := raw[:len(raw)-32], raw[len(raw)-32:]
	mac := hmac.New(sha256.New, m.CursorSecret)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return invalid()
	}
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.UseNumber()
	var value Object
	if dec.Decode(&value) != nil || len(value) != 4 || number(value["v"]) != 1 {
		return invalid()
	}
	for _, k := range []string{"v", "scope", "position", "exp"} {
		if _, ok := value[k]; !ok {
			return invalid()
		}
	}
	scope, e := m.cursorScope(actor, kind, filters)
	if e != nil || !hmac.Equal([]byte(text(value["scope"])), []byte(scope)) {
		return invalid()
	}
	exp, ok := strictInt(value["exp"])
	if !ok {
		return invalid()
	}
	if exp <= m.now().Unix() {
		return nil, domain.Err(409, "cursor_expired")
	}
	return value["position"], nil
}
func cursorPosition(value any) (time.Time, string, error) {
	p, ok := value.(map[string]any)
	if !ok || len(p) != 2 {
		return time.Time{}, "", domain.Err(422, "invalid_cursor")
	}
	stamp, ok := p["created_at"].(string)
	id, idok := p["id"].(string)
	if !ok || !idok {
		return time.Time{}, "", domain.Err(422, "invalid_cursor")
	}
	t, e := time.Parse(time.RFC3339Nano, stamp)
	if e != nil {
		return time.Time{}, "", domain.Err(422, "invalid_cursor")
	}
	return t.UTC(), id, nil
}
func requireVersion(job Object, expected int64) error {
	if expected < 1 {
		return domain.Err(428, "expected_version_required")
	}
	if expected != number(job["version"]) {
		return domain.Err(409, "job_version_conflict", Object{"current_version": job["version"]})
	}
	return nil
}
func (m *Manager) command(ctx context.Context, actor, id, role, k string, expected int64, kind string, data Object, allowPurged bool, action func(*store.Tx, Object) error) (Object, error) {
	var result Object
	e := m.withJob(ctx, actor, id, role, true, func(tx *store.Tx, job, member Object) error {
		body := copyObject(data)
		body["expected_version"] = expected
		var err error
		result, err = m.once(ctx, tx, actor, kind+":"+id, k, body, func() (Object, error) {
			if e := requireVersion(job, expected); e != nil {
				return nil, e
			}
			if job["purged_at"] != nil && !allowPurged {
				return nil, domain.Err(409, "job_purged")
			}
			if e := action(tx, job); e != nil {
				return nil, e
			}
			job["version"] = number(job["version"]) + 1
			job["updated_at"] = m.now()
			values := Object{}
			for _, key := range []string{"version", "updated_at", "state", "phase", "queue_reason", "cleanup_status"} {
				values[key] = job[key]
			}
			if e := tx.Update(ctx, "jm_jobs", Object{"id": id}, values); e != nil {
				return nil, e
			}
			if e := AppendEvent(ctx, tx, id, kind, actor, nil, m.now()); e != nil {
				return nil, e
			}
			// A caller can demote its own membership when another admin remains.
			// Refresh the response role while retaining the historical response
			// for a permitted self-removal, just as the reference ORM does.
			current, e := tx.One(ctx, "SELECT * FROM jm_job_members WHERE job_id = ? AND principal_id = ?", id, actor)
			if e != nil {
				return nil, e
			}
			if current != nil {
				member = current
			}
			return m.jobView(ctx, tx, job, member, true)
		}, nil)
		return err
	})
	return result, e
}
func decimal(v any) float64 {
	switch n := v.(type) {
	case json.Number:
		f, _ := n.Float64()
		return f
	case int64:
		return float64(n)
	case int:
		return float64(n)
	case float64:
		return n
	}
	return math.NaN()
}
func strconvID(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
