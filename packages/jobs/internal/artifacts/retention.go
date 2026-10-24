package artifacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func mapping(v any) map[string]any {
	if m, ok := v.(map[string]any); ok && m != nil {
		return m
	}
	return map[string]any{}
}
func copyMap(v any) map[string]any {
	out := map[string]any{}
	for k, x := range mapping(v) {
		out[k] = x
	}
	return out
}
func text(v any) string { s, _ := v.(string); return s }
func integer(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case int32:
		return int64(n)
	case json.Number:
		i, e := n.Int64()
		if e == nil {
			return i
		}
	}
	if v == nil {
		return 0
	}
	return -1
}
func flag(v any) bool { b, _ := v.(bool); return b }
func pythonUTC(t time.Time) string {
	t = t.UTC().Truncate(time.Microsecond)
	if t.Nanosecond() == 0 {
		return t.Format("2006-01-02T15:04:05Z07:00")
	}
	return t.Format("2006-01-02T15:04:05.000000Z07:00")
}
func stamp(v any) any {
	if t, ok := store.Time(v); ok {
		return pythonUTC(t)
	}
	return nil
}
func sameJSON(a, b any) bool {
	x, e := domain.CanonicalJSON(a)
	if e != nil {
		return false
	}
	y, e := domain.CanonicalJSON(b)
	return e == nil && string(x) == string(y)
}
func sumBytes(a, b int64) (int64, error) {
	if a < 0 || b < 0 || a > math.MaxInt64-b {
		return 0, domain.Err(409, "retained_storage_ledger_inconsistent")
	}
	return a + b, nil
}
func RetentionSummary(job map[string]any, now time.Time) map[string]any {
	expiry, ok := store.Time(job["artifacts_expire_at"])
	return map[string]any{"expires_at": stamp(job["artifacts_expire_at"]), "expired": ok && !expiry.After(now.UTC()), "cleanup_status": job["cleanup_status"], "purged_at": stamp(job["purged_at"])}
}
func ArtifactView(row map[string]any, now time.Time) map[string]any {
	expiry, ok := store.Time(row["expires_at"])
	state := text(row["state"])
	expired := (ok && !expiry.After(now.UTC())) || state == "expired" || state == "deleting" || state == "deleted"
	if expired && state != "deleted" {
		state = "expired"
	}
	return map[string]any{"id": row["id"], "attempt_number": row["attempt_number"], "kind": row["kind"], "name": row["name"], "size_bytes": row["size_bytes"], "sha256": row["sha256"], "state": state, "created_at": stamp(row["created_at"]), "expires_at": stamp(row["expires_at"]), "deleted_at": stamp(row["deleted_at"]), "download_available": !expired && (state == "available" || state == "retained")}
}

type Retention struct {
	DB    *store.DB
	Clock func() time.Time
}

func NewRetention(db *store.DB) *Retention { return &Retention{DB: db, Clock: time.Now} }
func (r *Retention) now() time.Time {
	if r.Clock != nil {
		return r.Clock().UTC()
	}
	return time.Now().UTC()
}
func projectReserve(ctx context.Context, tx *store.Tx, project map[string]any, amount int64) error {
	if amount < 0 {
		return domain.Err(422, "invalid_retained_size")
	}
	before := integer(project["retained_bytes"])
	after, e := sumBytes(before, amount)
	if e != nil {
		return e
	}
	quota := mapping(project["quotas_json"])
	limit, has := quota["retained_bytes"]
	if !has {
		limit, has = quota["disk_bytes"]
	}
	if !has {
		limit = project["quota_disk_bytes"]
	}
	if limit != nil && (integer(limit) < 0 || after > integer(limit)) {
		return domain.Err(409, "retained_storage_quota_exceeded")
	}
	version := integer(project["version"]) + 1
	if e = tx.Update(ctx, "jm_projects", map[string]any{"id": project["id"]}, map[string]any{"retained_bytes": after, "version": version}); e != nil {
		return e
	}
	project["retained_bytes"] = after
	project["version"] = version
	return nil
}
func PoolUsedBytes(ctx context.Context, tx *store.Tx, poolID string, exclude ...string) (int64, error) {
	total := int64(0)
	rows, e := tx.All(ctx, "SELECT disk_bytes,state,released_at,details_json FROM jm_allocations WHERE pool_id = ?", poolID)
	if e != nil {
		return 0, e
	}
	for _, row := range rows {
		d := mapping(row["details_json"])
		if row["released_at"] == nil || (text(row["state"]) == "RELEASED" && flag(d["retained_disk_charged"]) && !flag(d["storage_deleted"])) {
			total, e = sumBytes(total, integer(row["disk_bytes"]))
			if e != nil {
				return 0, e
			}
		}
	}
	rows, e = tx.All(ctx, "SELECT id,kind,size_bytes,details_json FROM jm_provisioning_resources WHERE retained = ? AND state <> ? AND kind <> ?", true, "deleted", "execution_state")
	if e != nil {
		return 0, e
	}
	for _, row := range rows {
		if len(exclude) > 0 && text(row["id"]) == exclude[0] {
			continue
		}
		if text(mapping(row["details_json"])["pool_id"]) == poolID {
			total, e = sumBytes(total, integer(row["size_bytes"]))
			if e != nil {
				return 0, e
			}
		}
	}
	return total, nil
}
func lockResource(ctx context.Context, tx *store.Tx, resourceID, jobID string) (project, job, resource, pool map[string]any, err error) {
	observed, err := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?", resourceID)
	if err != nil {
		return
	}
	if observed == nil || text(observed["job_id"]) != jobID || text(mapping(observed["ownership_json"])["job_id"]) != jobID {
		err = domain.Err(409, "retained_resource_ownership_mismatch")
		return
	}
	poolValue := mapping(observed["details_json"])["pool_id"]
	if poolValue != nil && text(poolValue) == "" {
		err = domain.Err(409, "retained_resource_pool_not_found")
		return
	}
	poolID := text(mapping(observed["details_json"])["pool_id"])
	if poolID != "" {
		pool, err = tx.One(ctx, "SELECT * FROM jm_pools WHERE id = ?"+tx.ForUpdate(), poolID)
		if err != nil {
			return
		}
		if pool == nil {
			err = domain.Err(409, "retained_resource_pool_not_found")
			return
		}
	}
	provisional, err := tx.One(ctx, "SELECT project_id FROM jm_jobs WHERE id = ?", jobID)
	if err != nil {
		return
	}
	if provisional == nil {
		err = domain.Err(404, "job_not_found")
		return
	}
	project, err = tx.One(ctx, "SELECT * FROM jm_projects WHERE id = ?"+tx.ForUpdate(), provisional["project_id"])
	if err != nil {
		return
	}
	job, err = tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?"+tx.ForUpdate(), jobID)
	if err != nil {
		return
	}
	resource, err = tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?"+tx.ForUpdate(), resourceID)
	if err != nil {
		return
	}
	if project == nil || job == nil || resource == nil || text(resource["job_id"]) != jobID || text(mapping(resource["ownership_json"])["job_id"]) != jobID || text(mapping(resource["details_json"])["pool_id"]) != poolID {
		err = domain.Err(409, "retained_resource_ownership_mismatch")
	}
	return
}
func reservePool(ctx context.Context, tx *store.Tx, resource, pool map[string]any, amount int64) error {
	if pool == nil || text(resource["kind"]) == "execution_state" {
		return nil
	}
	used, e := PoolUsedBytes(ctx, tx, text(pool["id"]), text(resource["id"]))
	if e != nil {
		return e
	}
	capacity := integer(pool["disk_bytes"])
	if amount < 0 || capacity < 0 || used > capacity || amount > capacity-used {
		return domain.Err(409, "retained_pool_storage_unavailable")
	}
	return nil
}
func ChargeInTransaction(ctx context.Context, tx *store.Tx, resource, project map[string]any, size int64) (bool, error) {
	if size < 0 {
		return false, domain.Err(422, "invalid_retained_size")
	}
	details := copyMap(resource["details_json"])
	if old, exists := details["retention_charged_bytes"]; exists {
		if integer(old) != size || flag(details["retention_charge_released"]) {
			return false, domain.Err(409, "retained_resource_charge_conflict")
		}
		return false, nil
	}
	if text(resource["state"]) == "deleted" || resource["deleted_at"] != nil {
		return false, domain.Err(409, "retained_resource_already_deleted")
	}
	if e := projectReserve(ctx, tx, project, size); e != nil {
		return false, e
	}
	details["retention_charged_bytes"] = size
	details["retention_charge_released"] = false
	details["retention_charge_settled"] = true
	details["retention_actual_bytes"] = size
	values := map[string]any{"retained": true, "size_bytes": size, "details_json": details}
	if e := tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": resource["id"]}, values); e != nil {
		return false, e
	}
	for k, v := range values {
		resource[k] = v
	}
	return true, nil
}
func ReserveInTransaction(ctx context.Context, tx *store.Tx, resource, project, pool map[string]any, maximum int64) (bool, error) {
	if maximum < 0 {
		return false, domain.Err(422, "invalid_retained_size")
	}
	if text(resource["state"]) == "deleted" || resource["deleted_at"] != nil {
		return false, domain.Err(409, "retained_resource_already_deleted")
	}
	details := copyMap(resource["details_json"])
	if id := text(details["pool_id"]); id != "" && (pool == nil || text(pool["id"]) != id) {
		return false, domain.Err(409, "retained_resource_pool_context_required")
	}
	if flag(details["retention_charge_released"]) {
		return false, domain.Err(409, "retained_resource_charge_conflict")
	}
	if charged, exists := details["retention_charged_bytes"]; exists {
		if integer(charged) < 0 {
			return false, domain.Err(409, "retained_storage_ledger_inconsistent")
		}
		_, hasReservation := details["retention_reservation_bytes"]
		settled, hasSettled := details["retention_charge_settled"]
		isSettled := flag(settled) || !hasSettled && !hasReservation
		if isSettled {
			if integer(charged) > maximum {
				return false, domain.Err(409, "retained_resource_exceeds_reservation")
			}
			return false, nil
		}
		if integer(details["retention_reservation_bytes"]) != maximum {
			return false, domain.Err(409, "retained_resource_reservation_conflict")
		}
		return false, nil
	}
	if e := reservePool(ctx, tx, resource, pool, maximum); e != nil {
		return false, e
	}
	if e := projectReserve(ctx, tx, project, maximum); e != nil {
		return false, e
	}
	details["retention_charged_bytes"] = maximum
	details["retention_reservation_bytes"] = maximum
	details["retention_charge_settled"] = false
	details["retention_charge_released"] = false
	values := map[string]any{"retained": true, "size_bytes": maximum, "details_json": details}
	if e := tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": resource["id"]}, values); e != nil {
		return false, e
	}
	for k, v := range values {
		resource[k] = v
	}
	return true, nil
}
func (r *Retention) ReserveResource(ctx context.Context, resourceID, jobID string, maximum int64) (changed bool, err error) {
	err = r.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		project, _, resource, pool, e := lockResource(ctx, tx, resourceID, jobID)
		if e != nil {
			return e
		}
		changed, e = ReserveInTransaction(ctx, tx, resource, project, pool, maximum)
		return e
	})
	return
}
func (r *Retention) ChargeResource(ctx context.Context, resourceID, jobID string, size int64) (changed bool, err error) {
	err = r.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		project, _, resource, pool, e := lockResource(ctx, tx, resourceID, jobID)
		if e != nil {
			return e
		}
		if e = reservePool(ctx, tx, resource, pool, size); e != nil {
			return e
		}
		changed, e = ChargeInTransaction(ctx, tx, resource, project, size)
		return e
	})
	return
}
func (r *Retention) SettleResource(ctx context.Context, resourceID, jobID string, actual int64) (changed bool, err error) {
	if actual < 0 {
		return false, domain.Err(422, "invalid_retained_size")
	}
	err = r.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		project, _, resource, _, e := lockResource(ctx, tx, resourceID, jobID)
		if e != nil {
			return e
		}
		d := copyMap(resource["details_json"])
		if text(resource["state"]) == "deleted" || resource["deleted_at"] != nil || flag(d["retention_charge_released"]) {
			return domain.Err(409, "retained_resource_already_deleted")
		}
		charged, exists := d["retention_charged_bytes"]
		if !exists {
			return domain.Err(409, "retained_resource_reservation_required")
		}
		_, hasReservation := d["retention_reservation_bytes"]
		settled, hasSettled := d["retention_charge_settled"]
		if flag(settled) || !hasSettled && !hasReservation {
			if integer(charged) != actual {
				return domain.Err(409, "retained_resource_charge_conflict")
			}
			return nil
		}
		reserved := integer(d["retention_reservation_bytes"])
		if reserved < 0 || actual > reserved {
			return domain.Err(409, "retained_resource_exceeds_reservation")
		}
		release := integer(charged) - actual
		if release < 0 || integer(project["retained_bytes"]) < release {
			return domain.Err(409, "retained_storage_ledger_inconsistent")
		}
		if e = tx.Update(ctx, "jm_projects", map[string]any{"id": project["id"]}, map[string]any{"retained_bytes": integer(project["retained_bytes"]) - release, "version": integer(project["version"]) + boolInt(release > 0)}); e != nil {
			return e
		}
		d["retention_charged_bytes"] = actual
		d["retention_actual_bytes"] = actual
		d["retention_charge_settled"] = true
		if e = tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": resourceID}, map[string]any{"size_bytes": actual, "details_json": d}); e != nil {
			return e
		}
		changed = true
		return nil
	})
	return
}
func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
func ChargeLogInTransaction(ctx context.Context, tx *store.Tx, project, chunk, budget map[string]any) (bool, error) {
	content, ok := chunk["data"].(string)
	if !ok || len(content) > 65536 {
		return false, domain.Err(422, "log_chunk_exceeds_bound")
	}
	amount := int64(len(content))
	if budget == nil {
		previous := integer(chunk["charged_bytes"])
		if previous != 0 {
			if previous != amount {
				return false, domain.Err(409, "retained_log_charge_conflict")
			}
			return false, nil
		}
		if e := projectReserve(ctx, tx, project, amount); e != nil {
			return false, e
		}
		chunk["charged_bytes"] = amount
		return true, nil
	}
	job, e := tx.One(ctx, "SELECT project_id FROM jm_jobs WHERE id = ?", chunk["job_id"])
	if e != nil {
		return false, e
	}
	d := copyMap(budget["details_json"])
	ownership := map[string]any{"job_id": chunk["job_id"], "component_id": chunk["component"], "kind": "log_budget"}
	external := "hf2l-log://" + text(chunk["job_id"]) + "/" + strconv.FormatInt(integer(chunk["attempt_number"]), 10) + "/" + text(chunk["component"])
	if job == nil || text(job["project_id"]) != text(project["id"]) || text(budget["job_id"]) != text(chunk["job_id"]) || text(budget["component_id"]) != text(chunk["component"]) || text(budget["kind"]) != "log_budget" || !sameJSON(budget["ownership_json"], ownership) || integer(d["attempt_number"]) != integer(chunk["attempt_number"]) || text(budget["external_id"]) != external || text(budget["state"]) == "deleted" || budget["deleted_at"] != nil || flag(d["retention_charge_released"]) || !flag(budget["retained"]) {
		return false, domain.Err(409, "retained_resource_ownership_mismatch")
	}
	maximum := integer(d["retention_reservation_bytes"])
	consumed := integer(d["log_consumed_bytes"])
	last := integer(d["log_last_sequence"])
	if maximum < 0 || consumed < 0 || last < 0 || consumed > maximum || integer(d["retention_charged_bytes"]) != maximum || integer(budget["size_bytes"]) != maximum || integer(project["retained_bytes"]) < maximum || maximum > 1<<20 {
		return false, domain.Err(409, "retained_storage_ledger_inconsistent")
	}
	if integer(chunk["sequence"]) <= last {
		previous, e := tx.One(ctx, "SELECT * FROM jm_log_chunks WHERE id = ?", chunk["id"])
		if e != nil {
			return false, e
		}
		if previous == nil || previous["job_id"] != chunk["job_id"] || previous["component"] != chunk["component"] || integer(previous["attempt_number"]) != integer(chunk["attempt_number"]) || integer(previous["charged_bytes"]) != 0 {
			return false, domain.Err(409, "retained_log_charge_conflict")
		}
		return false, nil
	}
	if integer(chunk["charged_bytes"]) != 0 {
		return false, domain.Err(409, "retained_log_charge_conflict")
	}
	remaining := maximum - consumed
	truncated := amount > remaining || flag(d["log_budget_exhausted"])
	if flag(d["log_budget_exhausted"]) {
		content = ""
		amount = 0
	} else if truncated {
		marker := "[manager log budget exhausted; further output omitted]\n"
		if remaining >= int64(len(marker)) {
			content = utf8Prefix([]byte(content), remaining-int64(len(marker))) + marker
		} else {
			content = utf8Prefix([]byte(content), remaining)
		}
		amount = int64(len(content))
	}
	chunk["data"] = content
	chunk["charged_bytes"] = int64(0)
	d["log_consumed_bytes"] = consumed + amount
	d["log_last_sequence"] = chunk["sequence"]
	d["log_last_chunk_id"] = chunk["id"]
	d["log_truncated"] = flag(d["log_truncated"]) || truncated
	d["log_budget_exhausted"] = flag(d["log_budget_exhausted"]) || truncated || consumed+amount == maximum
	if e = tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": budget["id"]}, map[string]any{"details_json": d}); e != nil {
		return false, e
	}
	budget["details_json"] = d
	return true, nil
}
func (r *Retention) ConfirmResourceDeleted(ctx context.Context, resourceID, jobID string) (changed bool, err error) {
	err = r.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		project, _, resource, _, e := lockResource(ctx, tx, resourceID, jobID)
		if e != nil {
			return e
		}
		if text(resource["state"]) != "deleted" || resource["deleted_at"] == nil {
			return domain.Err(409, "resource_deletion_unconfirmed")
		}
		d := copyMap(resource["details_json"])
		if flag(d["retention_charge_released"]) {
			return nil
		}
		amount := integer(d["retention_charged_bytes"])
		if amount < 0 || integer(project["retained_bytes"]) < amount {
			return domain.Err(409, "retained_storage_ledger_inconsistent")
		}
		if e = tx.Update(ctx, "jm_projects", map[string]any{"id": project["id"]}, map[string]any{"retained_bytes": integer(project["retained_bytes"]) - amount, "version": integer(project["version"]) + 1}); e != nil {
			return e
		}
		d["retention_charge_released"] = true
		d["retention_released_at"] = store.UTC(r.now())
		if e = tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": resourceID}, map[string]any{"details_json": d}); e != nil {
			return e
		}
		changed = true
		return nil
	})
	return
}
func appendEvent(ctx context.Context, tx *store.Tx, jobID, kind string, data map[string]any, now time.Time) error {
	sequence, e := tx.One(ctx, "SELECT COALESCE(MAX(sequence),0) AS sequence FROM jm_events WHERE job_id = ?", jobID)
	if e != nil {
		return e
	}
	return tx.Insert(ctx, "jm_events", map[string]any{"id": domain.NewID(), "job_id": jobID, "sequence": integer(sequence["sequence"]) + 1, "kind": kind, "actor_id": nil, "data_json": data, "created_at": now})
}
func (r *Retention) RequestExpiry(ctx context.Context, limits ...int) ([]string, error) {
	limit := 100
	if len(limits) > 0 {
		limit = limits[0]
	}
	if limit < 1 || limit > 1000 {
		return nil, domain.Err(422, "invalid_retention_limit")
	}
	requested := []string{}
	now := r.now()
	err := r.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		q := "SELECT * FROM jm_jobs WHERE state IN ('SUCCEEDED','FAILED','CANCELLED') AND purged_at IS NULL AND artifacts_expire_at IS NOT NULL AND artifacts_expire_at <= ? AND cleanup_status NOT IN ('purge_pending','expiry_pending','expired') ORDER BY artifacts_expire_at,id LIMIT ?"
		if tx.Dialect == "postgresql" {
			q += " FOR UPDATE SKIP LOCKED"
		}
		jobs, e := tx.All(ctx, q, now, limit)
		if e != nil {
			return e
		}
		for _, job := range jobs {
			active, e := tx.One(ctx, "SELECT COUNT(*) AS n FROM jm_allocations WHERE job_id = ? AND released_at IS NULL", job["id"])
			if e != nil {
				return e
			}
			if integer(active["n"]) > 0 {
				continue
			}
			key := "retention:" + text(job["id"]) + ":" + text(stamp(job["artifacts_expire_at"]))
			existing, e := tx.One(ctx, "SELECT * FROM jm_outbox WHERE idempotency_key = ?", key)
			if e != nil {
				return e
			}
			if existing == nil {
				hash := sha256.Sum256([]byte(key))
				if e = tx.Insert(ctx, "jm_outbox", map[string]any{"id": hex.EncodeToString(hash[:])[:32], "job_id": job["id"], "attempt_number": job["current_attempt"], "topic": "expire_artifacts", "state": "pending", "idempotency_key": key, "payload_json": map[string]any{"expires_at": stamp(job["artifacts_expire_at"]), "preserve_metadata": true, "confirm_before_release": true}, "created_at": now}); e != nil {
					return e
				}
				if e = appendEvent(ctx, tx, text(job["id"]), "retention.expiry_requested", map[string]any{"expires_at": stamp(job["artifacts_expire_at"])}, now); e != nil {
					return e
				}
			} else if text(existing["state"]) == "done" {
				continue
			}
			if e = tx.Update(ctx, "jm_jobs", map[string]any{"id": job["id"]}, map[string]any{"cleanup_status": "expiry_pending", "version": integer(job["version"]) + 1, "updated_at": now}); e != nil {
				return e
			}
			requested = append(requested, text(job["id"]))
		}
		return nil
	})
	return requested, err
}
func ownedDatabaseLogs(row map[string]any, jobID string) bool {
	d := mapping(row["details_json"])
	number := integer(d["attempt_number"])
	maximum, exists := d["retention_reservation_bytes"]
	return text(row["kind"]) == "log_budget" && number >= 1 && sameJSON(row["ownership_json"], map[string]any{"job_id": jobID, "component_id": row["component_id"], "kind": "log_budget"}) && text(row["external_id"]) == "hf2l-log://"+jobID+"/"+strconv.FormatInt(number, 10)+"/"+text(row["component_id"]) && exists && integer(maximum) >= 0 && integer(d["retention_charged_bytes"]) == integer(maximum) && integer(row["size_bytes"]) == integer(maximum)
}
func (r *Retention) ConfirmJobDataDeleted(ctx context.Context, jobID string) (released int64, err error) {
	now := r.now()
	err = r.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		observed, e := tx.All(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id = ?", jobID)
		if e != nil {
			return e
		}
		ids := map[string]bool{}
		for _, row := range observed {
			if id := text(mapping(row["details_json"])["pool_id"]); id != "" {
				ids[id] = true
			}
		}
		pools := []string{}
		for id := range ids {
			pools = append(pools, id)
		}
		sort.Strings(pools)
		for _, id := range pools {
			if _, e = tx.One(ctx, "SELECT id FROM jm_pools WHERE id = ?"+tx.ForUpdate(), id); e != nil {
				return e
			}
		}
		seen, e := tx.One(ctx, "SELECT project_id FROM jm_jobs WHERE id = ?", jobID)
		if e != nil {
			return e
		}
		if seen == nil {
			return domain.Err(404, "job_not_found")
		}
		project, e := tx.One(ctx, "SELECT * FROM jm_projects WHERE id = ?"+tx.ForUpdate(), seen["project_id"])
		if e != nil {
			return e
		}
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?"+tx.ForUpdate(), jobID)
		if e != nil {
			return e
		}
		if !domain.IsTerminal(text(job["state"])) {
			return domain.Err(409, "retention_requires_terminal")
		}
		active, e := tx.One(ctx, "SELECT COUNT(*) AS n FROM jm_allocations WHERE job_id = ? AND released_at IS NULL", jobID)
		if e != nil {
			return e
		}
		if integer(active["n"]) != 0 {
			return domain.Err(409, "resource_deletion_unconfirmed")
		}
		rows, e := tx.All(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id = ? AND retained = ?"+tx.ForUpdate(), jobID, true)
		if e != nil {
			return e
		}
		for _, row := range rows {
			d := mapping(row["details_json"])
			deleted := text(row["state"]) == "deleted" && row["deleted_at"] != nil
			auditOnly := text(row["state"]) == "retired" && (text(row["kind"]) == "exchange_space" || text(row["kind"]) == "exchange_member") && integer(row["size_bytes"]) == 0 && integer(d["retention_charged_bytes"]) == 0
			if !deleted && !auditOnly && !ownedDatabaseLogs(row, jobID) {
				return domain.Err(409, "resource_deletion_unconfirmed")
			}
		}
		for _, row := range rows {
			d := copyMap(row["details_json"])
			if !flag(d["retention_charge_released"]) {
				released, e = sumBytes(released, integer(d["retention_charged_bytes"]))
				if e != nil {
					return e
				}
				d["retention_charge_released"] = true
				d["retention_released_at"] = store.UTC(now)
			}
			values := map[string]any{"details_json": d}
			if ownedDatabaseLogs(row, jobID) {
				values["state"] = "deleted"
				if row["deleted_at"] == nil {
					values["deleted_at"] = now
				}
			}
			if e = tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": row["id"]}, values); e != nil {
				return e
			}
		}
		logs, e := tx.All(ctx, "SELECT * FROM jm_log_chunks WHERE job_id = ?"+tx.ForUpdate(), jobID)
		if e != nil {
			return e
		}
		for _, row := range logs {
			released, e = sumBytes(released, integer(row["charged_bytes"]))
			if e != nil {
				return e
			}
			values := map[string]any{"charged_bytes": int64(0), "data": ""}
			if row["deleted_at"] == nil {
				values["deleted_at"] = now
			}
			if e = tx.Update(ctx, "jm_log_chunks", map[string]any{"id": row["id"]}, values); e != nil {
				return e
			}
		}
		if integer(project["retained_bytes"]) < released {
			return domain.Err(409, "retained_storage_ledger_inconsistent")
		}
		if e = tx.Update(ctx, "jm_projects", map[string]any{"id": project["id"]}, map[string]any{"retained_bytes": integer(project["retained_bytes"]) - released, "version": integer(project["version"]) + boolInt(released > 0)}); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "UPDATE jm_artifacts SET state = ?,deleted_at = COALESCE(deleted_at,?) WHERE job_id = ?", "deleted", now, jobID); e != nil {
			return e
		}
		if text(job["cleanup_status"]) != "expired" {
			if e = tx.Update(ctx, "jm_jobs", map[string]any{"id": jobID}, map[string]any{"cleanup_status": "expired", "version": integer(job["version"]) + 1, "updated_at": now}); e != nil {
				return e
			}
			if e = appendEvent(ctx, tx, jobID, "retention.deletion_confirmed", map[string]any{"released_bytes": released, "metadata_retained": true}, now); e != nil {
				return e
			}
		}
		return nil
	})
	return
}
func TransferReservedInTransaction(ctx context.Context, tx *store.Tx, reservation, project map[string]any, children []map[string]any, retainUnused bool) (map[string]any, error) {
	if len(children) > 10000 {
		return nil, domain.Err(422, "invalid_retained_collection")
	}
	job, e := tx.One(ctx, "SELECT project_id FROM jm_jobs WHERE id = ?", reservation["job_id"])
	if e != nil {
		return nil, e
	}
	if job == nil || project["id"] != job["project_id"] || mapping(reservation["ownership_json"])["job_id"] != reservation["job_id"] || text(reservation["state"]) == "deleted" || reservation["deleted_at"] != nil {
		return nil, domain.Err(409, "retained_resource_ownership_mismatch")
	}
	d := copyMap(reservation["details_json"])
	if _, has := d["retention_reservation_bytes"]; !has || flag(d["retention_charge_released"]) {
		return nil, domain.Err(409, "retained_resource_reservation_required")
	}
	available := integer(d["retention_charged_bytes"])
	if available < 0 {
		return nil, domain.Err(409, "retained_storage_ledger_inconsistent")
	}
	settled := flag(d["retention_charge_settled"])
	manifest := map[string]any{}
	for _, child := range children {
		id := text(child["id"])
		data := mapping(child["details_json"])
		amount := integer(child["size_bytes"])
		if _, duplicate := manifest[id]; duplicate || id == text(reservation["id"]) || child["job_id"] != reservation["job_id"] || mapping(child["ownership_json"])["job_id"] != reservation["job_id"] || text(child["state"]) == "deleted" || child["deleted_at"] != nil || text(child["kind"]) == "execution_state" || amount < 0 {
			return nil, domain.Err(409, "retained_resource_ownership_mismatch")
		}
		if data["pool_id"] != nil && data["pool_id"] != d["pool_id"] {
			return nil, domain.Err(409, "retained_resource_ownership_mismatch")
		}
		manifest[id] = amount
	}
	if settled {
		if flag(d["retention_retain_unused"]) != retainUnused {
			return nil, domain.Err(409, "retained_resource_charge_conflict")
		}
		if previous, exists := d["retention_collection_manifest"]; exists && !sameJSON(previous, manifest) {
			return nil, domain.Err(409, "retained_resource_charge_conflict")
		}
	}
	transferred := int64(0)
	for _, child := range children {
		amount := integer(child["size_bytes"])
		data := copyMap(child["details_json"])
		if charge, exists := data["retention_charged_bytes"]; exists {
			if integer(charge) != amount || flag(data["retention_charge_released"]) || data["retention_reservation_source"] != reservation["id"] {
				return nil, domain.Err(409, "retained_resource_charge_conflict")
			}
			continue
		}
		if settled || amount > available {
			return nil, domain.Err(409, "retained_resource_exceeds_reservation")
		}
		available -= amount
		transferred += amount
		data["retention_charged_bytes"] = amount
		data["retention_charge_released"] = false
		data["retention_charge_settled"] = true
		data["retention_actual_bytes"] = amount
		data["retention_reservation_source"] = reservation["id"]
		if d["pool_id"] != nil {
			data["pool_id"] = d["pool_id"]
		}
		if e = tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": child["id"]}, map[string]any{"retained": true, "details_json": data}); e != nil {
			return nil, e
		}
		child["retained"] = true
		child["details_json"] = data
	}
	if integer(project["retained_bytes"]) < available {
		return nil, domain.Err(409, "retained_storage_ledger_inconsistent")
	}
	released := int64(0)
	if !settled && !retainUnused {
		released = available
	}
	if e = tx.Update(ctx, "jm_projects", map[string]any{"id": project["id"]}, map[string]any{"retained_bytes": integer(project["retained_bytes"]) - released, "version": integer(project["version"]) + boolInt(released > 0)}); e != nil {
		return nil, e
	}
	remaining := int64(0)
	if retainUnused {
		remaining = available
	}
	d["retention_charged_bytes"] = remaining
	d["retention_actual_bytes"] = int64(0)
	d["retention_charge_settled"] = true
	d["retention_retain_unused"] = retainUnused
	d["retention_conservative_footprint"] = retainUnused
	d["retention_collection_manifest"] = manifest
	d["retention_transferred_bytes"] = integer(d["retention_transferred_bytes"]) + transferred
	if e = tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": reservation["id"]}, map[string]any{"size_bytes": remaining, "details_json": d}); e != nil {
		return nil, e
	}
	reservation["details_json"] = d
	reservation["size_bytes"] = remaining
	return map[string]any{"transferred_bytes": transferred, "released_bytes": released}, nil
}

func asDomain(err error, status int, code string) error {
	if err == nil {
		return nil
	}
	var de *domain.Error
	if errors.As(err, &de) {
		return err
	}
	return domain.Err(status, code)
}
