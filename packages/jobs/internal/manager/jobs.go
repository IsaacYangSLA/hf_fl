package manager

import (
	"context"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/scheduler"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

var digestPattern = regexp.MustCompile("^sha256:[a-f0-9]{64}$")
var storageKindPattern = regexp.MustCompile("^[A-Za-z0-9_]+$")

func (m *Manager) approveSpec(ctx context.Context, tx *store.Tx, spec domain.JobSpec) (string, error) {
	source, e := tx.One(ctx, "SELECT * FROM jm_approved_sources WHERE id = ?", spec.SourceID)
	if e != nil {
		return "", e
	}
	if source == nil || !flag(source["enabled"]) || text(source["status"]) != "approved" || (source["project_id"] != nil && text(source["project_id"]) != spec.ProjectID) {
		return "", domain.Err(422, "source_not_approved")
	}
	if len(arr(source["allowed_commits"])) > 0 && !has(source["allowed_commits"], spec.SourceCommit) {
		return "", domain.Err(422, "source_commit_not_approved")
	}
	image, e := tx.One(ctx, "SELECT * FROM jm_runtime_images WHERE id = ?", spec.RuntimeImage)
	if e != nil {
		return "", e
	}
	if image == nil {
		image, e = tx.One(ctx, "SELECT * FROM jm_runtime_images WHERE digest = ? AND enabled = ? AND (project_id IS NULL OR project_id = ?) ORDER BY id LIMIT 1", spec.RuntimeImage, true, spec.ProjectID)
		if e != nil {
			return "", e
		}
	}
	if image == nil || !flag(image["enabled"]) || !flag(image["approved"]) || text(image["status"]) != "approved" || (image["project_id"] != nil && text(image["project_id"]) != spec.ProjectID) {
		return "", domain.Err(422, "runtime_image_not_approved")
	}
	digest := text(image["digest"])
	if !digestPattern.MatchString(digest) {
		return "", domain.Err(422, "invalid_runtime_image_digest")
	}
	for _, p := range spec.Participants {
		b, e := tx.One(ctx, "SELECT * FROM jm_participant_bindings WHERE id = ?", p.DatasetBinding)
		if e != nil {
			return "", e
		}
		if b == nil || !flag(b["enabled"]) || text(b["project_id"]) != spec.ProjectID || text(b["participant_id"]) != p.ParticipantID || (p.Mode == "external" && text(b["node_id"]) == "") {
			return "", domain.Err(422, "participant_binding_not_approved")
		}
	}
	for _, ref := range spec.SecretRefs {
		secret, e := tx.One(ctx, "SELECT * FROM jm_secret_references WHERE id = ?", ref)
		if e != nil {
			return "", e
		}
		if secret == nil || !flag(secret["enabled"]) || text(secret["project_id"]) != spec.ProjectID {
			return "", domain.Err(422, "secret_reference_not_approved")
		}
	}
	validator := m.AdmissionValidator
	if validator == nil {
		validator = scheduler.ValidateAdmission
	}
	if e = validator(ctx, tx, spec); e != nil {
		return "", e
	}
	return digest, nil
}
func (m *Manager) validateStorage(ctx context.Context, tx *store.Tx, job Object, spec domain.JobSpec) error {
	if m.StoragePlanner == nil && m.StoragePlannerTx == nil {
		return nil
	}
	var plans []scheduler.StoragePlan
	var e error
	if m.StoragePlannerTx != nil {
		plans, e = m.StoragePlannerTx(ctx, tx, job)
	} else {
		plans, e = m.StoragePlanner(ctx, job)
	}
	if e != nil {
		return domain.Err(422, "storage_plan_unavailable")
	}
	if len(plans) > 10000 {
		return domain.Err(422, "storage_plan_unavailable")
	}
	requested := scheduler.RequestedByPool(spec)
	components := map[string]domain.ComponentSpec{}
	for _, c := range spec.Components {
		components[c.ComponentID] = c
	}
	external := map[string]bool{}
	for _, p := range spec.Participants {
		if p.Mode == "external" {
			h, e := hash([]any{p.ParticipantID})
			if e != nil {
				return e
			}
			external["participant-"+h[:40]] = true
		}
	}
	identities := map[string]bool{}
	extra := int64(0)
	for _, plan := range plans {
		component, exists := components[plan.ComponentID]
		externalLog := plan.Kind == "log_budget" && external[plan.ComponentID] && plan.MaxBytes == 1<<20 && plan.ExternalID == "hf2l-log://"+text(job["id"])+"/"+strconvID(job["current_attempt"])+"/"+plan.ComponentID
		if len(plan.Kind) < 1 || len(plan.Kind) > 64 || !storageKindPattern.MatchString(plan.Kind) || (!exists && !externalLog) || plan.PoolID == "" || plan.ExternalID == "" || plan.MaxBytes < 0 {
			return domain.Err(422, "storage_plan_unavailable")
		}
		identity := plan.Kind + "\x00" + plan.ExternalID
		if identities[identity] {
			return domain.Err(422, "storage_plan_unavailable")
		}
		identities[identity] = true
		if requested[plan.PoolID] == nil {
			requested[plan.PoolID] = scheduler.Amounts{"disk_bytes": 0}
		}
		if plan.CoveredByAllocation {
			if plan.Kind != "execution_state" || !exists || component.Resources.PoolID != plan.PoolID || component.Resources.DiskBytes != plan.MaxBytes {
				return domain.Err(422, "storage_plan_unavailable")
			}
		} else {
			if plan.MaxBytes > math.MaxInt64-requested[plan.PoolID]["disk_bytes"] {
				return domain.Err(422, "resource_request_exceeds_pool")
			}
			requested[plan.PoolID]["disk_bytes"] += plan.MaxBytes
		}
		if plan.MaxBytes > math.MaxInt64-extra {
			return domain.Err(422, "resource_request_exceeds_project_quota")
		}
		extra += plan.MaxBytes
	}
	disk := int64(0)
	for poolID, amounts := range requested {
		pool, e := tx.One(ctx, "SELECT * FROM jm_pools WHERE id = ?", poolID)
		if e != nil {
			return e
		}
		if pool == nil {
			return domain.Err(422, "resource_pool_not_found")
		}
		if amounts["disk_bytes"] > number(pool["disk_bytes"]) {
			return domain.Err(422, "resource_request_exceeds_pool")
		}
		if amounts["disk_bytes"] > math.MaxInt64-disk {
			return domain.Err(422, "resource_request_exceeds_project_quota")
		}
		disk += amounts["disk_bytes"]
	}
	project, e := tx.One(ctx, "SELECT * FROM jm_projects WHERE id = ?", spec.ProjectID)
	if e != nil {
		return e
	}
	quota, e := scheduler.Quota(project)
	if e != nil {
		return e
	}
	if limit, ok := quota["disk_bytes"]; ok && disk > limit {
		return domain.Err(422, "resource_request_exceeds_project_quota")
	}
	if limit, ok := quota["retained_bytes"]; ok && extra > limit {
		return domain.Err(422, "resource_request_exceeds_project_quota")
	}
	return nil
}
func (m *Manager) CreateJob(ctx context.Context, actor string, spec domain.JobSpec, k string) (Object, error) {
	if e := principal(actor); e != nil {
		return nil, e
	}
	if e := key(k); e != nil {
		return nil, e
	}
	if e := spec.Validate(); e != nil {
		return nil, domain.Err(422, "invalid_job_spec")
	}
	var result Object
	e := m.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		project, e := tx.One(ctx, "SELECT * FROM jm_projects WHERE id = ?"+tx.ForUpdate(), spec.ProjectID)
		if e != nil {
			return e
		}
		var member Object
		if project != nil {
			member, e = tx.One(ctx, "SELECT * FROM jm_project_members WHERE project_id = ? AND principal_id = ?", spec.ProjectID, actor)
			if e != nil {
				return e
			}
		}
		if member == nil || (text(member["role"]) != "submitter" && text(member["role"]) != "admin") {
			return domain.Err(403, "project_submitter_required")
		}
		result, e = m.once(ctx, tx, actor, "job.create", k, spec.Map(), func() (Object, error) {
			minimum := int64(2)
			if value, ok := spec.Options["minimum_participants"]; ok {
				var valid bool
				minimum, valid = strictInt(value)
				if !valid {
					return nil, domain.Err(422, "invalid_job_spec")
				}
			}
			if minimum < 2 || minimum > int64(len(spec.Participants)) {
				return nil, domain.Err(422, "invalid_job_spec")
			}
			digest, e := m.approveSpec(ctx, tx, spec)
			if e != nil {
				return nil, e
			}
			pinned := spec
			pinned.RuntimeImage = digest
			specHash, e := pinned.Digest()
			if e != nil {
				return nil, e
			}
			now := m.now()
			job := Object{"id": domain.NewID(), "project_id": spec.ProjectID, "creator_id": actor, "name": spec.Name, "spec_json": pinned.Map(), "spec_hash": specHash, "state": "QUEUED", "phase": "waiting_resources", "queue_reason": Object{"code": "awaiting_scheduler"}, "version": int64(1), "current_attempt": int64(1), "attempt_count": int64(1), "epoch": int64(0), "backfill_count": int64(0), "target_round": spec.TargetRound, "current_round": int64(0), "cleanup_status": "none", "created_at": now, "updated_at": now}
			if e = m.validateStorage(ctx, tx, job, pinned); e != nil {
				return nil, e
			}
			if e = tx.Insert(ctx, "jm_jobs", job); e != nil {
				return nil, e
			}
			membership := Object{"job_id": job["id"], "principal_id": actor, "role": "admin"}
			if e = tx.Insert(ctx, "jm_job_members", membership); e != nil {
				return nil, e
			}
			if e = tx.Insert(ctx, "jm_attempts", Object{"id": domain.NewID(), "job_id": job["id"], "number": int64(1), "state": "QUEUED", "epoch": int64(1), "resources_json": Object{}, "created_at": now}); e != nil {
				return nil, e
			}
			if e = AppendEvent(ctx, tx, text(job["id"]), "job.created", actor, Object{"spec_hash": specHash}, now); e != nil {
				return nil, e
			}
			return m.jobView(ctx, tx, job, membership, true)
		}, func(old Object) (Object, error) {
			job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?", old["id"])
			if e != nil {
				return nil, e
			}
			if job == nil {
				return nil, domain.Err(404, "job_not_found")
			}
			current, e := tx.One(ctx, "SELECT * FROM jm_job_members WHERE job_id = ? AND principal_id = ?", job["id"], actor)
			if e != nil {
				return nil, e
			}
			if current == nil || roleLevel(text(current["role"])) == 0 {
				return nil, domain.Err(404, "job_not_found")
			}
			return m.jobView(ctx, tx, job, current, true)
		})
		return e
	})
	return result, e
}
func validateFilters(filters Object) (Object, error) {
	f := copyObject(filters)
	for k := range f {
		if k != "view" && k != "state" && k != "project_id" && k != "search" {
			return nil, domain.Err(422, "invalid_job_filter")
		}
	}
	if v := f["view"]; v != nil && !has([]any{"queued", "current", "history", "all"}, text(v)) {
		return nil, domain.Err(422, "invalid_job_filter")
	}
	if v := f["state"]; v != nil && !has([]any{"QUEUED", "PROVISIONING", "STARTING", "RUNNING", "RECONCILING", "NEEDS_ATTENTION", "CANCELLING", "SUCCEEDED", "FAILED", "CANCELLED"}, text(v)) {
		return nil, domain.Err(422, "invalid_job_filter")
	}
	for _, key := range []string{"project_id", "search"} {
		if value, ok := f[key]; ok {
			v, yes := value.(string)
			maximum := 128
			if key == "search" {
				maximum = 200
			}
			if !yes || utf8.RuneCountInString(v) > maximum {
				return nil, domain.Err(422, "invalid_job_filter")
			}
		}
	}
	return f, nil
}
func counts(rows []Object) (Object, Object) {
	by := Object{}
	queued, history, current := int64(0), int64(0), int64(0)
	for _, r := range rows {
		state := text(r["state"])
		n := number(r["n"])
		by[state] = n
		if state == "QUEUED" {
			queued += n
		} else if domain.IsTerminal(state) {
			history += n
		} else {
			current += n
		}
	}
	return Object{"queued": queued, "history": history, "current": current}, by
}
func (m *Manager) jobCounts(ctx context.Context, tx *store.Tx, actor string) (Object, Object, error) {
	rows, e := tx.All(ctx, "SELECT j.state,COUNT(*) AS n FROM jm_jobs j JOIN jm_job_members m ON m.job_id = j.id AND m.principal_id = ? WHERE j.purged_at IS NULL GROUP BY j.state", actor)
	if e != nil {
		return nil, nil, e
	}
	a, b := counts(rows)
	return a, b, nil
}
func (m *Manager) JobCounts(ctx context.Context, actor string) (Object, error) {
	if e := principal(actor); e != nil {
		return nil, e
	}
	var result Object
	e := m.DB.WithTx(ctx, false, func(tx *store.Tx) error { var e error; result, _, e = m.jobCounts(ctx, tx, actor); return e })
	return result, e
}
func (m *Manager) ListJobs(ctx context.Context, actor string, filters Object, limit int, cursor string) (Object, error) {
	if e := principal(actor); e != nil {
		return nil, e
	}
	if e := pageLimit(limit); e != nil {
		return nil, e
	}
	filters, e := validateFilters(filters)
	if e != nil {
		return nil, e
	}
	var position any
	if cursor != "" {
		position, e = m.decodeCursor(cursor, actor, "jobs", filters)
		if e != nil {
			return nil, e
		}
	}
	var result Object
	e = m.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		base := " FROM jm_jobs j JOIN jm_job_members m ON m.job_id = j.id AND m.principal_id = ? WHERE j.purged_at IS NULL"
		args := []any{actor}
		switch text(filters["view"]) {
		case "queued":
			base += " AND j.state = 'QUEUED'"
		case "current":
			base += " AND j.state NOT IN ('QUEUED','FAILED','CANCELLED','SUCCEEDED')"
		case "history":
			base += " AND j.state IN ('FAILED','CANCELLED','SUCCEEDED')"
		}
		for _, k := range []string{"state", "project_id"} {
			if text(filters[k]) != "" {
				base += " AND j." + k + " = ?"
				args = append(args, filters[k])
			}
		}
		if search := text(filters["search"]); search != "" {
			search = strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(search)
			base += " AND LOWER(j.name) LIKE LOWER(?) ESCAPE '\\'"
			args = append(args, "%"+search+"%")
		}
		total, e := tx.One(ctx, "SELECT COUNT(*) AS n"+base, args...)
		if e != nil {
			return e
		}
		if position != nil {
			stamp, id, e := cursorPosition(position)
			if e != nil {
				return e
			}
			base += " AND (j.created_at < ? OR (j.created_at = ? AND j.id < ?))"
			args = append(args, stamp, stamp, id)
		}
		args = append(args, limit+1)
		rows, e := tx.All(ctx, "SELECT j.*,m.role AS membership_role"+base+" ORDER BY j.created_at DESC,j.id DESC LIMIT ?", args...)
		if e != nil {
			return e
		}
		items := []Object{}
		for i, r := range rows {
			if i == limit {
				break
			}
			v, e := m.jobView(ctx, tx, r, Object{"role": r["membership_role"]}, false)
			if e != nil {
				return e
			}
			items = append(items, v)
		}
		var next any
		if len(rows) > limit {
			last := rows[limit-1]
			next, e = m.encodeCursor(actor, "jobs", filters, Object{"created_at": iso(last["created_at"]), "id": last["id"]})
			if e != nil {
				return e
			}
		}
		count, by, e := m.jobCounts(ctx, tx, actor)
		if e != nil {
			return e
		}
		result = Object{"items": items, "next_cursor": next, "total": number(total["n"]), "counts": count, "counts_by_state": by}
		return nil
	})
	return result, e
}
func (m *Manager) Cancel(ctx context.Context, actor, id string, expected int64, k string) (Object, error) {
	return m.command(ctx, actor, id, "operator", k, expected, "job.cancel_requested", Object{}, false, func(tx *store.Tx, job Object) error {
		if domain.IsTerminal(text(job["state"])) {
			return domain.Err(409, "job_already_terminal")
		}
		if text(job["state"]) != "CANCELLING" {
			job["state"] = "CANCELLING"
			job["phase"] = "fencing"
			job["queue_reason"] = nil
			return m.outbox(ctx, tx, job, "fence_stop", actor, Object{"desired_outcome": "CANCELLED", "grace_seconds": int64(60)})
		}
		return nil
	})
}
func (m *Manager) Retry(ctx context.Context, actor, id string, expected int64, k string) (Object, error) {
	return m.command(ctx, actor, id, "operator", k, expected, "job.retry_requested", Object{}, false, func(tx *store.Tx, job Object) error {
		if text(job["state"]) != "FAILED" {
			return domain.Err(409, "job_retry_requires_failed")
		}
		if expired(job["deadline_at"], m.now()) {
			return domain.Err(409, "job_deadline_expired")
		}
		if text(job["cleanup_status"]) == "purge_pending" {
			return domain.Err(409, "job_purge_pending")
		}
		if has([]any{"expiry_pending", "expired"}, text(job["cleanup_status"])) || expired(job["artifacts_expire_at"], m.now()) {
			return domain.Err(409, "job_artifacts_expired")
		}
		job["state"] = "RECONCILING"
		job["phase"] = "retry_pending"
		job["queue_reason"] = nil
		return m.outbox(ctx, tx, job, "prepare_retry", actor, Object{"next_attempt": number(job["current_attempt"]) + 1})
	})
}
func (m *Manager) Reconcile(ctx context.Context, actor, id string, expected int64, k string, evidence Object) (Object, error) {
	if len(evidence) != 3 || !has([]any{"published", "not_published"}, text(evidence["outcome"])) || badText(text(evidence["publication_id"]), 256) || badText(text(evidence["evidence_ref"]), 256) {
		return nil, domain.Err(422, "reconciliation_evidence_required")
	}
	for key := range evidence {
		if key != "publication_id" && key != "outcome" && key != "evidence_ref" {
			return nil, domain.Err(422, "reconciliation_evidence_required")
		}
	}
	return m.command(ctx, actor, id, "operator", k, expected, "job.reconcile_requested", Object{"evidence": evidence}, false, func(tx *store.Tx, job Object) error {
		if text(job["state"]) != "NEEDS_ATTENTION" {
			return domain.Err(409, "job_reconcile_requires_attention")
		}
		job["state"] = "RECONCILING"
		job["phase"] = "verifying_evidence"
		if e := m.outbox(ctx, tx, job, "reconcile", actor, Object{"evidence": evidence}); e != nil {
			return e
		}
		return AppendEvent(ctx, tx, id, "reconciliation.evidence_submitted", actor, evidence, m.now())
	})
}
func (m *Manager) Purge(ctx context.Context, actor, id string, expected int64, k string) (Object, error) {
	return m.command(ctx, actor, id, "admin", k, expected, "job.purge_requested", Object{}, false, func(tx *store.Tx, job Object) error {
		if !domain.IsTerminal(text(job["state"])) {
			return domain.Err(409, "job_purge_requires_terminal")
		}
		active, e := tx.One(ctx, "SELECT COUNT(*) AS n FROM jm_allocations WHERE job_id = ? AND released_at IS NULL", id)
		if e != nil {
			return e
		}
		running, e := tx.One(ctx, "SELECT COUNT(*) AS n FROM jm_attempts WHERE job_id = ? AND state IN ('PROVISIONING','STARTING','RUNNING','RECONCILING','CANCELLING')", id)
		if e != nil {
			return e
		}
		if number(active["n"]) > 0 || number(running["n"]) > 0 {
			return domain.Err(409, "job_runtime_not_confirmed_stopped")
		}
		if text(job["cleanup_status"]) != "purge_pending" {
			job["cleanup_status"] = "purge_pending"
			return m.outbox(ctx, tx, job, "purge", actor, Object{"preserve_audit": true, "confirm_before_release": true})
		}
		return nil
	})
}
func (m *Manager) ListMembers(ctx context.Context, actor, id string) (Object, error) {
	var result Object
	e := m.withJob(ctx, actor, id, "reader", false, func(tx *store.Tx, job, member Object) error {
		rows, e := tx.All(ctx, "SELECT principal_id,role FROM jm_job_members WHERE job_id = ? ORDER BY principal_id", id)
		result = Object{"items": rows}
		return e
	})
	return result, e
}
func preserveAdmin(ctx context.Context, tx *store.Tx, id string) error {
	count, e := tx.One(ctx, "SELECT COUNT(*) AS n FROM jm_job_members WHERE job_id = ? AND role = 'admin'", id)
	if e != nil {
		return e
	}
	if number(count["n"]) <= 1 {
		return domain.Err(409, "last_job_admin_required")
	}
	return nil
}
func (m *Manager) PutMember(ctx context.Context, actor, id, memberID, role string, expected int64, k string) (Object, error) {
	if badText(memberID, 256) {
		return nil, domain.Err(422, "invalid_member_principal")
	}
	if roleLevel(role) == 0 {
		return nil, domain.Err(422, "invalid_job_role")
	}
	return m.command(ctx, actor, id, "admin", k, expected, "job.membership_updated", Object{"principal_id": memberID, "role": role}, true, func(tx *store.Tx, job Object) error {
		row, e := tx.One(ctx, "SELECT * FROM jm_job_members WHERE job_id = ? AND principal_id = ?", id, memberID)
		if e != nil {
			return e
		}
		if row != nil && text(row["role"]) == "admin" && role != "admin" {
			if e = preserveAdmin(ctx, tx, id); e != nil {
				return e
			}
		}
		if row != nil {
			e = tx.Update(ctx, "jm_job_members", Object{"job_id": id, "principal_id": memberID}, Object{"role": role})
		} else {
			e = tx.Insert(ctx, "jm_job_members", Object{"job_id": id, "principal_id": memberID, "role": role})
		}
		if e != nil {
			return e
		}
		return AppendEvent(ctx, tx, id, "membership.granted", actor, Object{"principal_id": memberID, "role": role}, m.now())
	})
}
func (m *Manager) DeleteMember(ctx context.Context, actor, id, memberID string, expected int64, k string) (Object, error) {
	if badText(memberID, 256) {
		return nil, domain.Err(422, "invalid_member_principal")
	}
	return m.command(ctx, actor, id, "admin", k, expected, "job.membership_deleted", Object{"principal_id": memberID}, true, func(tx *store.Tx, job Object) error {
		row, e := tx.One(ctx, "SELECT * FROM jm_job_members WHERE job_id = ? AND principal_id = ?", id, memberID)
		if e != nil {
			return e
		}
		if row == nil {
			return nil
		}
		if text(row["role"]) == "admin" {
			if e = preserveAdmin(ctx, tx, id); e != nil {
				return e
			}
		}
		if _, e = tx.Exec(ctx, "DELETE FROM jm_job_members WHERE job_id = ? AND principal_id = ?", id, memberID); e != nil {
			return e
		}
		return AppendEvent(ctx, tx, id, "membership.revoked", actor, Object{"principal_id": memberID}, m.now())
	})
}
