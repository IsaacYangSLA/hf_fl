package manager

import (
	"context"
	"strings"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

// CanCreateStudy reports only a current global creation grant. Study access
// continues to depend exclusively on the existing per-project memberships.
func (m *Manager) CanCreateStudy(ctx context.Context, actor string) (bool, error) {
	if e := principal(actor); e != nil {
		return false, e
	}
	var allowed bool
	e := m.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		row, e := tx.One(ctx, "SELECT enabled FROM jm_study_creators WHERE principal_id=?", actor)
		if e != nil {
			return e
		}
		allowed = flag(row["enabled"])
		return nil
	})
	return allowed, e
}

// CreateStudy atomically creates a closed, approval-required study and its
// creator's administrator membership. It never accepts resource policy input.
func (m *Manager) CreateStudy(ctx context.Context, actor string, request Object, k string) (Object, error) {
	if e := principal(actor); e != nil {
		return nil, e
	}
	if len(request) != 1 {
		return nil, domain.Err(422, "invalid_study_fields")
	}
	value, ok := request["name"].(string)
	name := strings.TrimSpace(value)
	if !ok || name == "" || !studyText(name, 200) || strings.ContainsAny(name, "\n\r\t") {
		return nil, domain.Err(422, "invalid_study_fields")
	}
	var result Object
	e := m.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		// Grant changes lock this same durable row. Revocation is checked before
		// idempotent replay, so an old browser session cannot bypass revocation.
		grant, e := tx.One(ctx, "SELECT enabled FROM jm_study_creators WHERE principal_id=?"+tx.ForUpdate(), actor)
		if e != nil {
			return e
		}
		if !flag(grant["enabled"]) {
			return domain.Err(403, "study_creator_required")
		}
		result, e = m.once(ctx, tx, actor, "study.create", k, Object{"name": name}, func() (Object, error) {
			id, now := domain.NewID(), m.now()
			quota := Object{"cpu_millicores": int64(0), "memory_bytes": int64(0), "disk_bytes": int64(0), "gpu_count": int64(0), "max_running_jobs": int64(0), "retained_bytes": int64(0)}
			project := Object{"id": id, "name": name, "retention_days": int64(14), "quota_cpu_millicores": int64(0), "quota_memory_bytes": int64(0), "quota_disk_bytes": int64(0), "quota_gpus": int64(0), "max_active_jobs": int64(0), "quotas_json": quota, "retained_bytes": int64(0), "version": int64(1), "created_at": now}
			if e := tx.Insert(ctx, "jm_projects", project); e != nil {
				return nil, e
			}
			study := Object{"project_id": id, "enabled": true, "registration_open": false, "description": "", "row_version": int64(1), "created_at": now, "updated_at": now}
			if e := tx.Insert(ctx, "jm_studies", study); e != nil {
				return nil, e
			}
			if e := tx.Insert(ctx, "jm_project_members", Object{"project_id": id, "principal_id": actor, "role": "admin", "created_at": now}); e != nil {
				return nil, e
			}
			after := Object{"id": id, "name": name, "principal_id": actor, "role": "admin", "enabled": true, "status": "closed", "retention_days": int64(14), "version": int64(1), "quotas": quota}
			if e := RecordAdminAudit(ctx, tx, actor, "study.create", "study", id, nil, after, now); e != nil {
				return nil, e
			}
			return studyView(project, study, nil, true), nil
		}, func(previous Object) (Object, error) {
			project, study, own, admin, e := m.studyScope(ctx, tx, actor, text(previous["id"]), false)
			if e != nil {
				return nil, e
			}
			return studyView(project, study, own, admin), nil
		})
		return e
	})
	return result, e
}
