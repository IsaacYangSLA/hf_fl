package manager

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

// A study is an existing project with an explicitly enabled enrollment policy.
// Only project administrators expose studies; signing in never grants a role.
func studyText(value string, maximum int) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maximum {
		return false
	}
	for _, c := range value {
		if (c < 32 && c != '\n' && c != '\t') || c == 127 {
			return false
		}
	}
	return true
}
func studyVersion(study Object) int64 {
	if study == nil {
		return 1
	}
	return number(study["row_version"])
}
func requireStudyVersion(row Object, expected int64) error {
	if expected < 1 {
		return domain.Err(428, "expected_version_required")
	}
	current := studyVersion(row)
	if expected != current {
		return domain.Err(409, "study_version_conflict", Object{"current_version": current})
	}
	return nil
}
func applicationView(row Object) Object {
	if row == nil {
		return nil
	}
	return Object{"id": row["id"], "study_id": row["project_id"], "project_id": row["project_id"], "principal_id": row["principal_id"], "participant_id": row["participant_id"], "status": row["status"], "message": row["message"], "review_reason": row["review_reason"], "reviewer_id": row["reviewer_id"], "version": row["row_version"], "created_at": iso(row["created_at"]), "updated_at": iso(row["updated_at"])}
}
func (m *Manager) studyScope(ctx context.Context, tx *store.Tx, actor, id string, write bool) (Object, Object, Object, bool, error) {
	suffix := ""
	if write {
		suffix = tx.ForUpdate()
	}
	project, e := tx.One(ctx, "SELECT * FROM jm_projects WHERE id=?"+suffix, id)
	if e != nil {
		return nil, nil, nil, false, e
	}
	if project == nil {
		return nil, nil, nil, false, domain.Err(404, "study_not_found")
	}
	membership, e := tx.One(ctx, "SELECT role FROM jm_project_members WHERE project_id=? AND principal_id=?", id, actor)
	if e != nil {
		return nil, nil, nil, false, e
	}
	admin := text(membership["role"]) == "admin"
	study, e := tx.One(ctx, "SELECT * FROM jm_studies WHERE project_id=?", id)
	if e != nil {
		return nil, nil, nil, false, e
	}
	own, e := tx.One(ctx, "SELECT * FROM jm_study_applications WHERE project_id=? AND principal_id=?", id, actor)
	if e != nil {
		return nil, nil, nil, false, e
	}
	if !admin && own == nil && !(flag(study["enabled"]) && flag(study["registration_open"])) {
		return nil, nil, nil, false, domain.Err(404, "study_not_found")
	}
	return project, study, own, admin, nil
}
func studyView(project, study, own Object, admin bool) Object {
	return Object{"id": project["id"], "project_id": project["id"], "name": project["name"], "description": text(study["description"]), "registration_enabled": flag(study["enabled"]), "registration_open": flag(study["registration_open"]), "version": studyVersion(study), "can_manage": admin, "my_application": applicationView(own)}
}
func (m *Manager) GetStudy(ctx context.Context, actor, id string) (Object, error) {
	if e := principal(actor); e != nil {
		return nil, e
	}
	var result Object
	e := m.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		p, s, a, admin, e := m.studyScope(ctx, tx, actor, id, false)
		if e != nil {
			return e
		}
		result = studyView(p, s, a, admin)
		return nil
	})
	return result, e
}
func (m *Manager) ListStudies(ctx context.Context, actor string, limit int, cursor string) (Object, error) {
	if e := principal(actor); e != nil {
		return nil, e
	}
	if e := pageLimit(limit); e != nil {
		return nil, e
	}
	after := ""
	if cursor != "" {
		position, e := m.decodeCursor(cursor, actor, "studies", nil)
		if e != nil {
			return nil, e
		}
		var ok bool
		after, ok = position.(string)
		if !ok || after == "" {
			return nil, domain.Err(422, "invalid_cursor")
		}
	}
	items := []Object{}
	next := ""
	e := m.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		rows, e := tx.All(ctx, "SELECT p.id FROM jm_projects p WHERE p.id>? AND (EXISTS (SELECT 1 FROM jm_project_members m WHERE m.project_id=p.id AND m.principal_id=? AND m.role='admin') OR EXISTS (SELECT 1 FROM jm_studies s WHERE s.project_id=p.id AND s.enabled=? AND (s.registration_open=? OR EXISTS (SELECT 1 FROM jm_study_applications a WHERE a.project_id=p.id AND a.principal_id=?)))) ORDER BY p.id LIMIT ?", after, actor, true, true, actor, limit+1)
		if e != nil {
			return e
		}
		more := len(rows) > limit
		if more {
			rows = rows[:limit]
		}
		for _, row := range rows {
			p, s, a, admin, e := m.studyScope(ctx, tx, actor, text(row["id"]), false)
			if e != nil {
				return e
			}
			items = append(items, studyView(p, s, a, admin))
		}
		if more {
			next, e = m.encodeCursor(actor, "studies", nil, text(rows[len(rows)-1]["id"]))
			return e
		}
		return nil
	})
	return Object{"items": items, "next_cursor": next}, e
}
func (m *Manager) PutStudySettings(ctx context.Context, actor, id, description string, registrationOpen bool, expected int64, k string) (Object, error) {
	if e := principal(actor); e != nil {
		return nil, e
	}
	if !studyText(description, 2000) {
		return nil, domain.Err(422, "invalid_study_fields")
	}
	var result Object
	e := m.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		p, s, own, admin, e := m.studyScope(ctx, tx, actor, id, true)
		if e != nil {
			return e
		}
		if !admin {
			return domain.Err(403, "project_admin_required")
		}
		body := Object{"description": description, "registration_open": registrationOpen, "expected_version": expected}
		result, e = m.once(ctx, tx, actor, "study.settings:"+id, k, body, func() (Object, error) {
			if e := requireStudyVersion(s, expected); e != nil {
				return nil, e
			}
			if !flag(s["enabled"]) {
				active, e := tx.One(ctx, "SELECT id FROM jm_jobs WHERE project_id=? AND state NOT IN ('SUCCEEDED','FAILED','CANCELLED') LIMIT 1", id)
				if e != nil {
					return nil, e
				}
				if active != nil {
					return nil, domain.Err(409, "study_has_active_jobs")
				}
			}
			before := Object(nil)
			if s != nil {
				before = Object{"id": id, "enabled": s["enabled"], "status": map[bool]string{true: "open", false: "closed"}[flag(s["registration_open"])], "version": s["row_version"]}
			}
			now := m.now()
			updated := Object{"enabled": true, "registration_open": registrationOpen, "description": description, "row_version": studyVersion(s) + 1, "updated_at": now}
			if s == nil {
				updated["project_id"] = id
				updated["created_at"] = now
				e = tx.Insert(ctx, "jm_studies", updated)
				s = updated
			} else {
				e = tx.Update(ctx, "jm_studies", Object{"project_id": id}, updated)
				for field, value := range updated {
					s[field] = value
				}
			}
			if e != nil {
				return nil, e
			}
			after := Object{"id": id, "enabled": true, "status": map[bool]string{true: "open", false: "closed"}[registrationOpen], "version": s["row_version"]}
			if e = RecordAdminAudit(ctx, tx, actor, "study.settings", "study", id, before, after, now); e != nil {
				return nil, e
			}
			return studyView(p, s, own, true), nil
		}, func(_ Object) (Object, error) {
			current, e := tx.One(ctx, "SELECT * FROM jm_studies WHERE project_id=?", id)
			if e != nil {
				return nil, e
			}
			return studyView(p, current, own, true), nil
		})
		return e
	})
	return result, e
}
func (m *Manager) GetStudyApplication(ctx context.Context, actor, id string) (Object, error) {
	if e := principal(actor); e != nil {
		return nil, e
	}
	var result Object
	e := m.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		_, _, own, _, e := m.studyScope(ctx, tx, actor, id, false)
		if e != nil {
			return e
		}
		result = Object{"application": applicationView(own)}
		return nil
	})
	return result, e
}
func (m *Manager) ApplyToStudy(ctx context.Context, actor, id, participantID, message, k string) (Object, error) {
	if e := principal(actor); e != nil {
		return nil, e
	}
	if !domain.ValidIdentifier(participantID) || !studyText(message, 2000) {
		return nil, domain.Err(422, "invalid_study_application")
	}
	var result Object
	e := m.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		_, study, own, _, e := m.studyScope(ctx, tx, actor, id, true)
		if e != nil {
			return e
		}
		result, e = m.once(ctx, tx, actor, "study.apply:"+id, k, Object{"participant_id": participantID, "message": message}, func() (Object, error) {
			if !flag(study["enabled"]) || !flag(study["registration_open"]) {
				return nil, domain.Err(409, "study_registration_closed")
			}
			if text(own["status"]) == "approved" {
				return nil, domain.Err(409, "study_already_approved")
			}
			if text(own["status"]) == "pending" {
				return nil, domain.Err(409, "study_application_pending")
			}
			taken, e := tx.One(ctx, "SELECT id FROM jm_study_applications WHERE project_id=? AND participant_id=? AND status='approved'", id, participantID)
			if e != nil {
				return nil, e
			}
			if taken != nil {
				return nil, domain.Err(409, "study_participant_id_taken")
			}
			before := applicationAudit(own)
			now := m.now()
			row := Object{"participant_id": participantID, "status": "pending", "message": message, "review_reason": nil, "reviewer_id": nil, "row_version": int64(1), "updated_at": now}
			if own == nil {
				row["id"] = domain.NewID()
				row["project_id"] = id
				row["principal_id"] = actor
				row["created_at"] = now
				e = tx.Insert(ctx, "jm_study_applications", row)
				own = row
			} else {
				row["row_version"] = number(own["row_version"]) + 1
				e = tx.Update(ctx, "jm_study_applications", Object{"id": own["id"]}, row)
				for field, value := range row {
					own[field] = value
				}
			}
			if e != nil {
				return nil, e
			}
			if e = RecordAdminAudit(ctx, tx, actor, "study.apply", "study_application", text(own["id"]), before, applicationAudit(own), now); e != nil {
				return nil, e
			}
			return applicationView(own), nil
		}, func(_ Object) (Object, error) {
			row, e := tx.One(ctx, "SELECT * FROM jm_study_applications WHERE project_id=? AND principal_id=?", id, actor)
			if e != nil {
				return nil, e
			}
			return applicationView(row), nil
		})
		return e
	})
	return result, e
}
func applicationAudit(row Object) Object {
	if row == nil {
		return nil
	}
	return Object{"id": row["id"], "principal_id": row["principal_id"], "participant_id": row["participant_id"], "status": row["status"], "version": row["row_version"]}
}
func (m *Manager) ListStudyApplications(ctx context.Context, actor, id string, limit int, cursor string) (Object, error) {
	if e := principal(actor); e != nil {
		return nil, e
	}
	if e := pageLimit(limit); e != nil {
		return nil, e
	}
	after := ""
	if cursor != "" {
		position, e := m.decodeCursor(cursor, actor, "study-applications", id)
		if e != nil {
			return nil, e
		}
		var ok bool
		after, ok = position.(string)
		if !ok || after == "" {
			return nil, domain.Err(422, "invalid_cursor")
		}
	}
	items := []Object{}
	next := ""
	e := m.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		_, _, _, admin, e := m.studyScope(ctx, tx, actor, id, false)
		if e != nil {
			return e
		}
		if !admin {
			return domain.Err(403, "project_admin_required")
		}
		rows, e := tx.All(ctx, "SELECT * FROM jm_study_applications WHERE project_id=? AND id>? ORDER BY id LIMIT ?", id, after, limit+1)
		if e != nil {
			return e
		}
		more := len(rows) > limit
		if more {
			rows = rows[:limit]
		}
		for _, row := range rows {
			items = append(items, applicationView(row))
		}
		if more {
			next, e = m.encodeCursor(actor, "study-applications", id, text(rows[len(rows)-1]["id"]))
			return e
		}
		return nil
	})
	return Object{"items": items, "next_cursor": next}, e
}
func (m *Manager) ReviewStudyApplication(ctx context.Context, actor, projectID, applicationID, action, reason string, expected int64, k string) (Object, error) {
	if e := principal(actor); e != nil {
		return nil, e
	}
	if !has([]string{"approve", "reject", "withdraw"}, action) || !studyText(reason, 1000) {
		return nil, domain.Err(422, "invalid_study_review")
	}
	var result Object
	e := m.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		_, _, _, admin, e := m.studyScope(ctx, tx, actor, projectID, true)
		if e != nil {
			return e
		}
		row, e := tx.One(ctx, "SELECT * FROM jm_study_applications WHERE id=? AND project_id=?", applicationID, projectID)
		if e != nil {
			return e
		}
		if row == nil {
			return domain.Err(404, "study_application_not_found")
		}
		if action == "withdraw" {
			if text(row["principal_id"]) != actor {
				return domain.Err(404, "study_application_not_found")
			}
		} else if !admin {
			return domain.Err(403, "project_admin_required")
		}
		body := Object{"action": action, "reason": reason, "expected_version": expected}
		result, e = m.once(ctx, tx, actor, "study."+action+":"+applicationID, k, body, func() (Object, error) {
			if e := requireStudyVersion(row, expected); e != nil {
				return nil, e
			}
			if text(row["status"]) != "pending" {
				return nil, domain.Err(409, "study_application_not_pending")
			}
			status := map[string]string{"approve": "approved", "reject": "rejected", "withdraw": "withdrawn"}[action]
			if action == "approve" {
				taken, e := tx.One(ctx, "SELECT id FROM jm_study_applications WHERE project_id=? AND participant_id=? AND status='approved' AND id<>?", projectID, row["participant_id"], applicationID)
				if e != nil {
					return nil, e
				}
				if taken != nil {
					return nil, domain.Err(409, "study_participant_id_taken")
				}
			}
			before := applicationAudit(row)
			now := m.now()
			changes := Object{"status": status, "review_reason": reason, "reviewer_id": actor, "row_version": number(row["row_version"]) + 1, "updated_at": now}
			if action == "withdraw" {
				changes["review_reason"] = nil
				changes["reviewer_id"] = nil
			}
			if e = tx.Update(ctx, "jm_study_applications", Object{"id": applicationID}, changes); e != nil {
				return nil, e
			}
			for field, value := range changes {
				row[field] = value
			}
			if e = RecordAdminAudit(ctx, tx, actor, "study."+action, "study_application", applicationID, before, applicationAudit(row), now); e != nil {
				return nil, e
			}
			return applicationView(row), nil
		}, func(_ Object) (Object, error) {
			current, e := tx.One(ctx, "SELECT * FROM jm_study_applications WHERE id=? AND project_id=?", applicationID, projectID)
			if e != nil {
				return nil, e
			}
			return applicationView(current), nil
		})
		return e
	})
	return result, e
}

// RequireStudyParticipant is the common execution-eligibility boundary. It
// grants no project/job role and never substitutes dataset or node approval.
func (m *Manager) RequireStudyParticipant(ctx context.Context, projectID, participantID string) error {
	if strings.TrimSpace(projectID) == "" || !domain.ValidIdentifier(participantID) {
		return domain.Err(422, "invalid_study_application")
	}
	return m.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		_, e := store.StudyParticipantPrincipal(ctx, tx, projectID, participantID)
		return e
	})
}
