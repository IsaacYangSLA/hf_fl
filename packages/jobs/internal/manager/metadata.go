package manager

import (
	"context"
	"strings"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func (m *Manager) ListEvents(ctx context.Context, actor, id string, limit int, cursor string) (Object, error) {
	if e := pageLimit(limit); e != nil {
		return nil, e
	}
	filters := Object{"job_id": id}
	var result Object
	e := m.withJob(ctx, actor, id, "reader", false, func(tx *store.Tx, job, member Object) error {
		position := int64(0)
		if cursor != "" {
			v, e := m.decodeCursor(cursor, actor, "events", filters)
			if e != nil {
				return e
			}
			var ok bool
			position, ok = strictInt(v)
			if !ok || position < 0 {
				return domain.Err(422, "invalid_cursor")
			}
		}
		rows, e := tx.All(ctx, "SELECT * FROM jm_events WHERE job_id = ? AND sequence > ? ORDER BY sequence LIMIT ?", id, position, limit+1)
		if e != nil {
			return e
		}
		items := []Object{}
		for i, r := range rows {
			if i == limit {
				break
			}
			items = append(items, Object{"id": r["id"], "kind": r["kind"], "actor_id": r["actor_id"], "data": r["data_json"], "created_at": iso(r["created_at"])})
		}
		var next any
		if len(rows) > limit {
			next, e = m.encodeCursor(actor, "events", filters, rows[limit-1]["sequence"])
			if e != nil {
				return e
			}
		}
		result = Object{"items": items, "next_cursor": next}
		return nil
	})
	return result, e
}
func (m *Manager) ListLogs(ctx context.Context, actor, id string, limit int, cursor, component string, attempt *int64) (Object, error) {
	if e := pageLimit(limit); e != nil {
		return nil, e
	}
	if len([]rune(component)) > 128 || (attempt != nil && *attempt < 1) {
		return nil, domain.Err(422, "invalid_log_filter")
	}
	var comp any
	var attemptValue any
	if component != "" {
		comp = component
	}
	if attempt != nil {
		attemptValue = *attempt
	}
	filters := Object{"job_id": id, "component": comp, "attempt": attemptValue}
	var result Object
	e := m.withJob(ctx, actor, id, "reader", false, func(tx *store.Tx, job, member Object) error {
		query := "SELECT * FROM jm_log_chunks WHERE job_id = ?"
		args := []any{id}
		if component != "" {
			query += " AND component = ?"
			args = append(args, component)
		}
		if attempt != nil {
			query += " AND attempt_number = ?"
			args = append(args, *attempt)
		}
		if cursor != "" {
			position, e := m.decodeCursor(cursor, actor, "logs", filters)
			if e != nil {
				return e
			}
			stamp, identity, e := cursorPosition(position)
			if e != nil {
				return e
			}
			query += " AND (created_at > ? OR (created_at = ? AND id > ?))"
			args = append(args, stamp, stamp, identity)
		}
		args = append(args, limit+1)
		rows, e := tx.All(ctx, query+" ORDER BY created_at,id LIMIT ?", args...)
		if e != nil {
			return e
		}
		items := []Object{}
		bytesReturned := 0
		var last Object
		for i, r := range rows {
			if i == limit {
				break
			}
			gone := r["deleted_at"] != nil || expired(r["expires_at"], m.now()) || expired(job["artifacts_expire_at"], m.now()) || job["purged_at"] != nil
			data := text(r["data"])
			if gone {
				data = ""
			}
			if len(data) > 65536 {
				return domain.Err(503, "stored_log_exceeds_bound")
			}
			if len(items) > 0 && bytesReturned+len(data) > 1048576 {
				break
			}
			items = append(items, Object{"id": r["id"], "component": r["component"], "attempt_number": r["attempt_number"], "data": data, "expired": gone, "created_at": iso(r["created_at"]), "expires_at": iso(r["expires_at"])})
			bytesReturned += len(data)
			last = r
		}
		var next any
		if len(rows) > len(items) && last != nil {
			next, e = m.encodeCursor(actor, "logs", filters, Object{"created_at": iso(last["created_at"]), "id": last["id"]})
			if e != nil {
				return e
			}
		}
		result = Object{"items": items, "next_cursor": next, "bytes_returned": bytesReturned}
		return nil
	})
	return result, e
}
func (m *Manager) artifactView(job, artifact Object) Object {
	gone := expired(artifact["expires_at"], m.now()) || has([]any{"expired", "deleting", "deleted"}, text(artifact["state"]))
	state := artifact["state"]
	if gone && text(state) != "deleted" {
		state = "expired"
	}
	v := Object{"id": artifact["id"], "attempt_number": artifact["attempt_number"], "kind": artifact["kind"], "name": artifact["name"], "size_bytes": artifact["size_bytes"], "sha256": artifact["sha256"], "state": state, "created_at": iso(artifact["created_at"]), "expires_at": iso(artifact["expires_at"]), "deleted_at": iso(artifact["deleted_at"]), "download_available": !gone && has([]any{"available", "retained"}, text(artifact["state"]))}
	locator := obj(artifact["locator_json"])
	if text(artifact["kind"]) == "source" && text(locator["kind"]) == "local" {
		path := text(locator["relative_path"])
		if relativeArtifactPath(path) {
			v["source_path"] = path
		}
	}
	if job["purged_at"] != nil || expired(job["artifacts_expire_at"], m.now()) {
		v["download_available"] = false
		if text(v["state"]) != "deleted" {
			v["state"] = "expired"
		}
	}
	return v
}
func relativeArtifactPath(path string) bool {
	if path == "" || len([]rune(path)) > 1024 || strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\\\x00") {
		return false
	}
	for _, s := range strings.Split(path, "/") {
		if s == "" || s == "." || s == ".." {
			return false
		}
	}
	return true
}
func (m *Manager) ListArtifacts(ctx context.Context, actor, id string, limit int, cursor string) (Object, error) {
	if e := pageLimit(limit); e != nil {
		return nil, e
	}
	filters := Object{"job_id": id}
	var result Object
	e := m.withJob(ctx, actor, id, "reader", false, func(tx *store.Tx, job, member Object) error {
		query := "SELECT * FROM jm_artifacts WHERE job_id = ?"
		args := []any{id}
		if cursor != "" {
			position, e := m.decodeCursor(cursor, actor, "artifacts", filters)
			if e != nil {
				return e
			}
			stamp, identity, e := cursorPosition(position)
			if e != nil {
				return e
			}
			query += " AND (created_at > ? OR (created_at = ? AND id > ?))"
			args = append(args, stamp, stamp, identity)
		}
		args = append(args, limit+1)
		rows, e := tx.All(ctx, query+" ORDER BY created_at,id LIMIT ?", args...)
		if e != nil {
			return e
		}
		items := []Object{}
		for i, r := range rows {
			if i == limit {
				break
			}
			items = append(items, m.artifactView(job, r))
		}
		var next any
		if len(rows) > limit {
			last := rows[limit-1]
			next, e = m.encodeCursor(actor, "artifacts", filters, Object{"created_at": iso(last["created_at"]), "id": last["id"]})
			if e != nil {
				return e
			}
		}
		result = Object{"items": items, "next_cursor": next}
		return nil
	})
	return result, e
}
func (m *Manager) GetArtifact(ctx context.Context, actor, id, artifactID string) (Object, error) {
	var result Object
	e := m.withJob(ctx, actor, id, "reader", false, func(tx *store.Tx, job, member Object) error {
		row, e := tx.One(ctx, "SELECT * FROM jm_artifacts WHERE id = ? AND job_id = ?", artifactID, id)
		if e != nil {
			return e
		}
		if row == nil {
			return domain.Err(404, "artifact_not_found")
		}
		result = m.artifactView(job, row)
		return nil
	})
	return result, e
}
func (m *Manager) ArtifactStorage(ctx context.Context, actor, id, artifactID string) (Object, error) {
	var result Object
	e := m.withJob(ctx, actor, id, "reader", false, func(tx *store.Tx, job, member Object) error {
		artifact, e := tx.One(ctx, "SELECT * FROM jm_artifacts WHERE id = ? AND job_id = ?", artifactID, id)
		if e != nil {
			return e
		}
		if artifact == nil {
			return domain.Err(404, "artifact_not_found")
		}
		view := m.artifactView(job, artifact)
		if job["purged_at"] != nil || expired(job["artifacts_expire_at"], m.now()) || !flag(view["download_available"]) {
			return domain.Err(410, "artifact_expired")
		}
		locator, ok := artifact["locator_json"].(map[string]any)
		if !ok {
			return domain.Err(503, "artifact_locator_unavailable")
		}
		switch text(locator["kind"]) {
		case "exchange":
			if len(locator) != 4 || badText(text(locator["space_id"]), 256) || badText(text(locator["record_id"]), 256) || badText(text(locator["attachment_id"]), 256) {
				return domain.Err(503, "invalid_artifact_locator")
			}
			owned, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id = ? AND kind = ? AND external_id = ?", id, "exchange_space", locator["space_id"])
			if e != nil {
				return e
			}
			if owned == nil || obj(owned["ownership_json"])["job_id"] != id || has([]any{"deleted", "retired"}, text(owned["state"])) {
				return domain.Err(503, "invalid_artifact_locator")
			}
		case "local":
			if len(locator) != 3 || !relativeArtifactPath(text(locator["relative_path"])) {
				return domain.Err(503, "invalid_artifact_locator")
			}
			resource, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?", locator["resource_id"])
			if e != nil {
				return e
			}
			if resource == nil || resource["job_id"] != id || obj(resource["ownership_json"])["job_id"] != id || text(resource["state"]) == "deleted" || resource["deleted_at"] != nil {
				return domain.Err(503, "invalid_artifact_locator")
			}
		default:
			return domain.Err(503, "invalid_artifact_locator")
		}
		result = copyObject(view)
		result["locator"] = copyObject(locator)
		return nil
	})
	return result, e
}

// ArtifactDownloadDescriptor is the trusted broker descriptor, never an HTTP JSON response.
func (m *Manager) ArtifactDownloadDescriptor(ctx context.Context, actor, id, artifactID string) (Object, error) {
	return m.ArtifactStorage(ctx, actor, id, artifactID)
}
