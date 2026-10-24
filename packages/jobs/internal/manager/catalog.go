package manager

import (
	"context"
	"strings"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func (m *Manager) Catalog(ctx context.Context, actor string) (Object, error) {
	if e := principal(actor); e != nil {
		return nil, e
	}
	result := Object{"projects": []Object{}, "sources": []Object{}, "runtime_images": []Object{}, "participant_bindings": []Object{}, "pools": []Object{}}
	e := m.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		projects, e := tx.All(ctx, "SELECT p.* FROM jm_projects p JOIN jm_project_members m ON m.project_id = p.id AND m.principal_id = ? AND m.role IN ('submitter','admin') ORDER BY p.id", actor)
		if e != nil {
			return e
		}
		ids := []any{}
		projectView := []Object{}
		for _, p := range projects {
			ids = append(ids, p["id"])
			projectView = append(projectView, Object{"id": p["id"], "name": p["name"], "retention_days": p["retention_days"]})
		}
		result["projects"] = projectView
		if len(ids) == 0 {
			return nil
		}
		in := strings.TrimRight(strings.Repeat("?,", len(ids)), ",")
		source, e := tx.All(ctx, "SELECT * FROM jm_approved_sources WHERE enabled = ? AND status = 'approved' AND (project_id IS NULL OR project_id IN ("+in+")) ORDER BY id", append([]any{true}, ids...)...)
		if e != nil {
			return e
		}
		sources := []Object{}
		for _, s := range source {
			sources = append(sources, Object{"id": s["id"], "name": s["name"], "project_id": s["project_id"], "allowed_commits": s["allowed_commits"]})
		}
		result["sources"] = sources
		image, e := tx.All(ctx, "SELECT * FROM jm_runtime_images WHERE enabled = ? AND approved = ? AND status = 'approved' AND (project_id IS NULL OR project_id IN ("+in+")) ORDER BY id", append([]any{true, true}, ids...)...)
		if e != nil {
			return e
		}
		images := []Object{}
		for _, s := range image {
			images = append(images, Object{"id": s["id"], "name": s["name"], "project_id": s["project_id"], "digest": s["digest"]})
		}
		result["runtime_images"] = images
		binding, e := tx.All(ctx, "SELECT * FROM jm_participant_bindings WHERE enabled = ? AND project_id IN ("+in+") ORDER BY id", append([]any{true}, ids...)...)
		if e != nil {
			return e
		}
		bindings := []Object{}
		for _, s := range binding {
			bindings = append(bindings, Object{"id": s["id"], "project_id": s["project_id"], "participant_id": s["participant_id"], "dataset_label": s["dataset_label"], "node_id": s["node_id"]})
		}
		result["participant_bindings"] = bindings
		pool, e := tx.All(ctx, "SELECT * FROM jm_pools ORDER BY id")
		if e != nil {
			return e
		}
		pools := []Object{}
		for _, p := range pool {
			pools = append(pools, Object{"id": p["id"], "name": p["name"], "sandbox_profiles": p["sandbox_profiles"], "gpu_profiles": p["gpu_profiles"], "capacity": Object{"cpu_millicores": p["cpu_millicores"], "memory_bytes": p["memory_bytes"], "disk_bytes": p["disk_bytes"], "gpu_count": len(arr(p["gpu_uuids"]))}})
		}
		result["pools"] = pools
		return nil
	})
	return result, e
}
func poolView(pool Object) Object {
	v := Object{}
	for _, k := range []string{"id", "name", "node_id", "cpu_millicores", "memory_bytes", "disk_bytes", "gpu_uuids", "gpu_profiles", "sandbox_profiles", "healthy", "quarantined", "version"} {
		v[k] = pool[k]
	}
	return v
}
func poolUsed(ctx context.Context, tx *store.Tx, poolID string) (int64, error) {
	allocations, e := tx.All(ctx, "SELECT * FROM jm_allocations WHERE pool_id = ?", poolID)
	if e != nil {
		return 0, e
	}
	total := int64(0)
	for _, a := range allocations {
		d := obj(a["details_json"])
		if a["released_at"] == nil || (text(a["state"]) == "RELEASED" && flag(d["retained_disk_charged"]) && !flag(d["storage_deleted"])) {
			total += number(a["disk_bytes"])
		}
	}
	resources, e := tx.All(ctx, "SELECT * FROM jm_provisioning_resources WHERE retained = ? AND state <> 'deleted' AND kind <> 'execution_state'", true)
	if e != nil {
		return 0, e
	}
	for _, r := range resources {
		if text(obj(r["details_json"])["pool_id"]) == poolID {
			total += number(r["size_bytes"])
		}
	}
	return total, nil
}
func (m *Manager) platform(actor string) error {
	if e := principal(actor); e != nil {
		return e
	}
	if !m.PlatformOperatorIDs[actor] {
		return domain.Err(403, "platform_operator_required")
	}
	return nil
}
func (m *Manager) ListPools(ctx context.Context, actor string) (Object, error) {
	if e := m.platform(actor); e != nil {
		return nil, e
	}
	items := []Object{}
	e := m.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		pools, e := tx.All(ctx, "SELECT * FROM jm_pools ORDER BY id")
		if e != nil {
			return e
		}
		for _, p := range pools {
			allocations, e := tx.All(ctx, "SELECT * FROM jm_allocations WHERE pool_id = ? AND released_at IS NULL", p["id"])
			if e != nil {
				return e
			}
			usage := Object{"cpu_millicores": int64(0), "memory_bytes": int64(0), "disk_bytes": int64(0), "gpu_count": int64(0)}
			for _, a := range allocations {
				for key := range usage {
					usage[key] = number(usage[key]) + number(a[key])
				}
			}
			disk, e := poolUsed(ctx, tx, text(p["id"]))
			if e != nil {
				return e
			}
			v := poolView(p)
			v["reserved"] = usage
			v["disk_used_bytes"] = disk
			v["retained_disk_bytes"] = disk - number(usage["disk_bytes"])
			items = append(items, v)
		}
		return nil
	})
	return Object{"items": items}, e
}
func (m *Manager) PutPool(ctx context.Context, actor, poolID string, values Object) (Object, error) {
	if e := m.platform(actor); e != nil {
		return nil, e
	}
	if len(values) == 0 {
		return nil, domain.Err(422, "invalid_pool_fields")
	}
	allowed := map[string]bool{}
	for _, k := range []string{"name", "node_id", "cpu_millicores", "memory_bytes", "disk_bytes", "gpu_uuids", "gpu_profiles", "sandbox_profiles", "healthy", "quarantined", "expected_version"} {
		allowed[k] = true
	}
	for key := range values {
		if !allowed[key] {
			return nil, domain.Err(422, "invalid_pool_fields")
		}
	}
	for _, k := range []string{"cpu_millicores", "memory_bytes", "disk_bytes"} {
		if v, ok := values[k]; ok {
			n, yes := strictInt(v)
			if !yes || n < 0 || n > 1<<50 {
				return nil, domain.Err(422, "invalid_pool_capacity")
			}
		}
	}
	for _, k := range []string{"healthy", "quarantined"} {
		if v, ok := values[k]; ok {
			if _, yes := v.(bool); !yes {
				return nil, domain.Err(422, "invalid_pool_health")
			}
		}
	}
	for _, k := range []string{"gpu_uuids", "gpu_profiles", "sandbox_profiles"} {
		if v, ok := values[k]; ok {
			list := arr(v)
			switch v.(type) {
			case []string, []any:
			default:
				return nil, domain.Err(422, "invalid_pool_profiles")
			}
			if len(list) > 1024 {
				return nil, domain.Err(422, "invalid_pool_profiles")
			}
			seen := map[string]bool{}
			for _, item := range list {
				s, ok := item.(string)
				if !ok || s == "" || len([]rune(s)) > 128 || seen[s] {
					return nil, domain.Err(422, "invalid_pool_profiles")
				}
				seen[s] = true
			}
		}
	}
	for _, k := range []string{"name", "node_id"} {
		if v, ok := values[k]; ok {
			if _, yes := v.(string); !yes || text(v) == "" || len([]rune(text(v))) > 200 {
				return nil, domain.Err(422, "invalid_pool_identity")
			}
		}
	}
	var result Object
	e := m.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		pool, e := tx.One(ctx, "SELECT * FROM jm_pools WHERE id = ?"+tx.ForUpdate(), poolID)
		if e != nil {
			return e
		}
		existing := pool != nil
		if flag(obj(pool["details_json"])["manager_storage"]) {
			return domain.Err(409, "manager_storage_pool_requires_trusted_cli")
		}
		if flag(obj(pool["details_json"])["object_store"]) {
			return domain.Err(409, "object_store_pool_requires_trusted_cli")
		}
		var before Object
		if existing {
			before = poolView(pool)
		} else {
			if text(values["name"]) == "" || text(values["node_id"]) == "" {
				return domain.Err(422, "pool_name_and_node_required")
			}
			pool = Object{"id": poolID, "name": values["name"], "node_id": values["node_id"], "version": int64(1), "cpu_millicores": int64(0), "memory_bytes": int64(0), "disk_bytes": int64(0), "gpu_uuids": []any{}, "gpu_profiles": []any{}, "sandbox_profiles": []any{}, "healthy": false, "quarantined": false}
		}
		if existing && values["expected_version"] != nil {
			n, ok := strictInt(values["expected_version"])
			if !ok || n != number(pool["version"]) {
				return domain.Err(409, "pool_version_conflict")
			}
		}
		proposed := poolView(pool)
		for k, v := range values {
			if k != "expected_version" {
				proposed[k] = v
			}
		}
		expands := proposed["node_id"] != pool["node_id"]
		for _, k := range []string{"cpu_millicores", "memory_bytes", "disk_bytes"} {
			if number(proposed[k]) > number(pool[k]) {
				expands = true
			}
		}
		for _, k := range []string{"gpu_uuids", "gpu_profiles", "sandbox_profiles"} {
			for _, v := range arr(proposed[k]) {
				if !has(pool[k], text(v)) {
					expands = true
				}
			}
		}
		allocations, e := tx.All(ctx, "SELECT * FROM jm_allocations WHERE pool_id = ? AND released_at IS NULL"+tx.ForUpdate(), poolID)
		if e != nil {
			return e
		}
		for _, k := range []string{"cpu_millicores", "memory_bytes", "disk_bytes"} {
			if v, ok := values[k]; ok {
				reserved := int64(0)
				for _, a := range allocations {
					reserved += number(a[k])
				}
				if number(v) < reserved {
					return domain.Err(409, "pool_capacity_below_reserved")
				}
			}
		}
		if v, ok := values["disk_bytes"]; ok {
			used, e := poolUsed(ctx, tx, poolID)
			if e != nil {
				return e
			}
			if number(v) < used {
				return domain.Err(409, "pool_capacity_below_retained_storage")
			}
		}
		if len(allocations) > 0 && proposed["node_id"] != pool["node_id"] {
			return domain.Err(409, "pool_node_has_active_allocations")
		}
		if v, ok := values["gpu_uuids"]; ok {
			rows, e := tx.All(ctx, "SELECT gpu_uuid FROM jm_gpu_allocations WHERE pool_id = ? AND released_at IS NULL", poolID)
			if e != nil {
				return e
			}
			for _, r := range rows {
				if !has(v, text(r["gpu_uuid"])) {
					return domain.Err(409, "pool_gpu_has_active_allocation")
				}
			}
		}
		if flag(proposed["healthy"]) && (expands || !flag(pool["healthy"])) {
			if m.PoolQualifier == nil {
				return domain.Err(409, "pool_qualification_required")
			}
			ok, e := m.PoolQualifier(ctx, proposed)
			if e != nil {
				return e
			}
			if !ok {
				return domain.Err(409, "pool_qualification_required")
			}
		}
		for k, v := range values {
			if k != "expected_version" {
				pool[k] = v
			}
		}
		pool["updated_at"] = m.now()
		pool["version"] = number(pool["version"]) + 1
		if existing {
			updates := copyObject(pool)
			delete(updates, "id")
			if e = tx.Update(ctx, "jm_pools", Object{"id": poolID}, updates); e != nil {
				return e
			}
		} else {
			if e = tx.Insert(ctx, "jm_pools", pool); e != nil {
				return e
			}
		}
		operation := "pool.update"
		if !existing {
			operation = "pool.create"
		}
		if e = RecordAdminAudit(ctx, tx, actor, operation, "pool", poolID, before, poolView(pool), m.now()); e != nil {
			return e
		}
		result = poolView(pool)
		return nil
	})
	return result, e
}
