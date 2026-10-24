// Trusted administrative mutations run locally, outside the public HTTP API.
package manager

import (
	"context"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/secrets"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/source"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	"golang.org/x/sys/unix"
)

// AdminPolicy contains only operator-owned configuration and qualification
// callbacks. None of these settings can be supplied in a job request.
type AdminPolicy struct {
	StoragePoolID      string
	StorageRoot        string
	AllowedSourceHosts []string
	SourceResolver     func(context.Context, string) ([]net.IP, error)
	QualifyObjectStore func(context.Context) (string, Object, error)
}

var adminCommit = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)
var adminDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var adminProjectFields = []string{"name", "retention_days", "quotas_json", "version"}
var adminPoolFields = []string{"name", "node_id", "cpu_millicores", "memory_bytes", "disk_bytes", "gpu_uuids", "gpu_profiles", "sandbox_profiles", "healthy", "quarantined", "version"}

func adminInvalid() error { return domain.Err(422, "invalid_deployment_configuration") }
func adminKeys(v Object, required, optional []string) error {
	allowed := map[string]bool{}
	for _, k := range required {
		allowed[k] = true
		if _, ok := v[k]; !ok {
			return adminInvalid()
		}
	}
	for _, k := range optional {
		allowed[k] = true
	}
	for k := range v {
		if !allowed[k] {
			return adminInvalid()
		}
	}
	return nil
}
func adminID(v any) (string, error) {
	s, ok := v.(string)
	if !ok || domain.ValidateIdentifier(s) != nil {
		return "", adminInvalid()
	}
	return s, nil
}
func adminText(v any, max int) (string, error) {
	s, ok := v.(string)
	if !ok || badText(s, max) || strings.TrimSpace(s) == "" || strings.ContainsRune(s, 127) {
		return "", adminInvalid()
	}
	return s, nil
}
func adminInt(v any, min, max int64) (int64, error) {
	n, ok := strictInt(v)
	if !ok || n < min || n > max {
		return 0, adminInvalid()
	}
	return n, nil
}
func adminBool(v any, def bool) (bool, error) {
	if v == nil {
		return def, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, adminInvalid()
	}
	return b, nil
}
func adminBoolField(v Object, key string, def bool) (bool, error) {
	x, ok := v[key]
	if !ok {
		return def, nil
	}
	if x == nil {
		return false, adminInvalid()
	}
	return adminBool(x, def)
}
func adminIntDefault(v Object, key string, def, min, max int64) (int64, error) {
	x, ok := v[key]
	if !ok {
		return def, nil
	}
	return adminInt(x, min, max)
}
func adminPolicyFields(v Object, fields []string) Object {
	if v == nil {
		return nil
	}
	o := Object{}
	for _, k := range fields {
		o[k] = v[k]
	}
	return o
}
func adminQuota(v any) (Object, error) {
	q, ok := v.(map[string]any)
	if !ok {
		return nil, adminInvalid()
	}
	allowed := map[string]bool{"cpu_millicores": true, "memory_bytes": true, "disk_bytes": true, "gpu_count": true, "max_running_jobs": true, "retained_bytes": true}
	result := Object{}
	for k, v := range q {
		if !allowed[k] {
			return nil, adminInvalid()
		}
		n, e := adminInt(v, 0, 1<<50)
		if e != nil {
			return nil, e
		}
		result[k] = n
	}
	return result, nil
}
func adminList(v any) ([]string, error) {
	a, ok := v.([]any)
	if !ok {
		if s, yes := v.([]string); yes {
			a = make([]any, len(s))
			for i := range s {
				a[i] = s[i]
			}
		} else {
			return nil, adminInvalid()
		}
	}
	result := []string{}
	seen := map[string]bool{}
	for _, v := range a {
		s, e := adminID(v)
		if e != nil || seen[s] {
			return nil, adminInvalid()
		}
		seen[s] = true
		result = append(result, s)
	}
	return result, nil
}
func adminAdd(a, b int64) (int64, error) {
	if a < 0 || b < 0 || a > math.MaxInt64-b {
		return 0, adminInvalid()
	}
	return a + b, nil
}
func adminProject(ctx context.Context, tx *store.Tx, id string, lock bool) (Object, error) {
	suffix := ""
	if lock {
		suffix = tx.ForUpdate()
	}
	row, e := tx.One(ctx, "SELECT * FROM jm_projects WHERE id = ?"+suffix, id)
	if e != nil {
		return nil, e
	}
	if row == nil {
		return nil, adminInvalid()
	}
	return row, nil
}
func adminUpsert(ctx context.Context, tx *store.Tx, table, id string, old, values Object) error {
	if old == nil {
		values = copyObject(values)
		values["id"] = id
		return tx.Insert(ctx, table, values)
	}
	return tx.Update(ctx, table, Object{"id": id}, values)
}

// RecordAdminAudit inserts sanitized policy history in the caller's transaction.
func RecordAdminAudit(ctx context.Context, tx *store.Tx, actor, operation, resourceType, resourceID string, before, after Object, now time.Time) error {
	safeBefore, e := store.SanitizeAuditMetadata(before)
	if e != nil {
		return e
	}
	safeAfter, e := store.SanitizeAuditMetadata(after)
	if e != nil {
		return e
	}
	var beforeValue, afterValue any
	if before != nil {
		beforeValue = safeBefore
	}
	if after != nil {
		afterValue = safeAfter
	}
	return tx.Insert(ctx, "jm_admin_audit", Object{"id": domain.NewID(), "actor_id": actor, "operation": operation, "resource_type": resourceType, "resource_id": resourceID, "before_json": beforeValue, "after_json": afterValue, "created_at": now.UTC()})
}

// TrustedAdmin changes operator-approved policy. The caller must identify the
// current Unix UID; HTTP identities cannot invoke this local administration path.
func (m *Manager) TrustedAdmin(ctx context.Context, actor, operation string, values Object) (Object, error) {
	if actor != fmt.Sprintf("unix:%d", os.Getuid()) {
		return nil, domain.Err(403, "trusted_administrator_required")
	}
	if values == nil {
		return nil, adminInvalid()
	}
	var id string
	e := m.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		var err error
		switch operation {
		case "project-create":
			if err = adminKeys(values, []string{"id", "name", "quota"}, []string{"retention_days"}); err != nil {
				return err
			}
			id, err = adminID(values["id"])
			if err != nil {
				return err
			}
			old, e := tx.One(ctx, "SELECT * FROM jm_projects WHERE id = ?"+tx.ForUpdate(), id)
			if e != nil {
				return e
			}
			if old != nil {
				return adminInvalid()
			}
			name, e := adminText(values["name"], 200)
			if e != nil {
				return e
			}
			quota, e := adminQuota(values["quota"])
			if e != nil {
				return e
			}
			retention, e := adminIntDefault(values, "retention_days", 90, 0, 36500)
			if e != nil {
				return e
			}
			row := Object{"id": id, "name": name, "retention_days": retention, "quotas_json": quota, "version": int64(1)}
			if e = tx.Insert(ctx, "jm_projects", row); e != nil {
				return e
			}
			return RecordAdminAudit(ctx, tx, actor, operation, "project", id, nil, adminPolicyFields(row, adminProjectFields), m.now())
		case "project-update":
			if err = adminKeys(values, []string{"id"}, []string{"name", "quota", "retention_days"}); err != nil {
				return err
			}
			id, err = adminID(values["id"])
			if err != nil {
				return err
			}
			row, e := adminProject(ctx, tx, id, true)
			if e != nil {
				return e
			}
			before := adminPolicyFields(row, adminProjectFields)
			update := Object{}
			if value, ok := values["name"]; ok && value != nil {
				name, e := adminText(value, 200)
				if e != nil {
					return e
				}
				update["name"] = name
			}
			if value, ok := values["retention_days"]; ok && value != nil {
				retention, e := adminInt(value, 0, 36500)
				if e != nil {
					return e
				}
				update["retention_days"] = retention
			}
			if value, ok := values["quota"]; ok && value != nil {
				quota, e := adminQuota(value)
				if e != nil {
					return e
				}
				if n, yes := quota["retained_bytes"]; yes && number(n) < number(row["retained_bytes"]) {
					return adminInvalid()
				}
				active, e := tx.All(ctx, "SELECT a.* FROM jm_allocations a JOIN jm_jobs j ON a.job_id = j.id WHERE j.project_id = ? AND a.released_at IS NULL", id)
				if e != nil {
					return e
				}
				floors := map[string]int64{}
				jobs := map[string]bool{}
				for _, allocation := range active {
					for _, field := range []string{"cpu_millicores", "memory_bytes", "disk_bytes", "gpu_count"} {
						n, e := adminAdd(floors[field], number(allocation[field]))
						if e != nil {
							return e
						}
						floors[field] = n
					}
					jobs[text(allocation["job_id"])] = true
				}
				floors["max_running_jobs"] = int64(len(jobs))
				for k, n := range floors {
					if v, yes := quota[k]; yes && number(v) < n {
						return adminInvalid()
					}
				}
				update["quotas_json"] = quota
				for k, column := range map[string]string{"cpu_millicores": "quota_cpu_millicores", "memory_bytes": "quota_memory_bytes", "disk_bytes": "quota_disk_bytes", "gpu_count": "quota_gpus", "max_running_jobs": "max_active_jobs"} {
					update[column] = quota[k]
				}
			}
			if len(update) == 0 {
				return adminInvalid()
			}
			update["version"] = number(row["version"]) + 1
			if e = tx.Update(ctx, "jm_projects", Object{"id": id}, update); e != nil {
				return e
			}
			for k, v := range update {
				row[k] = v
			}
			return RecordAdminAudit(ctx, tx, actor, operation, "project", id, before, adminPolicyFields(row, adminProjectFields), m.now())
		case "project-member":
			if err = adminKeys(values, []string{"project", "principal", "role"}, nil); err != nil {
				return err
			}
			id, err = adminID(values["project"])
			if err != nil {
				return err
			}
			if _, err = adminProject(ctx, tx, id, true); err != nil {
				return err
			}
			member, e := adminText(values["principal"], 256)
			if e != nil {
				return e
			}
			role := text(values["role"])
			if role != "submitter" && role != "admin" && role != "remove" {
				return adminInvalid()
			}
			old, e := tx.One(ctx, "SELECT * FROM jm_project_members WHERE project_id = ? AND principal_id = ?", id, member)
			if e != nil {
				return e
			}
			if role == "remove" {
				_, e = tx.Exec(ctx, "DELETE FROM jm_project_members WHERE project_id = ? AND principal_id = ?", id, member)
				return e
			}
			if old == nil {
				return tx.Insert(ctx, "jm_project_members", Object{"project_id": id, "principal_id": member, "role": role})
			}
			return tx.Update(ctx, "jm_project_members", Object{"project_id": id, "principal_id": member}, Object{"role": role})
		case "pool-set", "storage-pool-set", "object-store-pool-set":
			id, err = adminID(values["id"])
			if err != nil {
				return err
			}
			return m.adminPool(ctx, tx, actor, operation, id, values)
		case "source-approve", "image-approve", "dataset-approve", "secret-ref-approve":
			id, err = adminID(values["id"])
			if err != nil {
				return err
			}
			return m.adminApproval(ctx, tx, operation, id, values)
		default:
			return adminInvalid()
		}
	})
	if e != nil {
		return nil, e
	}
	return Object{"operation": operation, "id": id, "status": "ok"}, nil
}

func adminPoolUsed(ctx context.Context, tx *store.Tx, poolID string) (int64, error) {
	rows, e := tx.All(ctx, "SELECT * FROM jm_allocations WHERE pool_id = ?", poolID)
	if e != nil {
		return 0, e
	}
	var total int64
	for _, a := range rows {
		d := obj(a["details_json"])
		if a["released_at"] == nil || (text(a["state"]) == "RELEASED" && flag(d["retained_disk_charged"]) && !flag(d["storage_deleted"])) {
			total, e = adminAdd(total, number(a["disk_bytes"]))
			if e != nil {
				return 0, e
			}
		}
	}
	resources, e := tx.All(ctx, "SELECT * FROM jm_provisioning_resources WHERE retained = ? AND state != ? AND kind != ?", true, "deleted", "execution_state")
	if e != nil {
		return 0, e
	}
	for _, r := range resources {
		if text(obj(r["details_json"])["pool_id"]) == poolID {
			total, e = adminAdd(total, number(r["size_bytes"]))
			if e != nil {
				return 0, e
			}
		}
	}
	return total, nil
}
func (m *Manager) adminPool(ctx context.Context, tx *store.Tx, actor, operation, id string, data Object) error {
	var required, optional []string
	switch operation {
	case "pool-set":
		required = []string{"id", "name", "node_id", "cpu_millicores", "memory_bytes", "disk_bytes"}
		optional = []string{"gpu_uuids", "gpu_profiles", "sandbox_profiles", "healthy", "quarantined"}
	case "storage-pool-set":
		required = []string{"id", "name", "node_id", "disk_bytes"}
	case "object-store-pool-set":
		required = []string{"id", "name", "disk_bytes"}
	}
	if e := adminKeys(data, required, optional); e != nil {
		return e
	}
	name, e := adminText(data["name"], 200)
	if e != nil {
		return e
	}
	minimum := int64(0)
	if operation != "pool-set" {
		minimum = 1
	}
	capacity, e := adminInt(data["disk_bytes"], minimum, 1<<50)
	if e != nil {
		return e
	}
	// Consistent ordering prevents two concurrent administrative pool changes from
	// locking the same pool set in opposite order.
	all, e := tx.All(ctx, "SELECT * FROM jm_pools ORDER BY id"+tx.ForUpdate())
	if e != nil {
		return e
	}
	var old Object
	for _, row := range all {
		if text(row["id"]) == id {
			old = row
		}
	}
	before := adminPolicyFields(old, adminPoolFields)
	update := Object{"name": name, "disk_bytes": capacity, "updated_at": m.now()}
	if old == nil {
		update["version"] = int64(1)
	} else {
		update["version"] = number(old["version"]) + 1
	}
	details := obj(nil)
	if old != nil {
		details = obj(old["details_json"])
	}
	switch operation {
	case "pool-set":
		nodeID, e := adminID(data["node_id"])
		if e != nil {
			return e
		}
		update["node_id"] = nodeID
		for _, field := range []string{"cpu_millicores", "memory_bytes"} {
			n, e := adminInt(data[field], 0, 1<<50)
			if e != nil {
				return e
			}
			update[field] = n
		}
		for _, field := range []string{"gpu_uuids", "gpu_profiles", "sandbox_profiles"} {
			raw, yes := data[field]
			if !yes {
				raw = []any{}
			}
			list, e := adminList(raw)
			if e != nil {
				return e
			}
			if field != "sandbox_profiles" && len(list) > 0 {
				return adminInvalid()
			}
			for _, profile := range list {
				if profile != "runsc-cpu-v1" {
					return adminInvalid()
				}
			}
			update[field] = list
		}
		healthy, e := adminBoolField(data, "healthy", false)
		if e != nil {
			return e
		}
		quarantined, e := adminBoolField(data, "quarantined", false)
		if e != nil {
			return e
		}
		if healthy {
			if m.PoolQualifier == nil {
				return domain.Err(409, "pool_qualification_required")
			}
			ok, e := m.PoolQualifier(ctx, copyObject(data))
			if e != nil {
				return e
			}
			if !ok {
				return domain.Err(409, "pool_qualification_required")
			}
		}
		if old != nil {
			if flag(details["manager_storage"]) || flag(details["object_store"]) {
				return adminInvalid()
			}
			active, e := tx.All(ctx, "SELECT * FROM jm_allocations WHERE pool_id = ? AND released_at IS NULL", id)
			if e != nil {
				return e
			}
			if len(active) > 0 && (text(old["node_id"]) != nodeID || (flag(old["quarantined"]) && !quarantined)) {
				return adminInvalid()
			}
			for _, field := range []string{"cpu_millicores", "memory_bytes"} {
				var used int64
				for _, row := range active {
					used, e = adminAdd(used, number(row[field]))
					if e != nil {
						return e
					}
				}
				if number(update[field]) < used {
					return adminInvalid()
				}
			}
		}
		update["healthy"] = healthy
		update["quarantined"] = quarantined
		newDetails := copyObject(details)
		newDetails["min_disk_bytes"] = int64(32 * 1024 * 1024)
		update["details_json"] = newDetails
	case "storage-pool-set":
		if m.AdminPolicy == nil || m.AdminPolicy.StoragePoolID != id {
			return adminInvalid()
		}
		nodeID, e := adminID(data["node_id"])
		if e != nil {
			return e
		}
		fd, metadata, e := adminStorageRoot(m.AdminPolicy.StorageRoot)
		if e != nil {
			return e
		}
		defer unix.Close(fd)
		var volume unix.Statfs_t
		if e = unix.Fstatfs(fd, &volume); e != nil {
			return e
		}
		if volume.Flags&unix.ST_RDONLY != 0 || volume.Bsize <= 0 || volume.Bavail < uint64((capacity+volume.Bsize-1)/volume.Bsize) {
			return adminInvalid()
		}
		dev, ino := int64(metadata.Dev), int64(metadata.Ino)
		for _, row := range all {
			if text(row["id"]) != id {
				info := obj(row["details_json"])
				if flag(info["manager_storage"]) && number(info["filesystem_device"]) == dev {
					return adminInvalid()
				}
			}
		}
		if old != nil && (!flag(details["manager_storage"]) || text(old["node_id"]) != nodeID || flag(old["quarantined"]) || number(details["filesystem_device"]) != dev || number(details["root_inode"]) != ino) {
			return adminInvalid()
		}
		update["node_id"] = nodeID
		update["details_json"] = Object{"manager_storage": true, "filesystem_device": dev, "root_inode": ino, "root_owner": int64(metadata.Uid)}
		adminStorageFields(update)
	case "object-store-pool-set":
		if m.AdminPolicy == nil || m.AdminPolicy.QualifyObjectStore == nil {
			return domain.Err(409, "object_store_qualification_required")
		}
		qualified, binding, e := m.AdminPolicy.QualifyObjectStore(ctx)
		if e != nil {
			return e
		}
		bound, e := adminInt(binding["capacity_bound_bytes"], 1, 1<<50)
		if e != nil || qualified != id || capacity > bound || !flag(binding["object_store"]) {
			return adminInvalid()
		}
		for _, k := range []string{"registration_id", "backend_id", "locator_id", "node_id"} {
			if _, e = adminText(binding[k], 256); e != nil {
				return e
			}
		}
		for _, row := range all {
			if text(row["id"]) != id {
				info := obj(row["details_json"])
				if flag(info["object_store"]) && text(info["locator_id"]) == text(binding["locator_id"]) {
					return adminInvalid()
				}
			}
		}
		if old != nil {
			if !flag(details["object_store"]) || flag(details["manager_storage"]) {
				return adminInvalid()
			}
			for _, k := range []string{"registration_id", "backend_id", "locator_id"} {
				if text(details[k]) != text(binding[k]) {
					return adminInvalid()
				}
			}
		}
		before = adminObjectPoolPolicy(old)
		update["node_id"] = binding["node_id"]
		update["details_json"] = binding
		adminStorageFields(update)
	}
	used, e := adminPoolUsed(ctx, tx, id)
	if e != nil {
		return e
	}
	if capacity < used {
		return adminInvalid()
	}
	if e = adminUpsert(ctx, tx, "jm_pools", id, old, update); e != nil {
		return e
	}
	row := copyObject(update)
	row["id"] = id
	after := adminPolicyFields(row, adminPoolFields)
	if operation == "object-store-pool-set" {
		after = adminObjectPoolPolicy(row)
	}
	return RecordAdminAudit(ctx, tx, actor, operation, "pool", id, before, after, m.now())
}
func adminStorageFields(row Object) {
	row["cpu_millicores"] = int64(0)
	row["memory_bytes"] = int64(0)
	row["gpu_uuids"] = []string{}
	row["gpu_profiles"] = []string{}
	row["sandbox_profiles"] = []string{}
	row["healthy"] = true
	row["quarantined"] = false
}
func adminObjectPoolPolicy(row Object) Object {
	if row == nil {
		return nil
	}
	v := adminPolicyFields(row, adminPoolFields)
	details := obj(row["details_json"])
	v["digest"] = details["backend_id"]
	v["quota_disk_bytes"] = details["capacity_bound_bytes"]
	v["status"] = "object_store"
	return v
}
func adminStorageRoot(root string) (int, *unix.Stat_t, error) {
	if !filepath.IsAbs(root) {
		return -1, nil, adminInvalid()
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, nil, e
	}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Clean(root), "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(fd)
		if e != nil {
			return -1, nil, adminInvalid()
		}
		fd = next
	}
	info := new(unix.Stat_t)
	if e = unix.Fstat(fd, info); e != nil {
		unix.Close(fd)
		return -1, nil, e
	}
	if info.Uid != uint32(os.Getuid()) || info.Mode&077 != 0 {
		unix.Close(fd)
		return -1, nil, adminInvalid()
	}
	return fd, info, nil
}

func (m *Manager) adminApproval(ctx context.Context, tx *store.Tx, operation, id string, data Object) error {
	enabled, e := adminBoolField(data, "enabled", true)
	if e != nil {
		return e
	}
	status := "approved"
	if !enabled {
		status = "disabled"
	}
	switch operation {
	case "source-approve":
		if e = adminKeys(data, []string{"id", "project_id", "allowed_commits"}, []string{"url", "mirror_path", "enabled", "max_bytes", "max_files", "max_git_bytes", "max_git_files"}); e != nil {
			return e
		}
		project, e := adminID(data["project_id"])
		if e != nil {
			return e
		}
		if _, e = adminProject(ctx, tx, project, true); e != nil {
			return e
		}
		commits, e := adminList(data["allowed_commits"])
		if e != nil || len(commits) == 0 {
			return adminInvalid()
		}
		for _, commit := range commits {
			if !adminCommit.MatchString(commit) {
				return adminInvalid()
			}
		}
		for _, field := range []string{"url", "mirror_path"} {
			if raw, present := data[field]; present && raw != nil {
				value, ok := raw.(string)
				if !ok || value == "" || len(value) > 2048 || strings.ContainsAny(value, "\x00\r\n") {
					return adminInvalid()
				}
			}
		}
		approval := source.Approval{SourceID: id, Projects: []string{project}, URL: text(data["url"]), MirrorPath: text(data["mirror_path"]), Commits: commits}
		for key, target := range map[string]*int64{"max_bytes": &approval.MaxBytes, "max_files": &approval.MaxFiles, "max_git_bytes": &approval.MaxGitBytes, "max_git_files": &approval.MaxGitFiles} {
			if v, ok := data[key]; ok {
				n, e := adminInt(v, 1, 1<<30)
				if e != nil {
					return e
				}
				*target = n
			}
		}
		approval = approval.Defaults()
		if e = approval.Validate(); e != nil {
			return adminInvalid()
		}
		hosts := []string{}
		if m.AdminPolicy != nil {
			hosts = append(hosts, m.AdminPolicy.AllowedSourceHosts...)
		}
		registry, e := source.NewRegistry([]source.Approval{approval}, hosts)
		if e != nil {
			return adminInvalid()
		}
		if m.AdminPolicy != nil && m.AdminPolicy.SourceResolver != nil {
			registry.Resolver = m.AdminPolicy.SourceResolver
		}
		if approval.URL != "" {
			if _, _, e = registry.Remote(ctx, approval); e != nil {
				return adminInvalid()
			}
		}
		old, e := tx.One(ctx, "SELECT * FROM jm_approved_sources WHERE id = ?"+tx.ForUpdate(), id)
		if e != nil {
			return e
		}
		if old != nil && text(old["project_id"]) != project {
			return adminInvalid()
		}
		details := Object{"max_bytes": approval.MaxBytes, "max_files": approval.MaxFiles, "max_git_bytes": approval.MaxGitBytes, "max_git_files": approval.MaxGitFiles}
		if approval.MirrorPath != "" {
			resolved, e := filepath.EvalSymlinks(approval.MirrorPath)
			if e != nil {
				return adminInvalid()
			}
			details["mirror_path"] = resolved
		}
		return adminUpsert(ctx, tx, "jm_approved_sources", id, old, Object{"project_id": project, "url": approval.URL, "allowed_commits": commits, "enabled": enabled, "allowed_hosts": hosts, "status": status, "details_json": details})
	case "image-approve":
		if e = adminKeys(data, []string{"id", "digest"}, []string{"enabled", "project_id"}); e != nil {
			return e
		}
		digest, ok := data["digest"].(string)
		if !ok || !adminDigest.MatchString(digest) {
			return adminInvalid()
		}
		var project any
		if raw, exists := data["project_id"]; exists && raw != nil {
			p, e := adminID(raw)
			if e != nil {
				return e
			}
			if _, e = adminProject(ctx, tx, p, true); e != nil {
				return e
			}
			project = p
		}
		old, e := tx.One(ctx, "SELECT * FROM jm_runtime_images WHERE id = ?"+tx.ForUpdate(), id)
		if e != nil {
			return e
		}
		if old != nil && (text(old["digest"]) != digest || old["project_id"] != project) {
			return adminInvalid()
		}
		return adminUpsert(ctx, tx, "jm_runtime_images", id, old, Object{"digest": digest, "enabled": enabled, "approved": enabled, "status": status, "project_id": project})
	case "dataset-approve":
		if e = adminKeys(data, []string{"id", "project_id", "participant_id", "dataset_label"}, []string{"node_id", "enabled"}); e != nil {
			return e
		}
		project, e := adminID(data["project_id"])
		if e != nil {
			return e
		}
		if _, e = adminProject(ctx, tx, project, true); e != nil {
			return e
		}
		participant, e := adminID(data["participant_id"])
		if e != nil {
			return e
		}
		label, e := adminText(data["dataset_label"], 200)
		if e != nil {
			return e
		}
		var nodeID any
		if raw, exists := data["node_id"]; exists && raw != nil {
			n, e := adminID(raw)
			if e != nil {
				return e
			}
			nodeID = n
		}
		old, e := tx.One(ctx, "SELECT * FROM jm_participant_bindings WHERE id = ?"+tx.ForUpdate(), id)
		if e != nil {
			return e
		}
		if old != nil && text(old["project_id"]) != project {
			return adminInvalid()
		}
		return adminUpsert(ctx, tx, "jm_participant_bindings", id, old, Object{"project_id": project, "participant_id": participant, "dataset_label": label, "node_id": nodeID, "enabled": enabled})
	case "secret-ref-approve":
		if e = adminKeys(data, []string{"id", "project_id", "reference"}, []string{"enabled"}); e != nil {
			return e
		}
		project, e := adminID(data["project_id"])
		if e != nil {
			return e
		}
		if _, e = adminProject(ctx, tx, project, true); e != nil {
			return e
		}
		path, ok := data["reference"].(string)
		if !ok || !filepath.IsAbs(path) {
			return adminInvalid()
		}
		secret, e := secrets.ReadPrivateFile(path, 64*1024)
		if e != nil {
			return adminInvalid()
		}
		validSecret := len(secret) > 0 && utf8.Valid(secret)
		for i := range secret {
			secret[i] = 0
		}
		if !validSecret {
			return adminInvalid()
		}
		canonical, e := filepath.EvalSymlinks(path)
		if e != nil {
			return adminInvalid()
		}
		old, e := tx.One(ctx, "SELECT * FROM jm_secret_references WHERE id = ?"+tx.ForUpdate(), id)
		if e != nil {
			return e
		}
		if old != nil && text(old["project_id"]) != project {
			return adminInvalid()
		}
		return adminUpsert(ctx, tx, "jm_secret_references", id, old, Object{"project_id": project, "reference": canonical, "enabled": enabled})
	}
	return adminInvalid()
}
