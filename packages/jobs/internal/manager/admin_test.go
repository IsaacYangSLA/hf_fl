package manager

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func adminFixture(t *testing.T) *Manager {
	t.Helper()
	db, e := store.Open(context.Background(), "sqlite:///"+filepath.Join(t.TempDir(), "admin.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if _, e = db.Migrate(context.Background()); e != nil {
		t.Fatal(e)
	}
	m, e := New(db, []byte(strings.Repeat("c", 32)))
	if e != nil {
		t.Fatal(e)
	}
	m.Clock = func() time.Time { return time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC) }
	return m
}
func adminActor() string { return fmt.Sprintf("unix:%d", os.Getuid()) }
func adminCall(t *testing.T, m *Manager, operation string, values Object) Object {
	t.Helper()
	out, e := m.TrustedAdmin(context.Background(), adminActor(), operation, values)
	if e != nil {
		t.Fatalf("%s: %v", operation, e)
	}
	if out["status"] != "ok" {
		t.Fatalf("result %#v", out)
	}
	return out
}
func adminRead(t *testing.T, m *Manager, table, id string) Object {
	t.Helper()
	row, e := m.DB.One(context.Background(), "SELECT * FROM "+table+" WHERE id = ?", id)
	if e != nil {
		t.Fatal(e)
	}
	return row
}
func adminCreateProject(t *testing.T, m *Manager, id string) {
	t.Helper()
	adminCall(t, m, "project-create", Object{"id": id, "name": "Research", "quota": Object{}})
}
func adminCPU(id string) Object {
	return Object{"id": id, "name": "CPU", "node_id": "node-a", "cpu_millicores": int64(6000), "memory_bytes": int64(12 << 30), "disk_bytes": int64(32 << 30), "sandbox_profiles": []string{"runsc-cpu-v1"}}
}

func TestAdminProjectPolicyAndMembership(t *testing.T) {
	m := adminFixture(t)
	ctx := context.Background()
	adminCall(t, m, "project-create", Object{"id": "research", "name": "Research", "quota": Object{"cpu_millicores": int64(6000), "max_running_jobs": int64(2)}})
	row := adminRead(t, m, "jm_projects", "research")
	if number(row["version"]) != 1 || number(row["retention_days"]) != 90 {
		t.Fatalf("defaults %#v", row)
	}
	adminCall(t, m, "project-member", Object{"project": "research", "principal": "alice", "role": "submitter"})
	member, e := m.DB.One(ctx, "SELECT * FROM jm_project_members WHERE project_id = ? AND principal_id = ?", "research", "alice")
	if e != nil || text(member["role"]) != "submitter" {
		t.Fatalf("membership %#v %v", member, e)
	}
	adminCall(t, m, "project-member", Object{"project": "research", "principal": "alice", "role": "admin"})
	adminCall(t, m, "project-member", Object{"project": "research", "principal": "alice", "role": "remove"})
	member, e = m.DB.One(ctx, "SELECT * FROM jm_project_members WHERE project_id = ? AND principal_id = ?", "research", "alice")
	if e != nil || member != nil {
		t.Fatalf("remove %#v %v", member, e)
	}
	adminCall(t, m, "project-update", Object{"id": "research", "name": "Changed", "retention_days": int64(14), "quota": Object{"retained_bytes": int64(1 << 30)}})
	row = adminRead(t, m, "jm_projects", "research")
	if text(row["name"]) != "Changed" || number(row["version"]) != 2 || number(row["retention_days"]) != 14 || row["quota_cpu_millicores"] != nil {
		t.Fatalf("replacement %#v", row)
	}
	audits, e := m.DB.All(ctx, "SELECT * FROM jm_admin_audit ORDER BY created_at,id")
	if e != nil || len(audits) != 2 {
		t.Fatalf("audit %#v %v", audits, e)
	}
	for _, a := range audits {
		if text(a["actor_id"]) != adminActor() || text(a["resource_type"]) != "project" {
			t.Fatalf("audit identity %#v", a)
		}
	}
	invalid := []Object{{"id": "research"}, {"id": "research", "quota": Object{"unknown": int64(1)}}, {"id": "research", "retention_days": 1.0}, {"id": "research", "name": "\x7fcontrol"}}
	for _, v := range invalid {
		if _, e = m.TrustedAdmin(ctx, adminActor(), "project-update", v); e == nil {
			t.Fatalf("accepted %#v", v)
		}
	}
	if _, e = m.TrustedAdmin(ctx, "human-owner", "project-update", Object{"id": "research", "name": "No"}); e == nil {
		t.Fatal("human identity accepted as local admin")
	}
	if number(adminRead(t, m, "jm_projects", "research")["version"]) != 2 {
		t.Fatal("invalid update changed project")
	}
}

func adminAllocation(t *testing.T, m *Manager, project, pool, jobID, component string, cpu, memory, disk int64) {
	t.Helper()
	ctx := context.Background()
	e := m.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?", jobID)
		if e != nil {
			return e
		}
		if job == nil {
			if e = tx.Insert(ctx, "jm_jobs", Object{"id": jobID, "project_id": project, "creator_id": "creator", "name": "Existing", "spec_json": Object{}, "spec_hash": strings.Repeat("a", 64), "target_round": int64(2), "current_attempt": int64(1), "epoch": int64(1)}); e != nil {
				return e
			}
		}
		attemptID := "attempt-" + jobID
		attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id = ?", attemptID)
		if e != nil {
			return e
		}
		if attempt == nil {
			if e = tx.Insert(ctx, "jm_attempts", Object{"id": attemptID, "job_id": jobID, "number": int64(1), "epoch": int64(1)}); e != nil {
				return e
			}
		}
		return tx.Insert(ctx, "jm_allocations", Object{"job_id": jobID, "attempt_id": attemptID, "component_id": component, "pool_id": pool, "cpu_millicores": cpu, "memory_bytes": memory, "disk_bytes": disk, "epoch": int64(1)})
	})
	if e != nil {
		t.Fatal(e)
	}
}
func TestAdminQuotaCannotShrinkBelowAdmittedOrRetainedUsage(t *testing.T) {
	m := adminFixture(t)
	ctx := context.Background()
	adminCreateProject(t, m, "research")
	adminCall(t, m, "pool-set", adminCPU("cpu"))
	adminAllocation(t, m, "research", "cpu", "job-a", "owner", 1000, 2048, 4096)
	adminAllocation(t, m, "research", "cpu", "job-a", "alice", 1000, 2048, 4096)
	if e := m.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		return tx.Update(ctx, "jm_projects", Object{"id": "research"}, Object{"retained_bytes": int64(128)})
	}); e != nil {
		t.Fatal(e)
	}
	for key, limit := range map[string]int64{"cpu_millicores": 1999, "memory_bytes": 4095, "disk_bytes": 8191, "retained_bytes": 127, "max_running_jobs": 0} {
		if _, e := m.TrustedAdmin(ctx, adminActor(), "project-update", Object{"id": "research", "quota": Object{key: limit}}); e == nil {
			t.Fatalf("accepted shrinking %s", key)
		}
	}
	// The two components occupy one admitted job, not two job slots.
	adminCall(t, m, "project-update", Object{"id": "research", "quota": Object{"max_running_jobs": int64(1), "cpu_millicores": int64(2000), "memory_bytes": int64(4096), "disk_bytes": int64(8192), "retained_bytes": int64(128)}})
	if number(adminRead(t, m, "jm_projects", "research")["version"]) != 2 {
		t.Fatal("rejected quota changes were persisted")
	}
}

func TestAdminCPUQualificationAndActivePoolGuards(t *testing.T) {
	m := adminFixture(t)
	ctx := context.Background()
	data := adminCPU("cpu")
	data["healthy"] = true
	if _, e := m.TrustedAdmin(ctx, adminActor(), "pool-set", data); e == nil {
		t.Fatal("healthy registration without qualifier")
	}
	if adminRead(t, m, "jm_pools", "cpu") != nil {
		t.Fatal("failed qualification left pool")
	}
	called := 0
	m.PoolQualifier = func(_ context.Context, _ Object) (bool, error) { called++; return true, nil }
	adminCall(t, m, "pool-set", data)
	if called != 1 {
		t.Fatal("qualification skipped")
	}
	adminCreateProject(t, m, "research")
	adminAllocation(t, m, "research", "cpu", "job-a", "owner", 1000, 1024, 4096)
	for key, value := range map[string]any{"cpu_millicores": int64(999), "memory_bytes": int64(1023), "disk_bytes": int64(4095), "node_id": "other-node", "gpu_uuids": []string{"gpu-a"}, "sandbox_profiles": []string{"plain-docker"}} {
		invalid := copyObject(data)
		invalid[key] = value
		if _, e := m.TrustedAdmin(ctx, adminActor(), "pool-set", invalid); e == nil {
			t.Fatalf("accepted invalid pool %s", key)
		}
	}
	quarantined := copyObject(data)
	quarantined["quarantined"] = true
	adminCall(t, m, "pool-set", quarantined)
	if _, e := m.TrustedAdmin(ctx, adminActor(), "pool-set", data); e == nil {
		t.Fatal("unquarantined live allocations")
	}
	if number(adminRead(t, m, "jm_pools", "cpu")["version"]) != 2 {
		t.Fatal("rejected pool changes changed state")
	}
}
func TestAdminManagerStorageIdentityAndDuplicateBacking(t *testing.T) {
	m := adminFixture(t)
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "private")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	m.AdminPolicy = &AdminPolicy{StoragePoolID: "storage", StorageRoot: root}
	data := Object{"id": "storage", "name": "Source files", "node_id": "manager", "disk_bytes": int64(1 << 20)}
	adminCall(t, m, "storage-pool-set", data)
	row := adminRead(t, m, "jm_pools", "storage")
	if !flag(row["healthy"]) || number(row["cpu_millicores"]) != 0 || !flag(obj(row["details_json"])["manager_storage"]) {
		t.Fatalf("storage %#v", row)
	}
	m.AdminPolicy.StoragePoolID = "second"
	duplicate := copyObject(data)
	duplicate["id"] = "second"
	if _, e := m.TrustedAdmin(ctx, adminActor(), "storage-pool-set", duplicate); e == nil {
		t.Fatal("same backing filesystem advertised twice")
	}
	// A substituted root inode cannot update the original approval.
	m.AdminPolicy.StoragePoolID = "storage"
	if e := os.Rename(root, root+"-old"); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := m.TrustedAdmin(ctx, adminActor(), "storage-pool-set", data); e == nil {
		t.Fatal("replacement root accepted")
	}
	m.AdminPolicy.StorageRoot = root + "-link"
	if e := os.Symlink(root, m.AdminPolicy.StorageRoot); e != nil {
		t.Fatal(e)
	}
	if _, e := m.TrustedAdmin(ctx, adminActor(), "storage-pool-set", data); e == nil {
		t.Fatal("symlink storage root accepted")
	}
	if number(adminRead(t, m, "jm_pools", "storage")["version"]) != 1 {
		t.Fatal("failed ownership checks persisted")
	}
}
func TestAdminObjectStoreRegistrationBoundToQualifiedIdentity(t *testing.T) {
	m := adminFixture(t)
	ctx := context.Background()
	id := "objects"
	binding := Object{"object_store": true, "registration_id": "approved", "backend_id": strings.Repeat("a", 64), "locator_id": strings.Repeat("b", 64), "capacity_bound_bytes": int64(1024), "node_id": "object-store-fixed"}
	m.AdminPolicy = &AdminPolicy{QualifyObjectStore: func(context.Context) (string, Object, error) { return id, copyObject(binding), nil }}
	data := Object{"id": "objects", "name": "Model storage", "disk_bytes": int64(512)}
	adminCall(t, m, "object-store-pool-set", data)
	oversized := copyObject(data)
	oversized["disk_bytes"] = int64(1025)
	if _, e := m.TrustedAdmin(ctx, adminActor(), "object-store-pool-set", oversized); e == nil {
		t.Fatal("exceeded approved object allocation")
	}
	id = "other"
	duplicate := copyObject(data)
	duplicate["id"] = "other"
	if _, e := m.TrustedAdmin(ctx, adminActor(), "object-store-pool-set", duplicate); e == nil {
		t.Fatal("same bucket/prefix advertised twice")
	}
	id = "objects"
	binding["backend_id"] = strings.Repeat("c", 64)
	if _, e := m.TrustedAdmin(ctx, adminActor(), "object-store-pool-set", data); e == nil {
		t.Fatal("changed backend identity accepted")
	}
	cpu := adminCPU("objects")
	if _, e := m.TrustedAdmin(ctx, adminActor(), "pool-set", cpu); e == nil {
		t.Fatal("storage reclassified as compute")
	}
	if number(adminRead(t, m, "jm_pools", "objects")["version"]) != 1 {
		t.Fatal("failed backend changes persisted")
	}
}

func TestAdminCatalogBindingsRemainImmutableAcrossProjects(t *testing.T) {
	m := adminFixture(t)
	ctx := context.Background()
	adminCreateProject(t, m, "research")
	adminCreateProject(t, m, "other")
	mirror := t.TempDir()
	source := Object{"id": "source", "project_id": "research", "allowed_commits": []string{strings.Repeat("a", 40)}, "mirror_path": mirror}
	adminCall(t, m, "source-approve", source)
	wrongType := copyObject(source)
	wrongType["url"] = false
	if _, e := m.TrustedAdmin(ctx, adminActor(), "source-approve", wrongType); e == nil {
		t.Fatal("non-string source URL ignored")
	}
	move := copyObject(source)
	move["project_id"] = "other"
	if _, e := m.TrustedAdmin(ctx, adminActor(), "source-approve", move); e == nil {
		t.Fatal("source moved projects")
	}
	invalid := copyObject(source)
	invalid["allowed_commits"] = []string{strings.Repeat("A", 40)}
	if _, e := m.TrustedAdmin(ctx, adminActor(), "source-approve", invalid); e == nil {
		t.Fatal("noncanonical source commit accepted")
	}
	image := Object{"id": "image", "project_id": "research", "digest": "sha256:" + strings.Repeat("a", 64)}
	adminCall(t, m, "image-approve", image)
	changed := copyObject(image)
	changed["digest"] = "sha256:" + strings.Repeat("b", 64)
	if _, e := m.TrustedAdmin(ctx, adminActor(), "image-approve", changed); e == nil {
		t.Fatal("image digest replaced")
	}
	changed = copyObject(image)
	changed["project_id"] = "other"
	if _, e := m.TrustedAdmin(ctx, adminActor(), "image-approve", changed); e == nil {
		t.Fatal("image moved projects")
	}
	dataset := Object{"id": "dataset", "project_id": "research", "participant_id": "alice", "dataset_label": "Local images", "node_id": "node-a"}
	adminCall(t, m, "dataset-approve", dataset)
	changed = copyObject(dataset)
	changed["project_id"] = "other"
	if _, e := m.TrustedAdmin(ctx, adminActor(), "dataset-approve", changed); e == nil {
		t.Fatal("dataset moved projects")
	}
	disabled := copyObject(image)
	disabled["enabled"] = false
	adminCall(t, m, "image-approve", disabled)
	if flag(adminRead(t, m, "jm_runtime_images", "image")["approved"]) {
		t.Fatal("disabled image still approved")
	}
}
func TestAdminSourceApprovalUsesFixedHostsAndPublicAddresses(t *testing.T) {
	m := adminFixture(t)
	ctx := context.Background()
	adminCreateProject(t, m, "research")
	m.AdminPolicy = &AdminPolicy{AllowedSourceHosts: []string{"code.example"}, SourceResolver: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.8")}, nil }}
	data := Object{"id": "source", "project_id": "research", "allowed_commits": []string{strings.Repeat("a", 40)}, "url": "https://code.example/repo.git"}
	adminCall(t, m, "source-approve", data)
	for _, url := range []string{"http://code.example/repo.git", "https://other.example/repo.git", "https://token@code.example/repo.git", "https://code.example/repo.git?credential=secret"} {
		invalid := copyObject(data)
		invalid["url"] = url
		if _, e := m.TrustedAdmin(ctx, adminActor(), "source-approve", invalid); e == nil {
			t.Fatalf("unsafe URL %q", url)
		}
	}
	m.AdminPolicy.SourceResolver = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("127.0.0.1")}, nil }
	if _, e := m.TrustedAdmin(ctx, adminActor(), "source-approve", data); e == nil {
		t.Fatal("private source address accepted")
	}
}
func TestAdminSecretReferenceValidatesPrivateSingleOwnedFile(t *testing.T) {
	m := adminFixture(t)
	ctx := context.Background()
	adminCreateProject(t, m, "research")
	path := filepath.Join(t.TempDir(), "secret")
	if e := os.Chmod(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte("private-value"), 0600); e != nil {
		t.Fatal(e)
	}
	data := Object{"id": "secret", "project_id": "research", "reference": path}
	adminCall(t, m, "secret-ref-approve", data)
	for _, invalid := range [][]byte{{}, {0xff}} {
		if e := os.WriteFile(path, invalid, 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := m.TrustedAdmin(ctx, adminActor(), "secret-ref-approve", data); e == nil {
			t.Fatal("empty or binary secret accepted")
		}
	}
	if e := os.WriteFile(path, []byte("private-value"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := m.TrustedAdmin(ctx, adminActor(), "secret-ref-approve", data); e == nil {
		t.Fatal("public secret file accepted")
	}
	if e := os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	link := path + "-link"
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	invalid := copyObject(data)
	invalid["reference"] = link
	if _, e := m.TrustedAdmin(ctx, adminActor(), "secret-ref-approve", invalid); e == nil {
		t.Fatal("secret symlink accepted")
	}
	if e := os.Link(path, path+"-hard"); e != nil {
		t.Fatal(e)
	}
	if _, e := m.TrustedAdmin(ctx, adminActor(), "secret-ref-approve", data); e == nil {
		t.Fatal("multiply-linked secret accepted")
	}
}
func TestAdminAuditDropsUnknownDataAndMutationIsAtomic(t *testing.T) {
	m := adminFixture(t)
	ctx := context.Background()
	e := m.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		return RecordAdminAudit(ctx, tx, adminActor(), "project-create", "project", "opaque", nil, Object{"name": "Safe", "reference": "/private/secret", "access_token": "hidden", "unknown": Object{"credential": "hidden"}}, m.now())
	})
	if e != nil {
		t.Fatal(e)
	}
	row, e := m.DB.One(ctx, "SELECT * FROM jm_admin_audit")
	if e != nil {
		t.Fatal(e)
	}
	after := obj(row["after_json"])
	if len(after) != 1 || text(after["name"]) != "Safe" {
		t.Fatalf("unsafe audit %#v", after)
	}
	e = m.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		return tx.Update(ctx, "jm_admin_audit", Object{"id": row["id"]}, Object{"operation": "rewritten"})
	})
	if e == nil {
		t.Fatal("audit update allowed")
	}
	if _, e = m.TrustedAdmin(ctx, adminActor(), "project-create", Object{"id": "unsafe", "name": "Bearer secret", "quota": Object{}}); e == nil {
		t.Fatal("credential audit text accepted")
	}
	if adminRead(t, m, "jm_projects", "unsafe") != nil {
		t.Fatal("audit rejection did not roll back mutation")
	}
}
