package manager

import (
	"context"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/scheduler"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func creatorGrant(t *testing.T, m *Manager, who string, enabled bool) {
	t.Helper()
	if _, e := m.TrustedAdmin(context.Background(), adminActor(), "study-creator-set", Object{"principal": who, "enabled": enabled}); e != nil {
		t.Fatal(e)
	}
}
func exerciseStudyCreator(t *testing.T, m *Manager) {
	t.Helper()
	ctx := context.Background()
	if can, e := m.CanCreateStudy(ctx, "creator-a"); e != nil || can {
		t.Fatalf("default grant: %v %v", can, e)
	}
	if _, e := m.CreateStudy(ctx, "creator-a", Object{"name": "New study"}, "denied"); e == nil {
		t.Fatal("ordinary user created study")
	}
	if _, e := m.TrustedAdmin(ctx, "creator-a", "study-creator-set", Object{"principal": "creator-a", "enabled": true}); e == nil {
		t.Fatal("browser identity granted a role")
	}
	creatorGrant(t, m, "creator-a", true)
	if can, e := m.CanCreateStudy(ctx, "creator-a"); e != nil || !can {
		t.Fatalf("grant: %v %v", can, e)
	}
	v, e := m.CreateStudy(ctx, "creator-a", Object{"name": "New study"}, "create-first")
	if e != nil {
		t.Fatal(e)
	}
	id := text(v["id"])
	if id == "" || v["can_manage"] != true || v["registration_enabled"] != true || v["registration_open"] != false || number(v["version"]) != 1 {
		t.Fatalf("defaults %#v", v)
	}
	again, e := m.CreateStudy(ctx, "creator-a", Object{"name": "New study"}, "create-first")
	if e != nil || again["id"] != id {
		t.Fatalf("replay %#v %v", again, e)
	}
	if _, e = m.CreateStudy(ctx, "creator-a", Object{"name": "Different"}, "create-first"); e == nil {
		t.Fatal("same key accepted changed name")
	}
	if _, e = m.GetStudy(ctx, "ordinary", id); e == nil {
		t.Fatal("ordinary user read closed study")
	}
	creatorGrant(t, m, "creator-b", true)
	other, e := m.CreateStudy(ctx, "creator-b", Object{"name": "Other study"}, "other")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.PutStudySettings(ctx, "creator-a", text(other["id"]), "unauthorized", true, 1, "cross-study"); e == nil {
		t.Fatal("creator managed another creator's study")
	}
	if e = m.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		project, e := tx.One(ctx, "SELECT * FROM jm_projects WHERE id=?", id)
		if e != nil {
			return e
		}
		if number(project["retention_days"]) != 14 {
			t.Fatalf("retention %#v", project)
		}
		for _, k := range []string{"quota_cpu_millicores", "quota_memory_bytes", "quota_disk_bytes", "quota_gpus", "max_active_jobs"} {
			if project[k] == nil || number(project[k]) != 0 {
				t.Fatalf("legacy quota %s=%v", k, project[k])
			}
		}
		quota := obj(project["quotas_json"])
		for _, k := range []string{"cpu_millicores", "memory_bytes", "disk_bytes", "gpu_count", "max_running_jobs", "retained_bytes"} {
			if value, ok := quota[k]; !ok || number(value) != 0 {
				t.Fatalf("quota %s=%v", k, value)
			}
		}
		members, e := tx.All(ctx, "SELECT * FROM jm_project_members WHERE project_id=?", id)
		if e != nil {
			return e
		}
		if len(members) != 1 || members[0]["principal_id"] != "creator-a" || members[0]["role"] != "admin" {
			t.Fatalf("members %#v", members)
		}
		audits, e := tx.All(ctx, "SELECT * FROM jm_admin_audit WHERE resource_id=? AND operation='study.create'", id)
		if e != nil {
			return e
		}
		if len(audits) != 1 || audits[0]["actor_id"] != "creator-a" {
			t.Fatalf("audit %#v", audits)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	creatorGrant(t, m, "creator-a", false)
	if can, e := m.CanCreateStudy(ctx, "creator-a"); e != nil || can {
		t.Fatalf("revoke: %v %v", can, e)
	}
	for _, k := range []string{"after-revoke", "create-first"} {
		if _, e = m.CreateStudy(ctx, "creator-a", Object{"name": "New study"}, k); e == nil {
			t.Fatal("revoked session created or replayed study")
		}
	}
	retained, e := m.GetStudy(ctx, "creator-a", id)
	if e != nil || retained["can_manage"] != true {
		t.Fatalf("revocation lost existing membership %#v %v", retained, e)
	}
}
func TestStudyCreatorLifecycle(t *testing.T) { exerciseStudyCreator(t, adminFixture(t)) }
func TestStudyCreatorPostgresLifecycle(t *testing.T) {
	exerciseStudyCreator(t, newPostgresMgrFixture(t).m)
}

func TestStudyCreatorInputAndAtomicRollback(t *testing.T) {
	m := adminFixture(t)
	ctx := context.Background()
	creatorGrant(t, m, "creator", true)
	for _, request := range []Object{nil, {}, {"name": ""}, {"name": strings.Repeat("x", 201)}, {"name": "bad\nname"}, {"name": "study", "quota": Object{}}, {"name": "study", "id": "chosen"}, {"name": int64(1)}} {
		if _, e := m.CreateStudy(ctx, "creator", request, "invalid"); e == nil {
			t.Fatalf("accepted %#v", request)
		}
	}
	if _, e := m.CreateStudy(ctx, "creator", Object{"name": "study"}, ""); e == nil {
		t.Fatal("missing idempotency key accepted")
	}
	if _, e := m.DB.Exec(ctx, "CREATE TRIGGER fail_creator_audit BEFORE INSERT ON jm_admin_audit BEGIN SELECT RAISE(ABORT, 'forced audit failure'); END"); e != nil {
		t.Fatal(e)
	}
	if _, e := m.CreateStudy(ctx, "creator", Object{"name": "Must roll back"}, "rollback"); e == nil {
		t.Fatal("creation ignored audit failure")
	}
	if _, e := m.TrustedAdmin(ctx, adminActor(), "study-creator-set", Object{"principal": "ungranted", "enabled": true}); e == nil {
		t.Fatal("grant ignored audit failure")
	}
	if can, e := m.CanCreateStudy(ctx, "ungranted"); e != nil || can {
		t.Fatalf("grant survived audit failure %v %v", can, e)
	}
	if e := m.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		for _, table := range []string{"jm_projects", "jm_studies", "jm_project_members", "jm_idempotency"} {
			rows, e := tx.All(ctx, "SELECT * FROM "+table)
			if e != nil {
				return e
			}
			if len(rows) != 0 {
				t.Fatalf("partial %s %#v", table, rows)
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func exerciseCreatorConcurrentReplay(t *testing.T, m *Manager) {
	t.Helper()
	creatorGrant(t, m, "creator", true)
	ctx := context.Background()
	var wg sync.WaitGroup
	ids := make(chan string, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := m.CreateStudy(ctx, "creator", Object{"name": "One study"}, "same-key")
			if e != nil {
				errs <- e
				return
			}
			ids <- text(v["id"])
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	id := ""
	for got := range ids {
		if id == "" {
			id = got
		}
		if got != id {
			t.Fatalf("duplicate study %s %s", id, got)
		}
	}
	if id == "" {
		t.Fatal("no study created")
	}
}
func TestStudyCreatorConcurrentReplay(t *testing.T) {
	exerciseCreatorConcurrentReplay(t, adminFixture(t))
}
func TestStudyCreatorPostgresConcurrentReplay(t *testing.T) {
	exerciseCreatorConcurrentReplay(t, newPostgresMgrFixture(t).m)
}

func TestStudyCreatorZeroQuotaBlocksAdmission(t *testing.T) {
	f := newMgrFixture(t)
	creatorGrant(t, f.m, "creator", true)
	ctx := context.Background()
	study, e := f.m.CreateStudy(ctx, "creator", Object{"name": "No capacity"}, "zero-quota")
	if e != nil {
		t.Fatal(e)
	}
	spec := mgrSpec()
	spec.ProjectID = text(study["id"])
	if e = f.db.WithTx(ctx, false, func(tx *store.Tx) error { return scheduler.ValidateAdmission(ctx, tx, spec) }); e == nil || !strings.Contains(e.Error(), "resource_request_exceeds_project_quota") {
		t.Fatalf("zero quota did not block admission: %v", e)
	}
}

func TestStudyCreatorZeroQuotaBlocksRetainedStorage(t *testing.T) {
	m := adminFixture(t)
	creatorGrant(t, m, "creator", true)
	ctx := context.Background()
	study, e := m.CreateStudy(ctx, "creator", Object{"name": "No storage"}, "zero-storage")
	if e != nil {
		t.Fatal(e)
	}
	e = m.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		project, e := tx.One(ctx, "SELECT * FROM jm_projects WHERE id=?", study["id"])
		if e != nil {
			return e
		}
		return scheduler.ReserveStorage(ctx, tx, Object{"id": "unused", "state": "created", "kind": "source", "details_json": Object{}}, project, 1, nil)
	})
	if e == nil || !strings.Contains(e.Error(), "retained_storage_quota_exceeded") {
		t.Fatalf("zero quota allowed retained bytes: %v", e)
	}
}

// Hold the audit table to pause the actual revocation after its role update.
// A concurrent creator must wait for that transaction and then observe denial.
func TestStudyCreatorPostgresRevocationOrdersCreation(t *testing.T) {
	f := newPostgresMgrFixture(t)
	m := f.m
	creatorGrant(t, m, "creator", true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	revoked := make(chan error, 1)
	created := make(chan error, 1)
	e := m.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "LOCK TABLE jm_admin_audit IN SHARE MODE"); e != nil {
			return e
		}
		go func() {
			_, e := m.TrustedAdmin(ctx, adminActor(), "study-creator-set", Object{"principal": "creator", "enabled": false})
			revoked <- e
		}()
		deadline := time.Now().Add(4 * time.Second)
		for {
			var waiting bool
			if e := m.DB.WithTx(ctx, false, func(probe *store.Tx) error {
				row, e := probe.One(ctx, "SELECT 1 AS waiting FROM pg_locks WHERE relation='jm_admin_audit'::regclass AND NOT granted LIMIT 1")
				waiting = row != nil
				return e
			}); e != nil {
				return e
			}
			if waiting {
				break
			}
			if time.Now().After(deadline) {
				t.Error("revocation never reached transactional audit")
				return context.DeadlineExceeded
			}
			time.Sleep(10 * time.Millisecond)
		}
		go func() {
			_, e := m.CreateStudy(ctx, "creator", Object{"name": "Racing with revoke"}, "racing-revoke")
			created <- e
		}()
		deadline = time.Now().Add(4 * time.Second)
		for {
			var waiting bool
			if e := m.DB.WithTx(ctx, false, func(probe *store.Tx) error {
				row, e := probe.One(ctx, "SELECT 1 AS waiting FROM pg_stat_activity WHERE datname=current_database() AND query LIKE 'SELECT enabled FROM jm_study_creators%' AND wait_event_type='Lock' LIMIT 1")
				waiting = row != nil
				return e
			}); e != nil {
				return e
			}
			if waiting {
				break
			}
			if time.Now().After(deadline) {
				t.Error("creation did not wait for role lock")
				return context.DeadlineExceeded
			}
			time.Sleep(10 * time.Millisecond)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-revoked:
		if e != nil {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal("revocation timed out")
	}
	select {
	case e := <-created:
		if e == nil || !strings.Contains(e.Error(), "study_creator_required") {
			t.Fatalf("creation bypassed revocation: %v", e)
		}
	case <-ctx.Done():
		t.Fatal("creation timed out")
	}
}
