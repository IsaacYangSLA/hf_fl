package artifacts

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

type testDB struct {
	db                             *store.DB
	job, attempt, pool, allocation map[string]any
	now                            time.Time
}

func newTestDB(t *testing.T) *testDB {
	t.Helper()
	ctx := context.Background()
	db, e := store.Open(ctx, "sqlite:///"+filepath.Join(t.TempDir(), "manager.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if _, e = db.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 10, 23, 12, 34, 56, 123400000, time.UTC)
	spec, e := domain.DecodeJobSpec([]byte(`{"project_id":"research","name":"Images","source_id":"approved","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","runtime_image":"cpu","plugin":"lenet","participants":[{"participant_id":"alice","dataset_binding":"alice-data"},{"participant_id":"bob","dataset_binding":"bob-data"}],"components":[{"component_id":"owner","role":"owner","resources":{"pool_id":"cpu","cpu_millicores":1000,"memory_bytes":1048576,"disk_bytes":1024}}],"target_round":3,"max_duration_seconds":3600}`))
	if e != nil {
		t.Fatal(e)
	}
	hash, e := spec.Digest()
	if e != nil {
		t.Fatal(e)
	}
	f := &testDB{db: db, now: now}
	e = db.WithTx(ctx, true, func(tx *store.Tx) error {
		rows := []struct {
			table string
			value map[string]any
		}{
			{"jm_projects", map[string]any{"id": "research", "name": "Research", "retention_days": 7, "quotas_json": map[string]any{"retained_bytes": int64(1 << 30)}, "created_at": now}},
			{"jm_pools", map[string]any{"id": "cpu", "name": "CPU", "node_id": "node-a", "cpu_millicores": int64(4000), "memory_bytes": int64(1 << 30), "disk_bytes": int64(1 << 30), "healthy": true, "sandbox_profiles": []string{"runsc-cpu-v1"}, "created_at": now, "updated_at": now}},
			{"jm_jobs", map[string]any{"id": "job-a", "project_id": "research", "creator_id": "owner", "name": "Images", "spec_json": spec.Map(), "spec_hash": hash, "state": "RUNNING", "phase": "training", "target_round": int64(3), "current_attempt": int64(1), "attempt_count": int64(1), "epoch": int64(1), "created_at": now, "updated_at": now}},
			{"jm_attempts", map[string]any{"id": "attempt-a", "job_id": "job-a", "number": int64(1), "epoch": int64(1), "state": "RUNNING", "created_at": now}},
			{"jm_allocations", map[string]any{"id": "allocation-a", "job_id": "job-a", "attempt_id": "attempt-a", "component_id": "owner", "pool_id": "cpu", "cpu_millicores": int64(1000), "memory_bytes": int64(1 << 20), "disk_bytes": int64(1024), "epoch": int64(1), "state": "RUNNING", "created_at": now}},
			{"jm_job_members", map[string]any{"job_id": "job-a", "principal_id": "owner", "role": "admin", "created_at": now}},
		}
		for _, r := range rows {
			if e := tx.Insert(ctx, r.table, r.value); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	f.refresh(t)
	return f
}
func (f *testDB) refresh(t *testing.T) {
	t.Helper()
	var e error
	f.job, e = f.db.One(context.Background(), "SELECT * FROM jm_jobs WHERE id = ?", "job-a")
	if e != nil {
		t.Fatal(e)
	}
	f.attempt, e = f.db.One(context.Background(), "SELECT * FROM jm_attempts WHERE id = ?", "attempt-a")
	if e != nil {
		t.Fatal(e)
	}
	f.pool, e = f.db.One(context.Background(), "SELECT * FROM jm_pools WHERE id = ?", "cpu")
	if e != nil {
		t.Fatal(e)
	}
	f.allocation, e = f.db.One(context.Background(), "SELECT * FROM jm_allocations WHERE id = ?", "allocation-a")
	if e != nil {
		t.Fatal(e)
	}
}
func (f *testDB) resource(t *testing.T, id, kind, external string, details map[string]any) map[string]any {
	t.Helper()
	r := map[string]any{"id": id, "job_id": "job-a", "attempt_id": "attempt-a", "component_id": "owner", "kind": kind, "external_id": external, "ownership_json": map[string]any{"job_id": "job-a", "attempt_id": "attempt-a", "component_id": "owner", "epoch": int64(1)}, "details_json": details, "state": "owned", "retained": true, "size_bytes": int64(0), "created_at": f.now, "updated_at": f.now}
	if e := f.db.WithTx(context.Background(), true, func(tx *store.Tx) error { return tx.Insert(context.Background(), "jm_provisioning_resources", r) }); e != nil {
		t.Fatal(e)
	}
	return r
}
func (f *testDB) update(t *testing.T, table string, where, values map[string]any) {
	t.Helper()
	if e := f.db.WithTx(context.Background(), true, func(tx *store.Tx) error { return tx.Update(context.Background(), table, where, values) }); e != nil {
		t.Fatal(e)
	}
}
func row(t *testing.T, db *store.DB, table, id string) map[string]any {
	t.Helper()
	r, e := db.One(context.Background(), "SELECT * FROM "+table+" WHERE id = ?", id)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func requireCode(t *testing.T, e error, code string) {
	t.Helper()
	var d *domain.Error
	if !errors.As(e, &d) || d.Code != code {
		t.Fatalf("expected %s, got %v", code, e)
	}
}
