package artifacts

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func TestRetentionReservesBeforeBytesAndOnlyReleasesConfirmedDeletion(t *testing.T) {
	f := newTestDB(t)
	f.resource(t, "copy-a", "source_snapshot", "owned-source", map[string]any{"pool_id": "cpu"})
	r := NewRetention(f.db)
	r.Clock = func() time.Time { return f.now }
	ctx := context.Background()
	changed, e := r.ReserveResource(ctx, "copy-a", "job-a", 4096)
	if e != nil || !changed {
		t.Fatal(e)
	}
	if changed, e = r.ReserveResource(ctx, "copy-a", "job-a", 4096); e != nil || changed {
		t.Fatal("reservation replay changed quota", e)
	}
	if _, e = r.ReserveResource(ctx, "copy-a", "job-a", 2048); e == nil {
		t.Fatal("changed immutable reservation")
	}
	if _, e = r.SettleResource(ctx, "copy-a", "job-a", 4097); e == nil {
		t.Fatal("copy exceeded prepaid bound")
	}
	if changed, e = r.SettleResource(ctx, "copy-a", "job-a", 7); e != nil || !changed {
		t.Fatal(e)
	}
	if amount := integer(row(t, f.db, "jm_projects", "research")["retained_bytes"]); amount != 7 {
		t.Fatalf("charged %d", amount)
	}
	if _, e = r.ConfirmResourceDeleted(ctx, "copy-a", "job-a"); e == nil {
		t.Fatal("released live raw data")
	}
	if amount := integer(row(t, f.db, "jm_projects", "research")["retained_bytes"]); amount != 7 {
		t.Fatal("failed confirmation released bytes")
	}
	f.update(t, "jm_provisioning_resources", map[string]any{"id": "copy-a"}, map[string]any{"state": "deleted", "deleted_at": f.now})
	if changed, e = r.ConfirmResourceDeleted(ctx, "copy-a", "job-a"); e != nil || !changed {
		t.Fatal(e)
	}
	if changed, e = r.ConfirmResourceDeleted(ctx, "copy-a", "job-a"); e != nil || changed {
		t.Fatal("double release", e)
	}
	if amount := integer(row(t, f.db, "jm_projects", "research")["retained_bytes"]); amount != 0 {
		t.Fatal("quota not released")
	}
}
func TestRetentionRejectsForeignResourceAndRollsBackQuotaFailure(t *testing.T) {
	f := newTestDB(t)
	ctx := context.Background()
	f.resource(t, "resource-a", "source_snapshot", "copy", map[string]any{"pool_id": "cpu"})
	r := NewRetention(f.db)
	if _, e := r.ReserveResource(ctx, "resource-a", "foreign-job", 10); e == nil {
		t.Fatal("adopted foreign resource")
	}
	f.update(t, "jm_projects", map[string]any{"id": "research"}, map[string]any{"quotas_json": map[string]any{"retained_bytes": int64(5)}})
	if _, e := r.ReserveResource(ctx, "resource-a", "job-a", 6); e == nil {
		t.Fatal("oversubscribed project retained quota")
	}
	if n := integer(row(t, f.db, "jm_projects", "research")["retained_bytes"]); n != 0 {
		t.Fatal("quota failure partially committed")
	}
	if _, exists := mapping(row(t, f.db, "jm_provisioning_resources", "resource-a")["details_json"])["retention_charged_bytes"]; exists {
		t.Fatal("failed reservation marked charged")
	}
}
func TestRetentionExpirySkipsActiveAndUsesPythonMicrosecondKey(t *testing.T) {
	f := newTestDB(t)
	ctx := context.Background()
	expiry := f.now.Add(-time.Hour)
	f.update(t, "jm_jobs", map[string]any{"id": "job-a"}, map[string]any{"state": "SUCCEEDED", "terminated_at": expiry, "artifacts_expire_at": expiry})
	r := NewRetention(f.db)
	r.Clock = func() time.Time { return f.now }
	ids, e := r.RequestExpiry(ctx)
	if e != nil || len(ids) != 0 {
		t.Fatal("expired active allocation", ids, e)
	}
	f.update(t, "jm_allocations", map[string]any{"id": "allocation-a"}, map[string]any{"state": "RELEASED", "released_at": f.now, "termination_confirmed": true})
	ids, e = r.RequestExpiry(ctx)
	if e != nil || len(ids) != 1 {
		t.Fatal(ids, e)
	}
	rows, e := f.db.All(ctx, "SELECT * FROM jm_outbox")
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	if text(rows[0]["idempotency_key"]) != "retention:job-a:2026-10-23T11:34:56.123400Z" {
		t.Fatalf("incompatible Python expiry operation key %q", rows[0]["idempotency_key"])
	}
	if ids, e = r.RequestExpiry(ctx); e != nil || len(ids) != 0 {
		t.Fatal("replayed deletion intent", ids, e)
	}
	if _, e = r.RequestExpiry(ctx, 0); e == nil {
		t.Fatal("unbounded expiry scan")
	}
}
func TestPrepaidLogsNeverBorrowOtherReservations(t *testing.T) {
	f := newTestDB(t)
	ctx := context.Background()
	budget := map[string]any{"id": "log-budget", "job_id": "job-a", "attempt_id": "attempt-a", "component_id": "owner", "kind": "log_budget", "external_id": "hf2l-log://job-a/1/owner", "ownership_json": map[string]any{"job_id": "job-a", "component_id": "owner", "kind": "log_budget"}, "details_json": map[string]any{"attempt_number": int64(1), "component_id": "owner", "retention_reservation_bytes": int64(10), "retention_charged_bytes": int64(10), "retention_charge_released": false, "retention_charge_settled": false}, "state": "owned", "retained": true, "size_bytes": int64(10)}
	if e := f.db.WithTx(ctx, true, func(tx *store.Tx) error { return tx.Insert(ctx, "jm_provisioning_resources", budget) }); e != nil {
		t.Fatal(e)
	}
	f.update(t, "jm_projects", map[string]any{"id": "research"}, map[string]any{"retained_bytes": int64(10)})
	f.update(t, "jm_allocations", map[string]any{"id": "allocation-a"}, map[string]any{"details_json": map[string]any{"log_resource_id": "log-budget"}})
	id := LogIdentity{"job-a", "attempt-a", "owner", 1}
	service := &LogService{DB: f.db, Clock: func() time.Time { return f.now }, ReadLogs: func(_ context.Context, _ LogIdentity, offset, max int64) (LogReceipt, error) {
		return LogReceipt{id, id.Key(), 0, 12, "abcdefghijkl", true, false}, nil
	}}
	result, e := service.IngestComponentLogs(ctx, "allocation-a", true, 32)
	if e != nil || result.Bytes != 10 || !result.Truncated || result.Status != "limit_reached" {
		t.Fatal(result, e)
	}
	rows, e := f.db.All(ctx, "SELECT * FROM jm_log_chunks")
	if e != nil || len(rows) != 1 || text(rows[0]["data"]) != "abcdefghij" || integer(rows[0]["charged_bytes"]) != 0 {
		t.Fatal(rows, e)
	}
	if integer(row(t, f.db, "jm_projects", "research")["retained_bytes"]) != 10 {
		t.Fatal("prepaid output charged twice")
	}
}
func TestExternalLogReceiptsBindNodeEpochAndDeduplicate(t *testing.T) {
	f := newTestDB(t)
	ctx := context.Background()
	id := LogIdentity{"job-a", "attempt-a", "external-alice", 1}
	resource := f.resource(t, "external-a", "external_execution", id.Key(), map[string]any{"node_id": "node-a", "epoch": int64(1)})
	f.update(t, "jm_provisioning_resources", map[string]any{"id": resource["id"]}, map[string]any{"component_id": "external-alice", "ownership_json": map[string]any{"job_id": "job-a", "attempt_id": "attempt-a", "component_id": "external-alice", "epoch": int64(1)}})
	service := &LogService{DB: f.db, Clock: func() time.Time { return f.now }}
	receipt := LogReceipt{id, id.Key(), 0, 6, "hello\n", true, false}
	result, e := service.AppendExternalLogs(ctx, id, receipt, "external-a", "node-a")
	if e != nil || integer(result["next_offset"]) != 6 {
		t.Fatal(result, e)
	}
	if _, e = service.AppendExternalLogs(ctx, id, receipt, "external-a", "node-a"); e != nil {
		t.Fatal(e)
	}
	if _, e = service.AppendExternalLogs(ctx, id, receipt, "external-a", "foreign-node"); e == nil {
		t.Fatal("accepted foreign node")
	}
	rows, e := f.db.All(ctx, "SELECT * FROM jm_log_chunks")
	if e != nil || len(rows) != 1 {
		t.Fatal("receipt duplicated", rows, e)
	}
	if integer(row(t, f.db, "jm_projects", "research")["retained_bytes"]) != 6 {
		t.Fatal("duplicate charge")
	}
}
func TestControllerStoragePrepaidCollectionAndPhysicalCleanupGate(t *testing.T) {
	f := newTestDB(t)
	ctx := context.Background()
	s := NewStorage(f.db, nil)
	s.Clock = func() time.Time { return f.now }
	s.ExecutorRoot = t.TempDir()
	if e := s.ReserveCollection(ctx, f.job, f.attempt, f.allocation); e != nil {
		t.Fatal(e)
	}
	cap := int64(1024 + 4<<20)
	if integer(row(t, f.db, "jm_projects", "research")["retained_bytes"]) != cap {
		t.Fatal("collection was not prepaid")
	}
	if e := s.RetainExecutionState(ctx, f.job, f.attempt, f.allocation); e != nil {
		t.Fatal(e)
	}
	source := t.TempDir()
	mustWrite(t, filepath.Join(source, "model.safetensors"), []byte("opaque-model"))
	collector, e := NewCollector(source, CollectorOptions{})
	if e != nil {
		t.Fatal(e)
	}
	defer collector.Close()
	identity := LogIdentity{"job-a", "attempt-a", "owner", 1}
	destination := filepath.Join(s.ExecutorRoot, identity.Key(), "retained", "state")
	retained, e := collector.Retain(destination)
	if e != nil {
		t.Fatal(e)
	}
	files := []domain.CollectedArtifact{{Path: retained[0].Path, Locator: retained[0].Locator, SizeBytes: retained[0].SizeBytes, SHA256: retained[0].SHA256}}
	if e = s.StoreCollected(ctx, f.job, f.attempt, f.allocation, files); e != nil {
		t.Fatal(e)
	}
	if e = s.StoreCollected(ctx, f.job, f.attempt, f.allocation, files); e != nil {
		t.Fatal("collection replay", e)
	}
	if integer(row(t, f.db, "jm_projects", "research")["retained_bytes"]) != cap+1024 {
		t.Fatal("child transfer changed total physical cap")
	}
	artifacts, e := f.db.All(ctx, "SELECT * FROM jm_artifacts")
	if e != nil || len(artifacts) != 1 {
		t.Fatal(artifacts, e)
	}
	f.update(t, "jm_jobs", map[string]any{"id": "job-a"}, map[string]any{"state": "SUCCEEDED", "terminated_at": f.now})
	if e = s.ConfirmJobDataDeleted(ctx, "job-a"); e == nil {
		t.Fatal("released running/retained bytes")
	}
	if ok, e := DeleteRetained(destination, retained, DeleteOptions{}); e != nil || !ok {
		t.Fatal(e)
	}
	f.update(t, "jm_allocations", map[string]any{"id": "allocation-a"}, map[string]any{"state": "RELEASED", "released_at": f.now, "termination_confirmed": true, "details_json": map[string]any{"retained_disk_charged": true, "storage_deleted": true}})
	if e = f.db.WithTx(ctx, true, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, "UPDATE jm_provisioning_resources SET state = ?,deleted_at = ? WHERE job_id = ?", "deleted", f.now, "job-a")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = s.ConfirmJobDataDeleted(ctx, "job-a"); e != nil {
		t.Fatal(e)
	}
	if integer(row(t, f.db, "jm_projects", "research")["retained_bytes"]) != 0 {
		t.Fatal("confirmed deletion did not release quota")
	}
	members, e := f.db.All(ctx, "SELECT * FROM jm_job_members WHERE job_id = ?", "job-a")
	if e != nil || len(members) != 1 {
		t.Fatal("history ACL was deleted", e)
	}
	if text(row(t, f.db, "jm_artifacts", text(artifacts[0]["id"]))["state"]) != "deleted" {
		t.Fatal("artifact availability survived raw purge")
	}
}
func TestCollectedManifestRejectsForeignRootsAndRemoteRoutes(t *testing.T) {
	identity := LogIdentity{"job-a", "attempt-a", "owner", 1}
	base := t.TempDir()
	valid := domain.CollectedArtifact{Path: "model.safetensors", Locator: filepath.Join(base, identity.Key(), "retained", "state", "model.safetensors"), SHA256: digest([]byte("x")), SizeBytes: 1}
	if _, e := collectedRoot(valid, identity, "node-a", base); e != nil {
		t.Fatal(e)
	}
	invalid := valid
	invalid.Locator = filepath.Join(base, "foreign", "retained", "state", "model.safetensors")
	if _, e := collectedRoot(invalid, identity, "node-a", base); e == nil {
		t.Fatal("foreign execution root accepted")
	}
	remote := valid
	remote.Locator = "hf2l-node://node-a/" + identity.Key() + "/model.safetensors"
	if _, e := collectedRoot(remote, identity, "node-a", base); e != nil {
		t.Fatal(e)
	}
	remote.Locator = "hf2l-node://node-b/" + identity.Key() + "/model.safetensors"
	if _, e := collectedRoot(remote, identity, "node-a", base); e == nil {
		t.Fatal("foreign node route accepted")
	}
}
