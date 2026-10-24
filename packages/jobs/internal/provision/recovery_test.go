package provision

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	buildworker "github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/build"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/resources"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func terminal(t *testing.T, h *harness) {
	t.Helper()
	h.job["state"] = "CANCELLED"
	ctx := context.Background()
	e := h.db.WithTx(ctx, true, func(tx *store.Tx) error {
		if e := tx.Update(ctx, "jm_jobs", map[string]any{"id": idOf(h.job)}, map[string]any{"state": "CANCELLED"}); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, "UPDATE jm_allocations SET state = ?,released_at = ?,termination_confirmed = ? WHERE job_id = ?", "RELEASED", time.Now().UTC(), true, idOf(h.job))
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
}
func TestTerminalLostNamespaceAckAdoptsOriginalBeforeRetirement(t *testing.T) {
	h := setup(t)
	h.reserve(t)
	ctx := context.Background()
	h.exchange.lostCreate = true
	if e := h.p.Ensure(ctx, h.job, h.attempt, 2); e == nil {
		t.Fatal("fixture did not lose acknowledgement")
	}
	terminal(t, h)
	if ok, e := h.p.PurgeJob(ctx, h.job); e != nil || !ok {
		t.Fatal("lost namespace cleanup failed", ok, e)
	}
	if h.exchange.creates != 1 || h.exchange.retires == 0 {
		t.Fatalf("wrong adoption/retirement %d/%d", h.exchange.creates, h.exchange.retires)
	}
	if _, e := os.Stat(filepath.Join(h.root, idOf(h.job))); !os.IsNotExist(e) {
		t.Fatal("retained source was not purged", e)
	}
}
func TestBuildProductsRemainOpaqueBoundAndRetainedBeforeConfigDelivery(t *testing.T) {
	h := setupOptions(t, true)
	h.reserve(t)
	ctx := context.Background()
	if e := h.p.Ensure(ctx, h.job, h.attempt, 2); e != nil {
		t.Fatal(e)
	}
	prepared, e := h.p.PreparedComponent(ctx, h.job, h.attempt, "builder")
	if e != nil {
		t.Fatal(e)
	}
	raw, e := domain.CanonicalJSON(prepared)
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := buildworker.DecodeConfig(raw)
	if e != nil {
		t.Fatal(e)
	}
	wheel := []byte("opaque wheel fixture; never unpack in the trusted manager\n")
	name := "example-1.0-py3-none-any.whl"
	result := buildworker.Result{SchemaVersion: 1, Status: "completed", Binding: cfg.DurableBinding(), Wheel: buildworker.Artifact{Filename: name, SHA256: checksum(wheel), SizeBytes: int64(len(wheel))}}
	report, e := json.Marshal(result)
	if e != nil {
		t.Fatal(e)
	}
	identity := executor.ExecutionIdentity{JobID: idOf(h.job), AttemptID: idOf(h.attempt), ComponentID: "builder", Epoch: 1}
	files := map[string][]byte{"artifacts/build.json": report, "artifacts/" + name: wheel}
	outputs := map[string][]executor.CollectedArtifact{"builder": {}}
	for _, path := range sortedKeys(files) {
		bytes := files[path]
		outputs["builder"] = append(outputs["builder"], executor.CollectedArtifact{Path: path, SHA256: checksum(bytes), SizeBytes: int64(len(bytes)), Locator: "hf2l-node://node/" + identity.Key() + "/" + path})
	}
	h.p.ArtifactReader = func(ctx context.Context, id executor.ExecutionIdentity, path string, maxBytes int64) ([]byte, error) {
		if id != identity {
			return nil, domain.Err(403, "foreign_identity")
		}
		bytes := files[path]
		if int64(len(bytes)) > maxBytes {
			return nil, domain.Err(413, "oversized")
		}
		return bytes, nil
	}
	if ok, e := h.p.PrepareBuildOutputs(ctx, h.job, h.attempt, outputs); e != nil || !ok {
		t.Fatal(ok, e)
	}
	data, e := h.p.ReadBuildProduct(ctx, h.job, name, 256<<20)
	if e != nil || string(data) != string(wheel) {
		t.Fatal("build transport mismatch", e)
	}
	owner, e := h.p.PreparedComponent(ctx, h.job, h.attempt, "owner")
	if e != nil {
		t.Fatal(e)
	}
	if len(obj(owner["built_artifacts"])) != 1 {
		t.Fatal("verified build not in owner configuration")
	}
	rows, e := h.p.Ledger.Resources(ctx, idOf(h.job), resources.ResourceFilter{Kind: "build_products"})
	if e != nil || len(rows) != 1 || !truth(details(rows[0])["retention_charge_settled"]) {
		t.Fatal("staging was not charged", e, rows)
	}
	if ok, e := h.p.PrepareBuildOutputs(ctx, h.job, h.attempt, outputs); e != nil || !ok {
		t.Fatal("identical build replay failed", ok, e)
	}
	products, e := h.p.PreparedBuildProducts(ctx, h.job, h.attempt, "owner")
	if e != nil || string(products[name]) != string(wheel) {
		t.Fatal("prepared products mismatch", e)
	}
	outputs["builder"][0].Locator = "hf2l-node://node/" + strings.Repeat("b", 32) + "/" + outputs["builder"][0].Path
	if _, e := h.p.PrepareBuildOutputs(ctx, h.job, h.attempt, outputs); e == nil {
		t.Fatal("foreign retained execution accepted")
	}
}
func TestRemoteAuxiliaryRequiresEveryExactNodeReceipt(t *testing.T) {
	h := setup(t)
	h.reserve(t)
	ctx := context.Background()
	if e := h.p.Ensure(ctx, h.job, h.attempt, 2); e != nil {
		t.Fatal(e)
	}
	h.attempt["termination_confirmed"] = true
	if ok, e := h.p.Cleanup(ctx, h.job, h.attempt); e != nil || !ok {
		t.Fatal(ok, e)
	}
	terminal(t, h)
	e := h.db.WithTx(ctx, true, func(tx *store.Tx) error {
		return tx.Update(ctx, "jm_allocations", map[string]any{"id": "allocation"}, map[string]any{"details_json": map[string]any{"node_id": "remote-node"}})
	})
	if e != nil {
		t.Fatal(e)
	}
	rid, e := h.p.Ledger.Own(ctx, resources.Ownership{JobID: idOf(h.job), AttemptID: idOf(h.attempt), ComponentID: "owner", Kind: "remote_auxiliary", ExternalID: "hf2l-aux://owned", Retained: true, Details: map[string]any{"node_id": "remote-node", "pool_id": "cpu", "spec_digest": mustDigest(h.spec)}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.p.Retention.ReserveResource(ctx, rid, idOf(h.job), 4096); e != nil {
		t.Fatal(e)
	}
	id := executor.ExecutionIdentity{JobID: idOf(h.job), AttemptID: idOf(h.attempt), ComponentID: "owner", Epoch: 1}
	receipt := map[string]any{"job_id": id.JobID, "attempt_id": id.AttemptID, "component_id": id.ComponentID, "epoch": id.Epoch, "node_id": "remote-node", "pool_id": "cpu", "spec_digest": mustDigest(h.spec), "purpose": "managed_node_purge", "operation_id": "purge-" + id.Key()}
	for _, key := range []string{"confirmed", "termination_confirmed", "source_deleted", "config_deleted", "build_deleted", "private_credentials_deleted", "private_secrets_deleted", "retained_deleted", "auxiliary_deleted"} {
		receipt[key] = true
	}
	receipt["node_id"] = "foreign-node"
	h.p.RemoteAuxiliaryCleanup = func(context.Context, map[string]any, []map[string]any) (map[string][]map[string]any, error) {
		return map[string][]map[string]any{rid: {receipt}}, nil
	}
	if ok, e := h.p.PurgeJob(ctx, h.job); e != nil || ok {
		t.Fatal("foreign node receipt released storage", ok, e)
	}
	row, e := h.db.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?", rid)
	if e != nil || row["state"] == "deleted" || truth(details(row)["retention_charge_released"]) {
		t.Fatal("unconfirmed remote bytes released", e)
	}
	receipt["node_id"] = "remote-node"
	if ok, e := h.p.PurgeJob(ctx, h.job); e != nil || !ok {
		t.Fatal("exact remote proof not accepted", ok, e)
	}
	row, e = h.db.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?", rid)
	if e != nil || row["state"] != "deleted" || !truth(details(row)["retention_charge_released"]) {
		t.Fatal("confirmed remote storage not released", e, row)
	}
}

func TestCleanupRefusesMissingProxyTerminationReceipt(t *testing.T) {
	h := setup(t)
	h.reserve(t)
	ctx := context.Background()
	if e := h.p.Ensure(ctx, h.job, h.attempt, 2); e != nil {
		t.Fatal(e)
	}
	h.attempt["termination_confirmed"] = true
	h.p.ProxyStopper = nil
	if ok, e := h.p.Cleanup(ctx, h.job, h.attempt); e == nil || ok {
		t.Fatal("missing proxy termination proof accepted", ok, e)
	}
	allocation, e := h.db.One(ctx, "SELECT * FROM jm_allocations WHERE id = ?", "allocation")
	if e != nil || allocation["released_at"] != nil {
		t.Fatal("cleanup released resources without proxy receipt", e)
	}
}
