package provision

import (
	"context"
	"math"
	"os"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/resources"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func TestDatetimeDerivedDeadlinesMatchPythonTimestampBits(t *testing.T) {
	data, e := os.ReadFile("testdata/datetime-contract.json")
	if e != nil {
		t.Fatal(e)
	}
	value, e := domain.DecodeJSON(data)
	if e != nil {
		t.Fatal(e)
	}
	fixtures, ok := array(obj(value)["fixtures"])
	if !ok || len(fixtures) != 3 {
		t.Fatal("missing datetime oracles")
	}
	for _, item := range fixtures {
		fixture := obj(item)
		t.Run(str(fixture["datetime"]), func(t *testing.T) {
			h := setup(t)
			ctx := context.Background()
			deadline, e := time.Parse(time.RFC3339Nano, str(fixture["datetime"]))
			if e != nil {
				t.Fatal(e)
			}
			expected, e := floating(fixture["unix_seconds"])
			if e != nil {
				t.Fatal(e)
			}
			legacy, e := floating(fixture["legacy_nanos_seconds"])
			if e != nil || math.Float64bits(legacy) == math.Float64bits(expected) {
				t.Fatal("fixture would not detect old nanosecond rounding")
			}
			h.job["deadline_at"] = deadline
			e = h.db.WithTx(ctx, true, func(tx *store.Tx) error {
				return tx.Update(ctx, "jm_jobs", map[string]any{"id": idOf(h.job)}, map[string]any{"deadline_at": deadline})
			})
			if e != nil {
				t.Fatal(e)
			}
			plan, e := h.p.Plan(ctx, h.job, h.attempt, 2)
			if e != nil {
				t.Fatal(e)
			}
			actual := plan["owner"].Deadline
			if actual == nil || math.Float64bits(*actual) != math.Float64bits(expected) {
				t.Fatalf("execution deadline bits %v != %.17g", actual, expected)
			}
			h.reserve(t)
			if e = h.p.Ensure(ctx, h.job, h.attempt, 2); e != nil {
				t.Fatal(e)
			}
			cfg, e := h.p.PreparedComponent(ctx, h.job, h.attempt, "owner")
			if e != nil {
				t.Fatal(e)
			}
			runtimeDeadline, e := floating(cfg["deadline_at"])
			if e != nil || math.Float64bits(runtimeDeadline) != math.Float64bits(expected) {
				t.Fatalf("worker deadline %.17g != %.17g: %v", runtimeDeadline, expected, e)
			}
			rows, e := h.db.All(ctx, "SELECT desired_json FROM jm_provisioning_operations WHERE job_id = ? AND operation = ?", idOf(h.job), "workload_grant")
			if e != nil || len(rows) != 1 {
				t.Fatal("missing durable grant operation", e)
			}
			expiry, e := floating(obj(rows[0]["desired_json"])["expires_at"])
			if e != nil || math.Float64bits(expiry) != math.Float64bits(expected) {
				t.Fatalf("grant expiry %.17g != %.17g: %v", expiry, expected, e)
			}
		})
	}
}
func TestPurgeRequiresPermanentBrokerFenceAndDeletesOwnedDownloadGrant(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	h.reserve(t)
	if e := h.p.Ensure(ctx, h.job, h.attempt, 2); e != nil {
		t.Fatal(e)
	}
	h.attempt["termination_confirmed"] = true
	if ok, e := h.p.Cleanup(ctx, h.job, h.attempt); e != nil || !ok {
		t.Fatal(ok, e)
	}
	terminal(t, h)
	rid, e := h.p.Ledger.Own(ctx, resources.Ownership{JobID: idOf(h.job), ComponentID: "download-broker", Kind: "workload_grant", ExternalID: "download-grant", Retained: true, Details: map[string]any{"space_id": "space-owned", "attempt_id": "artifact-fixed-attempt", "job_id": idOf(h.job), "principal_id": "download-principal", "roles": []string{"reader"}}})
	if e != nil {
		t.Fatal(e)
	}
	before, e := h.db.One(ctx, "SELECT retained_bytes FROM jm_projects WHERE id = ?", "research")
	if e != nil {
		t.Fatal(e)
	}
	h.p.ArtifactFenceRevoker = nil
	if ok, e := h.p.PurgeJob(ctx, h.job); e == nil || ok {
		t.Fatal("missing permanent broker fence accepted", ok, e)
	}
	if h.exchange.retires != 0 {
		t.Fatal("namespace retired before broker fencing")
	}
	h.p.ArtifactFenceRevoker = func(context.Context, string) (bool, error) { return false, nil }
	if ok, e := h.p.PurgeJob(ctx, h.job); e != nil || ok {
		t.Fatal("unconfirmed broker fence accepted", ok, e)
	}
	row, e := h.db.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?", rid)
	if e != nil || row["state"] == "deleted" || row["deleted_at"] != nil || !truth(row["retained"]) {
		t.Fatal("download grant disappeared before fencing", e, row)
	}
	after, e := h.db.One(ctx, "SELECT retained_bytes FROM jm_projects WHERE id = ?", "research")
	if e != nil || after["retained_bytes"] != before["retained_bytes"] {
		t.Fatal("charges released after failed broker fencing", e, before, after)
	}
	h.p.ArtifactFenceRevoker = func(context.Context, string) (bool, error) { return true, nil }
	if ok, e := h.p.PurgeJob(ctx, h.job); e != nil || !ok {
		t.Fatal("confirmed broker cleanup failed", ok, e)
	}
	row, e = h.db.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?", rid)
	if e != nil || row["state"] != "deleted" || row["deleted_at"] == nil {
		t.Fatal("retained download grant blocks confirmed cleanup", e, row)
	}
}
