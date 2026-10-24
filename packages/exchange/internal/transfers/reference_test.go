package transfers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/storage"
)

// These traces were generated independently from the retained Python service.
// The serial tick driver isolates engine semantics; worker tests separately
// verify concurrency pools and retention.
func referenceTick(t *testing.T, f *fixture) Object {
	t.Helper()
	counts := Object{}
	for _, key := range []string{"verified", "failed", "recovered", "cleaned", "retry", "skipped", "invalid_parts", "expired"} {
		counts[key] = int64(0)
	}
	expired, e := f.s.Expire(f.ctx, 32)
	if e != nil {
		t.Fatal(e)
	}
	counts["expired"] = int64(expired)
	verify, cleanup, e := f.s.Work(f.ctx, 32)
	if e != nil {
		t.Fatal(e)
	}
	for _, pool := range []struct {
		ids     []string
		cleanup bool
	}{{verify, false}, {cleanup, true}} {
		for _, id := range pool.ids {
			outcome, e := f.s.Process(f.ctx, id, pool.cleanup)
			if e != nil {
				t.Fatal(e)
			}
			if counts[outcome] == nil {
				t.Fatalf("unknown outcome %q", outcome)
			}
			counts[outcome] = integer(counts[outcome]) + 1
		}
	}
	return counts
}
func traceSnapshot(t *testing.T, f *fixture, step string, extra Object) Object {
	t.Helper()
	space := f.row(t, "v2_spaces", f.sid)
	r, e := f.s.DB.One(f.ctx, "SELECT * FROM v2_records WHERE id=?", f.rid)
	if e != nil {
		t.Fatal(e)
	}
	b, e := f.s.DB.One(f.ctx, "SELECT * FROM v2_blobs WHERE id=?", f.bid)
	if e != nil {
		t.Fatal(e)
	}
	rs, bs := "absent", "absent"
	version := false
	if r != nil {
		rs = str(r["state"])
	}
	if b != nil {
		bs = str(b["state"])
		version = b["object_version"] != nil
	}
	result := Object{"step": step, "record_state": rs, "blob_state": bs, "allocated": space["allocated"], "reclaiming": space["reclaiming"], "has_object_version": version, "attempts": []any{}}
	rows, e := f.s.DB.All(f.ctx, "SELECT * FROM v2_transfer_attempts WHERE blob_id=? ORDER BY created_at,id", f.bid)
	if e != nil {
		t.Fatal(e)
	}
	values := []any{}
	for _, a := range rows {
		h := obj(a["upload_handle"])
		values = append(values, Object{"state": a["state"], "mutation_count": len(list(a["mutation_tokens"])), "lease_present": a["lease_until"] != nil, "retry_count": a["retry_count"], "last_error": a["last_error"], "has_upload_handle": str(h["id"]) != "", "has_version": str(h["version"]) != ""})
	}
	result["attempts"] = values
	for key, value := range extra {
		result[key] = value
	}
	return result
}
func TestPythonReferenceTransferTraces(t *testing.T) {
	data, e := os.ReadFile(filepath.Join("testdata", "python_traces.json"))
	if e != nil {
		t.Fatal(e)
	}
	value, e := domain.DecodeJSON(data)
	if e != nil {
		t.Fatal(e)
	}
	gold := obj(value)
	for path, want := range obj(gold["reference_inputs_sha256"]) {
		source, e := os.ReadFile(filepath.Join("..", "..", strings.TrimPrefix(path, "packages/exchange/")))
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(source)
		if hex.EncodeToString(sum[:]) != str(want) {
			t.Fatalf("reference input changed: %s; regenerate independent traces", path)
		}
	}
	expected := obj(gold["snapshots"])
	for _, scenario := range []string{"normal", "uncertain_initiation", "invalid_parts", "verification_missing", "uncertain_completion"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t, false)
			f.s.Settings.Storage.GrantSeconds = 2
			actual := []any{}
			capture := func(step string, extra Object) { actual = append(actual, traceSnapshot(t, f, step, extra)) }
			tick := func(step string) { capture(step, Object{"worker_outcomes": referenceTick(t, f)}) }
			due := func() {
				a := f.current(t)
				f.due(t, str(a["id"]))
				f.update(t, "v2_blobs", f.bid, Object{"grant_expires_at": float64(0)})
			}
			repair := func(execute bool) {
				a := f.current(t)
				if _, e := RepairMutations(f.ctx, f.s.DB, []string{str(a["id"])}, execute, execute, execute); e != nil {
					t.Fatal(e)
				}
			}
			switch scenario {
			case "normal":
				capture("initial", nil)
				f.initiate(t)
				capture("initiate", nil)
				f.complete(t)
				capture("complete", nil)
				tick("verify")
				if _, e = f.core.PublishRecord(f.ctx, f.owner, f.sid, f.rid, "publish"); e != nil {
					t.Fatal(e)
				}
				capture("publish", nil)
				if _, e = f.s.Download(f.ctx, f.sid, f.rid, f.bid, f.owner); e != nil {
					t.Fatal(e)
				}
				capture("download", nil)
				f.withdraw(t)
				capture("withdraw", nil)
				tick("cleanup_before_grant_expiry")
				due()
				tick("cleanup_after_capabilities_due")
				if _, e = f.core.PurgeRecord(f.ctx, f.owner, f.sid, f.rid); e != nil {
					t.Fatal(e)
				}
				capture("purge", nil)
			case "uncertain_initiation":
				f.provider.fail(storage.Failure("storage_unavailable", true, true))
				f.initiate(t)
				capture("uncertain_initiate", nil)
				f.provider.fail(nil)
				due()
				tick("recovery_fenced")
				_, e = f.s.Initiate(f.ctx, f.sid, f.rid, f.bid, f.owner)
				errorCode(t, e, "storage_mutation_uncertain")
				capture("new_initiation_denied", Object{"error_code": "storage_mutation_uncertain"})
				f.withdraw(t)
				capture("withdraw", nil)
				repair(false)
				capture("repair_dry_run", nil)
				repair(true)
				capture("repair_applied", nil)
				tick("cleanup")
			case "invalid_parts":
				f.initiate(t)
				capture("initiate", nil)
				f.provider.fail(storage.Failure("invalid_parts", false, false))
				_, e = f.s.Complete(f.ctx, f.sid, f.rid, f.bid, f.owner)
				errorCode(t, e, "invalid_parts")
				capture("invalid_parts", Object{"error_code": "invalid_parts"})
				f.provider.fail(nil)
				f.complete(t)
				capture("corrected_complete", nil)
				tick("verify")
			case "verification_missing":
				f.upload(t)
				capture("complete", nil)
				f.provider.fail(storage.Failure("storage_missing", false, false))
				tick("verification_failed")
				tick("cleanup_retry")
				f.provider.fail(nil)
				due()
				tick("cleanup")
			case "uncertain_completion":
				f.initiate(t)
				capture("initiate", nil)
				f.provider.fail(storage.Failure("storage_unavailable", true, true))
				f.complete(t)
				capture("uncertain_complete", nil)
				f.provider.fail(nil)
				due()
				tick("recovery_fenced")
				repair(false)
				capture("repair_dry_run", nil)
				repair(true)
				capture("repair_applied", nil)
				tick("completion_recovered")
				tick("verify")
			}
			want, e := domain.CanonicalJSON(expected[scenario])
			if e != nil {
				t.Fatal(e)
			}
			got, e := domain.CanonicalJSON(actual)
			if e != nil {
				t.Fatal(e)
			}
			if string(got) != string(want) {
				var pretty any
				_ = json.Unmarshal(got, &pretty)
				formatted, _ := json.MarshalIndent(pretty, "", "  ")
				t.Fatalf("Go differs from independent Python trace\n%s\nwant %s", formatted, want)
			}
		})
	}
}
