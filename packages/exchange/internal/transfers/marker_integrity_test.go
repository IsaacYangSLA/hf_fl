package transfers

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/storage"
)

func persistRawLedger(t *testing.T, f *fixture, id, raw string) {
	t.Helper()
	if _, e := f.s.DB.Exec(f.ctx, "UPDATE v2_transfer_attempts SET mutation_tokens=? WHERE id=?", raw, id); e != nil {
		t.Fatal(e)
	}
}
func assertLedgerPreserved(t *testing.T, f *fixture, id, raw string) {
	t.Helper()
	row := f.row(t, "v2_transfer_attempts", id)
	got, e := json.Marshal(row["mutation_tokens"])
	if e != nil {
		t.Fatal(e)
	}
	var want any
	if e = json.Unmarshal([]byte(raw), &want); e != nil {
		t.Fatal(e)
	}
	normalized, e := json.Marshal(want)
	if e != nil {
		t.Fatal(e)
	}
	if string(got) != string(normalized) {
		t.Fatal("unknown persisted ownership ledger was overwritten")
	}
}
func malformedCase(t *testing.T, postgres bool, phase, raw string) {
	f := newFixture(t, postgres)
	var handle GatewayPutHandle
	if phase == "gateway_append" || phase == "gateway_finish" {
		f.owner = makeManaged(t, f)
	}
	f.initiate(t)
	id := str(f.current(t)["id"])
	var ownedAttempt Object
	switch phase {
	case "cleanup_process", "cleanup_execute", "cleanup_commit", "repair":
		f.withdraw(t)
		if phase == "cleanup_execute" || phase == "cleanup_commit" {
			cleanup := true
			var e error
			ownedAttempt, e = f.s.Acquire(f.ctx, id, &cleanup)
			if e != nil || ownedAttempt == nil {
				t.Fatal("cleanup fixture lease", e)
			}
		}
	case "initiate":
		f.update(t, "v2_transfer_attempts", id, Object{"state": "cleaned", "operation": "cleanup"})
		f.update(t, "v2_blobs", f.bid, Object{"state": "reserved"})
	case "commit_completion", "settlement", "abandon":
		now, e := f.s.DB.Now(f.ctx)
		if e != nil {
			t.Fatal(e)
		}
		token := "owned-provider-call"
		f.update(t, "v2_transfer_attempts", id, Object{"state": "completing", "token": token, "lease_until": now + 300, "mutation_tokens": []any{token}})
		ownedAttempt = f.current(t)
	case "gateway_finish":
		var e error
		handle, _, e = f.s.BeginGatewayPut(f.ctx, f.owner, f.sid, f.rid, f.bid, 1)
		if e != nil {
			t.Fatal(e)
		}
	}
	persistRawLedger(t, f, id, raw)
	startCalls, completeCalls, cleanupCalls, grantCalls, partsCalls := f.provider.count("start"), f.provider.count("complete"), f.provider.count("cleanup"), f.provider.count("upload_grant"), f.provider.count("parts")
	switch phase {
	case "cleanup_process":
		_, _ = f.s.Process(f.ctx, id, true)
	case "cleanup_execute":
		_, _ = f.s.execute(f.ctx, ownedAttempt)
	case "cleanup_commit":
		ok, e := f.s.Commit(f.ctx, ownedAttempt, "cleaned", nil)
		if ok || e == nil {
			t.Error("malformed markers authorized a cleanup commit")
		}
	case "parts":
		_, e := f.s.Parts(f.ctx, f.sid, f.rid, f.bid, f.owner)
		if e == nil {
			t.Error("unknown ownership authorized provider listing")
		}
	case "grants":
		_, e := f.s.Grants(f.ctx, f.sid, f.rid, f.bid, f.owner, []int{1})
		if e == nil {
			t.Error("unknown ownership authorized a fresh origin grant")
		}
	case "complete":
		_, e := f.s.Complete(f.ctx, f.sid, f.rid, f.bid, f.owner)
		if e == nil {
			t.Error("malformed markers authorized completion")
		}
	case "initiate":
		_, e := f.s.Initiate(f.ctx, f.sid, f.rid, f.bid, f.owner)
		if e == nil {
			t.Error("malformed markers authorized a successor upload")
		}
	case "commit_completion":
		ok, e := f.s.Commit(f.ctx, ownedAttempt, "verifying", storage.StoredObject{Key: str(ownedAttempt["object_key"]), Version: "version-exact"})
		if ok || e == nil {
			t.Error("malformed markers authorized a completion commit")
		}
	case "gateway_append":
		_, _, e := f.s.BeginGatewayPut(f.ctx, f.owner, f.sid, f.rid, f.bid, 1)
		if e == nil {
			t.Error("gateway append replaced unknown ownership")
		}
	case "gateway_finish":
		ok, _ := f.s.FinishGatewayPut(f.ctx, handle)
		if ok {
			t.Error("gateway settlement accepted unknown ownership")
		}
	case "settlement":
		_ = f.s.settleMutation(f.ctx, ownedAttempt)
	case "abandon":
		_ = f.s.abandon(f.ctx, ownedAttempt)
	case "repair":
		inventory, e := InspectMutations(f.ctx, f.s.DB, []string{id})
		if e != nil {
			t.Fatal(e)
		}
		items := list(inventory["attempts"])
		if len(items) != 1 {
			t.Fatal("unknown ledger missing from repair inventory")
		}
		item := obj(items[0])
		if item["mutation_count"] != nil || item["repairable"] != false || item["mutation_ledger_valid"] != false {
			t.Error("repair inventory represented unknown ownership as known/quiescent")
		}
		_, e = RepairMutations(f.ctx, f.s.DB, []string{id}, true, true, true)
		if e == nil {
			t.Error("ordinary repair erased unknown ledger schema")
		}
	default:
		t.Fatal("unknown test phase")
	}
	if f.provider.count("start") != startCalls || f.provider.count("complete") != completeCalls || f.provider.count("cleanup") != cleanupCalls || f.provider.count("upload_grant") != grantCalls || f.provider.count("parts") != partsCalls {
		t.Error("unknown persisted mutation ownership authorized provider I/O")
	}
	assertLedgerPreserved(t, f, id, raw)
	if phase == "cleanup_process" || phase == "cleanup_execute" || phase == "cleanup_commit" || phase == "repair" {
		f.quota(t, 0, 3)
	} else {
		f.quota(t, 3, 0)
	}
}
func malformedLedgerSuite(t *testing.T, postgres bool) {
	for name, raw := range map[string]string{"object": `{"pending":"unknown"}`, "string": `"pending"`} {
		t.Run(name, func(t *testing.T) {
			for _, phase := range []string{"cleanup_process", "cleanup_execute", "cleanup_commit", "parts", "grants", "complete", "initiate", "commit_completion", "gateway_append", "gateway_finish", "settlement", "abandon", "repair"} {
				t.Run(phase, func(t *testing.T) { malformedCase(t, postgres, phase, raw) })
			}
		})
	}
	for name, raw := range map[string]string{
		"json_null": "null", "empty_object": "{}", "number": "1", "boolean": "true", "null_member": "[null]", "number_member": "[1]", "object_member": "[{}]", "mixed_member": `["known",1]`, "empty_member": `[""]`, "duplicate": `["known","known"]`,
	} {
		t.Run(name, func(t *testing.T) { malformedCase(t, postgres, "cleanup_process", raw) })
	}
}
func TestMalformedMutationLedgersSQLite(t *testing.T)   { malformedLedgerSuite(t, false) }
func TestMalformedMutationLedgersPostgres(t *testing.T) { malformedLedgerSuite(t, true) }
func TestValidHistoricalMutationLedgerIsNotCoerced(t *testing.T) {
	f := newFixture(t, false)
	f.initiate(t)
	id := str(f.current(t)["id"])
	raw := `["legacy-opaque","gateway-put-1-opaque"]`
	persistRawLedger(t, f, id, raw)
	f.withdraw(t)
	_, _ = f.s.Process(f.ctx, id, true)
	assertLedgerPreserved(t, f, id, raw)
	f.quota(t, 0, 3)
	if _, valid := domain.MutationTokens(f.current(t)["mutation_tokens"]); !valid {
		t.Fatal("valid historical ownership rejected")
	}
}

func testUnknownCleanedHistoryRetainsQuota(t *testing.T, postgres bool) {
	for name, raw := range map[string]string{"object": `{"pending":"unknown"}`, "string": `"pending"`, "json_null": "null", "owned_marker": `["old-call-still-owned"]`} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, postgres)
			f.initiate(t)
			current := f.current(t)
			historical := domain.CloneMap(current)
			historical["id"] = "history-" + domain.NewID()
			historical["object_key"] = "history-" + domain.NewID()
			historical["state"] = "cleaned"
			historical["operation"] = "cleanup"
			historical["mutation_tokens"] = []any{}
			historical["token"] = nil
			historical["lease_until"] = nil
			if e := f.s.DB.Insert(f.ctx, "v2_transfer_attempts", historical); e != nil {
				t.Fatal(e)
			}
			f.withdraw(t)
			// This late integrity failure must not be hidden by a stale cleaned label.
			persistRawLedger(t, f, str(historical["id"]), raw)
			f.process(t, str(current["id"]), true, "cleaned")
			f.quota(t, 0, 3)
			if !flag(f.row(t, "v2_blobs", f.bid)["pending_deletion"]) {
				t.Fatal("historical uncertainty released pending physical ownership")
			}
			assertLedgerPreserved(t, f, str(historical["id"]), raw)
			if f.provider.count("cleanup") != 1 {
				t.Fatal("cleanup of known current key did not finish exactly once")
			}
			if f.row(t, "v2_transfer_attempts", str(historical["id"]))["state"] != "cleaned" {
				t.Fatal("current cleanup fabricated a sibling cleanup result")
			}
		})
	}
}
func TestCleanedHistoryOwnershipSQLite(t *testing.T) { testUnknownCleanedHistoryRetainsQuota(t, false) }
func TestCleanedHistoryOwnershipPostgres(t *testing.T) {
	testUnknownCleanedHistoryRetainsQuota(t, true)
}

func testLateMalformedCompletionIsNotNormalized(t *testing.T, postgres bool) {
	for name, raw := range map[string]string{"object": `{"pending":"unknown"}`, "string": `"pending"`} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, postgres)
			f.initiate(t)
			id := str(f.current(t)["id"])
			f.provider.onComplete = func(_ context.Context, _ storage.UploadHandle) error {
				persistRawLedger(t, f, id, raw)
				return nil
			}
			_, e := f.s.Complete(f.ctx, f.sid, f.rid, f.bid, f.owner)
			errorCode(t, e, "storage_mutation_uncertain")
			assertLedgerPreserved(t, f, id, raw)
			f.quota(t, 3, 0)
			if f.provider.count("complete") != 1 {
				t.Fatal("provider fixture did not reach the late writer boundary")
			}
			_, e = f.s.Complete(f.ctx, f.sid, f.rid, f.bid, f.owner)
			errorCode(t, e, "storage_mutation_uncertain")
			if f.provider.count("complete") != 1 {
				t.Fatal("unknown late completion was replayed")
			}
		})
	}
}
func TestLateMalformedCompletionSQLite(t *testing.T) {
	testLateMalformedCompletionIsNotNormalized(t, false)
}
func TestLateMalformedCompletionPostgres(t *testing.T) {
	testLateMalformedCompletionIsNotNormalized(t, true)
}
