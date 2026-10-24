package transfers

import (
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
)

func addReadySibling(t *testing.T, f *fixture) string {
	t.Helper()
	record := domain.CloneMap(f.row(t, "v2_records", f.rid))
	blob := domain.CloneMap(f.row(t, "v2_blobs", f.bid))
	record["id"] = domain.NewID()
	record["state"] = "draft"
	record["published_at"] = nil
	blob["id"] = domain.NewID()
	blob["record_id"] = record["id"]
	blob["state"] = "reserved"
	blob["object_key"] = nil
	blob["object_version"] = nil
	blob["verified_size"] = nil
	blob["verified_sha256"] = nil
	blob["grant_expires_at"] = float64(0)
	blob["pending_deletion"] = false
	e := f.s.DB.WithTx(f.ctx, true, func(tx *store.Tx) error {
		space, e := tx.One(f.ctx, "SELECT * FROM v2_spaces WHERE id=?"+tx.ForUpdate(), f.sid)
		if e != nil {
			return e
		}
		if e = tx.Insert(f.ctx, "v2_records", record); e != nil {
			return e
		}
		if e = tx.Insert(f.ctx, "v2_blobs", blob); e != nil {
			return e
		}
		return tx.Update(f.ctx, "v2_spaces", Object{"id": f.sid}, Object{"quota_bytes": int64(6), "principal_quota_bytes": int64(6), "allocated": int64(6), "record_count": integer(space["record_count"]) + 1, "metadata_bytes": integer(space["metadata_bytes"]) + integer(record["metadata_bytes"])})
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Initiate(f.ctx, f.sid, str(record["id"]), str(blob["id"]), f.owner); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Complete(f.ctx, f.sid, str(record["id"]), str(blob["id"]), f.owner); e != nil {
		t.Fatal(e)
	}
	attempt, e := f.s.DB.One(f.ctx, "SELECT id FROM v2_transfer_attempts WHERE blob_id=?", blob["id"])
	if e != nil || attempt == nil {
		t.Fatal("sibling fixture", e)
	}
	return str(attempt["id"])
}
func testMalformedBackoffDoesNotStarveHealthyWork(t *testing.T, postgres bool) {
	f := newFixture(t, postgres)
	f.upload(t)
	badID := str(f.current(t)["id"])
	goodID := addReadySibling(t, f)
	f.update(t, "v2_transfer_attempts", badID, Object{"next_attempt": float64(0)})
	f.update(t, "v2_transfer_attempts", goodID, Object{"next_attempt": float64(1)})
	raw := `{"pending":"unknown"}`
	persistRawLedger(t, f, badID, raw)
	before := f.current(t)
	clockBefore, e := f.s.DB.Now(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	verify, _, e := f.s.Work(f.ctx, 1)
	if e != nil || len(verify) != 1 || verify[0] != badID {
		t.Fatal("bad-first fixture ordering", e)
	}
	_, e = f.s.Process(f.ctx, badID, false)
	errorCode(t, e, "storage_mutation_uncertain")
	clockAfter, e := f.s.DB.Now(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	after := f.current(t)
	if after["state"] != before["state"] || after["token"] != before["token"] || after["lease_until"] != before["lease_until"] {
		t.Fatal("quarantine changed state or owner")
	}
	verify, _, e = f.s.Work(f.ctx, 1)
	if e != nil || len(verify) != 1 || verify[0] != goodID {
		t.Fatal("unknown ledger monopolized the next worker batch")
	}
	if after["last_error"] != "storage_mutation_uncertain" || number(after["next_attempt"]) < clockBefore+float64(f.s.Settings.Worker.RecoverAfter) || number(after["next_attempt"]) > clockAfter+float64(f.s.Settings.Worker.RecoverAfter) {
		t.Fatal("quarantine backoff was not committed using database time")
	}
	assertLedgerPreserved(t, f, badID, raw)
	f.quota(t, 6, 0)
	if f.provider.count("verify") != 0 {
		t.Fatal("quarantine invoked a provider operation")
	}
	f.process(t, goodID, false, "verified")
	if f.provider.count("verify") != 1 {
		t.Fatal("healthy work did not advance")
	}
	assertLedgerPreserved(t, f, badID, raw)
	f.quota(t, 6, 0)
}
func TestMalformedBackoffFairnessSQLite(t *testing.T) {
	testMalformedBackoffDoesNotStarveHealthyWork(t, false)
}
func TestMalformedBackoffFairnessPostgres(t *testing.T) {
	testMalformedBackoffDoesNotStarveHealthyWork(t, true)
}
func testMalformedBackoffPreservesCurrentOwnerAndCategory(t *testing.T, postgres bool) {
	for _, kind := range []string{"active_owner", "wrong_pool"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, postgres)
			f.upload(t)
			id := str(f.current(t)["id"])
			cleanup := false
			if kind == "active_owner" {
				owner, e := f.s.Acquire(f.ctx, id, &cleanup)
				if e != nil || owner == nil {
					t.Fatal("owner fixture", e)
				}
			} else {
				f.update(t, "v2_transfer_attempts", id, Object{"next_attempt": float64(0)})
				cleanup = true
			}
			raw := `"unknown-pending-call"`
			persistRawLedger(t, f, id, raw)
			before := f.current(t)
			acquired, e := f.s.Acquire(f.ctx, id, &cleanup)
			if e != nil || acquired != nil {
				t.Fatal("wrong category or current owner was not preserved", e)
			}
			after := f.current(t)
			for _, field := range []string{"state", "token", "lease_until", "last_error", "next_attempt"} {
				if after[field] != before[field] {
					t.Fatalf("quarantine clobbered %s", field)
				}
			}
			assertLedgerPreserved(t, f, id, raw)
			f.quota(t, 3, 0)
			if f.provider.count("verify") != 0 {
				t.Fatal("nonowner invoked provider")
			}
		})
	}
}
func TestMalformedBackoffOwnerSQLite(t *testing.T) {
	testMalformedBackoffPreservesCurrentOwnerAndCategory(t, false)
}
func TestMalformedBackoffOwnerPostgres(t *testing.T) {
	testMalformedBackoffPreservesCurrentOwnerAndCategory(t, true)
}
