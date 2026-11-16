package service

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
)

func coordError(t *testing.T, err error, code string) {
	t.Helper()
	var actual *domain.Error
	if !errors.As(err, &actual) || actual.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}
func coordService(t *testing.T, profile string) (*Service, domain.Principal, string) {
	t.Helper()
	db, err := store.Open(context.Background(), "sqlite:///:memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Initialize(context.Background(), db); err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := New(db, Options{})
	p := domain.Principal{ID: strings.Repeat("a", 64), Subject: "owner", BootstrapAdmin: true}
	space, err := s.CreateSpace(context.Background(), p, Object{"name": "coordination", "profile": profile}, domain.NewID())
	if err != nil {
		t.Fatal(err)
	}
	return s, p, str(space["id"])
}
func coordType(t *testing.T, s *Service, p domain.Principal, sid, kind string) string {
	t.Helper()
	row, err := s.RegisterType(context.Background(), p, sid, kind, Object{"schema": Object{"type": "object", "additionalProperties": true}}, domain.NewID())
	if err != nil {
		t.Fatal(err)
	}
	return str(row["id"])
}
func coordPublished(t *testing.T, s *Service, p domain.Principal, sid, kind, revision string, metadata Object) Object {
	t.Helper()
	row, err := s.CreateRecord(context.Background(), p, sid, Object{"kind": kind, "schema_revision_id": revision, "metadata": metadata, "attachments": []any{}}, domain.NewID())
	if err != nil {
		t.Fatal(err)
	}
	row, err = s.PublishRecord(context.Background(), p, sid, str(row["id"]), domain.NewID())
	if err != nil {
		t.Fatal(err)
	}
	return row
}
func coordMember(t *testing.T, s *Service, owner domain.Principal, sid, id string, roles []string, bindings Object) domain.Principal {
	t.Helper()
	p := domain.Principal{ID: id, Subject: id}
	if _, err := s.PutMember(context.Background(), owner, sid, id, Object{"subject": id, "roles": roles, "bindings": bindings}); err != nil {
		t.Fatal(err)
	}
	return p
}
func coordBase(t *testing.T, s *Service, p domain.Principal, sid string) Object {
	t.Helper()
	revision := coordType(t, s, p, sid, "asset")
	record := coordPublished(t, s, p, sid, "asset", revision, Object{})
	if _, err := s.PutReference(context.Background(), p, sid, "main", Object{"record_id": record["id"]}, "*", domain.NewID()); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestCoordinationReferenceCASAndAuthorization(t *testing.T) {
	s, p, sid := coordService(t, "generic.v1")
	revision := coordType(t, s, p, sid, "asset")
	first := coordPublished(t, s, p, sid, "asset", revision, Object{})
	second := coordPublished(t, s, p, sid, "asset", revision, Object{})
	ctx := context.Background()
	body := Object{"record_id": first["id"]}
	row, err := s.PutReference(ctx, p, sid, "main", body, "*", "initial")
	if err != nil || row["token"] != "1" {
		t.Fatalf("initial reference: %v %v", row, err)
	}
	row, err = s.PutReference(ctx, p, sid, "main", body, "*", "initial")
	if err != nil || row["token"] != "1" {
		t.Fatalf("idempotent initial reference: %v %v", row, err)
	}
	_, err = s.PutReference(ctx, p, sid, "main", Object{"record_id": second["id"]}, "*", "initial")
	coordError(t, err, "idempotency_conflict")
	_, err = s.PutReference(ctx, p, sid, "main", Object{"record_id": second["id"]}, "wrong", "bad-version")
	coordError(t, err, "reference_version_mismatch")
	row, err = s.PutReference(ctx, p, sid, "main", Object{"record_id": second["id"]}, "1", "advance")
	if err != nil || row["token"] != "2" {
		t.Fatalf("CAS advance: %v %v", row, err)
	}
	reader := coordMember(t, s, p, sid, strings.Repeat("b", 64), []string{"reader"}, Object{})
	admin := coordMember(t, s, p, sid, strings.Repeat("c", 64), []string{"admin"}, Object{})
	if row, err = s.GetReference(ctx, reader, sid, "main"); err != nil || row["record_id"] != second["id"] {
		t.Fatalf("reader: %v %v", row, err)
	}
	_, err = s.GetReference(ctx, admin, sid, "main")
	coordError(t, err, "record_not_found")
	_, err = s.PutReference(ctx, reader, sid, "main", body, "2", domain.NewID())
	coordError(t, err, "role_required")
	_, err = s.GetReference(ctx, p, sid, "bad/name")
	coordError(t, err, "invalid_reference_name")
	_, err = s.GetReference(ctx, p, sid, "missing")
	coordError(t, err, "reference_not_found")
}

func TestCoordinationLifecycleFencesAndReplay(t *testing.T) {
	s, p, sid := coordService(t, "generic.v1")
	base := coordBase(t, s, p, sid)
	other := coordMember(t, s, p, sid, strings.Repeat("b", 64), []string{"publisher"}, Object{})
	ctx := context.Background()
	body := Object{"reference": "main", "expected_token": "1", "lease_seconds": int64(10)}
	first, err := s.Acquire(ctx, p, sid, body, "acquire")
	if err != nil {
		t.Fatal(err)
	}
	fence := num(first["fence"])
	replayed, err := s.Acquire(ctx, p, sid, body, "acquire")
	if err != nil || replayed["id"] != first["id"] {
		t.Fatalf("acquisition replay %v %v", replayed, err)
	}
	_, err = s.Acquire(ctx, other, sid, body, "other")
	coordError(t, err, "acquisition_busy")
	_, err = s.Renew(ctx, other, sid, str(first["id"]), fence)
	coordError(t, err, "acquisition_holder_required")
	_, err = s.Renew(ctx, p, sid, str(first["id"]), fence+1)
	coordError(t, err, "acquisition_not_active")
	renewed, err := s.Renew(ctx, p, sid, str(first["id"]), fence)
	if err != nil || decimal(renewed["lease_until"]) <= decimal(first["lease_until"]) {
		t.Fatalf("renew did not extend authoritative lease %v %v", renewed, err)
	}
	_, err = s.PutReference(ctx, p, sid, "main", Object{"record_id": base["id"]}, "1", "during-acquisition")
	coordError(t, err, "acquisition_active")
	completed, err := s.Complete(ctx, p, sid, str(first["id"]), Object{"fence": fence, "result_record_id": base["id"]}, "complete")
	if err != nil || completed["state"] != "completed" {
		t.Fatalf("completion %v %v", completed, err)
	}
	ref, err := s.GetReference(ctx, p, sid, "main")
	if err != nil || ref["token"] != "2" {
		t.Fatalf("completed ref %v %v", ref, err)
	}
	replayed, err = s.Complete(ctx, p, sid, str(first["id"]), Object{"fence": fence, "result_record_id": base["id"]}, "different-key")
	if err != nil || replayed["id"] != first["id"] {
		t.Fatalf("completion replay %v %v", replayed, err)
	}
	_, err = s.Complete(ctx, p, sid, str(first["id"]), Object{"fence": fence + 1, "result_record_id": base["id"]}, "conflict")
	coordError(t, err, "completion_conflict")
	_, err = s.Abandon(ctx, p, sid, str(first["id"]), fence)
	coordError(t, err, "acquisition_not_active")

	nextBody := Object{"reference": "main", "expected_token": "2", "lease_seconds": int64(10)}
	next, err := s.Acquire(ctx, p, sid, nextBody, "next")
	if err != nil || num(next["fence"]) <= fence {
		t.Fatalf("next fence %v %v", next, err)
	}
	if err = s.DB.Update(ctx, "v2_coordinations", Object{"id": next["id"]}, Object{"lease_until": float64(0)}); err != nil {
		t.Fatal(err)
	}
	_, err = s.Acquire(ctx, p, sid, nextBody, "next")
	coordError(t, err, "acquisition_expired")
	newer, err := s.Acquire(ctx, other, sid, nextBody, "newer")
	if err != nil || num(newer["fence"]) <= num(next["fence"]) {
		t.Fatalf("takeover fence %v %v", newer, err)
	}
	_, err = s.Complete(ctx, p, sid, str(next["id"]), Object{"fence": next["fence"], "result_record_id": base["id"]}, "late")
	coordError(t, err, "acquisition_not_active")
	abandoned, err := s.Abandon(ctx, other, sid, str(newer["id"]), num(newer["fence"]))
	if err != nil || abandoned["state"] != "abandoned" {
		t.Fatalf("abandon %v %v", abandoned, err)
	}
	_, err = s.Acquire(ctx, other, sid, nextBody, "newer")
	coordError(t, err, "acquisition_not_active")
}

func TestCoordinationFedAvgSelectionAndCurrentParticipant(t *testing.T) {
	s, p, sid := coordService(t, "fedavg.v1")
	ctx := context.Background()
	globalType := coordType(t, s, p, sid, "model.global")
	updateType := coordType(t, s, p, sid, "training.update")
	base := coordPublished(t, s, p, sid, "model.global", globalType, Object{})
	if _, err := s.PutReference(ctx, p, sid, "main", Object{"record_id": base["id"]}, "*", "initial"); err != nil {
		t.Fatal(err)
	}
	alice := coordMember(t, s, p, sid, strings.Repeat("b", 64), []string{"contributor"}, Object{"participant": "alice"})
	bob := coordMember(t, s, p, sid, strings.Repeat("c", 64), []string{"contributor"}, Object{"participant": "bob"})
	older := coordPublished(t, s, alice, sid, "training.update", updateType, Object{"base_record_id": base["id"], "sample_count": int64(16)})
	newest := coordPublished(t, s, alice, sid, "training.update", updateType, Object{"base_record_id": base["id"], "sample_count": int64(16)})
	bobUpdate := coordPublished(t, s, bob, sid, "training.update", updateType, Object{"base_record_id": base["id"], "sample_count": int64(24)})
	// Deterministically make the second Alice update latest, independent of clock granularity.
	if err := s.DB.Update(ctx, "v2_records", Object{"id": older["id"]}, Object{"published_at": float64(1)}); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Update(ctx, "v2_records", Object{"id": newest["id"]}, Object{"published_at": float64(2)}); err != nil {
		t.Fatal(err)
	}
	_, err := s.Acquire(ctx, p, sid, Object{"reference": "main", "expected_token": "1", "input_record_ids": []string{str(older["id"]), str(bobUpdate["id"])}}, "stale-input")
	coordError(t, err, "profile_input_selection_mismatch")
	attempt, err := s.Acquire(ctx, p, sid, Object{"reference": "main", "expected_token": "1"}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	ids := stringsOf(attempt["input_record_ids"])
	want := []string{str(newest["id"]), str(bobUpdate["id"])}
	sort.Strings(want)
	if !equal(ids, want) {
		t.Fatalf("selected %v want %v", ids, want)
	}
	result := coordPublished(t, s, p, sid, "model.global", globalType, Object{"base_record_id": base["id"], "inputs": want})
	if _, err = s.PutMember(ctx, p, sid, alice.ID, Object{"subject": alice.Subject, "roles": []string{"contributor"}, "bindings": Object{"participant": "alice-changed"}}); err != nil {
		t.Fatal(err)
	}
	completeBody := Object{"fence": attempt["fence"], "result_record_id": result["id"]}
	_, err = s.Complete(ctx, p, sid, str(attempt["id"]), completeBody, "complete")
	coordError(t, err, "input_participant_revoked")
	ref, err := s.GetReference(ctx, p, sid, "main")
	if err != nil || ref["record_id"] != base["id"] || ref["token"] != "1" {
		t.Fatalf("failed completion changed reference %v %v", ref, err)
	}
	if _, err = s.PutMember(ctx, p, sid, alice.ID, Object{"subject": alice.Subject, "roles": []string{"contributor"}, "bindings": Object{"participant": "alice"}}); err != nil {
		t.Fatal(err)
	}
	completed, err := s.Complete(ctx, p, sid, str(attempt["id"]), completeBody, "complete")
	if err != nil || completed["state"] != "completed" {
		t.Fatalf("eligible completion %v %v", completed, err)
	}
	ref, err = s.GetReference(ctx, p, sid, "main")
	if err != nil || ref["record_id"] != result["id"] || ref["token"] != "2" {
		t.Fatalf("new global %v %v", ref, err)
	}
}

func TestCoordinationRejectsMalformedAcquisitionInputs(t *testing.T) {
	for _, test := range []struct {
		name  string
		field string
		value any
		code  string
	}{
		{"reference-integer", "reference", int64(1), "invalid_reference_name"},
		{"reference-boolean", "reference", true, "invalid_reference_name"},
		{"duplicates", "input_record_ids", []string{"x", "x"}, "invalid_input_records"},
		{"non-array", "input_record_ids", Object{}, "invalid_input_records"},
		{"boolean-id", "input_record_ids", []any{true}, "invalid_input_records"},
		{"too-short", "lease_seconds", int64(9), "invalid_lease_seconds"},
		{"float", "lease_seconds", float64(10), "invalid_lease_seconds"},
		{"boolean", "lease_seconds", true, "invalid_lease_seconds"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, p, sid := coordService(t, "generic.v1")
			base := coordBase(t, s, p, sid)
			if test.field == "reference" {
				if _, err := s.PutReference(context.Background(), p, sid, str(test.value), Object{"record_id": base["id"]}, "*", domain.NewID()); err != nil {
					t.Fatal(err)
				}
			}
			body := Object{"reference": "main", "expected_token": "1", test.field: test.value}
			_, err := s.Acquire(context.Background(), p, sid, body, "invalid")
			coordError(t, err, test.code)
			rows, err := s.DB.All(context.Background(), "SELECT id FROM v2_coordinations")
			if err != nil || len(rows) != 0 {
				t.Fatalf("invalid acquisition persisted %v %v", rows, err)
			}
		})
	}
}

func TestCoordinationPostgresConcurrentAcquire(t *testing.T) {
	base := os.Getenv("HF2L_GO_EXCHANGE_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("set HF2L_GO_EXCHANGE_TEST_DATABASE_URL to a disposable PostgreSQL database")
	}
	ctx := context.Background()
	admin, err := store.Open(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	schemaName := "go_coord_" + domain.NewID()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schemaName); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Exec(context.Background(), "DROP SCHEMA "+schemaName+" CASCADE"); admin.Close() })
	parsed, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schemaName)
	parsed.RawQuery = query.Encode()
	db, err := store.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err = store.Initialize(ctx, db); err != nil {
		t.Fatal(err)
	}
	s := New(db, Options{})
	p := domain.Principal{ID: strings.Repeat("a", 64), Subject: "owner", BootstrapAdmin: true}
	space, err := s.CreateSpace(ctx, p, Object{"name": "concurrent"}, domain.NewID())
	if err != nil {
		t.Fatal(err)
	}
	sid := str(space["id"])
	coordBase(t, s, p, sid)
	other := coordMember(t, s, p, sid, strings.Repeat("b", 64), []string{"publisher"}, Object{})
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, principal := range []domain.Principal{p, other} {
		wg.Add(1)
		go func(principal domain.Principal) {
			defer wg.Done()
			<-start
			_, err := s.Acquire(ctx, principal, sid, Object{"reference": "main", "expected_token": "1"}, domain.NewID())
			results <- err
		}(principal)
	}
	close(start)
	wg.Wait()
	close(results)
	winners, busy := 0, 0
	for err := range results {
		if err == nil {
			winners++
			continue
		}
		var public *domain.Error
		if errors.As(err, &public) && public.Code == "acquisition_busy" {
			busy++
		} else {
			t.Fatalf("unexpected concurrent result %v", err)
		}
	}
	if winners != 1 || busy != 1 {
		t.Fatalf("winners%d busy%d", winners, busy)
	}
	ref, err := db.One(ctx, "SELECT fence FROM v2_references WHERE space_id=? AND name='main'", sid)
	if err != nil || num(ref["fence"]) != 1 {
		t.Fatalf("fence %v %v", ref, err)
	}
	t.Run("EventsJSONVisibility", func(t *testing.T) {
		reader := coordMember(t, s, p, sid, strings.Repeat("d", 64), []string{"reader"}, Object{})
		revision := coordType(t, s, p, sid, "unreferenced")
		record := coordPublished(t, s, p, sid, "unreferenced", revision, Object{"private": "content"})
		if _, err = s.WithdrawRecord(ctx, p, sid, str(record["id"])); err != nil {
			t.Fatal(err)
		}
		if _, err = s.PurgeRecord(ctx, p, sid, str(record["id"])); err != nil {
			t.Fatal(err)
		}
		result, err := s.Events(ctx, reader, sid, 0, 1000)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, event := range eventItems(t, result) {
			if event["record_id"] == record["id"] {
				if event["type"] != "record.withdrawn" || !equal(event["payload"], Object{"state": "withdrawn"}) {
					t.Fatalf("invalid PostgreSQL tombstone %v", event)
				}
				found = true
			}
		}
		if !found {
			t.Fatal("PostgreSQL JSONB tombstone not visible")
		}
		if _, err = s.PutPolicy(ctx, p, sid, "unreferenced", Object{"publish_roles": []string{"contributor", "publisher"}, "visibility": "private"}); err != nil {
			t.Fatal(err)
		}
		result, err = s.Events(ctx, reader, sid, 0, 1000)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range eventItems(t, result) {
			if event["record_id"] == record["id"] {
				t.Fatalf("PostgreSQL private tombstone leaked %v", event)
			}
		}
	})
}

func TestCoordinationRetainedStateAcrossRestarts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	url := "sqlite:///" + filepath.Join(t.TempDir(), "exchange.db")
	open := func(initialize bool) (*store.DB, *Service) {
		t.Helper()
		db, err := store.Open(ctx, url)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		if initialize {
			err = store.Initialize(ctx, db)
		} else {
			err = store.Check(ctx, db)
		}
		if err != nil {
			t.Fatal(err)
		}
		return db, New(db, Options{})
	}
	p := domain.Principal{ID: domain.PrincipalID("https://issuer.example", "owner"), Subject: "owner", BootstrapAdmin: true}
	db, s := open(true)
	space, err := s.CreateSpace(ctx, p, Object{"name": "Restart continuation", "profile": "generic.v1"}, "restart-space")
	if err != nil {
		t.Fatal(err)
	}
	sid := str(space["id"])
	revision := coordType(t, s, p, sid, "asset")
	record := coordPublished(t, s, p, sid, "asset", revision, Object{"stage": "seed"})
	if _, err = s.PutReference(ctx, p, sid, "main", Object{"record_id": record["id"]}, "*", "initial"); err != nil {
		t.Fatal(err)
	}
	first, err := s.Acquire(ctx, p, sid, Object{"reference": "main", "expected_token": "1", "lease_seconds": int64(300)}, "first")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	// A distinct service and connection pool must honor the first process's
	// durable operation receipts and coordination authority after restart.
	db, s = open(false)
	replayedSpace, err := s.CreateSpace(ctx, p, Object{"name": "Restart continuation", "profile": "generic.v1"}, "restart-space")
	if err != nil || replayedSpace["id"] != sid || num(replayedSpace["record_count"]) != 0 {
		t.Fatalf("space operation replay: %v %v", replayedSpace, err)
	}
	replayed, err := s.Acquire(ctx, p, sid, Object{"reference": "main", "expected_token": "1", "lease_seconds": int64(300)}, "first")
	if err != nil || replayed["id"] != first["id"] || replayed["fence"] != first["fence"] {
		t.Fatalf("retained acquisition replay: %v %v", replayed, err)
	}
	done, err := s.Complete(ctx, p, sid, str(first["id"]), Object{"fence": first["fence"], "result_record_id": record["id"]}, "first-complete")
	if err != nil || done["state"] != "completed" {
		t.Fatalf("complete retained acquisition: %v %v", done, err)
	}
	second, err := s.Acquire(ctx, p, sid, Object{"reference": "main", "expected_token": "2", "lease_seconds": int64(300)}, "second")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	db, s = open(false)
	replayed, err = s.Acquire(ctx, p, sid, Object{"reference": "main", "expected_token": "2", "lease_seconds": int64(300)}, "second")
	if err != nil || replayed["id"] != second["id"] || replayed["fence"] != second["fence"] {
		t.Fatalf("second acquisition replay: %v %v", replayed, err)
	}
	done, err = s.Complete(ctx, p, sid, str(second["id"]), Object{"fence": second["fence"], "result_record_id": record["id"]}, "second-complete")
	if err != nil || done["state"] != "completed" {
		t.Fatalf("second completion: %v %v", done, err)
	}
	done, err = s.Complete(ctx, p, sid, str(first["id"]), Object{"fence": first["fence"], "result_record_id": record["id"]}, "new-key-after-restart")
	if err != nil || done["state"] != "completed" {
		t.Fatalf("first completion replay: %v %v", done, err)
	}
	_, err = s.Renew(ctx, p, sid, str(first["id"]), num(first["fence"]))
	coordError(t, err, "acquisition_not_active")
	ref, err := s.GetReference(ctx, p, sid, "main")
	if err != nil || ref["token"] != "3" || ref["record_id"] != record["id"] {
		t.Fatalf("retained reference: %v %v", ref, err)
	}
	for _, scope := range []string{"scope='acquisition.create'", "scope LIKE 'acquisition.complete:%'"} {
		operations, err := db.One(ctx, "SELECT COUNT(*) AS count FROM v2_operations WHERE "+scope)
		if err != nil || num(operations["count"]) != 2 {
			t.Fatalf("duplicate durable effects: %v %v", operations, err)
		}
	}
}
