package service

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
)

func newCoreFixture(t *testing.T) (*Service, domain.Principal, string, Object) {
	t.Helper()
	ctx := context.Background()
	db, e := store.Open(ctx, "sqlite:///"+filepath.Join(t.TempDir(), "exchange.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = db.Close() })
	if e = store.Initialize(ctx, db); e != nil {
		t.Fatal(e)
	}
	p := domain.Principal{ID: domain.PrincipalID("https://identity.example", "owner"), Subject: "owner", BootstrapAdmin: true}
	s := New(db, Options{Auth: AuthOptions{AdminSubject: "owner"}})
	space, e := s.CreateSpace(ctx, p, Object{"name": "Core federation"}, "space")
	if e != nil {
		t.Fatal(e)
	}
	sid := str(space["id"])
	revision, e := s.RegisterType(ctx, p, sid, "artifact", Object{"schema": Object{"type": "object"}}, "type")
	if e != nil {
		t.Fatal(e)
	}
	return s, p, sid, revision
}
func coreError(t *testing.T, e error, code string) {
	t.Helper()
	var typed *domain.Error
	if !errors.As(e, &typed) || typed.Code != code {
		t.Fatalf("got %T %v, want %s", e, e, code)
	}
}
func coreCreate(t *testing.T, s *Service, p domain.Principal, sid string, revision Object, key string, extra Object) Object {
	t.Helper()
	body := Object{"kind": revision["kind"], "schema_revision_id": revision["id"], "metadata": Object{}}
	for k, v := range extra {
		body[k] = v
	}
	record, e := s.CreateRecord(context.Background(), p, sid, body, key)
	if e != nil {
		t.Fatal(e)
	}
	return record
}
func coreMember(t *testing.T, s *Service, owner domain.Principal, sid, subject string, roles []string) domain.Principal {
	t.Helper()
	p := domain.Principal{ID: domain.PrincipalID("https://identity.example", subject), Subject: subject}
	if _, e := s.PutMember(context.Background(), owner, sid, p.ID, Object{"roles": roles}); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestSpaceIdentityLimitsAndIdempotency(t *testing.T) {
	s, p, sid, _ := newCoreFixture(t)
	ctx := context.Background()
	space, e := s.CreateSpace(ctx, p, Object{"name": "Core federation"}, "space")
	if e != nil || str(space["id"]) != sid {
		t.Fatalf("replay: %v %v", space, e)
	}
	hash, e := domain.Hash([]any{p.ID, "space"})
	if e != nil || sid != hash[:32] {
		t.Fatal("stable space hash mismatch")
	}
	_, e = s.CreateSpace(ctx, p, Object{"name": "conflict"}, "space")
	coreError(t, e, "idempotency_conflict")
	_, e = s.CreateSpace(ctx, domain.Principal{ID: p.ID, Subject: "other"}, Object{"name": "forbidden"}, "foreign")
	coreError(t, e, "bootstrap_admin_required")
	for _, v := range []any{true, float64(1), int64(0), json.Number("9223372036854775808")} {
		_, e = s.CreateSpace(ctx, p, Object{"name": "invalid", "quota_bytes": v}, domain.NewID())
		coreError(t, e, "invalid_quota")
	}
	_, e = s.UpdateSpaceLimits(ctx, p, sid, Object{"unknown": 1})
	coreError(t, e, "invalid_quota_fields")
	_, e = s.UpdateSpaceLimits(ctx, p, sid, Object{})
	coreError(t, e, "invalid_quota_fields")
	_, e = s.UpdateSpaceLimits(ctx, p, sid, Object{"quota_records": int64(1)})
	if e != nil {
		t.Fatal(e)
	}
}
func TestCurrentMembershipAndLastAdmin(t *testing.T) {
	s, owner, sid, _ := newCoreFixture(t)
	ctx := context.Background()
	_, e := s.PutMember(ctx, owner, sid, owner.ID, Object{"roles": []string{"reader"}})
	coreError(t, e, "last_admin")
	other := coreMember(t, s, owner, sid, "other-admin", []string{"admin"})
	if _, e = s.PutMember(ctx, other, sid, owner.ID, Object{"roles": []string{}}); e != nil {
		t.Fatal(e)
	}
	_, e = s.GetSpace(ctx, owner, sid)
	coreError(t, e, "space_not_found")
	_, e = s.CreateSpace(ctx, owner, Object{"name": "Core federation"}, "space")
	coreError(t, e, "space_not_found")
	members, e := s.ListMembers(ctx, other, sid)
	if e != nil || len(members["items"].([]Object)) != 2 {
		t.Fatalf("members: %v %v", members, e)
	}
}
func TestRecordVisibilityCASAndImmutablePublication(t *testing.T) {
	s, owner, sid, rev := newCoreFixture(t)
	ctx := context.Background()
	alice := coreMember(t, s, owner, sid, "alice", []string{"contributor"})
	bob := coreMember(t, s, owner, sid, "bob", []string{"contributor"})
	reader := coreMember(t, s, owner, sid, "reader", []string{"reader"})
	publisher := coreMember(t, s, owner, sid, "publisher", []string{"publisher"})
	admin := coreMember(t, s, owner, sid, "admin-only", []string{"admin"})
	r := coreCreate(t, s, alice, sid, rev, "draft", Object{"metadata": Object{"value": 1}})
	rid := str(r["id"])
	_, e := s.GetRecord(ctx, bob, sid, rid)
	coreError(t, e, "record_not_found")
	_, e = s.GetRecord(ctx, admin, sid, rid)
	coreError(t, e, "record_not_found")
	_, e = s.PatchRecord(ctx, bob, sid, rid, Object{"metadata": Object{}}, "1")
	coreError(t, e, "record_owner_required")
	_, e = s.PatchRecord(ctx, alice, sid, rid, Object{"metadata": Object{"value": 2}}, "2")
	coreError(t, e, "record_version_mismatch")
	r, e = s.PatchRecord(ctx, alice, sid, rid, Object{"metadata": Object{"value": 2}}, "1")
	if e != nil || num(r["version"]) != 2 {
		t.Fatalf("patch %v %v", r, e)
	}
	r, e = s.PublishRecord(ctx, alice, sid, rid, "publish")
	if e != nil || num(r["version"]) != 3 {
		t.Fatalf("publish %v %v", r, e)
	}
	for _, p := range []domain.Principal{reader, bob, publisher} {
		if _, e = s.GetRecord(ctx, p, sid, rid); e != nil {
			t.Fatal(e)
		}
	}
	_, e = s.GetRecord(ctx, admin, sid, rid)
	coreError(t, e, "record_not_found")
	_, e = s.PatchRecord(ctx, alice, sid, rid, Object{"metadata": Object{}}, "3")
	coreError(t, e, "record_not_draft")
	replay, e := s.PublishRecord(ctx, alice, sid, rid, "publish")
	if e != nil || !equal(replay, r) {
		t.Fatalf("publish replay: %v", e)
	}
	if _, e = s.PutPolicy(ctx, owner, sid, "artifact", Object{"visibility": "private"}); e != nil {
		t.Fatal(e)
	}
	_, e = s.GetRecord(ctx, reader, sid, rid)
	coreError(t, e, "record_not_found")
	if _, e = s.GetRecord(ctx, publisher, sid, rid); e != nil {
		t.Fatal(e)
	}
	_, e = s.PublishRecord(ctx, bob, sid, rid, "publish")
	coreError(t, e, "record_owner_required")
}
func TestRecordAdmissionRollbackAndQuotaOverflow(t *testing.T) {
	s, p, sid, rev := newCoreFixture(t)
	ctx := context.Background()
	digest := strings.Repeat("a", 64)
	body := Object{"kind": "artifact", "schema_revision_id": rev["id"], "metadata": Object{}, "attachments": []Object{{"path": "model.bin", "size": int64(6), "sha256": digest}}}
	if _, e := s.UpdateSpaceLimits(ctx, p, sid, Object{"quota_bytes": int64(10), "principal_quota_bytes": int64(10)}); e != nil {
		t.Fatal(e)
	}
	r, e := s.CreateRecord(ctx, p, sid, body, "first")
	if e != nil {
		t.Fatal(e)
	}
	replay, e := s.CreateRecord(ctx, p, sid, body, "first")
	if e != nil || !equal(r, replay) {
		t.Fatal("replay changed admitted record", e)
	}
	_, e = s.CreateRecord(ctx, p, sid, body, "second")
	coreError(t, e, "blob_quota_exceeded")
	row, e := s.DB.One(ctx, "SELECT record_count,allocated FROM v2_spaces WHERE id=?", sid)
	if e != nil || num(row["record_count"]) != 1 || num(row["allocated"]) != 6 {
		t.Fatalf("quota rollback failed %v %v", row, e)
	}
	if _, e = s.WithdrawRecord(ctx, p, sid, str(r["id"])); e != nil {
		t.Fatal(e)
	}
	row, e = s.DB.One(ctx, "SELECT allocated,reclaiming FROM v2_spaces WHERE id=?", sid)
	if e != nil || num(row["allocated"]) != 0 || num(row["reclaiming"]) != 0 {
		t.Fatalf("never-started release %v %v", row, e)
	}
	if _, e = s.PurgeRecord(ctx, p, sid, str(r["id"])); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(ctx, "UPDATE v2_spaces SET quota_bytes=?,allocated=?,reclaiming=? WHERE id=?", int64(math.MaxInt64), int64(math.MaxInt64-5), int64(0), sid); e != nil {
		t.Fatal(e)
	}
	_, e = s.CreateRecord(ctx, p, sid, body, "overflow")
	coreError(t, e, "blob_quota_exceeded")
}
func TestAttachmentPathsAndStrictDeclarations(t *testing.T) {
	s, p, sid, rev := newCoreFixture(t)
	ctx := context.Background()
	digest := strings.Repeat("a", 64)
	pairs := [][]string{{"straße.bin", "STRASSE.bin"}, {"a", "a/b"}, {"a/b", "a"}, {"Σ", "ς"}, {"K", "k"}}
	for _, pair := range pairs {
		_, e := s.CreateRecord(ctx, p, sid, Object{"kind": "artifact", "schema_revision_id": rev["id"], "attachments": []Object{{"path": pair[0], "size": int64(0), "sha256": digest}, {"path": pair[1], "size": int64(0), "sha256": digest}}}, domain.NewID())
		coreError(t, e, "duplicate_attachment_path")
	}
	for _, value := range []any{true, float64(0), int64(-1), int64(5*1024*1024*1024*1024 + 1)} {
		_, e := s.CreateRecord(ctx, p, sid, Object{"kind": "artifact", "schema_revision_id": rev["id"], "attachments": []Object{{"path": "model", "size": value, "sha256": digest}}}, domain.NewID())
		coreError(t, e, "invalid_attachment_size")
	}
	if _, e := s.UpdateSpaceLimits(ctx, p, sid, Object{"quota_bytes": int64(6 * 1024 * 1024 * 1024 * 1024), "principal_quota_bytes": int64(6 * 1024 * 1024 * 1024 * 1024)}); e != nil {
		t.Fatal(e)
	}
	r := coreCreate(t, s, p, sid, rev, "large-part", Object{"attachments": []Object{{"path": "huge", "size": int64(5 * 1024 * 1024 * 1024 * 1024), "sha256": digest}}})
	if num(r["attachments"].([]Object)[0]["part_size"]) != 525*1048576 {
		t.Fatal("large-attachment multipart sizing mismatch")
	}
}
func TestBlobPublishAndDurableReclamation(t *testing.T) {
	s, p, sid, rev := newCoreFixture(t)
	ctx := context.Background()
	digest := strings.Repeat("b", 64)
	r := coreCreate(t, s, p, sid, rev, "record", Object{"attachments": []Object{{"path": "checkpoint", "size": int64(12), "sha256": digest}}})
	rid := str(r["id"])
	bid := str(r["attachments"].([]Object)[0]["id"])
	_, e := s.PublishRecord(ctx, p, sid, rid, "not-ready")
	coreError(t, e, "attachments_not_verified")
	if _, e = s.DB.Exec(ctx, "UPDATE v2_blobs SET state=?,object_key=?,object_version=?,verified_size=?,verified_sha256=? WHERE id=?", "verified", "opaque", "v1", int64(12), digest, bid); e != nil {
		t.Fatal(e)
	}
	if _, e = s.PublishRecord(ctx, p, sid, rid, "ready"); e != nil {
		t.Fatal(e)
	}
	now, e := s.DB.Now(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.DB.Insert(ctx, "v2_transfer_attempts", Object{"id": "owned-attempt", "blob_id": bid, "object_key": "opaque", "state": "verified", "grant_expires_at": now + 300, "mutation_tokens": []string{"put-in-flight"}}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.WithdrawRecord(ctx, p, sid, rid); e != nil {
		t.Fatal(e)
	}
	space, e := s.DB.One(ctx, "SELECT * FROM v2_spaces WHERE id=?", sid)
	if e != nil || num(space["allocated"]) != 0 || num(space["reclaiming"]) != 12 {
		t.Fatalf("physical charge prematurely released %v %v", space, e)
	}
	attempt, e := s.DB.One(ctx, "SELECT * FROM v2_transfer_attempts WHERE id=?", "owned-attempt")
	if e != nil || str(attempt["state"]) != "cleanup" || decimal(attempt["next_attempt"]) < now+300 || len(stringsOf(attempt["mutation_tokens"])) != 1 {
		t.Fatalf("cleanup fence lost %v %v", attempt, e)
	}
	_, e = s.PurgeRecord(ctx, p, sid, rid)
	coreError(t, e, "cleanup_pending")
	if _, e = s.DB.Exec(ctx, "UPDATE v2_blobs SET state=? WHERE id=?", "cleaned", bid); e != nil {
		t.Fatal(e)
	}
	_, e = s.PurgeRecord(ctx, p, sid, rid)
	coreError(t, e, "cleanup_pending")
}
func TestPrincipalQuotaIncludesReclaiming(t *testing.T) {
	s, p, sid, rev := newCoreFixture(t)
	ctx := context.Background()
	digest := strings.Repeat("c", 64)
	if _, e := s.UpdateSpaceLimits(ctx, p, sid, Object{"quota_bytes": int64(100), "principal_quota_bytes": int64(10)}); e != nil {
		t.Fatal(e)
	}
	r := coreCreate(t, s, p, sid, rev, "one", Object{"attachments": []Object{{"path": "model", "size": int64(7), "sha256": digest}}})
	bid := str(r["attachments"].([]Object)[0]["id"])
	if e := s.DB.Insert(ctx, "v2_transfer_attempts", Object{"id": "attempt", "blob_id": bid, "object_key": "key"}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.WithdrawRecord(ctx, p, sid, str(r["id"])); e != nil {
		t.Fatal(e)
	}
	_, e := s.CreateRecord(ctx, p, sid, Object{"kind": "artifact", "schema_revision_id": rev["id"], "attachments": []Object{{"path": "new", "size": int64(4), "sha256": digest}}}, "two")
	coreError(t, e, "principal_blob_quota_exceeded")
	_, e = s.UpdateSpaceLimits(ctx, p, sid, Object{"principal_quota_bytes": int64(6)})
	coreError(t, e, "quota_below_current_usage")
}
func TestBoundMetadataAndTypePolicies(t *testing.T) {
	s, p, sid, rev := newCoreFixture(t)
	ctx := context.Background()
	nested := Object{}
	cursor := nested
	for i := 0; i < 18; i++ {
		n := Object{}
		cursor["next"] = n
		cursor = n
	}
	_, e := s.CreateRecord(ctx, p, sid, Object{"kind": "artifact", "schema_revision_id": rev["id"], "metadata": nested}, "deep")
	coreError(t, e, "metadata_too_deep")
	_, e = s.RegisterType(ctx, p, sid, "bad kind", Object{"schema": Object{"type": "object"}}, "bad")
	coreError(t, e, "invalid_kind")
	_, e = s.PutPolicy(ctx, p, sid, "artifact", Object{"publish_roles": []string{"admin"}})
	coreError(t, e, "invalid_publish_roles")
	revision, e := s.RegisterType(ctx, p, sid, "typed", Object{"schema": Object{"type": "object", "properties": Object{"value": Object{"type": "integer"}}, "required": []string{"value"}, "additionalProperties": false}}, "typed")
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.CreateRecord(ctx, p, sid, Object{"kind": "typed", "schema_revision_id": revision["id"], "metadata": Object{"value": true}}, "bad-metadata")
	coreError(t, e, "metadata_schema_mismatch")
}
func TestPythonBindingEqualityDistinctFromIdempotencyHash(t *testing.T) {
	if !equal(Object{"n": int64(1), "b": true}, Object{"n": float64(1), "b": json.Number("1")}) {
		t.Fatal("Python binding equality lost")
	}
	if equal(json.Number("9007199254740993"), float64(9007199254740992)) {
		t.Fatal("large integer rounded during binding equality")
	}
	s, p, sid, rev := newCoreFixture(t)
	ctx := context.Background()
	first := Object{"kind": "artifact", "schema_revision_id": rev["id"], "metadata": Object{"n": int64(1)}}
	if _, e := s.CreateRecord(ctx, p, sid, first, "number"); e != nil {
		t.Fatal(e)
	}
	first["metadata"] = Object{"n": float64(1)}
	_, e := s.CreateRecord(ctx, p, sid, first, "number")
	coreError(t, e, "idempotency_conflict")
}

func TestPurgeMalformedMutationMarkersRemainFenced(t *testing.T) {
	for name, markers := range malformedCoreMutationLedgers() {
		t.Run(name, func(t *testing.T) {
			s, p, sid, rev := newCoreFixture(t)
			ctx := context.Background()
			r := coreCreate(t, s, p, sid, rev, "record", Object{"attachments": []Object{{"path": "file", "size": int64(1), "sha256": strings.Repeat("d", 64)}}})
			rid := str(r["id"])
			bid := str(r["attachments"].([]Object)[0]["id"])
			if e := s.DB.Insert(ctx, "v2_transfer_attempts", Object{"id": "attempt", "blob_id": bid, "object_key": "private-key", "mutation_tokens": markers}); e != nil {
				t.Fatal(e)
			}
			if _, e := s.WithdrawRecord(ctx, p, sid, rid); e != nil {
				t.Fatal(e)
			}
			if _, e := s.DB.Exec(ctx, "UPDATE v2_blobs SET state=? WHERE id=?", "cleaned", bid); e != nil {
				t.Fatal(e)
			}
			_, e := s.PurgeRecord(ctx, p, sid, rid)
			coreError(t, e, "cleanup_pending")
			row, e := s.DB.One(ctx, "SELECT id FROM v2_records WHERE id=?", rid)
			if e != nil || row == nil {
				t.Fatalf("unknown mutation ledger deleted record: %v %v", row, e)
			}
			space, e := s.DB.One(ctx, "SELECT reclaiming FROM v2_spaces WHERE id=?", sid)
			if e != nil || num(space["reclaiming"]) != 1 {
				t.Fatalf("unknown mutation released charge: %v %v", space, e)
			}
		})
	}
}

func TestReleasePreviouslyCleanedDraftAttempts(t *testing.T) {
	s, p, sid, rev := newCoreFixture(t)
	ctx := context.Background()
	r := coreCreate(t, s, p, sid, rev, "repaired-draft", Object{"attachments": []Object{{"path": "model", "size": int64(3), "sha256": strings.Repeat("e", 64)}}})
	rid := str(r["id"])
	bid := str(r["attachments"].([]Object)[0]["id"])
	// Cleanup of an abandoned draft upload intentionally leaves its declaration
	// reusable. Both immutable attempt ledgers positively prove physical absence.
	for _, id := range []string{"old-one", "old-two"} {
		if e := s.DB.Insert(ctx, "v2_transfer_attempts", Object{"id": id, "blob_id": bid, "object_key": id, "state": "cleaned", "mutation_tokens": []string{}}); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := s.WithdrawRecord(ctx, p, sid, rid); e != nil {
		t.Fatal(e)
	}
	row, e := s.DB.One(ctx, "SELECT allocated,reclaiming FROM v2_spaces WHERE id=?", sid)
	if e != nil || num(row["allocated"]) != 0 || num(row["reclaiming"]) != 0 {
		t.Fatalf("fully cleaned draft orphaned quota: %v %v", row, e)
	}
	blob, e := s.DB.One(ctx, "SELECT state,pending_deletion FROM v2_blobs WHERE id=?", bid)
	if e != nil || str(blob["state"]) != "cleaned" || flag(blob["pending_deletion"]) {
		t.Fatalf("cleanup proof not applied %v %v", blob, e)
	}
	if _, e = s.PurgeRecord(ctx, p, sid, rid); e != nil {
		t.Fatal(e)
	}
}
func TestReleaseCleanedLabelCannotHideOutstandingMutation(t *testing.T) {
	for _, blobState := range []string{"reserved", "cleaned"} {
		t.Run(blobState, func(t *testing.T) {
			s, p, sid, rev := newCoreFixture(t)
			ctx := context.Background()
			r := coreCreate(t, s, p, sid, rev, "uncertain-cleaned", Object{"attachments": []Object{{"path": "model", "size": int64(3), "sha256": strings.Repeat("f", 64)}}})
			rid := str(r["id"])
			bid := str(r["attachments"].([]Object)[0]["id"])
			if _, e := s.DB.Exec(ctx, "UPDATE v2_blobs SET state=? WHERE id=?", blobState, bid); e != nil {
				t.Fatal(e)
			}
			now, e := s.DB.Now(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if e = s.DB.Insert(ctx, "v2_transfer_attempts", Object{"id": "late-effect", "blob_id": bid, "object_key": "old-key", "state": "cleaned", "mutation_tokens": []string{"still-running"}, "grant_expires_at": now + 300}); e != nil {
				t.Fatal(e)
			}
			if _, e = s.WithdrawRecord(ctx, p, sid, rid); e != nil {
				t.Fatal(e)
			}
			row, e := s.DB.One(ctx, "SELECT allocated,reclaiming FROM v2_spaces WHERE id=?", sid)
			if e != nil || num(row["allocated"]) != 0 || num(row["reclaiming"]) != 3 {
				t.Fatalf("marker lost accounting barrier %v %v", row, e)
			}
			attempt, e := s.DB.One(ctx, "SELECT state,mutation_tokens,next_attempt FROM v2_transfer_attempts WHERE id=?", "late-effect")
			if e != nil || str(attempt["state"]) != "cleanup" || len(stringsOf(attempt["mutation_tokens"])) != 1 || decimal(attempt["next_attempt"]) < now+300 {
				t.Fatalf("uncertain effect not rearmed %v %v", attempt, e)
			}
			_, e = s.PurgeRecord(ctx, p, sid, rid)
			coreError(t, e, "cleanup_pending")
		})
	}
}

// These are actual persisted JSON values, including SQL JSON-null rather than
// an omitted column. None can establish provider quiescence.
func malformedCoreMutationLedgers() map[string]any {
	return map[string]any{
		"object": Object{"put": "token"}, "string": "token", "true": true, "number": int64(1),
		"empty-object": Object{}, "empty-string": "", "null": nil, "nil-slice": []string(nil),
		"null-member": []any{nil}, "number-member": []any{int64(1)},
		"empty-member": []string{""}, "duplicate": []string{"put", "put"}, "mixed": []any{"put", int64(1)},
	}
}
func TestManagedRetirementMalformedMutationLedgerRemainsPending(t *testing.T) {
	for name, markers := range malformedCoreMutationLedgers() {
		t.Run(name, func(t *testing.T) {
			s, p, sid := newManagedFixture(t)
			ctx := context.Background()
			revision, e := s.RegisterType(ctx, p, sid, "artifact", Object{"schema": Object{"type": "object"}}, "type")
			if e != nil {
				t.Fatal(e)
			}
			r := coreCreate(t, s, p, sid, revision, "record", Object{"attachments": []Object{{"path": "model", "size": int64(3), "sha256": strings.Repeat("e", 64)}}})
			bid := str(r["attachments"].([]Object)[0]["id"])
			if e = s.DB.Insert(ctx, "v2_transfer_attempts", Object{"id": "unknown", "blob_id": bid, "object_key": "opaque-owned-key", "state": "cleaned", "mutation_tokens": markers}); e != nil {
				t.Fatal(e)
			}
			before, e := s.DB.One(ctx, "SELECT mutation_tokens FROM v2_transfer_attempts WHERE id=?", "unknown")
			if e != nil {
				t.Fatal(e)
			}
			expected, e := domain.CanonicalJSON(before["mutation_tokens"])
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.RetireManagedSpace(ctx, p, sid, Object{"job_id": "job-a"}, "retire"); e != nil {
				t.Fatal(e)
			}
			attempt, e := s.DB.One(ctx, "SELECT state,mutation_tokens FROM v2_transfer_attempts WHERE id=?", "unknown")
			if e != nil {
				t.Fatal(e)
			}
			actual, e := domain.CanonicalJSON(attempt["mutation_tokens"])
			if e != nil {
				t.Fatal(e)
			}
			if str(attempt["state"]) != "cleanup" || string(actual) != string(expected) {
				t.Fatalf("retirement rewrote or discarded unknown ownership: %v", attempt)
			}
			space, e := s.DB.One(ctx, "SELECT allocated,reclaiming FROM v2_spaces WHERE id=?", sid)
			if e != nil || num(space["allocated"]) != 0 || num(space["reclaiming"]) != 3 {
				t.Fatalf("unknown ownership released reservation: %v %v", space, e)
			}
			// Isolate the managed-state marker check from the ordinary blob-state check.
			if _, e = s.DB.Exec(ctx, "UPDATE v2_blobs SET state=? WHERE id=?", "cleaned", bid); e != nil {
				t.Fatal(e)
			}
			state, e := s.GetManagedSpace(ctx, p, sid)
			if e != nil || state["cleanup_pending"] != true {
				t.Fatalf("managed state advertised uncertain cleanup: %v %v", state, e)
			}
		})
	}
}
