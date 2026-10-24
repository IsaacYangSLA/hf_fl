package transfers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/service"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/storage"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
)

type fakeStore struct {
	mu           sync.Mutex
	calls        map[string]int
	failure      error
	onStart      func(context.Context, string) error
	onComplete   func(context.Context, storage.UploadHandle) error
	onSign       func(context.Context) error
	expiryOffset float64
}

func (f *fakeStore) call(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[name]++
	return f.failure
}
func (f *fakeStore) count(name string) int     { f.mu.Lock(); defer f.mu.Unlock(); return f.calls[name] }
func (f *fakeStore) fail(e error)              { f.mu.Lock(); f.failure = e; f.mu.Unlock() }
func (*fakeStore) Protocol() string            { return Protocol }
func (*fakeStore) Check(context.Context) error { return nil }
func (f *fakeStore) Start(ctx context.Context, key string) (storage.UploadHandle, error) {
	e := f.call("start")
	if f.onStart != nil {
		if x := f.onStart(ctx, key); x != nil {
			return storage.UploadHandle{}, x
		}
	}
	if e != nil {
		return storage.UploadHandle{}, e
	}
	return storage.UploadHandle{ID: "upload-" + key[strings.LastIndex(key, "/")+1:], Key: key}, nil
}
func (f *fakeStore) Parts(context.Context, storage.UploadHandle) ([]storage.UploadedPart, error) {
	e := f.call("parts")
	return []storage.UploadedPart{{Number: 1, ETag: "opaque", Size: 3}}, e
}
func (f *fakeStore) UploadGrant(ctx context.Context, h storage.UploadHandle, n int, size int64, expiry float64, seconds int) (storage.TransferGrant, error) {
	e := f.call("upload_grant")
	if f.onSign != nil {
		if x := f.onSign(ctx); x != nil {
			return storage.TransferGrant{}, x
		}
	}
	if e != nil {
		return storage.TransferGrant{}, e
	}
	return storage.TransferGrant{URL: "https://storage.example.test/put", Headers: map[string]string{"Content-Length": fmt.Sprint(size)}, ExpiresAt: expiry + f.expiryOffset}, nil
}
func (f *fakeStore) Complete(ctx context.Context, h storage.UploadHandle, size, partSize int64) (storage.StoredObject, error) {
	e := f.call("complete")
	if f.onComplete != nil {
		if x := f.onComplete(ctx, h); x != nil {
			return storage.StoredObject{}, x
		}
	}
	if e != nil {
		return storage.StoredObject{}, e
	}
	return storage.StoredObject{Key: h.Key, Version: "version-exact"}, nil
}
func (f *fakeStore) Verify(ctx context.Context, o storage.StoredObject, size int64, digest string) (storage.Verification, error) {
	e := f.call("verify")
	if o.Version != "version-exact" {
		return storage.Verification{}, storage.Failure("storage_missing", false, false)
	}
	return storage.Verification{Size: size, SHA256: digest}, e
}
func (f *fakeStore) DownloadGrant(ctx context.Context, o storage.StoredObject, expiry float64, seconds int) (storage.TransferGrant, error) {
	e := f.call("download_grant")
	if f.onSign != nil {
		if x := f.onSign(ctx); x != nil {
			return storage.TransferGrant{}, x
		}
	}
	if e != nil {
		return storage.TransferGrant{}, e
	}
	return storage.TransferGrant{URL: "https://storage.example.test/get", Headers: map[string]string{}, ExpiresAt: expiry + f.expiryOffset}, nil
}
func (f *fakeStore) Cleanup(context.Context, string) error { return f.call("cleanup") }

type fixture struct {
	ctx           context.Context
	core          *service.Service
	s             *Service
	provider      *fakeStore
	owner         domain.Principal
	sid, rid, bid string
	digest        string
}

func fixtureDB(t *testing.T, postgres bool) *store.DB {
	t.Helper()
	ctx := context.Background()
	if !postgres {
		db, e := store.Open(ctx, "sqlite:///"+filepath.Join(t.TempDir(), "exchange.db"))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = db.Close() })
		if e = store.Initialize(ctx, db); e != nil {
			t.Fatal(e)
		}
		return db
	}
	raw := os.Getenv("HF2L_EXCHANGE_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("set HF2L_EXCHANGE_TEST_DATABASE_URL for disposable PostgreSQL integration")
	}
	control, e := store.Open(ctx, raw)
	if e != nil {
		t.Fatal(e)
	}
	name := "ex_transfer_" + domain.NewID()
	if _, e = control.Exec(ctx, "CREATE SCHEMA "+name); e != nil {
		_ = control.Close()
		t.Fatal(e)
	}
	u, e := url.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	query := u.Query()
	query.Set("search_path", name)
	u.RawQuery = query.Encode()
	db, e := store.Open(ctx, u.String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_ = db.Close()
		_, _ = control.Exec(context.Background(), "DROP SCHEMA "+name+" CASCADE")
		_ = control.Close()
	})
	current, e := db.One(ctx, "SELECT current_schema() AS name")
	if e != nil || str(current["name"]) != name {
		t.Fatal("PostgreSQL fixture did not select its owned schema")
	}
	if e = store.Initialize(ctx, db); e != nil {
		t.Fatal(e)
	}
	return db
}
func newFixture(t *testing.T, postgres bool) *fixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	db := fixtureDB(t, postgres)
	settings := config.DefaultSettings()
	settings.Storage.Bucket = "fixture"
	owner := domain.Principal{ID: domain.PrincipalID("https://identity.example", "owner"), Subject: "owner", BootstrapAdmin: true}
	core := service.New(db, service.Options{Auth: service.AuthOptions{AdminSubject: "owner", WorkloadIssuer: "https://workload.example", ProvisioningPrincipalIDs: []string{owner.ID}}})
	space, e := core.CreateSpace(ctx, owner, Object{"name": "documents", "quota_bytes": int64(3)}, "space")
	if e != nil {
		t.Fatal(e)
	}
	sid := str(space["id"])
	rev, e := core.RegisterType(ctx, owner, sid, "document", Object{"schema": Object{"type": "object"}}, "type")
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256([]byte("abc"))
	digest := hex.EncodeToString(sum[:])
	rec, e := core.CreateRecord(ctx, owner, sid, Object{"kind": "document", "schema_revision_id": rev["id"], "metadata": Object{}, "attachments": []Object{{"path": "document.bin", "size": int64(3), "sha256": digest}}}, "record")
	if e != nil {
		t.Fatal(e)
	}
	blob, e := db.One(ctx, "SELECT id FROM v2_blobs WHERE record_id=?", rec["id"])
	if e != nil || blob == nil {
		t.Fatalf("blob fixture: %v", e)
	}
	provider := &fakeStore{}
	return &fixture{ctx: ctx, core: core, s: New(core, provider, settings), provider: provider, owner: owner, sid: sid, rid: str(rec["id"]), bid: str(blob["id"]), digest: digest}
}
func (f *fixture) current(t *testing.T) Object {
	t.Helper()
	a, e := f.s.DB.One(f.ctx, "SELECT * FROM v2_transfer_attempts WHERE blob_id=? ORDER BY created_at DESC,id DESC LIMIT 1", f.bid)
	if e != nil || a == nil {
		t.Fatalf("current attempt: %v", e)
	}
	return a
}
func (f *fixture) row(t *testing.T, table, id string) Object {
	t.Helper()
	a, e := f.s.DB.One(f.ctx, "SELECT * FROM "+table+" WHERE id=?", id)
	if e != nil || a == nil {
		t.Fatalf("row %s: %v", table, e)
	}
	return a
}
func (f *fixture) update(t *testing.T, table, id string, values Object) {
	t.Helper()
	if e := f.s.DB.Update(f.ctx, table, Object{"id": id}, values); e != nil {
		t.Fatal(e)
	}
}
func (f *fixture) initiate(t *testing.T) Object {
	t.Helper()
	v, e := f.s.Initiate(f.ctx, f.sid, f.rid, f.bid, f.owner)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func (f *fixture) complete(t *testing.T) Object {
	t.Helper()
	v, e := f.s.Complete(f.ctx, f.sid, f.rid, f.bid, f.owner)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func (f *fixture) upload(t *testing.T) { t.Helper(); f.initiate(t); f.complete(t) }
func (f *fixture) process(t *testing.T, id string, cleanup bool, want string) {
	t.Helper()
	got, e := f.s.Process(f.ctx, id, cleanup)
	if e != nil || got != want {
		t.Fatalf("process %q: %s %v, want %s", id, got, e, want)
	}
}
func (f *fixture) due(t *testing.T, id string) {
	t.Helper()
	f.update(t, "v2_transfer_attempts", id, Object{"next_attempt": float64(0), "lease_until": nil, "grant_expires_at": float64(0)})
}
func (f *fixture) withdraw(t *testing.T) {
	t.Helper()
	if _, e := f.core.WithdrawRecord(f.ctx, f.owner, f.sid, f.rid); e != nil {
		t.Fatal(e)
	}
}
func (f *fixture) quota(t *testing.T, a, r int64) {
	t.Helper()
	v := f.row(t, "v2_spaces", f.sid)
	if integer(v["allocated"]) != a || integer(v["reclaiming"]) != r {
		t.Fatalf("quota allocated=%v reclaiming=%v, want %d/%d", v["allocated"], v["reclaiming"], a, r)
	}
}
func errorCode(t *testing.T, e error, want string) {
	t.Helper()
	var typed *domain.Error
	if !errors.As(e, &typed) || typed.Code != want {
		t.Fatalf("error %T %v, want %s", e, e, want)
	}
}
func makeManaged(t *testing.T, f *fixture) domain.Principal {
	t.Helper()
	ctx := f.ctx
	if _, e := f.core.EnableManagedSpace(ctx, f.owner, f.sid, Object{"job_id": "job-a"}, "enable"); e != nil {
		t.Fatal(e)
	}
	subject := "alice"
	pid := domain.PrincipalID("https://workload.example", subject)
	if _, e := f.core.PutMember(ctx, f.owner, f.sid, pid, Object{"subject": subject, "roles": []string{"contributor", "reader"}, "bindings": Object{"participant": "alice"}}); e != nil {
		t.Fatal(e)
	}
	now, e := f.s.DB.Now(ctx)
	if e != nil {
		t.Fatal(e)
	}
	body := Object{"subject": subject, "job_id": "job-a", "attempt_id": "attempt-one", "component_id": "alice", "epoch": int64(1), "roles": []string{"contributor"}, "bindings": Object{"participant": "alice"}, "certificate_thumbprint": strings.Repeat("a", 43), "expires_at": now + 3600}
	grant, e := f.core.CreateWorkloadGrant(ctx, f.owner, f.sid, body, "grant")
	if e != nil {
		t.Fatal(e)
	}
	p := domain.Principal{ID: pid, Subject: subject, Workload: &domain.WorkloadIdentity{GrantID: str(grant["grant_id"]), SpaceID: f.sid, JobID: "job-a", AttemptID: "attempt-one", ComponentID: "alice", Epoch: 1, CertificateThumbprint: strings.Repeat("a", 43), ExpiresAt: now + 300}}
	f.update(t, "v2_records", f.rid, Object{"creator": pid, "creator_bindings": Object{"participant": "alice"}})
	return p
}
func TestCompletionAndVerificationDistinct(t *testing.T) { testCompletion(t, false) }
func testCompletion(t *testing.T, postgres bool) {
	f := newFixture(t, postgres)
	r := f.initiate(t)
	if r["state"] != "uploading" || r["object_key"] != nil {
		t.Fatalf("private initiation descriptor: %v", r)
	}
	r = f.complete(t)
	if r["state"] != "verifying" {
		t.Fatal(r)
	}
	b := f.row(t, "v2_blobs", f.bid)
	if b["object_key"] != nil || b["object_version"] != nil {
		t.Fatal("object exposed before verification")
	}
	f.process(t, str(f.current(t)["id"]), false, "verified")
	if _, e := f.core.PublishRecord(f.ctx, f.owner, f.sid, f.rid, "publish"); e != nil {
		t.Fatal(e)
	}
	grant, e := f.s.Download(f.ctx, f.sid, f.rid, f.bid, f.owner)
	if e != nil {
		t.Fatal(e)
	}
	if grant["sha256"] != f.digest || integer(grant["size"]) != 3 {
		t.Fatal(grant)
	}
	b = f.row(t, "v2_blobs", f.bid)
	if b["object_version"] != "version-exact" || number(b["grant_expires_at"]) < number(grant["expires_at"]) {
		t.Fatal("immutable version or grant expiry lost")
	}
}
func TestCompletionProviderOutsideTransactionAndOnlyOnce(t *testing.T) {
	f := newFixture(t, false)
	f.initiate(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f.provider.onComplete = func(ctx context.Context, _ storage.UploadHandle) error {
		if _, e := f.s.DB.Now(ctx); e != nil {
			return e
		}
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	done := make(chan error, 1)
	go func() { _, e := f.s.Complete(f.ctx, f.sid, f.rid, f.bid, f.owner); done <- e }()
	select {
	case <-entered:
	case <-f.ctx.Done():
		t.Fatal("provider I/O held a database transaction")
	}
	r, e := f.s.Complete(f.ctx, f.sid, f.rid, f.bid, f.owner)
	if e != nil || r["state"] != "completing" {
		t.Fatalf("overlapping completion: %v %v", r, e)
	}
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if f.provider.count("complete") != 1 {
		t.Fatal("competing provider completion")
	}
}
func TestStaleOwnerCannotCommitOrReleaseSuccessor(t *testing.T) { testStaleOwner(t, false) }
func testStaleOwner(t *testing.T, postgres bool) {
	f := newFixture(t, postgres)
	f.upload(t)
	a := f.current(t)
	old, e := f.s.Acquire(f.ctx, str(a["id"]), nil)
	if e != nil || old == nil {
		t.Fatal(e)
	}
	f.update(t, "v2_transfer_attempts", str(a["id"]), Object{"lease_until": float64(0)})
	next, e := f.s.Acquire(f.ctx, str(a["id"]), nil)
	if e != nil || next == nil || next["token"] == old["token"] {
		t.Fatalf("successor: %v", e)
	}
	ok, e := f.s.Commit(f.ctx, old, "verified", storage.Verification{Size: 3, SHA256: f.digest})
	if e != nil || ok {
		t.Fatalf("stale commit: %v %v", ok, e)
	}
	if e = f.s.ReleaseLease(f.ctx, old); e != nil {
		t.Fatal(e)
	}
	if f.current(t)["token"] != next["token"] {
		t.Fatal("stale release cleared successor")
	}
	ok, e = f.s.Commit(f.ctx, next, "verified", storage.Verification{Size: 3, SHA256: f.digest})
	if e != nil || !ok {
		t.Fatalf("current commit: %v %v", ok, e)
	}
}
func TestCleanupPoolRechecksSelectedCategory(t *testing.T) { testPoolCategory(t, false) }
func testPoolCategory(t *testing.T, postgres bool) {
	f := newFixture(t, postgres)
	f.upload(t)
	verify, _, e := f.s.Work(f.ctx, 32)
	if e != nil || len(verify) != 1 {
		t.Fatal(verify, e)
	}
	f.withdraw(t)
	f.quota(t, 0, 3)
	f.process(t, verify[0], false, "skipped")
	a := f.current(t)
	if a["token"] != nil || a["lease_until"] != nil {
		t.Fatal("wrong pool consumed a cleanup lease")
	}
	f.process(t, verify[0], true, "cleaned")
	f.quota(t, 0, 0)
}
func TestUncertainInitiationRequiresExplicitQuiescedRepair(t *testing.T) {
	testUncertainRepair(t, false)
}
func testUncertainRepair(t *testing.T, postgres bool) {
	f := newFixture(t, postgres)
	f.provider.fail(storage.Failure("storage_unavailable", true, true))
	f.initiate(t)
	a := f.current(t)
	if len(list(a["mutation_tokens"])) != 1 || a["token"] != nil {
		t.Fatal("uncertain mutation was not retained")
	}
	f.provider.fail(nil)
	f.due(t, str(a["id"]))
	f.process(t, str(a["id"]), false, "skipped")
	if f.provider.count("start") != 1 || f.row(t, "v2_blobs", f.bid)["state"] != "reserved" {
		t.Fatal("unknown initiation created a replacement")
	}
	f.withdraw(t)
	f.quota(t, 0, 3)
	f.due(t, str(a["id"]))
	f.process(t, str(a["id"]), true, "skipped")
	if f.provider.count("cleanup") != 0 {
		t.Fatal("lease age released unknown provider mutation")
	}
	for _, flags := range [][2]bool{{false, false}, {false, true}, {true, false}} {
		_, e := RepairMutations(f.ctx, f.s.DB, []string{str(a["id"])}, true, flags[0], flags[1])
		errorCode(t, e, "storage_quiescence_required")
	}
	if _, e := RepairMutations(f.ctx, f.s.DB, []string{str(a["id"])}, true, true, true); e != nil {
		t.Fatal(e)
	}
	f.process(t, str(a["id"]), true, "cleaned")
	f.quota(t, 0, 0)
}
func TestUnexpectedProviderPanicPreservesUncertainty(t *testing.T) {
	f := newFixture(t, false)
	f.provider.onStart = func(context.Context, string) error { panic("private provider payload") }
	_, e := f.s.Initiate(f.ctx, f.sid, f.rid, f.bid, f.owner)
	errorCode(t, e, "internal_transfer_error")
	if strings.Contains(e.Error(), "private") {
		t.Fatal("provider panic leaked")
	}
	a := f.current(t)
	if len(list(a["mutation_tokens"])) != 1 || a["token"] != nil {
		t.Fatal("panic settled an unknown provider mutation")
	}
	f.quota(t, 3, 0)
}
func TestActualSignedExpiryRetainsQuota(t *testing.T) {
	f := newFixture(t, false)
	f.initiate(t)
	f.provider.expiryOffset = 50
	result, e := f.s.Grants(f.ctx, f.sid, f.rid, f.bid, f.owner, []int{1})
	if e != nil {
		t.Fatal(e)
	}
	grant := obj(list(result["grants"])[0])
	f.withdraw(t)
	f.quota(t, 0, 3)
	a := f.current(t)
	if number(a["grant_expires_at"]) < number(grant["expires_at"]) {
		t.Fatal("actual signer expiry lost")
	}
	_, cleanup, e := f.s.Work(f.ctx, 32)
	if e != nil || len(cleanup) != 0 {
		t.Fatal("live capability scheduled cleanup", e)
	}
	f.process(t, str(a["id"]), true, "skipped")
	if f.provider.count("cleanup") != 0 {
		t.Fatal("live signed capability reclaimed")
	}
	// Fake provider has no live network capabilities; model clock progression.
	f.due(t, str(a["id"]))
	f.process(t, str(a["id"]), true, "cleaned")
	f.quota(t, 0, 0)
}
func TestCancellationDuringSigningNeverExposesGrant(t *testing.T) {
	f := newFixture(t, false)
	f.initiate(t)
	f.provider.onSign = func(context.Context) error { _, e := f.core.WithdrawRecord(f.ctx, f.owner, f.sid, f.rid); return e }
	result, e := f.s.Grants(f.ctx, f.sid, f.rid, f.bid, f.owner, []int{1})
	errorCode(t, e, "upload_not_ready")
	if result != nil {
		t.Fatal("grant escaped reauthorization")
	}
}
func TestInvalidPartsReturnToUpload(t *testing.T) {
	f := newFixture(t, false)
	f.initiate(t)
	f.provider.fail(storage.Failure("invalid_parts", false, false))
	_, e := f.s.Complete(f.ctx, f.sid, f.rid, f.bid, f.owner)
	errorCode(t, e, "invalid_parts")
	a := f.current(t)
	if a["state"] != "uploading" || len(list(a["mutation_tokens"])) != 0 {
		t.Fatalf("invalid parts did not recover: %v", a)
	}
	f.provider.fail(nil)
	f.complete(t)
}
func TestVerificationFailureHoldsPhysicalQuotaThroughCleanupRetry(t *testing.T) {
	f := newFixture(t, false)
	f.upload(t)
	f.provider.fail(storage.Failure("storage_missing", false, false))
	id := str(f.current(t)["id"])
	f.process(t, id, false, "failed")
	if f.row(t, "v2_records", f.rid)["state"] != "failed" {
		t.Fatal("record not failed")
	}
	f.quota(t, 0, 3)
	f.process(t, id, true, "retry")
	a := f.current(t)
	if integer(a["retry_count"]) != 1 || a["last_error"] != "storage_missing" {
		t.Fatal("retry evidence lost")
	}
	f.quota(t, 0, 3)
	f.provider.fail(nil)
	f.due(t, id)
	f.process(t, id, true, "cleaned")
	f.quota(t, 0, 0)
	f.process(t, id, true, "skipped")
}
func TestLateProviderMutationRearmsOnlyItsOwnCleanup(t *testing.T) {
	for _, phase := range []string{"initiation", "completion"} {
		t.Run(phase, func(t *testing.T) {
			f := newFixture(t, false)
			hook := func(ctx context.Context) error {
				_, e := f.core.WithdrawRecord(ctx, f.owner, f.sid, f.rid)
				if e != nil {
					return e
				}
				a := f.current(t)
				return f.s.DB.Update(ctx, "v2_transfer_attempts", Object{"id": a["id"]}, Object{"lease_until": float64(0)})
			}
			if phase == "initiation" {
				f.provider.onStart = func(ctx context.Context, _ string) error { return hook(ctx) }
				f.initiate(t)
			} else {
				f.initiate(t)
				f.provider.onComplete = func(ctx context.Context, _ storage.UploadHandle) error { return hook(ctx) }
				f.complete(t)
			}
			a := f.current(t)
			if a["state"] != "cleanup" || len(list(a["mutation_tokens"])) != 0 || a["token"] != nil {
				t.Fatalf("late effect failed cleanup rearm: %v", a)
			}
			f.quota(t, 0, 3)
			f.due(t, str(a["id"]))
			f.process(t, str(a["id"]), true, "cleaned")
			f.quota(t, 0, 0)
		})
	}
}
func TestLeaseHeartbeatPreventsCompetingAcquisition(t *testing.T) {
	f := newFixture(t, false)
	f.s.Settings.Worker.LeaseSeconds = 1
	f.initiate(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f.provider.onComplete = func(ctx context.Context, _ storage.UploadHandle) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	done := make(chan error, 1)
	go func() { _, e := f.s.Complete(f.ctx, f.sid, f.rid, f.bid, f.owner); done <- e }()
	<-entered
	time.Sleep(1400 * time.Millisecond)
	a := f.current(t)
	now, e := f.s.DB.Now(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	if number(a["lease_until"]) <= now {
		t.Fatal("active provider operation lease expired")
	}
	current, e := f.s.Acquire(f.ctx, str(a["id"]), nil)
	if e != nil || current != nil {
		t.Fatal("competing worker acquired live operation", e)
	}
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}
func TestGatewayReceiptsBindExactPriorMutationAfterRevocation(t *testing.T) {
	f := newFixture(t, false)
	human := f.owner
	p := makeManaged(t, f)
	f.owner = p
	f.initiate(t)
	markerSeen := false
	f.provider.onSign = func(context.Context) error {
		a := f.current(t)
		markerSeen = len(list(a["mutation_tokens"])) > 0
		return nil
	}
	first, _, e := f.s.BeginGatewayPut(f.ctx, p, f.sid, f.rid, f.bid, 1)
	if e != nil || !markerSeen {
		t.Fatal("PUT fence not persisted before signing", e)
	}
	second, _, e := f.s.BeginGatewayPut(f.ctx, p, f.sid, f.rid, f.bid, 1)
	if e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*GatewayPutHandle){
		func(h *GatewayPutHandle) { h.SpaceID = "foreign" }, func(h *GatewayPutHandle) { h.RecordID = "foreign" }, func(h *GatewayPutHandle) { h.AttachmentID = "foreign" }, func(h *GatewayPutHandle) { h.AttemptID = "foreign" }, func(h *GatewayPutHandle) { h.ObjectKey = "foreign" }, func(h *GatewayPutHandle) { h.UploadID = "foreign" }, func(h *GatewayPutHandle) { h.PartNumber = 2 }, func(h *GatewayPutHandle) { h.Token = "gateway-put-1-foreign" },
	} {
		copy := first
		mutate(&copy)
		ok, e := f.s.FinishGatewayPut(f.ctx, copy)
		if e != nil || ok {
			t.Fatal("forged gateway receipt settled", e)
		}
	}
	if _, e = f.core.RevokeWorkloadGrants(f.ctx, human, f.sid, Object{"attempt_id": "attempt-one"}, "revoke"); e != nil {
		t.Fatal(e)
	}
	if _, e = f.core.RetireManagedSpace(f.ctx, human, f.sid, Object{"job_id": "job-a"}, "retire"); e != nil {
		t.Fatal(e)
	}
	f.process(t, str(f.current(t)["id"]), true, "skipped")
	ok, e := f.s.FinishGatewayPut(f.ctx, first)
	if e != nil || !ok {
		t.Fatal("revoked prior PUT could not settle", e)
	}
	a := f.current(t)
	if len(list(a["mutation_tokens"])) != 1 || !hasToken(a["mutation_tokens"], second.Token) {
		t.Fatal("settlement removed successor/foreign marker")
	}
	ok, e = f.s.FinishGatewayPut(f.ctx, first)
	if e != nil || ok {
		t.Fatal("replay changed marker", e)
	}
	ok, e = f.s.FinishGatewayPut(f.ctx, second)
	if e != nil || !ok {
		t.Fatal(e)
	}
	f.quota(t, 0, 3)
	f.due(t, str(a["id"]))
	f.process(t, str(a["id"]), true, "cleaned")
	f.quota(t, 0, 0)
}
func TestManagedDescriptorsNeverSignOrigin(t *testing.T) {
	f := newFixture(t, false)
	p := makeManaged(t, f)
	f.owner = p
	managed := NewManaged(f.s)
	r, e := managed.Initiate(f.ctx, f.sid, f.rid, f.bid, p)
	if e != nil || r["protocol"] != ManagedProtocol {
		t.Fatal(r, e)
	}
	f.provider.onSign = func(context.Context) error {
		t.Error("managed descriptor invoked origin signer")
		return errors.New("unexpected signer")
	}
	grants, e := managed.Grants(f.ctx, f.sid, f.rid, f.bid, p, []int{1})
	if e != nil {
		t.Fatal(e)
	}
	g := obj(list(grants["grants"])[0])
	if g["url"] != nil || g["protocol"] != ManagedProtocol || obj(g["operation"])["method"] != "PUT" {
		t.Fatal(g)
	}
	f.complete(t)
	f.process(t, str(f.current(t)["id"]), false, "verified")
	if _, e = f.core.PublishRecord(f.ctx, p, f.sid, f.rid, "publish"); e != nil {
		t.Fatal(e)
	}
	download, e := managed.Download(f.ctx, f.sid, f.rid, f.bid, p)
	if e != nil || download["url"] != nil || download["sha256"] != f.digest {
		t.Fatal(download, e)
	}
	if f.provider.count("upload_grant") != 0 || f.provider.count("download_grant") != 0 {
		t.Fatal("origin signing invoked")
	}
}
func TestUnmanagedShimPreservesSignedOriginProtocol(t *testing.T) {
	f := newFixture(t, false)
	shim := NewManaged(f.s)
	r, e := shim.Initiate(f.ctx, f.sid, f.rid, f.bid, f.owner)
	if e != nil || r["protocol"] != Protocol {
		t.Fatal(r, e)
	}
	r, e = shim.Grants(f.ctx, f.sid, f.rid, f.bid, f.owner, []int{1})
	if e != nil || obj(list(r["grants"])[0])["url"] == nil {
		t.Fatal(r, e)
	}
}
func TestDraftExpiryWithoutUploadsNeedsNoProviderCalls(t *testing.T) {
	f := newFixture(t, false)
	f.update(t, "v2_records", f.rid, Object{"expires_at": float64(0)})
	n, e := f.s.Expire(f.ctx, 32)
	if e != nil || n != 1 {
		t.Fatal(n, e)
	}
	f.quota(t, 0, 0)
	if f.row(t, "v2_blobs", f.bid)["state"] != "cleaned" || f.provider.count("cleanup") != 0 {
		t.Fatal("unallocated storage required provider cleanup")
	}
}
func TestPartNumbersRejectDuplicateEmptyAndOutOfRange(t *testing.T) {
	f := newFixture(t, false)
	f.initiate(t)
	for _, numbers := range [][]int{nil, {}, {1, 1}} {
		_, e := f.s.Grants(f.ctx, f.sid, f.rid, f.bid, f.owner, numbers)
		errorCode(t, e, "invalid_part_numbers")
	}
	for _, n := range []int{0, -1, 2} {
		_, e := f.s.Grants(f.ctx, f.sid, f.rid, f.bid, f.owner, []int{n})
		var failure *storage.StorageFailure
		if !errors.As(e, &failure) || failure.Code != "invalid_part_number" {
			t.Fatal(n, e)
		}
	}
}
func TestRepairInventoryFiltersBeforeBoundingAndHidesLocators(t *testing.T) {
	f := newFixture(t, false)
	f.initiate(t)
	a := f.current(t)
	for i := 0; i < 102; i++ {
		row := domain.CloneMap(a)
		row["id"] = fmt.Sprintf("a%03d", i)
		row["object_key"] = fmt.Sprintf("private-key-%d", i)
		row["state"] = "cleaned"
		row["mutation_tokens"] = []any{}
		if e := f.s.DB.Insert(f.ctx, "v2_transfer_attempts", row); e != nil {
			t.Fatal(e)
		}
	}
	f.update(t, "v2_transfer_attempts", str(a["id"]), Object{"state": "cleanup", "mutation_tokens": []any{"uncertain"}, "lease_until": nil})
	r, e := InspectMutations(f.ctx, f.s.DB, nil)
	if e != nil {
		t.Fatal(e)
	}
	items := list(r["attempts"])
	if len(items) != 1 || r["truncated"] != false {
		t.Fatal("bounded before mutation filtering", r)
	}
	item := obj(items[0])
	for _, key := range []string{"object_key", "upload_handle", "token", "mutation_tokens"} {
		if item[key] != nil {
			t.Fatal("private locator exposed", key)
		}
	}
	_, e = RepairMutations(f.ctx, f.s.DB, nil, true, true, true)
	errorCode(t, e, "invalid_attempt_selection")
	_, e = InspectMutations(f.ctx, f.s.DB, []string{"x", "x"})
	errorCode(t, e, "invalid_attempt_selection")
	_, e = RepairMutations(f.ctx, f.s.DB, []string{"missing"}, true, true, true)
	errorCode(t, e, "attempt_not_found")
}
func TestUncertainCompletionResumesSameHandleAfterExplicitRepair(t *testing.T) {
	f := newFixture(t, false)
	f.initiate(t)
	original := f.current(t)
	f.provider.fail(storage.Failure("storage_unavailable", true, true))
	f.complete(t)
	a := f.current(t)
	if a["state"] != "completing" || len(list(a["mutation_tokens"])) != 1 {
		t.Fatal("unknown completion not held")
	}
	f.provider.fail(nil)
	f.due(t, str(a["id"]))
	f.process(t, str(a["id"]), false, "skipped")
	if f.provider.count("complete") != 1 {
		t.Fatal("uncertain completion was repeated automatically")
	}
	if _, e := RepairMutations(f.ctx, f.s.DB, []string{str(a["id"])}, true, true, true); e != nil {
		t.Fatal(e)
	}
	f.process(t, str(a["id"]), false, "recovered")
	f.process(t, str(a["id"]), false, "verified")
	if f.provider.count("start") != 1 || f.current(t)["object_key"] != original["object_key"] {
		t.Fatal("completion recovery changed resource identity")
	}
}
func TestRepairIsAtomicAndRejectsLiveOrMixedGatewayOwnership(t *testing.T) {
	f := newFixture(t, false)
	p := makeManaged(t, f)
	f.owner = p
	f.initiate(t)
	h, _, e := f.s.BeginGatewayPut(f.ctx, p, f.sid, f.rid, f.bid, 1)
	if e != nil {
		t.Fatal(e)
	}
	a := f.current(t)
	f.update(t, "v2_transfer_attempts", str(a["id"]), Object{"mutation_tokens": []any{h.Token, "worker-uncertain"}})
	_, e = RepairMutations(f.ctx, f.s.DB, []string{str(a["id"])}, true, true, true)
	errorCode(t, e, "attempt_not_repairable")
	f.update(t, "v2_transfer_attempts", str(a["id"]), Object{"mutation_tokens": []any{h.Token}, "lease_until": float64(9999999999)})
	_, e = RepairMutations(f.ctx, f.s.DB, []string{str(a["id"])}, true, true, true)
	errorCode(t, e, "attempt_not_repairable")
	if len(list(f.current(t)["mutation_tokens"])) != 1 {
		t.Fatal("ineligible repair changed ownership")
	}
}
func TestPostgresTransferStateAndFencing(t *testing.T) {
	for name, fn := range map[string]func(*testing.T, bool){"normal": testCompletion, "stale_owner": testStaleOwner, "pool_category": testPoolCategory, "uncertain_repair": testUncertainRepair, "stale_finalizer": testStaleFinalizer, "competing_workers": testCompetingWorkers, "cleaned_draft": testCleanedDraft} {
		t.Run(name, func(t *testing.T) { fn(t, true) })
	}
}

func TestStaleFinalizerCannotStealSuccessorCleanupLease(t *testing.T) {
	testStaleFinalizer(t, false)
}
func testStaleFinalizer(t *testing.T, postgres bool) {
	f := newFixture(t, postgres)
	f.initiate(t)
	a := f.current(t)
	token := "old-provider-mutation"
	f.update(t, "v2_transfer_attempts", str(a["id"]), Object{"state": "completing", "token": token, "mutation_tokens": []any{token}, "lease_until": float64(0)})
	old := f.current(t)
	f.withdraw(t)
	if e := f.s.settleMutation(f.ctx, old); e != nil {
		t.Fatal(e)
	}
	cleanup := true
	successor, e := f.s.Acquire(f.ctx, str(a["id"]), &cleanup)
	if e != nil || successor == nil {
		t.Fatalf("cleanup acquisition: %v", e)
	}
	if e = f.s.abandon(f.ctx, old); e != nil {
		t.Fatal(e)
	}
	if e = f.s.ReleaseLease(f.ctx, old); e != nil {
		t.Fatal(e)
	}
	current := f.current(t)
	if current["token"] != successor["token"] || number(current["lease_until"]) != number(successor["lease_until"]) {
		t.Fatal("old finalizer stole the current cleanup lease")
	}
	f.quota(t, 0, 3)
}
func TestCompetingWorkersAcquireOnePhaseMatchedLease(t *testing.T) { testCompetingWorkers(t, false) }
func testCompetingWorkers(t *testing.T, postgres bool) {
	f := newFixture(t, postgres)
	f.upload(t)
	id := str(f.current(t)["id"])
	start := make(chan struct{})
	results := make(chan Object, 16)
	failures := make(chan error, 16)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			cleanup := false
			a, e := f.s.Acquire(f.ctx, id, &cleanup)
			if e != nil {
				failures <- e
				return
			}
			results <- a
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(failures)
	for e := range failures {
		t.Fatal(e)
	}
	acquired := 0
	var owner Object
	for a := range results {
		if a != nil {
			acquired++
			owner = a
		}
	}
	if acquired != 1 || owner["token"] != f.current(t)["token"] {
		t.Fatalf("acquired %d competing leases", acquired)
	}
}

func TestHeartbeatIntervalCannotOverflow(t *testing.T) {
	for _, tc := range []struct {
		seconds int64
		want    time.Duration
	}{{0, 20 * time.Millisecond}, {1, time.Second / 3}, {300, 100 * time.Second}, {int64(1<<63 - 1), time.Duration(1<<63 - 1)}} {
		if got := heartbeatEvery(tc.seconds); got != tc.want {
			t.Fatalf("seconds %d produced %v, want %v", tc.seconds, got, tc.want)
		}
	}
}
func TestCleanedDraftAttemptWithdrawDoesNotOrphanQuota(t *testing.T) { testCleanedDraft(t, false) }
func testCleanedDraft(t *testing.T, postgres bool) {
	f := newFixture(t, postgres)
	f.provider.fail(storage.Failure("storage_unavailable", true, true))
	f.initiate(t)
	a := f.current(t)
	f.provider.fail(nil)
	f.due(t, str(a["id"]))
	f.process(t, str(a["id"]), false, "skipped")
	if _, e := RepairMutations(f.ctx, f.s.DB, []string{str(a["id"])}, true, true, true); e != nil {
		t.Fatal(e)
	}
	f.process(t, str(a["id"]), true, "cleaned")
	if f.row(t, "v2_blobs", f.bid)["state"] != "reserved" {
		t.Fatal("draft cannot retry its reserved attachment")
	}
	f.withdraw(t)
	f.quota(t, 0, 0)
	_, cleanup, e := f.s.Work(f.ctx, 32)
	if e != nil || len(cleanup) != 0 {
		t.Fatalf("unexpected pending cleanup: %v %v", cleanup, e)
	}
	if f.row(t, "v2_blobs", f.bid)["state"] != "cleaned" {
		t.Fatal("proven-clean draft attachment not finalized")
	}
}
