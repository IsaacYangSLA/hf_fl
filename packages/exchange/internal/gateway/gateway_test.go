package gateway

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/auth"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/service"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/storage"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/transfers"
	"github.com/golang-jwt/jwt/v5"
)

type fixtureStore struct {
	grants  atomic.Int64
	cleaned atomic.Int64
	mu      sync.Mutex
	onGrant func() error
}

func (*fixtureStore) Protocol() string            { return storage.MultipartProtocol }
func (*fixtureStore) Check(context.Context) error { return nil }
func (*fixtureStore) Start(_ context.Context, key string) (storage.UploadHandle, error) {
	return storage.UploadHandle{ID: "upload-" + domain.NewID(), Key: key}, nil
}
func (*fixtureStore) Parts(context.Context, storage.UploadHandle) ([]storage.UploadedPart, error) {
	return []storage.UploadedPart{{Number: 1, ETag: "fixture-etag", Size: 3}}, nil
}
func (s *fixtureStore) UploadGrant(_ context.Context, _ storage.UploadHandle, _ int, _ int64, expiry float64, _ int) (storage.TransferGrant, error) {
	s.grants.Add(1)
	s.mu.Lock()
	fn := s.onGrant
	s.mu.Unlock()
	if fn != nil {
		if err := fn(); err != nil {
			return storage.TransferGrant{}, err
		}
	}
	return storage.TransferGrant{URL: "https://storage.example.test/put", Headers: map[string]string{"Content-Length": "3"}, ExpiresAt: expiry}, nil
}
func (*fixtureStore) Complete(_ context.Context, h storage.UploadHandle, _, _ int64) (storage.StoredObject, error) {
	return storage.StoredObject{Key: h.Key, Version: "immutable-version-a"}, nil
}
func (*fixtureStore) Verify(_ context.Context, _ storage.StoredObject, size int64, digest string) (storage.Verification, error) {
	return storage.Verification{Size: size, SHA256: digest}, nil
}
func (*fixtureStore) DownloadGrant(_ context.Context, _ storage.StoredObject, expiry float64, _ int) (storage.TransferGrant, error) {
	return storage.TransferGrant{URL: "https://storage.example.test/get", Headers: map[string]string{}, ExpiresAt: expiry}, nil
}
func (s *fixtureStore) Cleanup(context.Context, string) error { s.cleaned.Add(1); return nil }
func (s *fixtureStore) setGrantHook(fn func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onGrant = fn
}

type gatewayFixture struct {
	t                                        *testing.T
	ctx                                      context.Context
	db                                       *store.DB
	core                                     *service.Service
	engine                                   *transfers.Service
	settings                                 config.Settings
	owner, workload                          domain.Principal
	humanKey, workloadKey                    *rsa.PrivateKey
	sid, rid, bid, gid, authorization, thumb string
	clock                                    atomic.Int64
	handler                                  http.Handler
	blobs                                    *fixtureStore
}

func publicPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	raw, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: raw}))
}
func newGatewayFixture(t *testing.T) *gatewayFixture {
	return newGatewayFixtureWithURL(t, "sqlite:///:memory:")
}

func newGatewayFixtureWithURL(t *testing.T, databaseURL string) *gatewayFixture {
	t.Helper()
	f := &gatewayFixture{t: t, ctx: context.Background(), thumb: strings.Repeat("a", 43), blobs: &fixtureStore{}}
	f.clock.Store(time.Now().Unix())
	var err error
	f.humanKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.workloadKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.settings = config.DefaultSettings()
	f.settings.Database.URL = databaseURL
	f.settings.Auth.Issuer = "https://identity.example.test"
	f.settings.Auth.Audience = "exchange"
	f.settings.Auth.PublicKey = publicPEM(t, f.humanKey)
	f.settings.Auth.WorkloadIssuer = "https://workload.example.test"
	f.settings.Auth.WorkloadAudience = "exchange-managed"
	f.settings.Auth.WorkloadPublicKey = publicPEM(t, f.workloadKey)
	f.settings.Auth.TrustedBackendSecret = "fixture-backend-assertion-secret-at-least-32-bytes"
	f.settings.Storage.Bucket = "fixture-bucket"
	f.owner = domain.Principal{ID: domain.PrincipalID(f.settings.Auth.Issuer, "owner"), Subject: "owner", BootstrapAdmin: true}
	f.settings.Auth.ProvisioningPrincipalIDs = []string{f.owner.ID}
	f.db, err = store.Open(f.ctx, f.settings.Database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.db.Close() })
	if err = store.Initialize(f.ctx, f.db); err != nil {
		t.Fatal(err)
	}
	f.core = service.New(f.db, service.Options{Auth: service.AuthOptions{WorkloadIssuer: f.settings.Auth.WorkloadIssuer, ProvisioningPrincipalIDs: []string{f.owner.ID}}, DraftSeconds: f.settings.DraftSeconds, CoordinationSeconds: f.settings.CoordinationSeconds, PartSize: f.settings.Storage.PartSize})
	space, err := f.core.CreateSpace(f.ctx, f.owner, domain.Object{"name": "Gateway fixture"}, "space-key")
	if err != nil {
		t.Fatal(err)
	}
	f.sid = space["id"].(string)
	if _, err = f.core.EnableManagedSpace(f.ctx, f.owner, f.sid, domain.Object{"job_id": "job-a"}, "manage-key"); err != nil {
		t.Fatal(err)
	}
	pid := domain.PrincipalID(f.settings.Auth.WorkloadIssuer, "participant-a")
	bindings := domain.Object{"participant": "alice"}
	roles := []string{"reader", "contributor", "publisher"}
	if _, err = f.core.PutMember(f.ctx, f.owner, f.sid, pid, domain.Object{"subject": "participant-a", "roles": roles, "bindings": bindings}); err != nil {
		t.Fatal(err)
	}
	grant, err := f.core.CreateWorkloadGrant(f.ctx, f.owner, f.sid, domain.Object{"subject": "participant-a", "job_id": "job-a", "attempt_id": "attempt-a", "component_id": "component-a", "epoch": int64(1), "certificate_thumbprint": f.thumb, "expires_at": float64(f.clock.Load() + 3600), "roles": roles, "bindings": bindings}, "grant-key")
	if err != nil {
		t.Fatal(err)
	}
	f.gid = grant["grant_id"].(string)
	f.workload = domain.Principal{ID: pid, Subject: "participant-a", Workload: &domain.WorkloadIdentity{GrantID: f.gid, SpaceID: f.sid, JobID: "job-a", AttemptID: "attempt-a", ComponentID: "component-a", Epoch: 1, CertificateThumbprint: f.thumb, ExpiresAt: float64(f.clock.Load() + 300)}}
	revision, err := f.core.RegisterType(f.ctx, f.owner, f.sid, "document", domain.Object{"schema": domain.Object{"type": "object"}}, "type-key")
	if err != nil {
		t.Fatal(err)
	}
	record, err := f.core.CreateRecord(f.ctx, f.workload, f.sid, domain.Object{"kind": "document", "schema_revision_id": revision["id"], "metadata": domain.Object{}, "attachments": []any{domain.Object{"path": "model.safetensors", "size": int64(3), "sha256": digestABC()}}}, "record-key")
	if err != nil {
		t.Fatal(err)
	}
	f.rid = record["id"].(string)
	items, _ := objects(record["attachments"])
	if len(items) != 1 {
		t.Fatalf("attachments %+v", record)
	}
	f.bid = items[0]["id"].(string)
	f.engine = transfers.New(f.core, f.blobs, f.settings)
	if _, err = f.engine.Initiate(f.ctx, f.sid, f.rid, f.bid, f.workload); err != nil {
		t.Fatal(err)
	}
	f.authorization = f.token(nil)
	f.handler, err = New(f.core, f.engine, f.settings, Options{Now: func() time.Time { return time.Unix(f.clock.Load(), 0) }})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func digestABC() string { s := sha256.Sum256([]byte("abc")); return hex.EncodeToString(s[:]) }
func (f *gatewayFixture) token(overrides domain.Object) string {
	f.t.Helper()
	now := f.clock.Load()
	claims := jwt.MapClaims{"iss": f.settings.Auth.WorkloadIssuer, "sub": "participant-a", "aud": "hf2l-transfer", "iat": now, "exp": now + 300, "scope": "transfer", "jti": f.gid, "grant_id": f.gid, "space_id": f.sid, "job_id": "job-a", "attempt_id": "attempt-a", "component_id": "component-a", "epoch": int64(1), "cnf": map[string]any{"x5t#S256": f.thumb}}
	for k, v := range overrides {
		claims[k] = v
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "at+jwt"
	signed, err := token.SignedString(f.workloadKey)
	if err != nil {
		f.t.Fatal(err)
	}
	return "Bearer " + signed
}
func (f *gatewayFixture) humanToken(subject string) string {
	f.t.Helper()
	now := f.clock.Load()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": f.settings.Auth.Issuer, "sub": subject, "aud": "exchange", "iat": now, "exp": now + 300, "scope": "exchange"})
	token.Header["typ"] = "at+jwt"
	signed, err := token.SignedString(f.humanKey)
	if err != nil {
		f.t.Fatal(err)
	}
	return "Bearer " + signed
}
func (f *gatewayFixture) part() string {
	return Base + "/spaces/" + f.sid + "/records/" + f.rid + "/attachments/" + f.bid + "/parts/1"
}
func (f *gatewayFixture) download() string {
	return Base + "/spaces/" + f.sid + "/records/" + f.rid + "/attachments/" + f.bid + "/download"
}
func (f *gatewayFixture) headers(path, authorization, thumb string) http.Header {
	h := auth.BackendAssertionHeaders(f.settings.Auth.TrustedBackendSecret, http.MethodPost, path, authorization, thumb, time.Unix(f.clock.Load(), 0))
	h.Set("Authorization", authorization)
	return h
}
func (f *gatewayFixture) post(path string, body any) (int, domain.Object) {
	f.t.Helper()
	var raw string
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			f.t.Fatal(err)
		}
		raw = string(b)
	}
	return f.raw(path, raw, f.headers(path, f.authorization, f.thumb), true)
}
func (f *gatewayFixture) raw(path, raw string, headers http.Header, verified bool) (int, domain.Object) {
	f.t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://backend.example.test"+path, strings.NewReader(raw))
	r.Header = headers.Clone()
	if raw != "" && r.Header.Get("Content-Type") == "" {
		r.Header.Set("Content-Type", "application/json")
	}
	r.TLS = &tls.ConnectionState{}
	if verified {
		r.TLS.VerifiedChains = [][]*x509.Certificate{{{}}}
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	var result domain.Object
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		f.t.Fatalf("nonJSON status%d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Request-ID") == "" {
		f.t.Fatal("requestid absent")
	}
	if errObj, ok := result["error"].(map[string]any); ok && errObj["request_id"] != w.Header().Get("X-Request-ID") {
		f.t.Fatal("requestid mismatch")
	}
	return w.Code, result
}
func errorCode(value domain.Object) string {
	e, _ := value["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}
func (f *gatewayFixture) mustPost(path string, body any) domain.Object {
	f.t.Helper()
	status, v := f.post(path, body)
	if status != 200 {
		f.t.Fatalf("status%d: %+v", status, v)
	}
	return v
}
func (f *gatewayFixture) begin() string {
	f.t.Helper()
	v := f.mustPost(f.part()+"/begin", nil)
	r, ok := v["receipt"].(string)
	if !ok || r == "" {
		f.t.Fatal("missing receipt")
	}
	return r
}
func (f *gatewayFixture) markers(bid string) []any {
	f.t.Helper()
	row, err := f.db.One(f.ctx, "SELECT mutation_tokens FROM v2_transfer_attempts WHERE blob_id=?", bid)
	if err != nil {
		f.t.Fatal(err)
	}
	v, _ := row["mutation_tokens"].([]any)
	return v
}
func (f *gatewayFixture) revoke() {
	f.t.Helper()
	if _, err := f.core.RevokeWorkloadGrants(f.ctx, f.owner, f.sid, domain.Object{"attempt_id": "attempt-a"}, "revoke-key"); err != nil {
		f.t.Fatal(err)
	}
}

func TestNativeAuthorizationAndOriginGrant(t *testing.T) {
	f := newGatewayFixture(t)
	v := f.mustPost(Base+"/spaces/"+f.sid+"/authorize", nil)
	if v["grant_id"] != f.gid {
		t.Fatalf("wrong grant %+v", v)
	}
	v = f.mustPost(f.part()+"/grant", domain.Object{})
	if v["url"] != "https://storage.example.test/put" || v["number"] != float64(1) {
		t.Fatalf("wrong descriptor %+v", v)
	}
	if len(f.markers(f.bid)) != 0 {
		t.Fatal("grant created mutation marker")
	}
}
func TestNativeBeginReceiptRestartReplayAndForeignFence(t *testing.T) {
	f := newGatewayFixture(t)
	receipt := f.begin()
	markers := f.markers(f.bid)
	if len(markers) != 1 {
		t.Fatal("begin missing durable marker")
	}
	handle, err := openReceipt(f.settings.Auth.TrustedBackendSecret, receipt, f.authorization, f.thumb)
	if err != nil || handle.Token != markers[0] || handle.RecordID != f.rid {
		t.Fatalf("wrong receipt %+v %v", handle, err)
	}
	f.handler, err = New(f.core, f.engine, f.settings, Options{Now: func() time.Time { return time.Unix(f.clock.Load(), 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if f.mustPost(Base+"/settle", domain.Object{"receipt": receipt})["settled"] != true {
		t.Fatal("oldreceipt not settled after restart")
	}
	newer := f.begin()
	before := f.markers(f.bid)
	if f.mustPost(Base+"/settle", domain.Object{"receipt": receipt})["settled"] != false || !reflect.DeepEqual(before, f.markers(f.bid)) {
		t.Fatal("oldreceipt cleared successor")
	}
	if f.mustPost(Base+"/settle", domain.Object{"receipt": newer})["settled"] != true {
		t.Fatal("successor failed")
	}
}
func TestNativeSettlementAfterJWTExpiryAndGrantRevocation(t *testing.T) {
	f := newGatewayFixture(t)
	receipt := f.begin()
	f.revoke()
	f.clock.Add(600)
	status, _ := f.post(Base+"/spaces/"+f.sid+"/authorize", nil)
	if status != 401 {
		t.Fatalf("expired authorize %d", status)
	}
	if f.mustPost(Base+"/settle", domain.Object{"receipt": receipt})["settled"] != true || len(f.markers(f.bid)) != 0 {
		t.Fatal("exactoldreceipt notsettled")
	}
}
func TestNativeRevokedGrantCannotMintNewDescriptor(t *testing.T) {
	f := newGatewayFixture(t)
	f.revoke()
	before := f.blobs.grants.Load()
	for _, path := range []string{Base + "/spaces/" + f.sid + "/authorize", f.part() + "/grant", f.part() + "/begin"} {
		status, _ := f.post(path, nil)
		if status != 403 && status != 404 {
			t.Fatalf("revoked path status%d", status)
		}
	}
	if f.blobs.grants.Load() != before || len(f.markers(f.bid)) != 0 {
		t.Fatal("revoked request touched provider")
	}
}
func TestNativeStrictIngressAndAssertions(t *testing.T) {
	f := newGatewayFixture(t)
	path := f.part() + "/begin"
	for _, body := range []string{`{"principal":"admin"}`, `{"receipt":"wrong"}`, `[]`, `null`, `true`, `{"x":1,"x":2}`, `{"x":NaN}`, `{`} {
		status, v := f.raw(path, body, f.headers(path, f.authorization, f.thumb), true)
		if status != 422 || errorCode(v) != "invalid_request" {
			t.Fatalf("invalidbody status%d %+v", status, v)
		}
	}
	status, _ := f.raw(path, "", f.headers(path, f.authorization, f.thumb), false)
	if status != 401 {
		t.Fatal("unverified clientchain accepted")
	}
	for _, name := range []string{"Authorization", "X-HF2L-Backend-Timestamp", "X-HF2L-TLS-Thumbprint", "X-HF2L-Backend-Signature"} {
		h := f.headers(path, f.authorization, f.thumb)
		h.Add(name, h.Get(name))
		status, _ := f.raw(path, "", h, true)
		if status != 401 {
			t.Fatalf("duplicate %s accepted", name)
		}
		h = f.headers(path, f.authorization, f.thumb)
		h.Del(name)
		status, _ = f.raw(path, "", h, true)
		if status != 401 {
			t.Fatalf("missing %s accepted", name)
		}
	}
	for _, name := range []string{"Cookie", "Proxy-Authorization", "X-Forwarded-Client-Cert"} {
		h := f.headers(path, f.authorization, f.thumb)
		h.Set(name, "untrusted")
		status, v := f.raw(path, "", h, true)
		if status != 400 || errorCode(v) != "forbidden_transfer_credentials" {
			t.Fatalf("forbidden %s %+v", name, v)
		}
	}
	h := f.headers(path, f.authorization, f.thumb)
	h.Set("X-HF2L-Backend-Timestamp", strconv.FormatInt(f.clock.Load()-31, 10))
	status, _ = f.raw(path, "", h, true)
	if status != 401 {
		t.Fatal("stale assertion accepted")
	}
	h = f.headers(f.part()+"/grant", f.authorization, f.thumb)
	status, _ = f.raw(path, "", h, true)
	if status != 401 {
		t.Fatal("substituted target accepted")
	}
	h = f.headers(path, f.authorization, f.thumb)
	h.Set("X-HF2L-TLS-Thumbprint", strings.Repeat("b", 43))
	status, _ = f.raw(path, "", h, true)
	if status != 401 {
		t.Fatal("substituted thumb accepted")
	}
	status, v := f.raw(path+"?unexpected=1", "", f.headers(path+"?unexpected=1", f.authorization, f.thumb), true)
	if status != 400 || errorCode(v) != "unexpected_transfer_query" {
		t.Fatal("query accepted")
	}
	encoded := strings.Replace(path, "/spaces/", "/%73paces/", 1)
	status, v = f.raw(encoded, "", f.headers(path, f.authorization, f.thumb), true)
	if status != 400 || errorCode(v) != "noncanonical_transfer_target" {
		t.Fatal("encoded target accepted")
	}
	for _, number := range []string{"0", "10001", "not-int"} {
		p := strings.Replace(path, "/parts/1/", "/parts/"+number+"/", 1)
		status, _ = f.raw(p, "", f.headers(p, f.authorization, f.thumb), true)
		if status != 422 {
			t.Fatalf("badnumber%s status%d", number, status)
		}
	}
	if len(f.markers(f.bid)) != 0 {
		t.Fatal("invalid request created fence")
	}
}
func TestNativeTransferTokenAudienceScopeAndCertificate(t *testing.T) {
	f := newGatewayFixture(t)
	path := f.part() + "/grant"
	for _, overrides := range []domain.Object{{"scope": "exchange"}, {"aud": "exchange-managed"}, {"aud": []string{"hf2l-transfer"}}} {
		authorization := f.token(overrides)
		status, _ := f.raw(path, "", f.headers(path, authorization, f.thumb), true)
		if status != 401 {
			t.Fatalf("token substitution %+v status%d", overrides, status)
		}
	}
	for _, authorization := range []string{f.humanToken("owner"), f.authorization} {
		thumb := f.thumb
		if authorization == f.authorization {
			thumb = strings.Repeat("b", 43)
		}
		status, _ := f.raw(path, "", f.headers(path, authorization, thumb), true)
		if status != 401 {
			t.Fatalf("bad token/certificate status%d", status)
		}
	}
	foreign := strings.Replace(path, "/spaces/"+f.sid+"/", "/spaces/foreign/", 1)
	status, v := f.raw(foreign, "", f.headers(foreign, f.authorization, f.thumb), true)
	if status != 404 || errorCode(v) != "resource_not_found" {
		t.Fatalf("foreignspace %+v", v)
	}
}
func TestNativeLostSigningOutcomeKeepsFenceAndRedacts(t *testing.T) {
	f := newGatewayFixture(t)
	f.blobs.setGrantHook(func() error { return storage.Failure("storage_unavailable", true, true) })
	status, v := f.post(f.part()+"/begin", nil)
	if status != 503 || errorCode(v) != "storage_unavailable" || v["receipt"] != nil || len(f.markers(f.bid)) != 1 {
		t.Fatalf("lost signing %+v markers%d", v, len(f.markers(f.bid)))
	}
}
func TestNativeDownloadRequiresVerifiedPublishedRecord(t *testing.T) {
	f := newGatewayFixture(t)
	status, _ := f.post(f.download(), nil)
	if status != 409 {
		t.Fatalf("draftdownload status%d", status)
	}
	if _, err := f.engine.Complete(f.ctx, f.sid, f.rid, f.bid, f.workload); err != nil {
		t.Fatal(err)
	}
	row, err := f.db.One(f.ctx, "SELECT id FROM v2_transfer_attempts WHERE blob_id=?", f.bid)
	if err != nil {
		t.Fatal(err)
	}
	statusName, err := f.engine.Process(f.ctx, row["id"].(string), false)
	if err != nil || statusName != "verified" {
		t.Fatalf("verify %s %v", statusName, err)
	}
	if _, err = f.core.PublishRecord(f.ctx, f.workload, f.sid, f.rid, "publish-key"); err != nil {
		t.Fatal(err)
	}
	v := f.mustPost(f.download(), nil)
	if v["url"] != "https://storage.example.test/get" || v["sha256"] != digestABC() || v["size"] != float64(3) {
		t.Fatalf("download %+v", v)
	}
}
func TestNativeHTTPBoundsSanitizedErrorsAndRequestIDs(t *testing.T) {
	f := newGatewayFixture(t)
	path := f.part() + "/grant"
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+path, nil)
	r.Header = f.headers(path, f.authorization, f.thumb)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != 426 {
		t.Fatal("HTTP accepted")
	}
	h := f.headers(Base+"/settle", f.authorization, f.thumb)
	status, v := f.raw(Base+"/settle", strings.Repeat("x", int(MaxBodyBytes)+1), h, true)
	if status != 413 || errorCode(v) != "request_too_large" {
		t.Fatal("oversize accepted")
	}
	f.blobs.setGrantHook(func() error { return errors.New("secret-origin-value") })
	status, v = f.post(path, nil)
	raw, _ := json.Marshal(v)
	if status != 500 || strings.Contains(string(raw), "secret-origin-value") {
		t.Fatalf("error disclosed %+v", v)
	}
	h = f.headers(path, f.authorization, f.thumb)
	h.Set("Content-Type", "text/plain")
	status, _ = f.raw(path, "{}", h, true)
	if status != 415 {
		t.Fatal("nonJSON accepted")
	}
}
func TestNativeSettlementKeepsReclamationChargeUntilPhysicalCleanup(t *testing.T) {
	f := newGatewayFixture(t)
	receipt := f.begin()
	if _, err := f.core.WithdrawRecord(f.ctx, f.workload, f.sid, f.rid); err != nil {
		t.Fatal(err)
	}
	f.revoke()
	if f.mustPost(Base+"/settle", domain.Object{"receipt": receipt})["settled"] != true {
		t.Fatal("settlement failed")
	}
	row, err := f.db.One(f.ctx, "SELECT reclaiming FROM v2_spaces WHERE id=?", f.sid)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := domain.Int64(row["reclaiming"]); n != 3 {
		t.Fatalf("quota released early %+v", row)
	}
	row, err = f.db.One(f.ctx, "SELECT state,mutation_tokens FROM v2_transfer_attempts WHERE blob_id=?", f.bid)
	if err != nil {
		t.Fatal(err)
	}
	if row["state"] != "cleanup" || len(f.markers(f.bid)) != 0 || f.blobs.cleaned.Load() != 0 {
		t.Fatal("settlement performed physicalcleanup or changedcategory")
	}
}

func TestProviderPanicRetainsAdmittedMutation(t *testing.T) {
	f := newGatewayFixture(t)
	f.blobs.setGrantHook(func() error { panic("private-origin-secret") })
	status, result := f.post(f.part()+"/begin", nil)
	if status != 500 || errorCode(result) != "internal_error" || len(f.markers(f.bid)) != 1 {
		t.Fatalf("panic did not fail closed: status%d %+v", status, result)
	}
}
