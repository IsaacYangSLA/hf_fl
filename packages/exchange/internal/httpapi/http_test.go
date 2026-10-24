package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
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

type httpBlobs struct {
	mu         sync.Mutex
	checkError error
}

func (*httpBlobs) Protocol() string { return storage.MultipartProtocol }
func (b *httpBlobs) Check(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.checkError
}
func (*httpBlobs) Start(_ context.Context, key string) (storage.UploadHandle, error) {
	return storage.UploadHandle{ID: domain.NewID(), Key: key}, nil
}
func (*httpBlobs) Parts(context.Context, storage.UploadHandle) ([]storage.UploadedPart, error) {
	return []storage.UploadedPart{}, nil
}
func (*httpBlobs) UploadGrant(_ context.Context, _ storage.UploadHandle, _ int, _ int64, expiry float64, _ int) (storage.TransferGrant, error) {
	return storage.TransferGrant{URL: "https://storage.example.test/put", Headers: map[string]string{}, ExpiresAt: expiry}, nil
}
func (*httpBlobs) Complete(_ context.Context, h storage.UploadHandle, _, _ int64) (storage.StoredObject, error) {
	return storage.StoredObject{Key: h.Key, Version: "immutable-version"}, nil
}
func (*httpBlobs) Verify(_ context.Context, _ storage.StoredObject, size int64, digest string) (storage.Verification, error) {
	return storage.Verification{Size: size, SHA256: digest}, nil
}
func (*httpBlobs) DownloadGrant(_ context.Context, _ storage.StoredObject, expiry float64, _ int) (storage.TransferGrant, error) {
	return storage.TransferGrant{URL: "https://storage.example.test/get", Headers: map[string]string{}, ExpiresAt: expiry}, nil
}
func (*httpBlobs) Cleanup(context.Context, string) error { return nil }

type httpFixture struct {
	t                *testing.T
	ctx              context.Context
	db               *store.DB
	core             *service.Service
	raw              *transfers.Service
	blobs            *httpBlobs
	settings         config.Settings
	key, workloadKey *rsa.PrivateKey
	owner            domain.Principal
	authenticator    *auth.Authenticator
	handler          http.Handler
}

func httpPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	raw, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: raw}))
}
func newHTTPFixture(t *testing.T) *httpFixture {
	t.Helper()
	f := &httpFixture{t: t, ctx: context.Background(), blobs: &httpBlobs{}}
	var e error
	f.key, e = rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	f.workloadKey, e = rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	f.settings = config.DefaultSettings()
	f.settings.Auth.Issuer = "https://identity.example.test"
	f.settings.Auth.Audience = "exchange"
	f.settings.Auth.PublicKey = httpPEM(t, f.key)
	f.settings.Auth.AdminSubject = "owner"
	f.settings.Auth.WorkloadIssuer = "https://workloads.example.test"
	f.settings.Auth.WorkloadAudience = "exchange-managed"
	f.settings.Auth.WorkloadPublicKey = httpPEM(t, f.workloadKey)
	f.settings.Auth.TrustedBackendSecret = "exchange-http-fixture-backend-secret-at-least-32-bytes"
	f.owner = domain.Principal{ID: domain.PrincipalID(f.settings.Auth.Issuer, "owner"), Subject: "owner", BootstrapAdmin: true}
	f.settings.Auth.ProvisioningPrincipalIDs = []string{f.owner.ID}
	f.settings.Storage.Bucket = "http-fixture"
	databaseURL := "sqlite:///:memory:"
	if supplied := os.Getenv("HF2L_EXCHANGE_HTTP_TEST_DATABASE_URL"); supplied != "" {
		// Never initialize or drop a caller's schema. Every run owns one generated
		// schema beneath the explicitly disposable configured test database.
		base, e := store.Open(f.ctx, supplied)
		if e != nil {
			t.Fatal("test PostgreSQL unavailable")
		}
		schema := "go_exchange_http_" + domain.NewID()
		if _, e = base.Exec(f.ctx, `CREATE SCHEMA "`+schema+`"`); e != nil {
			base.Close()
			t.Fatal("cannot create owned test schema")
		}
		u, e := url.Parse(supplied)
		if e != nil {
			t.Fatal(e)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		databaseURL = u.String()
		t.Cleanup(func() { _, _ = base.Exec(f.ctx, `DROP SCHEMA "`+schema+`" CASCADE`); _ = base.Close() })
	}
	f.db, e = store.Open(f.ctx, databaseURL)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = f.db.Close() })
	if e = f.db.Initialize(f.ctx); e != nil {
		t.Fatal(e)
	}
	f.core = service.New(f.db, service.Options{Auth: service.AuthOptions{AdminSubject: "owner", WorkloadIssuer: f.settings.Auth.WorkloadIssuer, ProvisioningPrincipalIDs: f.settings.Auth.ProvisioningPrincipalIDs}, DraftSeconds: 86400, CoordinationSeconds: 300, PartSize: f.settings.Storage.PartSize})
	f.raw = transfers.New(f.core, f.blobs, f.settings)
	f.authenticator, e = auth.New(f.settings.Auth)
	if e != nil {
		t.Fatal(e)
	}
	f.handler, e = New(f.core, f.raw, f.authenticator, Options{AuthSettings: f.settings.Auth, DocsEnabled: true})
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *httpFixture) human(subject string) string {
	f.t.Helper()
	now := time.Now().Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": f.settings.Auth.Issuer, "sub": subject, "aud": "exchange", "iat": now, "exp": now + 300, "scope": "exchange"})
	token.Header["typ"] = "at+jwt"
	value, e := token.SignedString(f.key)
	if e != nil {
		f.t.Fatal(e)
	}
	return "Bearer " + value
}
func (f *httpFixture) request(method, path, raw, authorization string, headers http.Header) (int, object, http.Header) {
	f.t.Helper()
	r := httptest.NewRequest(method, "https://exchange.example.test"+path, strings.NewReader(raw))
	if headers != nil {
		r.Header = headers.Clone()
	}
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	if raw != "" && r.Header.Get("Content-Type") == "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	out := object{}
	if strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		dec := json.NewDecoder(w.Body)
		dec.UseNumber()
		if e := dec.Decode(&out); e != nil {
			f.t.Fatal("HTTP returned malformed JSON", e)
		}
	}
	if w.Header().Get("X-Request-ID") == "" {
		f.t.Fatal("request ID missing")
	}
	if errorBody, ok := out["error"].(map[string]any); ok && errorBody["request_id"] != w.Header().Get("X-Request-ID") {
		f.t.Fatal("request ID envelope mismatch")
	}
	return w.Code, out, w.Header()
}
func (f *httpFixture) json(method, path string, body any, subject, key string, headers http.Header) (int, object, http.Header) {
	f.t.Helper()
	raw := ""
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			f.t.Fatal(e)
		}
		raw = string(b)
	}
	if headers == nil {
		headers = http.Header{}
	}
	if key != "" {
		headers.Set("Idempotency-Key", key)
	}
	return f.request(method, path, raw, f.human(subject), headers)
}
func (f *httpFixture) must(method, path string, body any, key string) object {
	f.t.Helper()
	status, value, _ := f.json(method, path, body, "owner", key, nil)
	if status < 200 || status >= 300 {
		f.t.Fatalf("%s %s =>%d %+v", method, path, status, value)
	}
	return value
}
func httpCode(body object) string {
	e, _ := body["error"].(map[string]any)
	code, _ := e["code"].(string)
	return code
}
func httpNumber(t *testing.T, v any) int64 {
	t.Helper()
	n, ok := domain.Int64(v)
	if !ok {
		t.Fatalf("not an integer %T", v)
	}
	return n
}
func (f *httpFixture) space() string {
	return f.must("POST", "/v2/spaces", object{"name": "HTTP example"}, "space-key")["id"].(string)
}
func (f *httpFixture) revision(sid string) string {
	return f.must("POST", "/v2/spaces/"+sid+"/types/document/revisions", object{"schema": object{"type": "object", "properties": object{"value": object{"type": "integer"}}, "required": []any{"value"}}}, "type-key")["id"].(string)
}
func (f *httpFixture) record(sid, revision string, value int) string {
	return f.must("POST", "/v2/spaces/"+sid+"/records", object{"kind": "document", "schema_revision_id": revision, "metadata": object{"value": value}}, domain.NewID())["id"].(string)
}
func TestNativeHTTPRecordLifecycleRBACETagsAndPagination(t *testing.T) {
	f := newHTTPFixture(t)
	sid := f.space()
	revision := f.revision(sid)
	rid := f.record(sid, revision, 1)
	rid2 := f.record(sid, revision, 2)
	draft := f.record(sid, revision, 3)
	base := "/v2/spaces/" + sid
	status, _, h := f.json("GET", base+"/records/"+rid, nil, "owner", "", nil)
	if status != 200 || h.Get("ETag") != `"1"` {
		t.Fatal("record ETag missing")
	}
	bob := domain.PrincipalID(f.settings.Auth.Issuer, "bob")
	f.must("PUT", base+"/members/"+bob, object{"roles": []any{"reader"}}, "")
	status, body, _ := f.json("GET", base+"/records/"+rid, nil, "bob", "", nil)
	if status != 404 {
		t.Fatalf("private draft visible to reader: %d %+v", status, body)
	}
	status, _, _ = f.json("GET", base+"/members", nil, "bob", "", nil)
	if status != 403 {
		t.Fatal("reader can enumerate members")
	}
	status, _, _ = f.json("POST", base+"/records", object{"kind": "document", "schema_revision_id": revision}, "bob", "denied", nil)
	if status != 403 {
		t.Fatal("reader can create record")
	}
	for _, record := range []string{rid, rid2} {
		v := f.must("POST", base+"/records/"+record+"/publish", nil, domain.NewID())
		if v["state"] != "published" {
			t.Fatal("record not published")
		}
	}
	status, body, _ = f.json("GET", base+"/records?limit=1.0", nil, "bob", "", nil)
	if status != 200 || len(body["items"].([]any)) != 1 || body["next_cursor"] == nil {
		t.Fatalf("first page %+v", body)
	}
	cursor := body["next_cursor"].(string)
	status, second, _ := f.json("GET", base+"/records?limit=1&after="+url.QueryEscape(cursor), nil, "bob", "", nil)
	if status != 200 || len(second["items"].([]any)) != 1 || second["next_cursor"] != nil {
		t.Fatalf("second page %+v", second)
	}
	firstID := body["items"].([]any)[0].(map[string]any)["id"]
	secondID := second["items"].([]any)[0].(map[string]any)["id"]
	if firstID == secondID || firstID == draft || secondID == draft {
		t.Fatal("pagination duplicated or disclosed draft")
	}

	status, invalid, _ := f.json("PATCH", base+"/records/"+draft, object{"metadata": "not-an-object"}, "owner", "", nil)
	if status != 422 || httpCode(invalid) != "invalid_request" {
		t.Fatal("endpoint CAS ran before model validation")
	}

	for _, tc := range []struct {
		tag    string
		status int
	}{{"", 428}, {`W/"1"`, 400}, {`"2"`, 412}, {`"1"`, 200}} {
		h := http.Header{}
		if tc.tag != "" {
			h.Set("If-Match", tc.tag)
		}
		status, body, headers := f.json("PATCH", base+"/records/"+draft, object{"metadata": object{"value": 4}}, "owner", "", h)
		if status != tc.status {
			t.Fatalf("patch %q =>%d %+v", tc.tag, status, body)
		}
		if status == 200 && headers.Get("ETag") != `"2"` {
			t.Fatal("updated ETag missing")
		}
	}
	status, events, _ := f.json("GET", base+"/events?after=0&limit=1000", nil, "bob", "", nil)
	if status != 200 {
		t.Fatalf("events %+v", events)
	}
	for _, raw := range events["items"].([]any) {
		event := raw.(map[string]any)
		if event["record_id"] != rid && event["record_id"] != rid2 {
			t.Fatalf("hidden event disclosed %+v", event)
		}
	}
	if httpNumber(t, events["next_cursor"]) < 1 {
		t.Fatal("event cursor absent")
	}
	status, _, _ = f.json("GET", base, nil, "foreign", "", nil)
	if status != 404 {
		t.Fatal("foreign principal can inspect space")
	}
}
func TestNativeHTTPReferenceAcquisitionAndLargeFence(t *testing.T) {
	f := newHTTPFixture(t)
	sid := f.space()
	rev := f.revision(sid)
	r1 := f.record(sid, rev, 1)
	r2 := f.record(sid, rev, 2)
	base := "/v2/spaces/" + sid
	f.must("POST", base+"/records/"+r1+"/publish", nil, "pub-one")
	f.must("POST", base+"/records/"+r2+"/publish", nil, "pub-two")
	h := http.Header{"If-None-Match": []string{"*"}}
	status, ref, headers := f.json("PUT", base+"/refs/main", object{"record_id": r1}, "owner", "ref-one", h)
	if status != 200 || ref["token"] != "1" || headers.Get("ETag") != `"1"` {
		t.Fatalf("reference %+v", ref)
	}
	status, _, _ = f.json("PUT", base+"/refs/main", object{"record_id": r2}, "owner", "ref-stale", http.Header{"If-Match": []string{`"0"`}})
	if status != 412 {
		t.Fatal("stale CAS accepted")
	}
	acq := f.must("POST", base+"/acquisitions", object{"reference": "main", "expected_token": "1", "lease_seconds": 10}, "acquire")
	id := acq["id"].(string)
	fence := httpNumber(t, acq["fence"])
	status, body, _ := f.request("POST", base+"/acquisitions/"+id+"/renew", `{"fence":9223372036854775808}`, f.human("owner"), nil)
	if status != 409 || httpCode(body) != "acquisition_not_active" {
		t.Fatalf("large fence %d %+v", status, body)
	}
	status, _, _ = f.request("POST", base+"/acquisitions/"+id+"/renew", `{"fence":9223372036854775808}`, f.human("foreign"), nil)
	if status != 404 {
		t.Fatal("overflow fence skipped space authorization")
	}
	status, renewed, _ := f.json("POST", base+"/acquisitions/"+id+"/renew", object{"fence": fence}, "owner", "", nil)
	if status != 200 || renewed["state"] != "active" {
		t.Fatalf("renew %+v", renewed)
	}
	completed := f.must("POST", base+"/acquisitions/"+id+"/complete", object{"fence": fence, "result_record_id": r2}, "complete")
	if completed["state"] != "completed" {
		t.Fatalf("completion %+v", completed)
	}
	ref = f.must("GET", base+"/refs/main", nil, "")
	if ref["record_id"] != r2 || ref["token"] != "2" {
		t.Fatalf("reference completion %+v", ref)
	}
}
func TestNativeHTTPManagedAssertionCurrentGrantAndPublicIsolation(t *testing.T) {
	f := newHTTPFixture(t)
	sid := f.space()
	if _, e := f.core.EnableManagedSpace(f.ctx, f.owner, sid, object{"job_id": "job-example"}, "manage"); e != nil {
		t.Fatal(e)
	}
	subject := "alice"
	pid := domain.PrincipalID(f.settings.Auth.WorkloadIssuer, subject)
	thumb := strings.Repeat("a", 43)
	roles := []string{"reader", "contributor", "publisher"}
	if _, e := f.core.PutMember(f.ctx, f.owner, sid, pid, object{"roles": roles, "subject": subject}); e != nil {
		t.Fatal(e)
	}
	now := time.Now().Unix()
	grant, e := f.core.CreateWorkloadGrant(f.ctx, f.owner, sid, object{"subject": subject, "job_id": "job-example", "attempt_id": "attempt-example", "component_id": "component-example", "epoch": int64(1), "expires_at": float64(now + 300), "certificate_thumbprint": thumb, "roles": roles}, "grant")
	if e != nil {
		t.Fatal(e)
	}
	claims := jwt.MapClaims{"iss": f.settings.Auth.WorkloadIssuer, "sub": subject, "aud": "exchange-managed", "iat": now, "exp": now + 300, "jti": grant["grant_id"], "grant_id": grant["grant_id"], "space_id": sid, "job_id": "job-example", "attempt_id": "attempt-example", "component_id": "component-example", "epoch": int64(1), "cnf": object{"x5t#S256": thumb}}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "at+jwt"
	signed, e := token.SignedString(f.workloadKey)
	if e != nil {
		t.Fatal(e)
	}
	authorization := "Bearer " + signed
	path := "/v2/spaces/" + sid + "/membership"
	headers := auth.BackendAssertionHeaders(f.settings.Auth.TrustedBackendSecret, "GET", path, authorization, thumb, time.Now())
	status, _, _ := f.request("GET", path, "", authorization, headers)
	if status != 401 {
		t.Fatal("public listener trusted forwarded certificate for workload")
	}
	f.handler, e = New(f.core, f.raw, f.authenticator, Options{ManagedIngress: true, AuthSettings: f.settings.Auth})
	if e != nil {
		t.Fatal(e)
	}
	status, body, _ := f.request("GET", path, "", authorization, headers)
	if status != 200 || body["principal_id"] != pid {
		t.Fatalf("managed %d %+v", status, body)
	}
	status, _, _ = f.request("GET", path, "", authorization, nil)
	if status != 401 {
		t.Fatal("managed listener accepted missing assertion")
	}
	altered := headers.Clone()
	altered.Set("X-HF2L-Backend-Signature", "invalid")
	status, _, _ = f.request("GET", path, "", authorization, altered)
	if status != 401 {
		t.Fatal("forged assertion accepted")
	}
	status, _, _ = f.request("GET", path+"?limit=1", "", authorization, headers)
	if status != 401 {
		t.Fatal("assertion not bound to query")
	}
	duplicate := headers.Clone()
	duplicate.Add("X-HF2L-Backend-Timestamp", duplicate.Get("X-HF2L-Backend-Timestamp"))
	status, _, _ = f.request("GET", path, "", authorization, duplicate)
	if status != 401 {
		t.Fatal("duplicate assertion accepted")
	}

	revision, e := f.core.RegisterType(f.ctx, f.owner, sid, "document", object{"schema": object{"type": "object"}}, "managed-type")
	if e != nil {
		t.Fatal(e)
	}
	recordPath := "/v2/spaces/" + sid + "/records"
	recordHeaders := auth.BackendAssertionHeaders(f.settings.Auth.TrustedBackendSecret, "POST", recordPath, authorization, thumb, time.Now())
	recordHeaders.Set("Idempotency-Key", "managed-record")
	status, record, _ := f.request("POST", recordPath, fmtJSON(object{"kind": "document", "schema_revision_id": revision["id"], "metadata": object{}, "attachments": []any{object{"path": "model.bin", "size": 3, "sha256": strings.Repeat("a", 64)}}}), authorization, recordHeaders)
	if status != 201 {
		t.Fatalf("managed create %d %+v", status, record)
	}
	attachments := record["attachments"].([]any)
	bid := attachments[0].(map[string]any)["id"].(string)
	attachmentPath := recordPath + "/" + record["id"].(string) + "/attachments/" + bid
	uploadPath := attachmentPath + "/upload"
	uploadHeaders := auth.BackendAssertionHeaders(f.settings.Auth.TrustedBackendSecret, "POST", uploadPath, authorization, thumb, time.Now())
	status, started, _ := f.request("POST", uploadPath, "", authorization, uploadHeaders)
	if status != 200 || started["protocol"] != "hf2l-managed-v1" {
		t.Fatalf("managed upload protocol %d %+v", status, started)
	}
	grantsPath := attachmentPath + "/grants"
	grantsHeaders := auth.BackendAssertionHeaders(f.settings.Auth.TrustedBackendSecret, "POST", grantsPath, authorization, thumb, time.Now())
	status, grants, _ := f.request("POST", grantsPath, `{"numbers":[1]}`, authorization, grantsHeaders)
	if status != 200 {
		t.Fatalf("managed grants %d %+v", status, grants)
	}
	descriptor := grants["grants"].([]any)[0].(map[string]any)
	if descriptor["protocol"] != "hf2l-managed-v1" || descriptor["operation"].(map[string]any)["method"] != "PUT" {
		t.Fatalf("managed descriptor %+v", descriptor)
	}
	if _, exposed := descriptor["url"]; exposed || strings.Contains(fmtJSON(grants), "storage.example.test") {
		t.Fatal("managed response exposed origin capability")
	}

	if _, e = f.core.RevokeWorkloadGrants(f.ctx, f.owner, sid, object{"attempt_id": "attempt-example"}, "revoke"); e != nil {
		t.Fatal(e)
	}
	headers = auth.BackendAssertionHeaders(f.settings.Auth.TrustedBackendSecret, "GET", path, authorization, thumb, time.Now())
	status, _, _ = f.request("GET", path, "", authorization, headers)
	if status == 200 {
		t.Fatal("revoked workload retains access")
	}
}
func TestNativeHTTPBoundariesReadinessAndPrivateRouteSeparation(t *testing.T) {
	f := newHTTPFixture(t)
	for _, path := range []string{"/internal/transfers/v1/storage/check", "/internal/transfers/v1/spaces/example/authorize", "/internal/transfers/v1/spaces/example/records/record/attachments/blob/parts/1/grant", "/internal/transfers/v1/spaces/example/records/record/attachments/blob/parts/1/begin", "/internal/transfers/v1/settle"} {
		a := f.human("owner")
		headers := auth.BackendAssertionHeaders(f.settings.Auth.TrustedBackendSecret, "POST", path, a, strings.Repeat("a", 43), time.Now())
		status, _, _ := f.request("POST", path, "{}", a, headers)
		if status != 404 {
			t.Fatalf("private route mounted %s", path)
		}
	}
	status, _, _ := f.request("GET", "/health", "", "", nil)
	if status != 200 {
		t.Fatal("health requires authentication")
	}
	status, _, _ = f.request("GET", "/ready", "", "", nil)
	if status != 200 {
		t.Fatal("ready failed")
	}
	f.blobs.mu.Lock()
	f.blobs.checkError = errors.New("credential value must not escape")
	f.blobs.mu.Unlock()
	status, body, h := f.request("GET", "/ready", "", "", nil)
	if status != 503 || h.Get("Retry-After") != "3" || httpCode(body) != "not_ready" || strings.Contains(fmtJSON(body), "credential") {
		t.Fatal("readiness error leaked or unavailable")
	}
	f.blobs.mu.Lock()
	f.blobs.checkError = nil
	f.blobs.mu.Unlock()
	status, _, _ = f.request("POST", "/v2/spaces", "{", "", nil)
	if status != 422 {
		t.Fatal("syntax validation dependency ordering changed")
	}
	status, _, _ = f.request("POST", "/v2/spaces", `{"name":true}`, "", nil)
	if status != 401 {
		t.Fatal("semantic validation bypassed auth ordering")
	}
	status, body, _ = f.request("POST", "/v2/spaces", `{"name":"secret-user-value","extra":"do-not-echo"}`, f.human("owner"), http.Header{"Idempotency-Key": []string{"key"}, "X-Request-ID": []string{"known.request-id"}})
	if status != 422 || strings.Contains(fmtJSON(body), "do-not-echo") {
		t.Fatal("invalid request echoed data")
	}
	_, _, h = f.request("GET", "/health", "", "", http.Header{"X-Request-ID": []string{"invalid identifier with spaces"}})
	if !requestIDPattern.MatchString(h.Get("X-Request-ID")) {
		t.Fatal("unsafe request id reflected")
	}
	r := httptest.NewRequest("GET", "http://exchange.example.test/health", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != 426 {
		t.Fatal("forwarded scheme bypassed TLS")
	}
	local, e := New(f.core, f.raw, f.authenticator, Options{AllowLocalHTTP: true, AuthSettings: f.settings.Auth, MaxBodyBytes: 16})
	if e != nil {
		t.Fatal(e)
	}
	w = httptest.NewRecorder()
	local.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("explicit loopback development refused")
	}
	r.RemoteAddr = "192.0.2.1:1234"
	w = httptest.NewRecorder()
	local.ServeHTTP(w, r)
	if w.Code != 426 {
		t.Fatal("nonlocal cleartext permitted")
	}
	r = httptest.NewRequest("POST", "https://exchange.example.test/v2/spaces", strings.NewReader(strings.Repeat("x", 17)))
	r.ContentLength = -1
	w = httptest.NewRecorder()
	local.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatal("chunked body limit bypassed")
	}
	if _, e = f.db.Exec(f.ctx, "DROP TABLE v2_schema_ledger"); e != nil {
		t.Fatal(e)
	}
	status, cookieBody, _ := f.request("GET", "/v2/spaces/example", "", "", http.Header{"Cookie": []string{"authorization=" + f.human("owner")}})
	if status != 401 || httpCode(cookieBody) != "invalid_access_token" {
		t.Fatal("cookie acquired bearer authority")
	}

	status, _, _ = f.request("GET", "/health", "", "", nil)
	if status != 200 {
		t.Fatal("health contacted database")
	}
	status, _, h = f.request("POST", "/v2/spaces", `{"name":"x"}`, f.human("owner"), http.Header{"Idempotency-Key": []string{"key"}})
	if status != 503 || h.Get("Retry-After") != "3" {
		t.Fatal("authenticated operation ignored schema state")
	}
}
func fmtJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
func TestNativeHTTPActualHTTPSAndErrorRedaction(t *testing.T) {
	f := newHTTPFixture(t)
	tlsServer := httptest.NewTLSServer(f.handler)
	defer tlsServer.Close()
	client := tlsServer.Client()
	req, e := http.NewRequest("POST", tlsServer.URL+"/v2/spaces", bytes.NewBufferString(`{"name":"TLS example"}`))
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("Authorization", f.human("owner"))
	req.Header.Set("Idempotency-Key", "tls-key")
	req.Header.Set("Content-Type", "application/json")
	response, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	if response.StatusCode != 201 {
		b, _ := io.ReadAll(response.Body)
		t.Fatalf("actual TLS status%d %s", response.StatusCode, b)
	}
	if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		t.Fatal("test bypassed TLS verification")
	}
	s := f.handler.(*server)
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{errors.New("private SQL password=must-not-leak"), 500, "internal_error"},
		{storage.Failure("storage_unavailable", true, true), 503, "storage_unavailable"},
		{storage.Failure("invalid_parts", false, false), 409, "invalid_parts"},
	} {
		w := httptest.NewRecorder()
		s.writeError(w, "request", tc.err)
		if w.Code != tc.status || strings.Contains(w.Body.String(), "password") || !strings.Contains(w.Body.String(), tc.code) {
			t.Fatal("error translation leaked or wrong classification")
		}
	}
}
