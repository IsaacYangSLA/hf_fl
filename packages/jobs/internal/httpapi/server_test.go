package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/auth"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/manager"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/scheduler"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	dashboard "github.com/IsaacYangSLA/hf_fl/packages/jobs/src/hf2l_jobs/static"
)

const webIssuer = "https://identity.example.test"

type webProvider struct {
	mu         sync.Mutex
	challenges map[string]string
	states     map[string]string
}

func (p *webProvider) AuthorizationURL(_ context.Context, state, nonce, challenge string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.challenges[nonce] = challenge
	p.states[state] = nonce
	return webIssuer + "/authorize?" + url.Values{"state": {state}, "nonce": {nonce}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}.Encode(), nil
}
func (p *webProvider) ExchangeCode(_ context.Context, code, verifier, nonce string) (auth.Identity, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := sha256.Sum256([]byte(verifier))
	if p.challenges[nonce] != base64.RawURLEncoding.EncodeToString(h[:]) {
		return auth.Identity{}, domain.Err(401, "invalid_pkce")
	}
	if code != "alice" && code != "bob" && code != "carol" {
		return auth.Identity{}, domain.Err(401, "invalid_authorization_code")
	}
	return auth.Identity{Issuer: webIssuer, Subject: code, AccessToken: code + "-token", ProviderSID: "provider-" + code}, nil
}
func (p *webProvider) OnlineCheck(_ context.Context, token, subject string) (bool, error) {
	return token == subject+"-token", nil
}
func (p *webProvider) AuthenticateAccessToken(_ context.Context, token string) (auth.Identity, error) {
	subject := strings.TrimSuffix(token, "-token")
	if token == subject+"-token" && (subject == "alice" || subject == "bob" || subject == "carol") {
		return auth.Identity{Issuer: webIssuer, Subject: subject, AccessToken: token}, nil
	}
	return auth.Identity{}, domain.Err(401, "invalid_access_token")
}
func (p *webProvider) LogoutIdentity(_ context.Context, token string) (auth.LogoutIdentity, error) {
	if token != "test-logout" {
		return auth.LogoutIdentity{}, domain.Err(401, "invalid_logout_token")
	}
	return auth.LogoutIdentity{Subject: "alice", JTI: "logout-fixture"}, nil
}

type webCredential struct {
	cookie        *http.Cookie
	csrf, subject string
}
type webFixture struct {
	t       *testing.T
	db      *store.DB
	manager *manager.Manager
	auth    *auth.Service
	server  *Server
	http    *httptest.Server
	client  *http.Client
}

func newWebFixture(t *testing.T, change func(*Options), mtls *tls.Config) *webFixture {
	t.Helper()
	db := newWebDatabase(t)
	var e error
	f := &webFixture{t: t, db: db}
	ts := httptest.NewUnstartedServer(nil)
	cfg := auth.Config{OIDC: auth.OIDCConfig{Issuer: webIssuer, ClientID: "dashboard", RedirectURI: "https://" + ts.Listener.Addr().String() + "/auth/callback", Audience: "hf2l-jobs"}, SessionSecret: strings.Repeat("s", 40), PlatformOperatorIDs: []string{webID("alice")}}
	provider := &webProvider{challenges: map[string]string{}, states: map[string]string{}}
	f.auth, e = auth.New(db, cfg, provider)
	if e != nil {
		t.Fatal(e)
	}
	f.manager, e = manager.New(db, []byte(strings.Repeat("c", 40)))
	if e != nil {
		t.Fatal(e)
	}
	f.manager.PlatformOperatorIDs[webID("alice")] = true
	opts := Options{Dashboard: dashboard.Files, SSEPollInterval: 50 * time.Millisecond}
	if change != nil {
		change(&opts)
	}
	f.server, e = New(f.manager, f.auth, opts)
	if e != nil {
		t.Fatal(e)
	}
	ts.Config.Handler = f.server
	if mtls != nil {
		ts.TLS = mtls
	}
	ts.StartTLS()
	f.http = ts
	f.client = ts.Client()
	f.client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	f.client.Timeout = 4 * time.Second
	t.Cleanup(func() { ts.CloseClientConnections(); ts.Close() })
	f.seed()
	return f
}
func webID(subject string) string { return domain.PrincipalID(webIssuer, subject) }
func (f *webFixture) insert(table string, row map[string]any) {
	f.t.Helper()
	if e := f.db.WithTx(context.Background(), true, func(tx *store.Tx) error { return tx.Insert(context.Background(), table, row) }); e != nil {
		f.t.Fatalf("seed %s: %v", table, e)
	}
}
func (f *webFixture) update(table string, where, values map[string]any) {
	f.t.Helper()
	if e := f.db.WithTx(context.Background(), true, func(tx *store.Tx) error { return tx.Update(context.Background(), table, where, values) }); e != nil {
		f.t.Fatalf("update %s: %v", table, e)
	}
}
func (f *webFixture) seed() {
	f.insert("jm_projects", map[string]any{"id": "research", "name": "Research"})
	for _, subject := range []string{"alice", "bob"} {
		f.insert("jm_project_members", map[string]any{"project_id": "research", "principal_id": webID(subject), "role": "submitter"})
	}
	f.insert("jm_pools", map[string]any{"id": "cpu", "name": "CPU", "node_id": "node-cpu", "cpu_millicores": int64(2000), "memory_bytes": int64(1 << 30), "disk_bytes": int64(1 << 30), "gpu_uuids": []string{}, "gpu_profiles": []string{}, "sandbox_profiles": []string{"runsc-cpu-v1"}, "healthy": true, "quarantined": false})
	f.insert("jm_approved_sources", map[string]any{"id": "approved", "project_id": "research", "name": "Approved trainer", "url": "https://source.example.test/model.git", "status": "approved", "enabled": true, "allowed_commits": []string{strings.Repeat("a", 40)}})
	f.insert("jm_runtime_images", map[string]any{"id": "cpu-image", "project_id": "research", "name": "Qualified CPU runtime", "approved": true, "status": "approved", "digest": "sha256:" + strings.Repeat("b", 64), "enabled": true})
	for _, subject := range []string{"alice", "bob"} {
		f.insert("jm_participant_bindings", map[string]any{"id": subject + "-data", "project_id": "research", "participant_id": subject, "node_id": "node-" + subject, "dataset_label": "Approved data", "enabled": true})
	}
}
func webSpec(name string) map[string]any {
	return map[string]any{"project_id": "research", "name": name, "source_id": "approved", "source_commit": strings.Repeat("a", 40), "runtime_image": "cpu-image", "plugin": "lenet", "options": map[string]any{}, "participants": []any{map[string]any{"participant_id": "alice", "dataset_binding": "alice-data", "mode": "external"}, map[string]any{"participant_id": "bob", "dataset_binding": "bob-data", "mode": "external"}}, "components": []any{map[string]any{"component_id": "owner", "role": "owner", "resources": map[string]any{"pool_id": "cpu", "cpu_millicores": 1000, "memory_bytes": 1024, "disk_bytes": 1024}}}, "target_round": 2, "max_duration_seconds": 600}
}
func (f *webFixture) raw(method, path string, body []byte, credential *webCredential, headers map[string]string) *http.Response {
	f.t.Helper()
	req, e := http.NewRequest(method, f.http.URL+path, bytes.NewReader(body))
	if e != nil {
		f.t.Fatal(e)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if credential != nil {
		req.AddCookie(credential.cookie)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	response, e := f.client.Do(req)
	if e != nil {
		f.t.Fatal(e)
	}
	return response
}
func (f *webFixture) request(method, path string, body any, credential *webCredential, headers map[string]string) *http.Response {
	f.t.Helper()
	var raw []byte
	if body != nil {
		var e error
		raw, e = json.Marshal(body)
		if e != nil {
			f.t.Fatal(e)
		}
	}
	return f.raw(method, path, raw, credential, headers)
}
func webJSON(t *testing.T, r *http.Response, want int) map[string]any {
	t.Helper()
	defer r.Body.Close()
	raw, e := io.ReadAll(r.Body)
	if e != nil {
		t.Fatal(e)
	}
	if r.StatusCode != want {
		t.Fatalf("HTTP %d, want %d: %s", r.StatusCode, want, raw)
	}
	var v map[string]any
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatalf("JSON %s: %v", raw, e)
	}
	return v
}
func webError(t *testing.T, r *http.Response, want int, code string) {
	t.Helper()
	v := webJSON(t, r, want)
	d, ok := v["error"].(map[string]any)
	if !ok || d["code"] != code {
		t.Fatalf("error=%v, want %q", v, code)
	}
	if d["request_id"] == "" || d["request_id"] != r.Header.Get("X-Request-ID") {
		t.Fatalf("unbound request ID %v", v)
	}
}
func (f *webFixture) mutation(c webCredential, key string, version int64) map[string]string {
	h := map[string]string{"Origin": f.http.URL, "X-CSRF-Token": c.csrf, "Idempotency-Key": key}
	if version > 0 {
		h["If-Match"] = strconv.Quote(strconv.FormatInt(version, 10))
	}
	return h
}
func (f *webFixture) login(subject string) webCredential {
	f.t.Helper()
	response := f.request("GET", "/auth/login", nil, nil, nil)
	if response.StatusCode != 303 {
		f.t.Fatalf("login %d", response.StatusCode)
	}
	response.Body.Close()
	target, e := url.Parse(response.Header.Get("Location"))
	if e != nil {
		f.t.Fatal(e)
	}
	state := target.Query().Get("state")
	if target.Query().Get("code_challenge_method") != "S256" || len(target.Query().Get("code_challenge")) < 40 {
		f.t.Fatal("login did not use PKCE")
	}
	var login *http.Cookie
	for _, c := range response.Cookies() {
		if c.Name == auth.LoginCookie {
			login = c
		}
	}
	if login == nil || !login.Secure || !login.HttpOnly || login.Path != "/" || login.SameSite != http.SameSiteLaxMode {
		f.t.Fatalf("unsafe login cookie %+v", login)
	}
	initial := webCredential{cookie: login}
	response = f.request("GET", "/auth/callback?"+url.Values{"state": {state}, "code": {subject}}.Encode(), nil, &initial, nil)
	if response.StatusCode != 303 {
		v := webJSON(f.t, response, 303)
		f.t.Fatal(v)
	}
	response.Body.Close()
	if response.Header.Get("Location") != "/dashboard/" {
		f.t.Fatal("callback redirect")
	}
	var session *http.Cookie
	for _, c := range response.Cookies() {
		if c.Name == auth.SessionCookie {
			session = c
		}
	}
	if session == nil || !session.Secure || !session.HttpOnly || session.Path != "/" || session.SameSite != http.SameSiteLaxMode || session.MaxAge != 28800 {
		f.t.Fatalf("unsafe session cookie %+v", session)
	}
	credential := webCredential{cookie: session, subject: subject}
	v := webJSON(f.t, f.request("GET", "/auth/session", nil, &credential, nil), 200)
	credential.csrf, _ = v["csrf_token"].(string)
	if len(credential.csrf) != 64 || v["authenticated"] != true {
		f.t.Fatal(v)
	}
	principal := v["principal"].(map[string]any)
	if principal["principal_id"] != webID(subject) {
		f.t.Fatal(principal)
	}
	return credential
}
func (f *webFixture) create(c webCredential, name, key string) map[string]any {
	f.t.Helper()
	response := f.request("POST", Prefix+"/jobs", webSpec(name), &c, f.mutation(c, key, 0))
	v := webJSON(f.t, response, 202)
	if response.Header.Get("ETag") != strconv.Quote("1") {
		f.t.Fatal("missing creation ETag", response.Header)
	}
	if response.Header.Get("Location") != Prefix+"/jobs/"+v["id"].(string) {
		f.t.Fatal("missing job Location")
	}
	return v
}
func webVersion(v map[string]any) int64 { return int64(v["version"].(float64)) }

func TestWebLoginSessionAndCSRFProtectActualJobCreation(t *testing.T) {
	f := newWebFixture(t, nil, nil)
	v := webJSON(t, f.request("GET", "/auth/session", nil, nil, nil), 200)
	if v["authenticated"] != false {
		t.Fatal(v)
	}
	webError(t, f.request("GET", Prefix+"/jobs", nil, nil, nil), 401, "authentication_required")
	alice := f.login("alice")
	bad := f.mutation(alice, "bad-csrf", 0)
	bad["X-CSRF-Token"] = strings.Repeat("0", 64)
	webError(t, f.request("POST", Prefix+"/jobs", webSpec("denied"), &alice, bad), 403, "csrf_invalid")
	bad = f.mutation(alice, "bad-origin", 0)
	bad["Origin"] = "https://foreign.example.test"
	webError(t, f.request("POST", Prefix+"/jobs", webSpec("denied"), &alice, bad), 403, "csrf_origin_invalid")
	row, e := f.db.One(context.Background(), "SELECT COUNT(*) AS n FROM jm_jobs")
	if e != nil || row["n"] != int64(0) {
		t.Fatal("CSRF created durable work", row, e)
	}
	created := f.create(alice, "First federation", "create-1")
	if created["state"] != "QUEUED" || created["role"] != "admin" {
		t.Fatal(created)
	}
	webError(t, f.request("GET", Prefix+"/jobs", nil, &alice, map[string]string{"Authorization": "Bearer alice-token"}), 401, "ambiguous_authentication")
	webError(t, f.request("POST", "/auth/logout", nil, &alice, nil), 403, "csrf_invalid")
	response := f.request("POST", "/auth/logout", nil, &alice, f.mutation(alice, "logout", 0))
	webJSON(t, response, 200)
	cleared := false
	for _, c := range response.Cookies() {
		if c.Name == auth.SessionCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("logout did not clear host cookie")
	}
	webError(t, f.request("GET", Prefix+"/jobs", nil, &alice, nil), 401, "invalid_session")
}

func TestWebProjectSubmitterAndPerJobRolesAreDistinct(t *testing.T) {
	f := newWebFixture(t, nil, nil)
	alice := f.login("alice")
	bob := f.login("bob")
	carol := f.login("carol")
	job := f.create(alice, "Private Alice job", "alice-create")
	id := job["id"].(string)
	webError(t, f.request("POST", Prefix+"/jobs", webSpec("No project permission"), &carol, f.mutation(carol, "carol-create", 0)), 403, "project_submitter_required")
	webError(t, f.request("GET", Prefix+"/jobs/"+id, nil, &bob, nil), 404, "job_not_found")
	listing := webJSON(t, f.request("GET", Prefix+"/jobs", nil, &bob, nil), 200)
	if len(listing["items"].([]any)) != 0 {
		t.Fatal("project member saw foreign job", listing)
	}
	empty := webJSON(t, f.request("GET", Prefix+"/catalog", nil, &carol, nil), 200)
	if len(empty["projects"].([]any)) != 0 {
		t.Fatal("foreign catalog", empty)
	}
	updated := webJSON(t, f.request("PUT", Prefix+"/jobs/"+id+"/members/"+webID("bob"), map[string]any{"role": "reader"}, &alice, f.mutation(alice, "grant-bob", 1)), 200)
	webJSON(t, f.request("GET", Prefix+"/jobs/"+id, nil, &bob, nil), 200)
	webError(t, f.request("POST", Prefix+"/jobs/"+id+"/cancel", nil, &bob, f.mutation(bob, "denied-cancel", webVersion(updated))), 403, "job_role_required")
	updated = webJSON(t, f.request("DELETE", Prefix+"/jobs/"+id+"/members/"+webID("bob"), nil, &alice, f.mutation(alice, "revoke-bob", webVersion(updated))), 200)
	webError(t, f.request("GET", Prefix+"/jobs/"+id, nil, &bob, nil), 404, "job_not_found")
	last := f.request("DELETE", Prefix+"/jobs/"+id+"/members/"+webID("alice"), nil, &alice, f.mutation(alice, "last-admin", webVersion(updated)))
	webError(t, last, 409, "last_job_admin_required")
	// A platform operator's global resource privilege does not grant foreign job access.
	bobJob := f.create(bob, "Private Bob job", "bob-create")
	webError(t, f.request("GET", Prefix+"/jobs/"+bobJob["id"].(string), nil, &alice, nil), 404, "job_not_found")
	webJSON(t, f.request("GET", Prefix+"/pools", nil, &alice, nil), 200)
	webError(t, f.request("GET", Prefix+"/pools", nil, &bob, nil), 403, "platform_operator_required")
}

func TestWebIdempotencyAndVersionChecksGuardDurableEffects(t *testing.T) {
	f := newWebFixture(t, nil, nil)
	alice := f.login("alice")
	original := f.create(alice, "Immutable job", "once")
	same := f.create(alice, "Immutable job", "once")
	if original["id"] != same["id"] {
		t.Fatal("idempotent creation duplicated job")
	}
	webError(t, f.request("POST", Prefix+"/jobs", webSpec("Changed"), &alice, f.mutation(alice, "once", 0)), 409, "idempotency_conflict")
	missing := f.mutation(alice, "unused", 0)
	delete(missing, "Idempotency-Key")
	webError(t, f.request("POST", Prefix+"/jobs", webSpec("Missing key"), &alice, missing), 400, "idempotency_key_required")
	id := original["id"].(string)
	path := Prefix + "/jobs/" + id + "/cancel"
	webError(t, f.request("POST", path, nil, &alice, f.mutation(alice, "no-version", 0)), 428, "if_match_required")
	invalid := f.mutation(alice, "bad-version", 1)
	invalid["If-Match"] = "1"
	webError(t, f.request("POST", path, nil, &alice, invalid), 400, "invalid_if_match")
	webError(t, f.request("POST", path, nil, &alice, f.mutation(alice, "stale-version", 99)), 409, "job_version_conflict")
	changed := webJSON(t, f.request("POST", path, nil, &alice, f.mutation(alice, "cancel-once", 1)), 202)
	replay := webJSON(t, f.request("POST", path, nil, &alice, f.mutation(alice, "cancel-once", 1)), 202)
	if changed["state"] != "CANCELLING" || webVersion(replay) != webVersion(changed) {
		t.Fatal("cancellation replay changed job", changed, replay)
	}
	row, e := f.db.One(context.Background(), "SELECT COUNT(*) AS n FROM jm_outbox WHERE job_id = ? AND topic = 'fence_stop'", id)
	if e != nil || row["n"] != int64(1) {
		t.Fatal("duplicate cancellation effects", row, e)
	}
	if _, e = f.db.Exec(context.Background(), "DELETE FROM jm_project_members WHERE project_id=? AND principal_id=?", "research", webID("alice")); e != nil {
		t.Fatal(e)
	}
	webError(t, f.request("POST", Prefix+"/jobs", webSpec("Immutable job"), &alice, f.mutation(alice, "once", 0)), 403, "project_submitter_required")
}

func TestWebQueueCurrentHistoryAndPrincipalBoundPagination(t *testing.T) {
	f := newWebFixture(t, nil, nil)
	alice := f.login("alice")
	bob := f.login("bob")
	jobs := []map[string]any{f.create(alice, "First", "first"), f.create(alice, "Second", "second"), f.create(alice, "Third", "third")}
	sc := scheduler.New(f.db)
	admitted, e := sc.Schedule(context.Background(), 100)
	if e != nil || len(admitted) != 2 {
		t.Fatal("scheduler", admitted, e)
	}
	current := webJSON(t, f.request("GET", Prefix+"/jobs?view=current", nil, &alice, nil), 200)
	queued := webJSON(t, f.request("GET", Prefix+"/jobs?view=queued", nil, &alice, nil), 200)
	if len(current["items"].([]any)) != 2 || len(queued["items"].([]any)) != 1 {
		t.Fatal(current, queued)
	}
	f.update("jm_jobs", map[string]any{"id": jobs[0]["id"]}, map[string]any{"state": "FAILED", "terminated_at": time.Now().UTC()})
	history := webJSON(t, f.request("GET", Prefix+"/jobs?view=history", nil, &alice, nil), 200)
	if len(history["items"].([]any)) != 1 {
		t.Fatal(history)
	}
	first := webJSON(t, f.request("GET", Prefix+"/jobs?view=all&limit=1", nil, &alice, nil), 200)
	cursor, ok := first["next_cursor"].(string)
	if !ok || cursor == "" {
		t.Fatal("missing continuation", first)
	}
	second := webJSON(t, f.request("GET", Prefix+"/jobs?view=all&limit=1&cursor="+url.QueryEscape(cursor), nil, &alice, nil), 200)
	if first["items"].([]any)[0].(map[string]any)["id"] == second["items"].([]any)[0].(map[string]any)["id"] {
		t.Fatal("pagination repeated first item")
	}
	webError(t, f.request("GET", Prefix+"/jobs?view=all&limit=1&cursor="+url.QueryEscape(cursor), nil, &bob, nil), 422, "invalid_cursor")
	webError(t, f.request("GET", Prefix+"/jobs?view=queued&limit=1&cursor="+url.QueryEscape(cursor), nil, &alice, nil), 422, "invalid_cursor")
}

func TestWebRejectsInvalidBodiesAndQueryBoundsBeforeEffects(t *testing.T) {
	f := newWebFixture(t, nil, nil)
	alice := f.login("alice")
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"extra", func(v map[string]any) { v["mounts"] = []any{"/"} }},
		{"inline-secret", func(v map[string]any) { v["options"] = map[string]any{"password": "not-allowed"} }},
		{"boolean-round", func(v map[string]any) { v["target_round"] = true }},
		{"fractional-round", func(v map[string]any) { v["target_round"] = 2.5 }},
		{"null-name", func(v map[string]any) { v["name"] = nil }},
		{"negative-duration", func(v map[string]any) { v["max_duration_seconds"] = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := webSpec("Invalid")
			tc.edit(v)
			webError(t, f.request("POST", Prefix+"/jobs", v, &alice, f.mutation(alice, "bad-"+tc.name, 0)), 422, "invalid_request")
		})
	}
	for _, raw := range []string{"{", "[]", "{\"name\":\"a\",\"name\":\"b\"}", "{} {}"} {
		webError(t, f.raw("POST", Prefix+"/jobs", []byte(raw), &alice, f.mutation(alice, "malformed", 0)), 422, "invalid_request")
	}
	for _, suffix := range []string{"?limit=0", "?limit=101", "?limit=1.0", "?view=bogus", "?search=" + strings.Repeat("x", 201)} {
		webError(t, f.request("GET", Prefix+"/jobs"+suffix, nil, &alice, nil), 422, "invalid_request")
	}
	row, e := f.db.One(context.Background(), "SELECT COUNT(*) AS n FROM jm_jobs")
	if e != nil || row["n"] != int64(0) {
		t.Fatal("invalid inputs persisted work", row, e)
	}
	f.server.options.MaxBodyBytes = 1024
	webError(t, f.raw("POST", Prefix+"/jobs", bytes.Repeat([]byte("x"), 1025), &alice, nil), 413, "request_too_large")
}

func TestWebServesExactPackagedAssetsWithSecurityHeaders(t *testing.T) {
	f := newWebFixture(t, nil, nil)
	for _, path := range []string{"/dashboard/", "/dashboard/app.js", "/dashboard/styles.css"} {
		response := f.request("GET", path, nil, nil, map[string]string{"X-Request-ID": "client-request-42"})
		raw, e := io.ReadAll(response.Body)
		response.Body.Close()
		if e != nil || response.StatusCode != 200 || len(raw) == 0 {
			t.Fatal(path, response.StatusCode, e)
		}
		name := strings.TrimPrefix(path, "/dashboard/")
		if name == "" {
			name = "index.html"
		}
		expected, e := dashboard.Files.ReadFile(name)
		if e != nil || !bytes.Equal(raw, expected) {
			t.Fatalf("asset differs %s: %v", path, e)
		}
		if !strings.Contains(response.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") || response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Request-ID") != "client-request-42" {
			t.Fatal("missing security headers", response.Header)
		}
	}
	for _, path := range []string{"/", "/dashboard"} {
		response := f.request("GET", path, nil, nil, nil)
		response.Body.Close()
		if response.StatusCode != 303 || response.Header.Get("Location") != "/dashboard/" {
			t.Fatal(response.StatusCode, response.Header)
		}
	}
	plain := httptest.NewServer(f.server)
	defer plain.Close()
	req, _ := http.NewRequest("GET", plain.URL+"/healthz", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	response, e := plain.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	webError(t, response, 426, "https_required")
}

func newWebClientCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "HTTP test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	raw, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	caCert, e := x509.ParseCertificate(raw)
	if e != nil {
		t.Fatal(e)
	}
	clientKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	client := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Node test client"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	clientRaw, e := x509.CreateCertificate(rand.Reader, client, caCert, &clientKey.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	keyRaw, e := x509.MarshalPKCS8PrivateKey(clientKey)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientRaw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyRaw}))
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return cert, pool
}
func TestWebPrivateCallbacksRequireVerifiedTLSAndExactAssignment(t *testing.T) {
	cert, pool := newWebClientCertificate(t)
	digest := sha256.Sum256(cert.Certificate[0])
	wantThumb := base64.RawURLEncoding.EncodeToString(digest[:])
	var effects atomic.Int64
	f := newWebFixture(t, func(opts *Options) {
		opts.NodeAuthenticate = func(_ context.Context, bearer, peer string) (ExecutionActor, error) {
			if bearer != "Bearer node-token" || peer != wantThumb {
				return ExecutionActor{}, domain.Err(401, "invalid_node_grant")
			}
			return ExecutionActor{NodeID: "node-cpu", PoolID: "cpu", JobID: "job", AttemptID: "attempt", ComponentID: "owner", Epoch: 1, CertificateThumbprint: peer, Scopes: []string{"acknowledge"}}, nil
		}
		opts.CheckAssignment = func(_ context.Context, nodeID, poolID string, id executor.ExecutionIdentity) (bool, error) {
			return nodeID == "node-cpu" && poolID == "cpu" && id.JobID == "job", nil
		}
		opts.NodeCommand = func(_ context.Context, action string, _ executor.ExecutionIdentity, _ map[string]any) (bool, error) {
			if action != "ack" {
				t.Error(action)
			}
			effects.Add(1)
			return true, nil
		}
	}, &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool})
	path := "/internal/jobs/v1/assignments/job/attempt/owner/1/ack"
	forged := map[string]string{"Authorization": "Bearer node-token", "X-Verified-Client-Certificate": wantThumb, "X-Client-Cert": wantThumb}
	webError(t, f.request("POST", path, nil, nil, forged), 401, "verified_node_certificate_required")
	if effects.Load() != 0 {
		t.Fatal("forged headers executed callback")
	}
	transport := f.client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	defer transport.CloseIdleConnections()
	do := func(path string) *http.Response {
		req, _ := http.NewRequest("POST", f.http.URL+path, nil)
		req.Header.Set("Authorization", "Bearer node-token")
		r, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	v := webJSON(t, do(path), 200)
	if v["accepted"] != true || effects.Load() != 1 {
		t.Fatal(v, effects.Load())
	}
	webError(t, do(strings.Replace(path, "/job/", "/foreign/", 1)), 404, "assignment_not_found")
	if effects.Load() != 1 {
		t.Fatal("foreign assignment executed callback")
	}
	f.server.options.PublicOnly = true
	webError(t, do(path), 404, "not_found")
}

func TestWebSessionCallbackRejectsReplayWithoutIssuingAnotherSession(t *testing.T) {
	f := newWebFixture(t, nil, nil)
	response := f.request("GET", "/auth/login", nil, nil, nil)
	response.Body.Close()
	target, _ := url.Parse(response.Header.Get("Location"))
	state := target.Query().Get("state")
	var initial webCredential
	for _, c := range response.Cookies() {
		if c.Name == auth.LoginCookie {
			initial.cookie = c
		}
	}
	path := "/auth/callback?" + url.Values{"code": {"alice"}, "state": {state}}.Encode()
	success := f.request("GET", path, nil, &initial, nil)
	success.Body.Close()
	if success.StatusCode != 303 {
		t.Fatal(success.StatusCode)
	}
	webError(t, f.request("GET", path, nil, &initial, nil), 401, "invalid_authorization_state")
	row, e := f.db.One(context.Background(), "SELECT COUNT(*) AS n FROM jm_auth_sessions")
	if e != nil || row["n"] != int64(1) {
		t.Fatal("callback replay minted session", row, e)
	}
}

// Provider authentication and SQL mutations above are real Go services. Only the
// external identity provider is replaced by an in-process protocol fixture.

func newWebDatabase(t *testing.T) *store.DB {
	t.Helper()
	ctx := context.Background()
	raw := os.Getenv("HF2L_GO_HTTP_TEST_DATABASE_URL")
	if raw == "" {
		db, e := store.Open(ctx, "sqlite:///"+filepath.Join(t.TempDir(), "manager.db"))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { db.Close() })
		if _, e = db.Migrate(ctx); e != nil {
			t.Fatal(e)
		}
		return db
	}
	u, e := url.Parse(raw)
	if e != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql" && u.Scheme != "postgresql+psycopg") {
		t.Fatal("HF2L_GO_HTTP_TEST_DATABASE_URL must be a PostgreSQL URL")
	}
	admin, e := store.Open(ctx, raw)
	if e != nil {
		t.Fatal(e)
	}
	schema := "hf2l_http_" + domain.NewID()
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		admin.Close()
		t.Fatal(e)
	}
	var db *store.DB
	t.Cleanup(func() {
		if db != nil {
			db.Close()
		}
		if _, e := admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); e != nil {
			t.Error("dropping owned test schema:", e)
		}
		admin.Close()
	})
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	db, e = store.Open(ctx, u.String())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	return db
}
