package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	"github.com/golang-jwt/jwt/v5"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type issuerFixture struct {
	mu                                     sync.Mutex
	key                                    *rsa.PrivateKey
	now                                    time.Time
	active, offline, introspection         bool
	subject, nonce, challenge              string
	headers, overrides, discoveryOverrides map[string]any
	requests                               []*http.Request
	jwksCalls                              int
	introspectionOverrides                 map[string]any
	responseLimit                          bool
}

var fixtureRSA struct {
	sync.Once
	key *rsa.PrivateKey
	err error
}

func testRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	fixtureRSA.Do(func() { fixtureRSA.key, fixtureRSA.err = rsa.GenerateKey(rand.Reader, 2048) })
	if fixtureRSA.err != nil {
		t.Fatal(fixtureRSA.err)
	}
	return fixtureRSA.key
}
func newIssuer(t *testing.T) *issuerFixture {
	return &issuerFixture{key: testRSA(t), now: time.Now().UTC(), active: true, introspection: true, subject: "alice", headers: map[string]any{"kid": "test-key"}, overrides: map[string]any{}, discoveryOverrides: map[string]any{}, introspectionOverrides: map[string]any{}}
}

const testIssuer = "https://identity.example.test"

func (f *issuerFixture) sign(claims jwt.MapClaims, headers map[string]any) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	for k, v := range headers {
		token.Header[k] = v
	}
	raw, e := token.SignedString(f.key)
	if e != nil {
		panic(e)
	}
	return raw
}
func (f *issuerFixture) access(changes map[string]any) string {
	claims := jwt.MapClaims{"iss": testIssuer, "sub": f.subject, "aud": "hf2l-jobs", "iat": float64(f.now.UnixNano()) / 1e9, "exp": float64(f.now.Add(10*time.Minute).UnixNano()) / 1e9, "scope": "jobs"}
	for k, v := range changes {
		claims[k] = v
	}
	return f.sign(claims, map[string]any{"kid": "test-key", "typ": "at+jwt"})
}
func (f *issuerFixture) idToken() string {
	claims := jwt.MapClaims{"iss": testIssuer, "sub": f.subject, "aud": "dashboard", "iat": float64(f.now.UnixNano()) / 1e9, "exp": float64(f.now.Add(10*time.Minute).UnixNano()) / 1e9, "nonce": f.nonce, "sid": "provider-session"}
	for k, v := range f.overrides {
		claims[k] = v
	}
	return f.sign(claims, f.headers)
}
func response(status int, data any) *http.Response {
	b, _ := json.Marshal(data)
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(b)))}
}
func (f *issuerFixture) handle(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req)
	if f.offline {
		return nil, errors.New("synthetic provider outage")
	}
	if f.responseLimit {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat(" ", 1_048_577)))}, nil
	}
	switch req.URL.Path {
	case "/.well-known/openid-configuration":
		data := map[string]any{"issuer": testIssuer, "authorization_endpoint": testIssuer + "/authorize", "token_endpoint": testIssuer + "/token", "jwks_uri": testIssuer + "/jwks", "code_challenge_methods_supported": []string{"S256"}, "id_token_signing_alg_values_supported": []string{"RS256"}}
		if f.introspection {
			data["introspection_endpoint"] = testIssuer + "/introspect"
		}
		for k, v := range f.discoveryOverrides {
			data[k] = v
		}
		return response(200, data), nil
	case "/jwks":
		f.jwksCalls++
		e := big.NewInt(int64(f.key.E)).Bytes()
		return response(200, map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e)}}}), nil
	case "/token":
		if e := req.ParseForm(); e != nil {
			return response(400, nil), nil
		}
		h := sha256.Sum256([]byte(req.Form.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(h[:]) != f.challenge || req.Form.Get("redirect_uri") != "https://jobs.example.test/auth/callback" {
			return response(400, map[string]any{"error": "invalid_grant"}), nil
		}
		return response(200, map[string]any{"id_token": f.idToken(), "access_token": "opaque-access"}), nil
	case "/introspect":
		data := map[string]any{"active": f.active, "sub": f.subject, "client_id": "dashboard", "exp": float64(f.now.Add(10*time.Minute).UnixNano()) / 1e9}
		for k, v := range f.introspectionOverrides {
			data[k] = v
		}
		return response(200, data), nil
	}
	return response(404, map[string]any{}), nil
}
func testConfig() Config {
	return Config{OIDC: OIDCConfig{Issuer: testIssuer, ClientID: "dashboard", RedirectURI: "https://jobs.example.test/auth/callback", Audience: "hf2l-jobs"}, SessionSecret: strings.Repeat("s", 32)}
}
func testProvider(t *testing.T, f *issuerFixture) *OIDCProvider {
	t.Helper()
	p, e := NewOIDCProvider(testConfig().OIDC, &http.Client{Transport: roundTripFunc(f.handle)})
	if e != nil {
		t.Fatal(e)
	}
	p.Clock = func() time.Time { return f.now }
	return p
}
func testService(t *testing.T) (*Service, *issuerFixture) {
	t.Helper()
	db, e := store.Open(context.Background(), "sqlite://")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if _, e = db.Migrate(context.Background()); e != nil {
		t.Fatal(e)
	}
	f := newIssuer(t)
	s, e := New(db, testConfig(), testProvider(t, f))
	if e != nil {
		t.Fatal(e)
	}
	s.Clock = func() time.Time { return f.now }
	return s, f
}
func begin(t *testing.T, s *Service, f *issuerFixture) (LoginStart, string) {
	t.Helper()
	start, e := s.BeginLogin(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(start.AuthorizationURL)
	if e != nil {
		t.Fatal(e)
	}
	f.nonce = u.Query().Get("nonce")
	f.challenge = u.Query().Get("code_challenge")
	return start, u.Query().Get("state")
}
func login(t *testing.T, s *Service, f *issuerFixture) SessionIssue {
	t.Helper()
	start, state := begin(t, s, f)
	out, e := s.FinishLogin(context.Background(), "test-code", state, start.StateCookie)
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func expectError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var e *domain.Error
	if !errors.As(err, &e) || e.Status != status || e.Code != code {
		t.Fatalf("got %T %v; want %d %s", err, err, status, code)
	}
}
func TestLoginPKCECookieBindingAndHashedSession(t *testing.T) {
	s, f := testService(t)
	start, state := begin(t, s, f)
	u, _ := url.Parse(start.AuthorizationURL)
	q := u.Query()
	for k, v := range map[string]string{"response_type": "code", "response_mode": "query", "code_challenge_method": "S256", "redirect_uri": "https://jobs.example.test/auth/callback", "client_id": "dashboard", "scope": "openid", "prompt": "login"} {
		if q.Get(k) != v {
			t.Fatalf("%s=%q", k, q.Get(k))
		}
	}
	if q.Get("nonce") == "" || state == start.StateCookie {
		t.Fatal("state, cookie and nonce must be distinct")
	}
	out, e := s.FinishLogin(context.Background(), "test-code", state, start.StateCookie)
	if e != nil {
		t.Fatal(e)
	}
	if out.Principal.ID != domain.PrincipalID(testIssuer, "alice") {
		t.Fatal("wrong principal")
	}
	row, e := s.DB.One(context.Background(), "SELECT * FROM jm_auth_sessions WHERE id = ?", digest(out.SessionToken))
	if e != nil {
		t.Fatal(e)
	}
	if row == nil || row["id"] == out.SessionToken || str(row, "csrf_hash") != digest(out.CSRFToken) || str(row, "access_token") != "opaque-access" {
		t.Fatal("session record mismatch")
	}
	info, e := s.SessionInfo(context.Background(), out.SessionToken)
	if e != nil {
		t.Fatal(e)
	}
	if info["csrf_token"] != out.CSRFToken || info["access_token"] != nil || info["session_token"] != nil {
		t.Fatal("session info exposed secret")
	}
}
func TestLoginStateConsumedAndProviderFailureNotReplayable(t *testing.T) {
	s, f := testService(t)
	start, state := begin(t, s, f)
	_, e := s.FinishLogin(context.Background(), "test-code", state, strings.Repeat("x", 43))
	expectError(t, e, 401, "invalid_authorization_state")
	out, e := s.FinishLogin(context.Background(), "test-code", state, start.StateCookie)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.FinishLogin(context.Background(), "test-code", state, start.StateCookie)
	expectError(t, e, 401, "invalid_authorization_state")
	if out.SessionToken == "" {
		t.Fatal("missing session")
	}
	start, state = begin(t, s, f)
	f.offline = true
	_, e = s.FinishLogin(context.Background(), "test-code", state, start.StateCookie)
	expectError(t, e, 503, "identity_provider_unavailable")
	f.offline = false
	_, e = s.FinishLogin(context.Background(), "test-code", state, start.StateCookie)
	expectError(t, e, 401, "invalid_authorization_state")
}
func TestExpiredStateNeverExchangesCode(t *testing.T) {
	s, f := testService(t)
	start, state := begin(t, s, f)
	before := len(f.requests)
	f.now = f.now.Add(LoginLifetime)
	_, e := s.FinishLogin(context.Background(), "test-code", state, start.StateCookie)
	expectError(t, e, 401, "invalid_authorization_state")
	if len(f.requests) != before {
		t.Fatal("expired state reached provider")
	}
}
func TestSessionIdleAbsoluteAndNoTouch(t *testing.T) {
	s, f := testService(t)
	issue := login(t, s, f)
	initial, e := s.DB.One(context.Background(), "SELECT * FROM jm_auth_sessions WHERE id = ?", digest(issue.SessionToken))
	if e != nil {
		t.Fatal(e)
	}
	f.now = f.now.Add(14 * time.Minute)
	if _, e = s.AuthenticateRequest(context.Background(), "", issue.SessionToken, false); e != nil {
		t.Fatal(e)
	}
	row, _ := s.DB.One(context.Background(), "SELECT * FROM jm_auth_sessions WHERE id = ?", digest(issue.SessionToken))
	if !timestamp(row, "last_seen_at").Equal(timestamp(initial, "last_seen_at")) {
		t.Fatal("stream authentication extended idle timer")
	}
	f.now = f.now.Add(16 * time.Minute)
	_, e = s.AuthenticateSession(context.Background(), issue.SessionToken, true)
	expectError(t, e, 401, "session_expired")
	s, f = testService(t)
	issue = login(t, s, f)
	initialNow := f.now
	for i := 0; i < 31; i++ {
		f.now = f.now.Add(15 * time.Minute)
		if _, e = s.AuthenticateSession(context.Background(), issue.SessionToken, true); e != nil {
			t.Fatal(e)
		}
	}
	f.now = initialNow.Add(SessionAbsolute)
	_, e = s.AuthenticateSession(context.Background(), issue.SessionToken, true)
	expectError(t, e, 401, "session_expired")
}
func TestIdentityCheckRevocationCommitsAndOutageDoesNotTouch(t *testing.T) {
	s, f := testService(t)
	issue := login(t, s, f)
	f.now = f.now.Add(15 * time.Minute)
	f.offline = true
	_, e := s.AuthenticateSession(context.Background(), issue.SessionToken, true)
	expectError(t, e, 503, "identity_provider_unavailable")
	row, _ := s.DB.One(context.Background(), "SELECT * FROM jm_auth_sessions WHERE id = ?", digest(issue.SessionToken))
	if !timestamp(row, "last_seen_at").Equal(timestamp(row, "created_at")) {
		t.Fatal("outage extended session")
	}
	f.offline = false
	f.active = false
	_, e = s.AuthenticateSession(context.Background(), issue.SessionToken, true)
	expectError(t, e, 401, "identity_revoked")
	row, _ = s.DB.One(context.Background(), "SELECT * FROM jm_auth_sessions WHERE id = ?", digest(issue.SessionToken))
	if row["revoked_at"] == nil || row["access_token"] != nil {
		t.Fatal("revocation was rolled back")
	}
	_, e = s.AuthenticateSession(context.Background(), issue.SessionToken, true)
	expectError(t, e, 401, "invalid_session")
}
func TestCSRFOriginLogoutAndAmbiguousAuthentication(t *testing.T) {
	s, f := testService(t)
	issue := login(t, s, f)
	ctx := context.Background()
	if e := s.RequireCSRF(ctx, issue.SessionToken, issue.CSRFToken, "https://jobs.example.test"); e != nil {
		t.Fatal(e)
	}
	expectError(t, s.RequireCSRF(ctx, issue.SessionToken, issue.CSRFToken, "https://foreign.example.test"), 403, "csrf_origin_invalid")
	expectError(t, s.RequireCSRF(ctx, issue.SessionToken, strings.Repeat("é", 64), "https://jobs.example.test"), 403, "csrf_invalid")
	_, e := s.AuthenticateRequest(ctx, "Bearer "+f.access(nil), issue.SessionToken, true)
	expectError(t, e, 401, "ambiguous_authentication")
	_, e = s.AuthenticateRequest(ctx, "", "", true)
	expectError(t, e, 401, "authentication_required")
	if e = s.Logout(ctx, issue.SessionToken, issue.CSRFToken, "https://jobs.example.test"); e != nil {
		t.Fatal(e)
	}
	_, e = s.AuthenticateSession(ctx, issue.SessionToken, true)
	expectError(t, e, 401, "invalid_session")
}
func TestPlatformOperatorOnlyExplicitConfiguration(t *testing.T) {
	s, f := testService(t)
	issue := login(t, s, f)
	if issue.Principal.PlatformOperator {
		t.Fatal("unconfigured operator")
	}
	s.Config.PlatformOperatorIDs = []string{issue.Principal.ID}
	p, e := s.AuthenticateSession(context.Background(), issue.SessionToken, true)
	if e != nil || !p.PlatformOperator {
		t.Fatal("explicit operator ignored")
	}
}
func TestJWTBindingsAndTokenKeySelection(t *testing.T) {
	tests := []struct {
		name    string
		changes map[string]any
		headers map[string]any
		code    string
	}{
		{"issuer", map[string]any{"iss": "https://foreign.example.test"}, nil, "invalid_access_token"},
		{"audience", map[string]any{"aud": "different"}, nil, "invalid_access_token"},
		{"expired", map[string]any{"iat": time.Now().Add(-20 * time.Minute).Unix(), "exp": time.Now().Add(-time.Minute).Unix()}, nil, "invalid_access_token"},
		{"scope", map[string]any{"scope": "exchange"}, nil, "invalid_access_scope"},
		{"iat_type", map[string]any{"iat": true}, nil, "invalid_access_token"},
		{"sub_type", map[string]any{"sub": 12}, nil, "invalid_access_token"},
		{"future", map[string]any{"iat": time.Now().Add(time.Hour).Unix(), "exp": time.Now().Add(2 * time.Hour).Unix()}, nil, "invalid_access_token"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newIssuer(t)
			p := testProvider(t, f)
			_, e := p.AuthenticateAccessToken(context.Background(), f.access(test.changes))
			expectError(t, e, 401, test.code)
		})
	}
	f := newIssuer(t)
	p := testProvider(t, f)
	raw := f.sign(jwt.MapClaims{"iss": testIssuer, "sub": "alice", "aud": "hf2l-jobs", "iat": f.now.Unix(), "exp": f.now.Add(time.Minute).Unix(), "scope": "jobs"}, map[string]any{"kid": "test-key", "typ": "JWT"})
	_, e := p.AuthenticateAccessToken(context.Background(), raw)
	expectError(t, e, 401, "invalid_access_token")
	for _, header := range []string{"jku", "x5u", "jwk"} {
		raw = f.sign(jwt.MapClaims{"iss": testIssuer, "sub": "alice", "aud": "hf2l-jobs", "iat": f.now.Unix(), "exp": f.now.Add(time.Minute).Unix(), "scope": "jobs"}, map[string]any{"kid": "test-key", "typ": "at+jwt", header: "https://evil.invalid/keys"})
		_, e = p.AuthenticateAccessToken(context.Background(), raw)
		expectError(t, e, 401, "invalid_access_token")
	}
	if len(f.requests) != 0 {
		t.Fatal("untrusted token header caused network fetch")
	}
}
func TestJWKSCacheAndUnknownKeyThrottle(t *testing.T) {
	f := newIssuer(t)
	p := testProvider(t, f)
	ctx := context.Background()
	raw := f.access(nil)
	for i := 0; i < 3; i++ {
		if _, e := p.AuthenticateAccessToken(ctx, raw); e != nil {
			t.Fatal(e)
		}
	}
	if f.jwksCalls != 1 {
		t.Fatal("JWKS not cached")
	}
	claims := jwt.MapClaims{"iss": testIssuer, "sub": "alice", "aud": "hf2l-jobs", "iat": f.now.Unix(), "exp": f.now.Add(time.Minute).Unix(), "scope": "jobs"}
	unknown := f.sign(claims, map[string]any{"kid": "unknown", "typ": "at+jwt"})
	_, e := p.AuthenticateAccessToken(ctx, unknown)
	expectError(t, e, 401, "invalid_access_token")
	if f.jwksCalls != 1 {
		t.Fatal("unknown key bypassed refresh throttle")
	}
	f.now = f.now.Add(3 * time.Second)
	_, e = p.AuthenticateAccessToken(ctx, unknown)
	expectError(t, e, 401, "invalid_access_token")
	if f.jwksCalls != 2 {
		t.Fatal("unknown key did not get bounded refresh")
	}
}
func TestIDTokenNonceAudienceAndHashes(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		claims     map[string]any
	}{
		{"nonce", "invalid_oidc_nonce", map[string]any{"nonce": "wrong"}},
		{"nonascii_nonce", "invalid_oidc_nonce", map[string]any{"nonce": "é"}},
		{"azp", "invalid_oidc_authorized_party", map[string]any{"aud": []string{"dashboard", "other"}}},
		{"at_hash", "invalid_oidc_token_hash", map[string]any{"at_hash": "wrong"}},
		{"c_hash", "invalid_oidc_token_hash", map[string]any{"c_hash": "wrong"}},
		{"sid", "invalid_oidc_session", map[string]any{"sid": 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, f := testService(t)
			start, state := begin(t, s, f)
			f.overrides = tc.claims
			_, e := s.FinishLogin(context.Background(), "test-code", state, start.StateCookie)
			expectError(t, e, 401, tc.code)
		})
	}
	s, f := testService(t)
	start, state := begin(t, s, f)
	ah, _ := halfHash("opaque-access")
	ch, _ := halfHash("test-code")
	f.overrides = map[string]any{"at_hash": ah, "c_hash": ch}
	if _, e := s.FinishLogin(context.Background(), "test-code", state, start.StateCookie); e != nil {
		t.Fatal(e)
	}
}
func TestDiscoveryBoundariesAndResponseLimit(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		override   map[string]any
	}{
		{"issuer", "identity_provider_issuer_mismatch", map[string]any{"issuer": "https://other.example.test"}},
		{"endpoint", "identity_provider_endpoint_rejected", map[string]any{"token_endpoint": "https://other.example.test/token"}},
		{"http", "identity_provider_endpoint_rejected", map[string]any{"jwks_uri": "http://127.0.0.1/jwks"}},
		{"pkce", "identity_provider_pkce_required", map[string]any{"code_challenge_methods_supported": []string{"plain"}}},
		{"algorithm", "identity_provider_algorithm_rejected", map[string]any{"id_token_signing_alg_values_supported": []string{"HS256"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newIssuer(t)
			f.discoveryOverrides = tc.override
			p := testProvider(t, f)
			_, e := p.Discovery(context.Background())
			expectError(t, e, 503, tc.code)
		})
	}
	f := newIssuer(t)
	f.responseLimit = true
	p := testProvider(t, f)
	_, e := p.Discovery(context.Background())
	expectError(t, e, 503, "identity_provider_invalid_response")
}
func TestOnlineIdentityBindingAndFreshAuthorization(t *testing.T) {
	for _, overrides := range []map[string]any{{"active": false}, {"sub": "bob"}, {"iss": "https://other.example.test"}, {"client_id": "other"}, {"exp": false}} {
		f := newIssuer(t)
		f.introspectionOverrides = overrides
		p := testProvider(t, f)
		active, e := p.OnlineCheck(context.Background(), "token", "alice")
		if e != nil || active {
			t.Fatalf("bad introspection accepted %v %v", active, e)
		}
	}
	f := newIssuer(t)
	f.introspection = false
	p := testProvider(t, f)
	_, e := p.AuthenticateAccessToken(context.Background(), f.access(map[string]any{"iat": f.now.Add(-901 * time.Second).Unix()}))
	expectError(t, e, 401, "fresh_authorization_required")
	s, f := testService(t)
	f.introspection = false
	issue := login(t, s, f)
	f.now = f.now.Add(15 * time.Minute)
	_, e = s.AuthenticateSession(context.Background(), issue.SessionToken, true)
	expectError(t, e, 401, "fresh_authorization_required")
}
func TestBackchannelLogoutSIDSubjectAndReplay(t *testing.T) {
	s, f := testService(t)
	first := login(t, s, f)
	second := login(t, s, f)
	claims := jwt.MapClaims{"iss": testIssuer, "aud": "dashboard", "iat": f.now.Unix(), "jti": "logout-1", "events": map[string]any{LogoutEvent: map[string]any{}}, "sid": "provider-session", "sub": "alice"}
	raw := f.sign(claims, map[string]any{"kid": "test-key"})
	if e := s.BackchannelLogout(context.Background(), raw); e != nil {
		t.Fatal(e)
	}
	for _, issue := range []SessionIssue{first, second} {
		_, e := s.AuthenticateSession(context.Background(), issue.SessionToken, true)
		expectError(t, e, 401, "invalid_session")
	}
	expectError(t, s.BackchannelLogout(context.Background(), raw), 401, "logout_token_replayed")
	for _, change := range []map[string]any{{"nonce": "forbidden"}, {"events": map[string]any{"wrong": map[string]any{}}}, {"iss": "https://other.example.test"}, {"iat": f.now.Add(-301 * time.Second).Unix()}, {"sub": nil, "sid": nil}} {
		modified := jwt.MapClaims{}
		for k, v := range claims {
			modified[k] = v
		}
		for k, v := range change {
			modified[k] = v
		}
		raw = f.sign(modified, map[string]any{"kid": "test-key"})
		_, e := s.Provider.LogoutIdentity(context.Background(), raw)
		expectError(t, e, 401, "invalid_logout_token")
	}
}
func TestConfigurationAndFixedPublicKey(t *testing.T) {
	for _, change := range []func(*OIDCConfig){
		func(c *OIDCConfig) { c.Issuer = "http://remote.example.test" },
		func(c *OIDCConfig) { c.RedirectURI += "?bad=1" },
		func(c *OIDCConfig) { c.JWKSURL = "https://different.example.test/key" },
		func(c *OIDCConfig) { c.EndpointOrigins = []string{"https://different.example.test/path"} },
		func(c *OIDCConfig) { c.PublicKey = "key"; c.JWKSURL = testIssuer + "/jwks" },
		func(c *OIDCConfig) { c.TimeoutSeconds = 31 },
	} {
		c := testConfig().OIDC
		change(&c)
		if c.Validate() == nil {
			t.Fatal("invalid config accepted")
		}
	}
	c := testConfig().OIDC
	c.Issuer = "http://127.0.0.1:9876"
	c.RedirectURI = "http://localhost:1234/auth/callback"
	c.AllowLocalHTTP = true
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	f := newIssuer(t)
	cfg := testConfig().OIDC
	der, e := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	cfg.PublicKey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	p, e := NewOIDCProvider(cfg, &http.Client{Transport: roundTripFunc(f.handle)})
	if e != nil {
		t.Fatal(e)
	}
	p.Clock = func() time.Time { return f.now }
	if _, e = p.AuthenticateAccessToken(context.Background(), f.access(nil)); e != nil {
		t.Fatal(e)
	}
	if f.jwksCalls != 0 {
		t.Fatal("fixed verification key fetched JWKS")
	}
}
func TestPrunePreservesActiveSessions(t *testing.T) {
	s, f := testService(t)
	issue := login(t, s, f)
	if _, e := s.PruneExpired(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e := s.AuthenticateSession(context.Background(), issue.SessionToken, true); e != nil {
		t.Fatal(e)
	}
	f.now = f.now.Add(SessionIdle)
	counts, e := s.PruneExpired(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if counts["sessions"] != 1 {
		t.Fatal(counts)
	}
}

func TestConcurrentLoginStateHasOneWinner(t *testing.T) {
	s, f := testService(t)
	start, state := begin(t, s, f)
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, e := s.FinishLogin(context.Background(), "test-code", state, start.StateCookie)
			results <- e
		}()
	}
	successes := 0
	for i := 0; i < 2; i++ {
		e := <-results
		if e == nil {
			successes++
		} else {
			expectError(t, e, 401, "invalid_authorization_state")
		}
	}
	if successes != 1 {
		t.Fatalf("login state accepted %d times", successes)
	}
}
func TestConcurrentJWKSRequestsShareVerifiedCache(t *testing.T) {
	f := newIssuer(t)
	p := testProvider(t, f)
	raw := f.access(nil)
	results := make(chan error, 12)
	for i := 0; i < 12; i++ {
		go func() { _, e := p.AuthenticateAccessToken(context.Background(), raw); results <- e }()
	}
	for i := 0; i < 12; i++ {
		if e := <-results; e != nil {
			t.Fatal(e)
		}
	}
	if f.jwksCalls != 1 {
		t.Fatalf("concurrent requests fetched JWKS%d times", f.jwksCalls)
	}
}
func TestJWKSPrivateWeakAndDuplicateKeysRejected(t *testing.T) {
	f := newIssuer(t)
	exponent := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes())
	valid := map[string]any{"kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()), "e": exponent}
	for _, kind := range []string{"private", "weak", "duplicate", "invalidExponent", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			entry := map[string]any{}
			for k, v := range valid {
				entry[k] = v
			}
			keys := []any{entry}
			switch kind {
			case "private":
				entry["d"] = "private-value"
			case "weak":
				entry["n"] = base64.RawURLEncoding.EncodeToString(big.NewInt(3).Bytes())
			case "duplicate":
				keys = append(keys, entry)
			case "invalidExponent":
				entry["e"] = base64.RawURLEncoding.EncodeToString([]byte{2})
			case "oversized":
				keys = make([]any, 101)
			}
			p, e := NewOIDCProvider(testConfig().OIDC, &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path == "/jwks" {
					return response(200, map[string]any{"keys": keys}), nil
				}
				return f.handle(req)
			})})
			if e != nil {
				t.Fatal(e)
			}
			p.Clock = func() time.Time { return f.now }
			_, e = p.AuthenticateAccessToken(context.Background(), f.access(nil))
			expectError(t, e, 503, "identity_provider_invalid_jwks")
		})
	}
}

func TestNonFiniteOIDCTimeoutRejected(t *testing.T) {
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		c := testConfig().OIDC
		c.TimeoutSeconds = v
		if err := c.Validate(); err == nil {
			t.Fatal("nonfinite timeout accepted")
		}
	}
}

func TestConfigurationFormattingDoesNotExposeSecrets(t *testing.T) {
	c := testConfig()
	c.OIDC.ClientSecret = "private-client-secret"
	for _, format := range []string{"%v", "%+v", "%#v"} {
		for _, v := range []any{c, c.OIDC} {
			output := fmt.Sprintf(format, v)
			if strings.Contains(output, c.SessionSecret) || strings.Contains(output, c.OIDC.ClientSecret) {
				t.Fatal("configuration formatting exposed credentials")
			}
		}
	}
}
