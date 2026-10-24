package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/auth"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/golang-jwt/jwt/v5"
)

var keyFixture struct {
	once            sync.Once
	human, workload *rsa.PrivateKey
	err             error
}

type fixture struct {
	human, workload *rsa.PrivateKey
	settings        config.AuthSettings
	now             time.Time
}

func publicPEM(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	raw, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: raw}))
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	keyFixture.once.Do(func() {
		keyFixture.human, keyFixture.err = rsa.GenerateKey(rand.Reader, 2048)
		if keyFixture.err == nil {
			keyFixture.workload, keyFixture.err = rsa.GenerateKey(rand.Reader, 2048)
		}
	})
	if keyFixture.err != nil {
		t.Fatal(keyFixture.err)
	}
	s := config.DefaultAuth()
	s.Issuer = "https://humans.example.test"
	s.PublicKey = publicPEM(t, &keyFixture.human.PublicKey)
	s.AdminSubject = "owner"
	s.WorkloadIssuer = "https://workloads.example.test"
	s.WorkloadPublicKey = publicPEM(t, &keyFixture.workload.PublicKey)
	s.TrustedBackendSecret = "public-fixture-terminator-secret-32-characters"
	s.ProvisioningPrincipalIDs = []string{domain.PrincipalID(s.Issuer, "owner")}
	s.DownloadBrokerPrincipalIDs = []string{domain.PrincipalID(s.Issuer, "broker")}
	return fixture{keyFixture.human, keyFixture.workload, s, time.Unix(1730000000, 0)}
}

func (f fixture) humanClaims(overrides jwt.MapClaims) jwt.MapClaims {
	out := jwt.MapClaims{"iss": f.settings.Issuer, "aud": f.settings.Audience, "sub": "owner", "iat": f.now.Unix() - 1, "exp": f.now.Unix() + 60, "scope": "exchange"}
	for k, v := range overrides {
		out[k] = v
	}
	return out
}

func (f fixture) workloadClaims(overrides jwt.MapClaims) jwt.MapClaims {
	out := f.humanClaims(jwt.MapClaims{"iss": f.settings.WorkloadIssuer, "aud": f.settings.WorkloadAudience, "sub": "component-a", "jti": "grant-a", "space_id": "space-a", "job_id": "job-a", "attempt_id": "attempt-a", "component_id": "component-a", "epoch": 1, "cnf": map[string]any{"x5t#S256": strings.Repeat("a", 43)}})
	for k, v := range overrides {
		out[k] = v
	}
	return out
}

func signToken(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims, header map[string]any) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["typ"] = "at+jwt"
	for k, v := range header {
		tok.Header[k] = v
	}
	value, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return "Bearer " + value
}

func authenticator(t *testing.T, f fixture) *auth.Authenticator {
	t.Helper()
	value, err := auth.NewWithOptions(f.settings, auth.Options{Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func requireError(t *testing.T, err error, status int, code string) *domain.Error {
	t.Helper()
	var value *domain.Error
	if !errors.As(err, &value) {
		t.Fatalf("wanted domain error %d/%s, got %T", status, code, err)
	}
	if value.Status != status || value.Code != code {
		t.Fatalf("wanted %d/%s, got %d/%s", status, code, value.Status, value.Code)
	}
	return value
}

func TestHumanAuthenticationAndIdentitySeparation(t *testing.T) {
	f := newFixture(t)
	a := authenticator(t, f)
	for _, scope := range []string{"exchange", "openid exchange profile"} {
		p, err := a.Authenticate(context.Background(), signToken(t, f.human, f.humanClaims(jwt.MapClaims{"scope": scope}), nil), false, "")
		if err != nil {
			t.Fatal(err)
		}
		if p.ID != domain.PrincipalID(f.settings.Issuer, "owner") || p.Subject != "owner" || !p.BootstrapAdmin || p.Workload != nil {
			t.Fatal("human identity or admin boundary changed")
		}
	}
	claims := f.humanClaims(jwt.MapClaims{"sub": "reader", "job_id": "job-foreign", "roles": []string{"admin"}, "space_id": "foreign"})
	p, err := a.Authenticate(context.Background(), signToken(t, f.human, claims, nil), true, "")
	if err != nil || p.BootstrapAdmin || p.Workload != nil || p.ID != domain.PrincipalID(f.settings.Issuer, "reader") {
		t.Fatal("job-shaped claims expanded human authority")
	}
	claims = f.humanClaims(jwt.MapClaims{"aud": []string{"another", f.settings.Audience}})
	if _, err = a.Authenticate(context.Background(), signToken(t, f.human, claims, nil), false, ""); err != nil {
		t.Fatalf("ordinary JWT audience list lost compatibility: %v", err)
	}
}

func TestHumanAuthenticationRejectsInvalidClaimsAndHeaders(t *testing.T) {
	f := newFixture(t)
	a := authenticator(t, f)
	cases := []struct {
		name   string
		values jwt.MapClaims
		header map[string]any
	}{
		{"issuer", jwt.MapClaims{"iss": "https://foreign.example"}, nil},
		{"audience", jwt.MapClaims{"aud": "different"}, nil},
		{"empty_subject", jwt.MapClaims{"sub": ""}, nil},
		{"subject_array", jwt.MapClaims{"sub": []string{"owner"}}, nil},
		{"subject_too_long", jwt.MapClaims{"sub": strings.Repeat("a", 257)}, nil},
		{"scope_missing", jwt.MapClaims{"scope": "openid"}, nil},
		{"scope_array", jwt.MapClaims{"scope": []string{"exchange"}}, nil},
		{"expired", jwt.MapClaims{"exp": f.now.Unix() - 1}, nil},
		{"future_iat", jwt.MapClaims{"iat": f.now.Unix() + 1}, nil},
		{"iat_array", jwt.MapClaims{"iat": []int{1}}, nil},
		{"expiration_object", jwt.MapClaims{"exp": map[string]any{}}, nil},
		{"wrong_type", nil, map[string]any{"typ": "JWT"}},
		{"wrong_type_case", nil, map[string]any{"typ": "AT+JWT"}},
		{"wrong_algorithm_header", nil, map[string]any{"alg": "HS256"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := a.Authenticate(context.Background(), signToken(t, f.human, f.humanClaims(tc.values), tc.header), false, "")
			e := requireError(t, err, 401, "invalid_access_token")
			if e.Headers["WWW-Authenticate"] != "Bearer" {
				t.Fatal("Bearer challenge omitted")
			}
		})
	}
	for _, field := range []string{"exp", "iat", "iss", "aud", "sub"} {
		t.Run("missing_"+field, func(t *testing.T) {
			claims := f.humanClaims(nil)
			delete(claims, field)
			_, err := a.Authenticate(context.Background(), signToken(t, f.human, claims, nil), false, "")
			requireError(t, err, 401, "invalid_access_token")
		})
	}
	for _, bad := range []string{"", "Basic abc", "Bearer ", "Bearer not-a-token", "Bearer a.b.c"} {
		_, err := a.Authenticate(context.Background(), bad, false, "")
		requireError(t, err, 401, "invalid_access_token")
	}
	for _, sub := range []string{strings.Repeat("界", 256), "Alice 🧠\n<admin>\u2028"} {
		p, err := a.Authenticate(context.Background(), signToken(t, f.human, f.humanClaims(jwt.MapClaims{"sub": sub}), nil), false, "")
		if err != nil || p.ID != domain.PrincipalID(f.settings.Issuer, sub) {
			t.Fatal("Unicode subject/principal compatibility failed")
		}
	}
}

func TestWorkloadAuthenticationBindingAndPublicDenial(t *testing.T) {
	f := newFixture(t)
	a := authenticator(t, f)
	thumb := strings.Repeat("a", 43)
	claims := f.workloadClaims(jwt.MapClaims{"sub": "owner", "grant_id": "grant-a"})
	p, err := a.Authenticate(context.Background(), signToken(t, f.workload, claims, nil), true, thumb)
	if err != nil {
		t.Fatal(err)
	}
	if p.BootstrapAdmin || p.ID == domain.PrincipalID(f.settings.Issuer, "owner") || p.ID != domain.PrincipalID(f.settings.WorkloadIssuer, "owner") || p.Workload == nil {
		t.Fatal("workload identity crossed issuer/admin boundary")
	}
	w := p.Workload
	if w.GrantID != "grant-a" || w.SpaceID != "space-a" || w.JobID != "job-a" || w.AttemptID != "attempt-a" || w.ComponentID != "component-a" || w.Epoch != 1 || w.CertificateThumbprint != thumb || w.ExpiresAt != float64(f.now.Unix()+60) {
		t.Fatal("workload bindings changed")
	}
	token := signToken(t, f.workload, f.workloadClaims(nil), nil)
	for _, presented := range []struct {
		managed bool
		thumb   string
	}{{false, thumb}, {true, ""}, {true, "bad"}, {true, strings.Repeat("b", 43)}} {
		_, err = a.Authenticate(context.Background(), token, presented.managed, presented.thumb)
		requireError(t, err, 401, "invalid_access_token")
	}
	claims = f.workloadClaims(jwt.MapClaims{"aud": []string{f.settings.WorkloadAudience}})
	if _, err = a.Authenticate(context.Background(), signToken(t, f.workload, claims, nil), true, thumb); err != nil {
		t.Fatal("ordinary managed audience-list compatibility changed")
	}
	claims = f.workloadClaims(jwt.MapClaims{"iat": f.now.Unix() - 1, "exp": f.now.Unix() + 299})
	if _, err = a.Authenticate(context.Background(), signToken(t, f.workload, claims, nil), true, thumb); err != nil {
		t.Fatal("exact 300-second workload lifetime rejected")
	}
}

func TestWorkloadStrictClaimsLifetimeAndIssuerKeys(t *testing.T) {
	f := newFixture(t)
	a := authenticator(t, f)
	thumb := strings.Repeat("a", 43)
	attacks := []struct {
		name   string
		values jwt.MapClaims
	}{
		{"epoch_boolean", jwt.MapClaims{"epoch": true}}, {"epoch_zero", jwt.MapClaims{"epoch": 0}},
		{"epoch_negative", jwt.MapClaims{"epoch": -1}}, {"epoch_float_lexeme", jwt.MapClaims{"epoch": json.Number("1.0")}},
		{"epoch_overflow", jwt.MapClaims{"epoch": json.Number("9223372036854775808")}},
		{"empty_job", jwt.MapClaims{"job_id": ""}}, {"empty_grant", jwt.MapClaims{"jti": ""}},
		{"space_long", jwt.MapClaims{"space_id": strings.Repeat("a", 65)}},
		{"grant_mismatch", jwt.MapClaims{"grant_id": "different"}},
		{"cnf_extra_key", jwt.MapClaims{"cnf": map[string]any{"x5t#S256": thumb, "jwk": map[string]any{}}}},
		{"cnf_wrong", jwt.MapClaims{"cnf": map[string]any{"x5t#S256": strings.Repeat("b", 43)}}},
		{"cnf_empty", jwt.MapClaims{"cnf": map[string]any{}}},
		{"cnf_string", jwt.MapClaims{"cnf": thumb}},
		{"too_long_lifetime", jwt.MapClaims{"iat": f.now.Unix() - 1, "exp": f.now.Unix() + 300}},
		{"string_exp", jwt.MapClaims{"exp": fmt.Sprint(f.now.Unix() + 60)}},
		{"string_iat", jwt.MapClaims{"iat": fmt.Sprint(f.now.Unix() - 1)}},
		{"boolean_iat", jwt.MapClaims{"iat": false}},
		{"expired", jwt.MapClaims{"exp": f.now.Unix() - 1}},
		{"wrong_aud", jwt.MapClaims{"aud": f.settings.Audience}},
		{"component_array", jwt.MapClaims{"component_id": []string{"component-a"}}},
	}
	for _, tc := range attacks {
		t.Run(tc.name, func(t *testing.T) {
			_, err := a.Authenticate(context.Background(), signToken(t, f.workload, f.workloadClaims(tc.values), nil), true, thumb)
			requireError(t, err, 401, "invalid_access_token")
		})
	}
	for _, field := range []string{"jti", "space_id", "job_id", "attempt_id", "component_id", "epoch", "cnf"} {
		t.Run("missing_"+field, func(t *testing.T) {
			claims := f.workloadClaims(nil)
			delete(claims, field)
			_, err := a.Authenticate(context.Background(), signToken(t, f.workload, claims, nil), true, thumb)
			requireError(t, err, 401, "invalid_access_token")
		})
	}
	for _, item := range []struct {
		key    *rsa.PrivateKey
		claims jwt.MapClaims
	}{
		{f.workload, f.workloadClaims(jwt.MapClaims{"iss": f.settings.Issuer})},
		{f.human, f.workloadClaims(nil)},
	} {
		_, err := a.Authenticate(context.Background(), signToken(t, item.key, item.claims, nil), true, thumb)
		requireError(t, err, 401, "invalid_access_token")
	}
	legacy := f
	legacy.settings.WorkloadIssuer = ""
	legacy.settings.WorkloadPublicKey = ""
	legacy.settings.TrustedBackendSecret = ""
	legacy.settings.ProvisioningPrincipalIDs = nil
	legacy.settings.DownloadBrokerPrincipalIDs = nil
	_, err := authenticator(t, legacy).Authenticate(context.Background(), signToken(t, f.workload, f.workloadClaims(nil), nil), true, thumb)
	requireError(t, err, 401, "invalid_access_token")
}

func TestTransferScopeRequiresExactAudienceAndWorkload(t *testing.T) {
	f := newFixture(t)
	f.settings.WorkloadAudience = "hf2l-transfer"
	a := authenticator(t, f)
	thumb := strings.Repeat("a", 43)
	claims := f.workloadClaims(jwt.MapClaims{"scope": "transfer"})
	if _, err := a.AuthenticateTransfer(context.Background(), signToken(t, f.workload, claims, nil), thumb); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		values jwt.MapClaims
		code   string
	}{
		{"managed_control_audience", jwt.MapClaims{"aud": "exchange-managed", "scope": "transfer"}, "invalid_access_token"},
		{"list_audience", jwt.MapClaims{"aud": []string{"hf2l-transfer"}, "scope": "transfer"}, "invalid_workload_token"},
		{"missing_transfer_scope", jwt.MapClaims{"scope": "exchange"}, "invalid_workload_token"},
		{"array_scope", jwt.MapClaims{"scope": []string{"transfer"}}, "invalid_workload_token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := a.AuthenticateTransfer(context.Background(), signToken(t, f.workload, f.workloadClaims(tc.values), nil), thumb)
			requireError(t, err, 401, tc.code)
		})
	}
	_, err := a.AuthenticateTransfer(context.Background(), signToken(t, f.human, f.humanClaims(jwt.MapClaims{"scope": "transfer exchange"}), nil), thumb)
	requireError(t, err, 401, "workload_identity_required")
}

type oracleFixture struct {
	Principals []struct{ Issuer, Subject, ID string } `json:"principals"`
	Assertions []struct {
		Secret, Method, Target, Authorization, Thumbprint, Signature string
		Timestamp                                                    int64
	} `json:"assertions"`
}

func TestPythonPrincipalAndBackendAssertionOracles(t *testing.T) {
	raw, err := os.ReadFile("testdata/python_auth_oracles.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases oracleFixture
	if err = json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases.Principals {
		if got := domain.PrincipalID(tc.Issuer, tc.Subject); got != tc.ID {
			t.Fatal("Python principal hash oracle mismatch")
		}
	}
	f := newFixture(t)
	for _, tc := range cases.Assertions {
		now := time.Unix(tc.Timestamp, 0)
		h := auth.BackendAssertionHeaders(tc.Secret, tc.Method, tc.Target, tc.Authorization, tc.Thumbprint, now)
		if h.Get("X-HF2L-Backend-Signature") != tc.Signature || h.Get("X-HF2L-Backend-Timestamp") != fmt.Sprint(tc.Timestamp) {
			t.Fatal("Python HMAC oracle mismatch")
		}
		s := f.settings
		s.TrustedBackendSecret = tc.Secret
		got, err := auth.VerifiedBackendThumbprint(s, tc.Method, tc.Target, tc.Authorization, h, now)
		if err != nil || got != tc.Thumbprint {
			t.Fatal("Python assertion oracle failed verification")
		}
		lower := http.Header{}
		for k, v := range h {
			lower[strings.ToLower(k)] = v
		}
		if _, err = auth.VerifiedBackendThumbprint(s, tc.Method, tc.Target, tc.Authorization, lower, now); err != nil {
			t.Fatal("assertion headers stopped being case-insensitive")
		}
	}
}

func TestBackendAssertionsBindEveryFieldAndTime(t *testing.T) {
	f := newFixture(t)
	thumb := strings.Repeat("a", 43)
	method, target, token := "GET", "/v2/spaces/space-a?limit=1", "Bearer opaque-test-token"
	h := auth.BackendAssertionHeaders(f.settings.TrustedBackendSecret, method, target, token, thumb, f.now)
	for _, tc := range []struct {
		name, method, target, token string
		mutate                      func(http.Header)
		now                         time.Time
	}{
		{"method", "POST", target, token, nil, f.now}, {"path", method, "/v2/spaces/space-b?limit=1", token, nil, f.now},
		{"query", method, "/v2/spaces/space-a?limit=2", token, nil, f.now}, {"token", method, target, token + "x", nil, f.now},
		{"certificate", method, target, token, func(h http.Header) { h.Set("X-HF2L-TLS-Thumbprint", strings.Repeat("b", 43)) }, f.now},
		{"signature", method, target, token, func(h http.Header) { h.Set("X-HF2L-Backend-Signature", strings.Repeat("0", 64)) }, f.now},
		{"missing", method, target, token, func(h http.Header) { h.Del("X-HF2L-Backend-Signature") }, f.now},
		{"malformed_thumb", method, target, token, func(h http.Header) { h.Set("X-HF2L-TLS-Thumbprint", "bad") }, f.now},
		{"stale", method, target, token, nil, f.now.Add(31 * time.Second)},
		{"future", method, target, token, nil, f.now.Add(-31 * time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := h.Clone()
			if tc.mutate != nil {
				tc.mutate(value)
			}
			_, err := auth.VerifiedBackendThumbprint(f.settings, tc.method, tc.target, tc.token, value, tc.now)
			requireError(t, err, 401, "invalid_backend_assertion")
		})
	}
	for _, delta := range []time.Duration{-30 * time.Second, 30 * time.Second} {
		if _, err := auth.VerifiedBackendThumbprint(f.settings, method, target, token, h, f.now.Add(delta)); err != nil {
			t.Fatal("exact 30-second tolerance changed")
		}
	}
	s := f.settings
	s.WorkloadIssuer = ""
	s.WorkloadPublicKey = ""
	if _, err := auth.VerifiedBackendThumbprint(s, method, target, token, h, f.now); err == nil {
		t.Fatal("disabled workloads accepted backend assertion")
	}
}

type jwksFixture struct {
	mu     sync.Mutex
	key    *rsa.PublicKey
	kid    string
	status int
	delay  time.Duration
	calls  atomic.Int64
	server *httptest.Server
}

func newJWKS(t *testing.T, key *rsa.PublicKey, kid string) *jwksFixture {
	t.Helper()
	j := &jwksFixture{key: key, kid: kid, status: 200}
	j.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		j.calls.Add(1)
		j.mu.Lock()
		key, kid, status, delay := j.key, j.kid, j.status, j.delay
		j.mu.Unlock()
		if delay > 0 {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(delay):
			}
		}
		if status != 200 {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		e := big.NewInt(int64(key.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid, "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e)}}})
	}))
	t.Cleanup(j.server.Close)
	return j
}

func jwksAuth(t *testing.T, f fixture, j *jwksFixture, now func() time.Time) *auth.Authenticator {
	t.Helper()
	s := f.settings
	s.PublicKey = ""
	s.JWKSURL = j.server.URL + "/keys"
	s.JWKSTimeout = 1
	s.JWKSCacheSeconds = 1
	a, err := auth.NewWithOptions(s, auth.Options{HTTPClient: j.server.Client(), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestJWKSHTTPSCacheAndUnknownKidRotation(t *testing.T) {
	f := newFixture(t)
	j := newJWKS(t, &f.human.PublicKey, "first")
	var stamp atomic.Int64
	stamp.Store(f.now.Unix())
	a := jwksAuth(t, f, j, func() time.Time { return time.Unix(stamp.Load(), 0) })
	first := signToken(t, f.human, f.humanClaims(nil), map[string]any{"kid": "first"})
	for i := 0; i < 2; i++ {
		if _, err := a.Authenticate(context.Background(), first, false, ""); err != nil {
			t.Fatal(err)
		}
	}
	if j.calls.Load() != 1 {
		t.Fatal("cached key triggered another network call")
	}
	j.mu.Lock()
	j.key = &f.workload.PublicKey
	j.kid = "second"
	j.mu.Unlock()
	second := signToken(t, f.workload, f.humanClaims(nil), map[string]any{"kid": "second"})
	if _, err := a.Authenticate(context.Background(), second, false, ""); err != nil {
		t.Fatal("kid rotation did not refresh current JWKS")
	}
	if j.calls.Load() != 2 {
		t.Fatal("unknown kid did not trigger exactly one refresh")
	}
	unknown := signToken(t, f.human, f.humanClaims(nil), map[string]any{"kid": "absent"})
	if _, err := a.Authenticate(context.Background(), unknown, false, ""); err == nil {
		t.Fatal("unknown key ID accepted")
	}
	stamp.Add(2)
	if _, err := a.Authenticate(context.Background(), second, false, ""); err != nil {
		t.Fatal(err)
	}
	if j.calls.Load() != 4 {
		t.Fatal("expired JWKS was not refreshed once")
	}
}

func TestJWKSOutageCooldownAndRecovery(t *testing.T) {
	f := newFixture(t)
	j := newJWKS(t, &f.human.PublicKey, "first")
	j.mu.Lock()
	j.status = 503
	j.mu.Unlock()
	var stamp atomic.Int64
	stamp.Store(f.now.Unix())
	a := jwksAuth(t, f, j, func() time.Time { return time.Unix(stamp.Load(), 0) })
	token := signToken(t, f.human, f.humanClaims(nil), map[string]any{"kid": "first"})
	for _, advance := range []int64{0, 0, 2} {
		stamp.Add(advance)
		_, err := a.Authenticate(context.Background(), token, false, "")
		e := requireError(t, err, 503, "identity_provider_unavailable")
		if e.Headers["Retry-After"] != "3" {
			t.Fatal("outage retry header changed")
		}
	}
	if j.calls.Load() != 1 {
		t.Fatal("cooldown allowed a JWKS fetch storm")
	}
	stamp.Add(2)
	j.mu.Lock()
	j.status = 200
	j.mu.Unlock()
	if _, err := a.Authenticate(context.Background(), token, false, ""); err != nil {
		t.Fatal("identity provider recovery failed")
	}
	if j.calls.Load() != 2 {
		t.Fatal("recovery did not retry once after cooldown")
	}
}

func TestJWKSFetchTimeoutAndConcurrentCache(t *testing.T) {
	f := newFixture(t)
	t.Run("timeout", func(t *testing.T) {
		j := newJWKS(t, &f.human.PublicKey, "first")
		j.mu.Lock()
		j.delay = 3 * time.Second
		j.mu.Unlock()
		a := jwksAuth(t, f, j, func() time.Time { return f.now })
		start := time.Now()
		_, err := a.Authenticate(context.Background(), signToken(t, f.human, f.humanClaims(nil), map[string]any{"kid": "first"}), false, "")
		requireError(t, err, 503, "identity_provider_unavailable")
		if time.Since(start) > 2*time.Second {
			t.Fatal("JWKS timeout was not bounded")
		}
	})
	t.Run("concurrent", func(t *testing.T) {
		j := newJWKS(t, &f.human.PublicKey, "first")
		a := jwksAuth(t, f, j, func() time.Time { return f.now })
		token := signToken(t, f.human, f.humanClaims(nil), map[string]any{"kid": "first"})
		var wg sync.WaitGroup
		errs := make(chan error, 12)
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); _, err := a.Authenticate(context.Background(), token, false, ""); errs <- err }()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		if j.calls.Load() != 1 {
			t.Fatal("concurrent key selection duplicated fetches")
		}
	})
}

func TestRejectedJWTAlgorithmsAndMissingType(t *testing.T) {
	f := newFixture(t)
	a := authenticator(t, f)
	for _, method := range []jwt.SigningMethod{jwt.SigningMethodHS256, jwt.SigningMethodNone, jwt.SigningMethodRS512} {
		t.Run(method.Alg(), func(t *testing.T) {
			tok := jwt.NewWithClaims(method, f.humanClaims(nil))
			tok.Header["typ"] = "at+jwt"
			var key any = f.human
			if method == jwt.SigningMethodHS256 {
				key = []byte(f.settings.PublicKey)
			}
			if method == jwt.SigningMethodNone {
				key = jwt.UnsafeAllowNoneSignatureType
			}
			value, err := tok.SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			_, err = a.Authenticate(context.Background(), "Bearer "+value, false, "")
			requireError(t, err, 401, "invalid_access_token")
		})
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, f.humanClaims(nil))
	delete(tok.Header, "typ")
	value, err := tok.SignedString(f.human)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Authenticate(context.Background(), "Bearer "+value, false, "")
	requireError(t, err, 401, "invalid_access_token")
}

func TestBackendAssertionsRejectDuplicateHeaders(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"X-HF2L-Backend-Timestamp", "X-HF2L-Backend-Signature", "X-HF2L-TLS-Thumbprint"} {
		t.Run(name, func(t *testing.T) {
			h := auth.BackendAssertionHeaders(f.settings.TrustedBackendSecret, "GET", "/v2/spaces/a", "Bearer test-token", strings.Repeat("a", 43), f.now)
			h.Add(name, h.Get(name))
			_, err := auth.VerifiedBackendThumbprint(f.settings, "GET", "/v2/spaces/a", "Bearer test-token", h, f.now)
			requireError(t, err, 401, "invalid_backend_assertion")
		})
	}
	h := auth.BackendAssertionHeaders(f.settings.TrustedBackendSecret, "GET", "/v2/spaces/a", "Bearer test-token", strings.Repeat("a", 43), f.now)
	h["x-hf2l-backend-signature"] = []string{h.Get("X-HF2L-Backend-Signature")}
	_, err := auth.VerifiedBackendThumbprint(f.settings, "GET", "/v2/spaces/a", "Bearer test-token", h, f.now)
	requireError(t, err, 401, "invalid_backend_assertion")
}

func TestJWKSResponseAndRedirectGuards(t *testing.T) {
	f := newFixture(t)
	key := &f.human.PublicKey
	good := map[string]any{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "first", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}
	valid, err := json.Marshal(map[string]any{"keys": []any{good}})
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := json.Marshal(map[string]any{"keys": []any{good, good}})
	if err != nil {
		t.Fatal(err)
	}
	oversized := append(append([]byte{}, valid[:len(valid)-1]...), []byte(`,"padding":"`+strings.Repeat("x", 2<<20)+`"}`)...)
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"malformed_json", []byte("{")},
		{"nonobject", []byte("[]")},
		{"missing_keys", []byte("{}")},
		{"no_keys", []byte(`{"keys":[]}`)},
		{"no_rsa", []byte(`{"keys":[{"kty":"oct","kid":"first","k":"cHVibGlj"}]}`)},
		{"duplicate_kid", duplicate},
		{"oversized", oversized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(tc.body)
			}))
			defer server.Close()
			s := f.settings
			s.PublicKey = ""
			s.JWKSURL = server.URL + "/keys"
			a, err := auth.NewWithOptions(s, auth.Options{HTTPClient: server.Client(), Now: func() time.Time { return f.now }})
			if err != nil {
				t.Fatal(err)
			}
			_, err = a.Authenticate(context.Background(), signToken(t, f.human, f.humanClaims(nil), map[string]any{"kid": "first"}), false, "")
			requireError(t, err, 401, "invalid_access_token")
		})
	}
	t.Run("redirect_downgrade", func(t *testing.T) {
		var downstream atomic.Int64
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			downstream.Add(1)
			_, _ = w.Write(valid)
		}))
		defer target.Close()
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/keys", http.StatusFound)
		}))
		defer server.Close()
		s := f.settings
		s.PublicKey = ""
		s.JWKSURL = server.URL + "/keys"
		a, err := auth.NewWithOptions(s, auth.Options{HTTPClient: server.Client(), Now: func() time.Time { return f.now }})
		if err != nil {
			t.Fatal(err)
		}
		_, err = a.Authenticate(context.Background(), signToken(t, f.human, f.humanClaims(nil), map[string]any{"kid": "first"}), false, "")
		requireError(t, err, 503, "identity_provider_unavailable")
		if downstream.Load() != 0 {
			t.Fatal("fixed JWKS endpoint followed a redirect to another authority")
		}
	})
}

func TestLegacyHumanNumericDateCompatibility(t *testing.T) {
	f := newFixture(t)
	a := authenticator(t, f)
	for _, tc := range []struct {
		name   string
		values jwt.MapClaims
	}{
		{"decimal_strings", jwt.MapClaims{"iat": "1729999999", "exp": "1730000060", "nbf": "1729999999"}},
		{"legacy_integer_strings", jwt.MapClaims{"iat": "\t+1_729_999_999 ", "exp": " +1_730_000_060 ", "nbf": " 1_729_999_999\n"}},
		{"legacy_boolean_iat_nbf", jwt.MapClaims{"iat": false, "nbf": true}},
		{"fractional_numeric_dates", jwt.MapClaims{"iat": json.Number("1730000000.9"), "exp": json.Number("1730000060.9"), "nbf": json.Number("1730000000.9")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := a.Authenticate(context.Background(), signToken(t, f.human, f.humanClaims(tc.values), nil), false, "")
			if err != nil {
				t.Fatalf("legacy human NumericDate compatibility changed: %v", err)
			}
		})
	}
	for _, bad := range []string{"1730000060.0", "1e20", "", " ", "1__730000060", "_1730000060", "1730000060_", "NaN"} {
		_, err := a.Authenticate(context.Background(), signToken(t, f.human, f.humanClaims(jwt.MapClaims{"exp": bad}), nil), false, "")
		requireError(t, err, 401, "invalid_access_token")
	}
	for _, values := range []jwt.MapClaims{
		{"iat": "1729999999", "exp": "1730000060"},
		{"iat": false},
		{"nbf": "1729999999"},
		{"nbf": false},
	} {
		_, err := a.Authenticate(context.Background(), signToken(t, f.workload, f.workloadClaims(values), nil), true, strings.Repeat("a", 43))
		requireError(t, err, 401, "invalid_access_token")
	}
}
