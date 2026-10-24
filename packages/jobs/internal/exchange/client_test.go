package exchange

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

func testClient(t *testing.T, handler http.HandlerFunc, configure func(*Config)) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	cfg := Config{Endpoint: server.URL, Token: "fixture-access-token", CAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), Sleep: func(context.Context, time.Duration) error { return nil }}
	if configure != nil {
		configure(&cfg)
	}
	c, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	return c, server
}
func TestFixedOriginTLSPolicyAndNoCallerCredentialOverrides(t *testing.T) {
	for _, endpoint := range []string{"http://public.example", "http://127.0.0.1", "https://user:password@example.test", "https://example.test/path", "https://example.test?query=1", "https://example.test#fragment", "file:///tmp/token", "https://example.test:99999", "https://example.test/%2f"} {
		if _, e := New(Config{Endpoint: endpoint, Token: "fixture"}); e == nil {
			t.Fatalf("accepted %s", endpoint)
		}
	}
	if _, e := ServiceEndpoint("http://localhost:1234", true); e != nil {
		t.Fatal(e)
	}
	if _, e := ServiceEndpoint("http://public.example:1234", true); e == nil {
		t.Fatal("public HTTP fixture escape")
	}
	var calls atomic.Int64
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, "{}")
	}, nil)
	for _, headers := range []map[string]string{{"Authorization": "Bearer other"}, {"Cookie": "session=other"}, {"Proxy-Authorization": "Basic stolen"}, {"Host": "elsewhere"}, {"X-Header": "line\r\nAuthorization: injected"}} {
		_, e := c.Request(context.Background(), "GET", "/v2/spaces/a", nil, headers, nil)
		if e == nil {
			t.Fatal("caller credential/header override")
		}
	}
	for _, path := range []string{"https://elsewhere.invalid/v2", "//elsewhere.invalid/path", "/v2/../spaces/a", "/v2/%2e%2e/spaces/a", "/v2/spaces/a?token=bad", "/v2/\\other"} {
		_, e := c.Request(context.Background(), "GET", path, nil, nil, nil)
		if e == nil {
			t.Fatal("unsafe path", path)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("unsafe request reached trusted origin")
	}
}
func TestRetriesKeepIdempotencyBodyAndDoNotUseEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	calls := 0
	var bodies []string
	var observedKeys []string
	var delays []time.Duration
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(raw))
		observedKeys = append(observedKeys, r.Header.Get("Idempotency-Key"))
		if r.Header.Get("Authorization") != "Bearer fixture-access-token" {
			t.Error("missing fixed credential")
		}
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			w.Header().Set("Retry-After", "999")
			w.WriteHeader(503)
			io.WriteString(w, `{"error":{"code":"temporary"}}`)
			return
		}
		w.WriteHeader(201)
		io.WriteString(w, `{"id":"space-a","count":1}`)
	}, func(cfg *Config) {
		cfg.Sleep = func(ctx context.Context, d time.Duration) error { delays = append(delays, d); return nil }
	})
	value, e := c.CreateSpace(context.Background(), "test", "fedavg.v1", "persistent-operation-a", map[string]any{"quota_bytes": int64(123)})
	if e != nil || calls != 2 || observedKeys[0] != "persistent-operation-a" || observedKeys[1] != observedKeys[0] || bodies[0] != bodies[1] || len(delays) != 1 || delays[0] != 60*time.Second {
		t.Fatalf("retry protocol: %v calls%d keys%v delays%v", e, calls, observedKeys, delays)
	}
	if n, ok := value["count"].(json.Number); !ok || n.String() != "1" {
		t.Fatal("response lost exact JSON integer")
	}
}
func TestRedirectDoesNotForwardCredentials(t *testing.T) {
	var foreignCalls atomic.Int64
	foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignCalls.Add(1)
		t.Error("credential-bearing redirect followed")
	}))
	defer foreign.Close()
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", foreign.URL+"/stolen")
		w.WriteHeader(307)
	}, nil)
	_, e := c.GetSpace(context.Background(), "space-a")
	assertCode(t, e, 307, "request_failed")
	if foreignCalls.Load() != 0 {
		t.Fatal("redirect reached foreign origin")
	}
}
func TestRenewableProviderRefreshesAfterUnauthorized(t *testing.T) {
	tokenCalls := 0
	httpCalls := 0
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		httpCalls++
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "Bearer first-token" {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":{"code":"invalid_access_token"}}`)
			return
		}
		io.WriteString(w, `{"id":"space-a"}`)
	}, func(cfg *Config) {
		cfg.Token = ""
		cfg.TokenProvider = func(context.Context) (string, error) {
			tokenCalls++
			if tokenCalls == 1 {
				return "first-token", nil
			}
			return "second-token", nil
		}
	})
	if _, e := c.GetSpace(context.Background(), "space-a"); e != nil || tokenCalls != 2 || httpCalls != 2 {
		t.Fatalf("renewal: %v calls%d/%d", e, tokenCalls, httpCalls)
	}
}
func TestAtomicPrivateTokenFileReplacementAndRefusals(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	path := filepath.Join(root, "access.token")
	if e := os.WriteFile(path, []byte("old-token\n"), 0600); e != nil {
		t.Fatal(e)
	}
	provider := FileTokenProvider(path)
	if token, e := provider(context.Background()); e != nil || token != "old-token" {
		t.Fatal(e)
	}
	temp := filepath.Join(root, "replacement")
	os.WriteFile(temp, []byte("new-token"), 0600)
	os.Rename(temp, path)
	if token, e := provider(context.Background()); e != nil || token != "new-token" {
		t.Fatal("renewed token not observed", e)
	}
	os.Chmod(path, 0644)
	_, e := provider(context.Background())
	assertCode(t, e, 503, "credential_unavailable")
	os.Chmod(path, 0600)
	alias := filepath.Join(root, "alias.token")
	os.Symlink(path, alias)
	_, e = FileTokenProvider(alias)(context.Background())
	assertCode(t, e, 503, "credential_unavailable")
}
func TestResponseBoundsJSONAndErrorRedaction(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/invalid":
			io.WriteString(w, `{"items":[]} {"another":1}`)
		case "/v2/large":
			io.WriteString(w, strings.Repeat("x", 1025))
		default:
			w.WriteHeader(500)
			io.WriteString(w, `{"error":{"code":"safe_provider_failure","detail":"PRIVATE-TOKEN-SHOULD-NOT-LEAK"}}`)
		}
	}, func(cfg *Config) { cfg.MaxResponseBytes = 1024 })
	_, e := c.Request(context.Background(), "GET", "/v2/invalid", nil, nil, nil)
	assertCode(t, e, 502, "invalid_exchange_response")
	_, e = c.Request(context.Background(), "GET", "/v2/large", nil, nil, nil)
	assertCode(t, e, 502, "exchange_response_too_large")
	_, e = c.Request(context.Background(), "GET", "/v2/failure", nil, nil, nil)
	assertCode(t, e, 500, "safe_provider_failure")
	var d *domain.Error
	errors.As(e, &d)
	if strings.Contains(e.Error(), "PRIVATE") || d.Details != nil {
		t.Fatal("provider details leaked")
	}
}
func TestContextDeadlineAndUnkeyedMutationAreNotBlindlyRetried(t *testing.T) {
	calls := 0
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(503)
		io.WriteString(w, `{"error":{"code":"unavailable"}}`)
	}, nil)
	_, e := c.Request(context.Background(), "POST", "/v2/some-mutation", map[string]any{}, nil, nil)
	assertCode(t, e, 503, "unavailable")
	if calls != 1 {
		t.Fatal("unkeyed mutation replayed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = c.GetSpace(ctx, "space-a")
	assertCode(t, e, 408, "request_cancelled")
}
func TestInvalidTLSRootAndCredentialConfigurationFailClosed(t *testing.T) {
	c, server := testClient(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "{}") }, nil)
	_ = c
	wrong, e := New(Config{Endpoint: server.URL, Token: "fixture", Retries: 1})
	if e != nil {
		t.Fatal(e)
	}
	defer wrong.Close()
	_, e = wrong.GetSpace(context.Background(), "space-a")
	assertCode(t, e, 503, "connection_failed")
	for _, cfg := range []Config{
		{Endpoint: "https://example.test"},
		{Endpoint: "https://example.test", Token: "fixture", TokenFile: "/private/token"},
		{Endpoint: "https://example.test", Token: "Bearer fixture"},
		{Endpoint: "https://example.test", Token: "fixture", CAPEM: []byte("not a CA")},
		{Endpoint: "https://example.test", Token: "fixture", CertificateFile: "/private/cert.pem"},
	} {
		if _, e := New(cfg); e == nil {
			t.Fatal("unsafe client config accepted")
		}
	}
	roots := x509.NewCertPool()
	if roots == nil {
		t.Fatal("unreachable")
	}
}
func TestControlMethodProtocolPathsAndHeaders(t *testing.T) {
	var method, path, key, match string
	var payload map[string]any
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		path = r.URL.Path
		key = r.Header.Get("Idempotency-Key")
		match = r.Header.Get("If-Match")
		json.NewDecoder(r.Body).Decode(&payload)
		io.WriteString(w, `{"id":"opaque","items":[]}`)
	}, nil)
	ctx := context.Background()
	_, e := c.ManageSpace(ctx, "space-a", "job-a", "op-manage")
	if e != nil || method != "PUT" || path != "/v2/spaces/space-a/managed" || key != "op-manage" || payload["job_id"] != "job-a" {
		t.Fatal("manage contract", e)
	}
	_, e = c.CreateGrant(ctx, "space-a", "op-grant", map[string]any{"subject": "job:hash"})
	if e != nil || path != "/v2/spaces/space-a/workload-grants" || key != "op-grant" {
		t.Fatal("grant contract", e)
	}
	_, e = c.RevokeGrants(ctx, "space-a", "attempt-a", "op-revoke")
	if e != nil || path != "/v2/spaces/space-a/workload-grants/revoke" || payload["attempt_id"] != "attempt-a" {
		t.Fatal("revoke contract", e)
	}
	_, e = c.RetireManagedSpace(ctx, "space-a", "job-a", "op-retire")
	if e != nil || path != "/v2/spaces/space-a/managed/retire" {
		t.Fatal("retire contract", e)
	}
	_, e = c.SetRef(ctx, "space-a", "main", "record-a", "op-publish", map[string]any{"name": "main", "token": "generation-3"})
	if e != nil || match != "\"generation-3\"" || payload["record_id"] != "record-a" {
		t.Fatal("reference contract", e)
	}
	_, e = c.Complete(ctx, "space-a", "claim-a", "record-a", "op-complete", int64(4))
	if e != nil || path != "/v2/spaces/space-a/acquisitions/claim-a/complete" || key != "op-complete" {
		t.Fatal("complete contract", e)
	}
	_, e = c.RecordsPage(ctx, "space-a", url.Values{"after": []string{"opaque-cursor"}})
	if e != nil {
		t.Fatal(e)
	}
}

func TestExplicitStandardSizeCABundleIsSupported(t *testing.T) {
	c, server := testClient(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "{}") }, nil)
	_ = c
	root := t.TempDir()
	os.Chmod(root, 0700)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	bundle := strings.Repeat(string(ca), 100)
	if len(bundle) < 65536 {
		t.Fatal("fixture bundle too small")
	}
	path := filepath.Join(root, "ca-bundle.pem")
	if e := os.WriteFile(path, []byte(bundle), 0644); e != nil {
		t.Fatal(e)
	}
	bundled, e := New(Config{Endpoint: server.URL, Token: "fixture", CAFile: path, Retries: 1})
	if e != nil {
		t.Fatal(e)
	}
	defer bundled.Close()
	if _, e = bundled.GetSpace(context.Background(), "space-a"); e != nil {
		t.Fatal(e)
	}
}
