package transfer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/golang-jwt/jwt/v5"
)

type transferFixture struct {
	root, caFile, caKey, clientCert, clientKey, serverCert, serverKey string
	ca, client                                                        *x509.Certificate
	signing                                                           *rsa.PrivateKey
	public                                                            string
	binding                                                           ExecutionBinding
}

func fixtureWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if e := os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
}
func newTransferFixture(t *testing.T) *transferFixture {
	t.Helper()
	f := &transferFixture{root: t.TempDir()}
	if e := os.Chmod(f.root, 0700); e != nil {
		t.Fatal(e)
	}
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Transfer test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	f.ca, e = x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	f.caFile = filepath.Join(f.root, "ca.pem")
	f.caKey = filepath.Join(f.root, "ca-key.pem")
	fixtureWrite(t, f.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	encoded, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	fixtureWrite(t, f.caKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}))
	for _, server := range []bool{false, true} {
		leafKey, e := rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			t.Fatal(e)
		}
		serial := int64(2)
		usage := x509.ExtKeyUsageClientAuth
		prefix := "client"
		if server {
			serial = 3
			usage = x509.ExtKeyUsageServerAuth
			prefix = "server"
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "transfer-" + prefix}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if server {
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			leaf.DNSNames = []string{"localhost"}
		}
		raw, e := x509.CreateCertificate(rand.Reader, leaf, f.ca, &leafKey.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		certPath, keyPath := filepath.Join(f.root, prefix+".pem"), filepath.Join(f.root, prefix+"-key.pem")
		fixtureWrite(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
		encoded, e := x509.MarshalPKCS8PrivateKey(leafKey)
		if e != nil {
			t.Fatal(e)
		}
		fixtureWrite(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}))
		if server {
			f.serverCert, f.serverKey = certPath, keyPath
		} else {
			f.clientCert, f.clientKey = certPath, keyPath
			f.client, e = x509.ParseCertificate(raw)
			if e != nil {
				t.Fatal(e)
			}
		}
	}
	f.signing, e = rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := x509.MarshalPKIXPublicKey(&f.signing.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	f.public = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: raw}))
	f.binding = ExecutionBinding{"job-a", "attempt-a", "owner", "space-a", 1, CertificateThumbprint(f.client.Raw)}
	return f
}
func (f *transferFixture) token(t *testing.T, b ExecutionBinding, audience, scope string, changes map[string]any, header map[string]any) string {
	t.Helper()
	c := jwt.MapClaims{"iss": "https://workloads.example", "aud": audience, "sub": "owner-subject", "jti": "grant-a", "job_id": b.JobID, "attempt_id": b.AttemptID, "component_id": b.ComponentID, "space_id": b.SpaceID, "epoch": b.Epoch, "iat": time.Now().Unix(), "exp": time.Now().Add(2 * time.Minute).Unix(), "scope": scope, "cnf": map[string]any{"x5t#S256": b.CertificateThumbprint}}
	for k, v := range changes {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	token.Header["typ"] = "at+jwt"
	for k, v := range header {
		token.Header[k] = v
	}
	signed, e := token.SignedString(f.signing)
	if e != nil {
		t.Fatal(e)
	}
	return signed
}
func (f *transferFixture) gatewayToken(t *testing.T) string {
	return f.token(t, f.binding, "hf2l-transfer", "transfer", nil, nil)
}
func (f *transferFixture) request(method, path string, body []byte, token string) *http.Request {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.client}, VerifiedChains: [][]*x509.Certificate{{f.client, f.ca}}}
	req.Header.Set("Authorization", "Bearer "+token)
	if method == "PUT" {
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	return req
}
func (f *transferFixture) proxySettings(t *testing.T, endpoint string) ProxySettings {
	return ProxySettings{ExchangeEndpoint: endpoint, GatewayEndpoint: endpoint, ClientCertificate: f.clientCert, ClientKey: f.clientKey, CAFile: f.caFile, Binding: f.binding, WorkloadIssuer: "https://workloads.example", WorkloadPublicKey: f.public, ExchangeAudience: "exchange-managed", GatewayAudience: "hf2l-transfer", ExchangeToken: func(context.Context) (string, error) {
		return f.token(t, f.binding, "exchange-managed", "exchange", nil, nil), nil
	}, GatewayToken: func(context.Context) (string, error) { return f.gatewayToken(t), nil }}
}

type fixtureBackend struct {
	grant     OriginGrant
	calls     atomic.Int64
	begun     atomic.Bool
	finished  atomic.Int64
	authorize func(int64) error
}

func (b *fixtureBackend) Authorize(_ context.Context, _ WorkloadIdentity) error {
	n := b.calls.Add(1)
	if b.authorize != nil {
		return b.authorize(n)
	}
	return nil
}
func (b *fixtureBackend) UploadGrant(context.Context, WorkloadIdentity, string, string, string, int) (OriginGrant, error) {
	return b.grant, nil
}
func (b *fixtureBackend) BeginUpload(context.Context, WorkloadIdentity, string, string, string, int) (string, OriginGrant, error) {
	b.begun.Store(true)
	return "sealed-mutation", b.grant, nil
}
func (b *fixtureBackend) FinishUpload(_ context.Context, _ WorkloadIdentity, handle string) (bool, error) {
	if handle != "sealed-mutation" {
		return false, errors.New("wrong mutation")
	}
	b.finished.Add(1)
	return true, nil
}
func (b *fixtureBackend) DownloadGrant(context.Context, WorkloadIdentity, string, string, string) (OriginGrant, error) {
	return b.grant, nil
}
func fixtureGateway(t *testing.T, f *transferFixture, origin string, backend *fixtureBackend) http.Handler {
	t.Helper()
	h, e := NewGateway(GatewaySettings{Verifier: WorkloadVerifier{Issuer: "https://workloads.example", PublicKey: f.public}, OriginEndpoints: []string{origin}, AllowLocalOriginHTTP: true, ChunkBytes: 1024}, backend)
	if e != nil {
		t.Fatal(e)
	}
	return h
}
func TestWorkloadTokenBindingAndRequiredClaims(t *testing.T) {
	f := newTransferFixture(t)
	verifier := WorkloadVerifier{Issuer: "https://workloads.example", Audience: "hf2l-transfer", Scope: "transfer", PublicKey: f.public}
	if e := verifier.Validate(); e != nil {
		t.Fatal(e)
	}
	if _, e := verifier.Verify(f.gatewayToken(t), f.binding.CertificateThumbprint); e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		name            string
		changes, header map[string]any
	}{
		{"wrong audience", map[string]any{"aud": "exchange-managed"}, nil},
		{"array audience", map[string]any{"aud": []string{"hf2l-transfer"}}, nil},
		{"wrong issuer", map[string]any{"iss": "https://foreign.example"}, nil},
		{"missing timestamp", map[string]any{"iat": nil}, nil},
		{"float epoch", map[string]any{"epoch": json.Number("1.0")}, nil},
		{"zero epoch", map[string]any{"epoch": 0}, nil},
		{"long lifetime", map[string]any{"exp": time.Now().Add(time.Hour).Unix()}, nil},
		{"wrong scope", map[string]any{"scope": "exchange"}, nil},
		{"wrong certificate", map[string]any{"cnf": map[string]any{"x5t#S256": strings.Repeat("a", 43)}}, nil},
		{"extra certificate binding", map[string]any{"cnf": map[string]any{"x5t#S256": f.binding.CertificateThumbprint, "extra": 1}}, nil},
		{"different grant", map[string]any{"grant_id": "foreign"}, nil},
		{"wrong type", nil, map[string]any{"typ": "JWT"}},
		{"token key URL", nil, map[string]any{"jku": "https://attacker.invalid/key"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			token := f.token(t, f.binding, "hf2l-transfer", "transfer", c.changes, c.header)
			if _, e := verifier.Verify(token, f.binding.CertificateThumbprint); e == nil {
				t.Fatal("accepted invalid workload")
			}
		})
	}
}
func TestBackendAssertionsBindEveryRequestField(t *testing.T) {
	secret := strings.Repeat("s", 32)
	stamp := time.Unix(1792771200, 0)
	thumb := strings.Repeat("a", 43)
	headers, e := BackendAssertionHeaders(secret, "post", "/v2/spaces/space-a?name=é🙂<>&", "Bearer opaque", thumb, stamp)
	if e != nil {
		t.Fatal(e)
	}
	const golden = "11c12f79761cb4aeaca75cf52ed1c78f2670976cb5b026945be49f95979b9614"
	if headers.Get("X-HF2L-Backend-Signature") != golden {
		t.Fatal("Python backend assertion mismatch", headers.Get("X-HF2L-Backend-Signature"))
	}
	if _, e := VerifiedBackendThumbprint(secret, "POST", "/v2/spaces/space-a?name=é🙂<>&", "Bearer opaque", headers, stamp); e != nil {
		t.Fatal(e)
	}
	for _, c := range []struct {
		method, target, authorization string
		time                          time.Time
	}{
		{"GET", "/v2/spaces/space-a?name=é🙂<>&", "Bearer opaque", stamp},
		{"POST", "/v2/spaces/foreign", "Bearer opaque", stamp},
		{"POST", "/v2/spaces/space-a?name=é🙂<>&", "Bearer changed", stamp},
		{"POST", "/v2/spaces/space-a?name=é🙂<>&", "Bearer opaque", stamp.Add(31 * time.Second)},
	} {
		if _, e := VerifiedBackendThumbprint(secret, c.method, c.target, c.authorization, headers, c.time); e == nil {
			t.Fatal("accepted substituted assertion")
		}
	}
}
func TestGatewayUploadFencesBeforeBytesAndSettlesOnlyAcknowledgedPUT(t *testing.T) {
	f := newTransferFixture(t)
	for _, status := range []int{204, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			backend := &fixtureBackend{}
			var got atomic.Int64
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !backend.begun.Load() {
					t.Error("provider bytes preceded durable marker")
				}
				data, e := io.ReadAll(r.Body)
				if e != nil {
					t.Error(e)
				}
				if string(data) != "abc" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("wrong body or leaked credentials")
				}
				got.Add(1)
				w.Header().Set("ETag", "part-etag")
				w.WriteHeader(status)
			}))
			defer origin.Close()
			backend.grant = OriginGrant{URL: origin.URL + "/bucket/part", ExpiresAt: float64(time.Now().Add(time.Minute).Unix()), Size: 3}
			h := fixtureGateway(t, f, origin.URL, backend)
			r := f.request("PUT", "/transfers/v1/spaces/space-a/records/r/attachments/a/parts/1", []byte("abc"), f.gatewayToken(t))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if status == 204 {
				if w.Code != 204 || backend.finished.Load() != 1 || w.Header().Get("ETag") != "part-etag" {
					t.Fatal(w.Code, w.Body.String(), backend.finished.Load())
				}
			} else if w.Code != 503 || backend.finished.Load() != 0 {
				t.Fatal("uncertain mutation was settled", w.Code)
			}
			if got.Load() != 1 {
				t.Fatal("origin not invoked exactly once")
			}
		})
	}
}
func TestGatewayDenialsNeverStartProviderMutation(t *testing.T) {
	f := newTransferFixture(t)
	backend := &fixtureBackend{grant: OriginGrant{URL: "http://127.0.0.1:1/part", ExpiresAt: float64(time.Now().Add(time.Minute).Unix()), Size: 3}}
	h := fixtureGateway(t, f, "http://127.0.0.1:1", backend)
	cases := []struct {
		name, path string
		change     func(*http.Request)
		status     int
	}{
		{"forged certificate", "/transfers/v1/spaces/space-a/records/r/attachments/a/parts/1", func(r *http.Request) { r.TLS = nil; r.Header.Set("X-Forwarded-Client-Cert", "fake") }, 400},
		{"foreign space", "/transfers/v1/spaces/foreign/records/r/attachments/a/parts/1", nil, 404},
		{"query", "/transfers/v1/spaces/space-a/records/r/attachments/a/parts/1?q=1", nil, 400},
		{"cookie", "/transfers/v1/spaces/space-a/records/r/attachments/a/parts/1", func(r *http.Request) { r.Header.Set("Cookie", "secret") }, 400},
		{"wrong size", "/transfers/v1/spaces/space-a/records/r/attachments/a/parts/1", func(r *http.Request) { r.ContentLength = 2 }, 400},
		{"part number", "/transfers/v1/spaces/space-a/records/r/attachments/a/parts/10001", nil, 422},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			backend.begun.Store(false)
			r := f.request("PUT", c.path, []byte("abc"), f.gatewayToken(t))
			if c.change != nil {
				c.change(r)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != c.status || backend.begun.Load() {
				t.Fatal(w.Code, w.Body.String(), backend.begun.Load())
			}
		})
	}
}
func TestGatewayDownloadRangeAndRevocationDuringStreaming(t *testing.T) {
	f := newTransferFixture(t)
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "range", true: "revoke"}[revoke], func(t *testing.T) {
			data := bytes.Repeat([]byte("x"), 10000)
			backend := &fixtureBackend{}
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !revoke {
					if r.Header.Get("Range") != "bytes=2-4" {
						t.Error("range not forwarded")
					}
					w.Header().Set("Content-Range", "bytes 2-4/10000")
					w.Header().Set("Content-Length", "3")
					w.WriteHeader(206)
					_, _ = w.Write([]byte("xxx"))
					return
				}
				w.Header().Set("Content-Length", "10000")
				_, _ = w.Write(data)
			}))
			defer origin.Close()
			backend.grant = OriginGrant{URL: origin.URL + "/bucket/object", ExpiresAt: float64(time.Now().Add(time.Minute).Unix()), Size: 10000, SHA256: strings.Repeat("c", 64)}
			if revoke {
				backend.authorize = func(n int64) error {
					if n >= 4 {
						return domain.Err(403, "revoked")
					}
					return nil
				}
			}
			h := fixtureGateway(t, f, origin.URL, backend)
			r := f.request("GET", "/transfers/v1/spaces/space-a/records/r/attachments/a/content", nil, f.gatewayToken(t))
			if !revoke {
				r.Header.Set("Range", "bytes=2-4")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if !revoke {
				if w.Code != 206 || w.Body.String() != "xxx" || w.Header().Get("Content-Range") != "bytes 2-4/10000" {
					t.Fatal(w.Code, w.Body.String())
				}
			} else if w.Code != 200 || w.Body.Len() >= len(data) || backend.calls.Load() < 4 {
				t.Fatal("revocation did not interrupt stream", w.Code, w.Body.Len(), backend.calls.Load())
			}
			if strings.Contains(w.Body.String(), origin.URL) {
				t.Fatal("origin leaked")
			}
		})
	}
}
func TestOriginAllowlistRejectsTraversalExpiredAndCredentialHeaders(t *testing.T) {
	f := newTransferFixture(t)
	s := GatewaySettings{Verifier: WorkloadVerifier{Issuer: "https://workloads.example", PublicKey: f.public}, OriginEndpoints: []string{"https://objects.example/bucket"}}
	if e := s.defaults(); e != nil {
		t.Fatal(e)
	}
	good := OriginGrant{URL: "https://objects.example/bucket/object?X-Amz-Signature=secret", ExpiresAt: float64(time.Now().Add(time.Minute).Unix()), Size: 1}
	if _, _, e := s.checkOrigin(good); e != nil {
		t.Fatal(e)
	}
	for _, value := range []string{"https://foreign.example/bucket/object", "https://objects.example/bucket2/object", "https://objects.example/bucket/%2e%2e/secret", "https://user:secret@objects.example/bucket/object", "https://objects.example/bucket/object#fragment"} {
		bad := good
		bad.URL = value
		if _, _, e := s.checkOrigin(bad); e == nil {
			t.Fatal("accepted unsafe origin", value)
		}
	}
	bad := good
	bad.ExpiresAt = float64(time.Now().Add(-time.Minute).Unix())
	if _, _, e := s.checkOrigin(bad); e == nil {
		t.Fatal("accepted expired descriptor")
	}
	bad = good
	bad.Headers = map[string]string{"Authorization": "secret"}
	if _, _, e := s.checkOrigin(bad); e == nil {
		t.Fatal("accepted origin credential header")
	}
}
func TestProxyClosedRoutesHeadersAndSafeControlResponses(t *testing.T) {
	f := newTransferFixture(t)
	var calls atomic.Int64
	body := []byte(`{"protocol":"hf2l-managed-v1"}`)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") == "" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("missing controlled credentials")
		}
		w.Header().Set("X-Origin-Secret", "not-visible")
		_, _ = w.Write(body)
	}))
	defer upstream.Close()
	settings := f.proxySettings(t, upstream.URL)
	settings.Client = upstream.Client()
	h, e := NewProxy(settings)
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/v2/spaces/foreign/records", "/v2/spaces/space-a/workload-grants", "/v2/spaces/space-a/records/../members", "/v2/spaces/space-a/records/%2e%2e", "/v2/spaces/space-a//records", "/http://evil.example"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 {
			t.Fatal(path, w.Code)
		}
	}
	for _, name := range []string{"Authorization", "Cookie", "Proxy-Authorization", "X-HF2L-Backend-Signature", "X-Forwarded-Client-Cert", "X-Forwarded-Host"} {
		r := httptest.NewRequest("GET", "/v2/spaces/space-a/records", nil)
		r.Header.Set(name, "forbidden")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal(name, w.Code)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("denied request reached upstream")
	}
	r := httptest.NewRequest("GET", "/v2/spaces/space-a/records", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("X-Origin-Secret") != "" {
		t.Fatal(w.Code, w.Body.String())
	}
	body = []byte(`{"u\u0072l":"https://private-origin/?secret=1"}`)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/v2/spaces/space-a/records", nil))
	if w.Code != 502 || strings.Contains(w.Body.String(), "private-origin") {
		t.Fatal("unsafe origin descriptor escaped", w.Code, w.Body.String())
	}
}
func TestProxyMapsAuthorityFailureWithoutPrivateDetails(t *testing.T) {
	f := newTransferFixture(t)
	settings := f.proxySettings(t, "https://exchange.example")
	settings.ExchangeToken = func(context.Context) (string, error) {
		return "", domain.Err(403, "private_enrollment_state", map[string]any{"secret": "never"})
	}
	h, e := NewProxy(settings)
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/v2/spaces/space-a/records", nil))
	if w.Code != 403 || !strings.Contains(w.Body.String(), "execution_authority_denied") || strings.Contains(w.Body.String(), "private_enrollment") {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestEdgeUsesVerifiedTLSAndReplacesForgedAssertions(t *testing.T) {
	f := newTransferFixture(t)
	secret := strings.Repeat("b", 32)
	var calls atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		thumb, e := VerifiedBackendThumbprint(secret, r.Method, requestTarget(r), r.Header.Get("Authorization"), r.Header, time.Now())
		if e != nil || thumb != f.binding.CertificateThumbprint {
			t.Error("incorrect backend assertion", e)
		}
		w.Header().Set("X-Private-Header", "hidden")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	h, e := NewEdge(EdgeSettings{BackendEndpoint: upstream.URL, BackendSecret: secret, Client: upstream.Client()})
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("GET", "/v2/spaces/space-a/membership", nil)
	r.Header.Set("X-Forwarded-Client-Cert", "forged")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 || calls.Load() != 0 {
		t.Fatal("forged TLS identity accepted")
	}
	r = f.request("GET", "/v2/spaces/space-a/membership?view=current", nil, "opaque")
	r.Header.Set("X-HF2L-Backend-Signature", "forged")
	r.Header.Set("X-HF2L-TLS-Thumbprint", "forged")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || calls.Load() != 1 || w.Header().Get("X-Private-Header") != "" {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestPrivateTLSListenerRejectsMissingClientCertificate(t *testing.T) {
	f := newTransferFixture(t)
	server, listener, e := NewMTLSServer(MTLSSettings{Address: "127.0.0.1:0", Certificate: f.serverCert, Key: f.serverKey, ClientCA: f.caFile}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		thumb, e := verifiedThumbprint(r)
		if e != nil {
			t.Error(e)
		}
		_, _ = w.Write([]byte(thumb))
	}))
	if e != nil {
		t.Fatal(e)
	}
	server.ErrorLog = log.New(io.Discard, "", 0)
	go server.Serve(listener)
	defer server.Close()
	address := "https://" + listener.Addr().String() + "/"
	client, e := newClient(f.caFile, "", "", time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if response, e := client.Get(address); e == nil {
		response.Body.Close()
		t.Fatal("missing client certificate accepted")
	}
	client, e = newClient(f.caFile, f.clientCert, f.clientKey, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer client.CloseIdleConnections()
	response, e := client.Get(address)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(response.Body)
	if e != nil || string(raw) != f.binding.CertificateThumbprint {
		t.Fatal("verified TLS certificate was not propagated", e)
	}
}

func TestConnectionLimitAppliesBeforeTLSAndUnblocksOnClose(t *testing.T) {
	raw, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	listener := limitConnections(raw, 1)
	defer listener.Close()
	client1, e := net.Dial("tcp", listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer client1.Close()
	first, e := listener.Accept()
	if e != nil {
		t.Fatal(e)
	}
	accepted := make(chan net.Conn, 1)
	failed := make(chan error, 1)
	go func() {
		c, e := listener.Accept()
		if e != nil {
			failed <- e
		} else {
			accepted <- c
		}
	}()
	client2, e := net.Dial("tcp", listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer client2.Close()
	select {
	case c := <-accepted:
		c.Close()
		t.Fatal("accepted beyond connection limit")
	case e := <-failed:
		t.Fatal(e)
	case <-time.After(50 * time.Millisecond):
	}
	first.Close()
	select {
	case c := <-accepted:
		c.Close()
	case e := <-failed:
		t.Fatal(e)
	case <-time.After(2 * time.Second):
		t.Fatal("closed connection did not release limit")
	}
}

type transferReaderFunc func([]byte) (int, error)

func (f transferReaderFunc) Read(p []byte) (int, error) { return f(p) }
func TestUploadReauthorizesAfterBlockedBodyRead(t *testing.T) {
	revoked := false
	source := io.NopCloser(transferReaderFunc(func(p []byte) (int, error) { revoked = true; return copy(p, []byte("private")), io.EOF }))
	reader := &checkedReader{source: source, remaining: 7, chunk: 1024, check: func() error {
		if revoked {
			return errors.New("revoked")
		}
		return nil
	}}
	n, e := reader.Read(make([]byte, 1024))
	if n != 0 || e == nil || reader.complete.Load() {
		t.Fatal("body bytes escaped after revocation", n, e)
	}
}
func TestDownloadReauthorizesAfterBlockedOriginRead(t *testing.T) {
	f := newTransferFixture(t)
	backend := &fixtureBackend{}
	ready := make(chan struct{})
	var revoked atomic.Bool
	backend.authorize = func(n int64) error {
		if revoked.Load() {
			return errors.New("revoked")
		}
		if n == 3 {
			close(ready)
		}
		return nil
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "7")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-ready
		revoked.Store(true)
		_, _ = w.Write([]byte("private"))
	}))
	defer origin.Close()
	backend.grant = OriginGrant{URL: origin.URL + "/bucket/object", ExpiresAt: float64(time.Now().Add(time.Minute).Unix()), Size: 7, SHA256: strings.Repeat("c", 64)}
	h := fixtureGateway(t, f, origin.URL, backend)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, f.request("GET", "/transfers/v1/spaces/space-a/records/r/attachments/a/content", nil, f.gatewayToken(t)))
	if w.Body.Len() != 0 {
		t.Fatal("origin bytes escaped after in-flight revocation")
	}
}

type transferRoundTripFunc func(*http.Request) (*http.Response, error)

func (f transferRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestProxyReauthorizesAfterBlockedUpstreamRead(t *testing.T) {
	f := newTransferFixture(t)
	var revoked atomic.Bool
	token := f.gatewayToken(t)
	settings := f.proxySettings(t, "https://exchange.example")
	settings.GatewayToken = func(context.Context) (string, error) {
		if revoked.Load() {
			return "", domain.Err(403, "execution_revoked")
		}
		return token, nil
	}
	settings.Client = &http.Client{Transport: transferRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := io.NopCloser(transferReaderFunc(func(p []byte) (int, error) { revoked.Store(true); return copy(p, []byte("private")), io.EOF }))
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Length": {"7"}}, Body: body}, nil
	})}
	h, e := NewProxy(settings)
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/transfers/v1/spaces/space-a/records/r/attachments/a/content", nil))
	if w.Body.Len() != 0 {
		t.Fatal("proxy bytes escaped after in-flight revocation")
	}
}

func TestEdgeAuthenticatesToBackendWithConfiguredClientCertificate(t *testing.T) {
	incoming := newTransferFixture(t)
	backendIdentity := newTransferFixture(t)
	secret := strings.Repeat("b", 32)
	var calls atomic.Int64
	backend, listener, e := NewMTLSServer(MTLSSettings{Address: "127.0.0.1:0", Certificate: backendIdentity.serverCert, Key: backendIdentity.serverKey, ClientCA: backendIdentity.caFile}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		actual, e := verifiedThumbprint(r)
		if e != nil || actual != backendIdentity.binding.CertificateThumbprint {
			t.Error("backend did not verify its configured edge client", e)
		}
		asserted, e := VerifiedBackendThumbprint(secret, r.Method, requestTarget(r), r.Header.Get("Authorization"), r.Header, time.Now())
		if e != nil || asserted != incoming.binding.CertificateThumbprint || asserted == actual {
			t.Error("workload certificate was replaced with backend service identity", e)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"ok\":true}"))
	}))
	if e != nil {
		t.Fatal(e)
	}
	backend.ErrorLog = log.New(io.Discard, "", 0)
	go backend.Serve(listener)
	defer backend.Close()
	endpoint := "https://" + listener.Addr().String()
	without, e := NewEdge(EdgeSettings{BackendEndpoint: endpoint, BackendSecret: secret, CAFile: backendIdentity.caFile, Timeout: 3 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	defer without.(*Edge).Close()
	w := httptest.NewRecorder()
	without.ServeHTTP(w, incoming.request("GET", "/v2/spaces/space-a/membership?view=current", nil, "original-workload"))
	if w.Code != 503 || calls.Load() != 0 {
		t.Fatal("backend accepted an edge without a client certificate", w.Code)
	}
	with, e := NewEdge(EdgeSettings{BackendEndpoint: endpoint, BackendSecret: secret, CAFile: backendIdentity.caFile, ClientCertificate: backendIdentity.clientCert, ClientKey: backendIdentity.clientKey, Timeout: 3 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	defer with.(*Edge).Close()
	w = httptest.NewRecorder()
	with.ServeHTTP(w, incoming.request("GET", "/v2/spaces/space-a/membership?view=current", nil, "original-workload"))
	if w.Code != 200 || calls.Load() != 1 || w.Body.String() != "{\"ok\":true}" {
		t.Fatal("configured backend mTLS failed", w.Code, w.Body.String())
	}
}
func TestEdgeRequiresPairedBoundedNoFollowPrivateClientMaterial(t *testing.T) {
	f := newTransferFixture(t)
	base := EdgeSettings{BackendEndpoint: "https://exchange.example", BackendSecret: strings.Repeat("b", 32), CAFile: f.caFile}
	onlyCertificate := base
	onlyCertificate.ClientCertificate = f.clientCert
	if h, e := NewEdge(onlyCertificate); e == nil {
		h.(*Edge).Close()
		t.Fatal("accepted a certificate without its private key")
	}
	onlyKey := base
	onlyKey.ClientKey = f.clientKey
	if h, e := NewEdge(onlyKey); e == nil {
		h.(*Edge).Close()
		t.Fatal("accepted a private key without its certificate")
	}
	key, e := os.ReadFile(f.clientKey)
	if e != nil {
		t.Fatal(e)
	}
	candidates := map[string]string{}
	symlink := filepath.Join(f.root, "symlink-key.pem")
	if e = os.Symlink(f.clientKey, symlink); e != nil {
		t.Fatal(e)
	}
	candidates["symlink"] = symlink
	oversized := filepath.Join(f.root, "oversized-key.pem")
	fixtureWrite(t, oversized, append(append([]byte(nil), key...), bytes.Repeat([]byte(" "), 65537)...))
	candidates["oversized valid PEM"] = oversized
	publicMode := filepath.Join(f.root, "public-key.pem")
	fixtureWrite(t, publicMode, key)
	if e = os.Chmod(publicMode, 0644); e != nil {
		t.Fatal(e)
	}
	candidates["unsafe mode"] = publicMode
	for name, path := range candidates {
		t.Run(name, func(t *testing.T) {
			settings := base
			settings.ClientCertificate = f.clientCert
			settings.ClientKey = path
			if h, e := NewEdge(settings); e == nil {
				h.(*Edge).Close()
				t.Fatal("accepted unsafe private client material")
			}
		})
	}
}
