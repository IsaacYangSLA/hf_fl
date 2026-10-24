//go:build linux

package artifacts

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/certificates"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
)

type artifactManagerFixture struct {
	mu       sync.Mutex
	metadata map[string]any
	revoked  bool
}

func (m *artifactManagerFixture) ArtifactStorage(_ context.Context, actor, job, artifact string) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revoked || actor != "owner" || job != "job-a" || artifact != "artifact-a" {
		return nil, domain.Err(404, "job_not_found")
	}
	return copyMap(m.metadata), nil
}
func (m *artifactManagerFixture) GetArtifact(ctx context.Context, actor, job, artifact string) (map[string]any, error) {
	return m.ArtifactStorage(ctx, actor, job, artifact)
}
func (m *artifactManagerFixture) GetJob(_ context.Context, actor, job string) (map[string]any, error) {
	return map[string]any{"id": job}, nil
}
func (m *artifactManagerFixture) revoke() { m.mu.Lock(); defer m.mu.Unlock(); m.revoked = true }
func localBroker(t *testing.T, content []byte) (*testDB, *Broker, *artifactManagerFixture, string) {
	t.Helper()
	f := newTestDB(t)
	root := t.TempDir()
	owned := filepath.Join(root, "job-a", "outputs")
	if e := os.MkdirAll(owned, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(owned, "model.safetensors")
	mustWrite(t, path, content)
	f.resource(t, "artifact-root", "artifact_directory", owned, map[string]any{})
	manager := &artifactManagerFixture{metadata: map[string]any{"id": "artifact-a", "name": "model.safetensors", "size_bytes": int64(len(content)), "sha256": digest(content), "download_available": true, "locator": map[string]any{"kind": "local", "resource_id": "artifact-root", "relative_path": "model.safetensors"}}}
	broker, e := NewBroker(manager, f.db, BrokerConfig{Root: root})
	if e != nil {
		t.Fatal(e)
	}
	return f, broker, manager, path
}
func TestBrokerStreamsOpaqueLocalFileAndRechecksRevocation(t *testing.T) {
	content := []byte(strings.Repeat("x", 150000))
	_, broker, manager, _ := localBroker(t, content)
	ctx := context.Background()
	download, e := broker.OpenAuthorized(ctx, "owner", "job-a", "artifact-a")
	if e != nil {
		t.Fatal(e)
	}
	defer download.Close()
	raw := make([]byte, 100000)
	n, e := download.Reader.Read(raw)
	if e != nil || n != 65536 {
		t.Fatal("unbounded stream chunk", n, e)
	}
	manager.revoke()
	if n, e = download.Reader.Read(raw); e == nil || n != 0 {
		t.Fatal("revoked content continued", n, e)
	}
}
func TestBrokerDetectsMutationAndDescriptorHashMismatch(t *testing.T) {
	content := []byte(strings.Repeat("x", 131072))
	_, broker, _, path := localBroker(t, content)
	download, e := broker.OpenAuthorized(context.Background(), "owner", "job-a", "artifact-a")
	if e != nil {
		t.Fatal(e)
	}
	first := make([]byte, 65536)
	if _, e = io.ReadFull(download.Reader, first); e != nil {
		t.Fatal(e)
	}
	file, e := os.OpenFile(path, os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	file.WriteAt([]byte("z"), 0)
	file.Close()
	future := time.Now().Add(time.Minute)
	if e = os.Chtimes(path, future, future); e != nil {
		t.Fatal(e)
	}
	if _, e = io.ReadAll(download.Reader); e == nil {
		t.Fatal("changed local file accepted")
	}
	download.Close()
	_, broker, manager, _ := localBroker(t, []byte("content"))
	manager.metadata["sha256"] = digest([]byte("different"))
	download, e = broker.OpenAuthorized(context.Background(), "owner", "job-a", "artifact-a")
	if e != nil {
		t.Fatal(e)
	}
	defer download.Close()
	if _, e = io.ReadAll(download.Reader); e == nil {
		t.Fatal("wrong hash accepted")
	}
}
func TestBrokerRefusesForeignOwnershipTraversalLinksAndSanitizesName(t *testing.T) {
	f, broker, manager, path := localBroker(t, []byte("opaque"))
	if _, e := broker.OpenAuthorized(context.Background(), "platform-operator", "job-a", "artifact-a"); e == nil {
		t.Fatal("platform role granted content")
	}
	manager.metadata["name"] = "bad\nname"
	download, e := broker.OpenAuthorized(context.Background(), "owner", "job-a", "artifact-a")
	if e != nil {
		t.Fatal(e)
	}
	if download.Name != "artifact.bin" {
		t.Fatal("unsafe download name")
	}
	download.Close()
	f.update(t, "jm_provisioning_resources", map[string]any{"id": "artifact-root"}, map[string]any{"ownership_json": map[string]any{"job_id": "foreign"}})
	if _, e = broker.OpenAuthorized(context.Background(), "owner", "job-a", "artifact-a"); e == nil {
		t.Fatal("foreign root adopted")
	}
	f.update(t, "jm_provisioning_resources", map[string]any{"id": "artifact-root"}, map[string]any{"ownership_json": map[string]any{"job_id": "job-a"}})
	manager.metadata["locator"] = map[string]any{"kind": "local", "resource_id": "artifact-root", "relative_path": "../private"}
	if _, e = broker.OpenAuthorized(context.Background(), "owner", "job-a", "artifact-a"); e == nil {
		t.Fatal("path traversal accepted")
	}
	manager.metadata["locator"] = map[string]any{"kind": "local", "resource_id": "artifact-root", "relative_path": "model.safetensors"}
	foreign := filepath.Join(t.TempDir(), "private")
	mustWrite(t, foreign, []byte("opaque"))
	os.Remove(path)
	if e = os.Symlink(foreign, path); e != nil {
		t.Fatal(e)
	}
	if _, e = broker.OpenAuthorized(context.Background(), "owner", "job-a", "artifact-a"); e == nil {
		t.Fatal("symbolic link exposed")
	}
	os.Remove(path)
	if e = os.Link(foreign, path); e != nil {
		t.Fatal(e)
	}
	if _, e = broker.OpenAuthorized(context.Background(), "owner", "job-a", "artifact-a"); e == nil {
		t.Fatal("hardlinked file exposed")
	}
}
func TestBrokerRemoteReadsOnlyRegisteredIdentityAndVerifiesBeforeExpose(t *testing.T) {
	f := newTestDB(t)
	identity := LogIdentity{"job-a", "attempt-a", "owner", 1}
	content := []byte("remote-data")
	f.resource(t, "remote-root", "retained_artifact_root", "hf2l-node://node-a/"+identity.Key(), map[string]any{"node_id": "node-a"})
	manager := &artifactManagerFixture{metadata: map[string]any{"id": "artifact-a", "name": "checkpoint", "size_bytes": int64(len(content)), "sha256": digest(content), "download_available": true, "locator": map[string]any{"kind": "local", "resource_id": "remote-root", "relative_path": "state/model.safetensors"}}}
	calls := 0
	cfg := BrokerConfig{Root: t.TempDir(), RemoteRoute: func(_ context.Context, id LogIdentity) (string, error) {
		if id != identity {
			t.Fatal("wrong registered identity")
		}
		return "node-a", nil
	}, RemoteRead: func(_ context.Context, id LogIdentity, path string, maximum int64) ([]byte, error) {
		calls++
		if id != identity || path != "state/model.safetensors" || maximum != int64(len(content)) {
			t.Fatal("unbounded/foreign remote read")
		}
		return content, nil
	}}
	broker, e := NewBroker(manager, f.db, cfg)
	if e != nil {
		t.Fatal(e)
	}
	download, e := broker.OpenAuthorized(context.Background(), "owner", "job-a", "artifact-a")
	if e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(download.Reader)
	download.Close()
	if e != nil || string(got) != string(content) || calls != 1 {
		t.Fatal(e)
	}
	cfg.RemoteRoute = func(context.Context, LogIdentity) (string, error) { return "foreign-node", nil }
	broker, _ = NewBroker(manager, f.db, cfg)
	if _, e = broker.OpenAuthorized(context.Background(), "owner", "job-a", "artifact-a"); e == nil || calls != 1 {
		t.Fatal("foreign route read bytes")
	}
	cfg.RemoteRoute = func(context.Context, LogIdentity) (string, error) { return "node-a", nil }
	cfg.RemoteRead = func(context.Context, LogIdentity, string, int64) ([]byte, error) { return []byte("tampered"), nil }
	broker, _ = NewBroker(manager, f.db, cfg)
	if _, e = broker.OpenAuthorized(context.Background(), "owner", "job-a", "artifact-a"); e == nil {
		t.Fatal("corrupt remote bytes exposed")
	}
}

type testCA struct {
	cert        *x509.Certificate
	key         *rsa.PrivateKey
	pem, keyPEM []byte
	server      tls.Certificate
}

func makeCA(t *testing.T) *testCA {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Artifact test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	rawKey, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	ca := &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rawKey})}
	leafKey, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, cert, &leafKey.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	leafPKCS8, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	ca.server, e = tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafPKCS8}))
	if e != nil {
		t.Fatal(e)
	}
	return ca
}
func startTLS(t *testing.T, ca *testCA, clientAuth bool, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.pem)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{ca.server}, MinVersion: tls.VersionTLS12}
	if clientAuth {
		server.TLS.ClientAuth = tls.RequireAndVerifyClientCert
		server.TLS.ClientCAs = roots
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}
func TestManagedArtifactBrokerUsesFreshMTLSReadOnlyGrantsAndPermanentRevoke(t *testing.T) {
	f := newTestDB(t)
	ctx := context.Background()
	ca := makeCA(t)
	signing, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	publicDER, _ := x509.MarshalPKIXPublicKey(&signing.PublicKey)
	privateDER, _ := x509.MarshalPKCS8PrivateKey(signing)
	workloads, e := exchange.NewBroker(exchange.BrokerSettings{Issuer: "https://workloads.example.test", ExchangeAudience: "exchange-managed", GatewayAudience: "transfer", NodeAudience: "nodes", PublicKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})})
	if e != nil {
		t.Fatal(e)
	}
	zero := int64(0)
	issuer, e := certificates.NewIssuer(certificates.Config{CACertificatePEM: ca.pem, CAPrivateKeyPEM: ca.keyPEM, GraceSeconds: &zero, MaxLifetimeSeconds: 300})
	if e != nil {
		t.Fatal(e)
	}
	f.resource(t, "space-root", "exchange_space", "space-a", map[string]any{})
	var mu sync.Mutex
	grants := map[string]map[string]any{}
	revoked := false
	next := 0
	control := startTLS(t, ca, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer provisioner-fixture" {
			http.Error(w, "unauthorized", 401)
			return
		}
		var body map[string]any
		if e := json.NewDecoder(r.Body).Decode(&body); e != nil {
			t.Error(e)
			http.Error(w, "invalid", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "PUT" && strings.Contains(r.URL.Path, "/members/") {
			roles, _ := body["roles"].([]any)
			if len(roles) != 1 || roles[0] != "reader" {
				t.Error("broker escalated roles")
			}
			json.NewEncoder(w).Encode(body)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/workload-grants/revoke") {
			if body["attempt_id"] != ArtifactAttemptID("job-a") {
				t.Error("wrong permanent revoke attempt")
			}
			mu.Lock()
			revoked = true
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"attempt_id": body["attempt_id"], "revoked_at": time.Now().UTC()})
			return
		}
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/workload-grants") {
			mu.Lock()
			defer mu.Unlock()
			if revoked {
				w.WriteHeader(409)
				json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "workload_attempt_revoked"}})
				return
			}
			if r.Header.Get("Idempotency-Key") == "" {
				t.Error("missing grant operation identity")
			}
			next++
			id := "grant-" + strconv.Itoa(next)
			principal, _ := exchange.StableWorkloadPrincipal(workloads.Issuer(), "job-a", "download-broker", nil)
			body["grant_id"] = id
			body["principal_id"] = principal
			body["space_id"] = "space-a"
			grants[id] = body
			json.NewEncoder(w).Encode(body)
			return
		}
		http.Error(w, "unexpected", 404)
	}))
	client, e := exchange.New(exchange.Config{Endpoint: control.URL, Token: "provisioner-fixture", CAPEM: ca.pem})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	content := []byte("abcdefgh")
	thumbprints := []string{}
	gatewayCalls := 0
	gateway := startTLS(t, ca, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			t.Error("missing real mutual TLS")
			http.Error(w, "unauthorized", 401)
			return
		}
		thumb := certificates.Thumbprint(r.TLS.PeerCertificates[0].Raw)
		principal, e := workloads.AuthenticateWorkload(r.Header.Get("Authorization"), thumb, "gateway")
		if e != nil {
			t.Error(e)
			http.Error(w, "unauthorized", 401)
			return
		}
		mu.Lock()
		grant := grants[principal.GrantID]
		thumbprints = append(thumbprints, thumb)
		gatewayCalls++
		mu.Unlock()
		if grant == nil || text(grant["certificate_thumbprint"]) != thumb || principal.ComponentID != "download-broker" || principal.AttemptID != ArtifactAttemptID("job-a") {
			t.Error("grant identity mismatch")
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		w.Header().Set("X-Content-SHA256", digest(content))
		w.Write(content)
	}))
	backend, e := NewManagedGatewayBackend(f.db, ManagedGatewayConfig{Endpoint: gateway.URL, CAPEM: ca.pem, Exchange: client, Workloads: workloads, Certificates: issuer})
	if e != nil {
		t.Fatal(e)
	}
	manager := &artifactManagerFixture{metadata: map[string]any{"id": "artifact-a", "name": "model.safetensors", "size_bytes": int64(len(content)), "sha256": digest(content), "download_available": true, "locator": map[string]any{"kind": "exchange", "space_id": "space-a", "record_id": "record-a", "attachment_id": "attachment-a"}}}
	broker, e := NewBroker(manager, f.db, BrokerConfig{Root: t.TempDir(), Gateway: backend})
	if e != nil {
		t.Fatal(e)
	}
	for range 2 {
		download, e := broker.OpenAuthorized(ctx, "owner", "job-a", "artifact-a")
		if e != nil {
			t.Fatal(e)
		}
		raw, e := io.ReadAll(download.Reader)
		download.Close()
		if e != nil || string(raw) != string(content) {
			t.Fatal("download", e)
		}
	}
	mu.Lock()
	different := len(thumbprints) == 2 && thumbprints[0] != thumbprints[1] && gatewayCalls == 2
	mu.Unlock()
	if !different {
		t.Fatal("broker reused invocation credentials")
	}
	owned, e := f.db.All(ctx, "SELECT * FROM jm_provisioning_resources WHERE kind = ?", "workload_grant")
	if e != nil || len(owned) != 2 {
		t.Fatal("grant ownership not durable", e)
	}
	if ok, e := broker.Revoke(ctx, "job-a"); e != nil || !ok {
		t.Fatal("revoke", e)
	}
	if _, e = broker.OpenAuthorized(ctx, "owner", "job-a", "artifact-a"); e == nil {
		t.Fatal("new download grant bypassed retirement fence")
	}
	mu.Lock()
	calls := gatewayCalls
	mu.Unlock()
	if calls != 2 {
		t.Fatal("retired job reached gateway")
	}
}
