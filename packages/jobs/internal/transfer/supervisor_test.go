//go:build linux

package transfer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"golang.org/x/sys/unix"
)

func supervisorSocketRoot(t *testing.T) string {
	t.Helper()
	home, e := os.UserHomeDir()
	if e != nil {
		t.Fatal(e)
	}
	root, e := os.MkdirTemp(home, ".hf2l-proxy-test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := os.RemoveAll(root); e != nil {
			t.Error(e)
		}
	})
	return root
}
func newSupervisorFixture(t *testing.T, f *transferFixture, socketRoot string) *Supervisor {
	t.Helper()
	root := filepath.Join(f.root, "proxies")
	supervisor, e := NewSupervisor(SupervisorConfig{Root: root, SocketRoot: socketRoot, ClientCACertificate: f.caFile, ClientCAKey: f.caKey, ServiceCAFile: f.caFile, ExchangeEndpoint: "https://exchange.example", GatewayEndpoint: "https://gateway.example", WorkloadIssuer: "https://workloads.example", WorkloadPublicKey: f.public, ExchangeAudience: "exchange-managed", GatewayAudience: "hf2l-transfer", TokenProvider: func(ctx context.Context, b ExecutionBinding, transfer bool) (string, error) {
		audience, scope := "exchange-managed", "exchange"
		if transfer {
			audience, scope = "hf2l-transfer", "transfer"
		}
		return f.token(t, b, audience, scope, nil, nil), nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = supervisor.Close() })
	return supervisor
}
func TestSupervisorIdentityReuseStopFencingAndDurablePurge(t *testing.T) {
	f := newTransferFixture(t)
	root := supervisorSocketRoot(t)
	s := newSupervisorFixture(t, f, root)
	id := ExecutionIdentity{"job-a", "attempt-a", "owner", 1}
	deadline := time.Now().Add(time.Hour)
	if alive, e := s.Alive(context.Background(), id); e != nil || alive {
		t.Fatal("freshproxy erroneously alive", e)
	}
	first, e := s.Ensure(context.Background(), id, "space-a", deadline)
	if e != nil {
		t.Fatal(e)
	}
	if alive, e := s.Alive(context.Background(), id); e != nil || !alive {
		t.Fatal("proxy not alive", e)
	}
	second, e := s.Ensure(context.Background(), id, "space-a", deadline)
	if e != nil || first != second {
		t.Fatal("proxy identity was not durable", e)
	}
	status, e := privateProxyOperation(context.Background(), first.ProxyEndpoint, first.Binding, "status", false)
	if e != nil || !status.Running {
		t.Fatal("control status failed", e)
	}
	if _, e = s.Stop(context.Background(), id, false); e == nil {
		t.Fatal("stopped without confirmed termination")
	}
	if _, e = s.Ensure(context.Background(), id, "foreign-space", deadline); e == nil {
		t.Fatal("rebound active proxy")
	}
	if ok, e := s.Stop(context.Background(), id, true); e != nil || !ok {
		t.Fatal("confirmed stop failed", ok, e)
	}
	if ok, e := s.Purge(context.Background(), id, true); e != nil || !ok {
		t.Fatal("purge failed", ok, e)
	}
	if _, e = os.Lstat(filepath.Dir(first.ProxyEndpoint)); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("proxy socket directory remains", e)
	}
	material := filepath.Join(s.config.Root, id.JobID, "attempts", id.AttemptID, id.ComponentID)
	if _, e = os.Lstat(material); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("private key directory remains", e)
	}
	raw, e := os.ReadFile(filepath.Join(s.config.Root, "purge-ledger", id.Key()+".json"))
	if e != nil {
		t.Fatal(e)
	}
	var receipt map[string]any
	if json.Unmarshal(raw, &receipt) != nil || receipt["status"] != "purged" || receipt["certificate_thumbprint"] != first.CertificateThumbprint {
		t.Fatal("missing bound purge audit")
	}
	if _, e = s.Ensure(context.Background(), id, "space-a", deadline); e == nil {
		t.Fatal("purged execution was recreated")
	}
	if ok, e := s.Purge(context.Background(), id, true); e != nil || !ok {
		t.Fatal("purge retry failed", e)
	}
}
func TestSupervisorRestartAdoptsExactPrivateBinding(t *testing.T) {
	f := newTransferFixture(t)
	root := supervisorSocketRoot(t)
	first := newSupervisorFixture(t, f, root)
	id := ExecutionIdentity{"job-a", "attempt-a", "owner", 1}
	deadline := time.Now().Add(time.Hour)
	original, e := first.Ensure(context.Background(), id, "space-a", deadline)
	if e != nil {
		t.Fatal(e)
	}
	second := newSupervisorFixture(t, f, root)
	if alive, e := second.Alive(context.Background(), id); e != nil || !alive {
		t.Fatal("recovered proxy not provably alive", e)
	}
	adopted, e := second.Restore(context.Background(), id, "space-a", deadline)
	if e != nil || adopted != original {
		t.Fatal("proxy adoption failed", e)
	}
	if len(second.active) != 0 || len(second.adopted) != 1 {
		t.Fatal("adoption created another server")
	}
	if ok, e := second.Stop(context.Background(), id, true); e != nil || !ok {
		t.Fatal("adopted stop failed", e)
	}
	if ok, e := second.Purge(context.Background(), id, true); e != nil || !ok {
		t.Fatal("adopted purge failed", e)
	}
}
func TestSupervisorRefusesSymlinkMaterialAndUnknownPurgeContent(t *testing.T) {
	f := newTransferFixture(t)
	root := supervisorSocketRoot(t)
	s := newSupervisorFixture(t, f, root)
	id := ExecutionIdentity{"job-a", "attempt-a", "owner", 1}
	result, e := s.Ensure(context.Background(), id, "space-a", time.Now().Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	material := filepath.Join(s.config.Root, id.JobID, "attempts", id.AttemptID, id.ComponentID)
	foreign := filepath.Join(f.root, "foreign-secret")
	fixtureWrite(t, foreign, []byte("retain"))
	if e := os.Symlink(foreign, filepath.Join(material, "foreign-link")); e != nil {
		t.Fatal(e)
	}
	if ok, e := s.Purge(context.Background(), id, true); e == nil || ok {
		t.Fatal("purged unknown private material")
	}
	if raw, e := os.ReadFile(foreign); e != nil || string(raw) != "retain" {
		t.Fatal("foreign data changed", e)
	}
	if _, e = os.Stat(filepath.Join(material, "proxy-key.pem")); e != nil {
		t.Fatal("private key removed before validation")
	}
	if e := os.Remove(filepath.Join(material, "foreign-link")); e != nil {
		t.Fatal(e)
	}
	key := filepath.Join(material, "proxy-key.pem")
	if e := os.Remove(key); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(foreign, key); e != nil {
		t.Fatal(e)
	}
	second := newSupervisorFixture(t, f, root)
	if _, e = second.Ensure(context.Background(), id, "space-a", time.Now().Add(time.Hour)); e == nil {
		t.Fatal("reused symlink key")
	}
	_ = result
}
func TestSupervisorRejectsChangedRootAndForeignSocket(t *testing.T) {
	f := newTransferFixture(t)
	root := supervisorSocketRoot(t)
	s := newSupervisorFixture(t, f, root)
	id := ExecutionIdentity{"job-a", "attempt-a", "owner", 1}
	endpoint, e := s.Endpoint(id)
	if e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(filepath.Dir(endpoint), 0700); e != nil {
		t.Fatal(e)
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: endpoint, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	// A live socket without the bound private control must not be unlinked or adopted.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, e = s.Ensure(ctx, id, "space-a", time.Now().Add(time.Hour)); e == nil {
		t.Fatal("adopted unbound live socket")
	}
	if _, e = os.Lstat(endpoint); e != nil {
		t.Fatal("foreign live socket was removed", e)
	}
	if e := os.Rename(s.config.Root, s.config.Root+"-old"); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(s.config.Root, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Ensure(context.Background(), ExecutionIdentity{"job-b", "attempt-b", "owner", 1}, "space-b", time.Now().Add(time.Hour)); e == nil {
		t.Fatal("accepted replaced private root")
	}
}
func TestUnixServerRejectsExistingFileAndCleansExactSocket(t *testing.T) {
	root := supervisorSocketRoot(t)
	path := filepath.Join(root, "s")
	if e := os.WriteFile(path, []byte("foreign"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e := NewUnixServer(UnixSettings{SocketPath: path}, http.NotFoundHandler()); e == nil {
		t.Fatal("replaced existing file")
	}
	if raw, e := os.ReadFile(path); e != nil || string(raw) != "foreign" {
		t.Fatal("foreign file was changed")
	}
	if e := os.Remove(path); e != nil {
		t.Fatal(e)
	}
	server, listener, e := NewUnixServer(UnixSettings{SocketPath: path}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	if e != nil {
		t.Fatal(e)
	}
	go server.Serve(listener)
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	response, e := client.Get("http://proxy/")
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	client.CloseIdleConnections()
	if e := server.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("owned socket not removed", e)
	}
}
func TestPrivateMaterialReaderRejectsHardLinksAndUnsafeMode(t *testing.T) {
	root := supervisorSocketRoot(t)
	if e := os.WriteFile(filepath.Join(root, "key"), []byte("secret"), 0600); e != nil {
		t.Fatal(e)
	}
	fd, e := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	if e := os.Link(filepath.Join(root, "key"), filepath.Join(root, "other")); e != nil {
		t.Fatal(e)
	}
	if _, e = privateRead(fd, "key"); e == nil {
		t.Fatal("accepted hard-linked private key")
	}
	if e := os.Remove(filepath.Join(root, "other")); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(filepath.Join(root, "key"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = privateRead(fd, "key"); e == nil {
		t.Fatal("accepted public private material")
	}
}
func TestProxySocketLengthRequiresShortQualifiedRoot(t *testing.T) {
	f := newTransferFixture(t)
	root := supervisorSocketRoot(t)
	s := newSupervisorFixture(t, f, root)
	s.config.SocketRoot = "/" + strings.Repeat("a", 90)
	if _, e := s.Endpoint(ExecutionIdentity{"job-a", "attempt-a", "owner", 1}); e == nil {
		t.Fatal("accepted too-long socket path")
	}
}

func TestSupervisorCentralCSRResumesSamePersistedKey(t *testing.T) {
	f := newTransferFixture(t)
	root := supervisorSocketRoot(t)
	first := newSupervisorFixture(t, f, root)
	config := first.config
	if e := first.Close(); e != nil {
		t.Fatal(e)
	}
	config.ClientCAKey = ""
	calls := 0
	var firstPublic []byte
	config.CertificateProvider = func(ctx context.Context, id ExecutionIdentity, space string, request []byte, expiry time.Time) (IssuedCertificate, error) {
		calls++
		block, _ := pem.Decode(request)
		if block == nil {
			return IssuedCertificate{}, errors.New("missing CSR")
		}
		csr, e := x509.ParseCertificateRequest(block.Bytes)
		if e != nil || csr.CheckSignature() != nil {
			return IssuedCertificate{}, errors.New("invalid CSR")
		}
		public, e := x509.MarshalPKIXPublicKey(csr.PublicKey)
		if e != nil {
			return IssuedCertificate{}, e
		}
		if calls == 1 {
			firstPublic = public
			return IssuedCertificate{}, domain.Err(503, "identity_service_unavailable")
		}
		if !bytes.Equal(firstPublic, public) {
			return IssuedCertificate{}, errors.New("retry regenerated private key")
		}
		encoded, e := os.ReadFile(f.caKey)
		if e != nil {
			return IssuedCertificate{}, e
		}
		key, e := parsePrivateKey(encoded)
		if e != nil {
			return IssuedCertificate{}, e
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: csr.Subject, NotBefore: time.Now().Add(-time.Minute), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
		certificate, e := x509.CreateCertificate(rand.Reader, template, f.ca, csr.PublicKey, key)
		if e != nil {
			return IssuedCertificate{}, e
		}
		return IssuedCertificate{CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})), CertificateThumbprint: CertificateThumbprint(certificate)}, nil
	}
	supervisor, e := NewSupervisor(config)
	if e != nil {
		t.Fatal(e)
	}
	defer supervisor.Close()
	id := ExecutionIdentity{"job-a", "attempt-a", "owner", 1}
	deadline := time.Now().Add(time.Hour)
	if _, e = supervisor.Ensure(context.Background(), id, "space-a", deadline); e == nil {
		t.Fatal("failed CSR issuer was accepted")
	}
	keyPath := filepath.Join(config.Root, id.JobID, "attempts", id.AttemptID, id.ComponentID, "proxy-key.pem")
	before, e := os.ReadFile(keyPath)
	if e != nil {
		t.Fatal("CSR key was not persisted before issuance", e)
	}
	if _, e = supervisor.Ensure(context.Background(), id, "space-a", deadline); e != nil {
		t.Fatal("CSR resumption failed", e)
	}
	after, e := os.ReadFile(keyPath)
	if e != nil || !bytes.Equal(before, after) || calls != 2 {
		t.Fatal("CSR retry changed identity")
	}
}
