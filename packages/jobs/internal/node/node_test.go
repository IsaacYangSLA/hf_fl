package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/resources"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/source"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func sampleSpec(t *testing.T, withBuild bool) domain.JobSpec {
	t.Helper()
	components := []any{map[string]any{"component_id": "owner", "role": "owner", "resources": map[string]any{"pool_id": "cpu", "cpu_millicores": 1000, "memory_bytes": 1 << 30, "disk_bytes": 1 << 30}}}
	if withBuild {
		components = append(components, map[string]any{"component_id": "builder", "role": "build", "resources": map[string]any{"pool_id": "cpu", "cpu_millicores": 1000, "memory_bytes": 1 << 30, "disk_bytes": 1 << 30}})
	}
	v := map[string]any{"project_id": "research", "name": "Classifier", "source_id": "trainer", "source_commit": strings.Repeat("a", 40), "runtime_image": "cpu-image", "plugin": "lenet", "options": map[string]any{}, "participants": []any{map[string]any{"participant_id": "alice", "dataset_binding": "data-alice"}, map[string]any{"participant_id": "bob", "dataset_binding": "data-bob"}}, "components": components, "target_round": 2, "max_duration_seconds": 3600}
	b, _ := json.Marshal(v)
	s, e := domain.DecodeJobSpec(b)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func sampleIdentity() executor.ExecutionIdentity {
	return executor.ExecutionIdentity{JobID: "job-a", AttemptID: "attempt-a", ComponentID: "owner", Epoch: 1}
}
func sampleAssignment(t *testing.T, build bool) RemoteAssignment {
	return RemoteAssignment{Identity: sampleIdentity(), NodeID: "node-a", PoolID: "cpu", Resources: executor.ResourceLimits{CPUMillis: 1000, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}.Defaults(), JobSpec: sampleSpec(t, build), ImageDigest: "sha256:" + strings.Repeat("b", 64), LeaseSeconds: 120}
}
func assertCode(t *testing.T, e error, code string) {
	t.Helper()
	var d *domain.Error
	if !errors.As(e, &d) || d.Code != code {
		t.Fatalf("expected %s, got %v", code, e)
	}
}
func TestAssignmentRejectsUnknownResourcesAndIdentity(t *testing.T) {
	a := sampleAssignment(t, false)
	b, _ := json.Marshal(a)
	if _, e := DecodeAssignment(b); e != nil {
		t.Fatal(e)
	}
	for _, mutation := range []func(map[string]any){
		func(m map[string]any) { m["host_path"] = "/private" },
		func(m map[string]any) { m["lease_seconds"] = nil },
		func(m map[string]any) { m["resources"].(map[string]any)["cpu_millis"] = 2000 },
		func(m map[string]any) { m["image_digest"] = "latest" },
		func(m map[string]any) { m["source_limits"] = map[string]any{"max_bytes": 0} },
	} {
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		mutation(m)
		bad, _ := json.Marshal(m)
		if _, e := DecodeAssignment(bad); e == nil {
			t.Fatal("unsafe assignment accepted")
		}
	}
	if e := strictDecode([]byte("{\"identity\":1,\"identity\":2}"), &map[string]any{}); e == nil {
		t.Fatal("duplicate JSON accepted")
	}
	if e := strictDecode([]byte("{\"a\":\"\\ud800\"}"), &map[string]any{}); e == nil {
		t.Fatal("unpaired surrogate accepted")
	}
}
func TestPurgeReceiptRequiresEveryOwnedDeletionProof(t *testing.T) {
	id := sampleIdentity()
	r := NodePurgeReceipt{JobID: id.JobID, AttemptID: id.AttemptID, ComponentID: id.ComponentID, Epoch: id.Epoch, NodeID: "node-a", PoolID: "cpu", SpecDigest: strings.Repeat("a", 64), OperationID: "purge-" + id.Key(), Purpose: "managed_node_purge", TerminationConfirmed: true, SourceDeleted: true, ConfigDeleted: true, BuildDeleted: true, PrivateCredentialsDeleted: true, PrivateSecretsDeleted: true, RetainedDeleted: true, AuxiliaryDeleted: true, Confirmed: true}
	if e := r.Validate(); e != nil {
		t.Fatal(e)
	}
	r.PrivateCredentialsDeleted = false
	assertCode(t, r.Validate(), "invalid_purge_receipt")
	r.PrivateCredentialsDeleted = true
	r.OperationID = "foreign"
	assertCode(t, r.Validate(), "invalid_purge_receipt")
}
func TestEndpointRefusesInsecureOriginsAndCredentialLinks(t *testing.T) {
	for _, origin := range []string{"http://example.test", "https://user:password@example.test", "https://example.test/path", "https://example.test?secret=a", "https://example.test#x", "https://example.test\n"} {
		e := NodeEndpoint{NodeID: "node", Origin: origin}.Defaults()
		if e.Validate() == nil {
			t.Fatalf("accepted unsafe origin %q", origin)
		}
	}
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(root, "key")
	if e := os.WriteFile(p, []byte("private"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := readTLSFile(p, true); e == nil {
		t.Fatal("broad key permissions accepted")
	}
	if e := os.Chmod(p, 0600); e != nil {
		t.Fatal(e)
	}
	alias := filepath.Join(root, "link")
	if e := os.Symlink(p, alias); e != nil {
		t.Fatal(e)
	}
	if _, e := readTLSFile(alias, true); e == nil {
		t.Fatal("symlink accepted")
	}
	hard := filepath.Join(root, "hard")
	if e := os.Link(p, hard); e != nil {
		t.Fatal(e)
	}
	if _, e := readTLSFile(p, true); e == nil {
		t.Fatal("hardlink accepted")
	}
}

type pki struct {
	ca, serverCert, serverKey, clientCert, clientKey []byte
	clientThumb                                      string
}

func makePKI(t *testing.T) pki {
	t.Helper()
	caKey, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Node test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	p := pki{ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})}
	issue := func(serial int64, client bool) ([]byte, []byte, []byte) {
		key, e := rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			t.Fatal(e)
		}
		c := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Node test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
		if client {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		} else {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, e := x509.CreateCertificate(rand.Reader, c, ca, &key.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), der
	}
	p.serverCert, p.serverKey, _ = issue(2, false)
	var clientDER []byte
	p.clientCert, p.clientKey, clientDER = issue(3, true)
	p.clientThumb = Thumbprint(clientDER)
	return p
}
func tlsFixture(t *testing.T, handler http.Handler) (NodeEndpoint, *httptest.Server, pki) {
	t.Helper()
	p := makePKI(t)
	cert, e := tls.X509KeyPair(p.serverCert, p.serverKey)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(p.ca)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	paths := []string{filepath.Join(root, "ca.pem"), filepath.Join(root, "client.pem"), filepath.Join(root, "client.key")}
	for i, b := range [][]byte{p.ca, p.clientCert, p.clientKey} {
		if e := os.WriteFile(paths[i], b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	endpoint := NodeEndpoint{NodeID: "node-a", Origin: server.URL, CAFile: paths[0], ClientCertificate: paths[1], ClientKey: paths[2]}.Defaults()
	return endpoint, server, p
}
func remoteFor(t *testing.T, handler http.Handler) (*RemoteExecutor, *httptest.Server) {
	t.Helper()
	endpoint, server, _ := tlsFixture(t, handler)
	a := sampleAssignment(t, false)
	r, e := NewRemoteExecutor(RemoteConfig{Endpoints: map[string]NodeEndpoint{"node-a": endpoint}, Route: func(context.Context, executor.ExecutionIdentity, string) (NodeRoute, error) {
		return NodeRoute{a.NodeID, a.PoolID, a.Resources}, nil
	}, AssignmentProvider: func(context.Context, executor.ExecutionSpec, NodeRoute) (RemoteAssignment, error) { return a, nil }, TokenProvider: func(context.Context, NodeRoute, executor.ExecutionIdentity, string) (string, error) {
		return "bound-token", nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(r.Close)
	return r, server
}
func TestRemoteTransportBindsMTLSAndValidatesReceipts(t *testing.T) {
	id := sampleIdentity()
	foreign := false
	calls := 0
	r, _ := remoteFor(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls++
		if req.Header.Get("Authorization") != "Bearer bound-token" || req.TLS == nil || len(req.TLS.VerifiedChains) == 0 {
			t.Error("unbound transport")
		}
		replyID := id
		if foreign {
			replyID.JobID = "foreign"
		}
		if strings.HasSuffix(req.URL.Path, "/reserve") {
			nodeJSON(w, executor.Reservation{Identity: replyID, Acknowledged: true, NodeID: "node-a", State: "RESERVED"})
			return
		}
		nodeJSON(w, executor.RuntimeObservation{Identity: replyID, State: "RUNNING", Metrics: map[string]float64{}, Details: map[string]any{}})
	}))
	a := sampleAssignment(t, false)
	spec := executor.ExecutionSpec{Identity: id, ImageDigest: a.ImageDigest, Resources: a.Resources, PoolID: a.PoolID, ProxyEndpoint: "/private/proxy.sock"}.Defaults()
	if _, e := r.Reserve(context.Background(), spec); e != nil {
		t.Fatal(e)
	}
	if _, e := r.Inspect(context.Background(), id); e != nil {
		t.Fatal(e)
	}
	foreign = true
	if _, e := r.Inspect(context.Background(), id); !executor.IsUncertain(e) {
		t.Fatalf("foreignreceipt %v", e)
	}
	if calls != 3 {
		t.Fatal(calls)
	}
}
func TestRemoteReplyBoundsRedirectsAndFailedProofRemainUncertain(t *testing.T) {
	mode := "oversize"
	r, server := remoteFor(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch mode {
		case "oversize":
			_, _ = w.Write(bytes.Repeat([]byte("a"), (2<<20)+1))
		case "redirect":
			w.Header().Set("Location", "https://foreign.invalid")
			w.WriteHeader(302)
		case "failure":
			w.WriteHeader(503)
		case "unconfirmed":
			nodeJSON(w, map[string]any{"confirmed": false})
		}
	}))
	_ = server
	for _, v := range []string{"oversize", "redirect", "failure"} {
		mode = v
		if _, e := r.Inspect(context.Background(), sampleIdentity()); !executor.IsUncertain(e) {
			t.Fatalf("%s %v", v, e)
		}
	}
	mode = "unconfirmed"
	if _, e := r.Release(context.Background(), sampleIdentity()); !executor.IsUncertain(e) {
		t.Fatalf("false release %v", e)
	}
}

type fakeProvisioner struct {
	document map[string]any
	grant    map[string]any
	read     func()
}

func (p *fakeProvisioner) PreparedComponent(context.Context, map[string]any, map[string]any, string) (map[string]any, error) {
	return p.document, nil
}
func (p *fakeProvisioner) OwnedSpace(context.Context, string) (string, error) { return "space-a", nil }
func (p *fakeProvisioner) ExchangeGrant(context.Context, string, string) (map[string]any, error) {
	if p.read != nil {
		p.read()
	}
	return p.grant, nil
}
func managedFixture(t *testing.T) (*AssignmentService, *store.DB, *fakeProvisioner, Principal) {
	t.Helper()
	ctx := context.Background()
	db, e := store.Open(ctx, "sqlite:///:memory:")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if _, e = db.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	pub, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	broker, e := exchange.NewBroker(exchange.BrokerSettings{Issuer: "https://workload.example.test", ExchangeAudience: "exchange-managed", GatewayAudience: "gateway", NodeAudience: "node", PublicKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), Clock: func() time.Time { return now }})
	if e != nil {
		t.Fatal(e)
	}
	a := sampleAssignment(t, false)
	spec := a.JobSpec
	hash, e := spec.Digest()
	if e != nil {
		t.Fatal(e)
	}
	e = db.WithTx(ctx, true, func(tx *store.Tx) error {
		inserts := []struct {
			table string
			v     map[string]any
		}{
			{"jm_projects", map[string]any{"id": "research", "name": "Research"}},
			{"jm_pools", map[string]any{"id": "cpu", "name": "CPU", "node_id": "node-a", "cpu_millicores": 4000, "memory_bytes": 4 << 30, "disk_bytes": 8 << 30, "healthy": true, "quarantined": false, "details_json": map[string]any{"registration_id": "registration-a"}, "sandbox_profiles": []string{"runsc-cpu-v1"}}},
			{"jm_jobs", map[string]any{"id": a.Identity.JobID, "project_id": "research", "creator_id": "creator", "name": "Classifier", "spec_json": spec.Map(), "spec_hash": hash, "state": "RUNNING", "phase": "training", "current_attempt": 1, "attempt_count": 1, "epoch": 1, "target_round": 2, "deadline_at": now.Add(time.Hour)}},
			{"jm_attempts", map[string]any{"id": a.Identity.AttemptID, "job_id": a.Identity.JobID, "number": 1, "epoch": 1, "state": "RUNNING"}},
			{"jm_allocations", map[string]any{"id": "allocation-a", "job_id": a.Identity.JobID, "attempt_id": a.Identity.AttemptID, "component_id": "owner", "pool_id": "cpu", "cpu_millicores": 1000, "memory_bytes": 1 << 30, "disk_bytes": 1 << 30, "gpu_count": 0, "epoch": 1, "state": "RUNNING", "acknowledged": true, "details_json": map[string]any{"node_id": "node-a", "registration_id": "registration-a"}}},
		}
		for _, v := range inserts {
			if e := tx.Insert(ctx, v.table, v.v); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	nodeThumb := Thumbprint([]byte("registered node"))
	managerThumb := Thumbprint([]byte("registered manager"))
	p := &fakeProvisioner{}
	service, e := NewAssignmentService(db, broker, AssignmentConfig{RegisteredNodes: map[string]ApprovedManagedNode{"node-a": {NodeID: "node-a", PoolID: "cpu", CertificateThumbprint: nodeThumb, RegistrationID: "registration-a", Enabled: true}}, ManagerCertificateThumbprint: managerThumb, Clock: func() time.Time { return now }, Provisioner: p, ValidatePrepared: func(map[string]any, string) error { return nil }})
	if e != nil {
		t.Fatal(e)
	}
	actor := Principal{NodeID: "node-a", PoolID: "cpu", JobID: a.Identity.JobID, AttemptID: a.Identity.AttemptID, ComponentID: "owner", Epoch: 1, GrantID: "allocation-a", CertificateThumbprint: nodeThumb, Scopes: []string{"assignment"}, Resources: map[string]any{"cpu_millicores": int64(1000), "memory_bytes": int64(1 << 30), "disk_bytes": int64(1 << 30)}}
	return service, db, p, actor
}
func TestManagedBootstrapAndCurrentGrantChecks(t *testing.T) {
	service, db, _, actor := managedFixture(t)
	ctx := context.Background()
	if _, e := service.Bootstrap(ctx, Thumbprint([]byte("foreign")), principalIdentity(actor)); e == nil {
		t.Fatal("foreign node bootstrapped")
	}
	token, e := service.Bootstrap(ctx, actor.CertificateThumbprint, principalIdentity(actor))
	if e != nil {
		t.Fatal(e)
	}
	current, e := service.AuthenticateNode(ctx, "Bearer "+valueString(token["token"]), actor.CertificateThumbprint)
	if e != nil || current.GrantID != "allocation-a" {
		t.Fatalf("bootstrap auth %v", e)
	}
	if _, e = service.AuthenticateNode(ctx, "Bearer "+valueString(token["token"]), service.Config.ManagerCertificateThumbprint); e == nil {
		t.Fatal("foreign cert accepted")
	}
	if valid, e := service.CheckNodeGrant(ctx, actor); e != nil || !valid {
		t.Fatalf("validnodegrant %v", e)
	}
	e = db.WithTx(ctx, true, func(tx *store.Tx) error {
		return tx.Update(ctx, "jm_allocations", map[string]any{"id": "allocation-a"}, map[string]any{"details_json": map[string]any{"node_id": "node-a", "registration_id": "retired"}})
	})
	if e != nil {
		t.Fatal(e)
	}
	if valid, e := service.CheckNodeGrant(ctx, actor); e != nil || valid {
		t.Fatalf("retiredregistration accepted %v", e)
	}
}
func TestManagedStartRequiresAllACKsAndCancellationDeniesNewWork(t *testing.T) {
	service, db, _, actor := managedFixture(t)
	ctx := context.Background()
	id := principalIdentity(actor)
	if _, e := service.IssueControlToken(ctx, id, "node-a", "cpu", "start", "", nil); e != nil {
		t.Fatal(e)
	}
	if e := db.WithTx(ctx, true, func(tx *store.Tx) error {
		return tx.Update(ctx, "jm_allocations", map[string]any{"id": "allocation-a"}, map[string]any{"acknowledged": false})
	}); e != nil {
		t.Fatal(e)
	}
	if _, e := service.IssueControlToken(ctx, id, "node-a", "cpu", "start", "", nil); e == nil {
		t.Fatal("start withoutACK")
	}
	if _, e := service.IssueControlToken(ctx, id, "node-a", "cpu", "reserve", "", nil); e != nil {
		t.Fatal(e)
	}
	if e := db.WithTx(ctx, true, func(tx *store.Tx) error {
		return tx.Update(ctx, "jm_jobs", map[string]any{"id": id.JobID}, map[string]any{"state": "CANCELLING"})
	}); e != nil {
		t.Fatal(e)
	}
	if _, e := service.IssueControlToken(ctx, id, "node-a", "cpu", "reserve", "", nil); e == nil {
		t.Fatal("cancelledwork authorized")
	}
	if _, e := service.IssueControlToken(ctx, id, "node-a", "cpu", "stop", "", nil); e != nil {
		t.Fatal(e)
	}
}
func TestManagedAssignmentRefusesHostPathsAndChangedModelSpec(t *testing.T) {
	service, _, p, actor := managedFixture(t)
	spec := sampleSpec(t, false)
	p.document = map[string]any{"job_id": actor.JobID, "attempt_id": actor.AttemptID, "component_id": actor.ComponentID, "epoch": actor.Epoch, "source_dir": "/job/source", "state_dir": "/job/state", "proxy_socket": "/run/hf2l/proxy.sock", "exchange_endpoint": "http://proxy", "spec": spec.Map()}
	if _, e := service.Assignment(context.Background(), actor); e != nil {
		t.Fatal(e)
	}
	p.document["source_dir"] = "/etc"
	if _, e := service.Assignment(context.Background(), actor); e == nil {
		t.Fatal("hostsourcepath accepted")
	}
	p.document["source_dir"] = "/job/source"
	changed := spec
	changed.Name = "Changed model"
	p.document["spec"] = changed.Map()
	if _, e := service.Assignment(context.Background(), actor); e == nil {
		t.Fatal("changedimmutable spec accepted")
	}
}
func materializerFixture(t *testing.T, withBuild bool) (*Materializer, RemoteAssignment, map[string]string) {
	t.Helper()
	ctx := context.Background()
	base := t.TempDir()
	_ = os.Chmod(base, 0700)
	repo := filepath.Join(base, "mirror")
	if e := os.Mkdir(repo, 0700); e != nil {
		t.Fatal(e)
	}
	run := func(args ...string) string {
		c := exec.Command("git", args...)
		c.Dir = repo
		c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0")
		out, e := c.CombinedOutput()
		if e != nil {
			t.Fatalf("gitfixture %v %s", e, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q")
	if e := os.WriteFile(filepath.Join(repo, "trainer.py"), []byte("print('trusted trainer')\n"), 0600); e != nil {
		t.Fatal(e)
	}
	run("add", "trainer.py")
	run("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-q", "-m", "Fixture")
	commit := run("rev-parse", "HEAD")
	a := sampleAssignment(t, withBuild)
	a.JobSpec.SourceCommit = commit
	approval := source.Approval{SourceID: "trainer", Projects: []string{"research"}, MirrorPath: repo, Commits: []string{commit}, MaxBytes: 1 << 20, MaxFiles: 100, MaxGitBytes: 4 << 20, MaxGitFiles: 100}
	registry, e := source.NewRegistry([]source.Approval{approval}, nil)
	if e != nil {
		t.Fatal(e)
	}
	catalog, e := source.NewCatalog(registry, map[string]string{"cpu-image": a.ImageDigest}, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	m, e := NewMaterializer(MaterializerConfig{Root: filepath.Join(base, "node"), NodeID: "node-a", PoolID: "cpu", Catalog: catalog, ValidateRuntime: func(map[string]any, string) error { return nil }})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { m.Close() })
	if _, e = m.Reserve(ctx, a); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256([]byte("print('trusted trainer')\n"))
	return m, a, map[string]string{"trainer.py": hex.EncodeToString(sum[:])}
}
func TestMaterializerImmutablePreparationAndScopedPurge(t *testing.T) {
	m, a, manifest := materializerFixture(t, false)
	ctx := context.Background()
	document := map[string]any{"job_id": a.Identity.JobID, "attempt_id": a.Identity.AttemptID, "component_id": a.Identity.ComponentID, "epoch": a.Identity.Epoch, "role": "owner", "source_dir": "/job/source", "state_dir": "/job/state", "proxy_socket": "/run/hf2l/proxy.sock", "exchange_endpoint": "http://proxy", "spec": a.JobSpec.Map(), "source_manifest": map[string]any{"trainer.py": manifest["trainer.py"]}, "dataset_bindings": map[string]any{}}
	if _, e := m.Prepare(ctx, a.Identity, document, nil); e != nil {
		t.Fatal(e)
	}
	if _, e := m.Prepare(ctx, a.Identity, document, nil); e != nil {
		t.Fatal("idempotentprepare", e)
	}
	document["source_dir"] = "/outside"
	if _, e := m.Prepare(ctx, a.Identity, document, nil); e == nil {
		t.Fatal("hostpath accepted")
	}
	document["source_dir"] = "/job/source"
	changed := a
	changed.LeaseSeconds = 121
	if _, e := m.Reserve(ctx, changed); e == nil {
		t.Fatal("changedassignment reused")
	}
	all, e := m.AllAssignments(ctx)
	if e != nil || len(all) != 1 {
		t.Fatalf("inventory %v %d", e, len(all))
	}
	if e = m.RemoveAssignment(ctx, a.Identity); e == nil {
		t.Fatal("metadata removedbeforephysicalpurge")
	}
	if ok, e := m.Purge(ctx, a.Identity); e != nil || !ok {
		t.Fatalf("purge %v", e)
	}
	if e = m.RemoveAssignment(ctx, a.Identity); e != nil {
		t.Fatal(e)
	}
	all, e = m.AllAssignments(ctx)
	if e != nil || len(all) != 0 {
		t.Fatalf("postpurge %v %d", e, len(all))
	}
}
func TestWheelChunkRetriesAndSymlinkAreBounded(t *testing.T) {
	m, a, _ := materializerFixture(t, true)
	ctx := context.Background()
	data := []byte("opaque verified wheel content")
	h := sha256.Sum256(data)
	filename := "trainer-1-py3-none-any.whl"
	manifest := map[string]any{filename: map[string]any{"sha256": hex.EncodeToString(h[:]), "size_bytes": int64(len(data))}}
	chunk := base64.StdEncoding.EncodeToString(data[:10])
	if _, e := m.StageBuildInput(ctx, a.Identity, manifest, filename, 0, chunk); e != nil {
		t.Fatal(e)
	}
	if _, e := m.StageBuildInput(ctx, a.Identity, manifest, filename, 0, chunk); e != nil {
		t.Fatal("retry", e)
	}
	if _, e := m.StageBuildInput(ctx, a.Identity, manifest, filename, 0, base64.StdEncoding.EncodeToString([]byte("different!"))); e == nil {
		t.Fatal("changedretry accepted")
	}
	if _, e := m.StageBuildInput(ctx, a.Identity, manifest, filename, 11, base64.StdEncoding.EncodeToString(data[11:])); e == nil {
		t.Fatal("gap accepted")
	}
	if _, e := m.StageBuildInput(ctx, a.Identity, manifest, filename, 10, base64.StdEncoding.EncodeToString(data[10:])); e != nil {
		t.Fatal(e)
	}
	if _, e := m.StageBuildInput(ctx, a.Identity, manifest, filename, 0, chunk); e != nil {
		t.Fatal("completedretry", e)
	}
	if _, e := m.StageBuildInput(ctx, a.Identity, manifest, "../../outside", 0, chunk); e == nil {
		t.Fatal("pathtraversal accepted")
	}
}
func TestVerifiedPeerRejectsForwardedCertificateHeaders(t *testing.T) {
	req := httptest.NewRequest("POST", "https://node.test/internal/nodes/v1/start", strings.NewReader("{}"))
	req.Header.Set("X-Client-Certificate-Thumbprint", Thumbprint([]byte("forged")))
	req.Header.Set("X-Forwarded-Client-Cert", "forged")
	if _, e := VerifiedPeer(req); e == nil {
		t.Fatal("forwardedheader accepted")
	}
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: []byte("unverified")}}}
	if _, e := VerifiedPeer(req); e == nil {
		t.Fatal("unverifiedTLScert accepted")
	}
}

type lifecycleBackend struct {
	state string
	id    executor.ExecutionIdentity
}

func (b *lifecycleBackend) Reserve(_ context.Context, s executor.ExecutionSpec) (executor.Reservation, error) {
	b.id = s.Identity
	b.state = "RESERVED"
	return executor.Reservation{Identity: s.Identity, Acknowledged: true, NodeID: "node-a", State: b.state}, nil
}
func (b *lifecycleBackend) observation(id executor.ExecutionIdentity) executor.RuntimeObservation {
	return executor.RuntimeObservation{Identity: id, State: b.state, TerminationConfirmed: b.state == "STOPPED" || b.state == "RELEASED", Metrics: map[string]float64{}, Details: map[string]any{}}
}
func (b *lifecycleBackend) Start(_ context.Context, id executor.ExecutionIdentity) (executor.RuntimeObservation, error) {
	b.state = "RUNNING"
	return b.observation(id), nil
}
func (b *lifecycleBackend) Inspect(_ context.Context, id executor.ExecutionIdentity) (executor.RuntimeObservation, error) {
	return b.observation(id), nil
}
func (b *lifecycleBackend) Stop(_ context.Context, id executor.ExecutionIdentity, _ int) (executor.RuntimeObservation, error) {
	b.state = "STOPPED"
	return b.observation(id), nil
}
func (b *lifecycleBackend) Collect(context.Context, executor.ExecutionIdentity) ([]executor.CollectedArtifact, error) {
	return []executor.CollectedArtifact{}, nil
}
func (b *lifecycleBackend) Release(context.Context, executor.ExecutionIdentity) (bool, error) {
	b.state = "RELEASED"
	return true, nil
}
func (b *lifecycleBackend) Purge(context.Context, executor.ExecutionIdentity) (bool, error) {
	return true, nil
}
func TestNodeServerMTLSLifecycleAndPhysicalPurge(t *testing.T) {
	m, a, manifest := materializerFixture(t, false)
	ctx := context.Background()
	backend := &lifecycleBackend{}
	agent, e := executor.NewNodeAgent(backend, filepath.Join(m.Config.Root, "node.sqlite"), "node-a", "cpu", executor.ResourceLimits{CPUMillis: 4000, MemoryBytes: 4 << 30, DiskBytes: 8 << 30}.Defaults())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { agent.Close() })
	peerThumb := ""
	handler, e := NewHandler(ServerConfig{NodeID: "node-a", PoolID: "cpu", Agent: agent, Materializer: m, Authenticate: func(ctx context.Context, authorization, peer, scope string) (Principal, error) {
		if authorization != "Bearer bound-token" || peer != peerThumb {
			return Principal{}, domain.Err(401, "invalid_node_access_token")
		}
		return Principal{NodeID: a.NodeID, PoolID: a.PoolID, JobID: a.Identity.JobID, AttemptID: a.Identity.AttemptID, ComponentID: a.Identity.ComponentID, Epoch: a.Identity.Epoch, GrantID: "allocation-a", CertificateThumbprint: peer, Scopes: []string{scope}, Resources: map[string]any{"cpu_millicores": a.Resources.CPUMillis, "memory_bytes": a.Resources.MemoryBytes, "disk_bytes": a.Resources.DiskBytes}}, nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	endpoint, _, p := tlsFixture(t, handler)
	peerThumb = p.clientThumb
	remote, e := NewRemoteExecutor(RemoteConfig{Endpoints: map[string]NodeEndpoint{"node-a": endpoint}, Route: func(context.Context, executor.ExecutionIdentity, string) (NodeRoute, error) {
		return NodeRoute{a.NodeID, a.PoolID, a.Resources}, nil
	}, AssignmentProvider: func(context.Context, executor.ExecutionSpec, NodeRoute) (RemoteAssignment, error) { return a, nil }, TokenProvider: func(context.Context, NodeRoute, executor.ExecutionIdentity, string) (string, error) {
		return "bound-token", nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer remote.Close()
	plan, e := m.Plan(ctx, a)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = remote.Reserve(ctx, plan); e != nil {
		t.Fatal("reserve", e)
	}
	document := map[string]any{"job_id": a.Identity.JobID, "attempt_id": a.Identity.AttemptID, "component_id": a.Identity.ComponentID, "epoch": a.Identity.Epoch, "role": "owner", "source_dir": "/job/source", "state_dir": "/job/state", "proxy_socket": "/run/hf2l/proxy.sock", "exchange_endpoint": "http://proxy", "spec": a.JobSpec.Map(), "source_manifest": map[string]any{"trainer.py": manifest["trainer.py"]}, "dataset_bindings": map[string]any{}}
	if _, e = remote.Prepare(ctx, a.Identity, document, nil, nil); e != nil {
		t.Fatal("prepare", e)
	}
	if _, e = remote.Start(ctx, a.Identity); e != nil {
		t.Fatal("start", e)
	}
	if e = remote.RenewLease(ctx, a.Identity, 120); e != nil {
		t.Fatal("renew", e)
	}
	if observation, e := remote.Inspect(ctx, a.Identity); e != nil || observation.State != "RUNNING" {
		t.Fatalf("inspect %v %#v", e, observation)
	}
	if _, e = remote.Stop(ctx, a.Identity, 0); e != nil {
		t.Fatal("stop", e)
	}
	if _, e = remote.Release(ctx, a.Identity); e != nil {
		t.Fatal("release", e)
	}
	digest, e := a.JobSpec.Digest()
	if e != nil {
		t.Fatal(e)
	}
	if receipt, e := remote.PurgeReceipt(ctx, a.Identity, digest); e != nil || !receipt.Confirmed {
		t.Fatalf("purge %v %#v", e, receipt)
	}
	if _, e = remote.PurgeReceipt(ctx, a.Identity, digest); e != nil {
		t.Fatal("idempotentpurge", e)
	}
	parent, _ := m.relativePaths(a.Identity)
	if _, e = os.Lstat(filepath.Join(m.Config.Root, parent)); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("component files retainedafterconfirmedpurge")
	}
}
func TestManagedCredentialsRecheckCancellationAfterGrantLookup(t *testing.T) {
	service, db, p, actor := managedFixture(t)
	ctx := context.Background()
	thumb := Thumbprint([]byte("executioncertificate"))
	principal, e := exchange.StableWorkloadPrincipal(service.Broker.Issuer(), actor.JobID, actor.ComponentID, nil)
	if e != nil {
		t.Fatal(e)
	}
	rows := []struct {
		kind, id string
		detail   map[string]any
	}{
		{"execution_certificate", principalIdentity(actor).Key(), map[string]any{"certificate_thumbprint": thumb, "space_id": "space-a", "principal_id": principal}},
		{"workload_grant", "grant-a", map[string]any{"grant_id": "grant-a"}},
	}
	for _, row := range rows {
		_, e := service.Ledger.Own(ctx, resources.Ownership{JobID: actor.JobID, AttemptID: actor.AttemptID, ComponentID: actor.ComponentID, Kind: row.kind, ExternalID: row.id, Details: row.detail})
		if e != nil {
			t.Fatal(e)
		}
	}
	p.grant = map[string]any{"job_id": actor.JobID, "attempt_id": actor.AttemptID, "component_id": actor.ComponentID, "epoch": actor.Epoch, "space_id": "space-a", "principal_id": principal, "certificate_thumbprint": thumb, "grant_id": "grant-a", "enabled": true, "expires_at": service.now().Unix() + 240}
	value, e := service.Credentials(ctx, actor, thumb, "exchange")
	if e != nil || valueString(value["token"]) == "" {
		t.Fatalf("validcredential %v", e)
	}
	p.read = func() {
		if e := db.WithTx(ctx, true, func(tx *store.Tx) error {
			return tx.Update(ctx, "jm_jobs", map[string]any{"id": actor.JobID}, map[string]any{"state": "CANCELLING"})
		}); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := service.Credentials(ctx, actor, thumb, "exchange"); e == nil {
		t.Fatal("tokenmintedaftercancellation")
	}
}
func TestWheelSymlinkCannotMutateForeignFile(t *testing.T) {
	m, a, _ := materializerFixture(t, true)
	ctx := context.Background()
	data := []byte("opaque wheel")
	h := sha256.Sum256(data)
	filename := "trainer-1-py3-none-any.whl"
	manifest := map[string]any{filename: map[string]any{"sha256": hex.EncodeToString(h[:]), "size_bytes": int64(len(data))}}
	parent, _, e := m.paths(a)
	if e != nil {
		t.Fatal(e)
	}
	if e = m.mkdir(parent + "/build-inputs"); e != nil {
		t.Fatal(e)
	}
	outside := filepath.Join(t.TempDir(), "foreign")
	if e = os.WriteFile(outside, []byte("preserve"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(outside, filepath.Join(m.Config.Root, parent, "build-inputs", filename)); e != nil {
		t.Fatal(e)
	}
	if _, e = m.StageBuildInput(ctx, a.Identity, manifest, filename, 0, base64.StdEncoding.EncodeToString(data)); e == nil {
		t.Fatal("linkedartifact accepted")
	}
	after, e := os.ReadFile(outside)
	if e != nil || string(after) != "preserve" {
		t.Fatal("foreignfile changed")
	}
}

func TestCertificateIssuanceIsImmutablePerExecutionCSR(t *testing.T) {
	service, _, _, actor := managedFixture(t)
	ctx := context.Background()
	issued := 0
	thumb := Thumbprint([]byte("issued execution"))
	service.Config.IssueCertificate = func(context.Context, string, executor.ExecutionIdentity, string, time.Time) (map[string]any, error) {
		issued++
		return map[string]any{"certificate_pem": "trusted issuer receipt", "certificate_thumbprint": thumb}, nil
	}
	principal, e := exchange.StableWorkloadPrincipal(service.Broker.Issuer(), actor.JobID, actor.ComponentID, nil)
	if e != nil {
		t.Fatal(e)
	}
	csr := func() string {
		key, e := rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			t.Fatal(e)
		}
		der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		if e != nil {
			t.Fatal(e)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	}
	original := csr()
	if _, e = service.IssueCertificate(ctx, actor, original, "space-a", principal); e != nil {
		t.Fatal(e)
	}
	if _, e = service.IssueCertificate(ctx, actor, original, "space-a", principal); e != nil {
		t.Fatal("idempotentissuance", e)
	}
	if issued != 1 {
		t.Fatalf("duplicatecertificate signing: %d", issued)
	}
	if _, e = service.IssueCertificate(ctx, actor, csr(), "space-a", principal); e == nil {
		t.Fatal("changedCSR reissuedforexecution")
	}
	if issued != 1 {
		t.Fatal("changedCSR reachedsigner")
	}
	if _, e = service.IssueCertificate(ctx, actor, original, "foreign-space", principal); e == nil {
		t.Fatal("foreignspace certificate")
	}
}
func TestCertificateIssuanceRechecksCancellationAfterSigner(t *testing.T) {
	service, db, _, actor := managedFixture(t)
	ctx := context.Background()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if e != nil {
		t.Fatal(e)
	}
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	service.Config.IssueCertificate = func(context.Context, string, executor.ExecutionIdentity, string, time.Time) (map[string]any, error) {
		if e := db.WithTx(ctx, true, func(tx *store.Tx) error {
			return tx.Update(ctx, "jm_jobs", map[string]any{"id": actor.JobID}, map[string]any{"state": "CANCELLING"})
		}); e != nil {
			t.Fatal(e)
		}
		return map[string]any{"certificate_pem": "trusted issuer receipt", "certificate_thumbprint": Thumbprint([]byte("signed"))}, nil
	}
	principal, e := exchange.StableWorkloadPrincipal(service.Broker.Issuer(), actor.JobID, actor.ComponentID, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = service.IssueCertificate(ctx, actor, csr, "space-a", principal); e == nil {
		t.Fatal("cancelledcertificate activated")
	}
	row, e := db.One(ctx, "SELECT id FROM jm_provisioning_resources WHERE job_id = ? AND kind = ?", actor.JobID, "execution_certificate")
	if e != nil || row != nil {
		t.Fatalf("cancelledissuance publishedresource %v", e)
	}
}
