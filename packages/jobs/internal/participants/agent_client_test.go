package participants

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/node"
)

func testParticipantBroker(t *testing.T) *exchange.Broker {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	public, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	b, e := exchange.NewBroker(exchange.BrokerSettings{Issuer: "https://workloads.example.test", ExchangeAudience: "exchange-managed", GatewayAudience: "gateway", NodeAudience: "nodes", PublicKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})})
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestParticipantClientHTTPSMethodsStreamingAndRedirectRefusal(t *testing.T) {
	id := executor.ExecutionIdentity{JobID: "job", AttemptID: "attempt", ComponentID: ComponentID("alice"), Epoch: 1}
	data := bytes.Repeat([]byte("w"), 150000)
	count := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("unsafe authentication or encoding")
		}
		if strings.HasSuffix(r.URL.Path, "/plan") {
			if r.Method != "GET" {
				t.Error(r.Method)
			}
			_, _ = w.Write([]byte(`{"node_id":"node"}`))
			return
		}
		if strings.Contains(r.URL.Path, "/build-products/") {
			if r.Method != "GET" {
				t.Error(r.Method)
			}
			_, _ = w.Write(data)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/source/plugin.py") {
			if r.Method != "GET" {
				t.Error(r.Method)
			}
			_, _ = w.Write([]byte("source"))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/credentials") {
			if r.Method != "POST" {
				t.Error(r.Method)
			}
			count++
			http.Redirect(w, r, "/foreign", 302)
			return
		}
		t.Error("redirect or unexpected endpoint reached", r.URL.Path)
		w.WriteHeader(500)
	}))
	defer server.Close()
	client, e := NewManagerClient(ClientConfig{Endpoint: server.URL, HTTP: server.Client()})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	plan, e := client.Request(context.Background(), id, "fixture", "plan", nil)
	if e != nil || plan["node_id"] != "node" {
		t.Fatalf("%v %v", plan, e)
	}
	source, e := client.Raw(context.Background(), id, "fixture", "source/plugin.py")
	if e != nil || string(source) != "source" {
		t.Fatalf("%q %v", source, e)
	}
	received := []byte{}
	chunks := 0
	e = client.Stream(context.Background(), id, "fixture", "build-products/model.whl", int64(len(data)), func(offset int64, chunk []byte) error {
		if offset != int64(len(received)) || len(chunk) > 65536 {
			t.Fatal("unbounded or discontinuous chunks")
		}
		chunks++
		received = append(received, chunk...)
		return nil
	})
	if e != nil || !bytes.Equal(data, received) || chunks < 3 {
		t.Fatalf("stream %d %v", chunks, e)
	}
	_, e = client.Request(context.Background(), id, "fixture", "credentials", map[string]any{})
	expectParticipantCode(t, e, "external_manager_redirect_forbidden")
	if count != 1 {
		t.Fatal(count)
	}
	for _, operation := range []string{"source/../secret", "source//secret", "build-products/../secret", "credentials?token=x", "/credentials"} {
		_, e = client.Request(context.Background(), id, "fixture", operation, nil)
		expectParticipantCode(t, e, "invalid_participant_operation")
	}
}
func TestParticipantClientRejectsReplySizeAndEncoding(t *testing.T) {
	id := executor.ExecutionIdentity{JobID: "job", AttemptID: "attempt", ComponentID: "component", Epoch: 1}
	for _, mode := range []string{"encoding", "size", "error"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "encoding" {
					w.Header().Set("Content-Encoding", "gzip")
					_, _ = w.Write([]byte("binary"))
					return
				}
				if mode == "size" {
					_, _ = w.Write([]byte("oversized"))
					return
				}
				w.WriteHeader(409)
				_, _ = w.Write([]byte(`{"error":{"code":"grant_revoked"}}`))
			}))
			defer server.Close()
			client, e := NewManagerClient(ClientConfig{Endpoint: server.URL, HTTP: server.Client()})
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			e = client.Stream(context.Background(), id, "fixture", "build-products/model.whl", 1, func(int64, []byte) error { return nil })
			if e == nil {
				t.Fatal("invalid stream accepted")
			}
			if mode == "error" {
				_, e = client.Request(context.Background(), id, "fixture", "credentials", nil)
				expectParticipantCode(t, e, "grant_revoked")
			}
		})
	}
}
func TestParticipantHandlerRejectsForgedCertificateHeaders(t *testing.T) {
	broker := testParticipantBroker(t)
	a := &Agent{Broker: broker, Config: AgentConfig{NodeID: "node", NodeCertificateThumbprint: participantThumb("node")}}
	handler := a.Handler([]string{participantThumb("manager")})
	for _, state := range []*tls.ConnectionState{nil, {PeerCertificates: []*x509.Certificate{{Raw: []byte("manager")}}}} {
		req := httptest.NewRequest("POST", "https://node.example.test/internal/nodes/v1/participants", strings.NewReader(`{"node_token":"forged"}`))
		req.TLS = state
		req.Header.Set("X-Verified-Client-Certificate", participantThumb("manager"))
		req.Header.Set("X-SSL-Client-Verify", "SUCCESS")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != 401 || !strings.Contains(response.Body.String(), "verified_manager_certificate_required") {
			t.Fatalf("%d %s", response.Code, response.Body.String())
		}
	}
}

type participantRuntimeFake struct {
	AgentRuntime
	events                   *[]string
	state                    string
	confirmed                bool
	stopError                error
	absent                   bool
	starts, renews, releases int
}

func (f *participantRuntimeFake) add(s string) { *f.events = append(*f.events, s) }
func (f *participantRuntimeFake) WithComponentGuardContext(ctx context.Context, id executor.ExecutionIdentity, purge bool, fn func(context.Context) error) error {
	f.add("guard")
	return fn(ctx)
}
func (f *participantRuntimeFake) Reserve(context.Context, executor.ExecutionSpec) (executor.Reservation, error) {
	f.add("reserve")
	if f.state == "" {
		f.state = "RESERVED"
	}
	return executor.Reservation{Acknowledged: true, State: f.state}, nil
}
func (f *participantRuntimeFake) Inspect(context.Context, executor.ExecutionIdentity) (executor.RuntimeObservation, error) {
	return executor.RuntimeObservation{State: f.state, TerminationConfirmed: f.confirmed}, nil
}
func (f *participantRuntimeFake) ChargeAuxiliaryBytes(context.Context, executor.ExecutionIdentity, int64) (bool, error) {
	f.add("charge")
	return true, nil
}
func (f *participantRuntimeFake) Start(context.Context, executor.ExecutionIdentity) (executor.RuntimeObservation, error) {
	f.starts++
	f.state = "RUNNING"
	f.add("start")
	return executor.RuntimeObservation{State: f.state}, nil
}
func (f *participantRuntimeFake) RenewLease(context.Context, executor.ExecutionIdentity, float64) error {
	f.renews++
	f.add("renew")
	return nil
}
func (f *participantRuntimeFake) Stop(context.Context, executor.ExecutionIdentity, int) (executor.RuntimeObservation, error) {
	f.add("stop")
	if f.stopError != nil {
		return executor.RuntimeObservation{}, f.stopError
	}
	f.state = "STOPPED"
	return executor.RuntimeObservation{State: f.state, TerminationConfirmed: f.confirmed}, nil
}
func (f *participantRuntimeFake) ConfirmAbsent(context.Context, executor.ExecutionIdentity) (bool, error) {
	return f.absent, nil
}
func (f *participantRuntimeFake) ReadLogs(context.Context, executor.ExecutionIdentity, int64, int64) (map[string]any, error) {
	return map[string]any{"next_offset": int64(0), "complete": true}, nil
}
func (f *participantRuntimeFake) Release(context.Context, executor.ExecutionIdentity) (bool, error) {
	f.releases++
	f.add("release")
	return f.confirmed, nil
}

type participantMaterializerFake struct {
	AgentMaterializer
	events     *[]string
	config     map[string]any
	assignment node.RemoteAssignment
}

func (f *participantMaterializerFake) Plan(ctx context.Context, a node.RemoteAssignment) (executor.ExecutionSpec, error) {
	*f.events = append(*f.events, "plan-local")
	f.assignment = a
	return executor.ExecutionSpec{Identity: a.Identity, Resources: a.Resources}, nil
}
func (f *participantMaterializerFake) Reserve(ctx context.Context, a node.RemoteAssignment) (executor.ExecutionSpec, error) {
	*f.events = append(*f.events, "persist-assignment")
	return executor.ExecutionSpec{Identity: a.Identity}, nil
}
func (f *participantMaterializerFake) Binding(context.Context, executor.ExecutionIdentity, string, string) (map[string]any, error) {
	return map[string]any{"certificate_thumbprint": participantThumb("execution"), "proxy_id": "proxy"}, nil
}
func (f *participantMaterializerFake) Prepare(ctx context.Context, id executor.ExecutionIdentity, c, b map[string]any) (bool, error) {
	*f.events = append(*f.events, "prepare")
	f.config = c
	return true, nil
}

type participantRequesterFake struct {
	events           *[]string
	plan, assignment map[string]any
	controlConfirmed bool
	credentialsError error
	stoppedBody      map[string]any
}

func (f *participantRequesterFake) Request(ctx context.Context, id executor.ExecutionIdentity, token, operation string, body any) (map[string]any, error) {
	*f.events = append(*f.events, "central-"+operation)
	switch operation {
	case "plan":
		return f.plan, nil
	case "assignment":
		return f.assignment, nil
	case "credentials":
		if f.credentialsError != nil {
			return nil, f.credentialsError
		}
		return map[string]any{"exchange_token": "workload", "gateway_token": "gateway"}, nil
	case "control":
		return map[string]any{"node_id": "node-alice", "identity": identityMap(id), "termination_confirmed": f.controlConfirmed}, nil
	case "heartbeat":
		return map[string]any{"accepted": true}, nil
	case "logs":
		return map[string]any{"accepted": true, "next_offset": int64(0), "complete": true}, nil
	case "stopped":
		f.stoppedBody = mapv(body)
		return map[string]any{"accepted": true}, nil
	}
	return nil, domain.Err(404, "unexpected_test_operation")
}
func (f *participantRequesterFake) Raw(context.Context, executor.ExecutionIdentity, string, string) ([]byte, error) {
	return nil, domain.Err(404, "unexpected_test_operation")
}
func newAgentFixture(t *testing.T) (*Agent, *participantRuntimeFake, *participantRequesterFake, map[string]any, *[]string) {
	t.Helper()
	base := newParticipantFixture(t)
	broker := testParticipantBroker(t)
	id := executor.ExecutionIdentity{JobID: "job", AttemptID: "attempt", ComponentID: ComponentID("alice"), Epoch: 1}
	events := []string{}
	manifest := map[string]any{"plugin.py": strings.Repeat("a", 64)}
	plan := map[string]any{"identity": identityMap(id), "node_id": "node-alice", "pool_id": "external", "resources": map[string]any{"cpu_millicores": int64(1000), "memory_bytes": int64(1 << 30), "disk_bytes": int64(1 << 30)}, "job_spec": base.spec.Map(), "image_digest": "sha256:" + strings.Repeat("b", 64), "lease_seconds": int64(120), "deadline": nil, "external_participant_id": "alice", "space_id": "space", "principal_id": "principal", "source_manifest": manifest, "source_limits": map[string]any{"max_bytes": int64(1 << 20), "max_files": int64(100), "max_git_bytes": int64(1 << 20), "max_git_files": int64(100)}, "built_artifacts": map[string]any{}}
	config := map[string]any{"role": "client", "job_id": "job", "attempt_id": "attempt", "component_id": id.ComponentID, "epoch": int64(1), "spec": base.spec.Map(), "spec_digest": base.digest, "source_manifest": manifest, "built_artifacts": map[string]any{}}
	requester := &participantRequesterFake{events: &events, plan: plan, assignment: map[string]any{"identity": identityMap(id), "runtime_config": config}}
	runtime := &participantRuntimeFake{events: &events, state: "RESERVED", confirmed: true}
	materializer := &participantMaterializerFake{events: &events}
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	agent, e := NewAgent(AgentConfig{NodeID: "node-alice", NodeCertificateThumbprint: participantThumb("node-alice"), Root: root, LedgerPath: filepath.Join(root, "node.sqlite"), ProxyStop: func(context.Context, executor.ExecutionIdentity, bool) (bool, error) {
		events = append(events, "proxy-stop")
		return true, nil
	}}, requester, materializer, runtime, broker)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(agent.Close)
	token, e := broker.IssueNode(exchange.NodeRequest{NodeID: "node-alice", PoolID: "external", JobID: "job", AttemptID: "attempt", ComponentID: id.ComponentID, GrantID: "enrollment", Epoch: 1, CertificateThumbprint: participantThumb("node-alice"), Scopes: []string{"assignment", "heartbeat", "stopped", "logs", "collect"}})
	if e != nil {
		t.Fatal(e)
	}
	doc := map[string]any{"node_token": token, "node_certificate_thumbprint": participantThumb("node-alice"), "operation": "start"}
	return agent, runtime, requester, doc, &events
}
func TestParticipantAgentStartOrderingReplayAndOnlineRevocation(t *testing.T) {
	a, runtime, requester, document, events := newAgentFixture(t)
	out, e := a.Receive(context.Background(), document)
	if e != nil || out["state"] != "RUNNING" {
		t.Fatalf("%v %v events=%v", out, e, *events)
	}
	if runtime.starts != 1 {
		t.Fatal(runtime.starts)
	}
	joined := strings.Join(*events, ",")
	if !strings.Contains(joined, "charge,persist-assignment") || !strings.Contains(joined, "prepare,central-credentials,start,central-heartbeat") {
		t.Fatal("unsafe side-effect ordering", joined)
	}
	if _, e = a.Receive(context.Background(), document); e != nil {
		t.Fatal("redispatch", e)
	}
	if runtime.starts != 1 || runtime.renews != 1 {
		t.Fatalf("duplicate execution start=%d renew=%d", runtime.starts, runtime.renews)
	}
	requester.credentialsError = domain.Err(401, "grant_revoked")
	_, e = a.Receive(context.Background(), document)
	expectParticipantCode(t, e, "grant_revoked")
	if runtime.starts != 1 || runtime.renews != 1 {
		t.Fatal("revocation still extended runtime")
	}
}
func TestParticipantAgentStopNeedsDurableRuntimeAndLogProof(t *testing.T) {
	a, runtime, requester, document, _ := newAgentFixture(t)
	document["operation"] = "stop"
	runtime.confirmed = false
	_, e := a.Receive(context.Background(), document)
	expectParticipantCode(t, e, "participant_termination_unconfirmed")
	if requester.stoppedBody != nil || runtime.releases != 0 {
		t.Fatal("unconfirmed stop released accounting")
	}
	runtime.confirmed = true
	out, e := a.Receive(context.Background(), document)
	if e != nil || out["state"] != "stopped" || requester.stoppedBody["termination_confirmed"] != true {
		t.Fatalf("%v %v", out, e)
	}
	if runtime.releases != 1 {
		t.Fatal(runtime.releases)
	}
}
func TestParticipantAgentUndeliveredStopRequiresIndependentAbsence(t *testing.T) {
	a, runtime, requester, document, _ := newAgentFixture(t)
	document["operation"] = "stop"
	runtime.stopError = domain.Err(409, "missing_reservation")
	_, e := a.Receive(context.Background(), document)
	expectParticipantCode(t, e, "participant_termination_unconfirmed")
	if requester.stoppedBody != nil {
		t.Fatal("unproven absence acknowledged")
	}
	runtime.absent = true
	if _, e = a.Receive(context.Background(), document); e != nil {
		t.Fatal(e)
	}
	if requester.stoppedBody["never_started"] != true || runtime.releases != 0 {
		t.Fatal("undelivered stop proof wrong")
	}
}
func TestParticipantAgentRejectsUnboundSourceAndUnknownDispatch(t *testing.T) {
	a, runtime, requester, document, _ := newAgentFixture(t)
	config := mapv(requester.assignment["runtime_config"])
	config["spec_digest"] = strings.Repeat("0", 64)
	_, e := a.Receive(context.Background(), document)
	expectParticipantCode(t, e, "participant_source_mismatch")
	if runtime.starts != 0 {
		t.Fatal("wrong source executed")
	}
	bad := clone(document)
	bad["command"] = "unsafe"
	_, e = a.Receive(context.Background(), bad)
	expectParticipantCode(t, e, "invalid_participant_dispatch")
}
func TestParticipantAgentNodeTokenRechecksIdentity(t *testing.T) {
	a, _, _, document, _ := newAgentFixture(t)
	if _, e := a.Receive(context.Background(), document); e != nil {
		t.Fatal(e)
	}
	id := executor.ExecutionIdentity{JobID: "job", AttemptID: "attempt", ComponentID: ComponentID("alice"), Epoch: 1}
	token, e := a.NodeToken(context.Background(), id)
	if e != nil || token == "" {
		t.Fatal(e)
	}
	other := id
	other.Epoch++
	_, e = a.NodeToken(context.Background(), other)
	expectParticipantCode(t, e, "external_node_grant_unavailable")
}
