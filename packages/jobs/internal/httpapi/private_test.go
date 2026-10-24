package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
)

func privateClient(t *testing.T, f *webFixture, certificate tls.Certificate) *http.Client {
	t.Helper()
	transport := f.client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}
}
func privateRequest(t *testing.T, f *webFixture, client *http.Client, path string, body []byte) *http.Response {
	t.Helper()
	request, err := http.NewRequest("POST", f.http.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer node-token")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
func TestPrivateProgressLogBoundsAndStaleEpochDoNotInvokeController(t *testing.T) {
	certificate, pool := newWebClientCertificate(t)
	digest := sha256.Sum256(certificate.Certificate[0])
	thumb := base64.RawURLEncoding.EncodeToString(digest[:])
	var mode, effects atomic.Int64
	f := newWebFixture(t, func(opts *Options) {
		opts.NodeAuthenticate = func(_ context.Context, bearer, peer string) (ExecutionActor, error) {
			if bearer != "Bearer node-token" || peer != thumb {
				return ExecutionActor{}, domain.Err(401, "invalid_node_grant")
			}
			actor := ExecutionActor{NodeID: "node", PoolID: "cpu", JobID: "job", AttemptID: "attempt", ComponentID: "owner", Epoch: 1, CertificateThumbprint: peer, Scopes: []string{"progress", "logs"}}
			if mode.Load() == 1 {
				actor.Epoch = 2
			}
			if mode.Load() == 2 {
				actor.Scopes = []string{"heartbeat"}
			}
			return actor, nil
		}
		opts.CheckAssignment = func(_ context.Context, node, pool string, id executor.ExecutionIdentity) (bool, error) {
			return mode.Load() != 3 && node == "node" && pool == "cpu" && id.JobID == "job", nil
		}
		opts.NodeCommand = func(_ context.Context, action string, id executor.ExecutionIdentity, body map[string]any) (bool, error) {
			effects.Add(1)
			if action == "progress" {
				if _, ok := body["current_round"].(json.Number); !ok {
					t.Error("round lost JSON integer type")
				}
			}
			return mode.Load() != 4, nil
		}
	}, &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool})
	client := privateClient(t, f, certificate)
	progress := "/internal/jobs/v1/assignments/job/attempt/owner/1/progress"
	good := []byte("{\"current_round\":2,\"phase\":\"training\",\"metrics\":{\"loss\":1.25}}")
	for _, tc := range []struct {
		mode   int64
		status int
		code   string
	}{
		{1, 404, "assignment_not_found"}, {2, 403, "node_scope_required"}, {3, 404, "assignment_not_found"},
	} {
		mode.Store(tc.mode)
		webError(t, privateRequest(t, f, client, progress, good), tc.status, tc.code)
		if effects.Load() != 0 {
			t.Fatal("denied callback produced effects")
		}
	}
	mode.Store(0)
	for _, body := range []string{"{}", "{\"current_round\":true}", "{\"current_round\":-1}", "{\"current_round\":1000001}", "{\"phase\":\"stopped\"}", "{\"metrics\":{\"loss\":true}}", "{\"metrics\":{\"loss\":1e309}}", "{\"current_round\":2,\"unexpected\":1}"} {
		webError(t, privateRequest(t, f, client, progress, []byte(body)), 422, "invalid_request")
	}
	if effects.Load() != 0 {
		t.Fatal("invalid reports invoked controller")
	}
	webJSON(t, privateRequest(t, f, client, progress, good), 200)
	if effects.Load() != 1 {
		t.Fatal("valid report did not invoke controller exactly once")
	}
	mode.Store(4)
	webError(t, privateRequest(t, f, client, progress, good), 409, "stale_assignment")
	if effects.Load() != 2 {
		t.Fatal("stale callback count", effects.Load())
	}
	mode.Store(0)
	logs := "/internal/jobs/v1/assignments/job/attempt/owner/1/logs"
	oversize, _ := json.Marshal(map[string]any{"entries": []string{strings.Repeat("é", 4097)}})
	webError(t, privateRequest(t, f, client, logs, oversize), 413, "log_line_too_large")
	entries := make([]string, 100)
	for i := range entries {
		entries[i] = strings.Repeat("x", 700)
	}
	batch, _ := json.Marshal(map[string]any{"entries": entries})
	webError(t, privateRequest(t, f, client, logs, batch), 413, "log_batch_too_large")
	if effects.Load() != 2 {
		t.Fatal("oversize logs invoked controller")
	}
	webJSON(t, privateRequest(t, f, client, logs, []byte("{\"entries\":[\"round complete\"]}")), 200)
	if effects.Load() != 3 {
		t.Fatal("valid logs missing")
	}
}

type privateRevokingReader struct {
	reads   int
	revoked *atomic.Bool
	closed  *atomic.Bool
}

func (r *privateRevokingReader) Read(p []byte) (int, error) {
	r.reads++
	switch r.reads {
	case 1:
		return copy(p, []byte("hello")), nil
	case 2:
		r.revoked.Store(true)
		return copy(p, []byte("world")), nil
	}
	return 0, io.EOF
}
func (r *privateRevokingReader) Close() error { r.closed.Store(true); return nil }
func TestParticipantSourceStreamReauthenticatesBeforeEachChunk(t *testing.T) {
	certificate, pool := newWebClientCertificate(t)
	digest := sha256.Sum256(certificate.Certificate[0])
	thumb := base64.RawURLEncoding.EncodeToString(digest[:])
	var revoked, closed atomic.Bool
	var opened, accessChecks atomic.Int64
	f := newWebFixture(t, func(opts *Options) {
		opts.NodeAuthenticate = func(_ context.Context, bearer, peer string) (ExecutionActor, error) {
			if bearer != "Bearer node-token" || peer != thumb || revoked.Load() {
				return ExecutionActor{}, domain.Err(401, "invalid_node_grant")
			}
			return ExecutionActor{ID: "workload", JobID: "job", AttemptID: "attempt", ComponentID: "client", Epoch: 1, CertificateThumbprint: peer, Scopes: []string{"assignment"}}, nil
		}
		opts.ParticipantCall = func(context.Context, string, ExecutionActor, executor.ExecutionIdentity, map[string]any) (map[string]any, error) {
			t.Error("source must use bounded file port")
			return nil, domain.Err(500, "unexpected_call")
		}
		opts.ParticipantOpen = func(_ context.Context, action string, actor ExecutionActor, path string) (*StreamFile, error) {
			opened.Add(1)
			if action != "source" || path != "trainer.py" {
				t.Error(action, path)
			}
			contentHash := sha256.Sum256([]byte("helloworld"))
			return &StreamFile{Reader: &privateRevokingReader{revoked: &revoked, closed: &closed}, SizeBytes: 10, SHA256: hex.EncodeToString(contentHash[:])}, nil
		}
		opts.ParticipantAccessValid = func(_ context.Context, action string, actor ExecutionActor) (bool, error) {
			accessChecks.Add(1)
			return !revoked.Load(), nil
		}
	}, &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool})
	client := privateClient(t, f, certificate)
	request, _ := http.NewRequest("GET", f.http.URL+"/internal/jobs/v1/participants/job/attempt/client/1/source/trainer.py", nil)
	request.Header.Set("Authorization", "Bearer node-token")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	content, readError := io.ReadAll(response.Body)
	response.Body.Close()
	if string(content) != "hello" || readError == nil || response.StatusCode != 200 {
		t.Fatalf("revocation must interrupt long download: %q %v HTTP%d", content, readError, response.StatusCode)
	}
	if opened.Load() != 1 || accessChecks.Load() != 1 || !closed.Load() {
		t.Fatal("source resource/authorization lifecycle", opened.Load(), accessChecks.Load(), closed.Load())
	}
	if response.Header.Get("Content-Length") != "10" || response.Header.Get("X-Content-SHA256") == "" {
		t.Fatal("missing pinned source metadata")
	}
}

func TestManagedBootstrapRequiresCertificateAndRejectsBearerOrCookie(t *testing.T) {
	certificate, pool := newWebClientCertificate(t)
	var calls atomic.Int64
	f := newWebFixture(t, func(opts *Options) {
		opts.ManagedBootstrap = func(_ context.Context, peer string, id executor.ExecutionIdentity) (map[string]any, error) {
			calls.Add(1)
			if peer == "" || id.Epoch != 1 {
				t.Error(peer, id)
			}
			return map[string]any{"registered": true}, nil
		}
	}, &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool})
	path := "/internal/jobs/v1/nodes/job/attempt/owner/1/bootstrap"
	webError(t, f.request("POST", path, map[string]any{}, nil, map[string]string{"X-Verified-Peer-Thumbprint": strings.Repeat("a", 43)}), 401, "verified_node_certificate_required")
	client := privateClient(t, f, certificate)
	webError(t, privateRequest(t, f, client, path, []byte("{}")), 401, "registered_node_certificate_required")
	request, _ := http.NewRequest("POST", f.http.URL+path, strings.NewReader("{}"))
	request.AddCookie(&http.Cookie{Name: "__Host-hf2l_jobs", Value: "human-session"})
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	webError(t, response, 401, "registered_node_certificate_required")
	request, _ = http.NewRequest("POST", f.http.URL+path, strings.NewReader("{}"))
	request.Header.Set("Content-Type", "application/json")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	webJSON(t, response, 200)
	if calls.Load() != 1 {
		t.Fatal("invalid bootstrap reached service", calls.Load())
	}
}
