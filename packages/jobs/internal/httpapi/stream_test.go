package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/artifacts"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

type webFrame struct{ event, id, data, raw string }

func webReadFrame(t *testing.T, reader *bufio.Reader) webFrame {
	t.Helper()
	f := webFrame{}
	for {
		line, e := reader.ReadString('\n')
		if e != nil {
			t.Fatalf("event stream ended before frame: %v; %s", e, f.raw)
		}
		f.raw += line
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return f
		}
		if strings.HasPrefix(line, "event:") {
			f.event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		}
		if strings.HasPrefix(line, "id:") {
			f.id = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
		}
		if strings.HasPrefix(line, "data:") {
			f.data += strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		}
	}
}
func webReadEvent(t *testing.T, reader *bufio.Reader) webFrame {
	t.Helper()
	for {
		f := webReadFrame(t, reader)
		if f.event != "" {
			return f
		}
	}
}
func (f *webFixture) openEvents(c webCredential, cursor string) (*http.Response, context.CancelFunc, *bufio.Reader) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	req, e := http.NewRequestWithContext(ctx, "GET", f.http.URL+Prefix+"/events/stream", nil)
	if e != nil {
		f.t.Fatal(e)
	}
	req.AddCookie(c.cookie)
	if cursor != "" {
		req.Header.Set("Last-Event-ID", cursor)
	}
	response, e := f.client.Do(req)
	if e != nil {
		cancel()
		f.t.Fatal(e)
	}
	if response.StatusCode != 200 {
		cancel()
		webJSON(f.t, response, 200)
	}
	return response, cancel, bufio.NewReader(response.Body)
}
func TestWebEventStreamCursorIsSignedPrincipalBoundAndExpires(t *testing.T) {
	var stamp atomic.Int64
	stamp.Store(time.Now().Unix())
	f := newWebFixture(t, func(o *Options) { o.Clock = func() time.Time { return time.Unix(stamp.Load(), 0) } }, nil)
	alice := f.login("alice")
	bob := f.login("bob")
	response, cancel, reader := f.openEvents(alice, "")
	first := webReadEvent(t, reader)
	if first.event != "invalidated" || first.id == "" {
		t.Fatal(first)
	}
	var data map[string]any
	if e := json.Unmarshal([]byte(first.data), &data); e != nil || len(data) != 1 || data["refetch"] != true {
		t.Fatal("stream exposed content instead of invalidation", first, e)
	}
	response.Body.Close()
	cancel()
	webError(t, f.request("GET", Prefix+"/events/stream", nil, &bob, map[string]string{"Last-Event-ID": first.id}), 400, "invalid_event_cursor")
	tampered := first.id[:len(first.id)-1] + "g"
	webError(t, f.request("GET", Prefix+"/events/stream", nil, &alice, map[string]string{"Last-Event-ID": tampered}), 400, "invalid_event_cursor")
	stamp.Add(3601)
	response, cancel, reader = f.openEvents(alice, first.id)
	defer cancel()
	defer response.Body.Close()
	reset := webReadEvent(t, reader)
	if reset.event != "reset" || reset.id == first.id {
		t.Fatal(reset)
	}
}
func TestWebEventStreamStopsAfterActualSessionRevocation(t *testing.T) {
	f := newWebFixture(t, nil, nil)
	alice := f.login("alice")
	response, cancel, reader := f.openEvents(alice, "")
	defer cancel()
	defer response.Body.Close()
	webReadEvent(t, reader)
	n, e := f.auth.RevokeSubject(context.Background(), webIssuer, "alice")
	if e != nil || n != 1 {
		t.Fatal(n, e)
	}
	expired := webReadEvent(t, reader)
	if expired.event != "session_expired" {
		t.Fatal(expired)
	}
	rest, e := io.ReadAll(reader)
	if e != nil || len(rest) != 0 {
		t.Fatal("revoked stream remained active", string(rest), e)
	}
}
func TestWebEventStreamInvalidatesWhenCurrentJobACLChanges(t *testing.T) {
	f := newWebFixture(t, nil, nil)
	alice := f.login("alice")
	bob := f.login("bob")
	job := f.create(alice, "Shared temporarily", "shared")
	id := job["id"].(string)
	shared := webJSON(t, f.request("PUT", Prefix+"/jobs/"+id+"/members/"+webID("bob"), map[string]any{"role": "reader"}, &alice, f.mutation(alice, "share", 1)), 200)
	response, cancel, reader := f.openEvents(bob, "")
	defer cancel()
	defer response.Body.Close()
	initial := webReadEvent(t, reader)
	webJSON(t, f.request("DELETE", Prefix+"/jobs/"+id+"/members/"+webID("bob"), nil, &alice, f.mutation(alice, "revoke", webVersion(shared))), 200)
	changed := webReadEvent(t, reader)
	if changed.event != "invalidated" || changed.id == initial.id || strings.Contains(changed.data, id) {
		t.Fatal("ACL invalidation leaked content or did not advance", changed)
	}
	webError(t, f.request("GET", Prefix+"/jobs/"+id, nil, &bob, nil), 404, "job_not_found")
}

type webBroker struct {
	open  func(context.Context, string, string, string) (*artifacts.Download, error)
	calls atomic.Int64
}

func (b *webBroker) OpenAuthorized(ctx context.Context, actor, job, artifact string) (*artifacts.Download, error) {
	b.calls.Add(1)
	return b.open(ctx, actor, job, artifact)
}

type webControlledReader struct {
	data          []byte
	offset, chunk int
	afterFirst    func()
	onFinal       func()
	finalCalled   bool
	called        bool
	finalError    error
	finalChecks   atomic.Int64
	closed        atomic.Bool
}

func (r *webControlledReader) Read(out []byte) (int, error) {
	if r.offset >= len(r.data) {
		r.finalChecks.Add(1)
		if !r.finalCalled && r.onFinal != nil {
			r.finalCalled = true
			r.onFinal()
		}
		if r.finalError != nil {
			return 0, r.finalError
		}
		return 0, io.EOF
	}
	if r.offset > 0 && !r.called && r.afterFirst != nil {
		r.called = true
		r.afterFirst()
	}
	n := len(out)
	if n > r.chunk {
		n = r.chunk
	}
	if n > len(r.data)-r.offset {
		n = len(r.data) - r.offset
	}
	copy(out, r.data[r.offset:r.offset+n])
	r.offset += n
	return n, nil
}
func (r *webControlledReader) Close() error { r.closed.Store(true); return nil }
func (f *webFixture) artifact(jobID string, payload []byte) string {
	f.t.Helper()
	resource, id := domain.NewID(), domain.NewID()
	f.insert("jm_provisioning_resources", map[string]any{"id": resource, "job_id": jobID, "component_id": "owner", "kind": "execution_state", "external_id": "retained-" + resource, "ownership_json": map[string]any{"job_id": jobID}, "state": "ready", "retained": true})
	digest := sha256.Sum256(payload)
	f.insert("jm_artifacts", map[string]any{"id": id, "job_id": jobID, "kind": "checkpoint", "name": "model.safetensors", "size_bytes": int64(len(payload)), "sha256": hex.EncodeToString(digest[:]), "storage_key": "opaque-artifact-" + id, "state": "available", "locator_json": map[string]any{"kind": "local", "resource_id": resource, "relative_path": "model.safetensors"}})
	return id
}
func webDownloadPath(job, artifact string) string {
	return Prefix + "/jobs/" + job + "/artifacts/" + artifact + "/download"
}
func webSharedArtifact(t *testing.T, f *webFixture, payload []byte) (webCredential, webCredential, string, string, int64) {
	t.Helper()
	alice := f.login("alice")
	bob := f.login("bob")
	job := f.create(alice, "Artifact sharing", "artifact-create")
	id := job["id"].(string)
	shared := webJSON(t, f.request("PUT", Prefix+"/jobs/"+id+"/members/"+webID("bob"), map[string]any{"role": "reader"}, &alice, f.mutation(alice, "artifact-grant", 1)), 200)
	return alice, bob, id, f.artifact(id, payload), webVersion(shared)
}
func TestWebArtifactDownloadChecksMetadataAndNeverExposesStorageCredentials(t *testing.T) {
	b := &webBroker{}
	f := newWebFixture(t, func(o *Options) { o.ArtifactBroker = b }, nil)
	alice := f.login("alice")
	bob := f.login("bob")
	payload := bytes.Repeat([]byte("checkpoint-bytes"), 9000)
	job := f.create(alice, "Artifact job", "artifact-job")
	id := job["id"].(string)
	artifact := f.artifact(id, payload)
	controlled := &webControlledReader{data: payload, chunk: 16384}
	b.open = func(ctx context.Context, actor, job, artifact string) (*artifacts.Download, error) {
		if _, e := f.manager.ArtifactStorage(ctx, actor, job, artifact); e != nil {
			return nil, e
		}
		return &artifacts.Download{Name: "model.safetensors", Size: int64(len(payload)), Reader: controlled}, nil
	}
	webError(t, f.request("GET", webDownloadPath(id, artifact), nil, &bob, nil), 404, "job_not_found")
	if b.calls.Load() != 0 {
		t.Fatal("foreign read reached storage broker")
	}
	response := f.request("GET", webDownloadPath(id, artifact), nil, &alice, nil)
	body, e := io.ReadAll(response.Body)
	response.Body.Close()
	if e != nil || response.StatusCode != 200 || !bytes.Equal(body, payload) {
		t.Fatal("download", response.StatusCode, len(body), e)
	}
	if !controlled.closed.Load() || controlled.finalChecks.Load() == 0 {
		t.Fatal("reader not closed or final verification not forced")
	}
	if response.Header.Get("Content-Type") != "application/octet-stream" || !strings.Contains(response.Header.Get("Content-Disposition"), "model.safetensors") {
		t.Fatal(response.Header)
	}
	for _, key := range []string{"Location", "Authorization", "X-Storage-URL", "X-Access-Token"} {
		if response.Header.Get(key) != "" {
			t.Fatalf("storage credentials exposed through %s", key)
		}
	}
}
func TestWebArtifactDownloadStopsBeforeSendingNextChunkAfterACLRevocation(t *testing.T) {
	b := &webBroker{}
	f := newWebFixture(t, func(o *Options) { o.ArtifactBroker = b }, nil)
	payload := bytes.Repeat([]byte("private-checkpoint"), 9000)
	alice, bob, job, artifact, version := webSharedArtifact(t, f, payload)
	controlled := &webControlledReader{data: payload, chunk: 16384}
	controlled.afterFirst = func() {
		if _, e := f.manager.DeleteMember(context.Background(), webID("alice"), job, webID("bob"), version, "stream-revoke"); e != nil {
			t.Error(e)
		}
	}
	b.open = func(ctx context.Context, actor, job, artifact string) (*artifacts.Download, error) {
		if _, e := f.manager.ArtifactStorage(ctx, actor, job, artifact); e != nil {
			return nil, e
		}
		return &artifacts.Download{Name: "model.safetensors", Size: int64(len(payload)), Reader: controlled}, nil
	}
	response := f.request("GET", webDownloadPath(job, artifact), nil, &bob, nil)
	body, e := io.ReadAll(response.Body)
	response.Body.Close()
	if e == nil || len(body) != controlled.chunk || len(body) >= len(payload) {
		t.Fatalf("revoked download completed: got %d of %d, read error=%v", len(body), len(payload), e)
	}
	if !controlled.closed.Load() {
		t.Fatal("revoked reader not closed")
	}
	webError(t, f.request("GET", webDownloadPath(job, artifact), nil, &bob, nil), 404, "job_not_found")
	_ = alice
}
func TestWebArtifactDownloadStopsAfterSessionRevocation(t *testing.T) {
	b := &webBroker{}
	f := newWebFixture(t, func(o *Options) { o.ArtifactBroker = b }, nil)
	payload := bytes.Repeat([]byte("checkpoint"), 12000)
	_, bob, job, artifact, _ := webSharedArtifact(t, f, payload)
	controlled := &webControlledReader{data: payload, chunk: 16384}
	controlled.afterFirst = func() {
		if _, e := f.auth.RevokeSubject(context.Background(), webIssuer, "bob"); e != nil {
			t.Error(e)
		}
	}
	b.open = func(ctx context.Context, actor, job, artifact string) (*artifacts.Download, error) {
		if _, e := f.manager.ArtifactStorage(ctx, actor, job, artifact); e != nil {
			return nil, e
		}
		return &artifacts.Download{Name: "checkpoint", Size: int64(len(payload)), Reader: controlled}, nil
	}
	response := f.request("GET", webDownloadPath(job, artifact), nil, &bob, nil)
	body, e := io.ReadAll(response.Body)
	response.Body.Close()
	if e == nil || len(body) >= len(payload) {
		t.Fatal("revoked identity received complete artifact", len(body), e)
	}
	if !controlled.closed.Load() {
		t.Fatal("reader remained open after identity revocation")
	}
}
func TestWebArtifactFinalIntegrityFailureCannotProduceCompleteHTTPBody(t *testing.T) {
	b := &webBroker{}
	f := newWebFixture(t, func(o *Options) { o.ArtifactBroker = b }, nil)
	alice := f.login("alice")
	payload := []byte("unverified final chunk")
	job := f.create(alice, "Integrity check", "integrity-job")
	id := job["id"].(string)
	artifact := f.artifact(id, payload)
	controlled := &webControlledReader{data: payload, chunk: 65536, finalError: errors.New("checkpoint digest mismatch")}
	b.open = func(ctx context.Context, actor, job, artifact string) (*artifacts.Download, error) {
		if _, e := f.manager.ArtifactStorage(ctx, actor, job, artifact); e != nil {
			return nil, e
		}
		return &artifacts.Download{Name: "checkpoint", Size: int64(len(payload)), Reader: controlled}, nil
	}
	response := f.request("GET", webDownloadPath(id, artifact), nil, &alice, nil)
	body, e := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode == 200 && e == nil && len(body) == len(payload) {
		t.Fatal("final verification error was swallowed after complete Content-Length delivery")
	}
	if !controlled.closed.Load() || controlled.finalChecks.Load() == 0 {
		t.Fatal("final integrity validation not attempted/closed")
	}
}

func TestWebArtifactUnavailableBrokerFailsClosed(t *testing.T) {
	f := newWebFixture(t, nil, nil)
	alice := f.login("alice")
	payload := []byte("checkpoint")
	job := f.create(alice, "Metadata only", "no-broker")
	id := job["id"].(string)
	artifact := f.artifact(id, payload)
	metadata := webJSON(t, f.request("GET", Prefix+"/jobs/"+id+"/artifacts/"+artifact, nil, &alice, nil), 200)
	if metadata["download_available"] != false || metadata["unavailable_reason"] != "artifact_broker_unavailable" {
		t.Fatal(metadata)
	}
	webError(t, f.request("GET", webDownloadPath(id, artifact), nil, &alice, nil), 503, "artifact_broker_unavailable")
}

// The HTTP streaming tests use actual SQL memberships/sessions. A controlled
// storage reader only schedules the independent revocation and integrity events.
var _ http.Handler = (*Server)(nil)

func TestWebArtifactCannotHideSurplusBytesAfterDeclaredLength(t *testing.T) {
	b := &webBroker{}
	f := newWebFixture(t, func(o *Options) { o.ArtifactBroker = b }, nil)
	alice := f.login("alice")
	declared := []byte("declared bytes")
	job := f.create(alice, "Surplus check", "surplus")
	id := job["id"].(string)
	artifact := f.artifact(id, declared)
	controlled := &webControlledReader{data: append(append([]byte(nil), declared...), []byte("unexpected tail")...), chunk: 65536}
	b.open = func(ctx context.Context, actor, job, artifact string) (*artifacts.Download, error) {
		if _, e := f.manager.ArtifactStorage(ctx, actor, job, artifact); e != nil {
			return nil, e
		}
		return &artifacts.Download{Name: "checkpoint", Size: int64(len(declared)), Reader: controlled}, nil
	}
	response := f.request("GET", webDownloadPath(id, artifact), nil, &alice, nil)
	body, e := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode == 200 && e == nil && len(body) == len(declared) {
		t.Fatal("surplus bytes were silently discarded after complete successful response")
	}
	if !controlled.closed.Load() {
		t.Fatal("surplus reader not closed")
	}
}
func TestWebArtifactRechecksSessionAfterFinalReaderVerification(t *testing.T) {
	b := &webBroker{}
	f := newWebFixture(t, func(o *Options) { o.ArtifactBroker = b }, nil)
	alice := f.login("alice")
	payload := []byte("withhold until final verification")
	job := f.create(alice, "Final authorization", "final-auth")
	id := job["id"].(string)
	artifact := f.artifact(id, payload)
	controlled := &webControlledReader{data: payload, chunk: 65536}
	controlled.onFinal = func() {
		if _, e := f.auth.RevokeSubject(context.Background(), webIssuer, "alice"); e != nil {
			t.Error(e)
		}
	}
	b.open = func(ctx context.Context, actor, job, artifact string) (*artifacts.Download, error) {
		if _, e := f.manager.ArtifactStorage(ctx, actor, job, artifact); e != nil {
			return nil, e
		}
		return &artifacts.Download{Name: "checkpoint", Size: int64(len(payload)), Reader: controlled}, nil
	}
	response := f.request("GET", webDownloadPath(id, artifact), nil, &alice, nil)
	body, e := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode == 200 && e == nil && len(body) == len(payload) {
		t.Fatal("final reader verification revoked session but final bytes still completed")
	}
	if controlled.finalChecks.Load() == 0 {
		t.Fatal("final reader verification skipped")
	}
}
func TestWebArtifactTruncationAndInvalidDescriptorsFailClosed(t *testing.T) {
	for _, kind := range []string{"truncated", "nil-reader", "negative-size"} {
		t.Run(kind, func(t *testing.T) {
			b := &webBroker{}
			f := newWebFixture(t, func(o *Options) { o.ArtifactBroker = b }, nil)
			alice := f.login("alice")
			payload := bytes.Repeat([]byte("checkpoint"), 30)
			job := f.create(alice, "Bounded output", "bounded")
			id := job["id"].(string)
			artifact := f.artifact(id, payload)
			controlled := &webControlledReader{data: payload[:20], chunk: 16}
			b.open = func(ctx context.Context, actor, job, artifact string) (*artifacts.Download, error) {
				if _, e := f.manager.ArtifactStorage(ctx, actor, job, artifact); e != nil {
					return nil, e
				}
				d := &artifacts.Download{Name: "checkpoint", Size: int64(len(payload)), Reader: controlled}
				if kind == "nil-reader" {
					d.Reader = nil
				}
				if kind == "negative-size" {
					d.Size = -1
				}
				return d, nil
			}
			response := f.request("GET", webDownloadPath(id, artifact), nil, &alice, nil)
			body, e := io.ReadAll(response.Body)
			response.Body.Close()
			if kind == "truncated" {
				if e == nil || len(body) >= len(payload) {
					t.Fatal("truncated bytes declared complete", len(body), e)
				}
			} else if response.StatusCode != 502 {
				t.Fatalf("invalid descriptor returned %d: %s", response.StatusCode, body)
			}
		})
	}
}
