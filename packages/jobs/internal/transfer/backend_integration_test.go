//go:build linux

package transfer

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type liveGatewayReady struct {
	BackendEndpoint          string `json:"backend_endpoint"`
	CAFile                   string `json:"ca_file"`
	ServerCertificate        string `json:"server_certificate"`
	ServerKey                string `json:"server_key"`
	BackendCertificate       string `json:"backend_certificate"`
	BackendKey               string `json:"backend_key"`
	BackendThumbprint        string `json:"backend_thumbprint"`
	ClientCertificate        string `json:"client_certificate"`
	ClientKey                string `json:"client_key"`
	ClientThumbprint         string `json:"client_thumbprint"`
	ForeignCertificate       string `json:"foreign_certificate"`
	ForeignKey               string `json:"foreign_key"`
	WorkloadIssuer           string `json:"workload_issuer"`
	WorkloadPublicKey        string `json:"workload_public_key"`
	GatewayAudience          string `json:"gateway_audience"`
	Token                    string `json:"token"`
	BackendSecret            string `json:"backend_secret"`
	ProvisionerAuthorization string `json:"provisioner_authorization"`
	SpaceID                  string `json:"space_id"`
	RecordID                 string `json:"record_id"`
	AttachmentID             string `json:"attachment_id"`
	DataFile                 string `json:"data_file"`
	Size                     int64  `json:"size"`
	SHA256                   string `json:"sha256"`
	PartSize                 int64  `json:"part_size"`
	S3Endpoint               string `json:"s3_endpoint"`
	S3Bucket                 string `json:"s3_bucket"`
	S3Prefix                 string `json:"s3_prefix"`
	S3Region                 string `json:"s3_region"`
}

type liveGatewayFixture struct {
	root string
	cmd  *exec.Cmd
	done chan struct{}
	err  error
	info liveGatewayReady
}

func liveGatewayJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temp := path + ".tmp"
	if err = os.WriteFile(temp, data, 0600); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

func startLiveGatewayFixture(t *testing.T) *liveGatewayFixture {
	t.Helper()
	python := os.Getenv("HF2L_GO_EXCHANGE_TEST_PYTHON")
	database := os.Getenv("HF2L_GO_EXCHANGE_TEST_DATABASE_CONFIG")
	storage := os.Getenv("HF2L_GO_EXCHANGE_TEST_STORAGE_CONFIG")
	if python == "" || database == "" || storage == "" {
		if os.Getenv("HF2L_GO_REQUIRE_EXCHANGE_INTEGRATION") == "1" {
			t.Fatal("real Exchange gate requires explicit Python, database and storage configuration")
		}
		t.Skip("set HF2L_GO_EXCHANGE_TEST_PYTHON, HF2L_GO_EXCHANGE_TEST_DATABASE_CONFIG and HF2L_GO_EXCHANGE_TEST_STORAGE_CONFIG for the real PostgreSQL/S3 gate")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "integration", "gateway_backend_fixture.py"))
	if err != nil {
		t.Fatal("locate portable Exchange fixture")
	}
	root := t.TempDir()
	if artifacts := os.Getenv("HF2L_GO_EXCHANGE_TEST_ARTIFACTS"); artifacts != "" {
		if err := os.MkdirAll(artifacts, 0700); err != nil {
			t.Fatal("create private integration evidence root")
		}
		info, err := os.Lstat(artifacts)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			t.Fatal("integration evidence root must be a private directory")
		}
		root, err = os.MkdirTemp(artifacts, "gateway-")
		if err != nil {
			t.Fatal("create owned integration evidence directory")
		}
	}
	diagnostic, err := os.OpenFile(filepath.Join(root, "fixture.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("create private fixture diagnostic")
	}
	fixture := &liveGatewayFixture{root: root, done: make(chan struct{})}
	fixture.cmd = exec.Command(python, script, "--runtime", root, "--database-config", database, "--storage-config", storage)
	fixture.cmd.Stdout, fixture.cmd.Stderr = diagnostic, diagnostic
	fixture.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err = fixture.cmd.Start(); err != nil {
		diagnostic.Close()
		t.Fatal("start real Exchange fixture; no credentials logged")
	}
	go func() {
		fixture.err = fixture.cmd.Wait()
		diagnostic.Close()
		close(fixture.done)
	}()
	t.Cleanup(func() {
		select {
		case <-fixture.done:
		default:
			_ = fixture.cmd.Process.Signal(syscall.SIGTERM)
		}
		select {
		case <-fixture.done:
		case <-time.After(15 * time.Second):
			_ = syscall.Kill(-fixture.cmd.Process.Pid, syscall.SIGKILL)
			<-fixture.done
			t.Error("fixture exceeded cleanup deadline")
		}
		raw, err := os.ReadFile(filepath.Join(root, "cleanup.json"))
		if err != nil {
			t.Error("fixture cleanup receipt unavailable")
			return
		}
		var cleanup struct {
			ServerStopped bool     `json:"server_stopped"`
			BucketRemoved bool     `json:"bucket_removed"`
			SchemaRemoved bool     `json:"schema_removed"`
			Errors        []string `json:"errors"`
		}
		if json.Unmarshal(raw, &cleanup) != nil || !cleanup.ServerStopped || !cleanup.BucketRemoved || !cleanup.SchemaRemoved || len(cleanup.Errors) != 0 {
			t.Error("owned Exchange/SQL/S3 fixture cleanup did not complete")
		}
	})
	deadline := time.Now().Add(60 * time.Second)
	for {
		if raw, err := os.ReadFile(filepath.Join(root, "ready.json")); err == nil {
			info, err := os.Stat(filepath.Join(root, "ready.json"))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("fixture ready file must be private")
			}
			if json.Unmarshal(raw, &fixture.info) != nil {
				t.Fatal("invalid private fixture ready document")
			}
			return fixture
		}
		select {
		case <-fixture.done:
			var failure struct {
				Error string `json:"error"`
			}
			data, _ := os.ReadFile(filepath.Join(root, "failure.json"))
			_ = json.Unmarshal(data, &failure)
			if identifierRE.MatchString(failure.Error) && len(failure.Error) <= 64 {
				t.Fatalf("fixture startup failed (%s); diagnostics remain private", failure.Error)
			}
			t.Fatal("fixture startup failed; diagnostics remain private")
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("real Exchange fixture startup timed out")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (f *liveGatewayFixture) command(t *testing.T, action string) map[string]json.RawMessage {
	t.Helper()
	var nonce [16]byte
	if _, err := crand.Read(nonce[:]); err != nil {
		t.Fatal("create fixture command identity")
	}
	name := hex.EncodeToString(nonce[:]) + ".json"
	if liveGatewayJSON(filepath.Join(f.root, "commands", name), map[string]string{"action": action}) != nil {
		t.Fatal("write private fixture command")
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if raw, err := os.ReadFile(filepath.Join(f.root, "replies", name)); err == nil {
			var reply struct {
				OK     bool                       `json:"ok"`
				Result map[string]json.RawMessage `json:"result"`
				Error  string                     `json:"error"`
			}
			if json.Unmarshal(raw, &reply) != nil || !reply.OK {
				t.Fatalf("owned fixture action %s failed; diagnostics remain private", action)
			}
			return reply.Result
		}
		select {
		case <-f.done:
			t.Fatal("owned fixture stopped during command")
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("owned fixture command timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func liveGatewayString(t *testing.T, values map[string]json.RawMessage, name string) string {
	t.Helper()
	var value string
	if json.Unmarshal(values[name], &value) != nil || value == "" {
		t.Fatalf("missing private fixture field %s", name)
	}
	return value
}

type liveGatewayPauseTransport struct {
	base   http.RoundTripper
	active atomic.Bool
	paused chan struct{}
	resume chan struct{}
	once   sync.Once
}

func (p *liveGatewayPauseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := p.base.RoundTrip(request)
	if err == nil && request.Method == http.MethodGet && p.active.CompareAndSwap(true, false) {
		response.Body = &liveGatewayPausedReader{ReadCloser: response.Body, pause: p}
	}
	return response, err
}

type liveGatewayPausedReader struct {
	io.ReadCloser
	pause *liveGatewayPauseTransport
	reads int
}

func (p *liveGatewayPausedReader) Read(data []byte) (int, error) {
	p.reads++
	if p.reads == 2 {
		p.pause.once.Do(func() { close(p.pause.paused) })
		<-p.pause.resume
	}
	return p.ReadCloser.Read(data)
}

func liveGatewayClient(t *testing.T, ready liveGatewayReady, cert, key string) *http.Client {
	t.Helper()
	trust, err := os.ReadFile(ready.CAFile)
	if err != nil {
		t.Fatal("read private fixture CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(trust) {
		t.Fatal("invalid fixture CA")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	if cert != "" {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			t.Fatal("read fixture client certificate")
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	transport.TLSClientConfig = cfg
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(transport.CloseIdleConnections)
	return client
}

func liveGatewayRequest(t *testing.T, client *http.Client, method, endpoint, token string, content io.Reader) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, endpoint, content)
	if err != nil {
		t.Fatal("create actual gateway request")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("actual gateway request failed (%T); no URL or credentials logged", err)
	}
	return response
}

// TestRealExchangeGateway executes actual Go HTTPS/mTLS handlers against the
// independent Python Exchange server, PostgreSQL and versioned S3. The only
// transport seam pauses a real origin response so mid-stream revocation has a
// deterministic observation point; provider responses and bytes are never faked.
func TestRealExchangeGateway(t *testing.T) {
	fixture := startLiveGatewayFixture(t)
	ready := fixture.info
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	backend, err := NewHTTPGatewayBackend(GatewayBackendSettings{Endpoint: ready.BackendEndpoint,
		BackendSecret: ready.BackendSecret, CAFile: ready.CAFile,
		ClientCertificate: ready.BackendCertificate, ClientKey: ready.BackendKey,
		Timeout: 15 * time.Second})
	if err != nil {
		t.Fatal("construct actual private Exchange backend")
	}
	t.Cleanup(backend.Close)
	attestation, err := backend.CheckStorage(ctx, ready.ProvisionerAuthorization, ready.BackendThumbprint)
	if err != nil || attestation["bucket"] != ready.S3Bucket || attestation["endpoint"] != ready.S3Endpoint ||
		attestation["prefix"] != ready.S3Prefix || attestation["region"] != ready.S3Region {
		t.Fatal("actual fixed versioned S3 backend qualification failed")
	}
	if _, err = backend.CheckStorage(ctx, "Bearer "+ready.Token, ready.BackendThumbprint); err == nil {
		t.Fatal("workload token unexpectedly qualified global storage")
	}
	verifier := WorkloadVerifier{Issuer: ready.WorkloadIssuer, Audience: ready.GatewayAudience,
		Scope: "transfer", PublicKey: ready.WorkloadPublicKey}
	if verifier.Validate() != nil {
		t.Fatal("construct real workload verifier")
	}
	id, err := verifier.Verify(ready.Token, ready.ClientThumbprint)
	if err != nil {
		t.Fatal("actual workload token and certificate do not match")
	}
	id.Token = ready.Token
	originTransport := http.DefaultTransport.(*http.Transport).Clone()
	originTransport.Proxy = nil
	originTransport.DisableCompression = true
	pause := &liveGatewayPauseTransport{base: originTransport, paused: make(chan struct{}), resume: make(chan struct{})}
	var resumeOnce sync.Once
	resume := func() { resumeOnce.Do(func() { close(pause.resume) }) }
	defer resume()
	originClient := &http.Client{Transport: pause, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(originTransport.CloseIdleConnections)
	handler, err := NewGateway(GatewaySettings{Verifier: verifier, OriginEndpoints: []string{ready.S3Endpoint},
		AllowLocalOriginHTTP: strings.HasPrefix(ready.S3Endpoint, "http://"), ChunkBytes: 65536,
		Client: originClient}, backend)
	if err != nil {
		t.Fatal("construct actual Go transfer gateway")
	}
	server, listener, err := NewMTLSServer(MTLSSettings{Address: "127.0.0.1:0",
		Certificate: ready.ServerCertificate, Key: ready.ServerKey, ClientCA: ready.CAFile}, handler)
	if err != nil {
		t.Fatal("start actual Go mTLS listener")
	}
	server.ErrorLog = log.New(io.Discard, "", 0)
	serverDone := make(chan struct{})
	go func() { _ = server.Serve(listener); close(serverDone) }()
	t.Cleanup(func() {
		stop, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = server.Shutdown(stop)
		_ = listener.Close()
		<-serverDone
	})
	gateway := "https://" + listener.Addr().String()
	client := liveGatewayClient(t, ready, ready.ClientCertificate, ready.ClientKey)
	content, err := os.ReadFile(ready.DataFile)
	if err != nil || int64(len(content)) != ready.Size {
		t.Fatal("read bounded owned fixture input")
	}
	attachmentPath := "/transfers/v1/spaces/" + ready.SpaceID + "/records/" + ready.RecordID + "/attachments/" + ready.AttachmentID
	for offset, number := int64(0), 1; offset < ready.Size; offset, number = offset+ready.PartSize, number+1 {
		end := offset + ready.PartSize
		if end > ready.Size {
			end = ready.Size
		}
		response := liveGatewayRequest(t, client, http.MethodPut, gateway+attachmentPath+"/parts/"+strconv.Itoa(number),
			ready.Token, bytes.NewReader(content[offset:end]))
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("actual Go multipart gateway returned status %d", response.StatusCode)
		}
	}
	state := fixture.command(t, "publish")
	var markers int
	if json.Unmarshal(state["mutations"], &markers) != nil || markers != 0 {
		t.Fatal("successful Go PUT did not settle its exact durable fences")
	}
	response := liveGatewayRequest(t, client, http.MethodGet, gateway+attachmentPath+"/content", ready.Token, nil)
	downloaded, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	digest := sha256.Sum256(downloaded)
	if response.StatusCode != 200 || readErr != nil || int64(len(downloaded)) != ready.Size ||
		hex.EncodeToString(digest[:]) != ready.SHA256 || response.Header.Get("X-Content-SHA256") != ready.SHA256 {
		t.Fatal("actual Go download size/hash disagrees with verified Exchange object")
	}
	if strings.Contains(response.Header.Get("Location"), ready.S3Bucket) {
		t.Fatal("origin location escaped the trusted gateway")
	}
	request, _ := http.NewRequest(http.MethodGet, gateway+attachmentPath+"/content", nil)
	request.Header.Set("Authorization", "Bearer "+ready.Token)
	request.Header.Set("Range", "bytes=100-199")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal("actual ranged download failed")
	}
	part, rangeErr := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 206 || rangeErr != nil || !bytes.Equal(part, content[100:200]) {
		t.Fatal("actual ranged download does not match stored bytes")
	}
	response = liveGatewayRequest(t, client, http.MethodHead, gateway+attachmentPath+"/content", ready.Token, nil)
	response.Body.Close()
	if response.StatusCode != 200 || response.ContentLength != ready.Size {
		t.Fatal("actual HEAD metadata disagrees with verified object")
	}
	foreign := strings.Replace(attachmentPath, ready.SpaceID, "foreign-space", 1)
	response = liveGatewayRequest(t, client, http.MethodGet, gateway+foreign+"/content", ready.Token, nil)
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatal("foreign model space was not concealed")
	}
	wrongClient := liveGatewayClient(t, ready, ready.ForeignCertificate, ready.ForeignKey)
	response = liveGatewayRequest(t, wrongClient, http.MethodGet, gateway+attachmentPath+"/content", ready.Token, nil)
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("copied workload token accepted a different verified certificate")
	}
	noCert := liveGatewayClient(t, ready, "", "")
	request, _ = http.NewRequest(http.MethodGet, gateway+attachmentPath+"/content", nil)
	request.Header.Set("Authorization", "Bearer "+ready.Token)
	if response, err = noCert.Do(request); err == nil {
		response.Body.Close()
		t.Fatal("actual mTLS gateway accepted a client without a certificate")
	}

	receiptData := fixture.command(t, "receipt_upload")
	shortToken := liveGatewayString(t, receiptData, "token")
	var expiry int64
	if json.Unmarshal(receiptData["expires_at"], &expiry) != nil {
		t.Fatal("short receipt token expiry missing")
	}
	shortID, err := verifier.Verify(shortToken, ready.ClientThumbprint)
	if err != nil {
		t.Fatal("short-lived receipt token invalid before admitted PUT")
	}
	shortID.Token = shortToken
	record, attachment := liveGatewayString(t, receiptData, "record_id"), liveGatewayString(t, receiptData, "attachment_id")
	receipt, grant, err := backend.BeginUpload(ctx, shortID, ready.SpaceID, record, attachment, 1)
	if err != nil || grant.Size != 3 || receipt == "" {
		t.Fatal("actual private backend failed to persist origin PUT receipt")
	}
	put, _ := http.NewRequestWithContext(ctx, http.MethodPut, grant.URL, bytes.NewReader([]byte("abc")))
	for key, value := range grant.Headers {
		put.Header.Set(key, value)
	}
	put.ContentLength = 3
	originResponse, err := originClient.Do(put)
	if err != nil {
		t.Fatal("actual admitted S3 PUT failed; signed URL is not logged")
	}
	putStatus := originResponse.StatusCode
	_, drainErr := io.Copy(io.Discard, originResponse.Body)
	closeErr := originResponse.Body.Close()
	if putStatus != 200 || drainErr != nil || closeErr != nil {
		t.Fatal("actual S3 PUT did not produce a known successful closed acknowledgement")
	}
	pause.active.Store(true)
	type streamResult struct {
		bytes  int
		err    error
		status int
	}
	streamDone := make(chan streamResult, 1)
	go func() {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, gateway+attachmentPath+"/content", nil)
		req.Header.Set("Authorization", "Bearer "+ready.Token)
		result, e := client.Do(req)
		if e != nil {
			streamDone <- streamResult{err: e}
			return
		}
		data, e := io.ReadAll(result.Body)
		result.Body.Close()
		streamDone <- streamResult{bytes: len(data), err: e, status: result.StatusCode}
	}()
	select {
	case <-pause.paused:
	case <-time.After(10 * time.Second):
		t.Fatal("real origin response did not reach the revocation observation point")
	}
	if wait := time.Until(time.Unix(expiry, 0).Add(100 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	fixture.command(t, "revoke")
	resume()
	select {
	case result := <-streamDone:
		if result.status != 200 || result.err == nil || result.bytes == 0 || int64(result.bytes) >= ready.Size {
			t.Fatal("actual revoked in-flight stream was not interrupted")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("revoked actual stream did not finish")
	}
	if err = backend.Authorize(ctx, id); err == nil {
		t.Fatal("revoked persisted grant still authorized another operation")
	}
	if _, err = verifier.Verify(shortToken, ready.ClientThumbprint); err == nil {
		t.Fatal("settlement proof token was not expired")
	}
	settled, err := backend.FinishUpload(ctx, shortID, receipt)
	if err != nil || !settled {
		t.Fatal("known successful old PUT could not settle after expiry and revocation")
	}
	if settled, err = backend.FinishUpload(ctx, shortID, receipt); err != nil || settled {
		t.Fatal("old receipt replay did not retain exact-ledger semantics")
	}
	snapshot := fixture.command(t, "inspect")
	var reclaiming int64
	if json.Unmarshal(snapshot["mutations"], &markers) != nil || markers != 0 ||
		json.Unmarshal(snapshot["reclaiming"], &reclaiming) != nil || reclaiming != 3 {
		t.Fatal("late settlement released physical storage charge or left an owned mutation")
	}
	t.Log("real Go mTLS gateway, PostgreSQL, versioned S3, multipart/download/range hashes, revocation, exact settlement and operator storage probe passed")
}
