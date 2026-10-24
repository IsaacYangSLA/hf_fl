package transfer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGatewayForwardsSignedPayloadSHA256FromTypedBackend(t *testing.T) {
	f := newTransferFixture(t)
	for _, tc := range []struct {
		name, body, digest string
	}{
		{"empty", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"nonempty", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := strings.Repeat("b", 32)
			token := f.gatewayToken(t)
			var began atomic.Bool
			var puts, settled atomic.Int64
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				puts.Add(1)
				data, err := io.ReadAll(r.Body)
				if err != nil || string(data) != tc.body || r.Method != "PUT" ||
					r.ContentLength != int64(len(tc.body)) || len(r.TransferEncoding) != 0 ||
					r.Header.Get("X-Amz-Content-Sha256") != tc.digest || !began.Load() {
					t.Error("signed origin PUT lost its payload hash, exact framing, or durable fence", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("workload credentials reached storage")
				}
				w.Header().Set("ETag", "signed-part")
				w.WriteHeader(http.StatusNoContent)
			}))
			defer origin.Close()
			grant := OriginGrant{
				URL:       origin.URL + "/bucket/part?X-Amz-Signature=private",
				Headers:   map[string]string{"x-amz-content-sha256": tc.digest},
				ExpiresAt: float64(time.Now().Add(time.Minute).Unix()),
				Size:      int64(len(tc.body)), Number: 1,
			}
			private := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				thumb, err := VerifiedBackendThumbprint(secret, r.Method, requestTarget(r), r.Header.Get("Authorization"), r.Header, time.Now())
				if err != nil || thumb != f.binding.CertificateThumbprint ||
					r.Header.Get("Authorization") != "Bearer "+token || r.Method != "POST" {
					t.Error("typed backend lost original workload assertion", err)
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/internal/transfers/v1/spaces/space-a/authorize":
					_ = json.NewEncoder(w).Encode(map[string]any{"effective_roles": []string{"owner"}})
				case "/internal/transfers/v1/spaces/space-a/records/r/attachments/a/parts/1/grant":
					_ = json.NewEncoder(w).Encode(grant)
				case "/internal/transfers/v1/spaces/space-a/records/r/attachments/a/parts/1/begin":
					began.Store(true)
					_ = json.NewEncoder(w).Encode(map[string]any{"receipt": "sealed-part", "grant": grant})
				case "/internal/transfers/v1/settle":
					var body struct {
						Receipt string `json:"receipt"`
					}
					if json.NewDecoder(r.Body).Decode(&body) != nil || body.Receipt != "sealed-part" || puts.Load() != 1 {
						t.Error("typed backend settled without acknowledged origin PUT")
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					settled.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]any{"settled": true})
				default:
					t.Error("unexpected private operation", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer private.Close()
			backend, err := NewHTTPGatewayBackend(GatewayBackendSettings{
				Endpoint: private.URL, BackendSecret: secret, Client: private.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer backend.Close()
			handler, err := NewGateway(GatewaySettings{
				Verifier:        WorkloadVerifier{Issuer: "https://workloads.example", PublicKey: f.public},
				OriginEndpoints: []string{origin.URL}, Client: origin.Client(),
			}, backend)
			if err != nil {
				t.Fatal(err)
			}
			defer handler.(*Gateway).Close()
			server, listener, err := NewMTLSServer(MTLSSettings{
				Address: "127.0.0.1:0", Certificate: f.serverCert, Key: f.serverKey, ClientCA: f.caFile,
			}, handler)
			if err != nil {
				t.Fatal(err)
			}
			go server.Serve(listener)
			defer server.Close()
			client, err := newClient(f.caFile, f.clientCert, f.clientKey, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			req, err := http.NewRequest("PUT", "https://"+listener.Addr().String()+"/transfers/v1/spaces/space-a/records/r/attachments/a/parts/1", bytes.NewBufferString(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Length", strconv.Itoa(len(tc.body)))
			// An untrusted caller's header must never replace the signed backend grant.
			req.Header.Set("X-Amz-Content-Sha256", strings.Repeat("0", 64))
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			data, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != http.StatusNoContent || len(data) != 0 ||
				resp.Header.Get("ETag") != "signed-part" || puts.Load() != 1 || settled.Load() != 1 {
				t.Fatal("signed PUT failed", resp.StatusCode, err, puts.Load(), settled.Load())
			}
		})
	}
}

type sha256PreparedBackend struct {
	*fixtureBackend
	prepared OriginGrant
}

func (b *sha256PreparedBackend) BeginUpload(_ context.Context, _ WorkloadIdentity, _, _, _ string, _ int) (string, OriginGrant, error) {
	b.begun.Store(true)
	return "sealed-mutation", b.prepared, nil
}

func TestGatewayRejectsMalformedOriginPayloadSHA256(t *testing.T) {
	f := newTransferFixture(t)
	var originCalls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()
	valid := strings.Repeat("a", 64)
	cases := []struct {
		name, key, value string
	}{
		{"empty", "x-amz-content-sha256", ""},
		{"short", "x-amz-content-sha256", strings.Repeat("a", 63)},
		{"long", "x-amz-content-sha256", strings.Repeat("a", 65)},
		{"uppercase", "x-amz-content-sha256", strings.Repeat("A", 64)},
		{"nonhex", "x-amz-content-sha256", strings.Repeat("g", 64)},
		{"unsigned", "x-amz-content-sha256", "UNSIGNED-PAYLOAD"},
		{"streaming", "x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"},
		{"leading space", "x-amz-content-sha256", " " + valid},
		{"trailing space", "x-amz-content-sha256", valid + " "},
		{"CRLF", "x-amz-content-sha256", valid + "\r\nX-Injected: true"},
		{"foreign header", "x-amz-foreign-control", valid},
		{"credential header", "Authorization", valid},
	}
	for _, tc := range cases {
		for _, phase := range []string{"grant", "begin"} {
			t.Run(tc.name+"/"+phase, func(t *testing.T) {
				grant := OriginGrant{URL: origin.URL + "/bucket/part", ExpiresAt: float64(time.Now().Add(time.Minute).Unix()), Size: 0}
				bad := grant
				bad.Headers = map[string]string{tc.key: tc.value}
				backend := &sha256PreparedBackend{fixtureBackend: &fixtureBackend{grant: grant}, prepared: grant}
				if phase == "grant" {
					backend.grant = bad
				} else {
					backend.prepared = bad
				}
				handler, err := NewGateway(GatewaySettings{
					Verifier:        WorkloadVerifier{Issuer: "https://workloads.example", PublicKey: f.public},
					OriginEndpoints: []string{origin.URL}, AllowLocalOriginHTTP: true,
				}, backend)
				if err != nil {
					t.Fatal(err)
				}
				defer handler.(*Gateway).Close()
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, f.request("PUT", "/transfers/v1/spaces/space-a/records/r/attachments/a/parts/1", nil, f.gatewayToken(t)))
				if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "invalid_origin_headers") ||
					originCalls.Load() != 0 || backend.finished.Load() != 0 || backend.begun.Load() != (phase == "begin") {
					t.Fatal("invalid origin headers reached storage or settled a mutation", w.Code, w.Body.String())
				}
			})
		}
	}
}
