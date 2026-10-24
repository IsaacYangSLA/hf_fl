package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/storage"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func makeCA(t *testing.T, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return testCA{cert, key, pool}
}
func (c testCA) leaf(t *testing.T, serial int64, purpose x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "gateway-backend-fixture"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{purpose}}
	if purpose == x509.ExtKeyUsageServerAuth {
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		template.DNSNames = []string{"localhost"}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestActualMTLSGatewayRequiresBackendClientCertificate(t *testing.T) {
	f := newGatewayFixture(t)
	ca := makeCA(t, "service-ca")
	serverCert := ca.leaf(t, 2, x509.ExtKeyUsageServerAuth)
	clientCert := ca.leaf(t, 3, x509.ExtKeyUsageClientAuth)
	server := httptest.NewUnstartedServer(f.handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.pool}
	server.StartTLS()
	t.Cleanup(server.Close)
	call := func(certificate *tls.Certificate) (int, error) {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: ca.pool}}}
		if certificate != nil {
			c.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{*certificate}
		}
		defer c.Transport.(*http.Transport).CloseIdleConnections()
		req, err := http.NewRequest(http.MethodPost, server.URL+f.part()+"/grant", nil)
		if err != nil {
			return 0, err
		}
		req.Header = f.headers(f.part()+"/grant", f.authorization, f.thumb)
		response, err := c.Do(req)
		if err != nil {
			return 0, err
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode, nil
	}
	if status, err := call(&clientCert); err != nil || status != 200 {
		t.Fatalf("verified independent backend client certificate: status%d %v", status, err)
	}
	if _, err := call(nil); err == nil {
		t.Fatal("missing backend clientcertificate accepted")
	}
	foreign := makeCA(t, "foreign-ca").leaf(t, 4, x509.ExtKeyUsageClientAuth)
	if _, err := call(&foreign); err == nil {
		t.Fatal("foreign backend clientcertificate accepted")
	}
	if _, err := call(&serverCert); err == nil {
		t.Fatal("server-only certificate accepted asclient")
	}
}

func TestStorageCheckUsesActualFixedVersionedS3AndExplicitProvisioner(t *testing.T) {
	f := newGatewayFixture(t)
	var calls atomic.Int64
	var enabled atomic.Bool
	enabled.Store(true)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method == http.MethodGet && r.URL.Query().Has("versioning") {
			w.Header().Set("Content-Type", "application/xml")
			status := "Enabled"
			if !enabled.Load() {
				status = "Suspended"
			}
			_, _ = io.WriteString(w, `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>`+status+`</Status></VersioningConfiguration>`)
			return
		}
		if r.Method == http.MethodHead && strings.HasPrefix(r.URL.Path, "/fixture-bucket/exchange-v2/readiness/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(provider.Close)
	settings := f.settings.Storage
	settings.Endpoint = provider.URL
	settings.AllowLocalHTTP = true
	settings.AccessKey = "fixture-access-key"
	settings.SecretKey = "fixture-secret-key"
	f.settings.Storage = settings
	backend, err := storage.NewS3(context.Background(), settings)
	if err != nil {
		t.Fatal(err)
	}
	f.engine.Storage = backend
	f.handler, err = New(f.core, f.engine, f.settings, Options{Now: func() time.Time { return time.Unix(f.clock.Load(), 0) }})
	if err != nil {
		t.Fatal(err)
	}
	path := Base + "/storage/check"
	authorization := f.humanToken("owner")
	status, result := f.raw(path, "", f.headers(path, authorization, f.thumb), true)
	if status != 200 || result["checked"] != true || result["versioning"] != "Enabled" || result["protocol"] != storage.MultipartProtocol || result["endpoint"] != provider.URL || result["prefix"] != "exchange-v2" {
		t.Fatalf("storage check status%d %+v", status, result)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected actual versioning and scopedHEAD calls, got%d", calls.Load())
	}
	raw, _ := jsonText(result)
	if strings.Contains(raw, "fixture-access-key") || strings.Contains(raw, "fixture-secret-key") {
		t.Fatal("credential disclosure")
	}
	before := calls.Load()
	for _, token := range []string{f.humanToken("unlisted-user"), f.authorization} {
		status, _ := f.raw(path, "", f.headers(path, token, f.thumb), true)
		if status != 401 && status != 403 {
			t.Fatalf("unlisted principal status%d", status)
		}
	}
	status, _ = f.raw(path, `{"endpoint":"https://attacker.example.test"}`, f.headers(path, authorization, f.thumb), true)
	if status != 422 {
		t.Fatal("namespace input accepted")
	}
	if calls.Load() != before {
		t.Fatal("unauthorized request probed provider")
	}
	enabled.Store(false)
	status, result = f.raw(path, "", f.headers(path, authorization, f.thumb), true)
	if status != 503 || result["checked"] == true {
		t.Fatalf("unversioned backend accepted %+v", result)
	}
	mismatch := settings
	mismatch.Bucket = "another-bucket"
	f.engine.Storage, err = storage.NewS3(context.Background(), mismatch)
	if err != nil {
		t.Fatal(err)
	}
	before = calls.Load()
	status, result = f.raw(path, "", f.headers(path, authorization, f.thumb), true)
	if status != 503 || errorCode(result) != "storage_backend_mismatch" || calls.Load() != before {
		t.Fatal("mismatched namespace probed provider")
	}
	f.engine.Storage = f.blobs
	status, result = f.raw(path, "", f.headers(path, authorization, f.thumb), true)
	if status != 503 || errorCode(result) != "storage_backend_unavailable" {
		t.Fatal("nonS3 provider approved")
	}
}

func jsonText(value any) (string, error) {
	raw, err := domain.CanonicalJSON(value)
	return string(raw), err
}

func TestExactOldReceiptCannotClearForeignRecordMarker(t *testing.T) {
	f := newGatewayFixture(t)
	old := f.begin()
	revision, err := f.db.One(f.ctx, "SELECT id FROM v2_schema_revisions WHERE space_id=? AND kind=?", f.sid, "document")
	if err != nil {
		t.Fatal(err)
	}
	record, err := f.core.CreateRecord(f.ctx, f.workload, f.sid, domain.Object{"kind": "document", "schema_revision_id": revision["id"], "metadata": domain.Object{}, "attachments": []any{domain.Object{"path": "model.safetensors", "size": int64(3), "sha256": digestABC()}}}, "second-record")
	if err != nil {
		t.Fatal(err)
	}
	items, _ := objects(record["attachments"])
	rid, bid := record["id"].(string), items[0]["id"].(string)
	if _, err = f.engine.Initiate(f.ctx, f.sid, rid, bid, f.workload); err != nil {
		t.Fatal(err)
	}
	path := Base + "/spaces/" + f.sid + "/records/" + rid + "/attachments/" + bid + "/parts/1/begin"
	otherReceipt := f.mustPost(path, nil)["receipt"].(string)
	otherMarkers := f.markers(bid)
	if f.mustPost(Base+"/settle", domain.Object{"receipt": old})["settled"] != true || len(f.markers(f.bid)) != 0 {
		t.Fatal("oldreceipt notsettled")
	}
	if len(otherMarkers) != 1 || !reflect.DeepEqual(otherMarkers, f.markers(bid)) {
		t.Fatal("oldreceipt cleared foreign marker")
	}
	if f.mustPost(Base+"/settle", domain.Object{"receipt": otherReceipt})["settled"] != true {
		t.Fatal("foreignowner receipt failed")
	}
}
func TestSettlementKeyRotationAndMalformedReceiptHTTP(t *testing.T) {
	f := newGatewayFixture(t)
	receipt := f.begin()
	for _, value := range []any{receipt + "x", "", nil, 1} {
		status, result := f.post(Base+"/settle", domain.Object{"receipt": value})
		if status != 401 || errorCode(result) != "invalid_gateway_put_receipt" {
			t.Fatalf("malformed receipt %+v", result)
		}
	}
	authorization := f.token(domain.Object{"nonce": "different-token"})
	status, _ := f.raw(Base+"/settle", `{"receipt":"`+receipt+`"}`, f.headers(Base+"/settle", authorization, f.thumb), true)
	if status != 401 {
		t.Fatal("reissued token substituted fororiginal")
	}
	f.settings.Auth.TrustedBackendSecret = "rotated-fixture-backend-secret-at-least-32-bytes"
	var err error
	f.handler, err = New(f.core, f.engine, f.settings, Options{Now: func() time.Time { return time.Unix(f.clock.Load(), 0) }})
	if err != nil {
		t.Fatal(err)
	}
	status, result := f.post(Base+"/settle", domain.Object{"receipt": receipt})
	if status != 401 || errorCode(result) != "invalid_gateway_put_receipt" || len(f.markers(f.bid)) != 1 {
		t.Fatal("keyrotation cleared oldmarker")
	}
}

func TestPrivateBackendConstructorAndNonAPIRoutes(t *testing.T) {
	f := newGatewayFixture(t)
	if _, err := New(f.core, f.engine, f.settings, Options{Audience: f.settings.Auth.WorkloadAudience}); err == nil {
		t.Fatal("managed audience reused")
	}
	settings := f.settings
	settings.Auth.WorkloadIssuer = ""
	settings.Auth.WorkloadPublicKey = ""
	if _, err := New(f.core, f.engine, settings, Options{}); err == nil {
		t.Fatal("unmanaged settings accepted")
	}
	for _, path := range []string{"/v2/spaces", "/docs", "/openapi.json", "/health", "/ready"} {
		status, _ := f.post(path, nil)
		if status != 404 {
			t.Fatalf("private route surfaced %s status%d", path, status)
		}
	}
}
