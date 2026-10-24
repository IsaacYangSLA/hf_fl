package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
)

func TestCommandHelpHasNoRuntimeDependency(t *testing.T) {
	t.Setenv("EXCHANGE_DATABASE_URL", "invalid-private-database")
	t.Setenv("EXCHANGE_ISSUER", "invalid-private-identity")
	t.Setenv("EXCHANGE_S3_BUCKET", "")
	for _, command := range append([]string{""}, commands...) {
		t.Run(command, func(t *testing.T) {
			args := []string{"--help"}
			if command != "" {
				args = []string{command, "--help"}
			}
			var out, errs bytes.Buffer
			if code := Run(context.Background(), args, &out, &errs); code != 0 {
				t.Fatalf("help status%d stderr%s", code, errs.String())
			}
			if !strings.Contains(out.String(), "Usage:") {
				t.Fatal("command has no usage")
			}
		})
	}
}
func TestNativeWorkerModelAndRepairGuards(t *testing.T) {
	for _, args := range [][]string{
		{"serve", "--workers", "2"},
		{"repair-transfers", "--apply"},
		{"repair-transfers", "--apply", "--attempt", "a", "--writers-stopped"},
		{"repair-transfers", "--attempt", "a", "--attempt", "a"},
		{"serve", "--apply"},
		{"worker", "--port", "0"},
		{"serve", "--once"},
	} {
		var out, errs bytes.Buffer
		if code := Run(context.Background(), args, &out, &errs); code != 2 {
			t.Fatalf("unsafe flags status%d", code)
		}
	}
	var out, errs bytes.Buffer
	if Run(context.Background(), []string{"serve", "--workers", "2"}, &out, &errs) != 2 || !strings.Contains(errs.String(), "--workers must be 1") {
		t.Fatal("native process model is not explicit")
	}
}
func TestFlagErrorsRedactSuppliedValues(t *testing.T) {
	for _, args := range [][]string{{"serve", "--port", "private-credential"}, {"serve", "--private-credential"}, {"worker", "private-credential"}} {
		var out, errs bytes.Buffer
		Run(context.Background(), args, &out, &errs)
		if strings.Contains(out.String()+errs.String(), "private-credential") {
			t.Fatal("argument value leaked")
		}
	}
}
func TestExportIsSelfContainedAndMatchesReference(t *testing.T) {
	t.Setenv("EXCHANGE_DATABASE_URL", "invalid-private-database")
	t.Setenv("EXCHANGE_ISSUER", "invalid-private-identity")
	t.Setenv("EXCHANGE_WORKER_POLL_SECONDS", "not-a-number")
	dir := t.TempDir()
	var out, errs bytes.Buffer
	if code := Run(context.Background(), []string{"export-contract", "--output-dir", dir}, &out, &errs); code != 0 {
		t.Fatalf("export status%d stderr%s", code, errs.String())
	}
	reference := filepath.Join("..", "..", "..", "..", "docs", "generated")
	for _, name := range contractNames {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join(reference, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s contract drift", name)
		}
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("owned"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "exchange-api.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "exchange-api.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportContracts(dir); err == nil {
		t.Fatal("contract export followed a destination symlink")
	}
}
func privateDatabase(t *testing.T) string {
	t.Helper()
	return "sqlite:///" + filepath.Join(t.TempDir(), "exchange.db")
}
func TestDatabaseCommandsIgnoreUnrelatedSecrets(t *testing.T) {
	t.Setenv("EXCHANGE_DATABASE_URL", privateDatabase(t))
	t.Setenv("EXCHANGE_ISSUER", "invalid-private-identity")
	t.Setenv("EXCHANGE_JWT_PUBLIC_KEY", "")
	t.Setenv("EXCHANGE_S3_ENDPOINT", "http://untrusted.invalid")
	t.Setenv("EXCHANGE_WORKER_POLL_SECONDS", "not-a-number")
	for _, command := range []string{"init-db", "check-db", "check-compatibility", "repair-transfers"} {
		var out, errs bytes.Buffer
		if code := Run(context.Background(), []string{command}, &out, &errs); code != 0 {
			t.Fatalf("%s status%d out%s err%s", command, code, out.String(), errs.String())
		}
		if command == "repair-transfers" {
			var result map[string]any
			if json.Unmarshal(out.Bytes(), &result) != nil || result["dry_run"] != true {
				t.Fatal("repair did not default to dry run")
			}
		}
	}
}
func TestRetainedSchemaPreflightRefusesBeforeRuntime(t *testing.T) {
	ctx := context.Background()
	databaseURL := privateDatabase(t)
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	sid, rid := domain.NewID(), domain.NewID()
	pattern := `\N{SNOWMAN}`
	err = db.WithTx(ctx, true, func(tx *store.Tx) error {
		if e := tx.Insert(ctx, "v2_spaces", domain.Object{"id": sid, "name": "retained"}); e != nil {
			return e
		}
		return tx.Insert(ctx, "v2_schema_revisions", domain.Object{"id": rid, "space_id": sid, "kind": "fixture", "revision": int64(1), "schema": domain.Object{"type": "object", "properties": domain.Object{"x": domain.Object{"pattern": pattern}}}})
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := CheckCompatibility(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if report.Checked != 1 || report.Compatible != 0 || len(report.Incompatible) != 1 || report.Incompatible[0].ID != rid || report.Incompatible[0].Code != "invalid_schema" {
		t.Fatalf("compatibility report %#v", report)
	}
	t.Setenv("EXCHANGE_DATABASE_URL", databaseURL)
	t.Setenv("EXCHANGE_ISSUER", "invalid-unrelated-identity")
	var out, errs bytes.Buffer
	if Run(ctx, []string{"check-compatibility"}, &out, &errs) != 1 {
		t.Fatal("incompatible schema did not stop compatibility command")
	}
	if strings.Contains(out.String()+errs.String(), pattern) || strings.Contains(out.String(), "SNOWMAN") {
		t.Fatal("compatibility diagnostics exposed schema")
	}
	settings := config.DefaultSettings()
	settings.Database.URL = databaseURL
	settings.Auth.Issuer = "https://identity.example"
	settings.Auth.PublicKey = "invalid-key-that-must-not-be-parsed"
	settings.Storage.Bucket = "fixture"
	_, err = BuildServices(ctx, settings, "server")
	var compatibility *CompatibilityError
	if !errors.As(err, &compatibility) {
		t.Fatalf("startup did not fail at retained compatibility boundary: %T", err)
	}
}
func signingPublicKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b}))
}
func TestServicesComposeActualNativePorts(t *testing.T) {
	ctx := context.Background()
	settings := config.DefaultSettings()
	settings.Database.URL = privateDatabase(t)
	db, err := OpenDatabase(ctx, settings.Database)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	db.Close()
	settings.Auth.Issuer = "https://identity.example"
	settings.Auth.PublicKey = signingPublicKey(t)
	settings.Auth.WorkloadIssuer = "https://workload.example"
	settings.Auth.WorkloadPublicKey = settings.Auth.PublicKey
	settings.Auth.TrustedBackendSecret = strings.Repeat("s", 32)
	settings.Auth.ProvisioningPrincipalIDs = []string{strings.Repeat("a", 64)}
	settings.Storage.Bucket = "fixture"
	settings.Storage.Endpoint = "http://127.0.0.1:1"
	settings.Storage.AllowLocalHTTP = true
	settings.Storage.AccessKey = "test-only-access"
	settings.Storage.SecretKey = "test-only-secret"
	s, err := BuildServices(ctx, settings, "server")
	if err != nil {
		t.Fatal(err)
	}
	if s.Core == nil || s.Transfers == nil || s.Auth == nil || s.Storage == nil || s.DB == nil {
		t.Fatal("native composition has missing services")
	}
	for _, mode := range []string{"public", "managed", "gateway"} {
		h, e := s.Handler(mode, "hf2l-transfer")
		if e != nil || h == nil {
			t.Fatalf("%s composition: %v", mode, e)
		}
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.SQL.PingContext(ctx); err == nil {
		t.Fatal("services did not close owned SQL pool")
	}
}
func TestCompositionErrorsRedactAndUnwrap(t *testing.T) {
	inner := errors.New("secret-database-value")
	err := stage("database", inner)
	if strings.Contains(err.Error(), "secret-database-value") || !errors.Is(err, inner) {
		t.Fatal("composition diagnostics or error identity invalid")
	}
}

type testPKI struct {
	CA                                           []byte
	ServerCert, ServerKey, ClientCert, ClientKey string
	Client                                       tls.Certificate
	Pool                                         *x509.CertPool
}

func makePKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	issue := func(serial int64, purpose x509.ExtKeyUsage) (string, string, tls.Certificate) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{purpose}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, e := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
		if e != nil {
			t.Fatal(e)
		}
		cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyDER, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			t.Fatal(e)
		}
		private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		c, k := write(fmt.Sprint(serial)+".crt", cert), write(fmt.Sprint(serial)+".key", private)
		pair, e := tls.X509KeyPair(cert, private)
		if e != nil {
			t.Fatal(e)
		}
		return c, k, pair
	}
	serverCert, serverKey, _ := issue(2, x509.ExtKeyUsageServerAuth)
	clientCert, clientKey, client := issue(3, x509.ExtKeyUsageClientAuth)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	return testPKI{CA: ca, ServerCert: serverCert, ServerKey: serverKey, ClientCert: clientCert, ClientKey: clientKey, Client: client, Pool: pool}
}
func TestTLSAuthorityAndFileGuards(t *testing.T) {
	for _, tc := range []struct {
		mode, host string
		allow      bool
		ok         bool
	}{{"public", "127.0.0.1", false, false}, {"public", "127.0.0.1", true, true}, {"public", "0.0.0.0", true, false}, {"gateway", "127.0.0.1", true, false}} {
		cfg, e := TLSConfig(tc.mode, ListenerOptions{Host: tc.host}, tc.allow)
		if (e == nil) != tc.ok || cfg != nil {
			t.Fatal("cleartext listener boundary invalid")
		}
	}
	pki := makePKI(t)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pki.CA, 0600)
	opts := ListenerOptions{Host: "127.0.0.1", CertificateFile: pki.ServerCert, KeyFile: pki.ServerKey, ClientCAFile: ca}
	cfg, err := TLSConfig("gateway", opts, false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert || cfg.MinVersion < tls.VersionTLS12 {
		t.Fatal("private listener client authority missing")
	}
	wrong := opts
	wrong.CertificateFile = pki.ClientCert
	wrong.KeyFile = pki.ClientKey
	if _, err = TLSConfig("gateway", wrong, false); err == nil {
		t.Fatal("client certificate accepted for server")
	}
	link := filepath.Join(t.TempDir(), "key")
	os.Symlink(pki.ServerKey, link)
	wrong = opts
	wrong.KeyFile = link
	if _, err = TLSConfig("gateway", wrong, false); err == nil {
		t.Fatal("symlink private key accepted")
	}
	os.Chmod(pki.ServerKey, 0644)
	if _, err = TLSConfig("gateway", opts, false); err == nil {
		t.Fatal("readable-by-others private key accepted")
	}
	os.Chmod(pki.ServerKey, 0600)
	oversized := filepath.Join(t.TempDir(), "large.pem")
	os.WriteFile(oversized, make([]byte, 1024*1024+1), 0600)
	wrong = opts
	wrong.ClientCAFile = oversized
	if _, err = TLSConfig("gateway", wrong, false); err == nil {
		t.Fatal("oversized authority file accepted")
	}
	wrong = opts
	wrong.ClientCAFile = pki.ServerCert
	if _, err = TLSConfig("gateway", wrong, false); err == nil {
		t.Fatal("non-CA trusted for client authentication")
	}
}
func TestPrivateListenerPerformsRealMutualTLS(t *testing.T) {
	pki := makePKI(t)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pki.CA, 0600)
	cfg, err := TLSConfig("gateway", ListenerOptions{Host: "127.0.0.1", CertificateFile: pki.ServerCert, KeyFile: pki.ServerKey, ClientCAFile: ca}, false)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			t.Error("unverified request reached handler")
		}
		w.WriteHeader(204)
	})}
	go server.Serve(tls.NewListener(listener, cfg))
	t.Cleanup(func() { server.Close() })
	request := func(clientCert []tls.Certificate) error {
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pki.Pool, ServerName: "localhost", Certificates: clientCert, MinVersion: tls.VersionTLS12}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		response, e := client.Get("https://" + listener.Addr().String() + "/")
		if e != nil {
			return e
		}
		defer response.Body.Close()
		io.Copy(io.Discard, response.Body)
		if response.StatusCode != 204 {
			return errors.New("unexpected mTLS response")
		}
		return nil
	}
	if err = request(nil); err == nil {
		t.Fatal("private listener admitted a missing client certificate")
	}
	foreign := makePKI(t)
	if err = request([]tls.Certificate{foreign.Client}); err == nil {
		t.Fatal("private listener admitted a foreign CA")
	}
	if err = request([]tls.Certificate{pki.Client}); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerOnceUsesNativeCleanupWithoutIdentityOrCompatibleMetadata(t *testing.T) {
	ctx := context.Background()
	databaseURL := privateDatabase(t)
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	sid := domain.NewID()
	err = db.WithTx(ctx, true, func(tx *store.Tx) error {
		if e := tx.Insert(ctx, "v2_spaces", domain.Object{"id": sid, "name": "retained"}); e != nil {
			return e
		}
		return tx.Insert(ctx, "v2_schema_revisions", domain.Object{"id": domain.NewID(), "space_id": sid, "kind": "fixture", "revision": int64(1), "schema": domain.Object{"type": "object", "properties": domain.Object{"x": domain.Object{"pattern": `\N{SNOWMAN}`}}}})
	})
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("EXCHANGE_DATABASE_URL", databaseURL)
	t.Setenv("EXCHANGE_ISSUER", "invalid-unrelated-identity")
	t.Setenv("EXCHANGE_JWT_PUBLIC_KEY", "")
	t.Setenv("EXCHANGE_S3_BUCKET", "fixture")
	t.Setenv("EXCHANGE_S3_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("EXCHANGE_ALLOW_LOCAL_HTTP", "true")
	t.Setenv("EXCHANGE_S3_ACCESS_KEY", "test-only-access")
	t.Setenv("EXCHANGE_S3_SECRET_KEY", "test-only-secret")
	for _, level := range []string{"ERROR", "INFO"} {
		runCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		var out, errs bytes.Buffer
		code := Run(runCtx, []string{"worker", "--once", "--log-level", level}, &out, &errs)
		cancel()
		if code != 0 {
			t.Fatalf("native worker cleanup status%d stderr%s", code, errs.String())
		}
		if strings.Contains(errs.String(), "worker pass") != (level == "INFO") {
			t.Fatal("worker log-level policy ignored")
		}
	}
}
