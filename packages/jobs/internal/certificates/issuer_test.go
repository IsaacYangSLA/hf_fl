package certificates

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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
	"sync"
	"testing"
	"time"
)

var fixtureOnce sync.Once
var caKey, leafKey *rsa.PrivateKey

func testKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	fixtureOnce.Do(func() { caKey, _ = rsa.GenerateKey(rand.Reader, 2048); leafKey, _ = rsa.GenerateKey(rand.Reader, 2048) })
	if caKey == nil || leafKey == nil {
		t.Fatal("testkeys")
	}
	return caKey, leafKey
}
func fixture(t *testing.T) (*Issuer, *time.Time, []byte, []byte) {
	t.Helper()
	key, _ := testKeys(t)
	now := time.Unix(1792771200, 0)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Ephemeral test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(40 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3, 4, 5}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kp := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	issuer, e := NewIssuer(Config{CACertificatePEM: cp, CAPrivateKeyPEM: kp, Clock: func() time.Time { return now }})
	if e != nil {
		t.Fatal(e)
	}
	return issuer, &now, cp, kp
}
func csr(t *testing.T, template *x509.CertificateRequest) []byte {
	t.Helper()
	_, key := testKeys(t)
	der, e := x509.CreateCertificateRequest(rand.Reader, template, key)
	if e != nil {
		t.Fatal(e)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
func execution() Binding {
	return Binding{JobID: "job-a", AttemptID: "attempt-a", ComponentID: "alice", SpaceID: "space-a", Epoch: 2}
}
func TestIssueCSRIsClientOnlyAndExecutionBound(t *testing.T) {
	issuer, now, ca, _ := fixture(t)
	request := csr(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "caller cannot select identity", Organization: []string{"untrusted"}}})
	result, e := issuer.Issue(request, execution(), now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode([]byte(result.CertificatePEM))
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	encoded, _ := json.Marshal([]any{"job-a", "attempt-a", "alice", int64(2), "space-a"})
	h := sha256.Sum256(encoded)
	if cert.Subject.CommonName != hex.EncodeToString(h[:]) || len(cert.Subject.Organization) != 0 || len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 || cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage != x509.KeyUsageDigitalSignature || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("unexpected certificate identity/purpose: %+v", cert)
	}
	if !bytes.Equal(cert.AuthorityKeyId, issuer.certificate.SubjectKeyId) || len(cert.SubjectKeyId) != 20 {
		t.Fatal("key identifiers not established")
	}
	if Thumbprint(cert.Raw) != result.CertificateThumbprint || base64.RawURLEncoding.EncodeToString(h[:]) == result.CertificateThumbprint {
		t.Fatal("invalid thumbprint")
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	if _, e = cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: *now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		t.Fatal(e)
	}
	if _, e = cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: *now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e == nil {
		t.Fatal("client certificate granted server purpose")
	}
	second, e := issuer.Issue(request, execution(), now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	if second.CertificateThumbprint == result.CertificateThumbprint {
		t.Fatal("reissuance reused serial")
	}
	if bytes.Contains([]byte(result.CertificatePEM), []byte("PRIVATE KEY")) {
		t.Fatal("private key returned")
	}
}
func TestCSRRejectsRequestedAuthorityMalformedAndWeakKeys(t *testing.T) {
	for _, template := range []*x509.CertificateRequest{
		{DNSNames: []string{"other.example"}},
		{ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0}}}},
	} {
		if _, e := ValidateCSR(csr(t, template)); !errors.Is(e, ErrRefused) {
			t.Fatal("accepted requested extension", e)
		}
	}
	good := csr(t, &x509.CertificateRequest{})
	for _, bad := range [][]byte{nil, []byte("/private/key/path"), append(append([]byte{}, good...), good...), append([]byte("prefix"), good...), bytes.Repeat([]byte("x"), MaxPEMBytes+1)} {
		if _, e := ValidateCSR(bad); !errors.Is(e, ErrRefused) {
			t.Fatal("accepted malformed/oversized CSR", e)
		}
	}
	block, _ := pem.Decode(good)
	block.Bytes[len(block.Bytes)-1] ^= 1
	if _, e := ValidateCSR(pem.EncodeToMemory(block)); !errors.Is(e, ErrRefused) {
		t.Fatal("accepted forged signature", e)
	}
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, weak)
	if _, e := ValidateCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})); !errors.Is(e, ErrRefused) {
		t.Fatal("accepted weak key")
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, ec)
	if _, e := ValidateCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})); !errors.Is(e, ErrRefused) {
		t.Fatal("accepted unsupported CSR key")
	}
}
func TestLifetimeCapsAndCARevalidation(t *testing.T) {
	issuer, now, _, _ := fixture(t)
	req := csr(t, &x509.CertificateRequest{})
	out, e := issuer.Issue(req, execution(), now.Add(time.Hour))
	if e != nil || out.ExpiresAt != float64(now.Add(time.Hour+300*time.Second).Unix()) {
		t.Fatalf("deadline grace %v %+v", e, out)
	}
	out, e = issuer.Issue(req, execution(), now.Add(365*24*time.Hour))
	if e != nil || out.ExpiresAt != float64(now.Add(30*24*time.Hour).Unix()) {
		t.Fatalf("lifetime cap %v %+v", e, out)
	}
	*now = issuer.certificate.NotAfter.Add(-time.Hour)
	out, e = issuer.Issue(req, execution(), now.Add(2*time.Hour))
	if e != nil || out.ExpiresAt != float64(issuer.certificate.NotAfter.Unix()) {
		t.Fatalf("CA cap %v %+v", e, out)
	}
	*now = issuer.certificate.NotAfter
	if _, e = issuer.Issue(req, execution(), now.Add(time.Hour)); !errors.Is(e, ErrRefused) {
		t.Fatal("expired CA accepted")
	}
}
func TestDeadlineBindingAndConstructorRefusals(t *testing.T) {
	issuer, now, ca, key := fixture(t)
	req := csr(t, &x509.CertificateRequest{})
	for _, deadline := range []time.Time{time.Time{}, *now, now.Add(-time.Second)} {
		if _, e := issuer.Issue(req, execution(), deadline); e == nil {
			t.Fatal("expired deadline")
		}
	}
	for _, binding := range []Binding{{JobID: "../other", AttemptID: "attempt-a", ComponentID: "owner", SpaceID: "space", Epoch: 1}, {JobID: "job", AttemptID: "attempt", ComponentID: "owner", SpaceID: "space", Epoch: 0}, {JobID: "job", AttemptID: "attempt", ComponentID: "owner", SpaceID: "../other", Epoch: 1}} {
		if _, e := issuer.Issue(req, binding, now.Add(time.Hour)); e == nil {
			t.Fatal("invalid binding accepted")
		}
	}
	zero := int64(0)
	over := int64(301)
	negative := int64(-1)
	for _, config := range []Config{
		{CACertificatePEM: ca, CAPrivateKeyPEM: key, GraceSeconds: &over},
		{CACertificatePEM: ca, CAPrivateKeyPEM: key, GraceSeconds: &negative},
		{CACertificatePEM: ca, CAPrivateKeyPEM: key, MaxLifetimeSeconds: MaxLifetimeSeconds + 1},
	} {
		if _, e := NewIssuer(config); !errors.Is(e, ErrRefused) {
			t.Fatal("invalid policy", e)
		}
	}
	good, e := NewIssuer(Config{CACertificatePEM: ca, CAPrivateKeyPEM: key, GraceSeconds: &zero, Clock: func() time.Time { return *now }})
	if e != nil {
		t.Fatal(e)
	}
	out, e := good.Issue(req, execution(), now.Add(time.Hour))
	if e != nil || out.ExpiresAt != float64(now.Add(time.Hour).Unix()) {
		t.Fatal("zero grace did not apply")
	}
	_, different := testKeys(t)
	wrong := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(different)})
	if _, e := NewIssuer(Config{CACertificatePEM: ca, CAPrivateKeyPEM: wrong, Clock: func() time.Time { return *now }}); e == nil {
		t.Fatal("mismatched CA key accepted")
	}
}
func TestP256CAIssuesRSAClient(t *testing.T) {
	_, now, _, _ := fixture(t)
	ec, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	temp := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "P256 CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, temp, temp, &ec.PublicKey, ec)
	if e != nil {
		t.Fatal(e)
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(ec)
	issuer, e := NewIssuer(Config{CACertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), CAPrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), Clock: func() time.Time { return *now }})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = issuer.Issue(csr(t, &x509.CertificateRequest{}), execution(), now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
}
func TestPrivateFileLoaderRefusesLinksModesAndDirectoryAliases(t *testing.T) {
	_, _, _, key := fixture(t)
	root := t.TempDir()
	os.Chmod(root, 0700)
	path := filepath.Join(root, "key.pem")
	if e := os.WriteFile(path, key, 0600); e != nil {
		t.Fatal(e)
	}
	if got, e := ReadPEMFile(path, true); e != nil || !bytes.Equal(got, key) {
		t.Fatal("safe file refused", e)
	}
	os.Chmod(path, 0644)
	if _, e := ReadPEMFile(path, true); e == nil {
		t.Fatal("world-readable private key accepted")
	}
	os.Chmod(path, 0600)
	link := filepath.Join(root, "link.pem")
	os.Symlink(path, link)
	if _, e := ReadPEMFile(link, true); e == nil {
		t.Fatal("symlink accepted")
	}
	hard := filepath.Join(root, "hard.pem")
	os.Link(path, hard)
	if _, e := ReadPEMFile(path, true); e == nil {
		t.Fatal("hardlink accepted")
	}
	os.Remove(hard)
	alias := filepath.Join(t.TempDir(), "alias")
	os.Symlink(root, alias)
	if _, e := ReadPEMFile(filepath.Join(alias, "key.pem"), true); e == nil {
		t.Fatal("parent alias accepted")
	}
	os.Chmod(root, 0755)
	if _, e := ReadPEMFile(path, true); e == nil {
		t.Fatal("public private-key directory accepted")
	}
	if _, e := ReadPEMFile("relative.pem", true); e == nil {
		t.Fatal("relative path accepted")
	}
}
func TestStrictOpenSSLAndRealMTLSClientPurpose(t *testing.T) {
	issuer, now, ca, _ := fixture(t)
	req := csr(t, &x509.CertificateRequest{})
	out, e := issuer.Issue(req, execution(), now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	if openssl, e := exec.LookPath("openssl"); e == nil {
		root := t.TempDir()
		cap := filepath.Join(root, "ca.pem")
		leaf := filepath.Join(root, "client.pem")
		os.WriteFile(cap, ca, 0600)
		os.WriteFile(leaf, []byte(out.CertificatePEM), 0600)
		output, e := exec.Command(openssl, "verify", "-x509_strict", "-purpose", "sslclient", "-attime", big.NewInt(now.Unix()).String(), "-CAfile", cap, leaf).CombinedOutput()
		if e != nil {
			t.Fatalf("strict client verification: %v %s", e, output)
		}
	}
	// The active wallclock is independent from the fixture clock; use it for a fresh TLS certificate.
	current := time.Now().UTC()
	issuer.clock = func() time.Time { return current }
	// Recreate a current CA to exercise the actual TLS implementation.
	key, clientKey := testKeys(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "TLS test CA"}, NotBefore: current.Add(-time.Hour), NotAfter: current.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	ca = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	issuer, e = NewIssuer(Config{CACertificatePEM: ca, CAPrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})})
	if e != nil {
		t.Fatal(e)
	}
	issued, e := issuer.Issue(req, execution(), current.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: current.Add(-time.Minute), NotAfter: current.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	serverDER, _ := x509.CreateCertificate(rand.Reader, serverTemplate, issuer.certificate, &key.PublicKey, key)
	serverPair, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.VerifiedChains) == 0 {
			t.Error("missing verified client chain")
		}
		w.WriteHeader(204)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverPair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	clientPair, e := tls.X509KeyPair([]byte(issued.CertificatePEM), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)}))
	if e != nil {
		t.Fatal(e)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientPair}, MinVersion: tls.VersionTLS12}}}
	response, e := client.Get(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal(response.Status)
	}
}

func TestIssuerRejectsNonCAExpiredFutureAndForbiddenCAUsage(t *testing.T) {
	_, now, _, _ := fixture(t)
	key, _ := testKeys(t)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	for _, test := range []struct {
		name       string
		ca         bool
		usage      x509.KeyUsage
		start, end time.Time
	}{
		{"not-ca", false, x509.KeyUsageDigitalSignature, now.Add(-time.Hour), now.Add(time.Hour)},
		{"expired", true, x509.KeyUsageCertSign, now.Add(-2 * time.Hour), now.Add(-time.Hour)},
		{"future", true, x509.KeyUsageCertSign, now.Add(time.Hour), now.Add(2 * time.Hour)},
		{"forbidden-usage", true, x509.KeyUsageDigitalSignature, now.Add(-time.Hour), now.Add(time.Hour)},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := &x509.Certificate{SerialNumber: big.NewInt(501), Subject: pkix.Name{CommonName: "test"}, IsCA: test.ca, BasicConstraintsValid: true, KeyUsage: test.usage, NotBefore: test.start, NotAfter: test.end}
			der, e := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
			if e != nil {
				t.Fatal(e)
			}
			_, e = NewIssuer(Config{CACertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), CAPrivateKeyPEM: keyPEM, Clock: func() time.Time { return *now }})
			if !errors.Is(e, ErrRefused) {
				t.Fatal("invalid trusted CA accepted", e)
			}
		})
	}
}

func TestCSRIdempotencyHashUsesExactPEMBytes(t *testing.T) {
	raw := csr(t, &x509.CertificateRequest{})
	parsed, e := ValidateCSR(raw)
	if e != nil {
		t.Fatal(e)
	}
	if CSRPEMDigest(raw) == CSRDigest(parsed) {
		t.Fatal("confused PEM and DER digests")
	}
	if CSRPEMDigest(raw) == CSRPEMDigest(append(raw, byte(10))) {
		t.Fatal("lost exact request byte identity")
	}
	expected := sha256.Sum256(raw)
	if CSRPEMDigest(raw) != hex.EncodeToString(expected[:]) {
		t.Fatal("incorrect PEM digest")
	}
}
