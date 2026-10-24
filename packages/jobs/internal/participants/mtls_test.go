package participants

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func participantTLSFixture(t *testing.T) (tls.Certificate, tls.Certificate, tls.Certificate, *x509.CertPool, string) {
	t.Helper()
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Unit test authority"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(serial int64, usage x509.ExtKeyUsage) tls.Certificate {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Unit test service"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, e := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	}
	server, manager, foreign := issue(2, x509.ExtKeyUsageServerAuth), issue(3, x509.ExtKeyUsageClientAuth), issue(4, x509.ExtKeyUsageClientAuth)
	sum := sha256.Sum256(manager.Certificate[0])
	return server, manager, foreign, roots, base64.RawURLEncoding.EncodeToString(sum[:])
}
func TestParticipantHandlerUsesActualVerifiedMutualTLS(t *testing.T) {
	serverCert, managerCert, foreignCert, roots, managerThumb := participantTLSFixture(t)
	agent := &Agent{Broker: testParticipantBroker(t), Config: AgentConfig{NodeID: "node-alice", NodeCertificateThumbprint: participantThumb("node-alice")}}
	server := httptest.NewUnstartedServer(agent.Handler([]string{managerThumb}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}
	server.StartTLS()
	defer server.Close()
	for _, test := range []struct {
		name string
		cert *tls.Certificate
		want string
	}{{"approved", &managerCert, "invalid_node_grant"}, {"foreign", &foreignCert, "verified_manager_certificate_required"}, {"absent", nil, ""}} {
		t.Run(test.name, func(t *testing.T) {
			config := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
			if test.cert != nil {
				config.Certificates = []tls.Certificate{*test.cert}
			}
			transport := &http.Transport{TLSClientConfig: config, Proxy: nil}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: time.Second}
			request, e := http.NewRequestWithContext(context.Background(), "POST", server.URL+"/internal/nodes/v1/participants", strings.NewReader(`{"node_token":"forged"}`))
			if e != nil {
				t.Fatal(e)
			}
			request.Header.Set("X-Verified-Peer-Thumbprint", managerThumb)
			response, e := client.Do(request)
			if test.cert == nil {
				if e == nil {
					response.Body.Close()
					t.Fatal("missing TLS client certificate admitted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer response.Body.Close()
			body, _ := io.ReadAll(response.Body)
			if response.StatusCode != 401 || !strings.Contains(string(body), test.want) {
				t.Fatalf("%d %s", response.StatusCode, body)
			}
		})
	}
}
