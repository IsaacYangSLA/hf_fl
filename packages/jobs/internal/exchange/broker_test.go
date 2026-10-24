package exchange

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/golang-jwt/jwt/v5"
)

var testOnce sync.Once
var testKey, testOtherKey *rsa.PrivateKey

func keys(t *testing.T) (*rsa.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	testOnce.Do(func() {
		testKey, _ = rsa.GenerateKey(rand.Reader, 2048)
		testOtherKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	})
	if testKey == nil || testOtherKey == nil {
		t.Fatal("test key generation")
	}
	return testKey, testOtherKey
}
func brokerFixture(t *testing.T) (*Broker, *time.Time, *rsa.PrivateKey) {
	t.Helper()
	key, _ := keys(t)
	public, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	now := time.Unix(1792771200, 0)
	b, e := NewBroker(BrokerSettings{Issuer: "https://workloads.example.test", ExchangeAudience: "exchange-managed", GatewayAudience: "gateway", NodeAudience: "nodes", KeyID: "signing-v1", PublicKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), Clock: func() time.Time { return now }})
	if e != nil {
		t.Fatal(e)
	}
	return b, &now, key
}
func thumb(value string) string {
	s := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(s[:])
}
func workloadReq() WorkloadRequest {
	participant := "alice"
	return WorkloadRequest{JobID: "job-a", AttemptID: "attempt-a", ComponentID: "alice", SpaceID: "space-a", GrantID: "grant-a", CertificateThumbprint: thumb("certificate-a"), Epoch: 1, TTLSeconds: 300, ParticipantID: &participant, Audience: "exchange"}
}
func assertCode(t *testing.T, e error, status int, code string) {
	t.Helper()
	var d *domain.Error
	if !errors.As(e, &d) || d.Status != status || d.Code != code {
		t.Fatalf("want %d %s, got %v", status, code, e)
	}
}
func unsignedClaims(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	_, _, e := jwt.NewParser(jwt.WithJSONNumber()).ParseUnverified(token, claims)
	if e != nil {
		t.Fatal(e)
	}
	return claims
}
func resign(t *testing.T, key *rsa.PrivateKey, c jwt.MapClaims, header map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	token.Header["typ"] = "at+jwt"
	token.Header["kid"] = "signing-v1"
	for k, v := range header {
		token.Header[k] = v
	}
	s, e := token.SignedString(key)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestWorkloadTokenIdentityAndAudience(t *testing.T) {
	b, _, _ := brokerFixture(t)
	r := workloadReq()
	token, e := b.IssueWorkload(r)
	if e != nil {
		t.Fatal(e)
	}
	p, e := b.AuthenticateWorkload("Bearer "+token, r.CertificateThumbprint, "exchange")
	if e != nil {
		t.Fatal(e)
	}
	want, e := StableWorkloadPrincipal(b.Issuer(), r.JobID, r.ComponentID, r.ParticipantID)
	if e != nil || p.ID != want || p.GrantID != r.GrantID || p.Epoch != 1 || p.Audience != "exchange-managed" {
		t.Fatalf("wrong binding: %+v", p)
	}
	_, e = b.AuthenticateWorkload("Bearer "+token, r.CertificateThumbprint, "gateway")
	assertCode(t, e, 401, "invalid_access_token")
	r.Audience = "gateway"
	gateway, e := b.IssueWorkload(r)
	if e != nil {
		t.Fatal(e)
	}
	gp, e := b.AuthenticateWorkload("Bearer "+gateway, r.CertificateThumbprint, "gateway")
	if e != nil || gp.ID != p.ID {
		t.Fatalf("gateway binding: %v", e)
	}
	_, e = b.AuthenticateWorkload("Bearer "+gateway, r.CertificateThumbprint, "exchange")
	assertCode(t, e, 401, "invalid_access_token")
	_, e = b.AuthenticateWorkload("Bearer "+token, thumb("certificate-b"), "exchange")
	assertCode(t, e, 401, "invalid_access_token")
}
func TestWorkloadSubjectMatchesPythonOracle(t *testing.T) {
	raw, e := os.ReadFile(filepath.Join("testdata", "identities.json"))
	if e != nil {
		t.Fatal(e)
	}
	var vectors []struct {
		Issuer      string  `json:"issuer"`
		Job         string  `json:"job"`
		Component   string  `json:"component"`
		Participant *string `json:"participant"`
		Subject     string  `json:"subject"`
		Principal   string  `json:"principal"`
	}
	if e = json.Unmarshal(raw, &vectors); e != nil {
		t.Fatal(e)
	}
	for _, v := range vectors {
		s, e := StableWorkloadSubject(v.Job, v.Component, v.Participant)
		if e != nil || s != v.Subject {
			t.Fatalf("subject mismatch: %v %s", e, s)
		}
		p, e := StableWorkloadPrincipal(v.Issuer, v.Job, v.Component, v.Participant)
		if e != nil || p != v.Principal {
			t.Fatalf("principal mismatch: %v %s", e, p)
		}
	}
}
func TestWorkloadEveryClaimAndHeaderIsValidated(t *testing.T) {
	b, _, key := brokerFixture(t)
	req := workloadReq()
	original, e := b.IssueWorkload(req)
	if e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"iss", "aud", "sub", "iat", "nbf", "exp", "jti", "cnf", "job_id", "attempt_id", "component_id", "space_id", "epoch", "token_use", "scope"} {
		t.Run("missing_"+field, func(t *testing.T) {
			c := unsignedClaims(t, original)
			delete(c, field)
			_, e = b.AuthenticateWorkload("Bearer "+resign(t, key, c, nil), req.CertificateThumbprint, "exchange")
			assertCode(t, e, 401, "invalid_access_token")
		})
	}
	changes := map[string]any{"iss": "other", "aud": []string{"exchange-managed"}, "sub": "job:forged", "iat": 1792771200.5, "nbf": int64(1792771199), "exp": int64(1792771501), "grant_id": "other", "epoch": json.Number("1.0"), "space_id": "../other", "participant_id": "bob", "token_use": "node", "scope": "transfer", "cnf": map[string]any{"x5t#S256": req.CertificateThumbprint, "extra": true}}
	for k, v := range changes {
		t.Run("changed_"+k, func(t *testing.T) {
			c := unsignedClaims(t, original)
			c[k] = v
			_, e = b.AuthenticateWorkload("Bearer "+resign(t, key, c, nil), req.CertificateThumbprint, "exchange")
			assertCode(t, e, 401, "invalid_access_token")
		})
	}
	for _, headers := range []map[string]any{{"jku": "https://evil.invalid/keys"}, {"x5u": "https://evil.invalid/cert"}, {"typ": "JWT"}, {"kid": "other"}, {"crit": []string{"test"}}} {
		_, e = b.AuthenticateWorkload("Bearer "+resign(t, key, unsignedClaims(t, original), headers), req.CertificateThumbprint, "exchange")
		assertCode(t, e, 401, "invalid_access_token")
	}
	_, other := keys(t)
	_, e = b.AuthenticateWorkload("Bearer "+resign(t, other, unsignedClaims(t, original), nil), req.CertificateThumbprint, "exchange")
	assertCode(t, e, 401, "invalid_access_token")
	for _, header := range []string{"", original, "Basic " + original, "Bearer ", "Bearer " + original + " ", "Bearer " + original + "\n", "Bearer " + strings.Repeat("x", 16385)} {
		_, e = b.AuthenticateWorkload(header, req.CertificateThumbprint, "exchange")
		assertCode(t, e, 401, "invalid_access_token")
	}
}
func TestTokenLifetimeAndVerificationOnlyKey(t *testing.T) {
	b, now, _ := brokerFixture(t)
	r := workloadReq()
	token, e := b.IssueWorkload(r)
	if e != nil {
		t.Fatal(e)
	}
	*now = now.Add(299 * time.Second)
	if _, e = b.AuthenticateWorkload("Bearer "+token, r.CertificateThumbprint, "exchange"); e != nil {
		t.Fatal(e)
	}
	*now = now.Add(time.Second)
	_, e = b.AuthenticateWorkload("Bearer "+token, r.CertificateThumbprint, "exchange")
	assertCode(t, e, 401, "invalid_access_token")
	r.TTLSeconds = 301
	_, e = b.IssueWorkload(r)
	assertCode(t, e, 422, "invalid_credential_lifetime")
	verification, e := NewBroker(BrokerSettings{Issuer: b.Issuer(), ExchangeAudience: "exchange-managed", GatewayAudience: "gateway", NodeAudience: "nodes", PublicKeyPEM: b.PublicKeyPEM()})
	if e != nil {
		t.Fatal(e)
	}
	_, e = verification.IssueWorkload(workloadReq())
	assertCode(t, e, 503, "signing_key_unavailable")
	if strings.Contains(b.String(), "PRIVATE") || strings.Contains(b.String(), "BEGIN") {
		t.Fatal("secret representation")
	}
}
func nodeReq() NodeRequest {
	return NodeRequest{NodeID: "node-a", PoolID: "pool-a", JobID: "job-a", AttemptID: "attempt-a", ComponentID: "owner", GrantID: "grant-a", CertificateThumbprint: thumb("peer"), Epoch: 1, TTLSeconds: 300, Scopes: []string{"reserve", "start"}, Resources: map[string]any{"cpu_millicores": int64(1000), "memory_bytes": int64(1 << 30), "disk_bytes": int64(1 << 30)}}
}
func TestNodeRequiresLiveGrantAndNarrowResources(t *testing.T) {
	b, _, _ := brokerFixture(t)
	r := nodeReq()
	token, e := b.IssueNode(r)
	if e != nil {
		t.Fatal(e)
	}
	_, e = b.AuthenticateNode(context.Background(), "Bearer "+token, r.CertificateThumbprint, nil)
	assertCode(t, e, 503, "node_grant_unavailable")
	checks := 0
	p, e := b.AuthenticateNode(context.Background(), "Bearer "+token, r.CertificateThumbprint, func(ctx context.Context, p NodePrincipal) (bool, error) {
		checks++
		return p.NodeID == r.NodeID && p.JobID == r.JobID && p.Epoch == r.Epoch, nil
	})
	if e != nil || checks != 1 || !p.HasScope("start") || p.HasScope("purge") {
		t.Fatalf("node %v %+v", e, p)
	}
	_, e = b.AuthenticateNode(context.Background(), "Bearer "+token, r.CertificateThumbprint, func(context.Context, NodePrincipal) (bool, error) { return false, nil })
	assertCode(t, e, 401, "invalid_access_token")
	_, e = b.AuthenticateNode(context.Background(), "Bearer "+token, r.CertificateThumbprint, func(context.Context, NodePrincipal) (bool, error) {
		return false, errors.New("private grant database failure")
	})
	assertCode(t, e, 503, "node_grant_unavailable")
	_, e = b.AuthenticateNode(context.Background(), "Bearer "+token, thumb("wrong"), func(context.Context, NodePrincipal) (bool, error) {
		t.Fatal("validator before certificate authentication")
		return true, nil
	})
	assertCode(t, e, 401, "invalid_access_token")
	for _, change := range []func(*NodeRequest){
		func(r *NodeRequest) { r.Scopes = []string{"root"} },
		func(r *NodeRequest) { r.Resources["cpu_millicores"] = 0 },
		func(r *NodeRequest) { r.Resources["cpu_millicores"] = 1.0 },
		func(r *NodeRequest) { r.Resources["secret"] = "bad" },
		func(r *NodeRequest) { delete(r.Resources, "memory_bytes") },
		func(r *NodeRequest) { r.Resources["gpu_uuids"] = []string{"gpu-a", "gpu-a"} },
	} {
		n := nodeReq()
		change(&n)
		if _, e = b.IssueNode(n); e == nil {
			t.Fatal("accepted unsafe node request")
		}
	}
}
func TestPlatformNodeCredentialsAreSeparateAndCurrent(t *testing.T) {
	b, _, key := brokerFixture(t)
	r := PlatformNodeRequest{NodeID: "node-a", PoolID: "pool-a", RegistrationID: "registration-a", CertificateThumbprint: thumb("manager"), TTLSeconds: 60}
	token, e := b.IssueNodePlatform(r)
	if e != nil {
		t.Fatal(e)
	}
	_, e = b.AuthenticateNodePlatform(context.Background(), "Bearer "+token, r.CertificateThumbprint, nil)
	assertCode(t, e, 503, "node_registration_unavailable")
	p, e := b.AuthenticateNodePlatform(context.Background(), "Bearer "+token, r.CertificateThumbprint, func(ctx context.Context, p PlatformNodePrincipal) (bool, error) {
		return p.RegistrationID == r.RegistrationID, nil
	})
	if e != nil || !p.HasScope("qualify") || p.HasScope("start") {
		t.Fatalf("%+v %v", p, e)
	}
	c := unsignedClaims(t, token)
	c["job_id"] = "job-a"
	_, e = b.AuthenticateNodePlatform(context.Background(), "Bearer "+resign(t, key, c, nil), r.CertificateThumbprint, func(context.Context, PlatformNodePrincipal) (bool, error) { return true, nil })
	assertCode(t, e, 401, "invalid_access_token")
}

func TestBrokerRejectsKeyConfusionAndInvalidSettings(t *testing.T) {
	b, _, key := brokerFixture(t)
	base := BrokerSettings{Issuer: b.Issuer(), ExchangeAudience: "exchange-managed", GatewayAudience: "gateway", NodeAudience: "nodes", PublicKeyPEM: b.PublicKeyPEM()}
	for _, change := range []func(*BrokerSettings){
		func(c *BrokerSettings) { c.Issuer = "" },
		func(c *BrokerSettings) { c.ExchangeAudience = c.GatewayAudience },
		func(c *BrokerSettings) { c.NodeAudience = "node audience" },
		func(c *BrokerSettings) { c.MaxTTLSeconds = 301 },
		func(c *BrokerSettings) { c.MaxTTLSeconds = -1 },
		func(c *BrokerSettings) { c.KeyID = "../arbitrary" },
		func(c *BrokerSettings) { c.PublicKeyPEM = []byte("untrusted malformed PEM") },
	} {
		config := base
		change(&config)
		if _, e := NewBroker(config); e == nil {
			t.Fatal("invalid broker configuration accepted")
		}
	}
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	weakDER, _ := x509.MarshalPKIXPublicKey(&weak.PublicKey)
	config := base
	config.PublicKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: weakDER})
	if _, e := NewBroker(config); e == nil {
		t.Fatal("weak signing key accepted")
	}
	_, other := keys(t)
	config = base
	config.PrivateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(other)})
	if _, e := NewBroker(config); e == nil {
		t.Fatal("mismatched signing key accepted")
	}
	config = base
	config.PrivateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if _, e := NewBroker(config); e != nil {
		t.Fatal("valid signing pair refused", e)
	}
}
func TestNodeScopesAndRequiredIntegerResourceClaimsAreRechecked(t *testing.T) {
	b, _, key := brokerFixture(t)
	r := nodeReq()
	original, e := b.IssueNode(r)
	if e != nil {
		t.Fatal(e)
	}
	validator := func(context.Context, NodePrincipal) (bool, error) { return true, nil }
	for _, scope := range []string{"start start", "start unknown", " start", "start ", ""} {
		c := unsignedClaims(t, original)
		c["scope"] = scope
		_, e = b.AuthenticateNode(context.Background(), "Bearer "+resign(t, key, c, nil), r.CertificateThumbprint, validator)
		assertCode(t, e, 401, "invalid_access_token")
	}
	for _, value := range []any{json.Number("1.0"), json.Number("1e3"), true, int64(0), int64(-1)} {
		c := unsignedClaims(t, original)
		resources := c["resources"].(map[string]any)
		resources["cpu_millicores"] = value
		_, e = b.AuthenticateNode(context.Background(), "Bearer "+resign(t, key, c, nil), r.CertificateThumbprint, validator)
		assertCode(t, e, 401, "invalid_access_token")
	}
}
