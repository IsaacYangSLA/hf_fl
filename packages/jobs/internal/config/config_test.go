package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func lookup(values map[string]string) Lookup {
	return func(k string) (string, bool) { v, ok := values[k]; return v, ok }
}
func databaseEnv() map[string]string {
	return map[string]string{"HF2L_JOBS_DATABASE_URL": "sqlite:///:memory:"}
}
func TestAliasesAndStrictEnvironment(t *testing.T) {
	m := databaseEnv()
	m["JOBS_DATABASE_URL"] = "postgresql://different/db"
	if _, e := FromEnv(lookup(m), "", "database"); e == nil {
		t.Fatal("conflicting aliases accepted")
	}
	delete(m, "JOBS_DATABASE_URL")
	for _, v := range []string{"true ", "yes", "2", ""} {
		m["HF2L_JOBS_ALLOW_LOCAL_HTTP"] = v
		if _, e := FromEnv(lookup(m), "", "database"); e == nil {
			t.Fatalf("invalid Boolean %q", v)
		}
	}
	delete(m, "HF2L_JOBS_ALLOW_LOCAL_HTTP")
	for _, v := range []string{"0", "61", "15.0", "999999999999999999999"} {
		m["HF2L_JOBS_GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS"] = v
		if _, e := FromEnv(lookup(m), "", "database"); e == nil {
			t.Fatalf("invalid timeout %q", v)
		}
	}
}
func TestServerRequiresDistinctSecretsAndOIDC(t *testing.T) {
	m := databaseEnv()
	m["HF2L_JOBS_OIDC_ISSUER"] = "https://identity.example/realm"
	m["HF2L_JOBS_OIDC_CLIENT_ID"] = "dashboard"
	m["HF2L_JOBS_OIDC_REDIRECT_URI"] = "https://manager.example/auth/callback"
	m["HF2L_JOBS_CURSOR_SECRET"] = strings.Repeat("a", 32)
	m["HF2L_JOBS_SESSION_SECRET"] = strings.Repeat("a", 32)
	if _, e := FromEnv(lookup(m), "", "server"); e == nil {
		t.Fatal("identical secrets accepted")
	}
	m["HF2L_JOBS_SESSION_SECRET"] = strings.Repeat("b", 32)
	s, e := FromEnv(lookup(m), "", "server")
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(s.String(), m["HF2L_JOBS_SESSION_SECRET"]) {
		t.Fatal("String leaks secrets")
	}
	m["HF2L_JOBS_OIDC_ISSUER"] = "http://remote.example/realm"
	if _, e = FromEnv(lookup(m), "", "server"); e == nil {
		t.Fatal("remote plaintext issuer accepted")
	}
}
func TestTLSAndEndpointTrust(t *testing.T) {
	for _, v := range []string{"http://remote.example", "https://user:secret@host", "https://host/#fragment", "file:///etc/passwd", "https:///missing"} {
		if RequireTLS(v, true) == nil {
			t.Fatalf("unsafe endpoint %s", v)
		}
	}
	for _, v := range []string{"http://localhost:9000", "http://127.0.0.1:9000", "http://[::1]:9000"} {
		if e := RequireTLS(v, true); e != nil {
			t.Fatal(e)
		}
		if RequireTLS(v, false) == nil {
			t.Fatal("plaintext accepted without optin")
		}
	}
	s := OIDCSettings{Issuer: "https://id.example/realm", ClientID: "client", RedirectURI: "https://jobs.example/auth/callback", Audience: "jobs", TimeoutSeconds: 5, JWKSCacheSeconds: 300}
	if s.ValidateEndpoint("https://untrusted.example/jwks") == nil {
		t.Fatal("untrusted endpoint accepted")
	}
	s.EndpointOrigins = []string{"https://keys.example"}
	if e := s.ValidateEndpoint("https://keys.example/jwks"); e != nil {
		t.Fatal(e)
	}
	s.EndpointOrigins = []string{"https://keys.example/"}
	if s.Validate() == nil {
		t.Fatal("nonexact origin accepted")
	}
}
func TestPrivateFilesAndDuplicateJSON(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if e := os.WriteFile(secret, []byte(" value \n"), 0600); e != nil {
		t.Fatal(e)
	}
	v, e := ReadSecret(secret)
	if e != nil || v != "value" {
		t.Fatal(v, e)
	}
	if e = os.Chmod(secret, 0640); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadSecret(secret); e == nil {
		t.Fatal("group readable secret accepted")
	}
	if e = os.Chmod(secret, 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(dir, "link")
	if e = os.Symlink(secret, link); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadSecret(link); e == nil {
		t.Fatal("secret symlink accepted")
	}
	parent := filepath.Join(dir, "parent")
	if e = os.Symlink(dir, parent); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadSecret(filepath.Join(parent, "secret")); e == nil {
		t.Fatal("parent symlink accepted")
	}
	hard := filepath.Join(dir, "hard")
	if e = os.Link(secret, hard); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadSecret(secret); e == nil {
		t.Fatal("hard linked secret accepted")
	}
	for _, raw := range []string{`{"service":{},"service":{}}`, `{"service":{"port":1,"port":2}}`, `[]`, `{} {}`, `{"service":NaN}`} {
		if _, e = DecodeJSON([]byte(raw)); e == nil {
			t.Fatalf("invalid JSON accepted %s", raw)
		}
	}
	data, e := DecodeJSON([]byte(`{"service":{"port":8082}}`))
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := data["service"].(map[string]any)["port"].(json.Number); !ok {
		t.Fatal("numeric type lost")
	}
}
func TestOperationalSectionsAndBounds(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	m := databaseEnv()
	for _, raw := range []string{`{"unexpected":{}}`, `{"service":[]}`, `{"service":null}`} {
		if e := os.WriteFile(p, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := FromEnv(lookup(m), p, "database"); e == nil {
			t.Fatalf("invalid sections accepted %s", raw)
		}
	}
	if e := os.WriteFile(p, []byte(`{"service":{"host":"127.0.0.1","port":8082}}`), 0600); e != nil {
		t.Fatal(e)
	}
	s, e := FromEnv(lookup(m), p, "database")
	if e != nil {
		t.Fatal(e)
	}
	section, e := s.Section("service", true)
	if e != nil {
		t.Fatal(e)
	}
	if e = Keys(section, []string{"host"}, []string{"port"}); e != nil {
		t.Fatal(e)
	}
	section["unknown"] = true
	if Keys(section, []string{"host"}, []string{"port"}) == nil {
		t.Fatal("unknown field accepted")
	}
	for _, v := range []any{json.Number("1.0"), json.Number("1e0"), true, "1", float64(1)} {
		if _, e := Int(v, 0, 10); e == nil {
			t.Fatalf("noninteger accepted %T", v)
		}
	}
}

func TestOIDCRejectsNonFiniteTimeout(t *testing.T) {
	m := databaseEnv()
	for _, v := range []string{"NaN", "+Inf", "-Inf"} {
		m["HF2L_JOBS_OIDC_TIMEOUT_SECONDS"] = v
		if _, e := FromEnv(lookup(m), "", "database"); e == nil {
			t.Fatalf("nonfinite timeout accepted %q", v)
		}
	}
}

func TestWorkloadPolicyAppliesToStandaloneCommands(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	public := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	base, e := FromEnv(lookup(databaseEnv()), "", "database")
	if e != nil {
		t.Fatal(e)
	}
	valid := WorkloadSettings{Issuer: "urn:hf2l:workloads", ExchangeAudience: "exchange-managed", GatewayAudience: "hf2l-transfer", NodeAudience: "hf2l-nodes", PublicKey: public, KeyID: "key-v1"}
	base.Workload = &valid
	if e = base.Validate("database"); e != nil {
		t.Fatal(e)
	}
	cases := map[string]func(*WorkloadSettings){
		"duplicate_gateway_audience": func(w *WorkloadSettings) { w.GatewayAudience = w.ExchangeAudience },
		"duplicate_node_audience":    func(w *WorkloadSettings) { w.NodeAudience = w.GatewayAudience },
		"issuer_control":             func(w *WorkloadSettings) { w.Issuer = "urn:hf2l\nworkloads" },
		"audience_space":             func(w *WorkloadSettings) { w.NodeAudience = "two audiences" },
		"issuer_bound":               func(w *WorkloadSettings) { w.Issuer = strings.Repeat("a", 2049) },
		"key_id":                     func(w *WorkloadSettings) { w.KeyID = "../private" },
		"invalid_public_key":         func(w *WorkloadSettings) { w.PublicKey = "unparsed-key" },
		"invalid_private_key":        func(w *WorkloadSettings) { w.PrivateKey = "unparsed-private-key" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w := valid
			mutate(&w)
			settings := base
			settings.Workload = &w
			if e := settings.Validate("database"); e == nil {
				t.Fatal("standalone configuration accepted invalid workload policy")
			}
		})
	}
}
