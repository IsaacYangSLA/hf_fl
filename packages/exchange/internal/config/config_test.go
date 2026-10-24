package config

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReferenceDefaults(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "reference-defaults.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	if err = json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	actual, err := json.Marshal(DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(actual, &got); err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if string(a) != string(w) {
		t.Fatalf("configuration default contract mismatch:\ngot%s\nwant%s", a, w)
	}
}
func TestRequireTLSBoundary(t *testing.T) {
	for _, tc := range []struct {
		raw       string
		local, ok bool
	}{
		{"https://service.example/realms/test", false, true},
		{"http://localhost:8000", false, false}, {"http://localhost:8000", true, true},
		{"http://127.8.4.2:8000", true, true}, {"http://[::1]:8000", true, true},
		{"http://testserver", true, true}, {"http://LOCALHOST", true, true},
		{"http://10.0.0.2", true, false}, {"http://example.com", true, false},
		{"https://user:secret@example.com", false, false}, {"https://example.com/#fragment", false, false},
		{"file:///tmp/file", true, false}, {"https:opaque", true, false}, {"https://", false, false},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			if (RequireTLS(tc.raw, tc.local) == nil) != tc.ok {
				t.Fatal("TLS boundary mismatch")
			}
		})
	}
}
func TestComponentConfigurationIsolation(t *testing.T) {
	t.Setenv("EXCHANGE_DATABASE_URL", "sqlite:///:memory:")
	t.Setenv("EXCHANGE_ISSUER", "invalid secret identity")
	t.Setenv("EXCHANGE_S3_ENDPOINT", "http://untrusted.invalid")
	t.Setenv("EXCHANGE_S3_ACCESS_KEY", "private-access")
	t.Setenv("EXCHANGE_WORKER_POLL_SECONDS", "not-a-number")
	if _, err := DatabaseFromEnv(); err != nil {
		t.Fatalf("database component read unrelated settings: %v", err)
	}
	if _, err := FromEnv("server"); err == nil {
		t.Fatal("server accepted invalid identity")
	}
	if _, err := StorageFromEnv(); err == nil {
		t.Fatal("storage accepted incomplete settings")
	}
}
func TestEnvironmentAndRetentionPrecedence(t *testing.T) {
	t.Setenv("EXCHANGE_WORKER_OPERATION_RETENTION_SECONDS", "900000")
	t.Setenv("EXCHANGE_OPERATION_RETENTION_SECONDS", "950000")
	t.Setenv("EXCHANGE_WORKER_EVENT_RETENTION_SECONDS", "2600000")
	t.Setenv("EXCHANGE_EVENT_RETENTION_SECONDS", "2700000")
	t.Setenv("EXCHANGE_WORKER_POLL_SECONDS", "2.5")
	s, err := WorkerFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if s.OperationRetentionSeconds != 950000 || s.EventRetentionSeconds != 2700000 || s.PollSeconds != 2.5 {
		t.Fatal("concise retention overrides lost")
	}
}
func TestPositiveFiniteDurations(t *testing.T) {
	for _, v := range []string{"NaN", "Inf", "-Inf", "1e999", "-1", "0", "0.5", "1e50"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("EXCHANGE_POOL_TIMEOUT", v)
			if _, err := DatabaseFromEnv(); err == nil {
				t.Fatal("accepted invalid duration")
			}
		})
	}
	for _, v := range []float64{math.NaN(), math.Inf(1), 0, -1, 1e100} {
		if _, err := Duration(v); err == nil {
			t.Fatal("duration conversion accepted overflow/nonpositive")
		}
	}
	if got, err := Duration(1.25); err != nil || got.Seconds() != 1.25 {
		t.Fatal("fractional duration lost")
	}
}
func TestConfigurationErrorsDoNotExposeValues(t *testing.T) {
	secret := "PRIVATE-value-with-token"
	for _, name := range []string{"POOL_SIZE", "POOL_TIMEOUT", "POOL_RECYCLE", "ALLOW_LOCAL_HTTP", "WORKER_BATCH_SIZE"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("EXCHANGE_"+name, secret)
			var err error
			switch name {
			case "ALLOW_LOCAL_HTTP":
				_, err = AuthFromEnv()
			case "WORKER_BATCH_SIZE":
				_, err = WorkerFromEnv()
			default:
				_, err = DatabaseFromEnv()
			}
			if err == nil || !IsError(err) {
				t.Fatal("configuration failure not typed")
			}
			if strings.Contains(fmt.Sprint(err), secret) {
				t.Fatal("secret configuration echoed")
			}
		})
	}
}
func TestAuthWorkloadConfiguration(t *testing.T) {
	s := DefaultAuth()
	s.Issuer = "https://identity.example/realm"
	s.PublicKey = "test-public-key"
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.WorkloadIssuer = "https://workloads.example"
	s.WorkloadPublicKey = "workload-public-key"
	s.TrustedBackendSecret = strings.Repeat("s", 32)
	s.ProvisioningPrincipalIDs = []string{strings.Repeat("a", 64)}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.WorkloadIssuer = s.Issuer
	if err := s.Validate(); err == nil {
		t.Fatal("workload issuer confused with human issuer")
	}
	s.WorkloadIssuer = "https://workloads.example"
	s.ProvisioningPrincipalIDs = []string{strings.Repeat("A", 64)}
	if err := s.Validate(); err == nil {
		t.Fatal("noncanonical managed principal accepted")
	}
}
func TestStorageConfiguration(t *testing.T) {
	s := DefaultStorage()
	s.Bucket = "fixture"
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*StorageSettings){
		func(s *StorageSettings) { s.AccessKey = "partial" },
		func(s *StorageSettings) { s.SessionToken = "partial" },
		func(s *StorageSettings) { s.Prefix = "one/../two" },
		func(s *StorageSettings) { s.Prefix = "/absolute" },
		func(s *StorageSettings) { s.PartSize = 5242879 },
		func(s *StorageSettings) { s.PartSize = 5368709121 },
		func(s *StorageSettings) { s.GrantSeconds = 3601 },
	} {
		copy := s
		mutate(&copy)
		if copy.Validate() == nil {
			t.Fatal("invalid storage configuration accepted")
		}
	}
}
func TestServerRetentionAndDraftBounds(t *testing.T) {
	s := DefaultSettings()
	s.Auth.Issuer = "https://identity.example"
	s.Auth.PublicKey = "public"
	s.Storage.Bucket = "fixture"
	if err := s.Validate("server"); err != nil {
		t.Fatal(err)
	}
	s.Worker.OperationRetentionSeconds = s.DraftSeconds + s.Storage.GrantSeconds + 86400
	if err := s.Validate("server"); err == nil {
		t.Fatal("retention too short for safe retry")
	}
	s.Worker = DefaultWorker()
	s.DraftSeconds = 604801
	if err := s.Validate("server"); err == nil {
		t.Fatal("unbounded draft accepted")
	}
}
func TestMalformedIntegerBooleanEnvironments(t *testing.T) {
	for _, v := range []string{"true", "1.0", "9223372036854775808", ""} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("EXCHANGE_POOL_SIZE", v)
			if _, err := DatabaseFromEnv(); err == nil {
				t.Fatal("noninteger/overflow accepted")
			}
		})
	}
	for _, v := range []string{"yes", "TRUE ", "-1", ""} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("EXCHANGE_ALLOW_LOCAL_HTTP", v)
			if _, err := AuthFromEnv(); err == nil {
				t.Fatal("invalid boolean accepted")
			}
		})
	}
}

func TestDiagnosticFormattingRedactsCredentials(t *testing.T) {
	secret := "private-runtime-credential"
	s := DefaultSettings()
	s.Database.URL = "postgresql://account:" + secret + "@db/private"
	s.Auth.PublicKey = secret
	s.Auth.TrustedBackendSecret = secret
	s.Storage.SecretKey = secret
	for _, v := range []any{s, s.Database, s.Auth, s.Storage} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, v), secret) {
				t.Fatal("configuration diagnostics leaked credentials")
			}
		}
	}
}
