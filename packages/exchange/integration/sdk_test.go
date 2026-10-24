package integration

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestPythonSDKAgainstNativeGoExchange uses the unchanged Python SDK and actual
// native Exchange listeners/worker, PostgreSQL, and versioned S3 storage.
func TestPythonSDKAgainstNativeGoExchange(t *testing.T) {
	config, python := os.Getenv("HF2L_GO_EXCHANGE_SDK_CONFIG"), os.Getenv("HF2L_GO_EXCHANGE_SDK_PYTHON")
	if config == "" || python == "" {
		t.Skip("set HF2L_GO_EXCHANGE_SDK_CONFIG and HF2L_GO_EXCHANGE_SDK_PYTHON for owned native service acceptance")
	}
	var settings struct {
		Root string `json:"root"`
	}
	raw, err := os.ReadFile(config)
	if err != nil || json.Unmarshal(raw, &settings) != nil || settings.Root == "" {
		t.Fatal("SDK integration configuration is unavailable")
	}
	if !filepath.IsAbs(settings.Root) {
		t.Fatal("SDK evidence root must be absolute")
	}
	if err = os.MkdirAll(settings.Root, 0700); err != nil {
		t.Fatal("private SDK evidence root unavailable")
	}
	root, err := os.MkdirTemp(settings.Root, "sdk-driver-")
	if err != nil {
		t.Fatal("private SDK evidence directory unavailable")
	}
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal("cannot secure SDK evidence directory")
	}
	log, err := os.OpenFile(filepath.Join(root, "driver.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("private SDK driver log unavailable")
	}
	defer log.Close()
	reportPath := filepath.Join(root, "result.json")
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, python, "verify_go_sdk.py", "--config", config, "--report", reportPath)
	command.Stdout, command.Stderr = log, log
	err = command.Run()
	var report struct {
		Status  string `json:"status"`
		Cleanup bool   `json:"cleanup_verified"`
		Checks  []struct {
			Name string `json:"name"`
		} `json:"checks"`
		Failure struct {
			Class string `json:"class"`
			Code  string `json:"code"`
		} `json:"failure"`
	}
	result, readErr := os.ReadFile(reportPath)
	if readErr != nil || json.Unmarshal(result, &report) != nil {
		t.Fatalf("SDK acceptance receipt missing; preserve private authority/evidence: %s", root)
	}
	if err != nil || report.Status != "PASS" || !report.Cleanup {
		t.Fatalf("SDK acceptance failed: class=%s code=%s; private evidence=%s",
			report.Failure.Class, report.Failure.Code, root)
	}
	observed := map[string]bool{}
	for _, check := range report.Checks {
		if observed[check.Name] {
			t.Fatal("duplicate SDK acceptance check")
		}
		observed[check.Name] = true
	}
	for _, name := range []string{
		"space_bootstrap_membership_idempotency",
		"full_schema_canonical_digest_huge_integer_draft_cas",
		"strict_http_error_and_precondition_contract",
		"sdk_zero_byte_multipart_publish_versioned_download",
		"sdk_pagination_event_visibility_revocation_and_explicit_purge",
		"reservation_quota_refusal",
		"fedavg_profile_coordinated_reference_and_fencing",
		"managed_ingress_certificate_bound_grant_revocation",
		"native_restart_retained_reference_and_immutable_record",
		"unchanged_python_sdk_no_python_exchange_server_modules",
	} {
		if !observed[name] {
			t.Fatalf("SDK acceptance omitted check %s", name)
		}
	}
	t.Log("Unchanged Python SDK passed native Go HTTPS/PG/S3, multipart/zero-byte, authorization, coordination, restart and physical cleanup acceptance")
}
