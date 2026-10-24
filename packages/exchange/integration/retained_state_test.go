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

// TestRetainedStatePythonAndGo swaps implementations over the same owned
// database and provider state. Python is an offline reference, never a bridge
// used by a running native Exchange process.
func TestRetainedStatePythonAndGo(t *testing.T) {
	config := os.Getenv("HF2L_GO_EXCHANGE_RETAINED_CONFIG")
	if config == "" {
		config = os.Getenv("HF2L_GO_EXCHANGE_SDK_CONFIG")
	}
	python := os.Getenv("HF2L_GO_EXCHANGE_RETAINED_PYTHON")
	if python == "" {
		python = os.Getenv("HF2L_GO_EXCHANGE_SDK_PYTHON")
	}
	if config == "" || python == "" {
		t.Skip("set HF2L_GO_EXCHANGE_RETAINED_CONFIG and HF2L_GO_EXCHANGE_RETAINED_PYTHON for owned retained-state acceptance")
	}
	var settings struct {
		Root string `json:"root"`
	}
	raw, err := os.ReadFile(config)
	if err != nil || json.Unmarshal(raw, &settings) != nil || settings.Root == "" {
		t.Fatal("retained-state configuration is unavailable")
	}
	if !filepath.IsAbs(settings.Root) {
		t.Fatal("retained-state evidence root must be absolute")
	}
	if err = os.MkdirAll(settings.Root, 0700); err != nil {
		t.Fatal("private retained-state evidence root unavailable")
	}
	root, err := os.MkdirTemp(settings.Root, "retained-state-")
	if err != nil {
		t.Fatal("private retained-state evidence directory unavailable")
	}
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal("cannot secure retained-state evidence directory")
	}
	log, err := os.OpenFile(filepath.Join(root, "driver.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("private retained-state log unavailable")
	}
	defer log.Close()
	reportPath := filepath.Join(root, "result.json")
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, python, "retained_state.py", "--config", config, "--report", reportPath)
	command.Stdout, command.Stderr = log, log
	err = command.Run()
	var report struct {
		Status        string                     `json:"status"`
		Cases         map[string]json.RawMessage `json:"cases"`
		ErrorClass    string                     `json:"error_class"`
		ErrorCode     string                     `json:"error_code"`
		CleanupErrors []json.RawMessage          `json:"cleanup_errors"`
	}
	result, readErr := os.ReadFile(reportPath)
	if readErr != nil || json.Unmarshal(result, &report) != nil {
		t.Fatal("retained-state receipt missing; private authority/evidence must be preserved")
	}
	if err != nil || report.Status != "PASS" || len(report.Cases) != 2 || len(report.CleanupErrors) != 0 {
		t.Fatalf("retained-state acceptance failed: class=%s code=%s; private evidence=%s", report.ErrorClass, report.ErrorCode, root)
	}
	t.Log("Python↔Go retained-state initialization, idempotency, coordination, multipart and exact PUT receipt continuation passed")
}
