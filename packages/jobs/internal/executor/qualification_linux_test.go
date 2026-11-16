//go:build linux

package executor

import (
	"context"
	"strings"
	"testing"
)

func TestQualificationAdapterProvesNativeLifecycleAndCleanup(t *testing.T) {
	f := fixture(t)
	f.host.badPath = "/dev/shm"
	f.mutation = func(raw *containerInspect) { raw.State.Running = false; raw.State.ExitCode = 1 }
	report, err := qualifyBackingIOAdapter(context.Background(), f.e, f.spec)
	if err != nil {
		t.Fatal(err)
	}
	if !report.CleanupConfirmed || len(report.Checks) != 5 || !f.removed || f.loop || f.mounted {
		t.Fatalf("incomplete proof or cleanup: %+v", report)
	}
	for _, check := range report.Checks {
		if !check.Passed {
			t.Fatalf("failed check %+v", check)
		}
	}
}

func TestQualificationWrongExitFailsAndStillReleasesResources(t *testing.T) {
	f := fixture(t)
	f.host.badPath = "/dev/shm"
	f.mutation = func(raw *containerInspect) { raw.State.Running = false; raw.State.ExitCode = 0 }
	report, err := qualifyBackingIOAdapter(context.Background(), f.e, f.spec)
	if err == nil || !strings.Contains(err.Error(), "adapter_fixed_isolated_command") {
		t.Fatalf("wrong exit accepted: %+v %v", report, err)
	}
	if report.CleanupConfirmed || !f.removed || f.loop || f.mounted {
		t.Fatalf("failure cleanup not conserved: %+v", report)
	}
}

func TestQualificationNonblockAcceptanceFailsBeforeReservation(t *testing.T) {
	f := fixture(t)
	report, err := qualifyBackingIOAdapter(context.Background(), f.e, f.spec)
	if err == nil || !strings.Contains(err.Error(), "adapter_unknown_nonblock_denied") {
		t.Fatalf("unknown backing accepted: %+v %v", report, err)
	}
	if f.created || f.loop || f.starts != 0 {
		t.Fatal("unsafe backing probe launched an execution")
	}
}
