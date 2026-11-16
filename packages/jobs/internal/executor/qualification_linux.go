//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// QualificationBackingDevice uses the production physical-device inspector while
// deferring the backing-I/O admission gate that this qualification establishes.
// It does not reserve or launch an execution.
func QualificationBackingDevice(profilePath, root, path string) (BackingDevice, error) {
	e, err := NewLinuxExecutor(profilePath, root, WithDeferredQualification())
	if err != nil {
		return BackingDevice{}, err
	}
	device, err := e.host.BackingDevice(path)
	if err == nil {
		return device, nil
	}
	var metadata unix.Stat_t
	if statErr := unix.Stat(path, &metadata); !os.IsPermission(statErr) {
		return BackingDevice{}, err
	}
	// Image-layer paths are root-private. Inspect their filesystem number using
	// the profile's existing explicit trusted system prefix, then apply the
	// exact same physical-device checks as the production host inspector.
	raw, statErr := e.system(context.Background(), []string{"stat", "--format=%d", "--", path}, false, false)
	if statErr != nil {
		return BackingDevice{}, statErr
	}
	number, parseErr := strconv.ParseUint(strings.TrimSpace(raw.Stdout), 10, 64)
	if parseErr != nil {
		return BackingDevice{}, refused("unsupported_backing")
	}
	return physicalBackingDevice(number)
}

type QualificationCheck struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
}
type AdapterQualification struct {
	Checks           []QualificationCheck `json:"checks"`
	CleanupConfirmed bool                 `json:"cleanup_confirmed"`
}

// QualifyBackingIOAdapter exercises the native production executor against a
// fresh task-owned build execution. The invalid build manifest must exit 1;
// successful training is deliberately outside this isolation qualification.
func QualifyBackingIOAdapter(ctx context.Context, profilePath, root, image, jobID string) (out AdapterQualification, err error) {
	identity := ExecutionIdentity{JobID: jobID, AttemptID: "attempt-1", ComponentID: "build", Epoch: 1}
	if err = identity.Validate(); err != nil {
		return out, err
	}
	if !imageDigest.MatchString(image) {
		return out, refused("image_not_pinned")
	}
	e, err := NewLinuxExecutor(profilePath, filepath.Join(root, "adapter-executor"))
	if err != nil {
		return out, err
	}
	job := filepath.Join(root, jobID)
	if err = os.Mkdir(job, 0700); err != nil {
		return out, err
	}
	source, state := filepath.Join(job, "source"), filepath.Join(job, "state")
	if err = os.Mkdir(source, 0700); err != nil {
		return out, err
	}
	if err = os.Mkdir(state, 0700); err != nil {
		return out, err
	}
	config := filepath.Join(job, "runtime.json")
	if err = os.WriteFile(config, []byte(`{"role":"build"}`), 0600); err != nil {
		return out, err
	}
	spec := ExecutionSpec{Identity: identity, ImageDigest: image, SourcePath: source, StatePath: state,
		ConfigPath: config, Role: "build", Resources: ResourceLimits{CPUMillis: 500, MemoryBytes: 512 << 20, DiskBytes: 64 << 20, PIDs: 64}}.Defaults()
	// This one-shot trusted qualification owns exactly this identity. The finite
	// context bounds launch authority; production services use the node ledger.
	e.SetLeaseGuard(func(id ExecutionIdentity) bool { return id == identity && ctx.Err() == nil })
	return qualifyBackingIOAdapter(ctx, e, spec)
}

func qualifyBackingIOAdapter(ctx context.Context, e *LinuxExecutor, spec ExecutionSpec) (out AdapterQualification, err error) {
	check := func(name string, passed bool) error {
		out.Checks = append(out.Checks, QualificationCheck{name, passed})
		if !passed {
			return fmt.Errorf("qualification failed: %s", name)
		}
		return nil
	}
	expectedSet := map[string]bool{}
	for _, path := range []string{spec.SourcePath, e.Profile.DockerDataRoot} {
		d, deviceErr := e.host.BackingDevice(path)
		if deviceErr != nil {
			return out, deviceErr
		}
		expectedSet[d.Path] = true
	}
	expected := []string{}
	for path := range expectedSet {
		expected = append(expected, path)
	}
	sort.Strings(expected)
	actual, err := e.ioDevices(spec, "")
	if err != nil {
		return out, err
	}
	if err = check("adapter_derived_trusted_devices", reflect.DeepEqual(expected, actual)); err != nil {
		return out, err
	}
	_, denied := e.host.BackingDevice("/dev/shm")
	if err = check("adapter_unknown_nonblock_denied", ErrorCode(denied) == "unsupported_backing"); err != nil {
		return out, err
	}
	reserved := false
	defer func() {
		if !reserved {
			return
		}
		// Cleanup must still run after a probe timeout or caller cancellation.
		cleanup, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		_, stopErr := e.Stop(cleanup, spec.Identity, 1)
		released, releaseErr := e.Release(cleanup, spec.Identity)
		if stopErr != nil || releaseErr != nil || !released {
			err = errors.Join(err, fmt.Errorf("adapter resource cleanup unconfirmed: stop=%v release=%v released=%v", stopErr, releaseErr, released))
		}
	}()
	if _, err = e.Reserve(ctx, spec); err != nil {
		return out, err
	}
	reserved = true
	if _, err = e.Start(ctx, spec.Identity); err != nil {
		return out, err
	}
	until := time.Now().Add(30 * time.Second)
	var observation RuntimeObservation
	for {
		observation, err = e.Inspect(ctx, spec.Identity)
		if err != nil {
			return out, err
		}
		if observation.TerminationConfirmed {
			break
		}
		if time.Now().After(until) {
			return out, fmt.Errorf("adapter termination timed out")
		}
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	record, err := e.load(spec.Identity)
	if err != nil {
		return out, err
	}
	inspection, err := e.readContainer(ctx, record)
	if err != nil {
		return out, err
	}
	expectedCaps := map[string]int64{record.LoopDevice: 16 << 20}
	for _, path := range expected {
		expectedCaps[path] = 16 << 20
	}
	reads, writes := map[string]int64{}, map[string]int64{}
	duplicate := false
	for _, cap := range inspection.HostConfig.BlkioDeviceReadBps {
		if _, ok := reads[cap.Path]; ok {
			duplicate = true
		}
		reads[cap.Path] = cap.Rate
	}
	for _, cap := range inspection.HostConfig.BlkioDeviceWriteBps {
		if _, ok := writes[cap.Path]; ok {
			duplicate = true
		}
		writes[cap.Path] = cap.Rate
	}
	if err = check("adapter_actual_physical_and_loop_caps", !duplicate && reflect.DeepEqual(reads, expectedCaps) && reflect.DeepEqual(writes, expectedCaps)); err != nil {
		return out, err
	}
	fixed := inspection.HostConfig.Runtime == "runsc" && inspection.HostConfig.NetworkMode == "none" && reflect.DeepEqual(inspection.Config.Entrypoint, []string{"python"}) && reflect.DeepEqual(inspection.Config.Cmd, spec.Argv[1:]) && observation.TerminationConfirmed && observation.ExitCode != nil && *observation.ExitCode == 1
	if err = check("adapter_fixed_isolated_command", fixed); err != nil {
		return out, err
	}
	released, err := e.Release(ctx, spec.Identity)
	if err != nil {
		return out, err
	}
	backing, readErr := os.ReadFile(filepath.Join("/sys/block", filepath.Base(record.LoopDevice), "loop/backing_file"))
	loopAbsent := os.IsNotExist(readErr) || readErr == nil && strings.TrimPrefix(strings.TrimSpace(string(backing)), "/") != strings.TrimPrefix(filepath.Join(e.directory(spec.Identity), "state.ext4"), "/")
	_, diskErr := os.Lstat(filepath.Join(e.directory(spec.Identity), "state.ext4"))
	absent, proofErr := e.docker(ctx, []string{"inspect", record.Container}, false, true)
	confirmed := released && loopAbsent && os.IsNotExist(diskErr) && proofErr == nil && confirmedMissingContainer(absent, record.Container)
	if err = check("adapter_confirmed_resource_cleanup", confirmed); err != nil {
		return out, err
	}
	out.CleanupConfirmed = true
	reserved = false
	return out, nil
}
