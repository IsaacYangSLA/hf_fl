//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeHost struct {
	device  BackingDevice
	badPath string
	reject  bool
}

func (h *fakeHost) BackingDevice(path string) (BackingDevice, error) {
	if path == h.badPath {
		return BackingDevice{}, refused("unsupported_backing")
	}
	return h.device, nil
}
func (h *fakeHost) ValidateDevice(d BackingDevice) error {
	if h.reject || d != h.device {
		return refused("runtime_unhealthy")
	}
	return nil
}
func (h *fakeHost) Affinity(int) ([]int, error) { return []int{0, 1}, nil }

type linuxFixture struct {
	t                                          *testing.T
	e                                          *LinuxExecutor
	spec                                       ExecutionSpec
	profilePath, owned, daemon, runsc, sidecar string
	host                                       *fakeHost
	mu                                         sync.Mutex
	commands                                   [][]string
	created, running, removed, mounted, loop   bool
	starts                                     int
	mutation                                   func(*containerInspect)
	failInspect                                bool
	foreignMount                               string
}

func fixture(t *testing.T) *linuxFixture {
	t.Helper()
	root := t.TempDir()
	os.Chmod(root, 0700)
	owned := filepath.Join(root, "owned")
	if err := os.MkdirAll(owned, 0700); err != nil {
		t.Fatal(err)
	}
	f := &linuxFixture{t: t, owned: owned}
	f.host = &fakeHost{device: BackingDevice{"/dev/test-physical", 8, 0, "/sys/devices/test-physical"}}
	f.runsc = filepath.Join(owned, "runsc")
	f.sidecar = filepath.Join(owned, "sidecar")
	f.daemon = filepath.Join(owned, "daemon.json")
	for _, p := range []string{f.runsc, f.sidecar} {
		if err := os.WriteFile(p, []byte("pinned runtime"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := map[string]any{"runtimes": map[string]any{"runsc": map[string]any{"path": f.runsc, "runtimeArgs": []string{"--network=sandbox", "--host-uds=open"}}}}
	raw, _ := json.Marshal(config)
	os.WriteFile(f.daemon, raw, 0600)
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		uid = 65532
	}
	if gid == 0 {
		gid = 65532
	}
	p := QualificationProfile{Qualified: true, Runtime: "runsc", Network: "none", ProxyTransport: "unix", BoundedVolumes: "loop-ext4", RunscNetwork: "sandbox", RunscHostUDS: "open", OwnedRoot: owned, DockerCommand: []string{"test-docker"}, SystemCommand: []string{"test-system"}, SandboxUID: uid, SandboxGID: gid, DaemonConfig: f.daemon, DaemonConfigSHA256: sum(raw), DockerDataRoot: filepath.Join(owned, "docker"), ContainerdSocket: filepath.Join(owned, "containerd.sock"), DaemonUnit: "owned.service", RunscSHA256: sum([]byte("pinned runtime")), RuntimeFilesSHA256: map[string]string{f.sidecar: sum([]byte("pinned runtime"))}, BackingIOQualified: true, BackingDevices: []BackingDevice{f.host.device}}
	raw, _ = json.Marshal(p)
	f.profilePath = filepath.Join(owned, "profile.json")
	os.WriteFile(f.profilePath, raw, 0600)
	e, err := NewLinuxExecutor(f.profilePath, filepath.Join(owned, "executor"), WithRunner(RunnerFunc(f.run)), WithHostInspector(f.host))
	if err != nil {
		t.Fatal(err)
	}
	f.e = e
	e.SetLeaseGuard(func(ExecutionIdentity) bool { return true })
	source, state := filepath.Join(owned, "jobs", "job", "source"), filepath.Join(owned, "jobs", "job", "state")
	os.MkdirAll(source, 0700)
	os.MkdirAll(state, 0700)
	configPath := filepath.Join(owned, "jobs", "job", "runtime.json")
	os.WriteFile(configPath, []byte(`{"role":"build"}`), 0600)
	f.spec = ExecutionSpec{Identity: ExecutionIdentity{"job", "attempt", "owner", 1}, ImageDigest: "sha256:" + strings.Repeat("a", 64), SourcePath: source, StatePath: state, ConfigPath: configPath, Resources: ResourceLimits{CPUMillis: 1000, MemoryBytes: 128 << 20, DiskBytes: 36 << 20}, Role: "build", PoolID: "cpu", NodeID: "node"}.Defaults()
	return f
}
func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func (f *linuxFixture) run(_ context.Context, argv []string, _ time.Duration) (CommandResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commands = append(f.commands, append([]string(nil), argv...))
	if len(argv) < 2 {
		return CommandResult{}, fmt.Errorf("missing test operation")
	}
	if argv[0] == "test-docker" {
		switch argv[1] {
		case "info":
			b, _ := json.Marshal(map[string]any{"Runtimes": map[string]any{"runsc": map[string]any{}}, "CgroupVersion": "2", "DockerRootDir": filepath.Join(f.owned, "docker"), "Containerd": map[string]any{"Address": filepath.Join(f.owned, "containerd.sock")}})
			return CommandResult{Stdout: string(b)}, nil
		case "create":
			f.created = true
			return CommandResult{Stdout: strings.Repeat("b", 64)}, nil
		case "start":
			f.starts++
			f.running = true
			return CommandResult{}, nil
		case "stop":
			f.running = false
			return CommandResult{}, nil
		case "rm":
			f.removed = true
			return CommandResult{}, nil
		case "logs":
			return CommandResult{Stdout: "2026-10-23T10:00:00.000000001Z epoch complete\n"}, nil
		case "inspect":
			if f.failInspect {
				return CommandResult{ExitCode: 2, Stderr: "daemon unavailable"}, nil
			}
			if !f.created || f.removed {
				return CommandResult{ExitCode: 1, Stderr: "No such container: " + argv[len(argv)-1]}, nil
			}
			r, err := f.e.load(f.spec.Identity)
			if err != nil {
				return CommandResult{}, err
			}
			raw := f.container(r)
			if f.mutation != nil {
				f.mutation(&raw)
			}
			b, _ := json.Marshal([]containerInspect{raw})
			return CommandResult{Stdout: string(b)}, nil
		}
	}
	if argv[0] == "test-system" {
		switch argv[1] {
		case "systemctl":
			if contains(argv, "--property=Environment") {
				return CommandResult{Stdout: "GOMAXPROCS=2"}, nil
			}
			return CommandResult{Stdout: "11"}, nil
		case "readlink":
			if argv[2] == "/proc/1/ns/net" {
				return CommandResult{Stdout: "net:[1]"}, nil
			}
			return CommandResult{Stdout: "net:[11]"}, nil
		case "losetup":
			if contains(argv, "--find") {
				f.loop = true
				return CommandResult{Stdout: "/dev/loop123"}, nil
			}
			if contains(argv, "--detach") {
				f.loop = false
				return CommandResult{}, nil
			}
			loops := []map[string]any{}
			if f.loop {
				loops = append(loops, map[string]any{"name": "/dev/loop123", "back-file": filepath.Join(f.e.directory(f.spec.Identity), "state.ext4")})
			}
			b, _ := json.Marshal(map[string]any{"loopdevices": loops})
			return CommandResult{Stdout: string(b)}, nil
		case "findmnt":
			if f.foreignMount != "" {
				return CommandResult{Stdout: f.foreignMount}, nil
			}
			if f.mounted {
				return CommandResult{Stdout: "/dev/loop123"}, nil
			}
			return CommandResult{ExitCode: 1}, nil
		case "mount":
			f.mounted = true
			return CommandResult{}, nil
		case "umount":
			f.mounted = false
			return CommandResult{}, nil
		case "mkfs.ext4", "chown", "rmdir":
			return CommandResult{}, nil
		}
	}
	return CommandResult{}, fmt.Errorf("unexpected test command %q", argv)
}
func (f *linuxFixture) container(r *executionRecord) containerInspect {
	var raw containerInspect
	raw.ID = r.ContainerID
	raw.Image = r.Spec.ImageDigest
	if strings.Contains(raw.Image, "@") {
		raw.Image = "sha256:" + strings.Repeat("a", 64)
	}
	raw.Config.Image = r.Spec.ImageDigest
	s := r.Spec
	h := &raw.HostConfig
	h.Runtime = "runsc"
	h.NetworkMode = "none"
	h.ReadonlyRootfs = true
	h.Memory = s.Resources.MemoryBytes
	h.MemorySwap = s.Resources.MemoryBytes
	h.PidsLimit = s.Resources.PIDs
	h.NanoCpus = s.Resources.CPUMillis * 1000000
	h.ShmSize = 16777216
	h.Tmpfs = map[string]string{"/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777"}
	h.CapDrop = []string{"ALL"}
	h.SecurityOpt = []string{"no-new-privileges"}
	for _, d := range append(append([]string(nil), r.BackingIODevices...), r.LoopDevice) {
		h.BlkioDeviceReadBps = append(h.BlkioDeviceReadBps, struct {
			Path string
			Rate int64
		}{d, s.Resources.IOBPS})
		h.BlkioDeviceWriteBps = append(h.BlkioDeviceWriteBps, struct {
			Path string
			Rate int64
		}{d, s.Resources.IOBPS})
	}
	raw.Config.User = fmt.Sprintf("%d:%d", f.e.Profile.SandboxUID, f.e.Profile.SandboxGID)
	raw.Config.Entrypoint = []string{"python"}
	raw.Config.Cmd = s.Argv[1:]
	raw.Config.Labels = map[string]string{"hf2l.managed": "true", "hf2l.job_id": s.Identity.JobID, "hf2l.attempt_id": s.Identity.AttemptID, "hf2l.component_id": s.Identity.ComponentID, "hf2l.epoch": fmt.Sprint(s.Identity.Epoch)}
	raw.Mounts = append(raw.Mounts, struct {
		Type, Destination, Source string
		RW                        bool
	}{"bind", "/job/source", s.SourcePath, false}, struct {
		Type, Destination, Source string
		RW                        bool
	}{"bind", "/job/state", filepath.Join(f.e.directory(s.Identity), "state"), true})
	for _, mount := range []struct{ src, dst string }{{s.ProxyEndpoint, "/run/hf2l/proxy.sock"}, {s.ConfigPath, "/run/hf2l/runtime.json"}, {s.SecretPath, "/run/hf2l/secrets.json"}, {r.DatasetPath, "/job/data/data.npz"}, {s.BuildInputPath, "/job/build"}} {
		if mount.src != "" {
			raw.Mounts = append(raw.Mounts, struct {
				Type, Destination, Source string
				RW                        bool
			}{"bind", mount.dst, mount.src, false})
		}
	}
	raw.State.Running = f.running
	return raw
}
func hasCommand(f *linuxFixture, operation string) bool {
	for _, a := range f.commands {
		if len(a) > 1 && a[1] == operation {
			return true
		}
	}
	return false
}
func reserveFixture(t *testing.T, f *linuxFixture) {
	t.Helper()
	r, e := f.e.Reserve(context.Background(), f.spec)
	if e != nil || !r.Acknowledged {
		t.Fatalf("reserve: %v %#v", e, r)
	}
}
func TestCPUProfileRejectsUnsafeSpecs(t *testing.T) {
	f := fixture(t)
	for name, change := range map[string]func(*ExecutionSpec){
		"gpu": func(s *ExecutionSpec) { s.Resources.GPUs = 1 }, "pids": func(s *ExecutionSpec) { s.Resources.PIDs = 129 }, "io": func(s *ExecutionSpec) { s.Resources.IOBPS = (16 << 20) + 1 }, "image": func(s *ExecutionSpec) { s.ImageDigest = "latest" }, "argv": func(s *ExecutionSpec) { s.Argv = []string{"bash", "-c", "untrusted"} }, "profile": func(s *ExecutionSpec) { s.Profile = "plain-container" }, "build-proxy": func(s *ExecutionSpec) { s.ProxyEndpoint = "/foreign/socket" },
	} {
		t.Run(name, func(t *testing.T) {
			s := f.spec
			s.Argv = append([]string(nil), s.Argv...)
			change(&s)
			if s.Validate() == nil {
				t.Fatal("unsafe spec accepted")
			}
		})
	}
}
func TestStrictExecutionWireDefaultsAndNulls(t *testing.T) {
	f := fixture(t)
	raw, e := f.spec.Canonical()
	if e != nil {
		t.Fatal(e)
	}
	var good ExecutionSpec
	if e = json.Unmarshal(raw, &good); e != nil {
		t.Fatal(e)
	}
	var m map[string]any
	json.Unmarshal(raw, &m)
	for _, key := range []string{"config_path", "secret_path", "dataset_binding_id", "participant_id", "build_input_path"} {
		if key != "config_path" && m[key] != nil {
			t.Fatalf("%s should be null", key)
		}
	}
	for _, bad := range []string{`{"cpu_millis":1,"memory_bytes":1,"disk_bytes":1,"pids":0}`, `{"cpu_millis":1.0,"memory_bytes":1,"disk_bytes":1}`, `{"cpu_millis":1,"memory_bytes":1,"disk_bytes":1,"pids":null}`, `{"cpu_millis":1,"memory_bytes":1,"disk_bytes":1,"unknown":1}`} {
		var r ResourceLimits
		if json.Unmarshal([]byte(bad), &r) == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	m["argv"] = nil
	bad, _ := json.Marshal(m)
	if json.Unmarshal(bad, &good) == nil {
		t.Fatal("null argv accepted")
	}
}
func TestReservationIdempotencyAndUnsafeRecordRefusal(t *testing.T) {
	f := fixture(t)
	reserveFixture(t, f)
	if _, e := f.e.Reserve(context.Background(), f.spec); e != nil {
		t.Fatal(e)
	}
	changed := f.spec
	changed.Resources.MemoryBytes++
	if _, e := f.e.Reserve(context.Background(), changed); ErrorCode(e) != "reservation_conflict" {
		t.Fatalf("expected conflict got %v", e)
	}
	record := filepath.Join(f.e.directory(f.spec.Identity), "execution.json")
	os.Chmod(record, 0666)
	if _, e := f.e.Reserve(context.Background(), f.spec); ErrorCode(e) != "unsafe_root" {
		t.Fatalf("unsafe record adopted %v", e)
	}
}
func TestQualificationDetectsMutableRuntimeIdentity(t *testing.T) {
	for _, kind := range []string{"daemon", "binary", "permissions", "device"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture(t)
			switch kind {
			case "daemon":
				os.WriteFile(f.daemon, []byte("{}"), 0600)
			case "binary":
				os.WriteFile(f.runsc, []byte("changed"), 0600)
			case "permissions":
				os.Chmod(f.sidecar, 0666)
			case "device":
				f.host.reject = true
			}
			if f.e.QualifyHealth(context.Background()) == nil {
				t.Fatal("changed qualification accepted")
			}
		})
	}
}
func TestProfileRejectsRootUIDAndUnqualifiedIO(t *testing.T) {
	f := fixture(t)
	raw, _ := os.ReadFile(f.profilePath)
	var m map[string]any
	json.Unmarshal(raw, &m)
	for _, change := range []func(){func() { m["sandbox_uid"] = float64(0) }, func() { m["sandbox_uid"] = float64(1234); m["backing_io_qualified"] = false }} {
		change()
		raw, _ = json.Marshal(m)
		os.WriteFile(f.profilePath, raw, 0600)
		if _, e := NewLinuxExecutor(f.profilePath, f.e.Root, WithRunner(RunnerFunc(f.run)), WithHostInspector(f.host)); e == nil {
			t.Fatal("unsafe profile accepted")
		}
	}
}
func TestObservedOCIIsolationViolationsPreventLaunch(t *testing.T) {
	mutations := map[string]func(*containerInspect){
		"foreign-container-id":    func(r *containerInspect) { r.ID = strings.Repeat("c", 64) },
		"foreign-image-id":        func(r *containerInspect) { r.Image = "sha256:" + strings.Repeat("d", 64) },
		"foreign-image-reference": func(r *containerInspect) { r.Config.Image = "unapproved:latest" },
		"host-network":            func(r *containerInspect) { r.HostConfig.NetworkMode = "host" },
		"privileged":              func(r *containerInspect) { r.HostConfig.Privileged = true },
		"writable-root":           func(r *containerInspect) { r.HostConfig.ReadonlyRootfs = false },
		"foreign-mount":           func(r *containerInspect) { r.Mounts[0].Source = "/foreign/source" },
		"extra-volume":            func(r *containerInspect) { r.Config.Volumes = map[string]any{"/escape": map[string]any{}} },
		"root-user":               func(r *containerInspect) { r.Config.User = "0:0" },
		"wrong-label":             func(r *containerInspect) { r.Config.Labels["hf2l.job_id"] = "another" },
		"unbounded-io":            func(r *containerInspect) { r.HostConfig.BlkioDeviceReadBps = nil },
		"wrong-command":           func(r *containerInspect) { r.Config.Cmd = []string{"-c", "untrusted"} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			f := fixture(t)
			reserveFixture(t, f)
			f.mutation = mutate
			if _, e := f.e.Start(context.Background(), f.spec.Identity); e == nil {
				t.Fatal("unsafe OCI launched")
			}
			if f.starts != 0 {
				t.Fatal("runtime started before inspected approval")
			}
		})
	}
}
func TestExpiredLeasePreventsRuntimeLaunch(t *testing.T) {
	f := fixture(t)
	reserveFixture(t, f)
	f.e.SetLeaseGuard(func(ExecutionIdentity) bool { return false })
	if _, e := f.e.Start(context.Background(), f.spec.Identity); ErrorCode(e) != "lease_expired" {
		t.Fatal(e)
	}
	if f.starts != 0 {
		t.Fatal("expired runtime launched")
	}
}
func TestUnknownRuntimeCannotReleaseOrCollect(t *testing.T) {
	f := fixture(t)
	reserveFixture(t, f)
	if _, e := f.e.Start(context.Background(), f.spec.Identity); e != nil {
		t.Fatal(e)
	}
	f.failInspect = true
	if _, e := f.e.Release(context.Background(), f.spec.Identity); !IsUncertain(e) {
		t.Fatalf("unknown release %v", e)
	}
	if hasCommand(f, "rm") || hasCommand(f, "umount") {
		t.Fatal("unknown execution physically released")
	}
}
func TestActiveRuntimeCannotCollect(t *testing.T) {
	f := fixture(t)
	reserveFixture(t, f)
	if _, e := f.e.Start(context.Background(), f.spec.Identity); e != nil {
		t.Fatal(e)
	}
	if _, e := f.e.Collect(context.Background(), f.spec.Identity); ErrorCode(e) != "runtime_active" {
		t.Fatal(e)
	}
}
func TestForeignMountIsNeverUnmountedOrDetached(t *testing.T) {
	f := fixture(t)
	reserveFixture(t, f)
	r, _ := f.e.load(f.spec.Identity)
	image := filepath.Join(f.e.directory(f.spec.Identity), "state.ext4")
	file, _ := os.OpenFile(image, os.O_CREATE|os.O_WRONLY, 0600)
	file.Truncate(f.spec.Resources.DiskBytes)
	file.Close()
	r.Mounted = true
	r.LoopDevice = "/dev/loop123"
	f.e.save(r.Identity, r)
	f.foreignMount = "/dev/foreign"
	if _, e := f.e.Release(context.Background(), f.spec.Identity); !IsUncertain(e) {
		t.Fatalf("foreign mount accepted %v", e)
	}
	if hasCommand(f, "umount") || hasCommand(f, "--detach") {
		t.Fatal("foreign mount was touched")
	}
}
func TestPrivateMountPathsRejectLinksAndForeignSockets(t *testing.T) {
	f := fixture(t)
	target := filepath.Join(f.owned, "jobs", "job", "link")
	os.Symlink(f.spec.SourcePath, target)
	if f.e.trustedPath(target, "directory") == nil {
		t.Fatal("symlink accepted")
	}
	if f.e.trustedPath("/etc/passwd", "file") == nil {
		t.Fatal("foreign mount accepted")
	}
	socket := filepath.Join(f.owned, "other.sock")
	s := f.spec
	s.Role = "owner"
	s.ProxyEndpoint = socket
	if f.e.proxyPath(s) == nil {
		t.Fatal("unassigned socket accepted")
	}
}
func TestStoppedRetentionReleaseRestoreAndPurge(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	reserveFixture(t, f)
	if _, e := f.e.Start(ctx, f.spec.Identity); e != nil {
		t.Fatal(e)
	}
	output := filepath.Join(f.e.directory(f.spec.Identity), "state", "result.txt")
	if e := os.WriteFile(output, []byte("learned checkpoint fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := f.e.Stop(ctx, f.spec.Identity, 0); e != nil {
		t.Fatal(e)
	}
	files, e := f.e.Collect(ctx, f.spec.Identity)
	if e != nil {
		t.Fatal(e)
	}
	if len(files) != 2 {
		t.Fatalf("expected result+log got %+v", files)
	}
	data, e := f.e.ReadArtifact(ctx, f.spec.Identity, "result.txt", 1024)
	if e != nil || string(data) != "learned checkpoint fixture" {
		t.Fatalf("read %q %v", data, e)
	}
	if ok, e := f.e.Release(ctx, f.spec.Identity); e != nil || !ok {
		t.Fatalf("release %v %v", ok, e)
	}
	if _, e := os.Stat(filepath.Join(f.e.directory(f.spec.Identity), "state.ext4")); !os.IsNotExist(e) {
		t.Fatal("scratch image retained after release")
	}
	if data, e := os.ReadFile(filepath.Join(f.spec.StatePath, "result.txt")); e != nil || string(data) != "learned checkpoint fixture" {
		t.Fatalf("restart state %q %v", data, e)
	}
	if ok, e := f.e.Purge(ctx, f.spec.Identity); e != nil || !ok {
		t.Fatalf("purge %v %v", ok, e)
	}
	if _, e := f.e.ReadArtifact(ctx, f.spec.Identity, "result.txt", 1024); ErrorCode(e) != "artifact_unavailable" {
		t.Fatalf("purged artifact readable %v", e)
	}
}
func TestTelemetryRejectsForeignIdentityAndDuplicateKeys(t *testing.T) {
	f := fixture(t)
	reserveFixture(t, f)
	r, _ := f.e.load(f.spec.Identity)
	r.Mounted = true
	root := filepath.Join(f.e.directory(f.spec.Identity), "state")
	os.MkdirAll(root, 0700)
	valid := `{"schema_version":1,"job_id":"job","attempt_id":"attempt","component_id":"owner","epoch":1,"current_round":3,"phase":"training","readiness":"ready","metrics":{"accuracy":0.5}}`
	os.WriteFile(filepath.Join(root, "runtime-status.json"), []byte(valid), 0600)
	ob := RuntimeObservation{}
	f.e.runtimeProgress(r, &ob)
	if ob.CurrentRound == nil || *ob.CurrentRound != 3 || ob.Metrics["accuracy"] != 0.5 {
		t.Fatalf("valid telemetry ignored %+v", ob)
	}
	for _, bad := range []string{strings.Replace(valid, "\"job_id\":\"job\"", "\"job_id\":\"foreign\"", 1), strings.Replace(valid, "\"epoch\":1", "\"epoch\":2,\"epoch\":1", 1), strings.Replace(valid, "0.5", "1e101", 1)} {
		os.WriteFile(filepath.Join(root, "runtime-status.json"), []byte(bad), 0600)
		ob = RuntimeObservation{}
		f.e.runtimeProgress(r, &ob)
		if ob.CurrentRound != nil || len(ob.Details) > 0 {
			t.Fatalf("untrusted telemetry accepted %+v", ob)
		}
	}
}

func TestRetainedReadsRejectForeignLocatorAndChangedBytes(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	reserveFixture(t, f)
	if _, err := f.e.Start(ctx, f.spec.Identity); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(f.e.directory(f.spec.Identity), "state", "result.txt")
	os.WriteFile(output, []byte("private result"), 0600)
	if _, err := f.e.Stop(ctx, f.spec.Identity, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.e.Collect(ctx, f.spec.Identity); err != nil {
		t.Fatal(err)
	}
	record, err := f.e.load(f.spec.Identity)
	if err != nil {
		t.Fatal(err)
	}
	index := -1
	for n, item := range record.RetainedArtifacts {
		if item.Path == "result.txt" {
			index = n
		}
	}
	if index < 0 {
		t.Fatal("missing result")
	}
	original := record.RetainedArtifacts[index].Locator
	record.RetainedArtifacts[index].Locator = "/etc/passwd"
	if err = f.e.save(record.Identity, record); err != nil {
		t.Fatal(err)
	}
	if _, err = f.e.ReadArtifact(ctx, f.spec.Identity, "result.txt", 1024); ErrorCode(err) != "unsafe_output" {
		t.Fatalf("foreign locator accepted %v", err)
	}
	record.RetainedArtifacts[index].Locator = original
	f.e.save(record.Identity, record)
	os.Chmod(original, 0600)
	os.WriteFile(original, []byte("changed result"), 0600)
	if _, err = f.e.ReadArtifact(ctx, f.spec.Identity, "result.txt", 1024); ErrorCode(err) != "unsafe_output" {
		t.Fatalf("changed retained bytes accepted %v", err)
	}
}
func TestReleaseRefusesUnsafeRestartDestinationWithoutReleasingLedger(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	reserveFixture(t, f)
	if _, err := f.e.Start(ctx, f.spec.Identity); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(f.e.directory(f.spec.Identity), "state", "result.txt"), []byte("result"), 0600)
	if _, err := f.e.Stop(ctx, f.spec.Identity, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.e.Collect(ctx, f.spec.Identity); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(f.owned, "foreign.txt")
	os.WriteFile(foreign, []byte("untouched"), 0600)
	if err := os.Symlink(foreign, filepath.Join(f.spec.StatePath, "result.txt")); err != nil {
		t.Fatal(err)
	}
	if ok, err := f.e.Release(ctx, f.spec.Identity); err == nil || ok {
		t.Fatalf("unsafe restart destination released %v %v", ok, err)
	}
	data, _ := os.ReadFile(foreign)
	if string(data) != "untouched" {
		t.Fatal("foreign destination modified")
	}
	record, _ := f.e.load(f.spec.Identity)
	if record.State == "RELEASED" {
		t.Fatal("unsafe restart prematurely released ledger")
	}
}
func TestExecutionIdentityMatchesPythonGolden(t *testing.T) {
	id := ExecutionIdentity{"job", "attempt", "owner", 1}
	// SHA256 of Python json.dumps(asdict(id),sort_keys=True,separators=(",",":")).
	const expected = "41689b21b8e7c74987807c6046a6d7c6"
	if id.Key() != expected {
		t.Fatalf("identity drift got %s want %s", id.Key(), expected)
	}
}

func TestExecutionSpecCanonicalMatchesPythonASCIIWire(t *testing.T) {
	expected, err := os.ReadFile("testdata/execution_spec_python.json")
	if err != nil {
		t.Fatal(err)
	}
	spec := ExecutionSpec{Identity: ExecutionIdentity{"job", "attempt", "owner", 1}, ImageDigest: "sha256:" + strings.Repeat("a", 64), SourcePath: "/node/jobs/job/source/界<>&", StatePath: "/node/jobs/job/state", ConfigPath: "/node/jobs/job/runtime.json", Resources: ResourceLimits{CPUMillis: 1000, MemoryBytes: 128 << 20, DiskBytes: 36 << 20}, Role: "build", PoolID: "cpu", NodeID: "node"}.Defaults()
	actual, err := spec.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != strings.TrimSpace(string(expected)) {
		t.Fatalf("Python node ledger wire drift\ngot %s\nwant %s", actual, expected)
	}
}

func TestNodeReleaseRetriesPartialPhysicalCleanupWithoutFreeingDisk(t *testing.T) {
	for _, scenario := range []string{"detached-query-reply-lost", "loop-still-associated"} {
		t.Run(scenario, func(t *testing.T) {
			f := fixture(t)
			ctx := context.Background()
			agent, err := NewNodeAgent(f.e, filepath.Join(f.owned, "node.sqlite"), "node", "cpu", ResourceLimits{CPUMillis: 2000, MemoryBytes: 1 << 30, DiskBytes: 1 << 30})
			if err != nil {
				t.Fatal(err)
			}
			defer agent.Close()
			if _, err = agent.Reserve(ctx, f.spec); err != nil {
				t.Fatal(err)
			}
			if _, err = agent.Start(ctx, f.spec.Identity); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(f.e.directory(f.spec.Identity), "state", "checkpoint.bin"), []byte("retained checkpoint"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = agent.Stop(ctx, f.spec.Identity, 0); err != nil {
				t.Fatal(err)
			}
			if _, err = agent.Collect(ctx, f.spec.Identity); err != nil {
				t.Fatal(err)
			}
			initialCharge, err := agent.StorageUsageBytes(ctx)
			if err != nil || initialCharge <= 0 {
				t.Fatal("missing charged reservation")
			}
			detached := false
			allowProof := false
			f.e.runner = RunnerFunc(func(c context.Context, argv []string, timeout time.Duration) (CommandResult, error) {
				if len(argv) > 1 && argv[0] == "test-system" && argv[1] == "losetup" {
					if contains(argv, "--detach") {
						result, err := f.run(c, argv, timeout)
						detached = true
						if scenario == "loop-still-associated" && !allowProof {
							f.mu.Lock()
							f.loop = true
							f.mu.Unlock()
						}
						return result, err
					}
					if detached && contains(argv, "--associated") && !allowProof {
						return CommandResult{}, context.DeadlineExceeded
					}
				}
				return f.run(c, argv, timeout)
			})
			if ok, err := agent.Release(ctx, f.spec.Identity); ok || !IsUncertain(err) {
				t.Fatalf("partial cleanup confirmed %v/%v", ok, err)
			}
			receipt, err := f.e.load(f.spec.Identity)
			if err != nil {
				t.Fatal(err)
			}
			if receipt.State == "RELEASED" || receipt.Mounted || !receipt.ContainerRemoved || receipt.LoopDevice == "" || receipt.StateCopied {
				t.Fatal("unexpected durable partial cleanup boundary")
			}
			if _, err = os.Stat(filepath.Join(f.e.directory(f.spec.Identity), "state.ext4")); err != nil {
				t.Fatal("unconfirmed scratch bytes deleted")
			}
			if charge, err := agent.StorageUsageBytes(ctx); err != nil || charge != initialCharge {
				t.Fatal("partial cleanup prematurely released storage")
			}
			// Persistent uncertainty on a retry must retain both physical and ledger proof.
			if ok, err := agent.Release(ctx, f.spec.Identity); ok || !IsUncertain(err) {
				t.Fatalf("unproven retry confirmed %v/%v", ok, err)
			}
			allowProof = true
			if ok, err := agent.Release(ctx, f.spec.Identity); !ok || err != nil {
				t.Fatalf("proven retry failed %v/%v", ok, err)
			}
			if ok, err := agent.Release(ctx, f.spec.Identity); !ok || err != nil {
				t.Fatalf("confirmed retry not idempotent %v/%v", ok, err)
			}
			restored, err := os.ReadFile(filepath.Join(f.spec.StatePath, "checkpoint.bin"))
			if err != nil || string(restored) != "retained checkpoint" {
				t.Fatal("retained state not restored on retry")
			}
			receipt, err = f.e.load(f.spec.Identity)
			if err != nil || receipt.State != "RELEASED" || receipt.Mounted || receipt.LoopDevice != "" || !receipt.FixedVolumeDeleted || !receipt.StateCopied {
				t.Fatal("released receipt lacks physical cleanup proof")
			}
			if charge, err := agent.StorageUsageBytes(ctx); err != nil || charge != initialCharge {
				t.Fatal("release must retain disk quota until explicit purge")
			}
			if ok, err := agent.Purge(ctx, f.spec.Identity); !ok || err != nil {
				t.Fatalf("purge failed %v/%v", ok, err)
			}
			if charge, err := agent.StorageUsageBytes(ctx); err != nil || charge != 0 {
				t.Fatal("purge did not release disk accounting")
			}
		})
	}
}

func TestReleaseRecoversLostContainerRemovalReply(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	reserveFixture(t, f)
	if _, err := f.e.Start(ctx, f.spec.Identity); err != nil {
		t.Fatal(err)
	}
	if _, err := f.e.Stop(ctx, f.spec.Identity, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.e.Collect(ctx, f.spec.Identity); err != nil {
		t.Fatal(err)
	}
	lost := false
	f.e.runner = RunnerFunc(func(c context.Context, argv []string, timeout time.Duration) (CommandResult, error) {
		result, err := f.run(c, argv, timeout)
		if len(argv) > 1 && argv[0] == "test-docker" && argv[1] == "rm" && !lost {
			lost = true
			return CommandResult{}, context.DeadlineExceeded
		}
		return result, err
	})
	if ok, err := f.e.Release(ctx, f.spec.Identity); ok || !IsUncertain(err) {
		t.Fatalf("lost reply release %v/%v", ok, err)
	}
	if ok, err := f.e.Release(ctx, f.spec.Identity); !ok || err != nil {
		t.Fatalf("proven absent container did not recover %v/%v", ok, err)
	}
}

func TestNaturalCompletionLostRemovalStopAndReleaseRecover(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	reserveFixture(t, f)
	if _, err := f.e.Start(ctx, f.spec.Identity); err != nil {
		t.Fatal(err)
	}
	// A naturally exited worker still has its prior RUNNING durable receipt.
	f.mu.Lock()
	f.running = false
	f.mu.Unlock()
	if _, err := f.e.Collect(ctx, f.spec.Identity); err != nil {
		t.Fatal(err)
	}
	lost := false
	f.e.runner = RunnerFunc(func(c context.Context, argv []string, timeout time.Duration) (CommandResult, error) {
		result, err := f.run(c, argv, timeout)
		if len(argv) > 1 && argv[0] == "test-docker" && argv[1] == "rm" && !lost {
			lost = true
			return CommandResult{}, context.DeadlineExceeded
		}
		return result, err
	})
	if ok, err := f.e.Release(ctx, f.spec.Identity); ok || !IsUncertain(err) {
		t.Fatalf("lost reply release %v/%v", ok, err)
	}
	record, err := f.e.load(f.spec.Identity)
	if err != nil || record.State != "STOPPED" || !record.ContainerRemovalIntent || record.ContainerRemoved {
		t.Fatal("stopped and collected removal intent not durable")
	}
	if observation, err := f.e.Stop(ctx, f.spec.Identity, 0); err != nil || !observation.TerminationConfirmed {
		t.Fatalf("repeated stop could not prove removal: %+v/%v", observation, err)
	}
	if ok, err := f.e.Release(ctx, f.spec.Identity); !ok || err != nil {
		t.Fatalf("release after proven stop failed %v/%v", ok, err)
	}
}

func TestRemovalRecoveryRequiresExactBoundAbsence(t *testing.T) {
	for _, scenario := range []string{"no-intent", "invalid-id", "name-rebound", "id-still-present", "daemon-unavailable", "permission-denied", "incidental-absence-text"} {
		t.Run(scenario, func(t *testing.T) {
			f := fixture(t)
			ctx := context.Background()
			reserveFixture(t, f)
			if _, err := f.e.Start(ctx, f.spec.Identity); err != nil {
				t.Fatal(err)
			}
			if _, err := f.e.Stop(ctx, f.spec.Identity, 0); err != nil {
				t.Fatal(err)
			}
			if _, err := f.e.Collect(ctx, f.spec.Identity); err != nil {
				t.Fatal(err)
			}
			lost := false
			f.e.runner = RunnerFunc(func(c context.Context, argv []string, timeout time.Duration) (CommandResult, error) {
				result, err := f.run(c, argv, timeout)
				if len(argv) > 1 && argv[0] == "test-docker" && argv[1] == "rm" && !lost {
					lost = true
					return CommandResult{}, context.DeadlineExceeded
				}
				return result, err
			})
			if ok, err := f.e.Release(ctx, f.spec.Identity); ok || !IsUncertain(err) {
				t.Fatalf("lost reply release %v/%v", ok, err)
			}
			record, err := f.e.load(f.spec.Identity)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "no-intent" {
				record.ContainerRemovalIntent = false
			}
			if scenario == "invalid-id" {
				record.ContainerID = "not-an-immutable-id"
			}
			if err = f.e.save(record.Identity, record); err != nil {
				t.Fatal(err)
			}
			f.e.runner = RunnerFunc(func(c context.Context, argv []string, timeout time.Duration) (CommandResult, error) {
				if len(argv) > 1 && argv[0] == "test-docker" && argv[1] == "inspect" {
					target := argv[len(argv)-1]
					switch scenario {
					case "name-rebound":
						if target == record.Container {
							raw := f.container(record)
							raw.ID = strings.Repeat("d", 64)
							data, _ := json.Marshal([]containerInspect{raw})
							return CommandResult{Stdout: string(data)}, nil
						}
					case "id-still-present":
						if target == record.ContainerID {
							return CommandResult{Stdout: "[]"}, nil
						}
					case "daemon-unavailable":
						return CommandResult{ExitCode: 2, Stderr: "daemon unavailable"}, nil
					case "permission-denied":
						return CommandResult{ExitCode: 1, Stderr: "permission denied"}, nil
					case "incidental-absence-text":
						return CommandResult{ExitCode: 1, Stderr: "transport failed; No such object: " + target}, nil
					}
				}
				return f.run(c, argv, timeout)
			})
			if ok, err := f.e.Release(ctx, f.spec.Identity); ok || err == nil {
				t.Fatalf("unproven removal recovered %v/%v", ok, err)
			}
			record, err = f.e.load(f.spec.Identity)
			if err != nil || record.ContainerRemoved || record.State == "RELEASED" {
				t.Fatal("unproven absence changed durable receipt")
			}
			if hasCommand(f, "umount") || hasCommand(f, "--detach") {
				t.Fatal("unproven container absence caused physical cleanup")
			}
			if _, err = os.Stat(filepath.Join(f.e.directory(f.spec.Identity), "state.ext4")); err != nil {
				t.Fatal("unproven absence deleted scratch")
			}
		})
	}
}

func TestExactMissingContainerDiagnostics(t *testing.T) {
	target := "hf2l-test-bound-target"
	for _, prefix := range []string{"Error: No such object: ", "Error: No such container: ", "Error response from daemon: No such container: ", "No such container: "} {
		if !confirmedMissingContainer(CommandResult{ExitCode: 1, Stderr: prefix + target + "\n"}, target) {
			t.Fatal("known exact missing diagnostic rejected")
		}
	}
	for _, result := range []CommandResult{{ExitCode: 0, Stderr: "No such container: " + target}, {ExitCode: 2, Stderr: "No such container: " + target}, {ExitCode: 1, Stderr: "permission denied"}, {ExitCode: 1, Stderr: "No such container: " + target + "-other"}, {ExitCode: 1, Stderr: "transport failed: No such container: " + target}} {
		if confirmedMissingContainer(result, target) {
			t.Fatal("nonexact absence accepted")
		}
	}
}

func TestImmutableRepositoryReferenceMatchesContainerConfig(t *testing.T) {
	f := fixture(t)
	f.spec.ImageDigest = "registry.example.invalid/worker@sha256:" + strings.Repeat("c", 64)
	reserveFixture(t, f)
	if _, err := f.e.Start(context.Background(), f.spec.Identity); err != nil {
		t.Fatalf("immutable repository reference refused: %v", err)
	}
}
