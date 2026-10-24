//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func openChecked(path string, directory, private bool) (*os.File, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\n\r\\") {
		return nil, refused("unsafe_mount")
	}
	components := strings.Split(path, "/")
	for _, c := range components {
		if c == "." || c == ".." {
			return nil, refused("unsafe_mount")
		}
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for n, c := range components {
		if c == "" {
			continue
		}
		last := n == len(components)-1
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if !last || directory {
			flags |= unix.O_DIRECTORY
		}
		next, e := unix.Openat(fd, c, flags, 0)
		unix.Close(fd)
		if e != nil {
			return nil, refused("unsafe_mount")
		}
		fd = next
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		unix.Close(fd)
		return nil, refused("unsafe_mount")
	}
	kind := st.Mode & unix.S_IFMT
	if (directory && kind != unix.S_IFDIR) || (!directory && (kind != unix.S_IFREG || st.Nlink != 1)) {
		unix.Close(fd)
		return nil, refused("unsafe_mount")
	}
	if private && (int(st.Uid) != os.Geteuid() || st.Mode&0077 != 0) {
		unix.Close(fd)
		return nil, refused("unsafe_mount")
	}
	return os.NewFile(uintptr(fd), path), nil
}
func readPrivateFile(path string, max int64, private bool) ([]byte, error) {
	f, err := openChecked(path, false, private)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Mode().Perm()&0022 != 0 || st.Size() > max {
		return nil, refused("unsafe_mount")
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, refused("unsafe_mount")
	}
	return data, nil
}
func writeAtomic(path string, value any) error {
	parent, err := openChecked(filepath.Dir(path), true, false)
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(path)
	if name == "." || name == ".." {
		return refused("unsafe_output")
	}
	if st, err := os.Lstat(path); err == nil {
		sys, ok := st.Sys().(*unix.Stat_t)
		_ = sys
		_ = ok
		if !st.Mode().IsRegular() {
			return refused("unsafe_output")
		}
		var meta unix.Stat_t
		if unix.Fstatat(int(parent.Fd()), name, &meta, unix.AT_SYMLINK_NOFOLLOW) != nil || meta.Nlink != 1 {
			return refused("unsafe_output")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary := "." + name + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	fd, err := unix.Openat(int(parent.Fd()), temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), temporary)
	defer func() { f.Close(); unix.Unlinkat(int(parent.Fd()), temporary, 0) }()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = unix.Renameat(int(parent.Fd()), temporary, int(parent.Fd()), name); err != nil {
		return err
	}
	return parent.Sync()
}
func (e *LinuxExecutor) directory(id ExecutionIdentity) string {
	return filepath.Join(e.Root, id.Key())
}
func (e *LinuxExecutor) withLock(id ExecutionIdentity, fn func() error) error {
	if err := id.Validate(); err != nil {
		return err
	}
	locks := filepath.Join(e.Root, "locks")
	if err := os.MkdirAll(locks, 0700); err != nil {
		return err
	}
	dir, err := openChecked(locks, true, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), id.Key()+".lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return refused("unsafe_root")
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || int(st.Uid) != os.Geteuid() || st.Mode&0077 != 0 {
		return refused("unsafe_root")
	}
	if err = unix.Flock(fd, unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	return fn()
}

type executionRecord struct {
	Identity               ExecutionIdentity   `json:"identity"`
	Spec                   ExecutionSpec       `json:"spec"`
	State                  string              `json:"state"`
	Container              string              `json:"container"`
	ContainerID            string              `json:"container_id,omitempty"`
	Mounted                bool                `json:"mounted"`
	LoopDevice             string              `json:"loop_device"`
	OwnedLoopDevices       []string            `json:"owned_loop_devices,omitempty"`
	BackingIODevices       []string            `json:"backing_io_devices,omitempty"`
	DatasetPath            string              `json:"dataset_path,omitempty"`
	Retained               bool                `json:"retained"`
	NeverStarted           bool                `json:"never_started,omitempty"`
	ContainerRemovalIntent bool                `json:"container_removal_intent,omitempty"`
	ContainerRemoved       bool                `json:"container_removed,omitempty"`
	DiskDeleted            bool                `json:"disk_deleted,omitempty"`
	FixedVolumeDeleted     bool                `json:"fixed_volume_deleted,omitempty"`
	ArtifactsCollected     bool                `json:"artifacts_collected,omitempty"`
	StateCopied            bool                `json:"state_copied,omitempty"`
	RetainedArtifacts      []CollectedArtifact `json:"retained_artifacts,omitempty"`
	RetainedBytes          int64               `json:"retained_bytes,omitempty"`
	CopyTempfiles          []string            `json:"copy_tempfiles,omitempty"`
}

func (e *LinuxExecutor) load(id ExecutionIdentity) (*executionRecord, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	recordPath := filepath.Join(e.directory(id), "execution.json")
	if _, err := os.Lstat(recordPath); os.IsNotExist(err) {
		return nil, refused("missing_reservation")
	} else if err != nil {
		return nil, refused("unsafe_root")
	}
	raw, err := readPrivateFile(recordPath, 8<<20, true)
	if err != nil {
		return nil, refused("unsafe_root")
	}
	var r executionRecord
	if json.Unmarshal(raw, &r) != nil || r.Identity != id || r.Spec.Identity != id || r.Container != "hf2l-"+id.Key() {
		return nil, refused("identity_mismatch")
	}
	if err := r.Spec.Validate(); err != nil {
		return nil, err
	}
	switch r.State {
	case "RESERVED", "PREPARING", "STARTING", "RUNNING", "STOPPED", "RELEASED":
	default:
		return nil, refused("invalid_execution_state")
	}
	return &r, nil
}
func (e *LinuxExecutor) save(id ExecutionIdentity, r *executionRecord) error {
	if r.Identity != id || r.Spec.Identity != id || r.Container != "hf2l-"+id.Key() {
		return refused("identity_mismatch")
	}
	return writeAtomic(filepath.Join(e.directory(id), "execution.json"), r)
}
func (e *LinuxExecutor) trustedPath(path, kind string) error {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, ",\x00\n\r\\") || !strings.HasPrefix(path, e.OwnedRoot+"/") {
		return refused("unsafe_mount")
	}
	if kind == "socket" {
		f, err := openChecked(filepath.Dir(path), true, false)
		if err != nil {
			return err
		}
		defer f.Close()
		var st unix.Stat_t
		if unix.Fstatat(int(f.Fd()), filepath.Base(path), &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Nlink != 1 {
			return refused("unsafe_proxy")
		}
		return nil
	}
	f, err := openChecked(path, kind == "directory", false)
	if err != nil {
		return err
	}
	return f.Close()
}
func (e *LinuxExecutor) datasetPath(ctx context.Context, s ExecutionSpec) (string, error) {
	if s.DatasetBindingID == "" {
		return "", nil
	}
	var b DatasetBinding
	var err error
	if e.datasetAuthorizer != nil {
		b, err = e.datasetAuthorizer(ctx, s.DatasetBindingID, s.Identity, s.ParticipantID)
		if err != nil {
			return "", err
		}
	} else {
		var ok bool
		b, ok = e.datasets[s.DatasetBindingID]
		if !ok || b.ParticipantID != s.ParticipantID || !contains(b.JobIDs, s.Identity.JobID) {
			return "", refused("dataset_not_approved")
		}
	}
	if b.Synthetic {
		return "", nil
	}
	if b.Path == "" {
		return "", refused("dataset_not_approved")
	}
	f, err := openChecked(b.Path, false, false)
	if err != nil {
		return "", refused("unsafe_dataset")
	}
	f.Close()
	return b.Path, nil
}
func (e *LinuxExecutor) proxyPath(s ExecutionSpec) error {
	if s.ProxyEndpoint == "" {
		return nil
	}
	if s.ProxyEndpoint != filepath.Join(e.OwnedRoot, "p", s.Identity.Key(), "s") {
		return refused("unsafe_proxy")
	}
	return nil
}
func (e *LinuxExecutor) Reserve(ctx context.Context, s ExecutionSpec) (Reservation, error) {
	s = s.Defaults()
	if err := s.Validate(); err != nil {
		return Reservation{}, err
	}
	if err := e.QualifyHealth(ctx); err != nil {
		return Reservation{}, err
	}
	if err := e.proxyPath(s); err != nil {
		return Reservation{}, err
	}
	if _, err := e.datasetPath(ctx, s); err != nil {
		return Reservation{}, err
	}
	var result Reservation
	err := e.withLock(s.Identity, func() error {
		if old, err := e.load(s.Identity); err == nil {
			if !canonicalEqual(old.Spec, s) {
				return refused("reservation_conflict")
			}
			result = Reservation{s.Identity, true, s.NodeID, old.State}
			return nil
		} else if ErrorCode(err) != "missing_reservation" {
			return err
		}
		if s.Resources.DiskBytes < 36<<20 {
			return refused("invalid_resources")
		}
		dir := e.directory(s.Identity)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		f, err := openChecked(dir, true, true)
		if err != nil {
			return err
		}
		f.Close()
		r := &executionRecord{Identity: s.Identity, Spec: s, State: "RESERVED", Container: "hf2l-" + s.Identity.Key()}
		if err := e.save(s.Identity, r); err != nil {
			return err
		}
		result = Reservation{s.Identity, true, s.NodeID, "RESERVED"}
		return nil
	})
	return result, err
}
func (e *LinuxExecutor) ConfirmAbsent(ctx context.Context, id ExecutionIdentity) (bool, error) {
	absent := false
	err := e.withLock(id, func() error {
		if _, err := os.Lstat(e.directory(id)); !os.IsNotExist(err) {
			return nil
		}
		if err := e.QualifyHealth(ctx); err != nil {
			return err
		}
		container := "hf2l-" + id.Key()
		r, err := e.docker(ctx, []string{"inspect", "--type", "container", container}, false, true)
		if err != nil {
			return err
		}
		absent = r.ExitCode == 1 && (strings.Contains(r.Stderr, "No such object: "+container) || strings.Contains(r.Stderr, "No such container: "+container))
		return nil
	})
	return absent, err
}
func (e *LinuxExecutor) prepareVolume(ctx context.Context, id ExecutionIdentity, r *executionRecord) (string, error) {
	dir := e.directory(id)
	image := filepath.Join(dir, "state.ext4")
	mount := filepath.Join(dir, "state")
	if err := os.MkdirAll(mount, 0700); err != nil {
		return "", err
	}
	mf, err := openChecked(mount, true, false)
	if err != nil {
		return "", err
	}
	mf.Close()
	if _, err := os.Lstat(image); os.IsNotExist(err) {
		fd, err := unix.Open(image, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if err != nil {
			return "", err
		}
		file := os.NewFile(uintptr(fd), image)
		err = file.Truncate(r.Spec.Resources.DiskBytes)
		if err == nil {
			err = file.Sync()
		}
		file.Close()
		if err != nil {
			return "", err
		}
		if _, err = e.system(ctx, []string{"mkfs.ext4", "-q", "-F", image}, false, false); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	} else {
		f, err := openChecked(image, false, true)
		if err != nil {
			return "", err
		}
		info, _ := f.Stat()
		f.Close()
		if info == nil || info.Size() != r.Spec.Resources.DiskBytes {
			return "", refused("unsafe_mount")
		}
	}
	if !r.Mounted {
		// Authoritatively recover an uncommitted loop/mount before allocating another.
		if err = e.reconcileVolume(ctx, id, r); err != nil {
			return "", err
		}
		if r.LoopDevice == "" {
			result, err := e.system(ctx, []string{"losetup", "--find", "--show", image}, true, false)
			if err != nil {
				return "", err
			}
			loop := strings.TrimSpace(result.Stdout)
			if !loopDevice.MatchString(loop) {
				return "", uncertain(nil)
			}
			r.LoopDevice = loop
			if err = e.save(id, r); err != nil {
				return "", err
			}
		}
		if !r.Mounted {
			if _, err = e.system(ctx, []string{"mount", "-t", "ext4", "-o", "nodev,nosuid,noexec", r.LoopDevice, mount}, true, false); err != nil {
				return "", err
			}
			r.Mounted = true
			if err = e.save(id, r); err != nil {
				return "", err
			}
		}
		user := fmt.Sprintf("%d:%d", e.Profile.SandboxUID, e.Profile.SandboxGID)
		if _, err = e.system(ctx, []string{"chown", user, mount}, false, false); err != nil {
			return "", err
		}
		if _, err := os.Lstat(filepath.Join(mount, "lost+found")); err == nil {
			if _, err = e.system(ctx, []string{"rmdir", filepath.Join(mount, "lost+found")}, false, false); err != nil {
				return "", err
			}
		}
		if err = e.copyInitialState(ctx, r.Spec.StatePath, mount, r.Spec.Resources.DiskBytes/2, user); err != nil {
			return "", err
		}
	}
	return mount, nil
}
func (e *LinuxExecutor) Start(ctx context.Context, id ExecutionIdentity) (RuntimeObservation, error) {
	var obs RuntimeObservation
	err := e.withLock(id, func() error {
		if err := e.QualifyHealth(ctx); err != nil {
			return err
		}
		r, err := e.load(id)
		if err != nil {
			return err
		}
		if r.State == "RUNNING" || r.State == "STARTING" {
			obs, err = e.inspect(ctx, id)
			return err
		}
		if r.State != "RESERVED" && r.State != "PREPARING" {
			return refused("invalid_execution_state")
		}
		r.State = "PREPARING"
		if err = e.save(id, r); err != nil {
			return err
		}
		s := r.Spec
		for _, path := range []string{s.SourcePath, s.StatePath} {
			if err := e.trustedPath(path, "directory"); err != nil {
				return err
			}
			if !contains(strings.Split(path, "/"), id.JobID) {
				return refused("unsafe_mount")
			}
		}
		if err = e.proxyPath(s); err != nil {
			return err
		}
		if s.ProxyEndpoint != "" {
			if err = e.trustedPath(s.ProxyEndpoint, "socket"); err != nil {
				return err
			}
		}
		for _, path := range []string{s.ConfigPath, s.SecretPath} {
			if path != "" {
				if err = e.trustedPath(path, "file"); err != nil {
					return err
				}
			}
		}
		if s.SecretPath != "" && !contains(strings.Split(s.SecretPath, "/"), id.JobID) {
			return refused("unsafe_mount")
		}
		if s.BuildInputPath != "" {
			if err = e.trustedPath(s.BuildInputPath, "directory"); err != nil {
				return err
			}
			if !contains(strings.Split(s.BuildInputPath, "/"), id.JobID) {
				return refused("unsafe_mount")
			}
			if _, err = listSafeFiles(s.BuildInputPath, s.Resources.DiskBytes); err != nil {
				return err
			}
		}
		dataset, err := e.datasetPath(ctx, s)
		if err != nil {
			return err
		}
		r.DatasetPath = dataset
		devices, err := e.ioDevices(s, dataset)
		if err != nil {
			return err
		}
		r.BackingIODevices = devices
		if err = e.save(id, r); err != nil {
			return err
		}
		mount, err := e.prepareVolume(ctx, id, r)
		if err != nil {
			return err
		}
		if s.Role == "build" {
			raw, err := readPrivateFile(s.ConfigPath, 4<<20, false)
			if err != nil {
				return refused("invalid_invocation")
			}
			var m map[string]any
			if json.Unmarshal(raw, &m) != nil || m["role"] != "build" {
				return refused("invalid_invocation")
			}
		}
		args := e.createArgs(r, mount)
		r.State = "STARTING"
		if err = e.save(id, r); err != nil {
			return err
		}
		result, err := e.docker(ctx, args, true, false)
		if err != nil {
			return err
		}
		r.ContainerID = strings.TrimSpace(result.Stdout)
		if r.ContainerID == "" {
			return uncertain(nil)
		}
		if err = e.save(id, r); err != nil {
			return err
		}
		if err = e.verifyContainer(ctx, r); err != nil {
			return err
		}
		if !e.allowLaunch(id) {
			return refused("lease_expired")
		}
		if _, err = e.docker(ctx, []string{"start", r.Container}, true, false); err != nil {
			return err
		}
		r.State = "RUNNING"
		if err = e.save(id, r); err != nil {
			return err
		}
		obs, err = e.inspect(ctx, id)
		return err
	})
	return obs, err
}
func (e *LinuxExecutor) createArgs(r *executionRecord, mount string) []string {
	s := r.Spec
	lim := s.Resources
	user := fmt.Sprintf("%d:%d", e.Profile.SandboxUID, e.Profile.SandboxGID)
	rate := strconv.FormatInt(lim.IOBPS, 10)
	args := []string{"create", "--name", r.Container, "--runtime", "runsc", "--entrypoint", "python", "--workdir", "/job/state", "--network", "none", "--read-only", "--user", user, "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--cpus", strconv.FormatFloat(float64(lim.CPUMillis)/1000, 'f', 3, 64), "--memory", strconv.FormatInt(lim.MemoryBytes, 10), "--memory-swap", strconv.FormatInt(lim.MemoryBytes, 10), "--pids-limit", strconv.FormatInt(lim.PIDs, 10), "--shm-size", "16777216", "--ulimit", "nproc=64:64", "--device-read-bps", r.LoopDevice + ":" + rate, "--device-write-bps", r.LoopDevice + ":" + rate, "--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=3", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777", "--mount", "type=bind,src=" + s.SourcePath + ",dst=/job/source,readonly", "--mount", "type=bind,src=" + mount + ",dst=/job/state", "--env", "HF2L_STATE_DIR=/job/state", "--env", "HOME=/job/state/home", "--env", "OMP_NUM_THREADS=1", "--env", "OPENBLAS_NUM_THREADS=1"}
	add := func(src, dst string) {
		if src != "" {
			args = append(args, "--mount", "type=bind,src="+src+",dst="+dst+",readonly")
		}
	}
	add(s.ProxyEndpoint, "/run/hf2l/proxy.sock")
	if s.ProxyEndpoint != "" {
		args = append(args, "--env", "HF2L_PROXY_UDS=/run/hf2l/proxy.sock")
	}
	add(s.ConfigPath, "/run/hf2l/runtime.json")
	add(s.SecretPath, "/run/hf2l/secrets.json")
	add(r.DatasetPath, "/job/data/data.npz")
	add(s.BuildInputPath, "/job/build")
	for _, device := range r.BackingIODevices {
		args = append(args, "--device-read-bps", device+":"+rate, "--device-write-bps", device+":"+rate)
	}
	labels := map[string]string{"hf2l.managed": "true", "hf2l.job_id": s.Identity.JobID, "hf2l.attempt_id": s.Identity.AttemptID, "hf2l.component_id": s.Identity.ComponentID, "hf2l.epoch": strconv.FormatInt(s.Identity.Epoch, 10)}
	var keys []string
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--label", key+"="+labels[key])
	}
	return append(append(args, s.ImageDigest), s.Argv[1:]...)
}

type containerInspect struct {
	ID         string `json:"Id"`
	Image      string `json:"Image"`
	HostConfig struct {
		Runtime, NetworkMode                             string
		ReadonlyRootfs, Privileged                       bool
		Memory, MemorySwap, PidsLimit, NanoCpus, ShmSize int64
		Tmpfs                                            map[string]string
		CapDrop, CapAdd, SecurityOpt                     []string
		Devices                                          []json.RawMessage
		BlkioDeviceReadBps, BlkioDeviceWriteBps          []struct {
			Path string
			Rate int64
		}
		LogConfig struct {
			Type   string
			Config map[string]string
		}
		Ulimits []struct {
			Name       string
			Hard, Soft int64
		}
	}
	Config struct {
		Image                string
		User, WorkingDir     string
		Entrypoint, Cmd, Env []string
		Labels               map[string]string
		Volumes              map[string]any
	}
	Mounts []struct {
		Type, Destination, Source string
		RW                        bool
	}
	State struct {
		Running, OOMKilled bool
		ExitCode           int
	}
}

func (e *LinuxExecutor) readContainer(ctx context.Context, r *executionRecord) (containerInspect, error) {
	var list []containerInspect
	raw, err := e.docker(ctx, []string{"inspect", r.Container}, true, false)
	if err != nil {
		return containerInspect{}, err
	}
	if json.Unmarshal([]byte(raw.Stdout), &list) != nil || len(list) != 1 {
		return containerInspect{}, uncertain(nil)
	}
	return list[0], nil
}
func (e *LinuxExecutor) verifyContainer(ctx context.Context, r *executionRecord) error {
	raw, err := e.readContainer(ctx, r)
	if err != nil {
		return err
	}
	return e.validateContainer(r, raw)
}
func (e *LinuxExecutor) validateContainer(r *executionRecord, raw containerInspect) error {
	host, s := raw.HostConfig, r.Spec
	if r.ContainerID == "" || raw.ID != r.ContainerID || raw.Config.Image != s.ImageDigest || !strings.HasPrefix(raw.Image, "sha256:") || !imageDigest.MatchString(raw.Image) || (!strings.Contains(s.ImageDigest, "@") && raw.Image != s.ImageDigest) {
		return refused("identity_mismatch")
	}
	expectedIO := map[string]int64{}
	for _, d := range append(append([]string(nil), r.BackingIODevices...), r.LoopDevice) {
		expectedIO[d] = s.Resources.IOBPS
	}
	actualR, actualW := map[string]int64{}, map[string]int64{}
	for _, x := range host.BlkioDeviceReadBps {
		if _, ok := actualR[x.Path]; ok {
			return refused("unsafe_runtime")
		}
		actualR[x.Path] = x.Rate
	}
	for _, x := range host.BlkioDeviceWriteBps {
		if _, ok := actualW[x.Path]; ok {
			return refused("unsafe_runtime")
		}
		actualW[x.Path] = x.Rate
	}
	if !canonicalEqual(actualR, expectedIO) || !canonicalEqual(actualW, expectedIO) || host.Runtime != "runsc" || host.NetworkMode != "none" || !host.ReadonlyRootfs || host.Privileged || host.Memory != s.Resources.MemoryBytes || host.MemorySwap != s.Resources.MemoryBytes || host.PidsLimit != s.Resources.PIDs || host.NanoCpus != s.Resources.CPUMillis*1000000 || host.ShmSize != 16777216 || host.Tmpfs["/tmp"] != "rw,noexec,nosuid,nodev,size=16777216,mode=1777" || raw.Config.User != fmt.Sprintf("%d:%d", e.Profile.SandboxUID, e.Profile.SandboxGID) || !canonicalEqual(raw.Config.Entrypoint, []string{"python"}) || !canonicalEqual(raw.Config.Cmd, s.Argv[1:]) || !contains(host.CapDrop, "ALL") || len(host.CapAdd) > 0 || len(host.Devices) > 0 || len(raw.Config.Volumes) > 0 {
		return refused("unsafe_runtime")
	}
	nnp := false
	for _, x := range host.SecurityOpt {
		if x == "no-new-privileges" || x == "no-new-privileges=true" {
			nnp = true
		}
	}
	if !nnp {
		return refused("unsafe_runtime")
	}
	expected := map[string]any{"/job/source": []any{s.SourcePath, false}, "/job/state": []any{filepath.Join(e.directory(s.Identity), "state"), true}}
	for src, dst := range map[string]string{s.ProxyEndpoint: "/run/hf2l/proxy.sock", s.ConfigPath: "/run/hf2l/runtime.json", s.SecretPath: "/run/hf2l/secrets.json", r.DatasetPath: "/job/data/data.npz", s.BuildInputPath: "/job/build"} {
		if src != "" {
			expected[dst] = []any{src, false}
		}
	}
	actual := map[string]any{}
	for _, m := range raw.Mounts {
		if m.Type == "tmpfs" && m.Destination == "/tmp" {
			continue
		}
		if m.Type != "bind" {
			return refused("unsafe_mount")
		}
		if _, ok := actual[m.Destination]; ok {
			return refused("unsafe_mount")
		}
		actual[m.Destination] = []any{m.Source, m.RW}
	}
	if !canonicalEqual(actual, expected) {
		return refused("unsafe_mount")
	}
	labels := map[string]string{"hf2l.managed": "true", "hf2l.job_id": s.Identity.JobID, "hf2l.attempt_id": s.Identity.AttemptID, "hf2l.component_id": s.Identity.ComponentID, "hf2l.epoch": strconv.FormatInt(s.Identity.Epoch, 10)}
	for k, v := range labels {
		if raw.Config.Labels[k] != v {
			return refused("identity_mismatch")
		}
	}
	return nil
}

// confirmContainerRemoval recovers a lost remove reply only after a durable
// stopped-and-collected removal intent. Check both the job-bound name and the
// original immutable ID: a renamed or rebound container is never treated as gone.
func confirmedMissingContainer(result CommandResult, target string) bool {
	if result.ExitCode != 1 {
		return false
	}
	message := strings.TrimSpace(result.Stderr)
	return message == "Error: No such object: "+target ||
		message == "Error: No such container: "+target ||
		message == "Error response from daemon: No such container: "+target ||
		message == "No such container: "+target
}

func (e *LinuxExecutor) confirmContainerRemoval(ctx context.Context, r *executionRecord) (bool, error) {
	if !r.ContainerRemovalIntent || r.State != "STOPPED" || !r.ArtifactsCollected || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(r.ContainerID) {
		return false, uncertain(nil)
	}
	if err := e.QualifyHealth(ctx); err != nil {
		return false, err
	}
	for _, target := range []string{r.Container, r.ContainerID} {
		result, err := e.docker(ctx, []string{"inspect", "--type", "container", target}, true, true)
		if err != nil {
			return false, err
		}
		if result.ExitCode == 0 {
			return false, nil
		}
		if !confirmedMissingContainer(result, target) {
			return false, uncertain(nil)
		}
	}
	return true, nil
}

func (e *LinuxExecutor) Inspect(ctx context.Context, id ExecutionIdentity) (RuntimeObservation, error) {
	return e.inspect(ctx, id)
}
func (e *LinuxExecutor) inspect(ctx context.Context, id ExecutionIdentity) (RuntimeObservation, error) {
	r, err := e.load(id)
	if err != nil {
		return RuntimeObservation{}, err
	}
	if r.ContainerRemovalIntent && !r.ContainerRemoved {
		absent, err := e.confirmContainerRemoval(ctx, r)
		if err != nil {
			return RuntimeObservation{}, err
		}
		if absent {
			return RuntimeObservation{Identity: id, State: "STOPPED", TerminationConfirmed: true, PublicationStatus: "unknown", Details: map[string]any{}, Metrics: map[string]float64{}}, nil
		}
	}
	if r.NeverStarted || r.ContainerRemoved || r.State == "RESERVED" || r.State == "PREPARING" || r.State == "RELEASED" {
		return RuntimeObservation{Identity: id, State: r.State, TerminationConfirmed: true, PublicationStatus: "unknown", Details: map[string]any{}, Metrics: map[string]float64{}}, nil
	}
	raw, err := e.readContainer(ctx, r)
	if err != nil {
		return RuntimeObservation{}, err
	}
	if err = e.validateContainer(r, raw); err != nil {
		return RuntimeObservation{}, err
	}
	status := "STOPPED"
	if raw.State.Running {
		status = "RUNNING"
	}
	code := raw.State.ExitCode
	ob := RuntimeObservation{Identity: id, State: status, TerminationConfirmed: !raw.State.Running, PublicationStatus: "not_observed", ExitCode: &code, Details: map[string]any{}, Metrics: map[string]float64{}}
	if code == 4 {
		ob.ErrorCode = "publication_unknown"
		ob.PublicationStatus = "unknown"
	}
	if raw.State.OOMKilled {
		ob.ErrorCode = "oom_killed"
	}
	e.runtimeProgress(r, &ob)
	return ob, nil
}
func (e *LinuxExecutor) Stop(ctx context.Context, id ExecutionIdentity, graceSeconds int) (RuntimeObservation, error) {
	var ob RuntimeObservation
	err := e.withLock(id, func() error {
		r, err := e.load(id)
		if err != nil {
			return err
		}
		if r.ContainerRemovalIntent && !r.ContainerRemoved {
			absent, proofErr := e.confirmContainerRemoval(ctx, r)
			if proofErr != nil {
				return proofErr
			}
			if absent {
				r.ContainerRemoved = true
				if err = e.save(id, r); err != nil {
					return err
				}
			}
		}
		if r.State == "RELEASED" || r.ContainerRemoved {
			ob, err = e.inspect(ctx, id)
			return err
		}
		if r.State == "RESERVED" || r.State == "PREPARING" || r.NeverStarted {
			r.State = "STOPPED"
			r.NeverStarted = true
			if err = e.save(id, r); err != nil {
				return err
			}
			ob = RuntimeObservation{Identity: id, State: "STOPPED", TerminationConfirmed: true, PublicationStatus: "unknown"}
			return nil
		}
		if err = e.verifyContainer(ctx, r); err != nil {
			return err
		}
		if graceSeconds < 0 {
			graceSeconds = 0
		}
		if graceSeconds > 60 {
			graceSeconds = 60
		}
		if _, err = e.command(ctx, e.Profile.DockerCommand, []string{"stop", "--time", strconv.Itoa(graceSeconds), r.Container}, time.Duration(graceSeconds+15)*time.Second, true, false); err != nil {
			return err
		}
		ob, err = e.inspect(ctx, id)
		if err != nil {
			return err
		}
		if !ob.TerminationConfirmed {
			return uncertain(nil)
		}
		r.State = "STOPPED"
		return e.save(id, r)
	})
	return ob, err
}
