//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type CommandResult struct {
	Stdout, Stderr string
	ExitCode       int
}
type Runner interface {
	Run(context.Context, []string, time.Duration) (CommandResult, error)
}
type RunnerFunc func(context.Context, []string, time.Duration) (CommandResult, error)

func (f RunnerFunc) Run(c context.Context, a []string, t time.Duration) (CommandResult, error) {
	return f(c, a, t)
}

type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > w.limit-w.Len() {
		return 0, fmt.Errorf("command output exceeds bound")
	}
	return w.Buffer.Write(p)
}

type CommandRunner struct{}

func (CommandRunner) Run(ctx context.Context, argv []string, timeout time.Duration) (CommandResult, error) {
	if len(argv) == 0 {
		return CommandResult{}, fmt.Errorf("empty command")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, errout := &boundedOutput{limit: 8 << 20}, &boundedOutput{limit: 8 << 20}
	cmd.Stdout = out
	cmd.Stderr = errout
	err := cmd.Run()
	result := CommandResult{Stdout: out.String(), Stderr: errout.String()}
	if err != nil {
		if x, ok := err.(*exec.ExitError); ok && ctx.Err() == nil {
			result.ExitCode = x.ExitCode()
			return result, nil
		}
		return result, err
	}
	return result, nil
}

type BackingDevice struct {
	Path      string `json:"path"`
	Major     int64  `json:"major"`
	Minor     int64  `json:"minor"`
	SysfsPath string `json:"sysfs_path"`
}
type HostInspector interface {
	BackingDevice(string) (BackingDevice, error)
	ValidateDevice(BackingDevice) error
	Affinity(int) ([]int, error)
}
type LinuxHostInspector struct{}

func (LinuxHostInspector) Affinity(pid int) ([]int, error) {
	var cpus unix.CPUSet
	if e := unix.SchedGetaffinity(pid, &cpus); e != nil {
		return nil, e
	}
	var out []int
	for i := 0; i < len(cpus)*64; i++ {
		if cpus.IsSet(i) {
			out = append(out, i)
		}
	}
	return out, nil
}
func (LinuxHostInspector) BackingDevice(path string) (BackingDevice, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return BackingDevice{}, refused("unsupported_backing")
	}
	sys, err := filepath.EvalSymlinks(fmt.Sprintf("/sys/dev/block/%d:%d", unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev))))
	if err != nil || !strings.HasPrefix(sys, "/sys/devices/") {
		return BackingDevice{}, refused("unsupported_backing")
	}
	for {
		if _, err := os.Stat(filepath.Join(sys, "partition")); os.IsNotExist(err) {
			break
		}
		sys = filepath.Dir(sys)
	}
	name := filepath.Base(sys)
	for _, p := range []string{"loop", "ram", "zram", "dm-"} {
		if strings.HasPrefix(name, p) {
			return BackingDevice{}, refused("unsupported_backing")
		}
	}
	if entries, err := os.ReadDir(filepath.Join(sys, "slaves")); err == nil && len(entries) > 0 {
		return BackingDevice{}, refused("unsupported_backing")
	}
	raw, err := os.ReadFile(filepath.Join(sys, "dev"))
	if err != nil {
		return BackingDevice{}, refused("unsupported_backing")
	}
	parts := strings.Split(strings.TrimSpace(string(raw)), ":")
	if len(parts) != 2 {
		return BackingDevice{}, refused("unsupported_backing")
	}
	major, e1 := strconv.ParseInt(parts[0], 10, 32)
	minor, e2 := strconv.ParseInt(parts[1], 10, 32)
	if e1 != nil || e2 != nil {
		return BackingDevice{}, refused("unsupported_backing")
	}
	device := BackingDevice{filepath.Join("/dev", name), major, minor, sys}
	if err := (LinuxHostInspector{}).ValidateDevice(device); err != nil {
		return BackingDevice{}, err
	}
	return device, nil
}
func (LinuxHostInspector) ValidateDevice(d BackingDevice) error {
	if d.Major < 0 || d.Minor < 0 {
		return refused("unqualified_profile")
	}
	sys, e := filepath.EvalSymlinks(fmt.Sprintf("/sys/dev/block/%d:%d", d.Major, d.Minor))
	if e != nil || sys != d.SysfsPath || !strings.HasPrefix(sys, "/sys/devices/") || d.Path != filepath.Join("/dev", filepath.Base(sys)) {
		return refused("runtime_unhealthy")
	}
	if _, e := os.Stat(filepath.Join(sys, "partition")); !os.IsNotExist(e) {
		return refused("runtime_unhealthy")
	}
	raw, e := os.ReadFile(filepath.Join(sys, "dev"))
	if e != nil || strings.TrimSpace(string(raw)) != fmt.Sprintf("%d:%d", d.Major, d.Minor) {
		return refused("runtime_unhealthy")
	}
	var st unix.Stat_t
	if e := unix.Lstat(d.Path, &st); e != nil || st.Mode&unix.S_IFMT != unix.S_IFBLK || uint64(st.Rdev) != unix.Mkdev(uint32(d.Major), uint32(d.Minor)) {
		return refused("runtime_unhealthy")
	}
	return nil
}

type QualificationProfile struct {
	Qualified              bool              `json:"qualified"`
	Runtime                string            `json:"runtime"`
	Network                string            `json:"network"`
	ProxyTransport         string            `json:"proxy_transport"`
	BoundedVolumes         string            `json:"bounded_volumes"`
	RunscNetwork           string            `json:"runsc_network"`
	RunscHostUDS           string            `json:"runsc_host_uds"`
	OwnedRoot              string            `json:"owned_root"`
	DockerCommand          []string          `json:"docker_command"`
	SystemCommand          []string          `json:"system_command"`
	DockerHost             string            `json:"docker_host"`
	SandboxUID             int               `json:"sandbox_uid"`
	SandboxGID             int               `json:"sandbox_gid"`
	DaemonConfig           string            `json:"daemon_config"`
	DaemonConfigSHA256     string            `json:"daemon_config_sha256"`
	DockerDataRoot         string            `json:"docker_data_root"`
	ContainerdSocket       string            `json:"containerd_socket"`
	DaemonUnit             string            `json:"daemon_unit"`
	ContainerdUnit         string            `json:"containerd_unit"`
	RunscSHA256            string            `json:"runsc_sha256"`
	RuntimeFilesSHA256     map[string]string `json:"runtime_files_sha256"`
	RuntimeEnvironment     map[string]string `json:"runtime_environment"`
	RuntimeCPUAffinity     []int             `json:"runtime_cpu_affinity"`
	RuntimeCPUCount        int               `json:"runtime_cpu_count"`
	RuntimeCPUPolicy       string            `json:"runtime_cpu_policy"`
	RuntimeCPUPolicySHA256 string            `json:"runtime_cpu_policy_sha256"`
	BackingIOQualified     bool              `json:"backing_io_qualified"`
	BackingDevices         []BackingDevice   `json:"backing_devices"`
}
type DatasetBinding struct {
	ParticipantID string
	JobIDs        []string
	Path          string
	Synthetic     bool
}
type DatasetAuthorizer func(context.Context, string, ExecutionIdentity, string) (DatasetBinding, error)
type Option func(*LinuxExecutor)

func WithRunner(r Runner) Option {
	return func(e *LinuxExecutor) {
		if r != nil {
			e.runner = r
		}
	}
}
func WithHostInspector(h HostInspector) Option {
	return func(e *LinuxExecutor) {
		if h != nil {
			e.host = h
		}
	}
}

// WithDeferredQualification defers only constructor probing. Reserve and Start always qualify.
func WithDeferredQualification() Option {
	return func(e *LinuxExecutor) { e.deferQualification = true }
}
func WithDatasets(bindings map[string]DatasetBinding) Option {
	return func(e *LinuxExecutor) { e.datasets = bindings }
}
func WithDatasetAuthorizer(fn DatasetAuthorizer) Option {
	return func(e *LinuxExecutor) { e.datasetAuthorizer = fn }
}

type LinuxExecutor struct {
	Profile            QualificationProfile
	Root               string
	OwnedRoot          string
	runner             Runner
	host               HostInspector
	datasets           map[string]DatasetBinding
	datasetAuthorizer  DatasetAuthorizer
	deferQualification bool
	leaseMu            sync.RWMutex
	leaseGuard         func(ExecutionIdentity) bool
}

func NewLinuxExecutor(profilePath, root string, opts ...Option) (*LinuxExecutor, error) {
	raw, err := readPrivateFile(profilePath, 4<<20, false)
	if err != nil {
		return nil, refused("unqualified_profile")
	}
	var p QualificationProfile
	if err = json.Unmarshal(raw, &p); err != nil {
		return nil, refused("unqualified_profile")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, refused("unqualified_profile")
	}
	for _, field := range []string{"sandbox_uid", "sandbox_gid"} {
		if v, ok := fields[field]; ok {
			var n *int
			if json.Unmarshal(v, &n) != nil || n == nil || *n <= 0 {
				return nil, refused("unsafe_runtime")
			}
		}
	}
	if !p.Qualified || p.Runtime != "runsc" || p.Network != "none" || p.ProxyTransport != "unix" || p.BoundedVolumes != "loop-ext4" || p.RunscNetwork != "sandbox" || p.RunscHostUDS != "open" {
		return nil, refused("unqualified_profile")
	}
	if p.OwnedRoot == "" {
		p.OwnedRoot = root
	}
	if !filepath.IsAbs(root) || !filepath.IsAbs(p.OwnedRoot) {
		return nil, refused("unsafe_root")
	}
	root = filepath.Clean(root)
	owned := filepath.Clean(p.OwnedRoot)
	if root != owned && !strings.HasPrefix(root, owned+string(os.PathSeparator)) {
		return nil, refused("unsafe_root")
	}
	if len(p.DockerCommand) == 0 {
		p.DockerCommand = []string{"sudo", "-n", "docker", "-H", p.DockerHost}
	}
	if len(p.SystemCommand) == 0 {
		p.SystemCommand = []string{"sudo", "-n"}
	}
	if p.SandboxUID == 0 {
		p.SandboxUID = os.Getuid()
		if p.SandboxUID == 0 {
			p.SandboxUID = 65532
		}
	}
	if p.SandboxGID == 0 {
		p.SandboxGID = os.Getgid()
		if p.SandboxGID == 0 {
			p.SandboxGID = 65532
		}
	}
	if p.SandboxUID <= 0 || p.SandboxGID <= 0 {
		return nil, refused("unsafe_runtime")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, refused("unsafe_root")
	}
	if f, err := openChecked(root, true, false); err != nil {
		return nil, err
	} else {
		f.Close()
	}
	e := &LinuxExecutor{Profile: p, Root: root, OwnedRoot: owned, runner: CommandRunner{}, host: LinuxHostInspector{}, datasets: map[string]DatasetBinding{}}
	for _, o := range opts {
		o(e)
	}
	if !e.deferQualification {
		if err := e.QualifyHealth(context.Background()); err != nil {
			return nil, err
		}
	}
	return e, nil
}
func (e *LinuxExecutor) SetLeaseGuard(fn func(ExecutionIdentity) bool) {
	e.leaseMu.Lock()
	defer e.leaseMu.Unlock()
	e.leaseGuard = fn
}
func (e *LinuxExecutor) allowLaunch(id ExecutionIdentity) bool {
	e.leaseMu.RLock()
	fn := e.leaseGuard
	e.leaseMu.RUnlock()
	return fn != nil && fn(id)
}
func (e *LinuxExecutor) command(ctx context.Context, prefix, args []string, timeout time.Duration, uncertainEffect, allowFailure bool) (CommandResult, error) {
	argv := append(append([]string(nil), prefix...), args...)
	r, err := e.runner.Run(ctx, argv, timeout)
	if err != nil || (!allowFailure && r.ExitCode != 0) {
		if uncertainEffect {
			return r, uncertain(err)
		}
		return r, refused("runtime_unhealthy")
	}
	return r, nil
}
func (e *LinuxExecutor) docker(ctx context.Context, args []string, uncertainEffect, allowFailure bool) (CommandResult, error) {
	return e.command(ctx, e.Profile.DockerCommand, args, 60*time.Second, uncertainEffect, allowFailure)
}
func (e *LinuxExecutor) system(ctx context.Context, args []string, uncertainEffect, allowFailure bool) (CommandResult, error) {
	return e.command(ctx, e.Profile.SystemCommand, args, 120*time.Second, uncertainEffect, allowFailure)
}
func hashFile(path string) (string, error) {
	f, err := openChecked(path, false, false)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Mode().Perm()&0022 != 0 {
		return "", refused("runtime_unhealthy")
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (e *LinuxExecutor) QualifyHealth(ctx context.Context) error {
	p := e.Profile
	raw, err := e.docker(ctx, []string{"info", "--format", "{{json .}}"}, false, false)
	if err != nil {
		return err
	}
	var info struct {
		Runtimes                     map[string]json.RawMessage
		CgroupVersion, DockerRootDir string
		Containerd                   struct{ Address string }
	}
	if json.Unmarshal([]byte(raw.Stdout), &info) != nil || info.Runtimes["runsc"] == nil || info.CgroupVersion != "2" {
		return refused("runtime_unhealthy")
	}
	if info.DockerRootDir != p.DockerDataRoot || info.Containerd.Address != p.ContainerdSocket {
		return refused("runtime_unhealthy")
	}
	config, err := readPrivateFile(p.DaemonConfig, 4<<20, false)
	if err != nil {
		return refused("unqualified_profile")
	}
	h := sha256.Sum256(config)
	if hex.EncodeToString(h[:]) != p.DaemonConfigSHA256 {
		return refused("runtime_unhealthy")
	}
	var daemon struct {
		Runtimes map[string]struct {
			Path        string   `json:"path"`
			RuntimeArgs []string `json:"runtimeArgs"`
		} `json:"runtimes"`
	}
	if json.Unmarshal(config, &daemon) != nil {
		return refused("runtime_unhealthy")
	}
	runtime := daemon.Runtimes["runsc"]
	if runtime.Path == "" || p.RunscSHA256 == "" {
		return refused("unqualified_profile")
	}
	haveNetwork, haveUDS := false, false
	for _, a := range runtime.RuntimeArgs {
		if a == "--network=sandbox" {
			haveNetwork = true
		}
		if a == "--host-uds=open" {
			haveUDS = true
		}
		if strings.HasPrefix(a, "--network=") && a != "--network=sandbox" {
			return refused("runtime_unhealthy")
		}
	}
	if !haveNetwork || !haveUDS {
		return refused("runtime_unhealthy")
	}
	if len(p.RuntimeFilesSHA256) == 0 {
		return refused("unqualified_profile")
	}
	for path, digest := range p.RuntimeFilesSHA256 {
		if !filepath.IsAbs(path) {
			return refused("runtime_unhealthy")
		}
		actual, err := hashFile(path)
		if err != nil || actual != digest {
			return refused("runtime_unhealthy")
		}
	}
	actual, err := hashFile(runtime.Path)
	if err != nil || actual != p.RunscSHA256 {
		return refused("runtime_unhealthy")
	}
	if p.DaemonUnit == "" {
		return refused("unqualified_profile")
	}
	pidResult, err := e.system(ctx, []string{"systemctl", "show", p.DaemonUnit, "--property=MainPID", "--value"}, false, false)
	if err != nil {
		return err
	}
	pid := strings.TrimSpace(pidResult.Stdout)
	pidInt, err := strconv.Atoi(pid)
	if err != nil || pidInt <= 0 {
		return refused("runtime_unhealthy")
	}
	net, err := e.system(ctx, []string{"readlink", "/proc/" + pid + "/ns/net"}, false, false)
	if err != nil {
		return err
	}
	hostNet, err := e.system(ctx, []string{"readlink", "/proc/1/ns/net"}, false, false)
	if err != nil {
		return err
	}
	if strings.TrimSpace(net.Stdout) == "" || strings.TrimSpace(net.Stdout) == strings.TrimSpace(hostNet.Stdout) {
		return refused("runtime_unhealthy")
	}
	if p.RuntimeEnvironment != nil {
		if !reflect.DeepEqual(p.RuntimeEnvironment, map[string]string{"GOMAXPROCS": "2"}) || p.ContainerdUnit == "" || len(p.RuntimeCPUAffinity) == 0 || p.RuntimeCPUCount < len(p.RuntimeCPUAffinity) {
			return refused("unqualified_profile")
		}
		last := -1
		for _, cpu := range p.RuntimeCPUAffinity {
			if cpu < 0 || cpu <= last {
				return refused("unqualified_profile")
			}
			last = cpu
		}
		policy, err := readPrivateFile(p.RuntimeCPUPolicy, 64<<10, true)
		if err != nil {
			return refused("runtime_unhealthy")
		}
		h := sha256.Sum256(policy)
		if hex.EncodeToString(h[:]) != p.RuntimeCPUPolicySHA256 {
			return refused("runtime_unhealthy")
		}
		var cp struct {
			CPUCount    int   `json:"cpu_count"`
			CPUAffinity []int `json:"cpu_affinity"`
		}
		if json.Unmarshal(policy, &cp) != nil || cp.CPUCount != p.RuntimeCPUCount || !reflect.DeepEqual(cp.CPUAffinity, p.RuntimeCPUAffinity) {
			return refused("runtime_unhealthy")
		}
		for _, unit := range []string{p.DaemonUnit, p.ContainerdUnit} {
			env, err := e.system(ctx, []string{"systemctl", "show", unit, "--property=Environment", "--value"}, false, false)
			if err != nil || !contains(strings.Fields(env.Stdout), "GOMAXPROCS=2") {
				return refused("runtime_unhealthy")
			}
			result, err := e.system(ctx, []string{"systemctl", "show", unit, "--property=MainPID", "--value"}, false, false)
			if err != nil {
				return err
			}
			n, err := strconv.Atoi(strings.TrimSpace(result.Stdout))
			if err != nil || n <= 0 {
				return refused("runtime_unhealthy")
			}
			affinity, err := e.host.Affinity(n)
			if err != nil || !reflect.DeepEqual(affinity, p.RuntimeCPUAffinity) {
				return refused("runtime_unhealthy")
			}
		}
	}
	devices, err := e.qualifiedDevices()
	if err != nil {
		return err
	}
	for _, path := range []string{e.OwnedRoot, p.DockerDataRoot} {
		d, err := e.host.BackingDevice(path)
		if err != nil || !containsDevice(devices, d) {
			return refused("runtime_unhealthy")
		}
	}
	return nil
}
func (e *LinuxExecutor) qualifiedDevices() ([]BackingDevice, error) {
	p := e.Profile
	if !p.BackingIOQualified || len(p.BackingDevices) == 0 {
		return nil, refused("unqualified_profile")
	}
	seen := map[BackingDevice]bool{}
	for _, d := range p.BackingDevices {
		if seen[d] || d.Path == "" || d.SysfsPath == "" || d.Major < 0 || d.Minor < 0 {
			return nil, refused("unqualified_profile")
		}
		if err := e.host.ValidateDevice(d); err != nil {
			return nil, err
		}
		seen[d] = true
	}
	return p.BackingDevices, nil
}
func (e *LinuxExecutor) ioDevices(s ExecutionSpec, dataset string) ([]string, error) {
	approved, err := e.qualifiedDevices()
	if err != nil {
		return nil, err
	}
	paths := []string{e.Root, e.Profile.DockerDataRoot, s.SourcePath, s.StatePath}
	for _, p := range []string{s.ConfigPath, s.SecretPath, s.BuildInputPath, dataset} {
		if p != "" {
			paths = append(paths, p)
		}
	}
	seen := map[string]bool{}
	for _, path := range paths {
		d, err := e.host.BackingDevice(path)
		if err != nil || !containsDevice(approved, d) {
			return nil, refused("unqualified_backing")
		}
		seen[d.Path] = true
	}
	var result []string
	for p := range seen {
		result = append(result, p)
	}
	sort.Strings(result)
	return result, nil
}
func containsDevice(devices []BackingDevice, d BackingDevice) bool {
	for _, v := range devices {
		if v == d {
			return true
		}
	}
	return false
}
func contains[T comparable](xs []T, x T) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
