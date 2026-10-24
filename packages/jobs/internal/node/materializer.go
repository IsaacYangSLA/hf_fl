package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/build"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/resources"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/source"
	"golang.org/x/sys/unix"
)

type MaterializerConfig struct {
	Root, NodeID, PoolID, WorkloadIssuer string
	Catalog                              *source.Catalog
	ProxyEndpoint                        func(context.Context, executor.ExecutionIdentity) (string, error)
	ExecutionBindings                    func(context.Context, RemoteAssignment, string, string) (map[string]any, error)
	DatasetBindings                      func(context.Context, RemoteAssignment) (map[string]any, error)
	SecretPlanner                        func(context.Context, RemoteAssignment) (string, error)
	SecretMaterializer                   func(context.Context, RemoteAssignment, map[string]any, string) error
	BuildPreparer                        func(context.Context, RemoteAssignment, map[string]any) error
	AuxiliaryReserver                    func(context.Context, executor.ExecutionIdentity, int64) (bool, error)
	SharedAuxiliaryReserver              func(context.Context, executor.ExecutionIdentity, int64) (bool, error)
	RequireSourceLimits                  bool
	ValidateRuntime                      func(map[string]any, string) error
}
type Materializer struct {
	Config      MaterializerConfig
	Directories *resources.OwnedDirectories
	root        *os.Root
	mu          sync.Mutex
	locks       map[string]*sync.Mutex
	pending     map[string]RemoteAssignment
}

func NewMaterializer(cfg MaterializerConfig) (*Materializer, error) {
	if domain.ValidateIdentifier(cfg.NodeID) != nil || domain.ValidateIdentifier(cfg.PoolID) != nil || cfg.Catalog == nil || cfg.Catalog.Registry == nil {
		return nil, domain.Err(422, "invalid_node_configuration")
	}
	root, e := resources.PrivateRoot(cfg.Root)
	if e != nil {
		return nil, e
	}
	cfg.Root = root
	dirs, e := resources.NewOwnedDirectories(filepath.Join(root, "jobs"))
	if e != nil {
		return nil, e
	}
	handle, e := os.OpenRoot(root)
	if e != nil {
		dirs.Close()
		return nil, e
	}
	out := &Materializer{Config: cfg, Directories: dirs, root: handle, locks: map[string]*sync.Mutex{}, pending: map[string]RemoteAssignment{}}
	for _, name := range []string{"assignments", "purge-receipts", "locks"} {
		if e = out.mkdir(name); e != nil {
			out.Close()
			return nil, e
		}
	}
	return out, nil
}
func (m *Materializer) Close() error {
	a := m.root.Close()
	b := m.Directories.Close()
	if a != nil {
		return a
	}
	return b
}

// openParent anchors every component independently; os.Root's in-root symlink
// support must not turn a sibling job into an accepted parent.
func openParent(root *os.Root, relative string) (*os.File, string, error) {
	if !safeRelative(relative) {
		return nil, "", domain.Err(409, "unsafe_mount")
	}
	parts := splitRelative(relative)
	dir, e := root.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, "", e
	}
	for _, part := range parts[:len(parts)-1] {
		fd, e := unix.Openat(int(dir.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			dir.Close()
			return nil, "", e
		}
		dir.Close()
		dir = os.NewFile(uintptr(fd), "owned node directory")
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
			dir.Close()
			return nil, "", domain.Err(409, "unsafe_mount")
		}
	}
	return dir, parts[len(parts)-1], nil
}
func (m *Materializer) open(relative string, flags int, mode os.FileMode) (*os.File, error) {
	parent, name, e := openParent(m.root, relative)
	if e != nil {
		return nil, e
	}
	defer parent.Close()
	fd, e := unix.Openat(int(parent.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), "owned node file"), nil
}
func (m *Materializer) mkdir(relative string) error {
	if !safeRelative(relative) {
		return domain.Err(409, "unsafe_mount")
	}
	dir, e := m.root.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	defer func() { dir.Close() }()
	for _, part := range splitRelative(relative) {
		if e = unix.Mkdirat(int(dir.Fd()), part, 0700); e != nil && e != unix.EEXIST {
			return e
		}
		fd, e := unix.Openat(int(dir.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return domain.Err(409, "unsafe_mount")
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
			unix.Close(fd)
			return domain.Err(409, "unsafe_mount")
		}
		dir.Close()
		dir = os.NewFile(uintptr(fd), "owned node directory")
	}
	return nil
}

func splitRelative(value string) []string {
	result := []string{}
	start := 0
	for i, c := range value {
		if c == '/' {
			result = append(result, value[start:i])
			start = i + 1
		}
	}
	return append(result, value[start:])
}
func (m *Materializer) read(relative string, limit int64) ([]byte, error) {
	if !safeRelative(relative) || limit < 0 || limit > 1<<30 {
		return nil, domain.Err(409, "unsafe_output")
	}
	f, e := m.open(relative, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil {
		return nil, e
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || before.Size() > limit {
		return nil, domain.Err(409, "unsafe_output")
	}
	data, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(data)) > limit {
		return nil, domain.Err(409, "unsafe_output")
	}
	after, e := f.Stat()
	if e != nil {
		return nil, e
	}
	ast := after.Sys().(*syscall.Stat_t)
	if st.Dev != ast.Dev || st.Ino != ast.Ino || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || st.Ctim != ast.Ctim {
		return nil, domain.Err(409, "unsafe_output")
	}
	return data, nil
}
func (m *Materializer) readObject(relative string) (map[string]any, error) {
	b, e := m.read(relative, 4<<20)
	if e != nil {
		return nil, e
	}
	v, e := domain.DecodeJSON(b)
	if e != nil {
		return nil, domain.Err(409, "unsafe_output")
	}
	o, ok := v.(map[string]any)
	if !ok {
		return nil, domain.Err(409, "unsafe_output")
	}
	return o, nil
}
func (m *Materializer) withLock(id executor.ExecutionIdentity, fn func() error) error {
	if e := id.Validate(); e != nil {
		return e
	}
	key := id.Key()
	m.mu.Lock()
	l := m.locks[key]
	if l == nil {
		l = &sync.Mutex{}
		m.locks[key] = l
	}
	m.mu.Unlock()
	l.Lock()
	defer l.Unlock()
	f, e := m.open("locks/"+key+".lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || info.Mode().Perm()&0077 != 0 {
		return domain.Err(409, "unsafe_mount")
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX); e != nil {
		return e
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return fn()
}
func (m *Materializer) Assignment(_ context.Context, id executor.ExecutionIdentity) (RemoteAssignment, error) {
	b, e := m.read("assignments/"+id.Key()+".json", 4<<20)
	if errors.Is(e, os.ErrNotExist) {
		m.mu.Lock()
		a, ok := m.pending[id.Key()]
		m.mu.Unlock()
		if ok && a.Identity == id {
			return a, nil
		}
	}
	if e != nil {
		return RemoteAssignment{}, e
	}
	a, e := DecodeAssignment(b)
	if e != nil || a.Identity != id {
		return a, domain.Err(409, "assignment_conflict")
	}
	return a, nil
}
func (m *Materializer) catalog(ctx context.Context, a RemoteAssignment) (*source.Catalog, source.Approval, error) {
	current, e := m.Config.Catalog.Refresh(ctx)
	if e != nil {
		return nil, source.Approval{}, e
	}
	approval, e := current.Registry.Authorize(a.JobSpec.ProjectID, a.JobSpec.SourceID, a.JobSpec.SourceCommit)
	if e != nil {
		return nil, approval, e
	}
	if a.SourceLimits == nil && m.Config.RequireSourceLimits {
		return nil, approval, domain.Err(409, "source_not_approved")
	}
	if a.SourceLimits != nil {
		approval.MaxBytes = min(approval.MaxBytes, a.SourceLimits["max_bytes"])
		approval.MaxFiles = min(approval.MaxFiles, a.SourceLimits["max_files"])
		approval.MaxGitBytes = min(approval.MaxGitBytes, a.SourceLimits["max_git_bytes"])
		approval.MaxGitFiles = min(approval.MaxGitFiles, a.SourceLimits["max_git_files"])
	}
	cloned := *current
	registry := *current.Registry
	registry.Approvals = map[string]source.Approval{}
	for k, v := range current.Registry.Approvals {
		registry.Approvals[k] = v
	}
	registry.Approvals[approval.SourceID] = approval
	cloned.Registry = &registry
	cloned.Database = nil
	scoped := a.JobSpec
	scoped.Participants = nil
	scoped.SecretRefs = map[string]string{}
	c, _ := a.Component()
	for _, p := range a.JobSpec.Participants {
		if c.ParticipantID != nil && p.ParticipantID == *c.ParticipantID {
			scoped.Participants = append(scoped.Participants, p)
		}
	}
	for k, v := range a.JobSpec.SecretRefs {
		if current.SecretRefs[v] {
			scoped.SecretRefs[k] = v
		}
	}
	image, e := cloned.Validate(ctx, scoped)
	if e != nil {
		return nil, approval, e
	}
	if image != a.ImageDigest {
		return nil, approval, domain.Err(409, "image_not_approved")
	}
	return &cloned, approval, nil
}
func (m *Materializer) relativePaths(id executor.ExecutionIdentity) (parent, attempt string) {
	parent = "jobs/" + id.JobID + "/components/" + id.ComponentID
	attempt = parent + "/attempts/" + id.AttemptID + "/" + strconv.FormatInt(id.Epoch, 10)
	return
}
func (m *Materializer) paths(a RemoteAssignment) (string, string, error) {
	digest, e := a.JobSpec.Digest()
	if e != nil {
		return "", "", e
	}
	if _, e = m.Directories.EnsureJob(a.Identity.JobID, digest); e != nil {
		return "", "", e
	}
	parent, attempt := m.relativePaths(a.Identity)
	if e = m.mkdir(attempt); e != nil {
		return "", "", e
	}
	return parent, attempt, nil
}
func (m *Materializer) Plan(ctx context.Context, a RemoteAssignment) (executor.ExecutionSpec, error) {
	a = a.Defaults()
	if e := a.Validate(); e != nil {
		return executor.ExecutionSpec{}, e
	}
	if a.NodeID != m.Config.NodeID || a.PoolID != m.Config.PoolID {
		return executor.ExecutionSpec{}, domain.Err(409, "node_mismatch")
	}
	if _, _, e := m.catalog(ctx, a); e != nil {
		return executor.ExecutionSpec{}, e
	}
	parent, attempt := m.relativePaths(a.Identity)
	c, _ := a.Component()
	role := c.Role
	if role == "participant" {
		role = "client"
	}
	proxy := ""
	var e error
	if role != "build" {
		proxy = filepath.Join(m.Config.Root, attempt, "proxy.sock")
		if m.Config.ProxyEndpoint != nil {
			proxy, e = m.Config.ProxyEndpoint(ctx, a.Identity)
			if e != nil {
				return executor.ExecutionSpec{}, e
			}
		}
	}
	secret := ""
	if m.Config.SecretPlanner != nil {
		secret, e = m.Config.SecretPlanner(ctx, a)
		if e != nil {
			return executor.ExecutionSpec{}, e
		}
	}
	participant := ""
	dataset := ""
	if c.ParticipantID != nil {
		participant = *c.ParticipantID
		for _, p := range a.JobSpec.Participants {
			if p.ParticipantID == participant {
				dataset = p.DatasetBinding
			}
		}
	}
	buildInput := ""
	if role != "build" {
		for _, v := range a.JobSpec.Components {
			if v.Role == "build" {
				buildInput = filepath.Join(m.Config.Root, parent, "build-inputs")
			}
		}
	}
	s := executor.ExecutionSpec{Identity: a.Identity, ImageDigest: a.ImageDigest, SourcePath: filepath.Join(m.Config.Root, parent, "source"), StatePath: filepath.Join(m.Config.Root, parent, "state"), Resources: a.Resources, ProxyEndpoint: proxy, LeaseSeconds: a.LeaseSeconds, PoolID: a.PoolID, NodeID: a.NodeID, Deadline: a.Deadline, ConfigPath: filepath.Join(m.Config.Root, attempt, "runtime.json"), Role: role, SecretPath: secret, DatasetBindingID: dataset, ParticipantID: participant, BuildInputPath: buildInput}.Defaults()
	return s, s.Validate()
}
func (m *Materializer) Reserve(ctx context.Context, a RemoteAssignment) (executor.ExecutionSpec, error) {
	var out executor.ExecutionSpec
	e := m.withLock(a.Identity, func() error {
		var err error
		out, err = m.Plan(ctx, a)
		if err != nil {
			return err
		}
		path := "assignments/" + a.Identity.Key() + ".json"
		existing, err := m.read(path, 4<<20)
		data, ce := domain.CanonicalJSON(a)
		if ce != nil {
			return ce
		}
		if err == nil {
			if !mapsEqualJSON(existing, data) {
				return domain.Err(409, "assignment_conflict")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		} else if err = resources.AtomicJSON(filepath.Join(m.Config.Root, path), a, 0600); err != nil {
			return err
		}
		_, _, err = m.paths(a)
		return err
	})
	return out, e
}
func mapsEqualJSON(a, b []byte) bool {
	aa, e := domain.DecodeJSON(a)
	if e != nil {
		return false
	}
	bb, e := domain.DecodeJSON(b)
	return e == nil && mapsEqual(aa, bb)
}
func (m *Materializer) WithPending(a RemoteAssignment, fn func() error) error {
	m.mu.Lock()
	old, exists := m.pending[a.Identity.Key()]
	if exists && !mapsEqual(old, a) {
		m.mu.Unlock()
		return domain.Err(409, "assignment_conflict")
	}
	m.pending[a.Identity.Key()] = a
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		if exists {
			m.pending[a.Identity.Key()] = old
		} else {
			delete(m.pending, a.Identity.Key())
		}
		m.mu.Unlock()
	}()
	return fn()
}
func (m *Materializer) AuxiliaryPeakBytes(ctx context.Context, a RemoteAssignment, buildBytes int64) (int64, error) {
	_, approval, e := m.catalog(ctx, a)
	if e != nil {
		return 0, e
	}
	builders := int64(0)
	for _, c := range a.JobSpec.Components {
		if c.Role == "build" {
			builders++
		}
	}
	metadata := int64(0)
	if buildBytes > 0 {
		metadata = 8192 * (builders + 4)
	}
	total := approval.MaxBytes + source.MetadataPeakBytes(approval) + source.GitPeakBytes(approval) + (4 << 20) + (256 << 10) + buildBytes + metadata
	if total < 0 || total > math.MaxInt64/2 {
		return 0, domain.Err(409, "invalid_resources")
	}
	return total, nil
}
func (m *Materializer) charge(ctx context.Context, a RemoteAssignment, buildBytes int64) error {
	total, e := m.AuxiliaryPeakBytes(ctx, a, buildBytes)
	if e != nil {
		return e
	}
	fixed := int64((4 << 20) + (256 << 10))
	if m.Config.SharedAuxiliaryReserver != nil {
		if m.Config.AuxiliaryReserver == nil {
			return domain.Err(409, "invalid_resources")
		}
		ok, e := m.Config.SharedAuxiliaryReserver(ctx, a.Identity, total-fixed)
		if e != nil {
			return e
		}
		if !ok {
			return domain.Err(409, "resource_limit_exceeded")
		}
		ok, e = m.Config.AuxiliaryReserver(ctx, a.Identity, fixed)
		if e != nil {
			return e
		}
		if !ok {
			return domain.Err(409, "resource_limit_exceeded")
		}
	} else if m.Config.AuxiliaryReserver != nil {
		ok, e := m.Config.AuxiliaryReserver(ctx, a.Identity, total)
		if e != nil {
			return e
		}
		if !ok {
			return domain.Err(409, "resource_limit_exceeded")
		}
	}
	return nil
}
func (m *Materializer) Binding(ctx context.Context, id executor.ExecutionIdentity, space, principal string) (map[string]any, error) {
	var out map[string]any
	e := m.withLock(id, func() error {
		a, e := m.Assignment(ctx, id)
		if e != nil {
			return e
		}
		if domain.ValidateIdentifier(space) != nil || principal == "" {
			return domain.Err(409, "invalid_assignment")
		}
		if m.Config.ExecutionBindings == nil {
			return domain.Err(409, "missing_proxy")
		}
		if e = m.charge(ctx, a, 0); e != nil {
			return e
		}
		value, e := m.Config.ExecutionBindings(ctx, a, space, principal)
		if e != nil {
			return e
		}
		plan, e := m.Plan(ctx, a)
		if e != nil {
			return e
		}
		thumb := valueString(value["certificate_thumbprint"])
		if value["proxy_endpoint"] != plan.ProxyEndpoint || validateThumbprint(thumb) != nil {
			return domain.Err(409, "missing_proxy")
		}
		datasets := map[string]any{}
		if m.Config.DatasetBindings != nil {
			datasets, e = m.Config.DatasetBindings(ctx, a)
			if e != nil {
				return e
			}
		}
		out = map[string]any{"certificate_thumbprint": thumb, "proxy_endpoint": "remote:" + id.Key(), "dataset_bindings": datasets}
		return nil
	})
	return out, e
}

var wheelPattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9_.+\\-]{0,240}\\.whl$")

func (m *Materializer) StageBuildInput(ctx context.Context, id executor.ExecutionIdentity, artifacts map[string]any, filename string, offset int64, encoded string) (bool, error) {
	e := m.withLock(id, func() error {
		a, e := m.Assignment(ctx, id)
		if e != nil {
			return e
		}
		c, _ := a.Component()
		builders := 0
		for _, v := range a.JobSpec.Components {
			if v.Role == "build" {
				builders++
			}
		}
		if c.Role == "build" || builders == 0 {
			return domain.Err(409, "build_not_approved")
		}
		if len(artifacts) == 0 || len(artifacts) > min(256, builders) {
			return domain.Err(409, "invalid_assignment")
		}
		limit := min(int64(256<<20), a.Resources.DiskBytes)
		manifest, e := build.ParseManifest(artifacts, limit)
		if e != nil {
			return e
		}
		var total int64
		for name, d := range manifest {
			if !wheelPattern.MatchString(name) {
				return domain.Err(409, "invalid_assignment")
			}
			total += d.SizeBytes
		}
		d, ok := manifest[filename]
		if !ok || offset < 0 || offset >= d.SizeBytes || len(encoded) > 4*((1<<20+2)/3) {
			return domain.Err(409, "invalid_assignment")
		}
		chunk, e := base64.StdEncoding.Strict().DecodeString(encoded)
		if e != nil || len(chunk) < 1 || len(chunk) > 1<<20 || offset+int64(len(chunk)) > d.SizeBytes {
			return domain.Err(409, "invalid_assignment")
		}
		if e = m.charge(ctx, a, total); e != nil {
			return e
		}
		parent, _, e := m.paths(a)
		if e != nil {
			return e
		}
		digest, e := a.JobSpec.Digest()
		if e != nil {
			return e
		}
		description := map[string]any{"job_id": id.JobID, "component_id": id.ComponentID, "spec_digest": digest, "artifacts": build.ProductManifestMap(manifest)}
		mp := parent + "/build-input-manifest.json"
		existing, e := m.readObject(mp)
		if e == nil {
			if !mapsEqual(existing, description) {
				return domain.Err(409, "assignment_conflict")
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		} else if e = resources.AtomicJSON(filepath.Join(m.Config.Root, mp), description, 0400); e != nil {
			return e
		}
		destination := parent + "/build-inputs"
		if e = m.mkdir(destination); e != nil {
			return e
		}
		final, e := m.read(destination+"/"+filename, d.SizeBytes)
		if e == nil {
			h := sha256.Sum256(final)
			if int64(len(final)) != d.SizeBytes || hex.EncodeToString(h[:]) != d.SHA256 {
				return domain.Err(409, "unsafe_output")
			}
			if !bytes.Equal(final[offset:offset+int64(len(chunk))], chunk) {
				return domain.Err(409, "assignment_conflict")
			}
			return nil
		}
		if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		part := destination + "/." + filename + ".part"
		f, e := m.open(part, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
		if e != nil {
			return e
		}
		defer f.Close()
		info, e := f.Stat()
		if e != nil {
			return e
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 || info.Size() > d.SizeBytes {
			return domain.Err(409, "unsafe_output")
		}
		if info.Size() == offset {
			if _, e = f.WriteAt(chunk, offset); e != nil {
				return e
			}
			if e = f.Sync(); e != nil {
				return e
			}
		} else if info.Size() >= offset+int64(len(chunk)) {
			old := make([]byte, len(chunk))
			if _, e = f.ReadAt(old, offset); e != nil {
				return e
			}
			if !bytes.Equal(old, chunk) {
				return domain.Err(409, "assignment_conflict")
			}
		} else {
			return domain.Err(409, "assignment_conflict")
		}
		info, e = f.Stat()
		if e != nil {
			return e
		}
		if info.Size() == d.SizeBytes {
			if _, e = f.Seek(0, 0); e != nil {
				return e
			}
			hash := sha256.New()
			if _, e = io.Copy(hash, io.LimitReader(f, d.SizeBytes+1)); e != nil {
				return e
			}
			if hex.EncodeToString(hash.Sum(nil)) != d.SHA256 {
				return domain.Err(409, "unsafe_output")
			}
			if e = f.Chmod(0400); e != nil {
				return e
			}
			if e = f.Sync(); e != nil {
				return e
			}
			dir, e := m.open(destination, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
			if e != nil {
				return e
			}
			defer dir.Close()
			if e = unix.Renameat2(int(dir.Fd()), "."+filename+".part", int(dir.Fd()), filename, unix.RENAME_NOREPLACE); e != nil {
				return e
			}
			return dir.Sync()
		}
		return nil
	})
	return e == nil, e
}
func (m *Materializer) Prepare(ctx context.Context, id executor.ExecutionIdentity, document, binding map[string]any) (bool, error) {
	e := m.withLock(id, func() error {
		a, e := m.Assignment(ctx, id)
		if e != nil {
			return e
		}
		plan, e := m.Plan(ctx, a)
		if e != nil {
			return e
		}
		parent, _, e := m.paths(a)
		if e != nil {
			return e
		}
		declared := valueMap(document["built_artifacts"])
		manifest, e := build.ParseManifest(declared, min(int64(256<<20), a.Resources.DiskBytes))
		if e != nil && len(declared) > 0 {
			return e
		}
		total := int64(0)
		for _, d := range manifest {
			total += d.SizeBytes
		}
		if e = m.charge(ctx, a, total); e != nil {
			return e
		}
		if number(document["epoch"]) != id.Epoch || document["job_id"] != id.JobID || document["attempt_id"] != id.AttemptID || document["component_id"] != id.ComponentID {
			return domain.Err(409, "assignment_conflict")
		}
		if e = validatePrepared(document, plan.Role, a.JobSpec); e != nil {
			return e
		}
		role := valueString(document["role"])
		if role != plan.Role && !(plan.Role == "owner" && role == "init") {
			return domain.Err(409, "assignment_conflict")
		}
		if m.Config.ValidateRuntime == nil {
			return domain.Err(409, "runtime_validator_unavailable")
		}
		if e = m.Config.ValidateRuntime(document, plan.Role); e != nil {
			return e
		}
		if plan.Role == "build" {
			if m.Config.BuildPreparer == nil {
				return domain.Err(409, "build_not_approved")
			}
			if e = m.Config.BuildPreparer(ctx, a, document); e != nil {
				return e
			}
		} else {
			local := map[string]any{}
			if m.Config.DatasetBindings != nil {
				local, e = m.Config.DatasetBindings(ctx, a)
				if e != nil {
					return e
				}
			}
			if !mapsEqual(local, valueMap(document["dataset_bindings"])) {
				return domain.Err(409, "dataset_not_approved")
			}
		}
		if plan.BuildInputPath != "" {
			if len(manifest) == 0 {
				return domain.Err(409, "build_inputs_missing")
			}
			described, e := m.readObject(parent + "/build-input-manifest.json")
			if e != nil {
				return e
			}
			if !mapsEqual(described["artifacts"], build.ProductManifestMap(manifest)) {
				return domain.Err(409, "assignment_conflict")
			}
			if e = build.VerifyProducts(plan.BuildInputPath, manifest); e != nil {
				return e
			}
		} else if len(manifest) > 0 {
			return domain.Err(409, "build_not_approved")
		}
		catalog, approval, e := m.catalog(ctx, a)
		if e != nil {
			return e
		}
		sourcePath := filepath.Join(m.Config.Root, parent, "source")
		if _, e = os.Lstat(sourcePath); errors.Is(e, os.ErrNotExist) {
			if _, e = catalog.Registry.Materialize(ctx, a.JobSpec.ProjectID, a.JobSpec.SourceID, a.JobSpec.SourceCommit, sourcePath, filepath.Join(m.Config.Root, parent)); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
		expected := map[string]string{}
		for k, v := range valueMap(document["source_manifest"]) {
			h, ok := v.(string)
			if !ok {
				return domain.Err(409, "source_conflict")
			}
			expected[k] = h
		}
		if e = source.VerifySnapshot(sourcePath, expected, approval.MaxBytes, approval.MaxFiles); e != nil {
			return domain.Err(409, "source_conflict")
		}
		if plan.Role != "build" && binding != nil {
			if binding["proxy_endpoint"] != "remote:"+id.Key() || validateThumbprint(valueString(binding["certificate_thumbprint"])) != nil || m.Config.ExecutionBindings == nil || m.Config.WorkloadIssuer == "" {
				return domain.Err(409, "missing_proxy")
			}
			c, _ := a.Component()
			principal, e := exchange.StableWorkloadPrincipal(m.Config.WorkloadIssuer, id.JobID, id.ComponentID, c.ParticipantID)
			if e != nil {
				return e
			}
			actual, e := m.Config.ExecutionBindings(ctx, a, valueString(document["space_id"]), principal)
			if e != nil {
				return e
			}
			if actual["proxy_endpoint"] != plan.ProxyEndpoint || actual["certificate_thumbprint"] != binding["certificate_thumbprint"] {
				return domain.Err(409, "missing_proxy")
			}
		}
		if plan.Role != "build" {
			names, exists := document["secret_option_names"]
			nonempty := false
			if exists {
				switch v := names.(type) {
				case []any:
					nonempty = len(v) > 0
				case []string:
					nonempty = len(v) > 0
				}
			}
			if nonempty {
				if plan.SecretPath == "" || m.Config.SecretMaterializer == nil {
					return domain.Err(409, "secret_not_approved")
				}
				if e = m.Config.SecretMaterializer(ctx, a, document, plan.SecretPath); e != nil {
					return e
				}
			}
		}
		for _, name := range []string{"state", "state/cache", "state/logs", "state/artifacts"} {
			if e = m.mkdir(parent + "/" + name); e != nil {
				return e
			}
		}
		relative, e := filepath.Rel(m.Config.Root, plan.ConfigPath)
		if e != nil || !safeRelative(relative) {
			return domain.Err(409, "unsafe_mount")
		}
		existing, e := m.readObject(relative)
		if e == nil {
			if !mapsEqual(existing, document) {
				return domain.Err(409, "assignment_conflict")
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		} else if e = resources.AtomicJSON(plan.ConfigPath, document, 0400); e != nil {
			return e
		}
		return nil
	})
	return e == nil, e
}
func (m *Materializer) Purge(ctx context.Context, id executor.ExecutionIdentity) (bool, error) {
	var confirmed bool
	e := m.withLock(id, func() error {
		a, e := m.Assignment(ctx, id)
		if e != nil {
			return e
		}
		digest, e := a.JobSpec.Digest()
		if e != nil {
			return e
		}
		confirmed, e = m.Directories.PurgeComponent(id.JobID, id.ComponentID, digest)
		return e
	})
	return confirmed, e
}
func (m *Materializer) ReconciliationRoot(id executor.ExecutionIdentity) string {
	parent, _ := m.relativePaths(id)
	return filepath.Join(m.Config.Root, parent, "state")
}
func (m *Materializer) WritePurgeReceipt(receipt NodePurgeReceipt) error {
	if e := receipt.Validate(); e != nil {
		return e
	}
	path := "purge-receipts/" + receipt.Identity().Key() + ".json"
	existing, e := m.readObject(path)
	if e == nil {
		if !mapsEqual(existing, receipt) {
			return domain.Err(409, "assignment_conflict")
		}
		return nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return resources.AtomicJSON(filepath.Join(m.Config.Root, path), receipt, 0400)
}
func (m *Materializer) PurgeReceipt(id executor.ExecutionIdentity) (NodePurgeReceipt, error) {
	data, e := m.read("purge-receipts/"+id.Key()+".json", 16384)
	if e != nil {
		return NodePurgeReceipt{}, e
	}
	var receipt NodePurgeReceipt
	if strictDecode(data, &receipt) != nil || receipt.Validate() != nil || receipt.Identity() != id {
		return receipt, domain.Err(409, "invalid_purge_receipt")
	}
	return receipt, nil
}

func (m *Materializer) AllAssignments(ctx context.Context) ([]RemoteAssignment, error) {
	f, e := m.open("assignments", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	entries, e := f.ReadDir(10001)
	if e != nil && e != io.EOF {
		return nil, e
	}
	if len(entries) > 10000 {
		return nil, domain.Err(409, "assignment_inventory_exceeds_bound")
	}
	out := []RemoteAssignment{}
	var total int64
	for _, entry := range entries {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") || entry.IsDir() {
			return nil, domain.Err(409, "unsafe_output")
		}
		data, e := m.read("assignments/"+name, 4<<20)
		if e != nil {
			return nil, e
		}
		total += int64(len(data))
		if total > 256<<20 {
			return nil, domain.Err(409, "assignment_inventory_exceeds_bound")
		}
		a, e := DecodeAssignment(data)
		if e != nil || name != a.Identity.Key()+".json" || a.NodeID != m.Config.NodeID || a.PoolID != m.Config.PoolID {
			return nil, domain.Err(409, "assignment_conflict")
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity.Key() < out[j].Identity.Key() })
	return out, nil
}
func (m *Materializer) RemoveAssignment(ctx context.Context, id executor.ExecutionIdentity) error {
	return m.withLock(id, func() error {
		a, e := m.Assignment(ctx, id)
		if errors.Is(e, os.ErrNotExist) {
			return nil
		}
		if e != nil {
			return e
		}
		parent, _ := m.relativePaths(a.Identity)
		f, e := m.open(parent, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if e == nil {
			f.Close()
			return domain.Err(409, "runtime_active")
		}
		if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		parentFD, name, e := openParent(m.root, "assignments/"+id.Key()+".json")
		if e != nil {
			return e
		}
		defer parentFD.Close()
		if e = unix.Unlinkat(int(parentFD.Fd()), name, 0); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if e = parentFD.Sync(); e != nil {
			return e
		}
		return nil
	})
}

func (m *Materializer) ReserveBuildInputs(ctx context.Context, id executor.ExecutionIdentity, artifacts map[string]any) error {
	return m.withLock(id, func() error {
		a, e := m.Assignment(ctx, id)
		if e != nil {
			return e
		}
		c, _ := a.Component()
		builders := 0
		for _, v := range a.JobSpec.Components {
			if v.Role == "build" {
				builders++
			}
		}
		if c.Role == "build" || builders == 0 {
			return domain.Err(409, "build_not_approved")
		}
		if len(artifacts) < 1 || len(artifacts) > min(256, builders) {
			return domain.Err(409, "invalid_assignment")
		}
		manifest, e := build.ParseManifest(artifacts, min(int64(256<<20), a.Resources.DiskBytes))
		if e != nil {
			return e
		}
		var total int64
		for name, d := range manifest {
			if !wheelPattern.MatchString(name) {
				return domain.Err(409, "invalid_assignment")
			}
			total += d.SizeBytes
		}
		if e = m.charge(ctx, a, total); e != nil {
			return e
		}
		parent, _, e := m.paths(a)
		if e != nil {
			return e
		}
		digest, e := a.JobSpec.Digest()
		if e != nil {
			return e
		}
		document := map[string]any{"job_id": id.JobID, "component_id": id.ComponentID, "spec_digest": digest, "artifacts": build.ProductManifestMap(manifest)}
		path := parent + "/build-input-manifest.json"
		old, e := m.readObject(path)
		if e == nil {
			if !mapsEqual(old, document) {
				return domain.Err(409, "assignment_conflict")
			}
			return nil
		}
		if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		return resources.AtomicJSON(filepath.Join(m.Config.Root, path), document, 0400)
	})
}
