// Package resources owns physical directories and durable provisioning receipts.
package resources

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"golang.org/x/sys/unix"
)

var ErrUnsafe = errors.New("resource ownership or filesystem safety check failed")
var ErrBusy = errors.New("another provisioner owns this operation")

type ComponentPaths struct {
	Source    string `json:"source"`
	State     string `json:"state"`
	Cache     string `json:"cache"`
	Logs      string `json:"logs"`
	Artifacts string `json:"artifacts"`
}
type ResourceBundle struct {
	JobID          string                    `json:"job_id"`
	AttemptID      string                    `json:"attempt_id"`
	SpaceID        string                    `json:"space_id"`
	SourcePath     string                    `json:"source_path"`
	ImageDigest    string                    `json:"image_digest"`
	SourceManifest map[string]string         `json:"source_manifest"`
	Principals     map[string]string         `json:"principals"`
	ComponentPaths map[string]ComponentPaths `json:"component_paths"`
	ComponentSpecs map[string]any            `json:"component_specs"`
	WorkloadGrants map[string]map[string]any `json:"workload_grants"`
	InitRequired   bool                      `json:"init_required"`
}

func StableKey(parts ...string) string {
	values := make([]any, len(parts))
	for i, p := range parts {
		values[i] = p
	}
	data, err := domain.CanonicalJSON(values)
	if err != nil {
		panic("string canonical JSON failed")
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func identifier(s string) error {
	if len(s) < 1 || len(s) > 128 {
		return ErrUnsafe
	}
	for i, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || (i > 0 && (c == '_' || c == '.' || c == '-'))) {
			return ErrUnsafe
		}
	}
	return nil
}

const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

type dirIdentity struct {
	dev   uint64
	ino   uint64
	mount int64
	uid   uint32
}

func identity(fd int) (dirIdentity, error) {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return dirIdentity{}, ErrUnsafe
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		return dirIdentity{}, ErrUnsafe
	}
	var mount int64
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "mnt_id:") {
			count++
			mount, err = strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "mnt_id:")), 10, 64)
			if err != nil {
				return dirIdentity{}, ErrUnsafe
			}
		}
	}
	if count != 1 {
		return dirIdentity{}, ErrUnsafe
	}
	return dirIdentity{uint64(st.Dev), st.Ino, mount, st.Uid}, nil
}
func sameNamed(parent int, name string, id dirIdentity) error {
	var st unix.Stat_t
	if unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || uint64(st.Dev) != id.dev || st.Ino != id.ino || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return ErrUnsafe
	}
	return nil
}
func cleanAbsolute(path string) ([]string, error) {
	if !filepath.IsAbs(path) || path == "/" || strings.ContainsRune(path, 0) {
		return nil, ErrUnsafe
	}
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")[1:]
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return nil, ErrUnsafe
		}
	}
	return parts, nil
}
func openAbsolute(path string, create bool) (int, error) {
	parts, err := cleanAbsolute(path)
	if err != nil {
		return -1, err
	}
	fd, err := unix.Open("/", dirFlags, 0)
	if err != nil {
		return -1, ErrUnsafe
	}
	for _, p := range parts {
		if create {
			if e := unix.Mkdirat(fd, p, 0700); e != nil && e != unix.EEXIST {
				unix.Close(fd)
				return -1, ErrUnsafe
			}
		}
		child, e := unix.Openat(fd, p, dirFlags, 0)
		unix.Close(fd)
		if e != nil {
			return -1, ErrUnsafe
		}
		fd = child
	}
	return fd, nil
}
func ownedFD(fd int, private bool) error {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return ErrUnsafe
	}
	if private && st.Mode&0077 != 0 {
		return ErrUnsafe
	}
	return nil
}
func PrivateRoot(path string) (string, error) {
	fd, err := openAbsolute(path, true)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	if ownedFD(fd, false) != nil || unix.Fchmod(fd, 0700) != nil {
		return "", ErrUnsafe
	}
	return filepath.Clean(path), nil
}
func readJSONAt(fd int, name string, limit int64) (map[string]any, error) {
	out, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafe
	}
	f := os.NewFile(uintptr(out), "resource-metadata")
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(out, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Uid != uint32(os.Geteuid()) || before.Mode&0077 != 0 || before.Size > limit {
		return nil, ErrUnsafe
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, ErrUnsafe
	}
	if unix.Fstat(out, &after) != nil || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || int64(len(data)) != after.Size {
		return nil, ErrUnsafe
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value map[string]any
	if decoder.Decode(&value) != nil || value == nil {
		return nil, ErrUnsafe
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, ErrUnsafe
	}
	return value, nil
}
func atomicAt(fd int, name string, value any, mode fs.FileMode) error {
	if strings.Contains(name, "/") || name == "" || name == "." || name == ".." || mode.Perm()&0077 != 0 {
		return ErrUnsafe
	}
	var old unix.Stat_t
	if e := unix.Fstatat(fd, name, &old, unix.AT_SYMLINK_NOFOLLOW); e == nil {
		if old.Mode&unix.S_IFMT != unix.S_IFREG || old.Nlink != 1 || old.Uid != uint32(os.Geteuid()) {
			return ErrUnsafe
		}
	} else if e != unix.ENOENT {
		return ErrUnsafe
	}
	data, err := domain.CanonicalJSON(value)
	if err != nil || len(data) > 1024*1024 {
		return ErrUnsafe
	}
	temp := ".metadata-" + domain.NewID()
	out, err := unix.Openat(fd, temp, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return ErrUnsafe
	}
	defer unix.Unlinkat(fd, temp, 0)
	f := os.NewFile(uintptr(out), "resource-metadata")
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return ErrUnsafe
	}
	if unix.Renameat(fd, temp, fd, name) != nil || unix.Fsync(fd) != nil {
		return ErrUnsafe
	}
	return nil
}
func AtomicJSON(path string, value any, mode fs.FileMode) error {
	fd, err := openAbsolute(filepath.Dir(path), false)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if ownedFD(fd, true) != nil {
		return ErrUnsafe
	}
	return atomicAt(fd, filepath.Base(path), value, mode)
}

type OwnedDirectories struct {
	Root string
	fd   int
	id   dirIdentity
	mu   sync.RWMutex
}

func NewOwnedDirectories(path string) (*OwnedDirectories, error) {
	root, err := PrivateRoot(path)
	if err != nil {
		return nil, err
	}
	fd, err := openAbsolute(root, false)
	if err != nil {
		return nil, err
	}
	id, err := identity(fd)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &OwnedDirectories{Root: root, fd: fd, id: id}, nil
}
func (o *OwnedDirectories) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fd < 0 {
		return nil
	}
	err := unix.Close(o.fd)
	o.fd = -1
	return err
}
func (o *OwnedDirectories) check() error {
	if o.fd < 0 {
		return ErrUnsafe
	}
	fd, err := openAbsolute(o.Root, false)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	id, err := identity(fd)
	if err != nil || id != o.id {
		return ErrUnsafe
	}
	return ownedFD(fd, true)
}
func (o *OwnedDirectories) JobPath(jobID string) (string, error) {
	if identifier(jobID) != nil {
		return "", ErrUnsafe
	}
	return filepath.Join(o.Root, jobID), nil
}
func (o *OwnedDirectories) validate(jobID string, digest ...string) (int, error) {
	if identifier(jobID) != nil || o.check() != nil {
		return -1, ErrUnsafe
	}
	fd, err := unix.Openat(o.fd, jobID, dirFlags, 0)
	if err != nil {
		return -1, ErrUnsafe
	}
	reject := func() (int, error) { unix.Close(fd); return -1, ErrUnsafe }
	id, err := identity(fd)
	if err != nil || id.dev != o.id.dev || id.mount != o.id.mount || ownedFD(fd, true) != nil {
		return reject()
	}
	value, err := readJSONAt(fd, ".owner.json", 8192)
	if err != nil {
		return reject()
	}
	version, ok := value["schema_version"].(json.Number)
	if !ok || version.String() != "1" || value["job_id"] != jobID {
		return reject()
	}
	if len(digest) > 0 && value["spec_digest"] != digest[0] {
		return reject()
	}
	return fd, nil
}
func (o *OwnedDirectories) ValidateJob(jobID string, digest ...string) (string, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	fd, err := o.validate(jobID, digest...)
	if err != nil {
		return "", err
	}
	unix.Close(fd)
	return o.JobPath(jobID)
}
func (o *OwnedDirectories) EnsureJob(jobID, digest string) (string, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if identifier(jobID) != nil || len(digest) != 64 || o.check() != nil {
		return "", ErrUnsafe
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", ErrUnsafe
	}
	var existing unix.Stat_t
	if e := unix.Fstatat(o.fd, jobID, &existing, unix.AT_SYMLINK_NOFOLLOW); e == nil {
		fd, e := o.validate(jobID, digest)
		if e != nil {
			return "", e
		}
		unix.Close(fd)
		return o.JobPath(jobID)
	} else if e != unix.ENOENT {
		return "", ErrUnsafe
	}
	temp := ".job-pending-" + domain.NewID()
	if unix.Mkdirat(o.fd, temp, 0700) != nil {
		return "", ErrUnsafe
	}
	fd, err := unix.Openat(o.fd, temp, dirFlags, 0)
	if err != nil {
		return "", ErrUnsafe
	}
	defer unix.Close(fd)
	// The staging name remains owned even after its contents are moved to the job name.
	defer func() {
		if err := unix.Unlinkat(o.fd, temp, unix.AT_REMOVEDIR); err != nil && err != unix.ENOENT {
			unix.Unlinkat(fd, ".owner.json", 0)
			unix.Unlinkat(o.fd, temp, unix.AT_REMOVEDIR)
		}
	}()
	if err = atomicAt(fd, ".owner.json", map[string]any{"job_id": jobID, "spec_digest": digest, "schema_version": 1}, 0600); err != nil {
		return "", err
	}
	err = unix.Renameat2(o.fd, temp, o.fd, jobID, unix.RENAME_NOREPLACE)
	if err == unix.EEXIST {
		existing, e := o.validate(jobID, digest)
		if e != nil {
			return "", e
		}
		unix.Close(existing)
	} else if err != nil {
		return "", ErrUnsafe
	}
	if unix.Fsync(o.fd) != nil {
		return "", ErrUnsafe
	}
	return o.JobPath(jobID)
}
func makeChild(parent int, name string) (int, error) {
	if identifier(name) != nil {
		return -1, ErrUnsafe
	}
	if e := unix.Mkdirat(parent, name, 0700); e != nil && e != unix.EEXIST {
		return -1, ErrUnsafe
	}
	fd, err := unix.Openat(parent, name, dirFlags, 0)
	if err != nil {
		return -1, ErrUnsafe
	}
	if ownedFD(fd, true) != nil {
		unix.Close(fd)
		return -1, ErrUnsafe
	}
	return fd, nil
}
func (o *OwnedDirectories) Components(jobID string, ids []string) (map[string]ComponentPaths, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	job, err := o.validate(jobID)
	if err != nil {
		return nil, err
	}
	defer unix.Close(job)
	parent, err := makeChild(job, "components")
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	result := map[string]ComponentPaths{}
	for _, id := range ids {
		c, e := makeChild(parent, id)
		if e != nil {
			return nil, e
		}
		state, e := makeChild(c, "state")
		if e != nil {
			unix.Close(c)
			return nil, e
		}
		for _, name := range []string{"cache", "logs", "artifacts"} {
			fd, e := makeChild(state, name)
			if e != nil {
				unix.Close(state)
				unix.Close(c)
				return nil, e
			}
			unix.Close(fd)
		}
		unix.Close(state)
		unix.Close(c)
		base := filepath.Join(o.Root, jobID)
		s := filepath.Join(base, "components", id, "state")
		result[id] = ComponentPaths{Source: filepath.Join(base, "source"), State: s, Cache: filepath.Join(s, "cache"), Logs: filepath.Join(s, "logs"), Artifacts: filepath.Join(s, "artifacts")}
	}
	return result, nil
}
func entriesAt(fd int) ([]os.DirEntry, error) {
	child, err := unix.Openat(fd, ".", dirFlags, 0)
	if err != nil {
		return nil, ErrUnsafe
	}
	f := os.NewFile(uintptr(child), "owned-directory")
	defer f.Close()
	return f.ReadDir(-1)
}

type purgeNode struct {
	parent int
	name   string
	fd     int
	id     dirIdentity
	stat   unix.Stat_t
	dir    bool
}

func (o *OwnedDirectories) Purge(jobID, digest string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if identifier(jobID) != nil || o.check() != nil {
		return ErrUnsafe
	}
	var st unix.Stat_t
	if e := unix.Fstatat(o.fd, jobID, &st, unix.AT_SYMLINK_NOFOLLOW); e == unix.ENOENT {
		return nil
	} else if e != nil {
		return ErrUnsafe
	}
	job, err := o.validate(jobID, digest)
	if err != nil {
		return err
	}
	return o.purgeTree(o.fd, jobID, job)
}

// PurgeComponent removes only one component beneath a validated immutable job.
// It does not remove the shared source or any sibling component.
func (o *OwnedDirectories) PurgeComponent(jobID, componentID, digest string) (bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if identifier(componentID) != nil {
		return false, ErrUnsafe
	}
	job, err := o.validate(jobID, digest)
	if err != nil {
		return false, err
	}
	defer unix.Close(job)
	parent, err := unix.Openat(job, "components", dirFlags, 0)
	if err == unix.ENOENT {
		return false, nil
	}
	if err != nil {
		return false, ErrUnsafe
	}
	defer unix.Close(parent)
	id, err := identity(parent)
	if err != nil || id.dev != o.id.dev || id.mount != o.id.mount || ownedFD(parent, true) != nil {
		return false, ErrUnsafe
	}
	component, err := unix.Openat(parent, componentID, dirFlags, 0)
	if err == unix.ENOENT {
		return false, nil
	}
	if err != nil {
		return false, ErrUnsafe
	}
	err = o.purgeTree(parent, componentID, component)
	return err == nil, err
}

func (o *OwnedDirectories) purgeTree(parent int, name string, job int) error {
	nodes := []purgeNode{}
	opened := []int{job}
	defer func() {
		for _, fd := range opened {
			unix.Close(fd)
		}
	}()
	var inspect func(int, int, string) error
	inspect = func(fd, parent int, name string) error {
		id, e := identity(fd)
		if e != nil || id.dev != o.id.dev || id.mount != o.id.mount || id.uid != uint32(os.Geteuid()) {
			return ErrUnsafe
		}
		entries, e := entriesAt(fd)
		if e != nil {
			return ErrUnsafe
		}
		for _, entry := range entries {
			if len(nodes) > 100000 {
				return ErrUnsafe
			}
			var item unix.Stat_t
			if unix.Fstatat(fd, entry.Name(), &item, unix.AT_SYMLINK_NOFOLLOW) != nil {
				return ErrUnsafe
			}
			switch item.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				child, e := unix.Openat(fd, entry.Name(), dirFlags, 0)
				if e != nil {
					return ErrUnsafe
				}
				opened = append(opened, child)
				if e = inspect(child, fd, entry.Name()); e != nil {
					return e
				}
			case unix.S_IFREG, unix.S_IFLNK:
				nodes = append(nodes, purgeNode{parent: fd, name: entry.Name(), stat: item})
			default:
				return ErrUnsafe
			}
		}
		nodes = append(nodes, purgeNode{parent: parent, name: name, fd: fd, id: id, dir: true})
		return nil
	}
	// Validate the entire tree before deleting any entry. Mounted and foreign
	// directories therefore cannot turn partial deletion into a cleanup receipt.
	if err := inspect(job, parent, name); err != nil {
		return err
	}
	for _, node := range nodes {
		if node.dir {
			current, e := identity(node.fd)
			if e != nil || current != node.id || sameNamed(node.parent, node.name, node.id) != nil {
				return ErrUnsafe
			}
			if unix.Fchmod(node.fd, 0700) != nil {
				return ErrUnsafe
			}
		}
	}
	for _, node := range nodes {
		var current unix.Stat_t
		if unix.Fstatat(node.parent, node.name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil {
			return ErrUnsafe
		}
		if node.dir {
			id, e := identity(node.fd)
			if e != nil || id != node.id || sameNamed(node.parent, node.name, node.id) != nil {
				return ErrUnsafe
			}
			entries, e := entriesAt(node.fd)
			if e != nil || len(entries) != 0 {
				return ErrUnsafe
			}
			if unix.Unlinkat(node.parent, node.name, unix.AT_REMOVEDIR) != nil {
				return ErrUnsafe
			}
		} else {
			if current.Dev != node.stat.Dev || current.Ino != node.stat.Ino || current.Mode&unix.S_IFMT != node.stat.Mode&unix.S_IFMT {
				return ErrUnsafe
			}
			if unix.Unlinkat(node.parent, node.name, 0) != nil {
				return ErrUnsafe
			}
		}
		if unix.Fsync(node.parent) != nil {
			return ErrUnsafe
		}
	}
	return nil
}

// PurgeEmptyNeverStarted removes only the proven initial attempt's empty proxy
// skeleton. Its caller must establish the authoritative zero-effect proof.
func (o *OwnedDirectories) PurgeEmptyNeverStarted(jobID, attemptID string, components []string) (bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if identifier(jobID) != nil || identifier(attemptID) != nil || o.check() != nil {
		return false, ErrUnsafe
	}
	allowed := map[string]bool{}
	for _, id := range components {
		if identifier(id) != nil {
			return false, ErrUnsafe
		}
		allowed[id] = true
	}
	nodes := []purgeNode{}
	opened := []int{}
	defer func() {
		for _, fd := range opened {
			unix.Close(fd)
		}
	}()
	var inspect func(int, string, int) error
	inspect = func(parent int, name string, level int) error {
		fd, err := unix.Openat(parent, name, dirFlags, 0)
		if err == unix.ENOENT {
			return nil
		}
		if err != nil {
			return ErrUnsafe
		}
		opened = append(opened, fd)
		id, err := identity(fd)
		if err != nil || id.dev != o.id.dev || id.mount != o.id.mount || ownedFD(fd, true) != nil {
			return ErrUnsafe
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&0777 != 0700 {
			return ErrUnsafe
		}
		entries, err := entriesAt(fd)
		if err != nil {
			return ErrUnsafe
		}
		for _, entry := range entries {
			ok := (level == 0 && entry.Name() == "attempts") || (level == 1 && entry.Name() == attemptID) || (level == 2 && allowed[entry.Name()])
			if !ok {
				return ErrUnsafe
			}
			if err = inspect(fd, entry.Name(), level+1); err != nil {
				return err
			}
		}
		nodes = append(nodes, purgeNode{parent: parent, name: name, fd: fd, id: id, dir: true})
		return nil
	}
	if err := inspect(o.fd, jobID, 0); err != nil {
		return false, err
	}
	for _, node := range nodes {
		id, err := identity(node.fd)
		if err != nil || id != node.id || sameNamed(node.parent, node.name, node.id) != nil {
			return false, ErrUnsafe
		}
		entries, err := entriesAt(node.fd)
		if err != nil || len(entries) != 0 {
			return false, ErrUnsafe
		}
		if unix.Unlinkat(node.parent, node.name, unix.AT_REMOVEDIR) != nil || unix.Fsync(node.parent) != nil {
			return false, ErrUnsafe
		}
	}
	return len(nodes) > 0, nil
}
