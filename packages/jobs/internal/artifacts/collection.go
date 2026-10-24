//go:build linux

// Package artifacts handles opaque workload output and retained data.
// It never imports training code or decodes a model checkpoint.
package artifacts

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"golang.org/x/sys/unix"
)

type CollectionError struct{ Code string }

func (e *CollectionError) Error() string { return e.Code }
func collectionError(code string) error  { return &CollectionError{Code: code} }

type FileMetadata struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}
type RetainedFile struct {
	Path      string `json:"path"`
	Locator   string `json:"locator"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}
type CollectorOptions struct {
	MaxFiles                                       int
	MaxFileBytes, MaxTotalBytes                    int64
	MaxEvents, MaxEventBytes, MaxEntries, MaxDepth int
	SecretValues                                   []string
}
type DeleteOptions = CollectorOptions

func defaults(o CollectorOptions) (CollectorOptions, error) {
	if o.MaxFiles == 0 {
		o.MaxFiles = 1000
	}
	if o.MaxFileBytes == 0 {
		o.MaxFileBytes = 64 << 20
	}
	if o.MaxTotalBytes == 0 {
		o.MaxTotalBytes = 256 << 20
	}
	if o.MaxEvents == 0 {
		o.MaxEvents = 10000
	}
	if o.MaxEventBytes == 0 {
		o.MaxEventBytes = 65536
	}
	if o.MaxEntries == 0 {
		o.MaxEntries = 10000
	}
	if o.MaxDepth == 0 {
		o.MaxDepth = 32
	}
	if o.MaxFiles < 1 || o.MaxFileBytes < 1 || o.MaxTotalBytes < 1 || o.MaxEvents < 1 || o.MaxEventBytes < 1 || o.MaxEntries < 1 || o.MaxDepth < 1 {
		return o, collectionError("invalid_collection_bound")
	}
	if len(o.SecretValues) > 128 {
		return o, collectionError("invalid_secret_values")
	}
	set := map[string]bool{}
	secrets := []string{}
	for _, s := range o.SecretValues {
		if s == "" || len(s) > 8192 || !utf8.ValidString(s) {
			return o, collectionError("invalid_secret_values")
		}
		if !set[s] {
			set[s] = true
			secrets = append(secrets, s)
		}
	}
	sort.Slice(secrets, func(i, j int) bool {
		if len(secrets[i]) != len(secrets[j]) {
			return len(secrets[i]) > len(secrets[j])
		}
		return secrets[i] < secrets[j]
	})
	o.SecretValues = secrets
	return o, nil
}
func digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
func absoluteParts(path string) ([]string, error) {
	if !filepath.IsAbs(path) || path == "/" || len(path) > 4096 || strings.ContainsAny(path, "\x00\\") || !utf8.ValidString(path) {
		return nil, collectionError("unsafe_collection_root")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) > 127 {
		return nil, collectionError("unsafe_collection_root")
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || len(p) > 255 {
			return nil, collectionError("unsafe_collection_root")
		}
	}
	return parts, nil
}
func openAbsolute(path string, create bool, source *unix.Stat_t) (int, error) {
	parts, err := absoluteParts(path)
	if err != nil {
		return -1, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, collectionError("unsafe_collection_root")
	}
	for _, p := range parts {
		if source != nil {
			var st unix.Stat_t
			if unix.Fstat(fd, &st) != nil {
				unix.Close(fd)
				return -1, collectionError("unsafe_retention_root")
			}
			if st.Dev == source.Dev && st.Ino == source.Ino {
				unix.Close(fd)
				return -1, collectionError("retention_inside_source")
			}
		}
		next, openErr := unix.Openat(fd, p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if err := unix.Mkdirat(fd, p, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
				unix.Close(fd)
				return -1, collectionError("unsafe_retention_root")
			}
			if err := unix.Fsync(fd); err != nil {
				unix.Close(fd)
				return -1, err
			}
			next, openErr = unix.Openat(fd, p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		unix.Close(fd)
		if openErr != nil {
			return -1, openErr
		}
		fd = next
	}
	if source != nil {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Dev == source.Dev && st.Ino == source.Ino {
			unix.Close(fd)
			return -1, collectionError("retention_inside_source")
		}
	}
	return fd, nil
}
func mountID(fd int) (uint64, error) {
	var x unix.Statx_t
	err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &x)
	if err != nil || x.Mask&unix.STATX_MNT_ID == 0 {
		return 0, collectionError("mount_identity_unavailable")
	}
	return x.Mnt_id, nil
}

type SafeCollector struct {
	mu      sync.RWMutex
	Root    string
	Options CollectorOptions
	fd      int
	dev     uint64
	mount   uint64
}

func NewCollector(root string, options CollectorOptions) (*SafeCollector, error) {
	o, err := defaults(options)
	if err != nil {
		return nil, err
	}
	fd, err := openAbsolute(root, false, nil)
	if err != nil {
		return nil, collectionError("unsafe_collection_root")
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	mount, err := mountID(fd)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &SafeCollector{Root: root, Options: o, fd: fd, dev: uint64(st.Dev), mount: mount}, nil
}
func (c *SafeCollector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fd < 0 {
		return nil
	}
	err := unix.Close(c.fd)
	c.fd = -1
	return err
}
func (c *SafeCollector) parts(relative string) ([]string, error) {
	if c.fd < 0 {
		return nil, collectionError("collector_closed")
	}
	if relative == "" || strings.HasPrefix(relative, "/") || strings.ContainsAny(relative, "\x00\\") || len(relative) > 4096 || !utf8.ValidString(relative) {
		return nil, collectionError("unsafe_output_path")
	}
	parts := strings.Split(relative, "/")
	if len(parts) > c.Options.MaxDepth {
		return nil, collectionError("output_path_exceeds_bound")
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || len(p) > 255 {
			return nil, collectionError("unsafe_output_path")
		}
	}
	return parts, nil
}
func (c *SafeCollector) directory(parent int, name string) (int, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, collectionError("unsafe_output_directory")
	}
	var st unix.Stat_t
	err = unix.Fstat(fd, &st)
	mnt, merr := mountID(fd)
	if err != nil || merr != nil || uint64(st.Dev) != c.dev || mnt != c.mount {
		unix.Close(fd)
		return -1, collectionError("output_mount_crossing")
	}
	return fd, nil
}
func (c *SafeCollector) validateFile(fd int, st *unix.Stat_t) error {
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || uint64(st.Dev) != c.dev {
		return collectionError("unsafe_output_file")
	}
	m, err := mountID(fd)
	if err != nil || m != c.mount {
		return collectionError("output_mount_crossing")
	}
	return nil
}
func sameFile(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim && a.Nlink == b.Nlink
}
func (c *SafeCollector) openFile(relative string, maximum int64) (*os.File, unix.Stat_t, error) {
	parts, err := c.parts(relative)
	if err != nil {
		return nil, unix.Stat_t{}, err
	}
	parent, err := unix.Dup(c.fd)
	if err != nil {
		return nil, unix.Stat_t{}, err
	}
	defer func() { unix.Close(parent) }()
	for _, p := range parts[:len(parts)-1] {
		next, err := c.directory(parent, p)
		if err != nil {
			return nil, unix.Stat_t{}, err
		}
		unix.Close(parent)
		parent = next
	}
	fd, err := unix.Openat(parent, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, unix.Stat_t{}, collectionError("unsafe_output_file")
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err == nil {
		err = c.validateFile(fd, &st)
	}
	if err != nil || st.Size > maximum {
		unix.Close(fd)
		if err == nil {
			err = collectionError("output_file_exceeds_bound")
		}
		return nil, st, err
	}
	return os.NewFile(uintptr(fd), relative), st, nil
}
func (c *SafeCollector) read(relative string, maximum int64) ([]byte, error) {
	f, before, err := c.openFile(relative, maximum)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if err != nil {
		return nil, err
	}
	var after unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &after); err != nil {
		return nil, err
	}
	if err = c.validateFile(int(f.Fd()), &after); err != nil {
		return nil, err
	}
	if int64(len(raw)) > maximum || !sameFile(before, after) || int64(len(raw)) != after.Size {
		return nil, collectionError("output_changed")
	}
	return raw, nil
}
func (c *SafeCollector) Read(relative string, maxBytes int64) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if maxBytes < 0 {
		return nil, collectionError("invalid_collection_bound")
	}
	return c.read(relative, min64(maxBytes, min64(c.Options.MaxFileBytes, c.Options.MaxTotalBytes)))
}
func directoryNames(fd int, maximum int) ([]string, error) {
	dup, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dup), "directory")
	defer f.Close()
	// Open a fresh directory description: dup would share offsets with another
	// concurrent manifest and could skip entries.
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	names := []string{}
	for {
		batch, err := f.Readdirnames(64)
		if len(names)+len(batch) > maximum {
			return nil, collectionError("output_entries_exceed_bound")
		}
		names = append(names, batch...)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(names)
	return names, nil
}
func (c *SafeCollector) listFiles() ([]FileMetadata, error) {
	if c.fd < 0 {
		return nil, collectionError("collector_closed")
	}
	files := []FileMetadata{}
	entries := 0
	total := int64(0)
	var walk func(int, string) error
	walk = func(fd int, prefix string) error {
		names, err := directoryNames(fd, c.Options.MaxEntries-entries)
		if err != nil {
			return err
		}
		for _, name := range names {
			entries++
			relative := name
			if prefix != "" {
				relative = prefix + "/" + name
			}
			if _, err = c.parts(relative); err != nil {
				return err
			}
			var st unix.Stat_t
			if err = unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return collectionError("output_changed")
			}
			if st.Mode&unix.S_IFMT == unix.S_IFDIR {
				child, err := c.directory(fd, name)
				if err != nil {
					return err
				}
				err = walk(child, relative)
				unix.Close(child)
				if err != nil {
					return err
				}
			} else {
				if len(files) >= c.Options.MaxFiles {
					return collectionError("output_files_exceed_bound")
				}
				content, err := c.read(relative, min64(c.Options.MaxFileBytes, c.Options.MaxTotalBytes-total))
				if err != nil {
					return err
				}
				total += int64(len(content))
				files = append(files, FileMetadata{relative, int64(len(content)), digest(content)})
			}
		}
		return nil
	}
	if err := walk(c.fd, ""); err != nil {
		return nil, err
	}
	return files, nil
}
func (c *SafeCollector) ListFiles() ([]FileMetadata, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.listFiles()
}
func (c *SafeCollector) Collect() ([]FileMetadata, error) { return c.ListFiles() }
func privateDirectory(fd int) error {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		return collectionError("unsafe_retention_root")
	}
	return nil
}
func writeAll(fd int, raw []byte) error {
	for len(raw) > 0 {
		n, err := unix.Write(fd, raw)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		raw = raw[n:]
	}
	return nil
}
func (c *SafeCollector) Retain(destination string) ([]RetainedFile, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	manifest, err := c.listFiles()
	if err != nil {
		return nil, err
	}
	var src unix.Stat_t
	if err = unix.Fstat(c.fd, &src); err != nil {
		return nil, err
	}
	fd, err := openAbsolute(destination, true, &src)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err = privateDirectory(fd); err != nil {
		return nil, err
	}
	if err = unix.Flock(fd, unix.LOCK_EX); err != nil {
		return nil, err
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	target, err := NewCollector(destination, c.Options)
	if err != nil {
		return nil, err
	}
	defer target.Close()
	var root unix.Stat_t
	if unix.Fstat(target.fd, &root) != nil || root.Dev == src.Dev && root.Ino == src.Ino {
		return nil, collectionError("retention_inside_source")
	}
	var check unix.Stat_t
	if unix.Fstat(fd, &check) != nil || check.Dev != root.Dev || check.Ino != root.Ino {
		return nil, collectionError("retention_root_changed")
	}
	results := []RetainedFile{}
	for _, meta := range manifest {
		raw, err := c.read(meta.Path, c.Options.MaxFileBytes)
		if err != nil {
			return nil, err
		}
		if int64(len(raw)) != meta.SizeBytes || digest(raw) != meta.SHA256 {
			return nil, collectionError("output_changed")
		}
		parts, _ := target.parts(meta.Path)
		parent, err := unix.Dup(fd)
		if err != nil {
			return nil, err
		}
		err = func() error {
			defer func() { unix.Close(parent) }()
			for _, part := range parts[:len(parts)-1] {
				child, e := target.directory(parent, part)
				if e != nil {
					var info unix.Stat_t
					e = unix.Fstatat(parent, part, &info, unix.AT_SYMLINK_NOFOLLOW)
					if !errors.Is(e, unix.ENOENT) {
						return collectionError("unsafe_retention_directory")
					}
					if e = unix.Mkdirat(parent, part, 0700); e != nil && !errors.Is(e, unix.EEXIST) {
						return e
					}
					if e = unix.Fsync(parent); e != nil {
						return e
					}
					child, e = target.directory(parent, part)
					if e != nil {
						return e
					}
				}
				if e = privateDirectory(child); e != nil {
					unix.Close(child)
					return e
				}
				unix.Close(parent)
				parent = child
			}
			name := parts[len(parts)-1]
			var exists unix.Stat_t
			e := unix.Fstatat(parent, name, &exists, unix.AT_SYMLINK_NOFOLLOW)
			if e == nil {
				existing, e := target.read(meta.Path, c.Options.MaxFileBytes)
				if e != nil {
					return e
				}
				if int64(len(existing)) != meta.SizeBytes || digest(existing) != meta.SHA256 {
					return collectionError("retained_manifest_conflict")
				}
				return unix.Fsync(parent)
			}
			if !errors.Is(e, unix.ENOENT) {
				return e
			}
			temporary := ".hf2l-retain-" + domain.NewID()
			temp, e := unix.Openat(parent, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
			if e != nil {
				return e
			}
			published := false
			defer func() {
				if !published {
					unix.Unlinkat(parent, temporary, 0)
					unix.Fsync(parent)
				}
			}()
			if e = writeAll(temp, raw); e == nil {
				e = unix.Fsync(temp)
			}
			unix.Close(temp)
			if e != nil {
				return e
			}
			e = unix.Renameat2(parent, temporary, parent, name, unix.RENAME_NOREPLACE)
			if errors.Is(e, unix.EEXIST) {
				existing, e := target.read(meta.Path, c.Options.MaxFileBytes)
				if e != nil {
					return e
				}
				if int64(len(existing)) != meta.SizeBytes || digest(existing) != meta.SHA256 {
					return collectionError("retained_manifest_conflict")
				}
			} else if e != nil {
				return e
			} else {
				published = true
			}
			return unix.Fsync(parent)
		}()
		if err != nil {
			return nil, err
		}
		results = append(results, RetainedFile{meta.Path, filepath.Join(destination, meta.Path), meta.SizeBytes, meta.SHA256})
	}
	if err = unix.Fsync(fd); err != nil {
		return nil, err
	}
	return results, nil
}
func (c *SafeCollector) redact(value string, maximum int64) (string, error) {
	for _, secret := range c.Options.SecretValues {
		count := strings.Count(value, secret)
		// Bound expansion before allocating replacement text.
		expanded := int64(len(value)) + int64(count)*int64(len("[REDACTED]")-len(secret))
		if expanded > maximum {
			return "", collectionError("redacted_output_exceeds_bound")
		}
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}
	if int64(len(value)) > maximum {
		return "", collectionError("redacted_output_exceeds_bound")
	}
	return value, nil
}

var secretKey = regexp.MustCompile(`(?i)(^|_)(password|passwd|secret|token|credentials|private_key|access_key|api_key)($|_)`)
var normalizedKey = regexp.MustCompile(`[^a-z0-9]+`)

func (c *SafeCollector) sanitize(v any, depth int) (any, error) {
	if depth > 16 {
		return nil, collectionError("event_nesting_exceeds_bound")
	}
	switch value := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for key, item := range value {
			normal := strings.Trim(normalizedKey.ReplaceAllString(strings.ToLower(key), "_"), "_")
			if secretKey.MatchString(normal) {
				continue
			}
			safe, e := c.redact(key, int64(c.Options.MaxEventBytes))
			if e != nil {
				return nil, e
			}
			if _, exists := out[safe]; exists {
				return nil, collectionError("redacted_event_key_collision")
			}
			out[safe], e = c.sanitize(item, depth+1)
			if e != nil {
				return nil, e
			}
		}
		return out, nil
	case []any:
		out := make([]any, len(value))
		for i, item := range value {
			var e error
			out[i], e = c.sanitize(item, depth+1)
			if e != nil {
				return nil, e
			}
		}
		return out, nil
	case string:
		return c.redact(value, int64(c.Options.MaxEventBytes))
	default:
		return v, nil
	}
}
func (c *SafeCollector) Logs(relative string, maxBytes int64) (string, error) {
	raw, err := c.Read(relative, maxBytes)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(raw) {
		return "", collectionError("logs_not_utf8")
	}
	return c.redact(string(raw), min64(maxBytes, min64(c.Options.MaxFileBytes, c.Options.MaxTotalBytes)))
}
func (c *SafeCollector) Events(relative string) ([]map[string]any, error) {
	raw, err := c.Read(relative, min64(c.Options.MaxFileBytes, c.Options.MaxTotalBytes))
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	reader := bufio.NewReaderSize(bytes.NewReader(raw), c.Options.MaxEventBytes+2)
	lines := 0
	for {
		line, e := reader.ReadSlice('\n')
		if errors.Is(e, bufio.ErrBufferFull) {
			return nil, collectionError("event_exceeds_bound")
		}
		if len(line) == 0 && errors.Is(e, io.EOF) {
			break
		}
		if e != nil && !errors.Is(e, io.EOF) {
			return nil, e
		}
		lines++
		if lines > c.Options.MaxEvents {
			return nil, collectionError("event_count_exceeds_bound")
		}
		line = bytes.TrimSuffix(line, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) > c.Options.MaxEventBytes {
			return nil, collectionError("event_exceeds_bound")
		}
		if len(bytes.TrimSpace(line)) == 0 {
			if errors.Is(e, io.EOF) {
				break
			}
			continue
		}
		if !utf8.Valid(line) {
			return nil, collectionError("event_not_utf8")
		}
		value, err := strictEventJSON(line)
		if err != nil {
			return nil, collectionError("invalid_event_json")
		}
		obj, ok := value.(map[string]any)
		if !ok {
			return nil, collectionError("event_not_object")
		}
		safe, err := c.sanitize(obj, 0)
		if err != nil {
			return nil, err
		}
		encoded, err := domain.CanonicalJSON(safe)
		if err != nil || len(encoded) > c.Options.MaxEventBytes {
			return nil, collectionError("event_exceeds_bound")
		}
		out = append(out, safe.(map[string]any))
		if errors.Is(e, io.EOF) {
			break
		}
	}
	return out, nil
}

type fileNode struct {
	relative  string
	stat      unix.Stat_t
	directory bool
}

func DeleteRetained(root string, expected []RetainedFile, options DeleteOptions) (bool, error) {
	o, err := defaults(options)
	if err != nil {
		return false, err
	}
	parts, err := absoluteParts(root)
	if err != nil {
		return false, err
	}
	if len(expected) > o.MaxFiles {
		return false, collectionError("retained_manifest_exceeds_bound")
	}
	manifest := map[string]RetainedFile{}
	allowedDirs := map[string]bool{}
	total := int64(0)
	fake := &SafeCollector{fd: 0, Options: o}
	for _, item := range expected {
		pieces, e := fake.parts(item.Path)
		if e != nil {
			return false, e
		}
		if item.Locator != filepath.Join(root, item.Path) || item.SizeBytes < 0 || item.SizeBytes > o.MaxFileBytes || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(item.SHA256) {
			return false, collectionError("invalid_retained_manifest")
		}
		if _, exists := manifest[item.Path]; exists {
			return false, collectionError("duplicate_retained_file")
		}
		if item.SizeBytes > o.MaxTotalBytes-total {
			return false, collectionError("retained_manifest_exceeds_bound")
		}
		total += item.SizeBytes
		manifest[item.Path] = item
		for i := 1; i < len(pieces); i++ {
			allowedDirs[strings.Join(pieces[:i], "/")] = true
		}
	}
	parentPath := "/" + strings.Join(parts[:len(parts)-1], "/")
	var parent int
	if parentPath == "/" {
		parent, err = unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	} else {
		parent, err = openAbsolute(parentPath, false, nil)
	}
	if errors.Is(err, unix.ENOENT) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, parts[len(parts)-1], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	if err = privateDirectory(fd); err != nil {
		return false, err
	}
	if err = unix.Flock(fd, unix.LOCK_EX); err != nil {
		return false, err
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	var before unix.Stat_t
	if err = unix.Fstat(fd, &before); err != nil {
		return false, err
	}
	c, err := NewCollector(root, o)
	if err != nil {
		return false, err
	}
	defer c.Close()
	var reopen unix.Stat_t
	if unix.Fstat(c.fd, &reopen) != nil || before.Dev != reopen.Dev || before.Ino != reopen.Ino {
		return false, collectionError("retained_root_changed")
	}
	actual, err := c.ListFiles()
	if err != nil {
		return false, err
	}
	for _, item := range actual {
		owned, ok := manifest[item.Path]
		if !ok || owned.SizeBytes != item.SizeBytes || owned.SHA256 != item.SHA256 {
			return false, collectionError("retained_manifest_conflict")
		}
	}
	nodes := []fileNode{}
	count := 0
	var inventory func(int, string) error
	inventory = func(d int, prefix string) error {
		names, e := directoryNames(d, o.MaxEntries-count)
		if e != nil {
			return e
		}
		for _, name := range names {
			count++
			relative := name
			if prefix != "" {
				relative = prefix + "/" + name
			}
			var st unix.Stat_t
			if e = unix.Fstatat(d, name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
				return e
			}
			if st.Mode&unix.S_IFMT == unix.S_IFDIR {
				if !allowedDirs[relative] {
					return collectionError("unowned_retained_directory")
				}
				child, e := c.directory(d, name)
				if e != nil {
					return e
				}
				if e = privateDirectory(child); e == nil {
					e = inventory(child, relative)
				}
				unix.Close(child)
				if e != nil {
					return e
				}
				nodes = append(nodes, fileNode{relative, st, true})
			} else {
				if st.Uid != uint32(os.Geteuid()) {
					return collectionError("unowned_retained_file")
				}
				if _, ok := manifest[relative]; !ok {
					return collectionError("unowned_retained_file")
				}
				nodes = append(nodes, fileNode{relative, st, false})
			}
		}
		return nil
	}
	if err = inventory(fd, ""); err != nil {
		return false, err
	}
	// All files and directories are inventoried before the first destructive step.
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].directory != nodes[j].directory {
			return !nodes[i].directory
		}
		return strings.Count(nodes[i].relative, "/") > strings.Count(nodes[j].relative, "/")
	})
	for _, node := range nodes {
		pieces, _ := c.parts(node.relative)
		d, e := unix.Dup(fd)
		if e != nil {
			return false, e
		}
		e = func() error {
			defer func() { unix.Close(d) }()
			for _, p := range pieces[:len(pieces)-1] {
				child, e := c.directory(d, p)
				if e != nil {
					return e
				}
				unix.Close(d)
				d = child
			}
			name := pieces[len(pieces)-1]
			if !node.directory {
				raw, e := c.read(node.relative, o.MaxFileBytes)
				if e != nil {
					return e
				}
				meta := manifest[node.relative]
				if int64(len(raw)) != meta.SizeBytes || digest(raw) != meta.SHA256 {
					return collectionError("retained_file_changed")
				}
			}
			var st unix.Stat_t
			if e = unix.Fstatat(d, name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
				return e
			}
			if st.Dev != node.stat.Dev || st.Ino != node.stat.Ino {
				return collectionError("retained_identity_changed")
			}
			flags := 0
			if node.directory {
				flags = unix.AT_REMOVEDIR
				if st.Mode&unix.S_IFMT != unix.S_IFDIR {
					return collectionError("retained_identity_changed")
				}
			}
			if e = unix.Unlinkat(d, name, flags); e != nil {
				return e
			}
			return unix.Fsync(d)
		}()
		if e != nil {
			return false, e
		}
	}
	var final unix.Stat_t
	if err = unix.Fstatat(parent, parts[len(parts)-1], &final, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false, err
	}
	if final.Dev != before.Dev || final.Ino != before.Ino || final.Mode&unix.S_IFMT != unix.S_IFDIR {
		return false, collectionError("retained_root_changed")
	}
	if err = unix.Unlinkat(parent, parts[len(parts)-1], unix.AT_REMOVEDIR); err != nil {
		return false, err
	}
	if err = unix.Fsync(parent); err != nil {
		return false, err
	}
	return true, nil
}

func collectionContext(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("output collection refused: %w", err)
}

// strictEventJSON preserves the collection contract: duplicate keys in any
// nested object are rejected instead of silently replacing earlier values.
func strictEventJSON(raw []byte) (any, error) {
	if _, err := domain.DecodeJSON(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		if depth > 16 {
			return nil, collectionError("event_nesting_exceeds_bound")
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		delimiter, container := token.(json.Delim)
		if !container {
			return token, nil
		}
		switch delimiter {
		case '{':
			object := map[string]any{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, collectionError("invalid_event_json")
				}
				if _, exists := object[key]; exists {
					return nil, collectionError("duplicate_event_key")
				}
				value, err := read(depth + 1)
				if err != nil {
					return nil, err
				}
				object[key] = value
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, collectionError("invalid_event_json")
			}
			return object, nil
		case '[':
			array := []any{}
			for decoder.More() {
				value, err := read(depth + 1)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, collectionError("invalid_event_json")
			}
			return array, nil
		default:
			return nil, collectionError("invalid_event_json")
		}
	}
	value, err := read(0)
	if err != nil {
		return nil, err
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, collectionError("invalid_event_json")
	}
	return value, nil
}
