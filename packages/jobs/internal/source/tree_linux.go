//go:build linux

package source

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type Tree struct {
	root   *os.File
	dev    uint64
	limits Limits
	closed bool
}

func openDirectory(path string, private bool) (*os.File, error) {
	if !canonicalAbsolute(path) {
		return nil, fmt.Errorf("%w: expected canonical absolute directory", ErrUnsafe)
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return nil, fmt.Errorf("%w: directory contains link or inaccessible ancestor", ErrUnsafe)
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		f.Close()
		return nil, e
	}
	if private && (st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0) {
		f.Close()
		return nil, fmt.Errorf("%w: directory must be private and owned", ErrUnsafe)
	}
	return f, nil
}
func EnsurePrivateDirectory(path string) error {
	if !canonicalAbsolute(path) {
		return fmt.Errorf("%w: noncanonical workspace", ErrUnsafe)
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer func() { unix.Close(fd) }()
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == unix.ENOENT {
			if err = unix.Mkdirat(fd, part, 0700); err != nil && err != unix.EEXIST {
				return err
			}
			next, err = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if err != nil {
			return fmt.Errorf("%w: cannot allocate private directory", ErrUnsafe)
		}
		unix.Close(fd)
		fd = next
	}
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return e
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		return fmt.Errorf("%w: workspace parent must be private and owned", ErrUnsafe)
	}
	return nil
}
func OpenTree(path string, limits Limits) (*Tree, error) {
	limits = limits.defaults()
	if limits.MaxFiles < 1 || limits.MaxEntries < 1 || limits.MaxFileBytes < 1 || limits.MaxTotalBytes < 1 || limits.MaxDepth < 1 {
		return nil, fmt.Errorf("%w: invalid collection limits", ErrUnsafe)
	}
	f, e := openDirectory(path, false)
	if e != nil {
		return nil, e
	}
	var st unix.Stat_t
	if e = unix.Fstat(int(f.Fd()), &st); e != nil {
		f.Close()
		return nil, e
	}
	return &Tree{root: f, dev: st.Dev, limits: limits}, nil
}
func (t *Tree) Close() error {
	if t.closed {
		return nil
	}
	t.closed = true
	return t.root.Close()
}
func (t *Tree) check(st *unix.Stat_t, regular bool) error {
	if st.Dev != t.dev {
		return fmt.Errorf("%w: filesystem boundary changed", ErrUnsafe)
	}
	if regular && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1) {
		return fmt.Errorf("%w: link or special source file", ErrUnsafe)
	}
	return nil
}
func sameStat(a, b *unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func (t *Tree) openChildDir(parent int, name string) (int, error) {
	fd, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, fmt.Errorf("%w: unsafe source directory", ErrUnsafe)
	}
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e == nil {
		e = t.check(&st, false)
	}
	if e != nil {
		unix.Close(fd)
		return -1, e
	}
	return fd, nil
}
func (t *Tree) Read(name string, maxBytes int64) ([]byte, error) {
	var output bytes.Buffer
	_, err := t.Copy(name, maxBytes, &output)
	if err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

// Copy hashes a bounded regular file while streaming; it never buffers the body.
func (t *Tree) Copy(name string, maxBytes int64, sink io.Writer) (File, error) {
	if t.closed {
		return File{}, fmt.Errorf("%w: closed source reader", ErrUnsafe)
	}
	if e := SafeName(name); e != nil {
		return File{}, e
	}
	parts := strings.Split(name, "/")
	fd, e := unix.Dup(int(t.root.Fd()))
	if e != nil {
		return File{}, e
	}
	defer func() { unix.Close(fd) }()
	for _, part := range parts[:len(parts)-1] {
		next, err := t.openChildDir(fd, part)
		if err != nil {
			return File{}, err
		}
		unix.Close(fd)
		fd = next
	}
	leaf, e := unix.Openat(fd, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return File{}, fmt.Errorf("%w: inaccessible source file", ErrUnsafe)
	}
	f := os.NewFile(uintptr(leaf), name)
	defer f.Close()
	var before, after unix.Stat_t
	if e = unix.Fstat(leaf, &before); e != nil {
		return File{}, e
	}
	if e = t.check(&before, true); e != nil {
		return File{}, e
	}
	limit := min(t.limits.MaxFileBytes, t.limits.MaxTotalBytes, maxBytes)
	if limit < 0 || before.Size > limit {
		return File{}, fmt.Errorf("%w: file exceeds byte bound", ErrUnsafe)
	}
	if sink == nil {
		sink = io.Discard
	}
	digest := sha256.New()
	n, e := io.CopyBuffer(io.MultiWriter(sink, digest), io.LimitReader(f, limit+1), make([]byte, 65536))
	if e != nil {
		return File{}, e
	}
	if e = unix.Fstat(leaf, &after); e != nil {
		return File{}, e
	}
	if e = t.check(&after, true); e != nil {
		return File{}, e
	}
	if !sameStat(&before, &after) || n != before.Size || n > limit {
		return File{}, fmt.Errorf("%w: source changed during read", ErrUnsafe)
	}
	return File{name, hex.EncodeToString(digest.Sum(nil)), n, after.Blocks * 512}, nil
}
func (t *Tree) List() ([]File, error) {
	if t.closed {
		return nil, fmt.Errorf("%w: closed source reader", ErrUnsafe)
	}
	var files []File
	var entries, total int64
	var visit func(int, string, int) error
	visit = func(fd int, prefix string, depth int) error {
		duplicate, e := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if e != nil {
			return e
		}
		directory := os.NewFile(uintptr(duplicate), prefix)
		defer directory.Close()
		for {
			names, e := directory.Readdirnames(128)
			for _, name := range names {
				entries++
				if entries > t.limits.MaxEntries || depth >= t.limits.MaxDepth {
					return fmt.Errorf("%w: entry/depth limit", ErrUnsafe)
				}
				relative := name
				if prefix != "" {
					relative = prefix + "/" + name
				}
				if e := SafeName(relative); e != nil {
					return e
				}
				var st unix.Stat_t
				if e = unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
					return e
				}
				if e = t.check(&st, false); e != nil {
					return e
				}
				if st.Mode&unix.S_IFMT == unix.S_IFDIR {
					child, err := t.openChildDir(fd, name)
					if err != nil {
						return err
					}
					var current unix.Stat_t
					err = unix.Fstat(child, &current)
					if err == nil && (current.Dev != st.Dev || current.Ino != st.Ino) {
						err = fmt.Errorf("%w: directory replaced", ErrUnsafe)
					}
					if err == nil {
						err = visit(child, relative, depth+1)
					}
					unix.Close(child)
					if err != nil {
						return err
					}
				} else {
					if e = t.check(&st, true); e != nil {
						return e
					}
					if int64(len(files)) >= t.limits.MaxFiles || st.Size > t.limits.MaxFileBytes || total+st.Size > t.limits.MaxTotalBytes {
						return fmt.Errorf("%w: source byte/file limit", ErrUnsafe)
					}
					item, err := t.Copy(relative, min(t.limits.MaxFileBytes, t.limits.MaxTotalBytes-total), io.Discard)
					if err != nil {
						return err
					}
					files = append(files, item)
					total += item.SizeBytes
				}
			}
			if e == io.EOF {
				break
			}
			if e != nil {
				return e
			}
		}
		return nil
	}
	if e := visit(int(t.root.Fd()), "", 0); e != nil {
		return nil, e
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}
func PhysicalBytes(path string, a Approval) (int64, error) {
	tr, e := OpenTree(path, Limits{MaxFiles: a.MaxFiles, MaxEntries: 3*a.MaxFiles + 1024, MaxFileBytes: a.MaxBytes, MaxTotalBytes: a.MaxBytes})
	if e != nil {
		return 0, e
	}
	defer tr.Close()
	var total, entries, files, logical int64
	var visit func(int, int) error
	visit = func(fd, depth int) error {
		var st unix.Stat_t
		if e := unix.Fstat(fd, &st); e != nil {
			return e
		}
		if st.Dev != tr.dev || st.Uid != uint32(os.Geteuid()) {
			return fmt.Errorf("%w: physical ownership changed", ErrUnsafe)
		}
		total += st.Blocks * 512
		d, e := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if e != nil {
			return e
		}
		f := os.NewFile(uintptr(d), "physical")
		defer f.Close()
		for {
			names, err := f.Readdirnames(128)
			for _, name := range names {
				entries++
				if entries > 3*a.MaxFiles+1024 || depth >= 32 {
					return fmt.Errorf("%w: physical entry limit", ErrUnsafe)
				}
				var before unix.Stat_t
				if e := unix.Fstatat(fd, name, &before, unix.AT_SYMLINK_NOFOLLOW); e != nil {
					return e
				}
				if before.Dev != tr.dev || before.Uid != uint32(os.Geteuid()) {
					return fmt.Errorf("%w: physical ownership changed", ErrUnsafe)
				}
				if before.Mode&unix.S_IFMT == unix.S_IFDIR {
					child, e := tr.openChildDir(fd, name)
					if e != nil {
						return e
					}
					var current unix.Stat_t
					e = unix.Fstat(child, &current)
					if e == nil && (current.Dev != before.Dev || current.Ino != before.Ino) {
						e = fmt.Errorf("%w: physical directory replaced", ErrUnsafe)
					}
					if e == nil {
						e = visit(child, depth+1)
					}
					unix.Close(child)
					if e != nil {
						return e
					}
				} else {
					if e := tr.check(&before, true); e != nil {
						return e
					}
					files++
					logical += before.Size
					if files > a.MaxFiles || before.Size > a.MaxBytes || logical > a.MaxBytes {
						return fmt.Errorf("%w: physical logical bound", ErrUnsafe)
					}
					total += before.Blocks * 512
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
		}
		return nil
	}
	if e = visit(int(tr.root.Fd()), 0); e != nil {
		return 0, e
	}
	return total, nil
}

// PublishDirectory atomically refuses replacement of an existing destination.
func PublishDirectory(staged, destination string) error {
	parent, e := openDirectory(filepath.Dir(destination), true)
	if e != nil {
		return e
	}
	defer parent.Close()
	srcParent, e := openDirectory(filepath.Dir(staged), true)
	if e != nil {
		return e
	}
	defer srcParent.Close()
	if e = unix.Renameat2(int(srcParent.Fd()), filepath.Base(staged), int(parent.Fd()), filepath.Base(destination), unix.RENAME_NOREPLACE); e != nil {
		return fmt.Errorf("%w: immutable directory publication failed", ErrUnsafe)
	}
	return parent.Sync()
}
