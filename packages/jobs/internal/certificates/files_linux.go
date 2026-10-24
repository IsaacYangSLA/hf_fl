//go:build linux

package certificates

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ReadPEMFile refuses every symlink component and mutable/private material.
func readBoundedFile(path string, private bool, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, ErrRefused
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, e := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrRefused
	}
	defer func() { syscall.Close(fd) }()
	for _, part := range parts[:len(parts)-1] {
		child, e := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if e != nil {
			return nil, ErrRefused
		}
		syscall.Close(fd)
		fd = child
	}
	var parent syscall.Stat_t
	if syscall.Fstat(fd, &parent) != nil {
		return nil, ErrRefused
	}
	forbidden := uint32(0022)
	if private {
		forbidden = 0077
	}
	if (parent.Uid != 0 && parent.Uid != uint32(os.Geteuid())) || parent.Mode&forbidden != 0 {
		return nil, ErrRefused
	}
	filefd, e := syscall.Openat(fd, parts[len(parts)-1], syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrRefused
	}
	file := os.NewFile(uintptr(filefd), "approved certificate material")
	defer file.Close()
	var before, after syscall.Stat_t
	if syscall.Fstat(filefd, &before) != nil {
		return nil, ErrRefused
	}
	if before.Mode&syscall.S_IFMT != syscall.S_IFREG || before.Nlink != 1 || (before.Uid != 0 && before.Uid != uint32(os.Geteuid())) || before.Mode&forbidden != 0 || before.Size <= 0 || before.Size > maximum {
		return nil, ErrRefused
	}
	b, e := io.ReadAll(io.LimitReader(file, maximum+1))
	if e != nil || syscall.Fstat(filefd, &after) != nil || int64(len(b)) > maximum || int64(len(b)) != before.Size || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, ErrRefused
	}
	return b, nil
}

// ReadPEMFile loads bounded key or individual certificate material.
func ReadPEMFile(path string, private bool) ([]byte, error) {
	return readBoundedFile(path, private, MaxPEMBytes)
}

// ReadTrustBundleFile permits a bounded public CA bundle, preserving descriptor safety.
func ReadTrustBundleFile(path string) ([]byte, error) { return readBoundedFile(path, false, 1024*1024) }
