package participants

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func secureRead(root, path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(root) || root == "/" || path == "" || strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\\\x00\r\n") || maximum < 1 {
		return nil, errors.New("unsafe source path")
	}
	components := strings.Split(path, "/")
	if len(components) > 64 {
		return nil, errors.New("unsafe source path")
	}
	for _, p := range components {
		if p == "" || p == "." || p == ".." {
			return nil, errors.New("unsafe source path")
		}
	}
	// Walk from an already opened root and never follow symlinks. Restrict every
	// child to the same device and invoking owner.
	fd, e := cleanupOpenAbsolute(root)
	if e != nil {
		return nil, e
	}
	defer func() { unix.Close(fd) }()
	var base unix.Stat_t
	if e = unix.Fstat(fd, &base); e != nil {
		return nil, e
	}
	if base.Uid != uint32(os.Geteuid()) || base.Mode&0022 != 0 {
		return nil, errors.New("unsafe source root")
	}
	for i, name := range components {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(components)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, e := unix.Openat(fd, name, flags, 0)
		if e != nil {
			return nil, e
		}
		unix.Close(fd)
		fd = next
		var st unix.Stat_t
		if e = unix.Fstat(fd, &st); e != nil {
			return nil, e
		}
		if st.Dev != base.Dev || st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
			return nil, errors.New("unsafe source ownership")
		}
		if i < len(components)-1 {
			continue
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size < 0 || st.Size > maximum {
			return nil, errors.New("unsafe source file")
		}
		dup, e := unix.Dup(fd)
		if e != nil {
			return nil, e
		}
		file := os.NewFile(uintptr(dup), "participant-source")
		data, e := io.ReadAll(io.LimitReader(file, maximum+1))
		file.Close()
		if e != nil {
			return nil, e
		}
		var after unix.Stat_t
		if e = unix.Fstat(fd, &after); e != nil {
			return nil, e
		}
		if int64(len(data)) > maximum || int64(len(data)) != st.Size || after.Dev != st.Dev || after.Ino != st.Ino || after.Size != st.Size || after.Mtim != st.Mtim || after.Ctim != st.Ctim {
			return nil, errors.New("source changed while reading")
		}
		return data, nil
	}
	return nil, errors.New("source file missing")
}
