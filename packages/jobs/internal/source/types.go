// Package source materializes only approved immutable Git trees.
package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var ErrUnsafe = errors.New("unsafe or unapproved source")
var objectID = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)
var digestID = regexp.MustCompile(`^[a-f0-9]{64}$`)
var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type Approval struct {
	SourceID    string
	Projects    []string
	URL         string
	MirrorPath  string
	Commits     []string
	MaxBytes    int64
	MaxFiles    int64
	MaxGitBytes int64
	MaxGitFiles int64
}

func (a Approval) Defaults() Approval {
	if a.MaxBytes == 0 {
		a.MaxBytes = 256 << 20
	}
	if a.MaxFiles == 0 {
		a.MaxFiles = 100000
	}
	if a.MaxGitBytes == 0 {
		a.MaxGitBytes = 256 << 20
	}
	if a.MaxGitFiles == 0 {
		a.MaxGitFiles = 100000
	}
	return a
}
func (a Approval) Validate() error {
	if !identifier.MatchString(a.SourceID) || len(a.Projects) == 0 || len(a.Commits) == 0 || (a.URL == "") == (a.MirrorPath == "") {
		return fmt.Errorf("%w: incomplete source approval", ErrUnsafe)
	}
	for _, v := range a.Projects {
		if !identifier.MatchString(v) {
			return fmt.Errorf("%w: invalid project", ErrUnsafe)
		}
	}
	for _, v := range a.Commits {
		if !objectID.MatchString(v) {
			return fmt.Errorf("%w: commit is not exact lowercase object ID", ErrUnsafe)
		}
	}
	if a.MaxBytes < 1 || a.MaxBytes > 1<<30 || a.MaxGitBytes < 1 || a.MaxGitBytes > 1<<30 || a.MaxFiles < 1 || a.MaxFiles > 100000 || a.MaxGitFiles < 1 || a.MaxGitFiles > 100000 {
		return fmt.Errorf("%w: unsupported source bound", ErrUnsafe)
	}
	if a.MirrorPath != "" {
		f, e := openDirectory(a.MirrorPath, false)
		if e != nil {
			return e
		}
		f.Close()
	}
	return nil
}

type Snapshot struct {
	SourceID      string
	Commit        string
	Path          string
	Manifest      map[string]string
	Digest        string
	Bytes         int64
	PhysicalBytes int64
}
type File struct {
	Path                     string
	SHA256                   string
	SizeBytes, PhysicalBytes int64
}
type Limits struct {
	MaxFiles, MaxEntries, MaxFileBytes, MaxTotalBytes int64
	MaxDepth                                          int
}

func (l Limits) defaults() Limits {
	if l.MaxFiles == 0 {
		l.MaxFiles = 100000
	}
	if l.MaxEntries == 0 {
		l.MaxEntries = 3*l.MaxFiles + 1024
	}
	if l.MaxFileBytes == 0 {
		l.MaxFileBytes = 1 << 30
	}
	if l.MaxTotalBytes == 0 {
		l.MaxTotalBytes = 1 << 30
	}
	if l.MaxDepth == 0 {
		l.MaxDepth = 32
	}
	return l
}
func MetadataPeakBytes(a Approval) int64 { return 8192 * (3*a.MaxFiles + 1024) }
func GitPeakBytes(a Approval) int64      { return a.MaxGitBytes + 8192*(3*a.MaxGitFiles+1024) }
func SafeName(name string) error {
	if name == "" || !utf8.ValidString(name) || len(name) > 4096 || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return fmt.Errorf("%w: unsafe source path", ErrUnsafe)
	}
	parts := strings.Split(name, "/")
	if len(parts) > 32 {
		return fmt.Errorf("%w: source path depth", ErrUnsafe)
	}
	for _, c := range name {
		if c < 32 || c == 127 {
			return fmt.Errorf("%w: control in source path", ErrUnsafe)
		}
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			return fmt.Errorf("%w: unsafe source path component", ErrUnsafe)
		}
		switch strings.ToLower(part) {
		case ".git", ".gitconfig", ".git-credentials", ".netrc", ".ssh":
			return fmt.Errorf("%w: credential-bearing source path", ErrUnsafe)
		}
	}
	return nil
}

// ManifestDigest matches Python's sorted compact json.dumps default ASCII form.
func ManifestDigest(m map[string]string) (string, error) {
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if !digestID.MatchString(v) {
			return "", fmt.Errorf("%w: invalid manifest digest", ErrUnsafe)
		}
		if err := SafeName(k); err != nil {
			return "", err
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(asciiJSON(k))
		b.WriteByte(':')
		b.WriteString(asciiJSON(m[k]))
	}
	b.WriteByte('}')
	d := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(d[:]), nil
}
func asciiJSON(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\b':
			b.WriteString("\\b")
		case '\f':
			b.WriteString("\\f")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if r < 32 || r >= 127 {
				if r <= 0xffff {
					fmt.Fprintf(&b, "\\u%04x", r)
				} else {
					hi, lo := utf16.EncodeRune(r)
					fmt.Fprintf(&b, "\\u%04x\\u%04x", hi, lo)
				}
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
func CloneManifest(m map[string]string) map[string]string {
	r := make(map[string]string, len(m))
	for k, v := range m {
		r[k] = v
	}
	return r
}
func VerifySnapshot(path string, manifest map[string]string, maxBytes, maxFiles int64) error {
	tr, e := OpenTree(path, Limits{MaxFiles: maxFiles, MaxEntries: 3*maxFiles + 1024, MaxFileBytes: maxBytes, MaxTotalBytes: maxBytes})
	if e != nil {
		return e
	}
	defer tr.Close()
	fs, e := tr.List()
	if e != nil {
		return e
	}
	if len(fs) != len(manifest) {
		return fmt.Errorf("%w: snapshot file set changed", ErrUnsafe)
	}
	for _, f := range fs {
		if manifest[f.Path] != f.SHA256 {
			return fmt.Errorf("%w: snapshot file changed", ErrUnsafe)
		}
	}
	return nil
}

type Resolver func(context.Context, string) ([]net.IP, error)

func canonicalAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/"
}
