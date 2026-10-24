//go:build linux

package source

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Registry struct {
	Approvals    map[string]Approval
	AllowedHosts map[string]bool
	Resolver     Resolver
}

func NewRegistry(approvals []Approval, allowedHosts []string) (*Registry, error) {
	r := &Registry{Approvals: map[string]Approval{}, AllowedHosts: map[string]bool{}}
	r.Resolver = func(ctx context.Context, host string) ([]net.IP, error) {
		values, e := net.DefaultResolver.LookupIPAddr(ctx, host)
		ips := make([]net.IP, 0, len(values))
		for _, v := range values {
			ips = append(ips, v.IP)
		}
		return ips, e
	}
	for _, a := range approvals {
		a = a.Defaults()
		if e := a.Validate(); e != nil {
			return nil, e
		}
		if _, exists := r.Approvals[a.SourceID]; exists {
			return nil, fmt.Errorf("%w: duplicate source approval", ErrUnsafe)
		}
		a.Projects = append([]string(nil), a.Projects...)
		a.Commits = append([]string(nil), a.Commits...)
		r.Approvals[a.SourceID] = a
	}
	for _, host := range allowedHosts {
		if host == "" || strings.ContainsAny(host, "/\\\r\n\x00") {
			return nil, fmt.Errorf("%w: invalid approved host", ErrUnsafe)
		}
		r.AllowedHosts[strings.ToLower(host)] = true
	}
	return r, nil
}
func (r *Registry) Authorize(project, sourceID, commit string) (Approval, error) {
	a, ok := r.Approvals[sourceID]
	if !ok || !contains(a.Projects, project) || !contains(a.Commits, commit) {
		return Approval{}, fmt.Errorf("%w: source or exact commit is not approved for project", ErrUnsafe)
	}
	if e := a.Validate(); e != nil {
		return Approval{}, e
	}
	return a, nil
}
func contains(items []string, value string) bool {
	for _, v := range items {
		if v == value {
			return true
		}
	}
	return false
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
}

func publicAddress(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsUnspecified() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// Remote resolves once and pins every transport address; redirects and proxies are disabled by runGit.
func (r *Registry) Remote(ctx context.Context, a Approval) (string, string, error) {
	u, e := url.Parse(a.URL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") || !r.AllowedHosts[strings.ToLower(u.Hostname())] || !strings.HasPrefix(u.Path, "/") || strings.ContainsAny(a.URL, "\r\n\x00") {
		return "", "", fmt.Errorf("%w: expected approved credential-free HTTPS repository", ErrUnsafe)
	}
	ips, e := r.Resolver(ctx, strings.ToLower(u.Hostname()))
	if e != nil || len(ips) == 0 {
		return "", "", fmt.Errorf("%w: approved host did not resolve", ErrUnsafe)
	}
	addressSet := map[string]bool{}
	for _, ip := range ips {
		if !publicAddress(ip) {
			return "", "", fmt.Errorf("%w: source address is not public", ErrUnsafe)
		}
		value := ip.String()
		if strings.Contains(value, ":") {
			value = "[" + value + "]"
		}
		addressSet[value] = true
	}
	addresses := make([]string, 0, len(addressSet))
	for v := range addressSet {
		addresses = append(addresses, v)
	}
	sort.Strings(addresses)
	return a.URL, strings.ToLower(u.Hostname()) + ":443:" + strings.Join(addresses, ","), nil
}

type limitWriter struct {
	target   io.Writer
	limit, n int64
	cancel   context.CancelFunc
	mu       sync.Mutex
}

func (w *limitWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if int64(len(p)) > w.limit-w.n {
		w.cancel()
		return 0, fmt.Errorf("%w: bounded Git output exceeded", ErrUnsafe)
	}
	n, e := w.target.Write(p)
	w.n += int64(n)
	return n, e
}
func runGit(ctx context.Context, repository, resolved string, outputLimit, fileLimit int64, sink io.Writer, args ...string) ([]byte, error) {
	if outputLimit < 1 || fileLimit < 1 {
		return nil, fmt.Errorf("%w: invalid Git bounds", ErrUnsafe)
	}
	limiter, e := exec.LookPath("prlimit")
	if e != nil {
		return nil, fmt.Errorf("%w: bounded Git requires Linux prlimit", ErrUnsafe)
	}
	timeout, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	command := []string{"--as=536870912", "--cpu=120", "--fsize=" + strconv.FormatInt(fileLimit, 10), "--", "git", "--no-optional-locks",
		"-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null", "-c", "credential.helper=", "-c", "credential.interactive=false",
		"-c", "http.followRedirects=false", "-c", "http.proxy=", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
		"-c", "fetch.unpackLimit=1", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-c", "transfer.unpackLimit=1", "-c", "core.deltaBaseCacheLimit=16777216", "-c", "pack.threads=1"}
	if resolved != "" {
		command = append(command, "-c", "http.curloptResolve="+resolved)
	}
	command = append(command, "--git-dir="+repository)
	command = append(command, args...)
	cmd := exec.CommandContext(timeout, limiter, command...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_NO_REPLACE_OBJECTS=1", "GIT_ATTR_NOSYSTEM=1", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = 5 * time.Second
	var output bytes.Buffer
	if sink == nil {
		sink = &output
	}
	cmd.Stdout = &limitWriter{target: sink, limit: outputLimit, cancel: cancel}
	cmd.Stderr = &limitWriter{target: io.Discard, limit: 1 << 20, cancel: cancel}
	if e = cmd.Start(); e != nil {
		return nil, fmt.Errorf("%w: Git operation could not start", ErrUnsafe)
	}
	success := false
	defer func() {
		if !success {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	}()
	if e = cmd.Wait(); e != nil {
		return nil, fmt.Errorf("%w: bounded Git operation failed", ErrUnsafe)
	}
	success = true
	return output.Bytes(), nil
}
func objectHash(id, kind string, size int64) hash.Hash {
	var h hash.Hash
	if len(id) == 40 {
		h = sha1.New()
	} else {
		h = sha256.New()
	}
	fmt.Fprintf(h, "%s %d\x00", kind, size)
	return h
}
func verifiedObject(ctx context.Context, repository, kind, id string, maximum int64) ([]byte, error) {
	if !objectID.MatchString(id) {
		return nil, fmt.Errorf("%w: invalid object ID", ErrUnsafe)
	}
	content, e := runGit(ctx, repository, "", maximum, 256<<20, nil, "cat-file", kind, id)
	if e != nil {
		return nil, e
	}
	h := objectHash(id, kind, int64(len(content)))
	h.Write(content)
	if hex.EncodeToString(h.Sum(nil)) != id {
		return nil, fmt.Errorf("%w: immutable Git object changed", ErrUnsafe)
	}
	return content, nil
}
func copyMirrorObjects(ctx context.Context, a Approval, repository string) error {
	objects := filepath.Join(a.MirrorPath, "objects")
	if _, e := os.Lstat(objects); os.IsNotExist(e) {
		objects = filepath.Join(a.MirrorPath, ".git", "objects")
	}
	tr, e := OpenTree(objects, Limits{MaxFiles: a.MaxGitFiles, MaxEntries: 3*a.MaxGitFiles + 1024, MaxFileBytes: a.MaxGitBytes, MaxTotalBytes: a.MaxGitBytes})
	if e != nil {
		return e
	}
	defer tr.Close()
	files, e := tr.List()
	if e != nil {
		return e
	}
	var total int64
	for _, entry := range files {
		if e = ctx.Err(); e != nil {
			return e
		}
		if strings.Split(entry.Path, "/")[0] == "info" {
			continue
		}
		target := filepath.Join(repository, "objects", filepath.FromSlash(entry.Path))
		if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
			return e
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		copied, err := tr.Copy(entry.Path, a.MaxGitBytes-total, out)
		closeError := out.Close()
		if err != nil {
			return err
		}
		if closeError != nil {
			return closeError
		}
		if copied.SizeBytes != entry.SizeBytes || copied.SHA256 != entry.SHA256 {
			return fmt.Errorf("%w: mirror object changed during copy", ErrUnsafe)
		}
		total += copied.SizeBytes
	}
	return nil
}

type treeRecord struct{ mode, id, name string }

func readTree(ctx context.Context, repository, commit string, a Approval) ([]treeRecord, error) {
	commitData, e := verifiedObject(ctx, repository, "commit", commit, 1<<20)
	if e != nil {
		return nil, e
	}
	rootLine := strings.SplitN(string(commitData), "\n", 2)[0]
	if !strings.HasPrefix(rootLine, "tree ") || !objectID.MatchString(strings.TrimPrefix(rootLine, "tree ")) {
		return nil, fmt.Errorf("%w: commit root tree missing", ErrUnsafe)
	}
	rootTree := strings.TrimPrefix(rootLine, "tree ")
	if _, e = verifiedObject(ctx, repository, "tree", rootTree, 16<<20); e != nil {
		return nil, e
	}
	tree, e := runGit(ctx, repository, "", min(16<<20, (3*a.MaxFiles+1024)*4200), a.MaxGitBytes, nil, "ls-tree", "-rtz", "--full-tree", commit)
	if e != nil {
		return nil, e
	}
	entries := map[string]bool{}
	filenames := map[string]bool{}
	trees := map[string]bool{}
	var records []treeRecord
	for _, raw := range bytes.Split(tree, []byte{0}) {
		if len(raw) == 0 {
			continue
		}
		chunks := bytes.SplitN(raw, []byte{'\t'}, 2)
		if len(chunks) != 2 {
			return nil, fmt.Errorf("%w: invalid tree entry", ErrUnsafe)
		}
		metadata := strings.Split(string(chunks[0]), " ")
		if len(metadata) != 3 || !objectID.MatchString(metadata[2]) {
			return nil, fmt.Errorf("%w: invalid tree metadata", ErrUnsafe)
		}
		mode, kind, id := metadata[0], metadata[1], metadata[2]
		name := string(chunks[1])
		if e = SafeName(name); e != nil {
			return nil, e
		}
		isTree := mode == "040000" && kind == "tree"
		if (!isTree && ((mode != "100644" && mode != "100755") || kind != "blob")) || name == ".gitmodules" {
			return nil, fmt.Errorf("%w: symlink, submodule or special source file", ErrUnsafe)
		}
		parts := strings.Split(name, "/")
		for i := range parts {
			entries[strings.Join(parts[:i+1], "/")] = true
		}
		if int64(len(entries)) > 3*a.MaxFiles+1024 {
			return nil, fmt.Errorf("%w: tree entry limit", ErrUnsafe)
		}
		if isTree {
			trees[id] = true
			continue
		}
		if filenames[name] || int64(len(records)) >= a.MaxFiles {
			return nil, fmt.Errorf("%w: source file count", ErrUnsafe)
		}
		filenames[name] = true
		records = append(records, treeRecord{mode, id, name})
	}
	for id := range trees {
		if _, e = verifiedObject(ctx, repository, "tree", id, 16<<20); e != nil {
			return nil, e
		}
	}
	return records, nil
}
func (r *Registry) Materialize(ctx context.Context, project, sourceID, commit, destination, workspaceParent string) (result Snapshot, err error) {
	a, e := r.Authorize(project, sourceID, commit)
	if e != nil {
		return result, e
	}
	if !canonicalAbsolute(destination) {
		return result, fmt.Errorf("%w: snapshot requires a new absolute destination", ErrUnsafe)
	}
	if _, e = os.Lstat(destination); !os.IsNotExist(e) {
		return result, fmt.Errorf("%w: snapshot destination already exists or is inaccessible", ErrUnsafe)
	}
	parent := filepath.Dir(destination)
	if e = EnsurePrivateDirectory(parent); e != nil {
		return result, e
	}
	if workspaceParent == "" {
		workspaceParent = parent
	}
	if e = EnsurePrivateDirectory(workspaceParent); e != nil {
		return result, e
	}
	authority, e := openDirectory(workspaceParent, true)
	if e != nil {
		return result, e
	}
	defer authority.Close()
	var before unix.Stat_t
	if e = unix.Fstat(int(authority.Fd()), &before); e != nil {
		return result, e
	}
	fetch, e := os.MkdirTemp(workspaceParent, "hf2l-fetch-")
	if e != nil {
		return result, e
	}
	current, e := openDirectory(workspaceParent, true)
	if e != nil {
		return result, e
	}
	var after unix.Stat_t
	e = unix.Fstat(int(current.Fd()), &after)
	current.Close()
	if e != nil || before.Dev != after.Dev || before.Ino != after.Ino {
		return result, fmt.Errorf("%w: workspace parent replaced", ErrUnsafe)
	}
	mounted := false
	defer func() {
		if mounted {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(cleanupCtx, "sudo", "-n", "umount", fetch)
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			if e := cmd.Run(); e != nil {
				err = fmt.Errorf("%w: source workspace deletion unconfirmed", ErrUnsafe)
				return
			}
			if e := os.Remove(fetch); e != nil {
				err = fmt.Errorf("%w: source workspace deletion unconfirmed", ErrUnsafe)
			}
		} else if e := os.RemoveAll(fetch); e != nil {
			err = fmt.Errorf("%w: source workspace deletion unconfirmed", ErrUnsafe)
		}
	}()
	if a.MirrorPath == "" {
		options := fmt.Sprintf("size=%d,nr_inodes=%d,mode=0700,uid=%d,gid=%d,nodev,nosuid,noexec", a.MaxGitBytes, a.MaxGitFiles+1024, os.Getuid(), os.Getgid())
		mountCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		cmd := exec.CommandContext(mountCtx, "sudo", "-n", "mount", "-t", "tmpfs", "-o", options, "tmpfs", fetch)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		e = cmd.Run()
		cancel()
		if e != nil {
			return result, fmt.Errorf("%w: HTTPS fetch requires enforced private tmpfs quota", ErrUnsafe)
		}
		mounted = true
		var fs unix.Statfs_t
		if e = unix.Statfs(fetch, &fs); e != nil || int64(fs.Blocks)*fs.Bsize > a.MaxGitBytes+4096 {
			return result, fmt.Errorf("%w: source workspace quota mismatch", ErrUnsafe)
		}
	}
	repository := filepath.Join(fetch, "repository.git")
	format := "sha1"
	if len(commit) == 64 {
		format = "sha256"
	}
	if _, e = runGit(ctx, repository, "", 1<<20, a.MaxGitBytes, nil, "init", "--bare", "--object-format="+format); e != nil {
		return result, e
	}
	if a.MirrorPath != "" {
		if e = copyMirrorObjects(ctx, a, repository); e != nil {
			return result, e
		}
	} else {
		remote, resolved, e := r.Remote(ctx, a)
		if e != nil {
			return result, e
		}
		if _, e = runGit(ctx, repository, resolved, 1<<20, a.MaxGitBytes, nil, "fetch", "--no-tags", "--no-recurse-submodules", "--depth=1", "--", remote, commit); e != nil {
			return result, e
		}
	}
	resolved, e := runGit(ctx, repository, "", 1<<20, a.MaxGitBytes, nil, "rev-parse", "--verify", commit+"^{commit}")
	if e != nil {
		return result, e
	}
	if strings.TrimSpace(string(resolved)) != commit {
		return result, fmt.Errorf("%w: resolved commit changed", ErrUnsafe)
	}
	records, e := readTree(ctx, repository, commit, a)
	if e != nil {
		return result, e
	}
	stagingRoot, e := os.MkdirTemp(parent, "hf2l-source-")
	if e != nil {
		return result, e
	}
	defer os.RemoveAll(stagingRoot)
	staging := filepath.Join(stagingRoot, "snapshot")
	if e = os.Mkdir(staging, 0700); e != nil {
		return result, e
	}
	manifest := map[string]string{}
	var total int64
	for _, record := range records {
		sizeData, e := runGit(ctx, repository, "", 100, a.MaxGitBytes, nil, "cat-file", "-s", record.id)
		if e != nil {
			return result, e
		}
		size, e := strconv.ParseInt(strings.TrimSpace(string(sizeData)), 10, 64)
		if e != nil || size < 0 || size > a.MaxBytes-total {
			return result, fmt.Errorf("%w: source bytes exceed approval", ErrUnsafe)
		}
		target := filepath.Join(staging, filepath.FromSlash(record.name))
		if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
			return result, e
		}
		out, e := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return result, e
		}
		fileHash := sha256.New()
		gitHash := objectHash(record.id, "blob", size)
		var counter countingWriter
		counter.target = io.MultiWriter(out, fileHash, gitHash)
		_, runErr := runGit(ctx, repository, "", max(1, size), a.MaxGitBytes, &counter, "cat-file", "blob", record.id)
		if runErr == nil && counter.n != size {
			runErr = fmt.Errorf("%w: Git blob size changed", ErrUnsafe)
		}
		if runErr == nil && hex.EncodeToString(gitHash.Sum(nil)) != record.id {
			runErr = fmt.Errorf("%w: Git blob digest changed", ErrUnsafe)
		}
		if runErr == nil {
			runErr = out.Sync()
		}
		closeErr := out.Close()
		if runErr != nil {
			return result, runErr
		}
		if closeErr != nil {
			return result, closeErr
		}
		mode := os.FileMode(0444)
		if record.mode == "100755" {
			mode = 0555
		}
		if e = os.Chmod(target, mode); e != nil {
			return result, e
		}
		manifest[record.name] = hex.EncodeToString(fileHash.Sum(nil))
		total += size
	}
	digest, e := ManifestDigest(manifest)
	if e != nil {
		return result, e
	}
	if e = PublishDirectory(staging, destination); e != nil {
		return result, e
	}
	if e = filepath.WalkDir(destination, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(path, 0555)
		}
		return nil
	}); e != nil {
		return result, e
	}
	physical, e := PhysicalBytes(destination, a)
	if e != nil {
		return result, e
	}
	return Snapshot{sourceID, commit, destination, manifest, digest, total, physical}, nil
}

type countingWriter struct {
	target io.Writer
	n      int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, e := w.target.Write(p)
	w.n += int64(n)
	return n, e
}
