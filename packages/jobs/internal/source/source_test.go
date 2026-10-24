//go:build linux

package source

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	"golang.org/x/sys/unix"
)

func testGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0")
	b, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("git %v: %v %s", args, e, b)
	}
	return strings.TrimSpace(string(b))
}
func testRepo(t *testing.T, format string) (string, string) {
	t.Helper()
	r := filepath.Join(privateTemp(t), "repo")
	if e := os.Mkdir(r, 0700); e != nil {
		t.Fatal(e)
	}
	testGit(t, r, "init", "-q", "--object-format="+format)
	if e := os.WriteFile(filepath.Join(r, "plugin.py"), []byte("VALUE = 7\n"), 0600); e != nil {
		t.Fatal(e)
	}
	testGit(t, r, "add", ".")
	testGit(t, r, "-c", "user.name=Source Test", "-c", "user.email=source@example.invalid", "commit", "-qm", "approved")
	return r, testGit(t, r, "rev-parse", "HEAD")
}
func testRegistry(t *testing.T, repo, commit string, change func(*Approval)) *Registry {
	t.Helper()
	a := Approval{SourceID: "source", Projects: []string{"project"}, MirrorPath: repo, Commits: []string{commit}}.Defaults()
	if change != nil {
		change(&a)
	}
	r, e := NewRegistry([]Approval{a}, nil)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func writableCleanup(t *testing.T, path string) {
	t.Helper()
	t.Cleanup(func() {
		_ = filepath.WalkDir(path, func(p string, d os.DirEntry, e error) error {
			if e == nil && d.IsDir() {
				_ = os.Chmod(p, 0700)
			}
			return nil
		})
	})
}
func TestManifestDigestMatchesPythonUnicodeAndHTML(t *testing.T) {
	raw, e := os.ReadFile("testdata/python-manifest-contract.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Manifest map[string]string
		Digest   string
	}
	if e = json.Unmarshal(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	actual, e := ManifestDigest(fixture.Manifest)
	if e != nil || actual != fixture.Digest {
		t.Fatalf("manifest hash %s != %s: %v", actual, fixture.Digest, e)
	}
}
func TestMaterializePinnedMirrorNeverExecutesHooksOrCopiesGit(t *testing.T) {
	for _, format := range []string{"sha1", "sha256"} {
		t.Run(format, func(t *testing.T) {
			repo, commit := testRepo(t, format)
			sentinel := filepath.Join(privateTemp(t), "executed")
			if e := os.WriteFile(filepath.Join(repo, ".git/hooks/post-checkout"), []byte("#!/bin/sh\ntouch "+sentinel+"\n"), 0700); e != nil {
				t.Fatal(e)
			}
			parent := privateTemp(t)
			writableCleanup(t, parent)
			destination := filepath.Join(parent, "snapshot")
			snapshot, e := testRegistry(t, repo, commit, nil).Materialize(context.Background(), "project", "source", commit, destination, "")
			if e != nil {
				t.Fatal(e)
			}
			if _, e = os.Lstat(sentinel); !os.IsNotExist(e) {
				t.Fatal("source hook executed")
			}
			if _, e = os.Lstat(filepath.Join(destination, ".git")); !os.IsNotExist(e) {
				t.Fatal("history copied")
			}
			expected := sha256.Sum256([]byte("VALUE = 7\n"))
			if snapshot.Manifest["plugin.py"] != hex.EncodeToString(expected[:]) || snapshot.Bytes != 10 || snapshot.PhysicalBytes < snapshot.Bytes {
				t.Fatalf("invalid snapshot %+v", snapshot)
			}
			if info, e := os.Stat(filepath.Join(destination, "plugin.py")); e != nil || info.Mode().Perm()&0222 != 0 {
				t.Fatal("source not readonly")
			}
			if e = VerifySnapshot(destination, snapshot.Manifest, 1<<20, 100); e != nil {
				t.Fatal(e)
			}
			if _, e = testRegistry(t, repo, commit, nil).Materialize(context.Background(), "project", "source", commit, destination, ""); e == nil {
				t.Fatal("existing destination adopted")
			}
		})
	}
}
func TestUnapprovedProjectCommitRefusedBeforeWrites(t *testing.T) {
	repo, commit := testRepo(t, "sha1")
	parent := privateTemp(t)
	r := testRegistry(t, repo, commit, nil)
	for _, values := range [][2]string{{"foreign", commit}, {"project", strings.Repeat("0", 40)}} {
		destination := filepath.Join(parent, "not-created")
		if _, e := r.Materialize(context.Background(), values[0], "source", values[1], destination, ""); e == nil {
			t.Fatal("unapproved source accepted")
		}
		if _, e := os.Lstat(destination); !os.IsNotExist(e) {
			t.Fatal("refusal wrote destination")
		}
	}
}
func TestSourceTreeRejectsLinksSubmodulesCredentialsAndLimits(t *testing.T) {
	for _, kind := range []string{"symlink", "gitlink", "gitmodules", "credentials", "size", "files"} {
		t.Run(kind, func(t *testing.T) {
			repo, commit := testRepo(t, "sha1")
			change := func(*Approval) {}
			switch kind {
			case "symlink":
				if e := os.Symlink("/etc/passwd", filepath.Join(repo, "foreign")); e != nil {
					t.Fatal(e)
				}
			case "gitlink":
				testGit(t, repo, "update-index", "--add", "--cacheinfo", "160000,"+commit+",nested")
			case "gitmodules":
				if e := os.WriteFile(filepath.Join(repo, ".gitmodules"), []byte("no submodules"), 0600); e != nil {
					t.Fatal(e)
				}
			case "credentials":
				if e := os.Mkdir(filepath.Join(repo, ".ssh"), 0700); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(filepath.Join(repo, ".ssh/config"), []byte("secret"), 0600); e != nil {
					t.Fatal(e)
				}
			case "size":
				change = func(a *Approval) { a.MaxBytes = 1 }
			case "files":
				if e := os.WriteFile(filepath.Join(repo, "second.py"), []byte("second"), 0600); e != nil {
					t.Fatal(e)
				}
				change = func(a *Approval) { a.MaxFiles = 1 }
			}
			if kind != "size" {
				if kind != "gitlink" {
					testGit(t, repo, "add", ".")
				}
				testGit(t, repo, "-c", "user.name=Source Test", "-c", "user.email=source@example.invalid", "commit", "-qm", "unsafe")
				commit = testGit(t, repo, "rev-parse", "HEAD")
			}
			parent := privateTemp(t)
			writableCleanup(t, parent)
			if _, e := testRegistry(t, repo, commit, change).Materialize(context.Background(), "project", "source", commit, filepath.Join(parent, "snapshot"), ""); e == nil {
				t.Fatal("unsafe source accepted")
			}
		})
	}
}
func TestCorruptLooseObjectRejected(t *testing.T) {
	repo, commit := testRepo(t, "sha1")
	blob := testGit(t, repo, "rev-parse", "HEAD:plugin.py")
	path := filepath.Join(repo, ".git/objects", blob[:2], blob[2:])
	if e := os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	var encoded bytes.Buffer
	z := zlib.NewWriter(&encoded)
	_, _ = z.Write([]byte("blob 10\x00VALUE = 9\n"))
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, encoded.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
	parent := privateTemp(t)
	writableCleanup(t, parent)
	if _, e := testRegistry(t, repo, commit, nil).Materialize(context.Background(), "project", "source", commit, filepath.Join(parent, "snapshot"), ""); e == nil {
		t.Fatal("object filename trusted without digest")
	}
}
func TestRemoteRequiresAllPublicPinnedAddresses(t *testing.T) {
	cases := []struct {
		url     string
		ips     []string
		allowed bool
	}{
		{"https://code.example/repo", []string{"8.8.8.8", "2606:4700:4700::1111"}, true},
		{"http://code.example/repo", []string{"8.8.8.8"}, false}, {"https://user:secret@code.example/repo", []string{"8.8.8.8"}, false},
		{"https://code.example/repo?redirect=elsewhere", []string{"8.8.8.8"}, false}, {"https://code.example:8443/repo", []string{"8.8.8.8"}, false},
		{"https://code.example/repo", []string{"8.8.8.8", "127.0.0.1"}, false}, {"https://code.example/repo", []string{"169.254.169.254"}, false},
		{"https://code.example/repo", []string{"192.0.2.1"}, false}, {"https://code.example/repo", []string{"::ffff:10.0.0.1"}, false},
	}
	for _, c := range cases {
		t.Run(c.url+strings.Join(c.ips, "_"), func(t *testing.T) {
			r, e := NewRegistry(nil, []string{"code.example"})
			if e != nil {
				t.Fatal(e)
			}
			r.Resolver = func(context.Context, string) ([]net.IP, error) {
				var ips []net.IP
				for _, s := range c.ips {
					ips = append(ips, net.ParseIP(s))
				}
				return ips, nil
			}
			_, pinned, e := r.Remote(context.Background(), Approval{URL: c.url})
			if (e == nil) != c.allowed {
				t.Fatalf("remote allow=%v error=%v", c.allowed, e)
			}
			if c.allowed && pinned != "code.example:443:8.8.8.8,[2606:4700:4700::1111]" {
				t.Fatalf("unexpected pin %s", pinned)
			}
		})
	}
}
func TestSafeReaderRejectsAncestorLeafHardlinksAndFIFO(t *testing.T) {
	root := privateTemp(t)
	if e := os.WriteFile(filepath.Join(root, "safe"), []byte("safe"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Link(filepath.Join(root, "safe"), filepath.Join(root, "hard")); e != nil {
		t.Fatal(e)
	}
	tr, e := OpenTree(root, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer tr.Close()
	if _, e = tr.Read("hard", 10); e == nil {
		t.Fatal("hardlink accepted")
	}
	if e = os.Symlink("/etc/passwd", filepath.Join(root, "link")); e != nil {
		t.Fatal(e)
	}
	if _, e = tr.Read("link", 10); e == nil {
		t.Fatal("symlink accepted")
	}
	if e = unix.Mkfifo(filepath.Join(root, "pipe"), 0600); e != nil {
		t.Fatal(e)
	}
	before := time.Now()
	if _, e = tr.Read("pipe", 10); e == nil {
		t.Fatal("fifo accepted")
	}
	if time.Since(before) > time.Second {
		t.Fatal("FIFO blocked")
	}
	alias := filepath.Join(privateTemp(t), "alias")
	if e = os.Symlink(root, alias); e != nil {
		t.Fatal(e)
	}
	if unsafe, e := OpenTree(alias, Limits{}); e == nil {
		unsafe.Close()
		t.Fatal("ancestor link accepted")
	}
}
func TestSafeReaderBoundsAndChangedSnapshot(t *testing.T) {
	root := privateTemp(t)
	payload := bytes.Repeat([]byte("a"), 65537)
	if e := os.WriteFile(filepath.Join(root, "large"), payload, 0600); e != nil {
		t.Fatal(e)
	}
	tr, e := OpenTree(root, Limits{MaxFileBytes: 65536, MaxTotalBytes: 65536})
	if e != nil {
		t.Fatal(e)
	}
	defer tr.Close()
	if _, e = tr.Read("large", 65536); e == nil {
		t.Fatal("oversize file accepted")
	}
	for _, n := range []string{"../large", "/large", "a//b", "a\\b", ".git/objects", "a/../b"} {
		if _, e = tr.Read(n, 10); e == nil {
			t.Fatalf("unsafe name %q accepted", n)
		}
	}
	if e = VerifySnapshot(root, map[string]string{"large": strings.Repeat("a", 64)}, 1<<20, 100); e == nil {
		t.Fatal("changed manifest accepted")
	}
}
func TestImmutablePublishNeverReplacesDestination(t *testing.T) {
	parent := privateTemp(t)
	stageParent := filepath.Join(parent, "stage")
	if e := os.Mkdir(stageParent, 0700); e != nil {
		t.Fatal(e)
	}
	staged := filepath.Join(stageParent, "data")
	if e := os.Mkdir(staged, 0700); e != nil {
		t.Fatal(e)
	}
	destination := filepath.Join(parent, "existing")
	if e := os.Mkdir(destination, 0700); e != nil {
		t.Fatal(e)
	}
	sentinel := filepath.Join(destination, "sentinel")
	_ = os.WriteFile(sentinel, []byte("keep"), 0600)
	if e := PublishDirectory(staged, destination); e == nil {
		t.Fatal("replaced existing directory")
	}
	if b, e := os.ReadFile(sentinel); e != nil || string(b) != "keep" {
		t.Fatal("foreign destination modified")
	}
}
func TestGitBoundAndCancelledContext(t *testing.T) {
	repo, commit := testRepo(t, "sha1")
	if _, e := runGit(context.Background(), filepath.Join(repo, ".git"), "", 1, 1<<20, nil, "cat-file", "commit", commit); e == nil {
		t.Fatal("stdout bound ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, e := runGit(ctx, filepath.Join(repo, ".git"), "", 1<<20, 1<<20, nil, "cat-file", "commit", commit); e == nil {
		t.Fatal("cancelled operation ran")
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancelled operation not bounded")
	}
}
func testSourceDB(t *testing.T) *store.DB {
	t.Helper()
	db, e := store.Open(context.Background(), "sqlite://")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if _, e = db.Migrate(context.Background()); e != nil {
		t.Fatal(e)
	}
	return db
}
func TestSourceArtifactPublicationReplayAndChangedFiles(t *testing.T) {
	ctx := context.Background()
	db := testSourceDB(t)
	parent := privateTemp(t)
	jobRoot := filepath.Join(parent, "job")
	sourceRoot := filepath.Join(jobRoot, "source")
	if e := os.MkdirAll(sourceRoot, 0700); e != nil {
		t.Fatal(e)
	}
	payload := []byte("training code\n")
	if e := os.WriteFile(filepath.Join(sourceRoot, "plugin.py"), payload, 0444); e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(payload)
	manifest := map[string]string{"plugin.py": hex.EncodeToString(hash[:])}
	digest, _ := ManifestDigest(manifest)
	spec := map[string]any{"project_id": "project"}
	size := int64(8192)
	e := db.WithTx(ctx, true, func(tx *store.Tx) error {
		if e := tx.Insert(ctx, "jm_projects", map[string]any{"id": "project", "name": "Project"}); e != nil {
			return e
		}
		if e := tx.Insert(ctx, "jm_jobs", map[string]any{"id": "job", "project_id": "project", "creator_id": "human", "name": "Source test", "spec_json": spec, "spec_hash": strings.Repeat("a", 64), "target_round": int64(1)}); e != nil {
			return e
		}
		return tx.Insert(ctx, "jm_provisioning_resources", map[string]any{"id": "source-resource", "job_id": "job", "component_id": "owner", "kind": "source", "external_id": sourceRoot, "ownership_json": map[string]any{"job_id": "job", "component_id": "owner", "kind": "source"}, "details_json": map[string]any{"sha256": digest, "logical_bytes": int64(len(payload)), "retention_charge_settled": true, "retention_charge_released": false, "retention_charged_bytes": size}, "size_bytes": size, "retained": true, "state": "ready"})
	})
	if e != nil {
		t.Fatal(e)
	}
	var first []string
	for i := 0; i < 2; i++ {
		e = db.WithTx(ctx, true, func(tx *store.Tx) error {
			ids, e := PublishArtifacts(ctx, tx, "job", "source-resource", jobRoot, manifest, digest, 100, 1<<20)
			if e != nil {
				return e
			}
			if i == 0 {
				first = ids
			} else if len(ids) != 1 || ids[0] != first[0] {
				return errors.New("source artifact identity changed")
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	}
	rows, e := db.All(ctx, "SELECT * FROM jm_artifacts")
	if e != nil || len(rows) != 1 {
		t.Fatalf("duplicate artifacts rows=%d err=%v", len(rows), e)
	}
	if e = os.Chmod(filepath.Join(sourceRoot, "plugin.py"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(sourceRoot, "plugin.py"), []byte("changed"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = db.WithTx(ctx, true, func(tx *store.Tx) error {
		_, e := PublishArtifacts(ctx, tx, "job", "source-resource", jobRoot, manifest, digest, 100, 1<<20)
		return e
	}); e == nil {
		t.Fatal("changed source artifact accepted")
	}
	locator := domain.ArtifactLocator{Kind: "local", ResourceID: ptr("source-resource"), RelativePath: ptr("../other")}
	if locator.Validate() == nil {
		t.Fatal("locator traversal accepted")
	}
}
func ptr(s string) *string { return &s }
func TestDatabaseCatalogRevocationAppliesWithoutRestart(t *testing.T) {
	ctx := context.Background()
	db := testSourceDB(t)
	repo, commit := testRepo(t, "sha1")
	e := db.WithTx(ctx, true, func(tx *store.Tx) error {
		for table, values := range map[string]map[string]any{
			"jm_projects": {"id": "project", "name": "Project"},
		} {
			if e := tx.Insert(ctx, table, values); e != nil {
				return e
			}
		}
		if e := tx.Insert(ctx, "jm_approved_sources", map[string]any{"id": "source", "project_id": "project", "url": "", "details_json": map[string]any{"mirror_path": repo}, "allowed_commits": []string{commit}}); e != nil {
			return e
		}
		return tx.Insert(ctx, "jm_runtime_images", map[string]any{"id": "runtime", "project_id": "project", "digest": "sha256:" + strings.Repeat("b", 64)})
	})
	if e != nil {
		t.Fatal(e)
	}
	catalog, e := FromDatabase(ctx, db)
	if e != nil {
		t.Fatal(e)
	}
	spec := domain.JobSpec{ProjectID: "project", SourceID: "source", SourceCommit: commit, RuntimeImage: "runtime"}
	if _, e = catalog.Validate(ctx, spec); e != nil {
		t.Fatal(e)
	}
	_, e = db.Exec(ctx, "UPDATE jm_runtime_images SET enabled=? WHERE id=?", false, "runtime")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = catalog.Validate(ctx, spec); e == nil {
		t.Fatal("revoked image remained usable")
	}
}

func privateTemp(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestDatabaseCatalogRejectsExplicitZeroSourceLimit(t *testing.T) {
	ctx := context.Background()
	db := testSourceDB(t)
	repo, commit := testRepo(t, "sha1")
	err := db.WithTx(ctx, true, func(tx *store.Tx) error {
		if err := tx.Insert(ctx, "jm_projects", map[string]any{"id": "project", "name": "Project"}); err != nil {
			return err
		}
		return tx.Insert(ctx, "jm_approved_sources", map[string]any{"id": "source", "project_id": "project", "url": "", "details_json": map[string]any{"mirror_path": repo, "max_bytes": int64(0)}, "allowed_commits": []string{commit}})
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = FromDatabase(ctx, db); err == nil {
		t.Fatal("explicit zero approval changed to permissive default")
	}
}
func TestGitOutputOverflowFencesTransportDescendants(t *testing.T) {
	tools := privateTemp(t)
	pidFile := filepath.Join(tools, "child.pid")
	gitScript := "#!/bin/sh\nsleep 60 &\nchild=$!\nprintf '%s' \"$child\" > " + pidFile + "\nprintf 'this exceeds output bound'\nwait\n"
	if err := os.WriteFile(filepath.Join(tools, "git"), []byte(gitScript), 0700); err != nil {
		t.Fatal(err)
	}
	originalPath := os.Getenv("PATH")
	t.Setenv("PATH", tools+":"+originalPath)
	if _, err := runGit(context.Background(), filepath.Join(tools, "unused.git"), "", 1, 1<<20, nil, "version"); err == nil {
		t.Fatal("overflow accepted")
	}
	pidData, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(pidData))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Kill(pid, unix.SIGKILL) })
	deadline := time.Now().Add(3 * time.Second)
	for {
		info, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if os.IsNotExist(err) {
			break
		}
		if err == nil {
			fields := strings.Fields(string(info))
			if len(fields) > 2 && fields[2] == "Z" {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("Git transport descendant survived process-group fencing")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
