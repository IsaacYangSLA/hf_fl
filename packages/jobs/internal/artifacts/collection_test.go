//go:build linux

package artifacts

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func mustWrite(t *testing.T, path string, content []byte) {
	t.Helper()
	if e := os.WriteFile(path, content, 0600); e != nil {
		t.Fatal(e)
	}
}
func TestCollectorOpaqueManifestRedactionAndBounds(t *testing.T) {
	root := t.TempDir()
	if e := os.Mkdir(filepath.Join(root, "nested"), 0700); e != nil {
		t.Fatal(e)
	}
	mustWrite(t, filepath.Join(root, "nested/model.safetensors"), []byte("opaque-not-decoded"))
	mustWrite(t, filepath.Join(root, "logs.txt"), []byte("credential=hidden-value"))
	mustWrite(t, filepath.Join(root, "events.jsonl"), []byte("{\"step\":1,\"password\":\"never-export\",\"message\":\"hidden-value\"}\n"))
	c, e := NewCollector(root, CollectorOptions{SecretValues: []string{"hidden-value"}})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	manifest, e := c.ListFiles()
	if e != nil || len(manifest) != 3 {
		t.Fatalf("manifest=%v err=%v", manifest, e)
	}
	logs, e := c.Logs("logs.txt", 64)
	if e != nil || logs != "credential=[REDACTED]" {
		t.Fatalf("logs=%q %v", logs, e)
	}
	events, e := c.Events("events.jsonl")
	if e != nil || len(events) != 1 || events[0]["password"] != nil || events[0]["message"] != "[REDACTED]" {
		t.Fatalf("events=%v err=%v", events, e)
	}
	if _, e = c.Read("nested/model.safetensors", 3); e == nil {
		t.Fatal("accepted oversized file")
	}
	for _, path := range []string{"../logs.txt", "/logs.txt", "nested//x", "nested/./x", "nested\\x", ""} {
		if _, e = c.Read(path, 64); e == nil {
			t.Errorf("accepted %q", path)
		}
	}
}
func TestCollectorRejectsAncestorSymlinksHardlinksAndSpecialFiles(t *testing.T) {
	cases := []string{"file-link", "hardlink", "fifo", "directory-link"}
	for _, kind := range cases {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			outside := t.TempDir()
			mustWrite(t, filepath.Join(outside, "secret"), []byte("private"))
			switch kind {
			case "file-link":
				if e := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "out")); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(filepath.Join(outside, "secret"), filepath.Join(root, "out")); e != nil {
					t.Fatal(e)
				}
			case "fifo":
				if e := unix.Mkfifo(filepath.Join(root, "out"), 0600); e != nil {
					t.Fatal(e)
				}
			case "directory-link":
				if e := os.Symlink(outside, filepath.Join(root, "out")); e != nil {
					t.Fatal(e)
				}
			}
			c, e := NewCollector(root, CollectorOptions{})
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			if _, e = c.ListFiles(); e == nil {
				t.Fatal("unsafe file exposed")
			}
		})
	}
	root := t.TempDir()
	alias := filepath.Join(t.TempDir(), "alias")
	if e := os.Symlink(root, alias); e != nil {
		t.Fatal(e)
	}
	if _, e := NewCollector(alias, CollectorOptions{}); e == nil {
		t.Fatal("root link accepted")
	}
	if e := os.Mkdir(filepath.Join(root, "child"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := NewCollector(filepath.Join(alias, "child"), CollectorOptions{}); e == nil {
		t.Fatal("ancestor link accepted")
	}
}
func TestCollectorStrictEventsAndRedactionExpansion(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "events")
	c, e := NewCollector(root, CollectorOptions{SecretValues: []string{"a"}, MaxEventBytes: 65536})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	for _, data := range []string{"{\"a\":1,\"a\":2}\n", "{\"value\":NaN}\n", "[]\n", string([]byte{0xff, '\n'})} {
		mustWrite(t, path, []byte(data))
		if _, e = c.Events("events"); e == nil {
			t.Fatalf("accepted %q", data)
		}
	}
	if _, e = c.Redact(strings.Repeat("a", 10), 20); e == nil {
		t.Fatal("unbounded redaction expansion")
	}
	// JSONL lines larger than bufio's default 4 KiB remain supported.
	large := "{\"message\":\"" + strings.Repeat("z", 8192) + "\"}\n"
	mustWrite(t, path, []byte(large))
	if events, e := c.Events("events"); e != nil || len(events) != 1 {
		t.Fatalf("large valid JSONL %v", e)
	}
}
func TestRetainIsImmutableAndPurgeRequiresCompleteOwnership(t *testing.T) {
	source := t.TempDir()
	if e := os.Mkdir(filepath.Join(source, "nested"), 0700); e != nil {
		t.Fatal(e)
	}
	mustWrite(t, filepath.Join(source, "nested/model"), bytes.Repeat([]byte{3}, 4096))
	c, e := NewCollector(source, CollectorOptions{})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	destination := filepath.Join(t.TempDir(), "retained")
	files, e := c.Retain(destination)
	if e != nil || len(files) != 1 {
		t.Fatalf("retain %v", e)
	}
	second, e := c.Retain(destination)
	if e != nil || second[0] != files[0] {
		t.Fatalf("immutable retry %v", e)
	}
	mustWrite(t, filepath.Join(destination, "unowned"), []byte("foreign"))
	if _, e = DeleteRetained(destination, files, DeleteOptions{}); e == nil {
		t.Fatal("deleted unowned tree")
	}
	if _, e = os.Stat(files[0].Locator); e != nil {
		t.Fatal("partial deletion occurred before inventory validation")
	}
	if e = os.Remove(filepath.Join(destination, "unowned")); e != nil {
		t.Fatal(e)
	}
	mustWrite(t, files[0].Locator, []byte("changed"))
	if _, e = DeleteRetained(destination, files, DeleteOptions{}); e == nil {
		t.Fatal("deleted changed checkpoint")
	}
	mustWrite(t, files[0].Locator, bytes.Repeat([]byte{3}, 4096))
	if ok, e := DeleteRetained(destination, files, DeleteOptions{}); e != nil || !ok {
		t.Fatalf("purge %v", e)
	}
	if _, e = os.Stat(destination); !os.IsNotExist(e) {
		t.Fatalf("root remains %v", e)
	}
	if ok, e := DeleteRetained(destination, files, DeleteOptions{}); e != nil || !ok {
		t.Fatalf("purge retry %v", e)
	}
}
func TestRetainRejectsSourceDescendantsAndConflicts(t *testing.T) {
	source := t.TempDir()
	mustWrite(t, filepath.Join(source, "data"), []byte("first"))
	c, e := NewCollector(source, CollectorOptions{})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if _, e = c.Retain(filepath.Join(source, "retained")); e == nil {
		t.Fatal("retained inside source")
	}
	destination := filepath.Join(t.TempDir(), "retained")
	if _, e = c.Retain(destination); e != nil {
		t.Fatal(e)
	}
	mustWrite(t, filepath.Join(source, "data"), []byte("second"))
	if _, e = c.Retain(destination); e == nil {
		t.Fatal("overwrote immutable retained file")
	}
	raw, e := os.ReadFile(filepath.Join(destination, "data"))
	if e != nil || string(raw) != "first" {
		t.Fatal("original changed")
	}
}
