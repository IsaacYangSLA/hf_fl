//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/artifacts"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/secrets"
	"golang.org/x/sys/unix"
)

func listSafeFiles(root string, max int64) ([]artifacts.FileMetadata, error) {
	c, err := artifacts.NewCollector(root, artifacts.CollectorOptions{MaxTotalBytes: max})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.ListFiles()
}
func (e *LinuxExecutor) copyInitialState(ctx context.Context, source, destination string, max int64, user string) error {
	c, err := artifacts.NewCollector(source, artifacts.CollectorOptions{MaxTotalBytes: max})
	if err != nil {
		return err
	}
	defer c.Close()
	files, err := c.ListFiles()
	if err != nil {
		return err
	}
	for _, item := range files {
		data, err := c.Read(item.Path, item.SizeBytes+1)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, filepath.FromSlash(item.Path))
		if err = makeSafeParents(destination, filepath.Dir(target)); err != nil {
			return err
		}
		if old, err := readPrivateFile(target, item.SizeBytes+1, false); err == nil {
			h := sha256.Sum256(old)
			if int64(len(old)) != item.SizeBytes || hex.EncodeToString(h[:]) != item.SHA256 {
				return refused("unsafe_output")
			}
		} else if ErrorCode(err) == "unsafe_mount" {
			if _, statErr := os.Lstat(target); !os.IsNotExist(statErr) {
				return err
			}
			if err = atomicBytes(target, data); err != nil {
				return err
			}
		} else {
			return err
		}
		if _, err = e.system(ctx, []string{"chown", user, target}, false, false); err != nil {
			return err
		}
	}
	if _, err = e.system(ctx, []string{"chown", "-R", user, destination}, false, false); err != nil {
		return err
	}
	return nil
}
func makeSafeParents(root, parent string) error {
	rel, err := filepath.Rel(root, parent)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return refused("unsafe_output")
	}
	fd, err := openChecked(root, true, false)
	if err != nil {
		return err
	}
	defer fd.Close()
	if rel == "." {
		return nil
	}
	cur := int(fd.Fd())
	owned := []int{}
	defer func() {
		for _, v := range owned {
			unix.Close(v)
		}
	}()
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		if part == "" || part == "." || part == ".." {
			return refused("unsafe_output")
		}
		next, err := unix.Openat(cur, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == unix.ENOENT {
			if err = unix.Mkdirat(cur, part, 0700); err != nil && err != unix.EEXIST {
				return err
			}
			if err = unix.Fsync(cur); err != nil {
				return err
			}
			next, err = unix.Openat(cur, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if err != nil {
			return refused("unsafe_output")
		}
		owned = append(owned, next)
		cur = next
	}
	return nil
}
func atomicBytes(path string, data []byte) error {
	parent, err := openChecked(filepath.Dir(path), true, false)
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(path)
	var st unix.Stat_t
	err = unix.Fstatat(int(parent.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1) {
		return refused("unsafe_output")
	}
	if err != nil && err != unix.ENOENT {
		return err
	}
	temp := ".hf2l-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	fd, err := unix.Openat(int(parent.Fd()), temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), temp)
	defer func() { f.Close(); unix.Unlinkat(int(parent.Fd()), temp, 0) }()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = unix.Renameat(int(parent.Fd()), temp, int(parent.Fd()), name); err != nil {
		return err
	}
	return parent.Sync()
}
func (e *LinuxExecutor) runtimeProgress(r *executionRecord, ob *RuntimeObservation) {
	root := filepath.Join(e.directory(r.Identity), "retained", "state")
	if r.Mounted {
		root = filepath.Join(e.directory(r.Identity), "state")
	}
	c, err := artifacts.NewCollector(root, artifacts.CollectorOptions{MaxFileBytes: 65536})
	if err != nil {
		return
	}
	defer c.Close()
	raw, err := c.Read("runtime-status.json", 65536)
	if err != nil {
		return
	}
	var value map[string]any
	if !uniqueJSON(raw) || decodeJSON(raw, &value) != nil {
		return
	}
	integer := func(v any) (int64, bool) {
		switch x := v.(type) {
		case json.Number:
			n, e := x.Int64()
			return n, e == nil
		case int64:
			return x, true
		}
		return 0, false
	}
	version, ok := integer(value["schema_version"])
	if !ok || version != 1 {
		return
	}
	epoch, ok := integer(value["epoch"])
	if !ok || epoch != r.Identity.Epoch || value["job_id"] != r.Identity.JobID || value["attempt_id"] != r.Identity.AttemptID || value["component_id"] != r.Identity.ComponentID {
		return
	}
	metrics := map[string]float64{}
	if v, ok := value["metrics"]; ok {
		m, ok := v.(map[string]any)
		if !ok || len(m) > 32 {
			return
		}
		for k, v := range m {
			if len(k) > 64 || !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]*$`).MatchString(k) {
				return
			}
			n, ok := v.(json.Number)
			if !ok {
				return
			}
			f, e := n.Float64()
			if e != nil || math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > 1e100 {
				return
			}
			metrics[k] = f
		}
	}
	readiness, has := value["readiness"]
	if has && readiness != nil && !contains([]any{"initializing", "waiting", "ready", "training", "finished", "failed"}, readiness) {
		return
	}
	details := map[string]any{"reported": true, "metrics": metrics}
	for _, key := range []string{"current_round", "target_round", "source_round", "eligible_count", "minimum_participants"} {
		if n, ok := integer(value[key]); ok && n >= 0 {
			details[key] = n
			if key == "current_round" {
				n := n
				ob.CurrentRound = &n
			}
		}
	}
	for _, key := range []string{"phase", "readiness", "revision", "role", "participant_id", "observed_at"} {
		if x, ok := value[key].(string); ok && len(x) <= 200 && !strings.ContainsFunc(x, func(r rune) bool { return r < 32 }) {
			details[key] = x
			if key == "phase" {
				ob.Phase = x
			}
			if key == "readiness" {
				ob.Readiness = x
			}
		}
	}
	ob.Details = details
	ob.Metrics = metrics
}
func uniqueJSON(raw []byte) bool {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	var read func() bool
	read = func() bool {
		t, e := d.Token()
		if e != nil {
			return false
		}
		if delim, ok := t.(json.Delim); ok {
			if delim == '{' {
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					key, ok := k.(string)
					if e != nil || !ok || seen[key] {
						return false
					}
					seen[key] = true
					if !read() {
						return false
					}
				}
				end, e := d.Token()
				return e == nil && end == json.Delim('}')
			}
			if delim == '[' {
				for d.More() {
					if !read() {
						return false
					}
				}
				end, e := d.Token()
				return e == nil && end == json.Delim(']')
			}
			return false
		}
		return true
	}
	if !read() {
		return false
	}
	_, e := d.Token()
	return e == io.EOF
}
func (e *LinuxExecutor) secretValues(s ExecutionSpec) ([]string, error) {
	if s.SecretPath == "" {
		return nil, nil
	}
	if err := e.trustedPath(s.SecretPath, "file"); err != nil {
		return nil, err
	}
	manifest, err := secrets.ReadManifest(s.SecretPath, secrets.Binding{JobID: s.Identity.JobID, AttemptID: s.Identity.AttemptID, ComponentID: s.Identity.ComponentID, Epoch: s.Identity.Epoch})
	if err != nil {
		return nil, refused("unsafe_output")
	}
	values := make([]string, 0, len(manifest.Options))
	for _, value := range manifest.Options {
		values = append(values, value)
	}
	return values, nil
}

func (e *LinuxExecutor) ReadLogs(ctx context.Context, id ExecutionIdentity, offset, maxBytes int64) (map[string]any, error) {
	var result map[string]any
	err := e.withLock(id, func() error { var err error; result, err = e.readLogs(ctx, id, offset, maxBytes); return err })
	return result, err
}
func (e *LinuxExecutor) readLogs(ctx context.Context, id ExecutionIdentity, offset, maxBytes int64) (map[string]any, error) {
	r, err := e.load(id)
	if err != nil {
		return nil, err
	}
	if r.DiskDeleted {
		return nil, refused("artifact_unavailable")
	}
	spool, err := artifacts.NewLogSpool(filepath.Join(e.directory(id), "canonical-logs"), 1<<20)
	if err != nil {
		return nil, err
	}
	if r.ContainerRemoved || r.State == "RELEASED" {
		if _, err := os.Stat(filepath.Join(e.directory(id), "canonical-logs", "stdout.log")); os.IsNotExist(err) {
			var data []byte
			for _, item := range r.RetainedArtifacts {
				if item.Path == "runtime/stdout.log" {
					data, err = e.readRetained(r, item.Path, 4<<20)
					if err != nil {
						return nil, err
					}
				}
			}
			if err = spool.Update(data, true); err != nil {
				return nil, err
			}
		} else {
			if err = spool.MarkComplete(); err != nil {
				return nil, err
			}
		}
	} else if r.State == "RESERVED" || r.State == "PREPARING" || r.NeverStarted {
		if err = spool.Update(nil, r.NeverStarted); err != nil {
			return nil, err
		}
	} else {
		if err = e.verifyContainer(ctx, r); err != nil {
			return nil, err
		}
		raw, err := e.docker(ctx, []string{"logs", "--timestamps", "--tail", "10000", r.Container}, true, false)
		if err != nil {
			return nil, err
		}
		text := raw.Stdout + raw.Stderr
		if len(text) > 4<<20 {
			return nil, refused("log_snapshot_exceeds_bound")
		}
		lines := strings.SplitAfter(text, "\n")
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		timestamp := regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[^ ]+ `)
		for _, line := range lines {
			if !timestamp.MatchString(line) {
				return nil, refused("invalid_log_snapshot")
			}
		}
		sort.SliceStable(lines, func(i, j int) bool { return strings.SplitN(lines[i], " ", 2)[0] < strings.SplitN(lines[j], " ", 2)[0] })
		secrets, err := e.secretValues(r.Spec)
		if err != nil {
			return nil, err
		}
		collector, err := artifacts.NewCollector(e.directory(id), artifacts.CollectorOptions{MaxFileBytes: 4 << 20, MaxTotalBytes: 4 << 20, SecretValues: secrets})
		if err != nil {
			return nil, err
		}
		redacted, err := collector.Redact(strings.Join(lines, ""), 4<<20)
		collector.Close()
		if err != nil {
			return nil, err
		}
		ob, err := e.inspect(ctx, id)
		if err != nil {
			return nil, err
		}
		if err = spool.Update([]byte(redacted), ob.TerminationConfirmed); err != nil {
			return nil, err
		}
	}
	receipt, err := spool.Read(artifacts.LogIdentity{JobID: id.JobID, AttemptID: id.AttemptID, ComponentID: id.ComponentID, Epoch: id.Epoch}, offset, maxBytes)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err = decodeJSON(raw, &result); err != nil {
		return nil, err
	}
	return result, nil
}
func (e *LinuxExecutor) Collect(ctx context.Context, id ExecutionIdentity) ([]CollectedArtifact, error) {
	var files []CollectedArtifact
	err := e.withLock(id, func() error { var err error; files, err = e.collect(ctx, id); return err })
	return files, err
}
func (e *LinuxExecutor) collect(ctx context.Context, id ExecutionIdentity) ([]CollectedArtifact, error) {
	r, err := e.load(id)
	if err != nil {
		return nil, err
	}
	if r.DiskDeleted {
		return []CollectedArtifact{}, nil
	}
	ob, err := e.inspect(ctx, id)
	if err != nil {
		return nil, err
	}
	if !ob.TerminationConfirmed {
		return nil, refused("runtime_active")
	}
	if r.NeverStarted || r.State == "RESERVED" || r.State == "PREPARING" {
		return []CollectedArtifact{}, nil
	}
	if r.ArtifactsCollected {
		return append([]CollectedArtifact(nil), r.RetainedArtifacts...), nil
	}
	source := filepath.Join(e.directory(id), "state")
	dest := filepath.Join(e.directory(id), "retained", "state")
	c, err := artifacts.NewCollector(source, artifacts.CollectorOptions{MaxTotalBytes: r.Spec.Resources.DiskBytes})
	if err != nil {
		return nil, err
	}
	retained, err := c.Retain(dest)
	c.Close()
	if err != nil {
		return nil, err
	}
	files := []CollectedArtifact{}
	for _, item := range retained {
		files = append(files, CollectedArtifact{Path: item.Path, Locator: item.Locator, SizeBytes: item.SizeBytes, SHA256: item.SHA256})
	}
	if _, err = e.readLogs(ctx, id, 0, 65536); err != nil {
		return nil, err
	}
	logroot := filepath.Join(e.directory(id), "canonical-logs")
	c, err = artifacts.NewCollector(logroot, artifacts.CollectorOptions{MaxTotalBytes: 1 << 20})
	if err != nil {
		return nil, err
	}
	data, err := c.Read("stdout.log", 1<<20)
	c.Close()
	if err != nil {
		return nil, err
	}
	logsource := filepath.Join(e.directory(id), "collected-logs")
	if err = os.MkdirAll(logsource, 0700); err != nil {
		return nil, err
	}
	if err = atomicBytes(filepath.Join(logsource, "stdout.log"), data); err != nil {
		return nil, err
	}
	c, err = artifacts.NewCollector(logsource, artifacts.CollectorOptions{MaxTotalBytes: 1 << 20})
	if err != nil {
		return nil, err
	}
	logs, err := c.Retain(filepath.Join(e.directory(id), "retained", "runtime"))
	c.Close()
	if err != nil {
		return nil, err
	}
	for _, item := range logs {
		files = append(files, CollectedArtifact{Path: "runtime/" + item.Path, Locator: item.Locator, SizeBytes: item.SizeBytes, SHA256: item.SHA256, Kind: "log"})
	}
	if err = os.Remove(filepath.Join(logsource, "stdout.log")); err != nil {
		return nil, err
	}
	if err = os.Remove(logsource); err != nil {
		return nil, err
	}
	var total int64
	for _, item := range files {
		total += item.SizeBytes
	}
	r.RetainedArtifacts = files
	r.ArtifactsCollected = true
	r.RetainedBytes = total
	if err = e.save(id, r); err != nil {
		return nil, err
	}
	return files, nil
}
func (e *LinuxExecutor) ReconciliationRoot(ctx context.Context, id ExecutionIdentity) (string, error) {
	ob, err := e.inspect(ctx, id)
	if err != nil {
		return "", err
	}
	if !ob.TerminationConfirmed {
		return "", refused("runtime_active")
	}
	r, err := e.load(id)
	if err != nil {
		return "", err
	}
	root := filepath.Join(e.directory(id), "retained", "state")
	if r.Mounted {
		root = filepath.Join(e.directory(id), "state")
	}
	f, err := openChecked(root, true, false)
	if err != nil {
		return "", refused("missing_resource")
	}
	f.Close()
	return root, nil
}
func (e *LinuxExecutor) ReadArtifact(ctx context.Context, id ExecutionIdentity, path string, maxBytes int64) ([]byte, error) {
	var data []byte
	err := e.withLock(id, func() error {
		if _, err := e.collect(ctx, id); err != nil {
			return err
		}
		r, err := e.load(id)
		if err != nil {
			return err
		}
		data, err = e.readRetained(r, path, maxBytes)
		return err
	})
	return data, err
}
func (e *LinuxExecutor) readRetained(r *executionRecord, path string, maxBytes int64) ([]byte, error) {
	if r.DiskDeleted || maxBytes < 1 || maxBytes > 256<<20 {
		return nil, refused("artifact_unavailable")
	}
	var item *CollectedArtifact
	for n := range r.RetainedArtifacts {
		if r.RetainedArtifacts[n].Path == path {
			if item != nil {
				return nil, refused("artifact_unavailable")
			}
			item = &r.RetainedArtifacts[n]
		}
	}
	if item == nil {
		return nil, refused("artifact_unavailable")
	}
	if item.SizeBytes > maxBytes {
		return nil, refused("output_too_large")
	}
	root := filepath.Join(e.directory(r.Identity), "retained")
	expected := filepath.Join(root, "state", filepath.FromSlash(path))
	if path == "runtime/stdout.log" && item.Locator == filepath.Join(root, "runtime", "stdout.log") {
		expected = item.Locator
	}
	if item.Locator != expected {
		return nil, refused("unsafe_output")
	}
	relative, err := filepath.Rel(root, item.Locator)
	if err != nil {
		return nil, err
	}
	c, err := artifacts.NewCollector(root, artifacts.CollectorOptions{MaxFileBytes: maxBytes, MaxTotalBytes: maxBytes})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	data, err := c.Read(filepath.ToSlash(relative), maxBytes)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)
	if int64(len(data)) != item.SizeBytes || hex.EncodeToString(hash[:]) != item.SHA256 {
		return nil, refused("unsafe_output")
	}
	return data, nil
}
func (e *LinuxExecutor) reconcileVolume(ctx context.Context, id ExecutionIdentity, r *executionRecord) error {
	image := filepath.Join(e.directory(id), "state.ext4")
	mount := filepath.Join(e.directory(id), "state")
	_, imageErr := os.Lstat(image)
	if os.IsNotExist(imageErr) {
		if r.Mounted || r.LoopDevice != "" || len(r.OwnedLoopDevices) > 0 {
			found, err := e.system(ctx, []string{"findmnt", "--mountpoint", mount, "--noheadings", "--output", "SOURCE"}, true, true)
			if err != nil || found.ExitCode != 1 {
				return uncertain(err)
			}
			loops, err := e.system(ctx, []string{"losetup", "--list", "--json", "--output", "NAME,BACK-FILE"}, true, false)
			if err != nil {
				return err
			}
			var value struct {
				LoopDevices []struct {
					Name     string `json:"name"`
					BackFile string `json:"back-file"`
				} `json:"loopdevices"`
			}
			if json.Unmarshal([]byte(loops.Stdout), &value) != nil {
				return uncertain(nil)
			}
			for _, item := range value.LoopDevices {
				if item.BackFile == image || item.BackFile == image+" (deleted)" {
					return uncertain(nil)
				}
			}
			r.Mounted = false
			r.LoopDevice = ""
			r.OwnedLoopDevices = nil
			return e.save(id, r)
		}
		return nil
	}
	if imageErr != nil {
		return uncertain(imageErr)
	}
	f, err := openChecked(image, false, true)
	if err != nil {
		return err
	}
	f.Close()
	loops, err := e.system(ctx, []string{"losetup", "--json", "--associated", image, "--output", "NAME,BACK-FILE"}, true, false)
	if err != nil {
		return err
	}
	var value struct {
		LoopDevices []struct {
			Name     string `json:"name"`
			BackFile string `json:"back-file"`
		} `json:"loopdevices"`
	}
	if json.Unmarshal([]byte(loops.Stdout), &value) != nil {
		return uncertain(nil)
	}
	owned := []string{}
	for _, item := range value.LoopDevices {
		if item.BackFile != image || !loopDevice.MatchString(item.Name) || contains(owned, item.Name) {
			return uncertain(nil)
		}
		owned = append(owned, item.Name)
	}
	found, err := e.system(ctx, []string{"findmnt", "--mountpoint", mount, "--noheadings", "--output", "SOURCE"}, true, true)
	if err != nil || found.ExitCode > 1 {
		return uncertain(err)
	}
	if found.ExitCode == 0 {
		source := strings.TrimSpace(found.Stdout)
		if !contains(owned, source) {
			return uncertain(nil)
		}
		r.Mounted = true
		r.LoopDevice = source
	} else {
		r.Mounted = false
		if !contains(owned, r.LoopDevice) {
			r.LoopDevice = ""
			if len(owned) > 0 {
				r.LoopDevice = owned[0]
			}
		}
	}
	r.OwnedLoopDevices = owned
	return e.save(id, r)
}
func (e *LinuxExecutor) Release(ctx context.Context, id ExecutionIdentity) (bool, error) {
	confirmed := false
	err := e.withLock(id, func() error {
		r, err := e.load(id)
		if err != nil {
			return err
		}
		if r.State == "RELEASED" {
			confirmed = true
			return nil
		}
		if r.ContainerRemovalIntent && !r.ContainerRemoved {
			absent, proofErr := e.confirmContainerRemoval(ctx, r)
			if proofErr != nil {
				return proofErr
			}
			if absent {
				r.ContainerRemoved = true
				if err = e.save(id, r); err != nil {
					return err
				}
			}
		}
		if err = e.reconcileVolume(ctx, id, r); err != nil {
			return err
		}
		if r.State == "RESERVED" || r.State == "PREPARING" {
			r.State = "STOPPED"
			r.NeverStarted = true
			if err = e.save(id, r); err != nil {
				return err
			}
		}
		if !r.NeverStarted {
			ob, err := e.inspect(ctx, id)
			if err != nil {
				return err
			}
			if !ob.TerminationConfirmed {
				return uncertain(nil)
			}
			if r.Mounted && !r.ArtifactsCollected {
				if _, err = e.collect(ctx, id); err != nil {
					return err
				}
				r, err = e.load(id)
				if err != nil {
					return err
				}
			}
			if !r.ContainerRemoved {
				raw, proofErr := e.readContainer(ctx, r)
				if proofErr != nil {
					return proofErr
				}
				if proofErr = e.validateContainer(r, raw); proofErr != nil {
					return proofErr
				}
				if raw.State.Running || !r.ArtifactsCollected {
					return uncertain(nil)
				}
				r.State = "STOPPED"
				r.ContainerRemovalIntent = true
				if err = e.save(id, r); err != nil {
					return err
				}
				if _, err = e.docker(ctx, []string{"rm", r.Container}, true, false); err != nil {
					return err
				}
				r.ContainerRemoved = true
				if err = e.save(id, r); err != nil {
					return err
				}
			}
		}
		if r.Mounted {
			if _, err = e.system(ctx, []string{"umount", filepath.Join(e.directory(id), "state")}, true, false); err != nil {
				return err
			}
			r.Mounted = false
			if err = e.save(id, r); err != nil {
				return err
			}
		}
		// Re-query associations rather than acting on a loop name from a prior boot/crash.
		if err = e.reconcileVolume(ctx, id, r); err != nil {
			return err
		}
		for _, device := range r.OwnedLoopDevices {
			if _, err = e.system(ctx, []string{"losetup", "--detach", device}, true, false); err != nil && !IsUncertain(err) {
				return err
			}
		}
		image := filepath.Join(e.directory(id), "state.ext4")
		if _, err := os.Lstat(image); err == nil {
			until := time.Now().Add(30 * time.Second)
			for {
				loops, err := e.system(ctx, []string{"losetup", "--json", "--associated", image, "--output", "NAME,BACK-FILE"}, true, false)
				if err != nil {
					return err
				}
				var value struct {
					LoopDevices []json.RawMessage `json:"loopdevices"`
				}
				if json.Unmarshal([]byte(loops.Stdout), &value) != nil {
					return uncertain(nil)
				}
				if len(value.LoopDevices) == 0 {
					break
				}
				if time.Now().After(until) {
					return uncertain(nil)
				}
				select {
				case <-ctx.Done():
					return uncertain(ctx.Err())
				case <-time.After(100 * time.Millisecond):
				}
			}
			if !r.ArtifactsCollected && !r.NeverStarted {
				return uncertain(nil)
			}
			f, err := openChecked(image, false, true)
			if err != nil {
				return err
			}
			f.Close()
			if err = os.Remove(image); err != nil {
				return err
			}
			if err = syncDirectory(filepath.Dir(image)); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		r.Mounted = false
		r.LoopDevice = ""
		r.OwnedLoopDevices = nil
		r.FixedVolumeDeleted = true
		if err = e.save(id, r); err != nil {
			return err
		}
		if !r.StateCopied && !r.NeverStarted {
			if err = e.restoreState(r); err != nil {
				return err
			}
			r.StateCopied = true
			if err = e.save(id, r); err != nil {
				return err
			}
		}
		r.State = "RELEASED"
		r.Retained = r.StateCopied
		if err = e.save(id, r); err != nil {
			return err
		}
		confirmed = true
		return nil
	})
	return confirmed, err
}
func syncDirectory(path string) error {
	f, err := openChecked(path, true, false)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func (e *LinuxExecutor) restoreState(r *executionRecord) error {
	if err := e.trustedPath(r.Spec.StatePath, "directory"); err != nil {
		return err
	}
	for _, temporary := range r.CopyTempfiles {
		if !safeRelative(temporary) || !strings.HasPrefix(filepath.Base(temporary), ".hf2l-") {
			return refused("unsafe_output")
		}
		path := filepath.Join(r.Spec.StatePath, filepath.FromSlash(temporary))
		if err := e.trustedPath(filepath.Dir(path), "directory"); err != nil {
			return err
		}
		if _, err := os.Lstat(path); err == nil {
			file, err := openChecked(path, false, true)
			if err != nil {
				return err
			}
			file.Close()
			if err = os.Remove(path); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	r.CopyTempfiles = nil
	if err := e.save(r.Identity, r); err != nil {
		return err
	}
	source := filepath.Join(e.directory(r.Identity), "retained", "state")
	expected := map[string]CollectedArtifact{}
	for _, item := range r.RetainedArtifacts {
		rel, err := filepath.Rel(source, item.Locator)
		if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
			continue
		}
		if filepath.ToSlash(rel) != item.Path {
			return refused("unsafe_output")
		}
		expected[item.Path] = item
	}
	c, err := artifacts.NewCollector(source, artifacts.CollectorOptions{MaxTotalBytes: r.Spec.Resources.DiskBytes})
	if err != nil {
		return err
	}
	defer c.Close()
	files, err := c.ListFiles()
	if err != nil {
		return err
	}
	if len(files) != len(expected) {
		return refused("unsafe_output")
	}
	for _, item := range files {
		want, ok := expected[item.Path]
		if !ok || want.SizeBytes != item.SizeBytes || want.SHA256 != item.SHA256 {
			return refused("unsafe_output")
		}
	}
	for _, item := range files {
		data, err := c.Read(item.Path, item.SizeBytes+1)
		if err != nil {
			return err
		}
		target := filepath.Join(r.Spec.StatePath, filepath.FromSlash(item.Path))
		if err = makeSafeParents(r.Spec.StatePath, filepath.Dir(target)); err != nil {
			return err
		}
		if err = e.trackedStateCopy(r, target, data); err != nil {
			return err
		}
	}
	return nil
}
func (e *LinuxExecutor) Purge(ctx context.Context, id ExecutionIdentity) (bool, error) {
	confirmed := false
	err := e.withLock(id, func() error {
		r, err := e.load(id)
		if err != nil {
			return err
		}
		if r.State != "RELEASED" || r.Mounted || r.LoopDevice != "" {
			return refused("runtime_active")
		}
		if err = e.reconcileVolume(ctx, id, r); err != nil {
			return err
		}
		if r.Mounted || len(r.OwnedLoopDevices) > 0 {
			return refused("runtime_active")
		}
		image := filepath.Join(e.directory(id), "state.ext4")
		if _, err := os.Lstat(image); err == nil {
			f, err := openChecked(image, false, true)
			if err != nil {
				return err
			}
			f.Close()
			if err = os.Remove(image); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		for _, pair := range []struct {
			Name string
			Max  int64
		}{{"retained/state", r.Spec.Resources.DiskBytes}, {"retained/runtime", 1 << 20}, {"collected-logs", 4 << 20}, {"canonical-logs", 1 << 20}} {
			root := filepath.Join(e.directory(id), pair.Name)
			if _, err := os.Lstat(root); os.IsNotExist(err) {
				continue
			} else if err != nil {
				return err
			}
			c, err := artifacts.NewCollector(root, artifacts.CollectorOptions{MaxTotalBytes: pair.Max})
			if err != nil {
				return err
			}
			files, err := c.ListFiles()
			c.Close()
			if err != nil {
				return err
			}
			manifest := []artifacts.RetainedFile{}
			for _, item := range files {
				manifest = append(manifest, artifacts.RetainedFile{Path: item.Path, Locator: filepath.Join(root, filepath.FromSlash(item.Path)), SizeBytes: item.SizeBytes, SHA256: item.SHA256})
			}
			if strings.HasPrefix(pair.Name, "retained/") && len(r.RetainedArtifacts) > 0 {
				expected := map[string]CollectedArtifact{}
				for _, item := range r.RetainedArtifacts {
					rel, err := filepath.Rel(root, item.Locator)
					if err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
						expected[filepath.ToSlash(rel)] = item
					}
				}
				if len(expected) != len(manifest) {
					return refused("unsafe_output")
				}
				for _, item := range manifest {
					old, ok := expected[item.Path]
					if !ok || old.SizeBytes != item.SizeBytes || old.SHA256 != item.SHA256 {
						return refused("unsafe_output")
					}
				}
			}
			if _, err = artifacts.DeleteRetained(root, manifest, artifacts.CollectorOptions{MaxTotalBytes: pair.Max}); err != nil {
				return err
			}
		}
		parent := filepath.Join(e.directory(id), "retained")
		if _, err := os.Lstat(parent); err == nil {
			if err = os.Remove(parent); err != nil {
				return err
			}
		}
		r.Retained = false
		r.DiskDeleted = true
		if err = e.save(id, r); err != nil {
			return err
		}
		confirmed = true
		return nil
	})
	return confirmed, err
}

func safeRelative(path string) bool {
	if path == "" || filepath.IsAbs(path) || strings.ContainsAny(path, "\\\x00\n\r") {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
func (e *LinuxExecutor) trackedStateCopy(r *executionRecord, target string, data []byte) error {
	parent, err := openChecked(filepath.Dir(target), true, false)
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(target)
	var st unix.Stat_t
	err = unix.Fstatat(int(parent.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1) {
		return refused("unsafe_output")
	}
	if err != nil && err != unix.ENOENT {
		return err
	}
	temporary := ".hf2l-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	fd, err := unix.Openat(int(parent.Fd()), temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	defer func() { file.Close(); unix.Unlinkat(int(parent.Fd()), temporary, 0) }()
	relative, err := filepath.Rel(r.Spec.StatePath, filepath.Join(filepath.Dir(target), temporary))
	if err != nil || !safeRelative(relative) {
		return refused("unsafe_output")
	}
	r.CopyTempfiles = append(r.CopyTempfiles, filepath.ToSlash(relative))
	if err = e.save(r.Identity, r); err != nil {
		return err
	}
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = unix.Renameat(int(parent.Fd()), temporary, int(parent.Fd()), name); err != nil {
		return err
	}
	if err = parent.Sync(); err != nil {
		return err
	}
	for i, path := range r.CopyTempfiles {
		if path == filepath.ToSlash(relative) {
			r.CopyTempfiles = append(r.CopyTempfiles[:i], r.CopyTempfiles[i+1:]...)
			break
		}
	}
	return e.save(r.Identity, r)
}
