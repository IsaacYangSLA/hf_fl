//go:build linux && integration

package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/resources"
)

// TestQualifiedCPULifecycle uses only an explicitly supplied, already qualified,
// private daemon. It exercises the real Go executor and ledger; no runner, host
// inspector, clock, image command, or qualification result is replaced.
func TestQualifiedCPULifecycle(t *testing.T) {
	profilePath := os.Getenv("HF2L_TEST_QUALIFIED_PROFILE")
	image := os.Getenv("HF2L_TEST_WORKER_IMAGE")
	root := os.Getenv("HF2L_TEST_EXECUTOR_ROOT")
	if profilePath == "" || image == "" || root == "" {
		t.Skip("set qualified profile, immutable worker image and fresh private executor root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	qualificationEvidence, err := validateLiveQualification(profilePath, image)
	must(err)
	must(os.Mkdir(root, 0700))
	e, err := NewLinuxExecutor(profilePath, filepath.Join(root, "executions"))
	must(err)
	must(e.QualifyHealth(ctx))
	// Every effect below is bound to this unique root and these three identities.
	agent, err := NewNodeAgent(e, filepath.Join(root, "node.sqlite"), "integration-node", "integration-cpu", ResourceLimits{CPUMillis: 2000, MemoryBytes: 2 << 30, DiskBytes: 1 << 30})
	must(err)
	t.Cleanup(func() { agent.Close() })
	dirs, err := resources.NewOwnedDirectories(filepath.Join(root, "jobs"))
	must(err)
	t.Cleanup(func() { dirs.Close() })
	prefix := "integration-" + domain.NewID()
	ids := []ExecutionIdentity{{prefix + "-a", "attempt-one", "build", 1}, {prefix + "-b", "attempt-one", "build", 1}, {prefix + "-a", "attempt-two", "build", 2}}
	digests := map[string]string{}
	specs := map[string]ExecutionSpec{}
	report := map[string]any{"scope": "real Go NodeAgent build application, cancellation, watchdog, retry, collection and physical cleanup; not federation", "profile": profilePath, "image": image, "root": root, "started_at": time.Now().UTC(), "qualification_evidence": qualificationEvidence}
	checkedCleanup := false
	cleanup := func() error {
		err := cleanupLiveFixture(context.Background(), e, agent, dirs, ids, specs, digests)
		if err == nil {
			report["final_storage_bytes"] = int64(0)
			report["physical_cleanup_confirmed"] = true
		}
		return err
	}
	t.Cleanup(func() {
		if !checkedCleanup {
			if err := cleanup(); err != nil {
				t.Errorf("failure cleanup: %v", err)
			}
		}
		report["completed_at"] = time.Now().UTC()
		report["passed"] = !t.Failed()
		raw, _ := json.MarshalIndent(report, "", "  ")
		if err := os.WriteFile(filepath.Join(root, "report.json"), append(raw, '\n'), 0600); err != nil {
			t.Error(err)
		}
	})
	sourceFiles := map[string]string{"pyproject.toml": "[build-system]\nrequires = [\"numpy==2.5.4\"]\nbuild-backend = \"backend\"\nbackend-path = [\".\"]\n", "backend.py": liveBuildBackend}
	manifest := map[string]string{}
	sourceBytes := int64(0)
	for name, content := range sourceFiles {
		manifest[name] = sum([]byte(content))
		sourceBytes += int64(len(content))
	}
	report["source_manifest"] = manifest
	limits := ResourceLimits{CPUMillis: 500, MemoryBytes: 512 << 20, DiskBytes: 64 << 20, PIDs: 64, IOBPS: 16 << 20}
	prepare := func(id ExecutionIdentity) {
		request := domain.ResourceRequest{PoolID: "integration-cpu", CPUMillicores: 500, MemoryBytes: 512 << 20, DiskBytes: 64 << 20, SandboxProfile: "runsc-cpu-v1"}
		job := domain.JobSpec{ProjectID: "integration-project", Name: "Qualified CPU lifecycle", SourceID: "integration-source", SourceCommit: strings.Repeat("a", 40), RuntimeImage: image, Plugin: "integration_probe", Options: map[string]any{}, SecretRefs: map[string]string{}, Participants: []domain.ParticipantSpec{}, Components: []domain.ComponentSpec{{ComponentID: "owner", Role: "owner", Resources: request}, {ComponentID: "build", Role: "build", Resources: request}}, TargetRound: 2, MaxDurationSeconds: 180}
		digest, err := job.Digest()
		must(err)
		digests[id.JobID] = digest
		_, err = dirs.EnsureJob(id.JobID, digest)
		must(err)
		paths, err := dirs.Components(id.JobID, []string{"build"})
		must(err)
		p := paths["build"]
		configPath := filepath.Join(root, "jobs", id.JobID, "components", "build", fmt.Sprintf("runtime-%d.json", id.Epoch))
		spec := ExecutionSpec{Identity: id, ImageDigest: image, SourcePath: p.Source, StatePath: p.State, ConfigPath: configPath, Resources: limits, LeaseSeconds: 120, PoolID: "integration-cpu", NodeID: "integration-node", Role: "build"}.Defaults()
		config := map[string]any{"schema_version": 1, "role": "build", "job_id": id.JobID, "attempt_id": id.AttemptID, "component_id": id.ComponentID, "epoch": id.Epoch, "spec": job.Map(), "spec_digest": digest, "source_dir": "/job/source", "state_dir": "/job/state", "source_manifest": manifest, "project_subdir": ".", "approved_dependencies": map[string]string{"build": "1.6.1", "numpy": "2.5.4"}}
		raw, err := json.Marshal(config)
		must(err)
		must(agent.WithComponentGuardContext(ctx, id, false, func(guarded context.Context) error {
			reservation, err := agent.Reserve(guarded, spec)
			if err != nil {
				return err
			}
			if !reservation.Acknowledged {
				return fmt.Errorf("reserve not acknowledged")
			}
			specs[id.Key()] = spec
			ok, err := agent.ChargeAuxiliaryBytes(guarded, id, int64(len(raw)))
			if err != nil || !ok {
				return fmt.Errorf("config charge: %v", err)
			}
			ok, err = agent.ChargeSharedAuxiliaryBytes(guarded, id, sourceBytes)
			if err != nil || !ok {
				return fmt.Errorf("source charge: %v", err)
			}
			if id.Epoch == 1 {
				if err := os.Mkdir(p.Source, 0700); err != nil {
					return err
				}
				for name, content := range sourceFiles {
					if err := os.WriteFile(filepath.Join(p.Source, name), []byte(content), 0400); err != nil {
						return err
					}
				}
			}
			return os.WriteFile(configPath, raw, 0600)
		}))
	}
	for _, id := range ids[:2] {
		prepare(id)
		observation, err := agent.Start(ctx, id)
		must(err)
		if observation.TerminationConfirmed {
			t.Fatalf("early termination: %+v", observation)
		}
	}
	waitProof := func(id ExecutionIdentity) {
		until := time.Now().Add(35 * time.Second)
		for time.Now().Before(until) {
			logs, err := agent.ReadLogs(ctx, id, 0, 65536)
			must(err)
			if strings.Contains(fmt.Sprint(logs["content"]), "NUMPY_PROOF_READY") {
				return
			}
			observation, err := agent.Inspect(ctx, id)
			must(err)
			if observation.TerminationConfirmed {
				t.Fatalf("worker ended before numeric proof: %+v logs=%v", observation, logs)
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("timed out waiting for NumPy build proof")
	}
	for _, id := range ids[:2] {
		waitProof(id)
	}
	for _, id := range ids[:2] {
		observation, err := agent.Inspect(ctx, id)
		must(err)
		if observation.State != "RUNNING" || observation.TerminationConfirmed {
			t.Fatalf("not concurrently running: %+v", observation)
		}
	}
	report["two_components_running"] = true
	stopped, err := agent.Stop(ctx, ids[0], 1)
	must(err)
	if !stopped.TerminationConfirmed {
		t.Fatal("cancel did not confirm termination")
	}
	report["cancel_confirmed"] = true
	must(agent.RenewLease(ctx, ids[1], 2))
	time.Sleep(2100 * time.Millisecond)
	affected, err := agent.WatchdogOnce(ctx)
	must(err)
	found := false
	for _, id := range affected {
		if id == ids[1] {
			found = true
		}
	}
	if !found {
		t.Fatalf("watchdog did not fence expired worker: %v", affected)
	}
	observation, err := agent.Inspect(ctx, ids[1])
	must(err)
	if !observation.TerminationConfirmed {
		t.Fatal("watchdog termination unconfirmed")
	}
	report["watchdog_confirmed"] = true
	retained := map[string]any{}
	for _, id := range ids[:2] {
		files, err := agent.Collect(ctx, id)
		must(err)
		retained[id.Key()] = files
		ok, err := agent.Release(ctx, id)
		must(err)
		if !ok {
			t.Fatal("release unconfirmed")
		}
		raw, err := os.ReadFile(filepath.Join(specs[id.Key()].StatePath, "numpy-proof.json"))
		must(err)
		var proof map[string]float64
		must(json.Unmarshal(raw, &proof))
		if proof["final_loss"] >= 1e-6 || proof["initial_loss"] <= proof["final_loss"] {
			t.Fatalf("numeric computation failed: %v", proof)
		}
		report[id.JobID+"_numeric_proof"] = proof
	}
	used, err := agent.StorageUsageBytes(ctx)
	must(err)
	if used <= 0 {
		t.Fatal("retained disk quota prematurely released")
	}
	report["retained_storage_bytes"] = used
	// A distinct attempt/epoch reuses its immutable source and retained state.
	prepare(ids[2])
	observation, err = agent.Start(ctx, ids[2])
	must(err)
	until := time.Now().Add(35 * time.Second)
	for !observation.TerminationConfirmed && time.Now().Before(until) {
		time.Sleep(100 * time.Millisecond)
		observation, err = agent.Inspect(ctx, ids[2])
		must(err)
	}
	if !observation.TerminationConfirmed || observation.ExitCode == nil || *observation.ExitCode != 0 {
		logs, _ := agent.ReadLogs(ctx, ids[2], 0, 65536)
		t.Fatalf("retry did not complete: %+v logs=%v", observation, logs)
	}
	files, err := agent.Collect(ctx, ids[2])
	must(err)
	retained[ids[2].Key()] = files
	wheel := false
	descriptor := false
	for _, f := range files {
		if strings.HasSuffix(f.Path, ".whl") {
			wheel = true
		}
		if strings.HasSuffix(f.Path, "build.json") {
			descriptor = true
		}
	}
	if !wheel || !descriptor {
		t.Fatalf("missing opaque build artifacts: %v", files)
	}
	report["collected_artifacts"] = retained
	report["retry_completed"] = true
	must(cleanup())
	checkedCleanup = true
}

// Validate the original adversarial and physical-I/O evidence, including hashes
// and every check, before making any runtime effect. The worker is the exact
// immutable image tested by the isolation qualification.
func validateLiveQualification(path, image string) (map[string]string, error) {
	raw, err := readPrivateFile(path, 1<<20, true)
	if err != nil {
		return nil, err
	}
	var profile map[string]any
	if json.Unmarshal(raw, &profile) != nil || profile["qualified"] != true || profile["backing_io_qualified"] != true || profile["qualification_image"] != image {
		return nil, fmt.Errorf("missing exact-image qualification")
	}
	result := map[string]string{"profile_sha256": sum(raw)}
	for _, entry := range []struct {
		prefix  string
		minimum int
	}{{"qualification", 201}, {"backing_io_qualification", 23}} {
		reportPath, ok := profile[entry.prefix+"_path"].(string)
		if !ok {
			return nil, fmt.Errorf("missing qualification report")
		}
		digest, ok := profile[entry.prefix+"_sha256"].(string)
		if !ok {
			return nil, fmt.Errorf("missing qualification hash")
		}
		reportRaw, err := readPrivateFile(reportPath, 8<<20, true)
		if err != nil {
			return nil, err
		}
		if sum(reportRaw) != digest {
			return nil, fmt.Errorf("qualification evidence changed")
		}
		var report struct {
			Qualified bool `json:"qualified"`
			Image     struct {
				ID string `json:"id"`
			} `json:"image"`
			Checks []struct {
				Name   string `json:"name"`
				Passed bool   `json:"passed"`
			} `json:"checks"`
		}
		if json.Unmarshal(reportRaw, &report) != nil || !report.Qualified || len(report.Checks) < entry.minimum || profile[entry.prefix+"_checks"] != float64(len(report.Checks)) {
			return nil, fmt.Errorf("incomplete original qualification")
		}
		if entry.prefix == "qualification" && report.Image.ID != image {
			return nil, fmt.Errorf("isolation report belongs to another image")
		}
		names := map[string]bool{}
		for _, check := range report.Checks {
			if !check.Passed || check.Name == "" || names[check.Name] {
				return nil, fmt.Errorf("failed or repeated qualification check")
			}
			names[check.Name] = true
		}
		result[entry.prefix+"_sha256"] = digest
	}
	return result, nil
}

// This preflight can be repeated against the real published evidence while
// another test owns the runtime: it performs no Docker, mount, or worker effects.
func TestLiveQualificationEvidenceProvidedProfile(t *testing.T) {
	path, image := os.Getenv("HF2L_TEST_QUALIFIED_PROFILE"), os.Getenv("HF2L_TEST_WORKER_IMAGE")
	if path == "" || image == "" {
		t.Skip("actual qualified profile and worker image required")
	}
	if _, err := validateLiveQualification(path, image); err != nil {
		t.Fatal(err)
	}
}

func TestLiveQualificationEvidenceRejectsTampering(t *testing.T) {
	image := "sha256:" + strings.Repeat("b", 64)
	fixture := func(t *testing.T) (string, map[string]any) {
		t.Helper()
		root := t.TempDir()
		os.Chmod(root, 0700)
		profile := map[string]any{"qualified": true, "backing_io_qualified": true, "qualification_image": image}
		for _, entry := range []struct {
			prefix string
			count  int
		}{{"qualification", 201}, {"backing_io_qualification", 23}} {
			checks := []map[string]any{}
			for n := 0; n < entry.count; n++ {
				checks = append(checks, map[string]any{"name": fmt.Sprintf("actual-check-%d", n), "passed": true})
			}
			raw, _ := json.Marshal(map[string]any{"qualified": true, "checks": checks, "image": map[string]any{"id": image}})
			path := filepath.Join(root, entry.prefix+".json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			profile[entry.prefix+"_path"] = path
			profile[entry.prefix+"_sha256"] = sum(raw)
			profile[entry.prefix+"_checks"] = entry.count
		}
		return filepath.Join(root, "profile.json"), profile
	}
	for _, name := range []string{"valid", "changed-bytes", "failed-check", "duplicate-check", "wrong-image", "report-wrong-image", "missing-report"} {
		t.Run(name, func(t *testing.T) {
			path, profile := fixture(t)
			switch name {
			case "changed-bytes":
				os.WriteFile(profile["qualification_path"].(string), []byte("{}"), 0600)
			case "failed-check", "duplicate-check", "report-wrong-image":
				reportPath := profile["qualification_path"].(string)
				raw, _ := os.ReadFile(reportPath)
				var report map[string]any
				json.Unmarshal(raw, &report)
				checks := report["checks"].([]any)
				if name == "report-wrong-image" {
					report["image"] = map[string]any{"id": "sha256:" + strings.Repeat("d", 64)}
				} else if name == "failed-check" {
					checks[0].(map[string]any)["passed"] = false
				} else {
					checks[1].(map[string]any)["name"] = checks[0].(map[string]any)["name"]
				}
				raw, _ = json.Marshal(report)
				os.WriteFile(reportPath, raw, 0600)
				profile["qualification_sha256"] = sum(raw)
			case "wrong-image":
				profile["qualification_image"] = "sha256:" + strings.Repeat("c", 64)
			case "missing-report":
				delete(profile, "qualification_path")
			}
			raw, _ := json.Marshal(profile)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := validateLiveQualification(path, image)
			if (err == nil) != (name == "valid") {
				t.Fatalf("evidence validation err=%v", err)
			}
		})
	}
}

// cleanupLiveFixture is restart-safe: released old epochs remain fenced while
// their opaque retention can still be purged under the component resource guard.
func cleanupLiveFixture(ctx context.Context, e *LinuxExecutor, agent *NodeAgent, dirs *resources.OwnedDirectories, ids []ExecutionIdentity, specs map[string]ExecutionSpec, digests map[string]string) error {
	inventory, err := agent.Inventory(ctx)
	if err != nil {
		return err
	}
	released := map[string]bool{}
	for _, row := range inventory {
		key, _ := row["execution_key"].(string)
		released[key] = row["state"] == "RELEASED"
	}
	for _, id := range ids {
		if _, ok := specs[id.Key()]; !ok || released[id.Key()] {
			continue
		}
		if _, err := agent.Stop(ctx, id, 1); err != nil {
			return err
		}
		if _, err := agent.Collect(ctx, id); err != nil {
			return err
		}
		ok, err := agent.Release(ctx, id)
		if err != nil || !ok {
			return fmt.Errorf("release %s: %v/%v", id.Key(), ok, err)
		}
	}
	done := map[string]bool{}
	for _, first := range ids {
		if done[first.JobID] || digests[first.JobID] == "" {
			continue
		}
		done[first.JobID] = true
		if err := agent.WithComponentGuardContext(ctx, first, true, func(guarded context.Context) error {
			if err := dirs.Purge(first.JobID, digests[first.JobID]); err != nil {
				return err
			}
			for _, id := range ids {
				if id.JobID != first.JobID {
					continue
				}
				if _, ok := specs[id.Key()]; !ok {
					continue
				}
				ok, err := agent.PurgeWithAuxiliary(guarded, id, true)
				if err != nil || !ok {
					return fmt.Errorf("purge %s: %v/%v", id.Key(), ok, err)
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	for _, id := range ids {
		if _, ok := specs[id.Key()]; !ok {
			continue
		}
		record, err := e.load(id)
		if err != nil {
			return err
		}
		if err = e.reconcileVolume(ctx, id, record); err != nil {
			return err
		}
		if record.State != "RELEASED" || !record.DiskDeleted || record.Mounted || record.LoopDevice != "" || len(record.OwnedLoopDevices) != 0 {
			return fmt.Errorf("physical resources remain for %s", id.Key())
		}
		if _, err = os.Lstat(filepath.Join(e.directory(id), "state.ext4")); !os.IsNotExist(err) {
			return fmt.Errorf("scratch file remains for %s", id.Key())
		}
		result, err := e.docker(ctx, []string{"inspect", "--type", "container", record.Container}, false, true)
		if err != nil || result.ExitCode != 1 || (!strings.Contains(result.Stderr, "No such object: "+record.Container) && !strings.Contains(result.Stderr, "No such container: "+record.Container)) {
			return fmt.Errorf("container absence unconfirmed for %s: %v", id.Key(), err)
		}
	}
	used, err := agent.StorageUsageBytes(ctx)
	if err != nil || used != 0 {
		return fmt.Errorf("nonzero final accounting %d: %v", used, err)
	}
	return nil
}

// TestQualifiedCPURecovery explicitly resumes cleanup for a failed invocation of
// this fixture only. It preserves the original report and uses the durable
// ledger plus immutable execution receipts rather than reconstructing effects.
func TestQualifiedCPURecovery(t *testing.T) {
	root := os.Getenv("HF2L_TEST_RECOVER_EXECUTOR_ROOT")
	profile := os.Getenv("HF2L_TEST_QUALIFIED_PROFILE")
	if root == "" || profile == "" {
		t.Skip("explicit failed fixture root required")
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(root, "report.json"))
	must(err)
	var report map[string]any
	must(json.Unmarshal(raw, &report))
	if report["root"] != root || !strings.HasPrefix(fmt.Sprint(report["scope"]), "real Go NodeAgent build application,") {
		t.Fatal("root is not this owned integration fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	e, err := NewLinuxExecutor(profile, filepath.Join(root, "executions"))
	must(err)
	agent, err := NewNodeAgent(e, filepath.Join(root, "node.sqlite"), "integration-node", "integration-cpu", ResourceLimits{CPUMillis: 2000, MemoryBytes: 2 << 30, DiskBytes: 1 << 30})
	must(err)
	defer agent.Close()
	dirs, err := resources.NewOwnedDirectories(filepath.Join(root, "jobs"))
	must(err)
	defer dirs.Close()
	inventory, err := agent.Inventory(ctx)
	must(err)
	ids := []ExecutionIdentity{}
	specs := map[string]ExecutionSpec{}
	digests := map[string]string{}
	for _, row := range inventory {
		id := ExecutionIdentity{JobID: row["job_id"].(string), AttemptID: row["attempt_id"].(string), ComponentID: row["component_id"].(string), Epoch: row["epoch"].(int64)}
		if !strings.HasPrefix(id.JobID, "integration-") || id.ComponentID != "build" {
			t.Fatal("foreign ledger assignment")
		}
		record, err := e.load(id)
		must(err)
		ids = append(ids, id)
		specs[id.Key()] = record.Spec
		if digests[id.JobID] == "" {
			path, err := dirs.ValidateJob(id.JobID)
			must(err)
			raw, err := os.ReadFile(filepath.Join(path, ".owner.json"))
			must(err)
			var owner map[string]any
			must(json.Unmarshal(raw, &owner))
			digests[id.JobID] = owner["spec_digest"].(string)
		}
	}
	must(cleanupLiveFixture(ctx, e, agent, dirs, ids, specs, digests))
	raw, err = json.MarshalIndent(map[string]any{"passed": true, "physical_cleanup_confirmed": true, "final_storage_bytes": 0, "recovered_execution_count": len(ids), "completed_at": time.Now().UTC()}, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(root, "recovery.json"), append(raw, '\n'), 0600))
}

const liveBuildBackend = `
import json,time,zipfile
from pathlib import Path
import numpy as np

def get_requires_for_build_wheel(config_settings=None):
    return []

def build_wheel(wheel_directory,config_settings=None,metadata_directory=None):
    state=Path("/job/state"); proof=state/"numpy-proof.json"; retry=proof.exists()
    x=np.array([-2.,-1.,0.,1.,2.]); y=3*x+1
    w=np.array([0.,0.])
    def loss(): return float(np.mean((w[0]*x+w[1]-y)**2))
    initial=loss()
    for _ in range(128):
        error=w[0]*x+w[1]-y
        w-=0.1*np.array([2*np.mean(error*x),2*np.mean(error)])
    final=loss()
    if not final < 1e-6: raise RuntimeError("tiny numeric training did not converge")
    proof.write_text(json.dumps({"initial_loss":initial,"final_loss":final,"updates":128}))
    print("NUMPY_PROOF_READY",flush=True)
    if not retry:
        while True: time.sleep(.1)
    name="integration_probe-0.0.0-py3-none-any.whl"
    with zipfile.ZipFile(Path(wheel_directory)/name,"w") as z:
        z.writestr("integration_probe.py","VALUE = 1\n")
        z.writestr("integration_probe-0.0.0.dist-info/METADATA","Metadata-Version: 2.1\nName: integration-probe\nVersion: 0.0.0\n")
        z.writestr("integration_probe-0.0.0.dist-info/WHEEL","Wheel-Version: 1.0\nGenerator: integration\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        z.writestr("integration_probe-0.0.0.dist-info/RECORD","")
    return name
`
