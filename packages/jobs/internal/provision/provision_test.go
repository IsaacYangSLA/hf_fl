package provision

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/resources"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

type fakeExchange struct {
	mu                                       sync.Mutex
	job, issuer                              string
	creates, retires, revokes                int
	lostCreate, foreignGrant, cleanupPending bool
	quota, principalQuota                    any
	createKeys                               map[string]bool
	round                                    *int64
}

func (f *fakeExchange) CreateSpace(ctx context.Context, name, profile, key string, options map[string]any) (map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createKeys == nil {
		f.createKeys = map[string]bool{}
	}
	if !f.createKeys[key] {
		f.creates++
		f.createKeys[key] = true
	}
	f.quota, f.principalQuota = options["quota_bytes"], options["principal_quota_bytes"]
	if f.lostCreate {
		f.lostCreate = false
		return nil, domain.Err(503, "lost_create_ack")
	}
	return map[string]any{"id": "space-owned"}, nil
}
func (f *fakeExchange) GetSpace(context.Context, string) (map[string]any, error) {
	return map[string]any{"id": "space-owned", "quota_bytes": f.quota, "principal_quota_bytes": f.principalQuota}, nil
}
func (f *fakeExchange) Request(ctx context.Context, method, path string, body any, headers map[string]string, query url.Values) (map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b := obj(body)
	switch {
	case strings.HasSuffix(path, "/managed") && method == "PUT":
		return map[string]any{"space_id": "space-owned", "job_id": f.job}, nil
	case strings.HasSuffix(path, "/managed") && method == "GET":
		return map[string]any{"space_id": "space-owned", "job_id": f.job, "status": "retired", "cleanup_pending": f.cleanupPending}, nil
	case strings.HasSuffix(path, "/managed/retire"):
		f.retires++
		return map[string]any{"space_id": "space-owned", "job_id": f.job}, nil
	case strings.Contains(path, "/types/") && strings.HasSuffix(path, "/revisions"):
		return map[string]any{"id": "type-revision"}, nil
	case strings.Contains(path, "/members/"):
		return map[string]any{"principal_id": filepath.Base(path)}, nil
	case strings.HasSuffix(path, "/workload-grants/revoke"):
		f.revokes++
		return map[string]any{"attempt_id": b["attempt_id"], "revoked_at": "2026-10-23T12:00:00Z"}, nil
	case strings.HasSuffix(path, "/workload-grants") && method == "POST":
		principal := domain.PrincipalID(f.issuer, str(b["subject"]))
		if f.foreignGrant {
			principal = "foreign"
		}
		result := map[string]any{"grant_id": "grant-" + str(b["component_id"]), "space_id": "space-owned", "principal_id": principal}
		for k, v := range b {
			result[k] = v
		}
		return result, nil
	case strings.HasSuffix(path, "/refs/main"):
		if f.round == nil {
			return nil, domain.Err(404, "reference_not_found")
		}
		return map[string]any{"record_id": "global"}, nil
	case strings.HasSuffix(path, "/records/global"):
		return map[string]any{"metadata": map[string]any{"hf2l_files": map[string]any{"fedavg_round.json": map[string]any{"round": *f.round}}}}, nil
	}
	return nil, domain.Err(404, "unexpected_fixture_request")
}
func git(t *testing.T, root string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0")
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("git fixture: %v %s", e, out)
	}
	return strings.TrimSpace(string(out))
}

type harness struct {
	p            *Provisioner
	db           *store.DB
	job, attempt map[string]any
	spec         domain.JobSpec
	exchange     *fakeExchange
	root         string
}

func setup(t *testing.T) *harness { return setupOptions(t, false) }
func setupOptions(t *testing.T, withBuild bool) *harness {
	t.Helper()
	ctx := context.Background()
	tmp := t.TempDir()
	if e := os.Chmod(tmp, 0700); e != nil {
		t.Fatal(e)
	}
	repo := filepath.Join(tmp, "source-repo")
	if e := os.Mkdir(repo, 0700); e != nil {
		t.Fatal(e)
	}
	git(t, repo, "init", "-q")
	if e := os.WriteFile(filepath.Join(repo, "plugin.py"), []byte("VALUE = 7\n"), 0600); e != nil {
		t.Fatal(e)
	}
	git(t, repo, "add", ".")
	git(t, repo, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "approved")
	commit := git(t, repo, "rev-parse", "HEAD")
	db, e := store.Open(ctx, "sqlite:///:memory:")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if _, e = db.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	specJSON := fmt.Sprintf(`{"project_id":"research","name":"Test federation","source_id":"approved","source_commit":%q,"runtime_image":"sha256:%s","plugin":"lenet","options":{},"secret_refs":{},"participants":[{"participant_id":"alice","dataset_binding":"alice-data"},{"participant_id":"bob","dataset_binding":"bob-data"}],"components":[{"component_id":"owner","role":"owner","resources":{"pool_id":"cpu","cpu_millicores":1000,"memory_bytes":1048576,"disk_bytes":1048576}}],"target_round":2,"max_duration_seconds":3600}`, commit, strings.Repeat("a", 64))
	spec, e := domain.DecodeJobSpec([]byte(specJSON))
	if e != nil {
		t.Fatal(e)
	}
	if withBuild {
		component := spec.Components[0]
		component.ComponentID = "builder"
		component.Role = "build"
		spec.Components = append(spec.Components, component)
	}
	now := time.Now().UTC()
	deadline := now.Add(time.Hour)
	job := map[string]any{"id": "job-one", "project_id": "research", "creator_id": "human", "name": spec.Name, "spec_json": spec.Map(), "spec_hash": mustDigest(spec), "state": "PROVISIONING", "current_attempt": int64(1), "attempt_count": int64(1), "epoch": int64(1), "target_round": int64(2), "deadline_at": deadline}
	attempt := map[string]any{"id": "attempt-one", "job_id": "job-one", "number": int64(1), "epoch": int64(1), "state": "RESERVED", "created_at": now}
	e = db.WithTx(ctx, true, func(tx *store.Tx) error {
		if e := tx.Insert(ctx, "jm_projects", map[string]any{"id": "research", "name": "Research", "quotas_json": map[string]any{"retained_bytes": int64(1 << 30), "disk_bytes": int64(1 << 30)}}); e != nil {
			return e
		}
		for _, pool := range []string{"cpu", "storage", "objects"} {
			d := map[string]any{}
			cpu := int64(0)
			memory := int64(0)
			if pool == "objects" {
				d["object_store"] = true
			}
			if pool == "cpu" {
				cpu = 4000
				memory = 1 << 30
			}
			if e := tx.Insert(ctx, "jm_pools", map[string]any{"id": pool, "name": pool, "node_id": "node", "cpu_millicores": cpu, "memory_bytes": memory, "disk_bytes": int64(1 << 30), "healthy": true, "details_json": d, "sandbox_profiles": []string{"runsc-cpu-v1"}}); e != nil {
				return e
			}
		}
		if e := tx.Insert(ctx, "jm_approved_sources", map[string]any{"id": "approved", "project_id": "research", "url": "", "allowed_commits": []string{commit}, "details_json": map[string]any{"mirror_path": repo, "max_bytes": int64(1 << 20), "max_files": int64(100), "max_git_bytes": int64(1 << 20), "max_git_files": int64(100)}}); e != nil {
			return e
		}
		if e := tx.Insert(ctx, "jm_runtime_images", map[string]any{"id": "image", "project_id": "research", "digest": spec.RuntimeImage}); e != nil {
			return e
		}
		for _, who := range []string{"alice", "bob"} {
			if e := tx.Insert(ctx, "jm_participant_bindings", map[string]any{"id": who + "-data", "project_id": "research", "participant_id": who, "node_id": "node-" + who, "dataset_label": "Private local dataset"}); e != nil {
				return e
			}
		}
		if e := tx.Insert(ctx, "jm_jobs", job); e != nil {
			return e
		}
		if e := tx.Insert(ctx, "jm_attempts", attempt); e != nil {
			return e
		}
		for _, component := range spec.Components {
			id := "allocation"
			if component.ComponentID != "owner" {
				id += "-" + component.ComponentID
			}
			if e := tx.Insert(ctx, "jm_allocations", map[string]any{"id": id, "job_id": job["id"], "attempt_id": attempt["id"], "component_id": component.ComponentID, "pool_id": "cpu", "cpu_millicores": int64(1000), "memory_bytes": int64(1 << 20), "disk_bytes": int64(1 << 20), "epoch": int64(1)}); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(tmp, "jobs")
	if e = os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	exchange := &fakeExchange{job: "job-one", issuer: "https://workloads.example.invalid"}
	config := Config{DB: db, Exchange: exchange, Root: root, WorkloadIssuer: exchange.issuer, StoragePoolID: "storage", ExchangeStoragePoolID: "objects",
		ExecutionBindings: func(ctx context.Context, job, attempt map[string]any, c domain.ComponentSpec, space, principal string) (map[string]any, error) {
			id := executor.ExecutionIdentity{JobID: idOf(job), AttemptID: idOf(attempt), ComponentID: c.ComponentID, Epoch: num(attempt["epoch"])}
			return map[string]any{"proxy_endpoint": filepath.Join(root, id.JobID, "attempts", id.AttemptID, id.ComponentID, "proxy.sock"), "certificate_thumbprint": strings.Repeat("a", 43)}, nil
		},
		ProxyStopper: func(context.Context, executor.ExecutionIdentity, bool) (bool, error) { return true, nil }, ArtifactFenceRevoker: func(context.Context, string) (bool, error) { return true, nil }, ProxyRestorer: func(context.Context, map[string]any, map[string]any) (bool, error) { return true, nil },
	}
	if withBuild {
		config.BuildApprovals = map[string]map[string]any{"builder": {"approved_dependencies": map[string]string{"build": "1.2.2"}}}
	}
	p, e := New(config)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(tmp, func(path string, d os.DirEntry, e error) error {
			if e == nil && d.IsDir() {
				_ = os.Chmod(path, 0700)
			}
			return nil
		})
	})
	return &harness{p, db, job, attempt, spec, exchange, root}
}
func (h *harness) reserve(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	plans, e := h.p.AdmissionStorage(ctx, h.job)
	if e != nil {
		t.Fatal(e)
	}
	for _, plan := range plans {
		rid, e := h.p.Ledger.Own(ctx, resources.Ownership{JobID: idOf(h.job), AttemptID: idOf(h.attempt), ComponentID: str(plan["component_id"]), Kind: str(plan["kind"]), ExternalID: str(plan["external_id"]), Retained: true, Details: obj(plan["details"])})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = h.p.Retention.ReserveResource(ctx, rid, idOf(h.job), num(plan["max_bytes"])); e != nil {
			t.Fatalf("reserve %s: %v", plan["kind"], e)
		}
	}
}
func TestPlanHasNoEffectsAndRejectsChangedIdentity(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	specs, e := h.p.Plan(ctx, h.job, h.attempt, 2)
	if e != nil {
		t.Fatal(e)
	}
	if len(specs) != 1 || specs["owner"].ProxyEndpoint == "" {
		t.Fatal("missing bound execution")
	}
	rows, e := h.db.All(ctx, "SELECT * FROM jm_provisioning_resources")
	if e != nil || len(rows) != 0 {
		t.Fatal("planning created resources", e)
	}
	if _, e = os.Stat(filepath.Join(h.root, "job-one")); !os.IsNotExist(e) {
		t.Fatal("planning created directory")
	}
	if h.exchange.creates != 0 {
		t.Fatal("planning contacted Exchange")
	}
	bad := map[string]any{}
	for k, v := range h.attempt {
		bad[k] = v
	}
	bad["job_id"] = "foreign"
	if _, e = h.p.Plan(ctx, h.job, bad, 2); e == nil {
		t.Fatal("foreign attempt accepted")
	}
	old := h.job["spec_hash"]
	h.job["spec_hash"] = strings.Repeat("0", 64)
	if _, e = h.p.Plan(ctx, h.job, h.attempt, 2); e == nil {
		t.Fatal("changed specification accepted")
	}
	h.job["spec_hash"] = old
}
func TestTransactionalStoragePlannerUsesExistingTransaction(t *testing.T) {
	h := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	e := h.db.WithTx(ctx, true, func(tx *store.Tx) error {
		plans, e := h.p.AdmissionStorageTx(ctx, tx, h.job)
		if e != nil {
			return e
		}
		if len(plans) < 8 {
			return fmt.Errorf("incomplete physical-copy budgets")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
func TestEnsureRequiresPrepaidBudgetBeforeAnyFilesystemEffect(t *testing.T) {
	h := setup(t)
	if e := h.p.Ensure(context.Background(), h.job, h.attempt, 2); e == nil {
		t.Fatal("unpaid namespace accepted")
	}
	if h.exchange.creates != 0 {
		t.Fatal("Exchange reached before payment")
	}
	if _, e := os.Stat(filepath.Join(h.root, "job-one")); !os.IsNotExist(e) {
		t.Fatal("created unpaid files")
	}
}
func TestEnsureReplaysOwnedSnapshotAndNamespaceAfterLostAck(t *testing.T) {
	h := setup(t)
	h.reserve(t)
	ctx := context.Background()
	h.exchange.lostCreate = true
	if e := h.p.Ensure(ctx, h.job, h.attempt, 2); e == nil {
		t.Fatal("lost namespace acknowledgement ignored")
	}
	if e := h.p.Ensure(ctx, h.job, h.attempt, 2); e != nil {
		t.Fatal(e)
	}
	if e := h.p.Ensure(ctx, h.job, h.attempt, 2); e != nil {
		t.Fatal("idempotent replay:", e)
	}
	if h.exchange.creates != 1 {
		t.Fatalf("namespace duplicated: %d", h.exchange.creates)
	}
	cfg, e := h.p.PreparedComponent(ctx, h.job, h.attempt, "owner")
	if e != nil {
		t.Fatal(e)
	}
	if cfg["spec_digest"] != mustDigest(h.spec) || len(obj(cfg["participant_principals"])) != 2 {
		t.Fatal("wrong runtime contract")
	}
	bytes, e := domain.CanonicalJSON(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(bytes), h.root) {
		t.Fatal("manager host path in sandbox config")
	}
	files, e := h.db.All(ctx, "SELECT * FROM jm_artifacts WHERE kind = ?", "source")
	if e != nil || len(files) != 1 || files[0]["name"] != "plugin.py" {
		t.Fatal("source artifacts missing", e, files)
	}
	root := filepath.Join(h.root, "job-one", "source")
	if e = os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(root, "plugin.py")
	if e = os.Chmod(file, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(file, []byte("TAMPERED"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = h.p.Ensure(ctx, h.job, h.attempt, 2); e == nil {
		t.Fatal("replayed source hash was not rechecked")
	}
}
func TestEnsureRejectsForeignGrantBeforeConfigPublication(t *testing.T) {
	h := setup(t)
	h.reserve(t)
	h.exchange.foreignGrant = true
	if e := h.p.Ensure(context.Background(), h.job, h.attempt, 2); e == nil {
		t.Fatal("foreign grant accepted")
	}
	if _, e := os.Stat(filepath.Join(h.root, "job-one", "attempts", "attempt-one", "owner", "runtime.json")); !os.IsNotExist(e) {
		t.Fatal("published config with foreign grant")
	}
}
func TestCurrentRoundAndPublicationUncertainty(t *testing.T) {
	h := setup(t)
	h.reserve(t)
	ctx := context.Background()
	if e := h.p.Ensure(ctx, h.job, h.attempt, 2); e != nil {
		t.Fatal(e)
	}
	n, e := h.p.CurrentRound(ctx, h.job)
	if e != nil || n != 0 {
		t.Fatal(n, e)
	}
	round := int64(2)
	h.exchange.round = &round
	n, e = h.p.CurrentRound(ctx, h.job)
	if e != nil || n != 2 {
		t.Fatal(n, e)
	}
	observed, e := h.p.Reconcile(ctx, h.job, h.attempt)
	if e != nil || observed.Known || observed.Status != "unknown" {
		t.Fatal("absence was guessed", observed, e)
	}
}
func TestCleanupRequiresTerminationAndPurgeRetainsUnconfirmedBytes(t *testing.T) {
	h := setup(t)
	h.reserve(t)
	ctx := context.Background()
	if e := h.p.Ensure(ctx, h.job, h.attempt, 2); e != nil {
		t.Fatal(e)
	}
	if ok, e := h.p.Cleanup(ctx, h.job, h.attempt); e != nil || ok {
		t.Fatal("unconfirmed execution cleaned", ok, e)
	}
	h.attempt["termination_confirmed"] = true
	if ok, e := h.p.Cleanup(ctx, h.job, h.attempt); e != nil || !ok {
		t.Fatal(ok, e)
	}
	if _, e := os.Stat(filepath.Join(h.root, "job-one", "attempts", "attempt-one", "owner", "runtime.json")); !os.IsNotExist(e) {
		t.Fatal("private config remains")
	}
	if _, e := h.p.PurgeJob(ctx, h.job); e == nil {
		t.Fatal("active job purged")
	}
	h.job["state"] = "SUCCEEDED"
	e := h.db.WithTx(ctx, true, func(tx *store.Tx) error {
		if e := tx.Update(ctx, "jm_jobs", map[string]any{"id": idOf(h.job)}, map[string]any{"state": "SUCCEEDED"}); e != nil {
			return e
		}
		return tx.Update(ctx, "jm_allocations", map[string]any{"id": "allocation"}, map[string]any{"state": "RELEASED", "released_at": time.Now().UTC(), "termination_confirmed": true})
	})
	if e != nil {
		t.Fatal(e)
	}
	h.exchange.cleanupPending = true
	if ok, e := h.p.PurgeJob(ctx, h.job); e != nil || ok {
		t.Fatal("pending object cleanup released job", ok, e)
	}
	if _, e := os.Stat(filepath.Join(h.root, "job-one", "source")); e != nil {
		t.Fatal("source deleted before authoritative retirement", e)
	}
	h.exchange.cleanupPending = false
	if ok, e := h.p.PurgeJob(ctx, h.job); e != nil || !ok {
		t.Fatal("purge failed", ok, e)
	}
	if _, e := os.Stat(filepath.Join(h.root, "job-one")); !os.IsNotExist(e) {
		t.Fatal("owned directory remains", e)
	}
	rows, e := h.p.Ledger.Resources(ctx, idOf(h.job), resources.ResourceFilter{Kind: "exchange_space"})
	if e != nil || len(rows) != 1 || rows[0]["state"] != "retired" {
		t.Fatal("namespace provenance lost", e, rows)
	}
}
func TestRuntimeConfigRejectsUnfencedOrCrossJobDirectives(t *testing.T) {
	h := setup(t)
	h.reserve(t)
	ctx := context.Background()
	if e := h.p.Ensure(ctx, h.job, h.attempt, 2); e != nil {
		t.Fatal(e)
	}
	good, e := h.p.PreparedComponent(ctx, h.job, h.attempt, "owner")
	if e != nil {
		t.Fatal(e)
	}
	cases := map[string]func(map[string]any){
		"foreign component":  func(c map[string]any) { c["component_id"] = "alice" },
		"overlapping source": func(c map[string]any) { c["state_dir"] = "/job/source/state" },
		"token option": func(c map[string]any) {
			c["secret_option_names"] = []string{"password"}
			c["secret_options_file"] = "/run/hf2l/secrets.json"
		},
		"invalid wheel": func(c map[string]any) {
			c["built_artifacts"] = map[string]any{"../foreign.whl": map[string]any{"sha256": strings.Repeat("a", 64), "size_bytes": int64(1)}}
		},
		"unfenced recovery": func(c map[string]any) {
			c["reconciliation"] = []any{map[string]any{"role": "owner", "action": "confirmed", "intent_sha256": strings.Repeat("a", 64), "old_attempt_id": "old", "old_epoch": int64(0), "grants_revoked": false, "termination_confirmed": true}}
		},
		"unknown field": func(c map[string]any) { c["host_path"] = "/etc/passwd" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b, e := domain.CanonicalJSON(good)
			if e != nil {
				t.Fatal(e)
			}
			copy, e := decodeMap(b)
			if e != nil {
				t.Fatal(e)
			}
			mutate(copy)
			if e = ValidateRuntimeConfig(copy); e == nil {
				t.Fatal("invalid runtime accepted")
			}
		})
	}
}
