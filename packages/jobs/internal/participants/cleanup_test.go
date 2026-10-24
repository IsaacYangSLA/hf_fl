package participants

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

type cleanupFixture struct {
	t      *testing.T
	ctx    context.Context
	db     *store.DB
	s      *Service
	c      *ExternalCleanup
	a      Actor
	spec   domain.JobSpec
	digest string
	now    time.Time
}

func newCleanupFixture(t *testing.T) *cleanupFixture {
	t.Helper()
	ctx := context.Background()
	db, e := store.Open(ctx, "sqlite:///"+filepath.Join(t.TempDir(), "cleanup.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if _, e = db.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	spec := domain.JobSpec{ProjectID: "project", Name: "cleanup", SourceID: "source", SourceCommit: strings.Repeat("a", 40), RuntimeImage: "runtime", Plugin: "plugin", Options: map[string]any{}, SecretRefs: map[string]string{}, Participants: []domain.ParticipantSpec{{ParticipantID: "alice", DatasetBinding: "data", Mode: "external"}}, Components: []domain.ComponentSpec{{ComponentID: "owner", Role: "owner", Resources: domain.ResourceRequest{PoolID: "cpu", CPUMillicores: 1, MemoryBytes: 1, DiskBytes: 1, SandboxProfile: "runsc-cpu-v1"}}}, TargetRound: 1, MaxDurationSeconds: 100}
	digest, e := spec.Digest()
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	a := Actor{NodeID: "node", PoolID: "external", JobID: "job", AttemptID: "attempt", ComponentID: domain.ExternalComponentID("alice"), GrantID: "execution", Epoch: 1, CertificateThumbprint: "pinned", Scopes: []string{"purge"}}
	s := &Service{DB: db, Clock: func() time.Time { return now }, Nodes: map[string]ApprovedNode{"node": {NodeID: "node", CertificateThumbprint: "pinned"}}}
	f := &cleanupFixture{t, ctx, db, s, NewExternalCleanup(s), a, spec, digest, now}
	e = db.WithTx(ctx, true, func(tx *store.Tx) error {
		if e := tx.Insert(ctx, "jm_projects", map[string]any{"id": "project", "name": "Project", "retained_bytes": int64(1024)}); e != nil {
			return e
		}
		if e := tx.Insert(ctx, "jm_jobs", map[string]any{"id": "job", "project_id": "project", "creator_id": "alice", "name": "cleanup", "spec_json": spec, "spec_hash": digest, "target_round": int64(1), "state": "FAILED", "cleanup_status": "purge_pending"}); e != nil {
			return e
		}
		if e := tx.Insert(ctx, "jm_attempts", map[string]any{"id": "attempt", "job_id": "job", "number": int64(1), "epoch": int64(1), "state": "FAILED", "revocation_confirmed": true, "termination_confirmed": true}); e != nil {
			return e
		}
		for _, kind := range []string{"external_execution", "external_enrollment", "external_execution_certificate", "log_budget"} {
			id := kind
			if kind == "external_execution" {
				id = "execution"
			}
			if e := tx.Insert(ctx, "jm_provisioning_resources", map[string]any{"id": id, "job_id": "job", "attempt_id": "attempt", "component_id": a.ComponentID, "kind": kind, "ownership_json": map[string]any{"job_id": "job", "attempt_id": "attempt", "component_id": a.ComponentID}, "details_json": map[string]any{"participant_id": "alice", "node_id": "node", "node_certificate_thumbprint": "pinned", "epoch": int64(1), "spec_digest": digest, "termination_confirmed": true, "source_manifest": map[string]string{"plugin.py": strings.Repeat("a", 64)}}, "state": "ready", "retained": true, "size_bytes": int64(1024)}); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *cleanupFixture) update(table, id string, values map[string]any) {
	f.t.Helper()
	if e := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error { return tx.Update(f.ctx, table, map[string]any{"id": id}, values) }); e != nil {
		f.t.Fatal(e)
	}
}
func (f *cleanupFixture) row(table, id string) map[string]any {
	f.t.Helper()
	r, e := f.db.One(f.ctx, "SELECT * FROM "+table+" WHERE id = ?", id)
	if e != nil {
		f.t.Fatal(e)
	}
	return r
}
func cleanupWantCode(t *testing.T, e error, code string) {
	t.Helper()
	var d *domain.Error
	if !errors.As(e, &d) || d.Code != code {
		t.Fatalf("want %s, got %v", code, e)
	}
}
func TestCleanupHistoricalReceiptsPreserveOtherRetention(t *testing.T) {
	f := newCleanupFixture(t)
	requests := 0
	f.s.Hooks.IssueNode = func(ctx context.Context, r NodeGrant) (string, error) {
		if !cleanupEqual(r.Scopes, []string{"purge"}) || r.GrantID != "execution" {
			t.Fatalf("wrong historical grant: %+v", r)
		}
		return "token", nil
	}
	f.s.Dispatch = func(ctx context.Context, node string, doc map[string]any) (map[string]any, error) {
		requests++
		if doc["operation"] != "purge" || node != "node" {
			t.Fatal(doc)
		}
		plan, e := f.c.PurgePlan(ctx, f.a)
		if e != nil {
			t.Fatal(e)
		}
		if !cleanupTrue(plan["preserve_dataset_inputs"]) || plan["participant_id"] != "alice" {
			t.Fatal(plan)
		}
		return f.c.ConfirmPurged(ctx, f.a, true)
	}
	done, e := f.c.PurgeJob(f.ctx, "job")
	if e != nil || !done {
		t.Fatalf("purge: %v %v", done, e)
	}
	if requests != 1 {
		t.Fatal(requests)
	}
	for _, id := range []string{"execution", "external_enrollment", "external_execution_certificate"} {
		r := f.row("jm_provisioning_resources", id)
		if r["state"] != "deleted" || r["deleted_at"] == nil || cleanupTrue(r["retained"]) {
			t.Fatal(r)
		}
	}
	if f.row("jm_provisioning_resources", "log_budget")["deleted_at"] != nil {
		t.Fatal("log retention prematurely released")
	}
	if number(f.row("jm_projects", "project")["retained_bytes"]) != 1024 {
		t.Fatal("project charge changed")
	}
	done, e = f.c.PurgeJob(f.ctx, "job")
	if e != nil || !done || requests != 1 {
		t.Fatalf("replay: %v %v calls=%d", done, e, requests)
	}
	events, e := f.db.All(f.ctx, "SELECT * FROM jm_events WHERE job_id = ?", "job")
	if e != nil || len(events) != 1 {
		t.Fatalf("duplicate receipt audit: %v %v", events, e)
	}
}
func TestCleanupAuthorizationFences(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		mutate     func(*cleanupFixture)
	}{
		{"retention", "participant_purge_not_authorized", func(f *cleanupFixture) { f.update("jm_jobs", "job", map[string]any{"cleanup_status": "none"}) }},
		{"running", "participant_purge_not_authorized", func(f *cleanupFixture) { f.update("jm_jobs", "job", map[string]any{"state": "RUNNING"}) }},
		{"revocation", "participant_purge_termination_unconfirmed", func(f *cleanupFixture) {
			f.update("jm_attempts", "attempt", map[string]any{"revocation_confirmed": false})
		}},
		{"termination", "participant_purge_termination_unconfirmed", func(f *cleanupFixture) {
			f.update("jm_attempts", "attempt", map[string]any{"termination_confirmed": false})
		}},
		{"historical execution", "participant_purge_termination_unconfirmed", func(f *cleanupFixture) {
			d := cleanupCopy(cleanupObject(f.row("jm_provisioning_resources", "execution")["details_json"]))
			d["termination_confirmed"] = false
			f.update("jm_provisioning_resources", "execution", map[string]any{"details_json": d})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCleanupFixture(t)
			tc.mutate(f)
			_, e := f.c.PurgePlan(f.ctx, f.a)
			cleanupWantCode(t, e, tc.code)
			if f.c.CheckNodeGrant(f.ctx, f.a) {
				t.Fatal("invalid historical grant accepted")
			}
		})
	}
	f := newCleanupFixture(t)
	f.update("jm_jobs", "job", map[string]any{"cleanup_status": "none", "artifacts_expire_at": f.now.Add(-time.Second)})
	if _, e := f.c.PurgePlan(f.ctx, f.a); e != nil {
		t.Fatal(e)
	}
}
func TestCleanupCertificateOwnershipAndScopeFences(t *testing.T) {
	for _, mutate := range []func(*Actor){
		func(a *Actor) { a.Scopes = []string{"purge", "assignment"} }, func(a *Actor) { a.CertificateThumbprint = "other" }, func(a *Actor) { a.NodeID = "other" }, func(a *Actor) { a.Epoch++ }, func(a *Actor) { a.PoolID = "cpu" }, func(a *Actor) { a.ComponentID = "owner" },
	} {
		f := newCleanupFixture(t)
		a := f.a
		mutate(&a)
		if f.c.CheckNodeGrant(f.ctx, a) {
			t.Fatalf("grant accepted: %+v", a)
		}
	}
	f := newCleanupFixture(t)
	_, e := f.c.ConfirmPurged(f.ctx, f.a, false)
	cleanupWantCode(t, e, "participant_purge_confirmation_required")
	f.update("jm_provisioning_resources", "execution", map[string]any{"ownership_json": map[string]any{"job_id": "foreign", "attempt_id": "attempt", "component_id": f.a.ComponentID}})
	_, e = f.c.PurgeJob(f.ctx, "job")
	cleanupWantCode(t, e, "participant_cleanup_ownership_mismatch")
	if f.row("jm_provisioning_resources", "execution")["deleted_at"] != nil {
		t.Fatal("foreign ownership deleted")
	}
}
func TestCleanupOfflineAndUnconfirmedDispatchRetainCharges(t *testing.T) {
	for _, offline := range []bool{false, true} {
		t.Run(map[bool]string{false: "ack missing", true: "offline"}[offline], func(t *testing.T) {
			f := newCleanupFixture(t)
			f.s.Hooks.IssueNode = func(context.Context, NodeGrant) (string, error) { return "token", nil }
			f.s.Dispatch = func(context.Context, string, map[string]any) (map[string]any, error) {
				if offline {
					return nil, errors.New("offline")
				}
				return map[string]any{"accepted": true}, nil
			}
			done, e := f.c.PurgeJob(f.ctx, "job")
			if e != nil || done {
				t.Fatalf("uncertain deletion completed: %v %v", done, e)
			}
			r := f.row("jm_provisioning_resources", "execution")
			if r["deleted_at"] != nil || number(r["size_bytes"]) != 1024 || !truth(r["retained"]) {
				t.Fatal(r)
			}
		})
	}
}
func TestCleanupLiveAllocationAndUnownedEnrollmentBlock(t *testing.T) {
	f := newCleanupFixture(t)
	e := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
		if e := tx.Insert(f.ctx, "jm_pools", map[string]any{"id": "cpu", "name": "CPU", "node_id": "owner", "cpu_millicores": int64(2), "memory_bytes": int64(2), "disk_bytes": int64(2)}); e != nil {
			return e
		}
		return tx.Insert(f.ctx, "jm_allocations", map[string]any{"id": "allocation", "job_id": "job", "attempt_id": "attempt", "component_id": "owner", "pool_id": "cpu", "cpu_millicores": int64(1), "memory_bytes": int64(1), "disk_bytes": int64(1), "epoch": int64(1)})
	})
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.c.PurgePlan(f.ctx, f.a)
	cleanupWantCode(t, e, "participant_purge_termination_unconfirmed")
	f = newCleanupFixture(t)
	f.update("jm_provisioning_resources", "execution", map[string]any{"kind": "orphaned_external_execution"})
	done, e := f.c.PurgeJob(f.ctx, "job")
	if done || e != nil {
		t.Fatalf("pre-ledger cleanup guessed: %v %v", done, e)
	}
}

type fakeCleanupAgent struct {
	all                                  []CleanupAssignment
	root                                 string
	i                                    executor.ExecutionIdentity
	assignment                           *CleanupAssignment
	rows                                 []CleanupReservation
	plan                                 map[string]any
	guarded                              bool
	absent                               bool
	privateOK                            bool
	runtimeOK                            bool
	privateCalls, runtimeCalls, ackCalls int
	loseAck                              bool
	planError                            error
	assignmentRemoved                    bool
}

func (a *fakeCleanupAgent) WithPurgeGuard(ctx context.Context, i executor.ExecutionIdentity, fn func() error) error {
	a.guarded = true
	defer func() { a.guarded = false }()
	return fn()
}
func (a *fakeCleanupAgent) Request(ctx context.Context, i executor.ExecutionIdentity, token, op string, body map[string]any) (map[string]any, error) {
	if !a.guarded {
		return nil, errors.New("unfenced request")
	}
	if op == "purge-plan" {
		return a.plan, a.planError
	}
	a.ackCalls++
	if a.loseAck {
		a.loseAck = false
		return nil, errors.New("lost ack")
	}
	return map[string]any{"confirmed": true}, nil
}
func (a *fakeCleanupAgent) NodeID() string { return "node" }
func (a *fakeCleanupAgent) Inventory(context.Context) ([]CleanupReservation, error) {
	return a.rows, nil
}
func (a *fakeCleanupAgent) ConfirmAbsent(context.Context, executor.ExecutionIdentity) (bool, error) {
	return a.absent, nil
}
func (a *fakeCleanupAgent) Assignment(context.Context, executor.ExecutionIdentity) (*CleanupAssignment, error) {
	return a.assignment, nil
}
func (a *fakeCleanupAgent) AllAssignments(context.Context) ([]CleanupAssignment, error) {
	if a.all != nil {
		return a.all, nil
	}
	if a.assignment != nil {
		return []CleanupAssignment{*a.assignment}, nil
	}
	return nil, nil
}
func (a *fakeCleanupAgent) OwnedRoot() string { return a.root }
func (a *fakeCleanupAgent) PurgePrivate(ctx context.Context, i executor.ExecutionIdentity, assignment *CleanupAssignment) (bool, error) {
	a.privateCalls++
	if assignment != nil {
		if _, e := os.Lstat(assignment.ComponentRoot); !os.IsNotExist(e) {
			return false, errors.New("private purge before owned bytes")
		}
	}
	return a.privateOK, nil
}
func (a *fakeCleanupAgent) PurgeRuntime(ctx context.Context, i executor.ExecutionIdentity, aux bool) (bool, error) {
	a.runtimeCalls++
	if !aux || a.privateCalls < 1 || !a.privateOK {
		return false, errors.New("quota released before private bytes")
	}
	return a.runtimeOK, nil
}
func (a *fakeCleanupAgent) RemoveAssignment(context.Context, executor.ExecutionIdentity) error {
	a.assignment = nil
	a.assignmentRemoved = true
	return nil
}
func newPhysicalCleanupFixture(t *testing.T) (*fakeCleanupAgent, Actor) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "owned")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	i := executor.ExecutionIdentity{JobID: "job", AttemptID: "attempt", ComponentID: "participant", Epoch: 1}
	component := filepath.Join(root, "jobs", i.JobID, "components", i.ComponentID)
	if e := os.MkdirAll(filepath.Join(component, "source", "nested"), 0700); e != nil {
		t.Fatal(e)
	}
	source := []byte("opaque input")
	hash := sha256.Sum256(source)
	manifest := map[string]string{"nested/plugin.py": hex.EncodeToString(hash[:])}
	if e := os.WriteFile(filepath.Join(component, "source", "nested", "plugin.py"), source, 0444); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "jobs", "job", ".owner.json"), []byte(`{"job_id":"job","spec_digest":"digest","schema_version":1}`), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(filepath.Join(component, "state"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(component, "state", "output"), []byte("output"), 0600); e != nil {
		t.Fatal(e)
	}
	a := &fakeCleanupAgent{root: root, i: i, absent: true, privateOK: true, runtimeOK: true, assignment: &CleanupAssignment{Identity: i, NodeID: "node", PoolID: "external", SpecDigest: "digest", ParticipantID: "alice", ComponentRoot: component, SourceRoot: filepath.Join(component, "source"), DiskBytes: 1024}, rows: []CleanupReservation{{Identity: i, State: "RELEASED", Stopped: true}}, plan: map[string]any{"identity": cleanupIdentity(i), "node_id": "node", "pool_id": "external", "spec_digest": "digest", "participant_id": "alice", "source_manifest": manifest, "termination_confirmed": true, "revocation_confirmed": true, "preserve_dataset_inputs": true}}
	actor := Actor{NodeID: "node", PoolID: "external", JobID: i.JobID, AttemptID: i.AttemptID, ComponentID: i.ComponentID, Epoch: i.Epoch, Scopes: []string{"purge"}}
	return a, actor
}
func TestPhysicalCleanupReceiptReplayAndDatasetPreservation(t *testing.T) {
	a, actor := newPhysicalCleanupFixture(t)
	dataset := filepath.Join(t.TempDir(), "dataset")
	if e := os.WriteFile(dataset, []byte("approved dataset"), 0600); e != nil {
		t.Fatal(e)
	}
	a.loseAck = true
	_, e := PurgeAssignment(context.Background(), a, actor, a.i, "token")
	if e == nil {
		t.Fatal("lost ack unexpectedly succeeded")
	}
	if a.runtimeCalls != 1 || a.privateCalls != 1 || !a.assignmentRemoved {
		t.Fatalf("wrong cleanup ordering %+v", a)
	}
	result, e := PurgeAssignment(context.Background(), a, actor, a.i, "token")
	if e != nil || result["state"] != "purged" {
		t.Fatalf("replay failed: %v %v", result, e)
	}
	if a.runtimeCalls != 1 || a.privateCalls != 1 || a.ackCalls != 2 {
		t.Fatal("replayed physical deletion")
	}
	if b, e := os.ReadFile(dataset); e != nil || string(b) != "approved dataset" {
		t.Fatal("dataset changed")
	}
	if _, e := os.Stat(filepath.Join(a.root, "jobs", "job", ".owner.json")); e != nil {
		t.Fatal("audit marker removed")
	}
}
func TestPhysicalCleanupRefusesUnsafeSourceBeforeDeleting(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "modified", "group writable"} {
		t.Run(kind, func(t *testing.T) {
			a, actor := newPhysicalCleanupFixture(t)
			file := filepath.Join(a.assignment.SourceRoot, "nested", "plugin.py")
			switch kind {
			case "symlink":
				if e := os.Remove(file); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink("/etc/passwd", file); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(file, file+".link"); e != nil {
					t.Fatal(e)
				}
			case "modified":
				if e := os.Chmod(file, 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(file, []byte("modified"), 0600); e != nil {
					t.Fatal(e)
				}
			case "group writable":
				if e := os.Chmod(a.assignment.SourceRoot, 0770); e != nil {
					t.Fatal(e)
				}
			}
			_, e := PurgeAssignment(context.Background(), a, actor, a.i, "token")
			if e == nil || a.ackCalls > 0 || a.runtimeCalls > 0 {
				t.Fatalf("unsafe source acknowledged: %v", e)
			}
			if _, e := os.Stat(filepath.Join(a.assignment.ComponentRoot, "state", "output")); e != nil {
				t.Fatal("state deleted before source validation")
			}
		})
	}
}
func TestPhysicalCleanupFencesAndPrivateFailureRetainQuota(t *testing.T) {
	for _, kind := range []string{"offline manager", "new live attempt", "private unconfirmed", "runtime unconfirmed", "foreign assignment", "foreign historical assignment", "foreign source binding", "false revocation"} {
		t.Run(kind, func(t *testing.T) {
			a, actor := newPhysicalCleanupFixture(t)
			switch kind {
			case "offline manager":
				a.planError = errors.New("offline")
			case "new live attempt":
				later := a.i
				later.AttemptID = "later"
				later.Epoch = 2
				a.rows = append(a.rows, CleanupReservation{Identity: later, State: "RUNNING"})
			case "private unconfirmed":
				a.privateOK = false
			case "runtime unconfirmed":
				a.runtimeOK = false
			case "foreign assignment":
				a.assignment.SpecDigest = "foreign"
			case "foreign historical assignment":
				other := *a.assignment
				other.Identity.AttemptID = "older"
				other.SpecDigest = "foreign"
				a.all = []CleanupAssignment{*a.assignment, other}
			case "foreign source binding":
				other := *a.assignment
				other.Identity.AttemptID = "older"
				other.SourceRoot = "/foreign"
				a.all = []CleanupAssignment{*a.assignment, other}
			case "false revocation":
				a.plan["revocation_confirmed"] = false
			}
			_, e := PurgeAssignment(context.Background(), a, actor, a.i, "token")
			if e == nil || a.ackCalls != 0 {
				t.Fatalf("unproven cleanup acknowledged: %v", e)
			}
			if kind != "runtime unconfirmed" && a.runtimeCalls != 0 {
				t.Fatal("disk release reached before full proof")
			}
			if a.assignmentRemoved {
				t.Fatal("assignment receipt removed before disk proof")
			}
		})
	}
}
func TestPhysicalCleanupResumesAfterPrivateFailure(t *testing.T) {
	a, actor := newPhysicalCleanupFixture(t)
	a.privateOK = false
	_, e := PurgeAssignment(context.Background(), a, actor, a.i, "token")
	cleanupWantCode(t, e, "participant_secret_cleanup_unconfirmed")
	a.privateOK = true
	_, e = PurgeAssignment(context.Background(), a, actor, a.i, "token")
	if e != nil {
		t.Fatal(e)
	}
	if a.runtimeCalls != 1 || a.ackCalls != 1 {
		t.Fatal("failed to resume pending tombstone")
	}
}
func TestPhysicalCleanupAbsentAssignmentRequiresNoOrphans(t *testing.T) {
	a, actor := newPhysicalCleanupFixture(t)
	a.assignment = nil
	a.rows = nil
	_, e := PurgeAssignment(context.Background(), a, actor, a.i, "token")
	cleanupWantCode(t, e, "participant_cleanup_ownership_missing")
	if a.ackCalls != 0 {
		t.Fatal("orphaned storage acknowledged")
	}
	// No local assignment was ever delivered: no job directory is created.
	b, actor := newPhysicalCleanupFixture(t)
	component := b.assignment.ComponentRoot
	// Fixture-only removal; the production implementation never calls RemoveAll.
	if e := os.RemoveAll(component); e != nil {
		t.Fatal(e)
	}
	b.assignment = nil
	b.rows = nil
	_, e = PurgeAssignment(context.Background(), b, actor, b.i, "token")
	if e != nil {
		t.Fatal(e)
	}
	if b.runtimeCalls != 0 || b.ackCalls != 1 || b.privateCalls != 1 {
		t.Fatal("unexpected absent cleanup")
	}
}
func TestPhysicalCleanupRejectsForgedOrLinkedReceipt(t *testing.T) {
	for _, linked := range []bool{false, true} {
		a, actor := newPhysicalCleanupFixture(t)
		purges := filepath.Join(a.root, "purges")
		if e := os.Mkdir(purges, 0700); e != nil {
			t.Fatal(e)
		}
		name := filepath.Join(purges, a.i.Key()+".json")
		if linked {
			if e := os.Symlink("/etc/passwd", name); e != nil {
				t.Fatal(e)
			}
		} else {
			b, _ := json.Marshal(map[string]any{"identity": cleanupIdentity(a.i), "node_id": "foreign", "spec_digest": "digest", "participant_id": "alice", "source_manifest": map[string]string{}, "purged": true})
			if e := os.WriteFile(name, b, 0600); e != nil {
				t.Fatal(e)
			}
		}
		_, e := PurgeAssignment(context.Background(), a, actor, a.i, "token")
		if e == nil || a.ackCalls != 0 || a.runtimeCalls != 0 {
			t.Fatal("untrusted receipt accepted")
		}
	}
}

func TestCleanupWaitsForEveryHistoricalAttempt(t *testing.T) {
	f := newCleanupFixture(t)
	e := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
		if e := tx.Insert(f.ctx, "jm_attempts", map[string]any{"id": "attempt-two", "job_id": "job", "number": int64(2), "epoch": int64(2), "state": "FAILED", "revocation_confirmed": true, "termination_confirmed": true}); e != nil {
			return e
		}
		return tx.Insert(f.ctx, "jm_provisioning_resources", map[string]any{"id": "execution-two", "job_id": "job", "attempt_id": "attempt-two", "component_id": f.a.ComponentID, "kind": "external_execution", "ownership_json": map[string]any{"job_id": "job", "attempt_id": "attempt-two", "component_id": f.a.ComponentID}, "details_json": map[string]any{"participant_id": "alice", "node_id": "node", "node_certificate_thumbprint": "pinned", "epoch": int64(2), "spec_digest": f.digest, "termination_confirmed": true}, "state": "ready", "retained": true, "size_bytes": int64(2048)})
	})
	if e != nil {
		t.Fatal(e)
	}
	second := f.a
	second.AttemptID = "attempt-two"
	second.Epoch = 2
	second.GrantID = "execution-two"
	plan, e := f.c.PurgePlan(f.ctx, second)
	if e != nil || plan["source_manifest"] == nil {
		t.Fatalf("historical source fallback failed: %v %v", plan, e)
	}
	f.s.Hooks.IssueNode = func(context.Context, NodeGrant) (string, error) { return "token", nil }
	confirmSecond := false
	calls := map[string]int{}
	f.s.Dispatch = func(ctx context.Context, node string, doc map[string]any) (map[string]any, error) {
		enrollment := cleanupObject(doc["enrollment"])
		id := cleanupString(enrollment["id"])
		calls[id]++
		if id == "execution" {
			return f.c.ConfirmPurged(ctx, f.a, true)
		}
		if confirmSecond {
			return f.c.ConfirmPurged(ctx, second, true)
		}
		return map[string]any{"accepted": true}, nil
	}
	done, e := f.c.PurgeJob(f.ctx, "job")
	if e != nil || done {
		t.Fatalf("incomplete history purge: %v %v", done, e)
	}
	if f.row("jm_provisioning_resources", "execution")["deleted_at"] == nil {
		t.Fatal("first historical acknowledgment not recorded")
	}
	for _, id := range []string{"execution-two", "external_enrollment", "external_execution_certificate"} {
		if f.row("jm_provisioning_resources", id)["deleted_at"] != nil {
			t.Fatalf("%s deleted before all receipts", id)
		}
	}
	confirmSecond = true
	done, e = f.c.PurgeJob(f.ctx, "job")
	if e != nil || !done {
		t.Fatalf("historical retry: %v %v", done, e)
	}
	if calls["execution"] != 1 || calls["execution-two"] != 2 {
		t.Fatal(calls)
	}
}

func TestCleanupSnapshotFallbackUsesSeparateSQLiteTransaction(t *testing.T) {
	f := newCleanupFixture(t)
	data := cleanupCopy(cleanupObject(f.row("jm_provisioning_resources", "execution")["details_json"]))
	delete(data, "source_manifest")
	f.update("jm_provisioning_resources", "execution", map[string]any{"details_json": data})
	called := false
	f.s.Hooks.Snapshot = func(ctx context.Context, job map[string]any, spec domain.JobSpec) (Snapshot, error) {
		called = true
		// SQLite has exactly one SQL connection. This read would time out if the
		// caller retained its authorization transaction while refreshing catalog.
		row, e := f.db.One(ctx, "SELECT id FROM jm_jobs WHERE id = ?", job["id"])
		if e != nil {
			return Snapshot{}, e
		}
		if row == nil {
			return Snapshot{}, errors.New("missing snapshot job")
		}
		return Snapshot{Root: "/pinned/source", Manifest: map[string]string{"plugin.py": strings.Repeat("b", 64)}}, nil
	}
	ctx, cancel := context.WithTimeout(f.ctx, time.Second)
	defer cancel()
	plan, e := f.c.PurgePlan(ctx, f.a)
	if e != nil || !called || ctx.Err() != nil {
		t.Fatalf("snapshot catalog transaction failed: called=%v err=%v deadline=%v", called, e, ctx.Err())
	}
	manifest, e := cleanupManifest(plan["source_manifest"])
	if e != nil || manifest["plugin.py"] != strings.Repeat("b", 64) {
		t.Fatalf("snapshot fallback omitted: %v %v", plan, e)
	}
}
func TestCleanupSnapshotFallbackRevalidatesRevokedAuthorization(t *testing.T) {
	for _, kind := range []string{"purge authorization", "termination proof", "node certificate"} {
		t.Run(kind, func(t *testing.T) {
			f := newCleanupFixture(t)
			data := cleanupCopy(cleanupObject(f.row("jm_provisioning_resources", "execution")["details_json"]))
			delete(data, "source_manifest")
			f.update("jm_provisioning_resources", "execution", map[string]any{"details_json": data})
			f.s.Hooks.Snapshot = func(ctx context.Context, job map[string]any, spec domain.JobSpec) (Snapshot, error) {
				// A real write transaction can revoke proof while snapshot work occurs.
				e := f.db.WithTx(ctx, true, func(tx *store.Tx) error {
					switch kind {
					case "purge authorization":
						return tx.Update(ctx, "jm_jobs", map[string]any{"id": "job"}, map[string]any{"cleanup_status": "none"})
					case "termination proof":
						return tx.Update(ctx, "jm_attempts", map[string]any{"id": "attempt"}, map[string]any{"revocation_confirmed": false})
					case "node certificate":
						changed := cleanupCopy(data)
						changed["node_certificate_thumbprint"] = "rotated"
						return tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": "execution"}, map[string]any{"details_json": changed})
					}
					return nil
				})
				if e != nil {
					return Snapshot{}, e
				}
				return Snapshot{Root: "/pinned/source", Manifest: map[string]string{"plugin.py": strings.Repeat("b", 64)}}, nil
			}
			ctx, cancel := context.WithTimeout(f.ctx, time.Second)
			defer cancel()
			plan, e := f.c.PurgePlan(ctx, f.a)
			if e == nil || plan != nil || ctx.Err() != nil {
				t.Fatalf("stale cleanup proof accepted: plan=%v err=%v deadline=%v", plan, e, ctx.Err())
			}
			expected := map[string]string{"purge authorization": "participant_purge_not_authorized", "termination proof": "participant_purge_termination_unconfirmed", "node certificate": "participant_purge_not_found"}[kind]
			cleanupWantCode(t, e, expected)
		})
	}
}
