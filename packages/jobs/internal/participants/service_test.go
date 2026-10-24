package participants

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

type participantFixture struct {
	t              *testing.T
	ctx            context.Context
	db             *store.DB
	s              *Service
	spec           domain.JobSpec
	digest         string
	actor          Actor
	now            time.Time
	sourceRoot     string
	grantEnabled   bool
	grantSpace     string
	grantPrincipal string
	grants         int
	nodeRequests   []NodeGrant
}

func participantThumb(label string) string {
	sum := sha256.Sum256([]byte(label))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func newParticipantFixture(t *testing.T) *participantFixture {
	t.Helper()
	ctx := context.Background()
	db, e := store.Open(ctx, "sqlite:///"+filepath.Join(t.TempDir(), "manager.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if _, e = db.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	spec := domain.JobSpec{ProjectID: "project", Name: "Federation", SourceID: "source", SourceCommit: strings.Repeat("a", 40), RuntimeImage: "runtime", Plugin: "plugin", Options: map[string]any{}, SecretRefs: map[string]string{}, Participants: []domain.ParticipantSpec{{ParticipantID: "alice", DatasetBinding: "data-alice", Mode: "external"}, {ParticipantID: "bob", DatasetBinding: "data-bob", Mode: "external"}}, Components: []domain.ComponentSpec{{ComponentID: "owner", Role: "owner", Resources: domain.ResourceRequest{PoolID: "cpu", CPUMillicores: 1000, MemoryBytes: 1 << 30, DiskBytes: 1 << 30, SandboxProfile: "runsc-cpu-v1"}}}, TargetRound: 10, MaxDurationSeconds: 7200}
	digest, e := spec.Digest()
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Second)
	f := &participantFixture{t: t, ctx: ctx, db: db, spec: spec, digest: digest, now: now, sourceRoot: t.TempDir(), grantEnabled: true, grantSpace: "space"}
	if e = os.Chmod(f.sourceRoot, 0700); e != nil {
		t.Fatal(e)
	}
	data := []byte("# Trusted training source\n")
	if e = os.WriteFile(filepath.Join(f.sourceRoot, "plugin.py"), data, 0600); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(data)
	node := func(id, participant string) ApprovedNode {
		return ApprovedNode{NodeID: id, CertificateThumbprint: participantThumb(id), DatasetBindings: map[string]map[string]any{"data-" + participant: {"participant_id": participant, "path": "/data/local", "synthetic": false}}, Resources: map[string]int64{"cpu_millicores": 1000, "memory_bytes": 1 << 30, "disk_bytes": 1 << 30}, Enabled: true}
	}
	nodes := []ApprovedNode{node("node-alice", "alice"), node("node-bob", "bob")}
	hooks := Hooks{WorkloadIssuer: "https://workloads.example.test", StoragePoolID: "cpu"}
	hooks.Snapshot = func(context.Context, map[string]any, domain.JobSpec) (Snapshot, error) {
		return Snapshot{Root: f.sourceRoot, Manifest: map[string]string{"plugin.py": hex.EncodeToString(sum[:])}}, nil
	}
	hooks.SpaceID = func(context.Context, string) (string, error) { return "space", nil }
	hooks.Image = func(context.Context, domain.JobSpec) (string, error) { return "sha256:" + strings.Repeat("b", 64), nil }
	hooks.SourceLimits = func(context.Context, domain.JobSpec) (map[string]any, error) {
		return map[string]any{"max_bytes": int64(1 << 20), "max_files": int64(100), "max_git_bytes": int64(1 << 20), "max_git_files": int64(100)}, nil
	}
	hooks.IssueNode = func(ctx context.Context, request NodeGrant) (string, error) {
		f.nodeRequests = append(f.nodeRequests, request)
		return "node-token", nil
	}
	hooks.CreateGrant = func(ctx context.Context, space string, body map[string]any, key string) (map[string]any, error) {
		f.grants++
		principal := stableWorkloadPrincipal(hooks.WorkloadIssuer, "job", ComponentID("alice"), "alice")
		if f.grantPrincipal != "" {
			principal = f.grantPrincipal
		}
		return map[string]any{"space_id": f.grantSpace, "grant_id": "grant", "principal_id": principal, "expires_at": f.now.Add(5 * time.Minute).Unix(), "enabled": true}, nil
	}
	hooks.GetGrant = func(context.Context, string, string) (map[string]any, error) {
		return map[string]any{"space_id": f.grantSpace, "grant_id": "grant", "enabled": f.grantEnabled, "expires_at": f.now.Add(120 * time.Second).Unix()}, nil
	}
	hooks.IssueWorkload = func(ctx context.Context, bindings map[string]any, audience string, ttl int64) (string, error) {
		if str(bindings["job_id"]) != "job" || str(bindings["attempt_id"]) != "attempt" || str(bindings["component_id"]) != ComponentID("alice") || str(bindings["participant_id"]) != "alice" || ttl != 120 {
			t.Fatalf("foreign or unbounded credentials: %v ttl=%d", bindings, ttl)
		}
		return audience + "-token", nil
	}
	s, e := NewService(db, nodes, hooks, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	s.Clock = func() time.Time { return now }
	f.s = s
	t.Cleanup(s.Close)
	e = db.WithTx(ctx, true, func(tx *store.Tx) error {
		if e := tx.Insert(ctx, "jm_projects", map[string]any{"id": "project", "name": "Project"}); e != nil {
			return e
		}
		if e := tx.Insert(ctx, "jm_pools", map[string]any{"id": "cpu", "name": "CPU", "node_id": "manager", "cpu_millicores": int64(4000), "memory_bytes": int64(4 << 30), "disk_bytes": int64(8 << 30)}); e != nil {
			return e
		}
		if e := tx.Insert(ctx, "jm_jobs", map[string]any{"id": "job", "project_id": "project", "creator_id": "owner", "name": spec.Name, "spec_json": spec, "spec_hash": digest, "target_round": int64(10), "state": "RUNNING", "current_attempt": int64(1), "epoch": int64(1), "deadline_at": now.Add(time.Hour), "version": int64(1)}); e != nil {
			return e
		}
		if e := tx.Insert(ctx, "jm_attempts", map[string]any{"id": "attempt", "job_id": "job", "number": int64(1), "epoch": int64(1), "state": "RUNNING"}); e != nil {
			return e
		}
		for principal, role := range map[string]string{"owner": "admin", "reader": "reader"} {
			if e := tx.Insert(ctx, "jm_job_members", map[string]any{"job_id": "job", "principal_id": principal, "role": role}); e != nil {
				return e
			}
		}
		for _, participant := range []string{"alice", "bob"} {
			if e := tx.Insert(ctx, "jm_participant_bindings", map[string]any{"id": "data-" + participant, "project_id": "project", "participant_id": participant, "node_id": "node-" + participant, "dataset_label": "Private local images", "enabled": true}); e != nil {
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
func (f *participantFixture) update(table, id string, values map[string]any) {
	f.t.Helper()
	if e := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error { return tx.Update(f.ctx, table, map[string]any{"id": id}, values) }); e != nil {
		f.t.Fatal(e)
	}
}
func (f *participantFixture) row(table, id string) map[string]any {
	f.t.Helper()
	row, e := f.db.One(f.ctx, "SELECT * FROM "+table+" WHERE id=?", id)
	if e != nil {
		f.t.Fatal(e)
	}
	return row
}
func (f *participantFixture) enroll() {
	f.t.Helper()
	out, e := f.s.Enroll(f.ctx, "owner", "job", "alice", "node-alice", 1, "enroll-key")
	if e != nil {
		f.t.Fatal(e)
	}
	f.actor = Actor{ID: "node-principal", NodeID: "node-alice", PoolID: "external", JobID: "job", AttemptID: "attempt", ComponentID: ComponentID("alice"), GrantID: str(out["id"]), Epoch: 1, CertificateThumbprint: participantThumb("node-alice"), Scopes: []string{"assignment", "heartbeat", "stopped", "logs", "collect"}}
}
func (f *participantFixture) budget() {
	f.t.Helper()
	e := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
		component := ComponentID("alice")
		return tx.Insert(f.ctx, "jm_provisioning_resources", map[string]any{"id": "log-budget", "job_id": "job", "attempt_id": "attempt", "component_id": component, "kind": "log_budget", "external_id": "hf2l-log://job/1/" + component, "state": "planned", "retained": true, "size_bytes": int64(1 << 20), "ownership_json": map[string]any{"job_id": "job", "component_id": component, "kind": "log_budget"}, "details_json": map[string]any{"spec_digest": f.digest, "component_id": component, "attempt_number": int64(1), "reservation_max_bytes": int64(1 << 20), "retention_reservation_bytes": int64(1 << 20), "retention_charged_bytes": int64(1 << 20), "retention_charge_released": false, "pool_id": "cpu"}})
	})
	if e != nil {
		f.t.Fatal(e)
	}
}
func (f *participantFixture) bootstrap() {
	f.t.Helper()
	f.enroll()
	f.budget()
	if _, e := f.s.BootstrapCredentials(f.ctx, f.actor.GrantID); e != nil {
		f.t.Fatal(e)
	}
}
func expectParticipantCode(t *testing.T, e error, code string) {
	t.Helper()
	var d *domain.Error
	if !errors.As(e, &d) || d.Code != code {
		t.Fatalf("want %s, got %v", code, e)
	}
}
func TestParticipantEnrollmentAuthorizationAndReplay(t *testing.T) {
	f := newParticipantFixture(t)
	for _, principal := range []string{"foreign", "reader"} {
		_, e := f.s.Enroll(f.ctx, principal, "job", "alice", "node-alice", 1, "key")
		code := "job_not_found"
		if principal == "reader" {
			code = "job_role_required"
		}
		expectParticipantCode(t, e, code)
	}
	f.enroll()
	result, e := f.s.Enroll(f.ctx, "owner", "job", "alice", "node-alice", 1, "enroll-key")
	if e != nil || number(result["version"]) != 2 {
		t.Fatalf("replay: %v %v", result, e)
	}
	if result["node_token"] != nil {
		t.Fatal("credential leaked in enrollment")
	}
	_, e = f.s.Enroll(f.ctx, "owner", "job", "bob", "node-bob", 2, "enroll-key")
	expectParticipantCode(t, e, "idempotency_conflict")
	_, e = f.s.Enroll(f.ctx, "owner", "job", "alice", "node-alice", 1, "new-key")
	expectParticipantCode(t, e, "job_version_conflict")
	if _, e = f.db.Exec(f.ctx, "DELETE FROM jm_job_members WHERE principal_id=?", "owner"); e != nil {
		t.Fatal(e)
	}
	_, e = f.s.Enroll(f.ctx, "owner", "job", "alice", "node-alice", 1, "enroll-key")
	expectParticipantCode(t, e, "job_not_found")
}
func TestParticipantEnrollmentBindsApprovedNodeCertificate(t *testing.T) {
	f := newParticipantFixture(t)
	f.enroll()
	n := f.s.Nodes["node-alice"]
	n.CertificateThumbprint = participantThumb("changed")
	f.s.Nodes["node-alice"] = n
	_, e := f.s.Enroll(f.ctx, "owner", "job", "alice", "node-alice", 2, "new-key")
	expectParticipantCode(t, e, "external_node_binding_immutable")
	f.update("jm_participant_bindings", "data-alice", map[string]any{"enabled": false})
	_, e = f.s.GetEnrollment(f.ctx, "reader", "job", "alice")
	if e != nil {
		t.Fatal("authorized metadata history must remain accessible", e)
	}
	_, e = f.s.Enroll(f.ctx, "owner", "job", "alice", "node-alice", 2, "disabled")
	expectParticipantCode(t, e, "external_node_not_approved")
}
func TestParticipantBootstrapRequiresPrechargedLogBudget(t *testing.T) {
	f := newParticipantFixture(t)
	f.enroll()
	_, e := f.s.BootstrapCredentials(f.ctx, f.actor.GrantID)
	expectParticipantCode(t, e, "participant_log_budget_unavailable")
	enrollment := f.row("jm_provisioning_resources", f.actor.GrantID)
	if enrollment["attempt_id"] != nil || mapv(enrollment["details_json"])["termination_confirmed"] != true {
		t.Fatal("failed bootstrap left a partial dispatch fence")
	}
	f.budget()
	document, e := f.s.BootstrapCredentials(f.ctx, f.actor.GrantID)
	if e != nil {
		t.Fatal(e)
	}
	if document["operation"] != "start" || len(f.nodeRequests) != 1 {
		t.Fatal(document)
	}
	request := f.nodeRequests[0]
	if request.PoolID != "external" || request.JobID != "job" || request.ComponentID != ComponentID("alice") || request.GrantID != f.actor.GrantID || request.CertificateThumbprint != participantThumb("node-alice") || !contains(request.Scopes, "assignment") {
		t.Fatalf("wrong node grant %+v", request)
	}
	confirmed, e := f.s.AttemptTerminationConfirmed(f.ctx, "job", "attempt")
	if e != nil || confirmed {
		t.Fatal("dispatch was not fenced", e)
	}
}
func TestParticipantStopInvalidatesAccessAndReceiptsAreImmutable(t *testing.T) {
	f := newParticipantFixture(t)
	f.bootstrap()
	confirmed, e := f.s.RequestStop(f.ctx, f.row("jm_jobs", "job"), f.row("jm_attempts", "attempt"))
	if e != nil || confirmed {
		t.Fatalf("stop must await actual proof: %v %v", confirmed, e)
	}
	if f.s.SourceAccessValid(f.ctx, f.actor) {
		t.Fatal("source access survived stop intent")
	}
	if _, e = f.s.ControlPlan(f.ctx, f.actor); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.ConfirmStopped(f.ctx, f.actor, true, false); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.ConfirmStopped(f.ctx, f.actor, true, false); e != nil {
		t.Fatal("identical stop replay rejected", e)
	}
	_, e = f.s.ConfirmStopped(f.ctx, f.actor, true, true)
	expectParticipantCode(t, e, "external_stop_receipt_immutable")
	confirmed, e = f.s.AttemptTerminationConfirmed(f.ctx, "job", "attempt")
	if e != nil || !confirmed {
		t.Fatal(e)
	}
	doc, e := f.s.BootstrapCredentials(f.ctx, f.actor.GrantID)
	if e != nil || doc["operation"] != "stop" {
		t.Fatalf("%v %v", doc, e)
	}
	if contains(f.nodeRequests[len(f.nodeRequests)-1].Scopes, "assignment") {
		t.Fatal("stopped node received new assignment authority")
	}
}
func TestParticipantCurrentGrantCertificateAndForeignJobFences(t *testing.T) {
	for _, mutate := range []func(*Actor){func(a *Actor) { a.JobID = "foreign" }, func(a *Actor) { a.AttemptID = "foreign" }, func(a *Actor) { a.ComponentID = "owner" }, func(a *Actor) { a.Epoch++ }, func(a *Actor) { a.PoolID = "cpu" }, func(a *Actor) { a.CertificateThumbprint = participantThumb("foreign") }, func(a *Actor) { a.NodeID = "node-bob" }} {
		f := newParticipantFixture(t)
		f.bootstrap()
		actor := f.actor
		mutate(&actor)
		if f.s.CheckNodeGrant(f.ctx, actor) || f.s.SourceAccessValid(f.ctx, actor) {
			t.Fatalf("foreign binding authorized: %+v", actor)
		}
	}
}
func TestParticipantAssignmentCredentialRenewalAndRevocation(t *testing.T) {
	f := newParticipantFixture(t)
	f.bootstrap()
	plan, e := f.s.AssignmentPlan(f.ctx, f.actor)
	if e != nil {
		t.Fatal(e)
	}
	if str(plan["space_id"]) != "space" || str(plan["principal_id"]) != stableWorkloadPrincipal(f.s.Hooks.WorkloadIssuer, "job", ComponentID("alice"), "alice") || plan["credentials"] != nil {
		t.Fatal(plan)
	}
	_, e = f.s.Assignment(f.ctx, f.actor, participantThumb("node-alice"), "proxy")
	expectParticipantCode(t, e, "execution_certificate_required")
	assigned, e := f.s.Assignment(f.ctx, f.actor, participantThumb("execution"), "proxy")
	if e != nil {
		t.Fatal(e)
	}
	if mapv(assigned["credentials"])["exchange_token"] != "exchange-token" || mapv(assigned["runtime_config"])["participant_id"] != "alice" {
		t.Fatal(assigned)
	}
	if _, e = f.s.Assignment(f.ctx, f.actor, participantThumb("execution"), "proxy"); e != nil {
		t.Fatal("assignment replay", e)
	}
	if f.grants != 1 {
		t.Fatalf("grant operation duplicated %d", f.grants)
	}
	_, e = f.s.Assignment(f.ctx, f.actor, participantThumb("other"), "proxy")
	expectParticipantCode(t, e, "participant_execution_binding_immutable")
	f.grantEnabled = false
	_, e = f.s.Credentials(f.ctx, f.actor)
	expectParticipantCode(t, e, "participant_grant_revoked")
}
func TestParticipantRejectsForeignGrantAndSourceTampering(t *testing.T) {
	f := newParticipantFixture(t)
	f.bootstrap()
	f.grantSpace = "foreign"
	_, e := f.s.Assignment(f.ctx, f.actor, participantThumb("execution"), "proxy")
	expectParticipantCode(t, e, "participant_foreign_grant")
	f.grantSpace = "space"
	if _, e = f.s.Credentials(f.ctx, f.actor); e == nil {
		t.Fatal("failed foreign grant enabled credentials")
	}
	if _, e := secureRead(f.sourceRoot, "plugin.py", 64<<20); e != nil {
		info, _ := os.Stat(f.sourceRoot)
		t.Fatalf("safe source fixture read: %v mode=%v uid=%d", e, info.Mode(), os.Geteuid())
	}
	source, e := f.s.OpenSource(f.ctx, f.actor, "plugin.py")
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(source)
	source.Close()
	if e != nil || string(b) != "# Trusted training source\n" {
		t.Fatalf("%q %v", b, e)
	}
	if e = os.WriteFile(filepath.Join(f.sourceRoot, "plugin.py"), []byte("tampered"), 0600); e != nil {
		t.Fatal(e)
	}
	_, e = f.s.OpenSource(f.ctx, f.actor, "plugin.py")
	expectParticipantCode(t, e, "participant_source_mismatch")
	_, e = f.s.OpenSource(f.ctx, f.actor, "../secret")
	expectParticipantCode(t, e, "participant_source_file_not_found")
}
func TestParticipantSourceRejectsSymlinksHardlinksAndSpecialFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			if e := os.Chmod(root, 0700); e != nil {
				t.Fatal(e)
			}
			target := filepath.Join(root, "file")
			switch kind {
			case "symlink":
				if e := os.Symlink("other", target); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.WriteFile(filepath.Join(root, "other"), []byte("data"), 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.Link(filepath.Join(root, "other"), target); e != nil {
					t.Fatal(e)
				}
			case "fifo":
				if e := unix.Mkfifo(target, 0600); e != nil {
					t.Fatal(e)
				}
			}
			done := make(chan error, 1)
			go func() { _, e := secureRead(root, "file", 1024); done <- e }()
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("unsafe file read")
				}
			case <-time.After(time.Second):
				t.Fatal("special file open blocked")
			}
		})
	}
}
func TestParticipantAsynchronousDispatchCancellation(t *testing.T) {
	f := newParticipantFixture(t)
	f.enroll()
	f.budget()
	entered := make(chan struct{})
	cancelled := make(chan struct{})
	f.s.Dispatch = func(ctx context.Context, nodeID string, doc map[string]any) (map[string]any, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	}
	started := time.Now()
	out, e := f.s.DispatchPending(f.ctx)
	if e != nil || number(out["dispatched"]) != 1 {
		t.Fatalf("%v %v", out, e)
	}
	if time.Since(started) > time.Second {
		t.Fatal("controller tick blocked on node")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("dispatch never entered")
	}
	f.s.Close()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("dispatch did not stop")
	}
	if f.row("jm_provisioning_resources", f.actor.GrantID)["deleted_at"] != nil {
		t.Fatal("cancelled dispatch released physical retention")
	}
}
