package participants

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/node"
)

type cleanupAdapterGuardKey struct{}
type cleanupAdapterRuntime struct {
	AgentRuntime
	rows                    []map[string]any
	guarded                 bool
	absent                  bool
	absentCalls, purgeCalls int
	purgeError              error
}

func (r *cleanupAdapterRuntime) WithComponentGuardContext(ctx context.Context, id executor.ExecutionIdentity, purge bool, fn func(context.Context) error) error {
	if purge {
		return errors.New("purge precheck rejects absent assignments")
	}
	r.guarded = true
	defer func() { r.guarded = false }()
	return fn(context.WithValue(ctx, cleanupAdapterGuardKey{}, r))
}
func (r *cleanupAdapterRuntime) Inventory(context.Context) ([]map[string]any, error) {
	return r.rows, nil
}
func (r *cleanupAdapterRuntime) ConfirmAbsent(ctx context.Context, id executor.ExecutionIdentity) (bool, error) {
	r.absentCalls++
	if !r.guarded || ctx.Value(cleanupAdapterGuardKey{}) != r {
		return false, errors.New("absence proof outside node guard")
	}
	return r.absent, nil
}
func (r *cleanupAdapterRuntime) PurgeWithAuxiliary(ctx context.Context, id executor.ExecutionIdentity, deleted bool) (bool, error) {
	r.purgeCalls++
	if !r.guarded || ctx.Value(cleanupAdapterGuardKey{}) != r || !deleted {
		return false, errors.New("quota release outside node guard")
	}
	return r.purgeError == nil, r.purgeError
}

type cleanupAdapterMaterializer struct {
	AgentMaterializer
	assignment node.RemoteAssignment
	values     []node.RemoteAssignment
	err        error
	removed    bool
}

func (m *cleanupAdapterMaterializer) Assignment(context.Context, executor.ExecutionIdentity) (node.RemoteAssignment, error) {
	return m.assignment, m.err
}
func (m *cleanupAdapterMaterializer) AllAssignments(context.Context) ([]node.RemoteAssignment, error) {
	return m.values, m.err
}
func (m *cleanupAdapterMaterializer) RemoveAssignment(context.Context, executor.ExecutionIdentity) error {
	m.removed = true
	return nil
}
func cleanupAdapterIdentity() executor.ExecutionIdentity {
	return executor.ExecutionIdentity{JobID: "job", AttemptID: "attempt", ComponentID: domain.ExternalComponentID("alice"), Epoch: 1}
}
func TestAgentCleanupOpaqueGuardAndPrivateProofs(t *testing.T) {
	id := cleanupAdapterIdentity()
	runtime := &cleanupAdapterRuntime{absent: true}
	order := []string{}
	cfg := AgentConfig{NodeID: "node", Root: t.TempDir(), ProxyStop: func(ctx context.Context, got executor.ExecutionIdentity, confirmed bool) (bool, error) {
		if got != id || !confirmed {
			t.Fatal("wrong proxy identity")
		}
		order = append(order, "proxy")
		return true, nil
	}, PurgePrivate: func(ctx context.Context, got executor.ExecutionIdentity, assignment *CleanupAssignment) (bool, error) {
		order = append(order, "private")
		return true, nil
	}}
	materializer := &cleanupAdapterMaterializer{}
	adapter := &agentCleanup{Agent: &Agent{Config: cfg, Node: runtime, Materializer: materializer}}
	_, e := adapter.ConfirmAbsent(context.Background(), id)
	cleanupWantCode(t, e, "participant_cleanup_guard_unavailable")
	e = adapter.WithPurgeGuard(context.Background(), id, func() error {
		if ok, e := adapter.ConfirmAbsent(context.Background(), id); e != nil || !ok {
			t.Fatalf("absence %v %v", ok, e)
		}
		if ok, e := adapter.PurgePrivate(context.Background(), id, nil); e != nil || !ok {
			t.Fatalf("private %v %v", ok, e)
		}
		if ok, e := adapter.PurgeRuntime(context.Background(), id, true); e != nil || !ok {
			t.Fatalf("runtime %v %v", ok, e)
		}
		return adapter.RemoveAssignment(context.Background(), id)
	})
	if e != nil {
		t.Fatal(e)
	}
	if strings.Join(order, ",") != "proxy,private" || runtime.purgeCalls != 1 || !materializer.removed {
		t.Fatal("cleanup order or evidence missing")
	}
	_, e = adapter.PurgeRuntime(context.Background(), id, true)
	cleanupWantCode(t, e, "participant_cleanup_guard_unavailable")
}
func TestAgentCleanupMissingOrFalsePrivateCallbacksRefuse(t *testing.T) {
	for _, kind := range []string{"missing proxy", "false proxy", "missing secrets", "false secrets", "proxy error", "secret error"} {
		t.Run(kind, func(t *testing.T) {
			id := cleanupAdapterIdentity()
			runtime := &cleanupAdapterRuntime{}
			privateCalls := 0
			cfg := AgentConfig{ProxyStop: func(context.Context, executor.ExecutionIdentity, bool) (bool, error) { return true, nil }, PurgePrivate: func(context.Context, executor.ExecutionIdentity, *CleanupAssignment) (bool, error) {
				privateCalls++
				return true, nil
			}}
			switch kind {
			case "missing proxy":
				cfg.ProxyStop = nil
			case "false proxy":
				cfg.ProxyStop = func(context.Context, executor.ExecutionIdentity, bool) (bool, error) { return false, nil }
			case "missing secrets":
				cfg.PurgePrivate = nil
			case "false secrets":
				cfg.PurgePrivate = func(context.Context, executor.ExecutionIdentity, *CleanupAssignment) (bool, error) { return false, nil }
			case "proxy error":
				cfg.ProxyStop = func(context.Context, executor.ExecutionIdentity, bool) (bool, error) {
					return false, errors.New("uncertain proxy")
				}
			case "secret error":
				cfg.PurgePrivate = func(context.Context, executor.ExecutionIdentity, *CleanupAssignment) (bool, error) {
					return false, errors.New("uncertain secrets")
				}
			}
			adapter := &agentCleanup{Agent: &Agent{Config: cfg, Node: runtime}}
			e := adapter.WithPurgeGuard(context.Background(), id, func() error {
				ok, e := adapter.PurgePrivate(context.Background(), id, nil)
				if e == nil || ok {
					t.Fatalf("unproven deletion accepted %v %v", ok, e)
				}
				return e
			})
			if e == nil || runtime.purgeCalls != 0 {
				t.Fatal("quota released after uncertain private cleanup")
			}
			if strings.Contains(kind, "proxy") && privateCalls != 0 {
				t.Fatal("secret deletion reached before proxy proof")
			}
		})
	}
}
func TestAgentCleanupInventoryRejectsMalformedProofs(t *testing.T) {
	id := cleanupAdapterIdentity()
	base := map[string]any{"job_id": id.JobID, "attempt_id": id.AttemptID, "component_id": id.ComponentID, "epoch": id.Epoch, "execution_key": id.Key(), "state": "RELEASED", "stopped": int64(1)}
	runtime := &cleanupAdapterRuntime{rows: []map[string]any{base}}
	adapter := &agentCleanup{Agent: &Agent{Node: runtime}}
	rows, e := adapter.Inventory(context.Background())
	if e != nil || len(rows) != 1 || !rows[0].Stopped {
		t.Fatalf("actual node integer flags rejected %v %v", rows, e)
	}
	for _, field := range []string{"epoch", "execution_key", "stopped"} {
		bad := cleanupCopy(base)
		bad[field] = "invalid"
		runtime.rows = []map[string]any{bad}
		if _, e := adapter.Inventory(context.Background()); e == nil {
			t.Fatalf("malformed %s accepted", field)
		}
	}
	nested := map[string]any{"identity": id, "state": "RELEASED", "stopped": true}
	runtime.rows = []map[string]any{nested}
	if _, e := adapter.Inventory(context.Background()); e != nil {
		t.Fatal(e)
	}
	runtime.rows = []map[string]any{base, base}
	if _, e := adapter.Inventory(context.Background()); e == nil {
		t.Fatal("duplicate identity accepted")
	}
}
func TestAgentCleanupAssignmentOnlyMissingFileProvesAbsence(t *testing.T) {
	f := newCleanupFixture(t)
	participant := "alice"
	assignment := node.RemoteAssignment{Identity: cleanupAdapterIdentity(), NodeID: "node", PoolID: "external", JobSpec: f.spec, ImageDigest: "sha256:" + strings.Repeat("a", 64), Resources: executor.ResourceLimits{CPUMillis: 1, MemoryBytes: 1, DiskBytes: 1024}, ExternalParticipantID: &participant}.Defaults()
	materializer := &cleanupAdapterMaterializer{assignment: assignment, values: []node.RemoteAssignment{assignment}}
	adapter := &agentCleanup{Agent: &Agent{Config: AgentConfig{Root: t.TempDir()}, Materializer: materializer}}
	converted, e := adapter.Assignment(context.Background(), assignment.Identity)
	if e != nil || converted.SpecDigest != f.digest || converted.ParticipantID != "alice" || converted.SourceRoot != filepath.Join(adapter.OwnedRoot(), "jobs", "job", "components", assignment.Identity.ComponentID, "source") {
		t.Fatalf("assignment conversion %v %v", converted, e)
	}
	if _, e := adapter.AllAssignments(context.Background()); e != nil {
		t.Fatal(e)
	}
	materializer.err = os.ErrNotExist
	converted, e = adapter.Assignment(context.Background(), assignment.Identity)
	if converted != nil || e != nil {
		t.Fatal("real missing assignment refused")
	}
	materializer.err = domain.Err(404, "assignment_missing")
	if _, e = adapter.Assignment(context.Background(), assignment.Identity); e == nil {
		t.Fatal("untrusted domain error interpreted as missing file")
	}
	materializer.err = os.ErrPermission
	if _, e = adapter.Assignment(context.Background(), assignment.Identity); e == nil {
		t.Fatal("inaccessible assignment accepted")
	}
}
func TestAgentCleanupMissingReservationRequiresFreshAbsence(t *testing.T) {
	id := cleanupAdapterIdentity()
	runtime := &cleanupAdapterRuntime{purgeError: domain.Err(409, "missing_reservation")}
	adapter := &agentCleanup{Agent: &Agent{Node: runtime, Config: AgentConfig{ProxyStop: func(context.Context, executor.ExecutionIdentity, bool) (bool, error) { return true, nil }, PurgePrivate: func(context.Context, executor.ExecutionIdentity, *CleanupAssignment) (bool, error) { return true, nil }}}}
	for _, absent := range []bool{false, true} {
		runtime.absent = absent
		e := adapter.WithPurgeGuard(context.Background(), id, func() error {
			if _, e := adapter.PurgePrivate(context.Background(), id, nil); e != nil {
				return e
			}
			ok, e := adapter.PurgeRuntime(context.Background(), id, true)
			if e != nil || ok != absent {
				t.Fatalf("absence=%v got %v %v", absent, ok, e)
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	}
	if runtime.absentCalls != 2 {
		t.Fatal("missing node reservation did not require backend proof")
	}
}

// This backend records no process or mount operations. The real NodeAgent
// still supplies its SQL ledger, accounting, and process-wide component locks.
type cleanupAdapterBackend struct {
	executor.Backend
	state                    string
	purgeCalls, absenceCalls int
}

func (b *cleanupAdapterBackend) Reserve(ctx context.Context, s executor.ExecutionSpec) (executor.Reservation, error) {
	b.state = "RESERVED"
	return executor.Reservation{Identity: s.Identity, Acknowledged: true, NodeID: "node", State: b.state}, nil
}
func (b *cleanupAdapterBackend) Inspect(ctx context.Context, id executor.ExecutionIdentity) (executor.RuntimeObservation, error) {
	return executor.RuntimeObservation{Identity: id, State: b.state, TerminationConfirmed: true}, nil
}
func (b *cleanupAdapterBackend) Release(context.Context, executor.ExecutionIdentity) (bool, error) {
	b.state = "RELEASED"
	return true, nil
}
func (b *cleanupAdapterBackend) Purge(context.Context, executor.ExecutionIdentity) (bool, error) {
	b.purgeCalls++
	return true, nil
}
func (b *cleanupAdapterBackend) ConfirmAbsent(context.Context, executor.ExecutionIdentity) (bool, error) {
	b.absenceCalls++
	return true, nil
}
func TestAgentCleanupRealNodeGuardDoesNotDeadlock(t *testing.T) {
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	backend := &cleanupAdapterBackend{}
	runtime, e := executor.NewNodeAgent(backend, filepath.Join(root, "node.sqlite"), "node", "external", executor.ResourceLimits{CPUMillis: 1000, MemoryBytes: 1 << 20, DiskBytes: 32 << 20}, executor.WithWatchdogInterval(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := runtime.Close(); e != nil {
			t.Error(e)
		}
	})
	id := cleanupAdapterIdentity()
	spec := executor.ExecutionSpec{Identity: id, ImageDigest: "sha256:" + strings.Repeat("a", 64), SourcePath: "/owned/source", StatePath: "/owned/state", ProxyEndpoint: "/owned/proxy", Resources: executor.ResourceLimits{CPUMillis: 1, MemoryBytes: 1024, DiskBytes: 1 << 20}, PoolID: "external", NodeID: "node"}.Defaults()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, e = runtime.Reserve(ctx, spec); e != nil {
		t.Fatal(e)
	}
	if ok, e := runtime.Release(ctx, id); e != nil || !ok {
		t.Fatalf("release %v %v", ok, e)
	}
	adapter := &agentCleanup{Agent: &Agent{Node: runtime, Config: AgentConfig{ProxyStop: func(context.Context, executor.ExecutionIdentity, bool) (bool, error) { return true, nil }, PurgePrivate: func(context.Context, executor.ExecutionIdentity, *CleanupAssignment) (bool, error) { return true, nil }}}}
	if e = adapter.WithPurgeGuard(ctx, id, func() error {
		if _, e := adapter.PurgePrivate(ctx, id, nil); e != nil {
			return e
		}
		ok, e := adapter.PurgeRuntime(ctx, id, true)
		if e != nil {
			return e
		}
		if !ok {
			return errors.New("purge unconfirmed")
		}
		return nil
	}); e != nil {
		t.Fatalf("nested real node purge guard deadlocked or failed: %v", e)
	}
	rows, e := runtime.Inventory(ctx)
	if e != nil || len(rows) != 1 || number(rows[0]["disk_released"]) != 1 || backend.purgeCalls != 1 {
		t.Fatalf("accounting %v %v", rows, e)
	}
	absent := id
	absent.AttemptID = "undelivered"
	absent.Epoch = 2
	if e = adapter.WithPurgeGuard(ctx, absent, func() error {
		ok, e := adapter.ConfirmAbsent(ctx, absent)
		if e != nil {
			return e
		}
		if !ok {
			return errors.New("absence not confirmed")
		}
		return nil
	}); e != nil {
		t.Fatalf("zero-ledger nested absence failed: %v", e)
	}
	if backend.absenceCalls != 1 {
		t.Fatal("backend absence proof skipped")
	}
}

func TestAgentCleanupRequiresContextGuardAndVerifiedPrivateReceipt(t *testing.T) {
	id := cleanupAdapterIdentity()
	legacy := struct{ AgentRuntime }{}
	adapter := &agentCleanup{Agent: &Agent{Node: legacy}}
	invoked := false
	e := adapter.WithPurgeGuard(context.Background(), id, func() error { invoked = true; return nil })
	cleanupWantCode(t, e, "participant_cleanup_guard_unavailable")
	if invoked {
		t.Fatal("unfenced cleanup callback ran")
	}
	runtime := &cleanupAdapterRuntime{}
	adapter = &agentCleanup{Agent: &Agent{Node: runtime}}
	e = adapter.WithPurgeGuard(context.Background(), id, func() error {
		confirmed, e := adapter.PurgeRuntime(context.Background(), id, true)
		if confirmed {
			t.Fatal("caller asserted unverified private deletion")
		}
		cleanupWantCode(t, e, "participant_disk_cleanup_unconfirmed")
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if runtime.purgeCalls != 0 {
		t.Fatal("auxiliary accounting released without private deletion proof")
	}
}
