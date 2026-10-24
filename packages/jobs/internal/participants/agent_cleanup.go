package participants

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/node"
)

// agentCleanup bridges physical cleanup to concrete materializer and local node
// ledgers. Guard contexts are opaque capabilities valid only during the node's
// component guard; they cannot be synthesized by request callers.
type agentCleanup struct {
	Agent        *Agent
	mu           sync.Mutex
	guards       map[string]context.Context
	privateProof map[string]bool
}
type cleanupContextGuard interface {
	WithComponentGuardContext(context.Context, executor.ExecutionIdentity, bool, func(context.Context) error) error
}

func (a *agentCleanup) WithPurgeGuard(ctx context.Context, id executor.ExecutionIdentity, fn func() error) error {
	if a == nil || a.Agent == nil || a.Agent.Node == nil {
		return domain.Err(503, "participant_cleanup_guard_unavailable")
	}
	guarded, ok := a.Agent.Node.(cleanupContextGuard)
	if !ok {
		return domain.Err(503, "participant_cleanup_guard_unavailable")
	}
	// A resource guard permits never-delivered assignments with no node ledger.
	// PurgeAssignment verifies every known reservation stopped inside this guard.
	err := guarded.WithComponentGuardContext(ctx, id, false, func(held context.Context) error {
		a.mu.Lock()
		if a.guards == nil {
			a.guards = map[string]context.Context{}
		}
		a.guards[id.Key()] = held
		if a.privateProof == nil {
			a.privateProof = map[string]bool{}
		}
		delete(a.privateProof, id.Key())
		a.mu.Unlock()
		defer func() { a.mu.Lock(); delete(a.guards, id.Key()); delete(a.privateProof, id.Key()); a.mu.Unlock() }()
		return fn()
	})
	var d *domain.Error
	if errors.As(err, &d) && d.Code == "runtime_active" {
		return domain.Err(409, "participant_purge_termination_unconfirmed")
	}
	return err
}
func (a *agentCleanup) guardedContext(id executor.ExecutionIdentity) (context.Context, error) {
	a.mu.Lock()
	held := a.guards[id.Key()]
	a.mu.Unlock()
	if held == nil {
		return nil, domain.Err(503, "participant_cleanup_guard_unavailable")
	}
	return held, nil
}
func (a *agentCleanup) Request(ctx context.Context, id executor.ExecutionIdentity, token, operation string, body map[string]any) (map[string]any, error) {
	if a.Agent.Client == nil {
		return nil, domain.Err(503, "external_manager_unavailable")
	}
	return a.Agent.Client.Request(ctx, id, token, operation, body)
}
func (a *agentCleanup) NodeID() string    { return a.Agent.Config.NodeID }
func (a *agentCleanup) OwnedRoot() string { return a.Agent.Config.Root }
func cleanupInventoryIdentity(row map[string]any) (executor.ExecutionIdentity, error) {
	var id executor.ExecutionIdentity
	if raw, ok := row["identity"]; ok {
		b, e := domain.CanonicalJSON(raw)
		if e != nil {
			return id, cleanupMismatch()
		}
		var identityMap map[string]any
		decoded, e := domain.DecodeJSON(b)
		if e != nil {
			return id, cleanupMismatch()
		}
		identityMap, ok = decoded.(map[string]any)
		if !ok {
			return id, cleanupMismatch()
		}
		row = identityMap
	}
	epoch, ok := cleanupInt(row["epoch"])
	if !ok {
		return id, cleanupMismatch()
	}
	id = executor.ExecutionIdentity{JobID: cleanupString(row["job_id"]), AttemptID: cleanupString(row["attempt_id"]), ComponentID: cleanupString(row["component_id"]), Epoch: epoch}
	if id.Validate() != nil {
		return id, cleanupMismatch()
	}
	return id, nil
}
func cleanupInventoryFlag(v any) (bool, error) {
	if b, ok := v.(bool); ok {
		return b, nil
	}
	n, ok := cleanupInt(v)
	if !ok || (n != 0 && n != 1) {
		return false, cleanupMismatch()
	}
	return n == 1, nil
}
func (a *agentCleanup) Inventory(ctx context.Context) ([]CleanupReservation, error) {
	rows, e := a.Agent.Node.Inventory(ctx)
	if e != nil {
		return nil, e
	}
	out := make([]CleanupReservation, 0, len(rows))
	seen := map[string]bool{}
	for _, r := range rows {
		id, e := cleanupInventoryIdentity(r)
		if e != nil {
			return nil, e
		}
		if seen[id.Key()] {
			return nil, cleanupMismatch()
		}
		seen[id.Key()] = true
		if key, ok := r["execution_key"]; ok && key != id.Key() {
			return nil, cleanupMismatch()
		}
		stopped, e := cleanupInventoryFlag(r["stopped"])
		if e != nil {
			return nil, e
		}
		state, ok := r["state"].(string)
		if !ok || state == "" {
			return nil, cleanupMismatch()
		}
		out = append(out, CleanupReservation{Identity: id, State: state, Stopped: stopped})
	}
	return out, nil
}
func (a *agentCleanup) ConfirmAbsent(ctx context.Context, id executor.ExecutionIdentity) (bool, error) {
	held, e := a.guardedContext(id)
	if e != nil {
		return false, e
	}
	return a.Agent.Node.ConfirmAbsent(held, id)
}
func (a *agentCleanup) assignment(value node.RemoteAssignment) (CleanupAssignment, error) {
	value = value.Defaults()
	if e := value.Validate(); e != nil {
		return CleanupAssignment{}, e
	}
	digest, e := value.JobSpec.Digest()
	if e != nil {
		return CleanupAssignment{}, e
	}
	participant := ""
	if value.ExternalParticipantID != nil {
		participant = *value.ExternalParticipantID
	}
	component := filepath.Join(a.Agent.Config.Root, "jobs", value.Identity.JobID, "components", value.Identity.ComponentID)
	return CleanupAssignment{Identity: value.Identity, NodeID: value.NodeID, PoolID: value.PoolID, SpecDigest: digest, ParticipantID: participant, ComponentRoot: component, SourceRoot: filepath.Join(component, "source"), DiskBytes: value.Resources.DiskBytes}, nil
}
func (a *agentCleanup) Assignment(ctx context.Context, id executor.ExecutionIdentity) (*CleanupAssignment, error) {
	value, e := a.Agent.Materializer.Assignment(ctx, id)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if value.Identity != id {
		return nil, cleanupMismatch()
	}
	out, e := a.assignment(value)
	if e != nil {
		return nil, e
	}
	return &out, nil
}
func (a *agentCleanup) AllAssignments(ctx context.Context) ([]CleanupAssignment, error) {
	values, e := a.Agent.Materializer.AllAssignments(ctx)
	if e != nil {
		return nil, e
	}
	out := make([]CleanupAssignment, 0, len(values))
	seen := map[string]bool{}
	for _, v := range values {
		converted, e := a.assignment(v)
		if e != nil {
			return nil, e
		}
		if seen[converted.Identity.Key()] {
			return nil, cleanupMismatch()
		}
		seen[converted.Identity.Key()] = true
		out = append(out, converted)
	}
	return out, nil
}
func (a *agentCleanup) PurgePrivate(ctx context.Context, id executor.ExecutionIdentity, assignment *CleanupAssignment) (bool, error) {
	held, e := a.guardedContext(id)
	if e != nil {
		return false, e
	}
	if a.Agent.Config.ProxyStop == nil {
		return false, domain.Err(503, "participant_proxy_cleanup_unconfirmed")
	}
	stopped, e := a.Agent.Config.ProxyStop(held, id, true)
	if e != nil {
		return false, e
	}
	if !stopped {
		return false, domain.Err(503, "participant_proxy_cleanup_unconfirmed")
	}
	if a.Agent.Config.PurgePrivate == nil {
		return false, domain.Err(503, "participant_secret_cleanup_unconfirmed")
	}
	deleted, e := a.Agent.Config.PurgePrivate(held, id, assignment)
	if e != nil {
		return false, e
	}
	if !deleted {
		return false, domain.Err(503, "participant_secret_cleanup_unconfirmed")
	}
	a.mu.Lock()
	a.privateProof[id.Key()] = true
	a.mu.Unlock()
	return true, nil
}
func (a *agentCleanup) PurgeRuntime(ctx context.Context, id executor.ExecutionIdentity, auxiliaryDeleted bool) (bool, error) {
	if !auxiliaryDeleted {
		return false, domain.Err(503, "participant_disk_cleanup_unconfirmed")
	}
	held, e := a.guardedContext(id)
	if e != nil {
		return false, e
	}
	a.mu.Lock()
	proof := a.privateProof[id.Key()]
	a.mu.Unlock()
	if !proof {
		return false, domain.Err(503, "participant_disk_cleanup_unconfirmed")
	}
	confirmed, e := a.Agent.Node.PurgeWithAuxiliary(held, id, true)
	var d *domain.Error
	if errors.As(e, &d) && d.Code == "missing_reservation" {
		// A staged assignment may never have reached Reserve. Require a fresh
		// backend absence proof under the same full component guard.
		return a.Agent.Node.ConfirmAbsent(held, id)
	}
	return confirmed, e
}
func (a *agentCleanup) RemoveAssignment(ctx context.Context, id executor.ExecutionIdentity) error {
	if _, e := a.guardedContext(id); e != nil {
		return e
	}
	return a.Agent.Materializer.RemoveAssignment(ctx, id)
}

var _ CleanupAgent = (*agentCleanup)(nil)
