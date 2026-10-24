package executor

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type nodeFakeBackend struct {
	mu                                                          sync.Mutex
	states                                                      map[string]string
	reserveCalls                                                int
	startCalls                                                  int
	stopCalls                                                   int
	releaseCalls                                                int
	purgeCalls                                                  int
	reserveErr, errorStart, errorStop, errorRelease, errorPurge error
	reserveHook                                                 func(ExecutionSpec)
	startHook                                                   func()
	guard                                                       func(ExecutionIdentity) bool
	artifacts                                                   []CollectedArtifact
	absence                                                     bool
}

func (f *nodeFakeBackend) SetLeaseGuard(guard func(ExecutionIdentity) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.guard = guard
}
func (f *nodeFakeBackend) Reserve(ctx context.Context, s ExecutionSpec) (Reservation, error) {
	f.mu.Lock()
	f.reserveCalls++
	hook := f.reserveHook
	err := f.reserveErr
	if err == nil {
		f.states[s.Identity.Key()] = "RESERVED"
	}
	f.mu.Unlock()
	if hook != nil {
		hook(s)
	}
	return Reservation{Identity: s.Identity, Acknowledged: err == nil, NodeID: "node", State: "RESERVED"}, err
}
func (f *nodeFakeBackend) Start(ctx context.Context, id ExecutionIdentity) (RuntimeObservation, error) {
	f.mu.Lock()
	f.startCalls++
	guard := f.guard
	hook := f.startHook
	err := f.errorStart
	f.mu.Unlock()
	if guard != nil && !guard(id) {
		return RuntimeObservation{}, refused("lease_expired")
	}
	if hook != nil {
		hook()
	}
	if err != nil {
		return RuntimeObservation{}, err
	}
	f.mu.Lock()
	f.states[id.Key()] = "RUNNING"
	f.mu.Unlock()
	return RuntimeObservation{Identity: id, State: "RUNNING"}, nil
}
func (f *nodeFakeBackend) Inspect(ctx context.Context, id ExecutionIdentity) (RuntimeObservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.states[id.Key()]
	if !ok {
		return RuntimeObservation{}, refused("missing_reservation")
	}
	return RuntimeObservation{Identity: id, State: state, TerminationConfirmed: state != "RUNNING" && state != "STARTING"}, nil
}
func (f *nodeFakeBackend) Stop(ctx context.Context, id ExecutionIdentity, grace int) (RuntimeObservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopCalls++
	if f.errorStop != nil {
		return RuntimeObservation{}, f.errorStop
	}
	if _, ok := f.states[id.Key()]; !ok {
		return RuntimeObservation{}, refused("missing_reservation")
	}
	f.states[id.Key()] = "STOPPED"
	return RuntimeObservation{Identity: id, State: "STOPPED", TerminationConfirmed: true}, nil
}
func (f *nodeFakeBackend) Collect(ctx context.Context, id ExecutionIdentity) ([]CollectedArtifact, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]CollectedArtifact(nil), f.artifacts...), nil
}
func (f *nodeFakeBackend) Release(ctx context.Context, id ExecutionIdentity) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releaseCalls++
	if f.errorRelease != nil {
		return false, f.errorRelease
	}
	f.states[id.Key()] = "RELEASED"
	return true, nil
}
func (f *nodeFakeBackend) Purge(ctx context.Context, id ExecutionIdentity) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.purgeCalls++
	return f.errorPurge == nil, f.errorPurge
}
func (f *nodeFakeBackend) ConfirmAbsent(ctx context.Context, id ExecutionIdentity) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.absence, nil
}
func (f *nodeFakeBackend) ReadLogs(ctx context.Context, id ExecutionIdentity, offset, maxBytes int64) (map[string]any, error) {
	return map[string]any{"identity": id, "offset": offset, "content": "fixture", "complete": true}, nil
}
func (f *nodeFakeBackend) ReadArtifact(ctx context.Context, id ExecutionIdentity, path string, maxBytes int64) ([]byte, error) {
	return []byte("data"), nil
}

type nodeTestClock struct{ mono, wall atomic.Int64 }

func newNodeClock() *nodeTestClock {
	c := &nodeTestClock{}
	c.mono.Store(100)
	c.wall.Store(1000)
	return c
}
func (c *nodeTestClock) now() float64     { return float64(c.mono.Load()) }
func (c *nodeTestClock) wallNow() float64 { return float64(c.wall.Load()) }
func nodeSpec(job string, epoch int64) ExecutionSpec {
	return ExecutionSpec{
		Identity:    ExecutionIdentity{JobID: job, AttemptID: "attempt", ComponentID: "owner", Epoch: epoch},
		ImageDigest: "sha256:" + strings.Repeat("a", 64), SourcePath: "/private/" + job + "/source", StatePath: "/private/" + job + "/state",
		ProxyEndpoint: "/private/p/socket", Resources: ResourceLimits{CPUMillis: 1000, MemoryBytes: 1024, DiskBytes: 64 * 1024 * 1024}, NodeID: "node", PoolID: "pool",
	}.Defaults()
}
func nodeCapacity(cpus, budgets int64) ResourceLimits {
	budget, _ := ExecutionStorageBudget(64 * 1024 * 1024)
	return ResourceLimits{CPUMillis: cpus * 1000, MemoryBytes: cpus * 1024, DiskBytes: budget * budgets, PIDs: 128, IOBPS: 16 * 1024 * 1024}
}
func nodeAgentForTest(t *testing.T, f *nodeFakeBackend, c *nodeTestClock, capacity ResourceLimits, ledger string, boot string) *NodeAgent {
	t.Helper()
	if err := os.Chmod(filepath.Dir(ledger), 0700); err != nil {
		t.Fatal(err)
	}
	if f.states == nil {
		f.states = map[string]string{}
	}
	a, err := NewNodeAgent(f, ledger, "node", "pool", capacity, WithNodeClocks(c.now, c.wallNow), WithNodeBootID(boot), WithWatchdogInterval(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.Close(); err != nil {
			t.Error(err)
		}
	})
	return a
}
func assertNodeCode(t *testing.T, err error, code string) {
	t.Helper()
	if ErrorCode(err) != code {
		t.Fatalf("expected %s, got %v (%s)", code, err, ErrorCode(err))
	}
}
func nodeOnlyRecord(t *testing.T, a *NodeAgent) map[string]any {
	t.Helper()
	rows, err := a.Inventory(context.Background())
	if err != nil || len(rows) != 1 {
		t.Fatalf("inventory %v %v", rows, err)
	}
	return rows[0]
}

func TestNodeReserveCommitsIntentBeforeEffectAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	f := &nodeFakeBackend{}
	c := newNodeClock()
	a := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), filepath.Join(t.TempDir(), "node.db"), "boot")
	sawIntent := false
	f.reserveHook = func(spec ExecutionSpec) { row := nodeOnlyRecord(t, a); sawIntent = row["state"] == "RESERVING" }
	spec := nodeSpec("one", 1)
	first, err := a.Reserve(ctx, spec)
	if err != nil || !first.Acknowledged || !sawIntent {
		t.Fatalf("reservation=%+v err=%v intent=%v", first, err, sawIntent)
	}
	if _, err = a.Reserve(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if f.reserveCalls != 1 {
		t.Fatalf("duplicate backend call %d", f.reserveCalls)
	}
	changed := spec
	changed.Resources.MemoryBytes++
	_, err = a.Reserve(ctx, changed)
	assertNodeCode(t, err, "reservation_conflict")
	if f.reserveCalls != 1 {
		t.Fatal("conflict reached backend")
	}
}
func TestNodeFailedReserveQuarantinesAndKeepsCapacityCharged(t *testing.T) {
	ctx := context.Background()
	f := &nodeFakeBackend{reserveErr: uncertain(errors.New("lost ack"))}
	c := newNodeClock()
	a := nodeAgentForTest(t, f, c, nodeCapacity(1, 3), filepath.Join(t.TempDir(), "node.db"), "boot")
	spec := nodeSpec("one", 1)
	_, err := a.Reserve(ctx, spec)
	if !IsUncertain(err) {
		t.Fatal(err)
	}
	if nodeOnlyRecord(t, a)["state"] != "QUARANTINED" {
		t.Fatal("not quarantined")
	}
	_, err = a.Reserve(ctx, spec)
	assertNodeCode(t, err, "node_quarantined")
	_, err = a.Reserve(ctx, nodeSpec("two", 1))
	assertNodeCode(t, err, "capacity")
	usage, err := a.StorageUsageBytes(ctx)
	budget, _ := ExecutionStorageBudget(spec.Resources.DiskBytes)
	if err != nil || usage != budget {
		t.Fatalf("usage=%d err=%v", usage, err)
	}
}
func TestNodeReleaseComputeRetainsDiskUntilPhysicalPurge(t *testing.T) {
	ctx := context.Background()
	f := &nodeFakeBackend{}
	c := newNodeClock()
	a := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), filepath.Join(t.TempDir(), "node.db"), "boot")
	one := nodeSpec("one", 1)
	two := nodeSpec("two", 1)
	if _, err := a.Reserve(ctx, one); err != nil {
		t.Fatal(err)
	}
	_, err := a.Reserve(ctx, two)
	assertNodeCode(t, err, "capacity")
	budget, _ := ExecutionStorageBudget(one.Resources.DiskBytes)
	if ok, err := a.Release(ctx, one.Identity); err != nil || !ok {
		t.Fatalf("release %v %v", ok, err)
	}
	if usage, err := a.StorageUsageBytes(ctx); err != nil || usage != budget {
		t.Fatalf("retained usage %d %v", usage, err)
	}
	if _, err = a.Reserve(ctx, two); err != nil {
		t.Fatal(err)
	}
	if ok, err := a.Purge(ctx, one.Identity); err != nil || !ok {
		t.Fatalf("purge %v %v", ok, err)
	}
	if usage, err := a.StorageUsageBytes(ctx); err != nil || usage != budget {
		t.Fatalf("purged usage %d %v", usage, err)
	}
}
func TestNodeExpiredLeaseStopsButDoesNotReleaseAndCannotRenew(t *testing.T) {
	ctx := context.Background()
	f := &nodeFakeBackend{}
	c := newNodeClock()
	a := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), filepath.Join(t.TempDir(), "node.db"), "boot")
	spec := nodeSpec("one", 1)
	if _, err := a.Reserve(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Start(ctx, spec.Identity); err != nil {
		t.Fatal(err)
	}
	c.mono.Store(221)
	c.wall.Store(1)
	expired, err := a.WatchdogOnce(ctx)
	if err != nil || len(expired) != 1 || f.stopCalls != 1 {
		t.Fatalf("watchdog=%v err=%v stops=%d", expired, err, f.stopCalls)
	}
	if nodeOnlyRecord(t, a)["state"] != "STOPPED" {
		t.Fatal("not stopped")
	}
	assertNodeCode(t, a.Renew(ctx, spec.Identity), "lease_expired")
	_, err = a.Reserve(ctx, nodeSpec("two", 1))
	assertNodeCode(t, err, "capacity")
}
func TestNodeStartStopsIfLeaseExpiresDuringLaunch(t *testing.T) {
	ctx := context.Background()
	f := &nodeFakeBackend{}
	c := newNodeClock()
	a := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), filepath.Join(t.TempDir(), "node.db"), "boot")
	spec := nodeSpec("one", 1)
	if _, err := a.Reserve(ctx, spec); err != nil {
		t.Fatal(err)
	}
	f.startHook = func() { c.mono.Store(500) }
	_, err := a.Start(ctx, spec.Identity)
	assertNodeCode(t, err, "lease_expired")
	if f.stopCalls != 1 || nodeOnlyRecord(t, a)["state"] != "STOPPED" {
		t.Fatal("late launch escaped stop")
	}
}
func TestNodeBootChangeFencesPersistedLease(t *testing.T) {
	ctx := context.Background()
	f := &nodeFakeBackend{}
	c := newNodeClock()
	ledger := filepath.Join(t.TempDir(), "node.db")
	a := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), ledger, "boot-a")
	spec := nodeSpec("one", 1)
	if _, err := a.Reserve(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	c.mono.Store(1)
	b := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), ledger, "boot-b")
	_, err := b.Start(ctx, spec.Identity)
	assertNodeCode(t, err, "lease_expired")
	expired, err := b.WatchdogOnce(ctx)
	if err != nil || len(expired) != 1 {
		t.Fatalf("boot watchdog=%v %v", expired, err)
	}
}
func TestNodeEpochFenceRejectsOldWriterAndSharedPurge(t *testing.T) {
	ctx := context.Background()
	f := &nodeFakeBackend{}
	c := newNodeClock()
	a := nodeAgentForTest(t, f, c, nodeCapacity(1, 3), filepath.Join(t.TempDir(), "node.db"), "boot")
	one := nodeSpec("one", 1)
	if _, err := a.Reserve(ctx, one); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ChargeSharedAuxiliaryBytes(ctx, one.Identity, 1024); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Release(ctx, one.Identity); err != nil {
		t.Fatal(err)
	}
	two := nodeSpec("one", 2)
	two.Identity.AttemptID = "attempt-two"
	if _, err := a.Reserve(ctx, two); err != nil {
		t.Fatal(err)
	}
	assertNodeCode(t, a.Renew(ctx, one.Identity), "stale_epoch")
	_, err := a.PurgeWithAuxiliary(ctx, one.Identity, true)
	assertNodeCode(t, err, "runtime_active")
	_, err = a.Reserve(ctx, one)
	assertNodeCode(t, err, "stale_epoch")
}
func TestNodeAuxiliaryStorageNeedsConfirmedSharedCleanup(t *testing.T) {
	ctx := context.Background()
	f := &nodeFakeBackend{}
	c := newNodeClock()
	a := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), filepath.Join(t.TempDir(), "node.db"), "boot")
	one := nodeSpec("one", 1)
	if _, err := a.Reserve(ctx, one); err != nil {
		t.Fatal(err)
	}
	if ok, err := a.ChargeAuxiliaryBytes(ctx, one.Identity, 512); err != nil || !ok {
		t.Fatal(err)
	}
	if ok, err := a.ChargeSharedAuxiliaryBytes(ctx, one.Identity, 2048); err != nil || !ok {
		t.Fatal(err)
	}
	if _, err := a.Release(ctx, one.Identity); err != nil {
		t.Fatal(err)
	}
	_, err := a.Purge(ctx, one.Identity)
	assertNodeCode(t, err, "auxiliary_storage_retained")
	if f.purgeCalls != 0 {
		t.Fatal("purge before shared cleanup")
	}
	if ok, err := a.PurgeWithAuxiliary(ctx, one.Identity, true); err != nil || !ok {
		t.Fatalf("purge=%v %v", ok, err)
	}
	if usage, err := a.StorageUsageBytes(ctx); err != nil || usage != 0 {
		t.Fatalf("usage %d %v", usage, err)
	}
	_, err = a.ChargeAuxiliaryBytes(ctx, one.Identity, 1024)
	assertNodeCode(t, err, "invalid_execution_state")
}
func TestNodeUnknownStopKeepsQuarantineAndPreventsRelease(t *testing.T) {
	ctx := context.Background()
	f := &nodeFakeBackend{}
	c := newNodeClock()
	a := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), filepath.Join(t.TempDir(), "node.db"), "boot")
	one := nodeSpec("one", 1)
	if _, err := a.Reserve(ctx, one); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Start(ctx, one.Identity); err != nil {
		t.Fatal(err)
	}
	f.errorStop = uncertain(errors.New("timeout"))
	if _, err := a.Stop(ctx, one.Identity, 0); !IsUncertain(err) {
		t.Fatal(err)
	}
	if nodeOnlyRecord(t, a)["state"] != "QUARANTINED" {
		t.Fatal("not quarantined")
	}
	if _, err := a.Release(ctx, one.Identity); !IsUncertain(err) {
		t.Fatal(err)
	}
	if f.releaseCalls != 0 {
		t.Fatal("released active runtime")
	}
}
func TestNodeReservationUsesCrossProcessLedgerCapacity(t *testing.T) {
	ctx := context.Background()
	f := &nodeFakeBackend{}
	c := newNodeClock()
	ledger := filepath.Join(t.TempDir(), "node.db")
	a := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), ledger, "boot")
	b := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), ledger, "boot")
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for n, agent := range []*NodeAgent{a, b} {
		wg.Add(1)
		go func(n int, agent *NodeAgent) {
			defer wg.Done()
			_, err := agent.Reserve(ctx, nodeSpec([]string{"one", "two"}[n], 1))
			results <- err
		}(n, agent)
	}
	wg.Wait()
	close(results)
	success, capacity := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if ErrorCode(err) == "capacity" {
			capacity++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || capacity != 1 || f.reserveCalls != 1 {
		t.Fatalf("success=%d capacity=%d calls=%d", success, capacity, f.reserveCalls)
	}
}
func TestNodeSameReservationSerializedAcrossAgents(t *testing.T) {
	ctx := context.Background()
	f := &nodeFakeBackend{}
	c := newNodeClock()
	ledger := filepath.Join(t.TempDir(), "node.db")
	a := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), ledger, "boot")
	b := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), ledger, "boot")
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, agent := range []*NodeAgent{a, b} {
		wg.Add(1)
		go func(agent *NodeAgent) { defer wg.Done(); _, err := agent.Reserve(ctx, nodeSpec("one", 1)); errs <- err }(agent)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.reserveCalls != 1 {
		t.Fatalf("duplicate external effect %d", f.reserveCalls)
	}
}
func TestNodeCollectionBoundAndActiveReadRefusal(t *testing.T) {
	ctx := context.Background()
	f := &nodeFakeBackend{}
	c := newNodeClock()
	a := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), filepath.Join(t.TempDir(), "node.db"), "boot")
	one := nodeSpec("one", 1)
	if _, err := a.Reserve(ctx, one); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Start(ctx, one.Identity); err != nil {
		t.Fatal(err)
	}
	_, err := a.Collect(ctx, one.Identity)
	assertNodeCode(t, err, "runtime_active")
	if _, err = a.Stop(ctx, one.Identity, 0); err != nil {
		t.Fatal(err)
	}
	f.artifacts = []CollectedArtifact{{Path: "oversize", SizeBytes: one.Resources.DiskBytes + StorageHeadroomBytes + 1}}
	_, err = a.Collect(ctx, one.Identity)
	assertNodeCode(t, err, "retention_capacity")
	if nodeOnlyRecord(t, a)["retained_output_bytes"] != int64(0) {
		t.Fatal("charged rejected collection")
	}
}
func TestNodeRejectsUnsafeLedgerAndGuardFiles(t *testing.T) {
	f := &nodeFakeBackend{states: map[string]string{}}
	c := newNodeClock()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "node.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err := NewNodeAgent(f, link, "node", "pool", nodeCapacity(1, 2), WithNodeClocks(c.now, c.wallNow), WithNodeBootID("boot"))
	assertNodeCode(t, err, "unsafe_root")
	if err = os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(target, link); err != nil {
		t.Fatal(err)
	}
	_, err = NewNodeAgent(f, link, "node", "pool", nodeCapacity(1, 2), WithNodeClocks(c.now, c.wallNow), WithNodeBootID("boot"))
	assertNodeCode(t, err, "unsafe_root")
	if err = os.Remove(link); err != nil {
		t.Fatal(err)
	}
	a := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), link, "boot")
	if err = os.Mkdir(a.guardRoot, 0700); err != nil {
		t.Fatal(err)
	}
	spec := nodeSpec("one", 1)
	guard := filepath.Join(a.guardRoot, "component-"+nodeComponentKey(spec.Identity)+".lock")
	if err = os.Symlink(target, guard); err != nil {
		t.Fatal(err)
	}
	_, err = a.Reserve(context.Background(), spec)
	assertNodeCode(t, err, "unsafe_root")
	if f.reserveCalls != 0 {
		t.Fatal("unsafe guard reached backend")
	}
}
func TestNodeMigratesLegacyLedgerColumns(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ledger := filepath.Join(dir, "node.db")
	db, err := sql.Open("sqlite", ledger)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE executions(execution_key TEXT PRIMARY KEY,job_id TEXT NOT NULL,attempt_id TEXT NOT NULL,component_id TEXT NOT NULL,epoch INTEGER NOT NULL,spec TEXT NOT NULL,state TEXT NOT NULL,cpu_millis INTEGER NOT NULL,memory_bytes INTEGER NOT NULL,disk_bytes INTEGER NOT NULL,lease_until REAL NOT NULL,deadline REAL,boot_id TEXT NOT NULL,stopped INTEGER NOT NULL DEFAULT 0)`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err = os.Chmod(ledger, 0600); err != nil {
		t.Fatal(err)
	}
	a := nodeAgentForTest(t, &nodeFakeBackend{}, newNodeClock(), nodeCapacity(1, 2), ledger, "boot")
	if _, err = a.Reserve(ctx, nodeSpec("one", 1)); err != nil {
		t.Fatal(err)
	}
	row := nodeOnlyRecord(t, a)
	if row["disk_released"] != int64(0) || row["auxiliary_bytes"] != int64(0) {
		t.Fatal(row)
	}
}
func TestNodeDeadlineAndNodeBindingsFailBeforeEffects(t *testing.T) {
	ctx := context.Background()
	f := &nodeFakeBackend{}
	c := newNodeClock()
	a := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), filepath.Join(t.TempDir(), "node.db"), "boot")
	spec := nodeSpec("one", 1)
	spec.NodeID = "other"
	_, err := a.Reserve(ctx, spec)
	assertNodeCode(t, err, "node_mismatch")
	spec.NodeID = "node"
	spec.PoolID = "other"
	_, err = a.Reserve(ctx, spec)
	assertNodeCode(t, err, "pool_mismatch")
	spec.PoolID = "pool"
	deadline := 999.0
	spec.Deadline = &deadline
	_, err = a.Reserve(ctx, spec)
	assertNodeCode(t, err, "job_deadline_expired")
	if f.reserveCalls != 0 {
		t.Fatal("rejected spec reached backend")
	}
}

func TestNodeWatchdogRechecksRenewalAfterItsInventorySnapshot(t *testing.T) {
	ctx := context.Background()
	f := &nodeFakeBackend{}
	c := newNodeClock()
	var block atomic.Bool
	entered := make(chan struct{})
	resumed := make(chan struct{})
	clock := func() float64 {
		if block.CompareAndSwap(true, false) {
			close(entered)
			<-resumed
		}
		return c.now()
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	f.states = map[string]string{}
	a, err := NewNodeAgent(f, filepath.Join(dir, "node.db"), "node", "pool", nodeCapacity(1, 2), WithNodeClocks(clock, c.wallNow), WithNodeBootID("boot"), WithWatchdogInterval(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	spec := nodeSpec("one", 1)
	if _, err = a.Reserve(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Start(ctx, spec.Identity); err != nil {
		t.Fatal(err)
	}
	c.mono.Store(219)
	block.Store(true)
	type outcome struct {
		expired []ExecutionIdentity
		err     error
	}
	done := make(chan outcome, 1)
	go func() { expired, err := a.WatchdogOnce(ctx); done <- outcome{expired, err} }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("watchdog did not reach snapshot")
	}
	if err = a.Renew(ctx, spec.Identity); err != nil {
		close(resumed)
		t.Fatal(err)
	}
	c.mono.Store(221)
	close(resumed)
	result := <-done
	if result.err != nil || len(result.expired) != 0 || f.stopCalls != 0 {
		t.Fatalf("renewed execution stopped: %+v calls=%d", result, f.stopCalls)
	}
	if nodeOnlyRecord(t, a)["state"] != "RUNNING" {
		t.Fatal("renewed job lost running state")
	}
}
func TestNodeStopIntentCannotBeRenewed(t *testing.T) {
	ctx := context.Background()
	f := &nodeFakeBackend{}
	c := newNodeClock()
	a := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), filepath.Join(t.TempDir(), "node.db"), "boot")
	spec := nodeSpec("one", 1)
	if _, err := a.Reserve(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.ExecContext(ctx, "UPDATE executions SET state='STOPPING' WHERE execution_key=?", spec.Identity.Key()); err != nil {
		t.Fatal(err)
	}
	assertNodeCode(t, a.Renew(ctx, spec.Identity), "lease_expired")
}

func TestNodeStopMissingReservationRequiresPositivePhysicalAbsence(t *testing.T) {
	ctx := context.Background()
	f := &nodeFakeBackend{reserveErr: uncertain(errors.New("lost reservation"))}
	c := newNodeClock()
	a := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), filepath.Join(t.TempDir(), "node.db"), "boot")
	spec := nodeSpec("one", 1)
	if _, err := a.Reserve(ctx, spec); !IsUncertain(err) {
		t.Fatal(err)
	}
	if _, err := a.Stop(ctx, spec.Identity, 0); err == nil {
		t.Fatal("missing reservation became proof of stop")
	}
	if nodeOnlyRecord(t, a)["state"] != "QUARANTINED" {
		t.Fatal("uncertainty lost quarantine")
	}
	f.absence = true
	observed, err := a.Stop(ctx, spec.Identity, 0)
	if err != nil || !observed.TerminationConfirmed || observed.Details["never_reserved"] != true {
		t.Fatalf("stop %+v %v", observed, err)
	}
	if _, err = a.Release(ctx, spec.Identity); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Purge(ctx, spec.Identity); err != nil {
		t.Fatal(err)
	}
	if f.releaseCalls != 0 || f.purgeCalls != 0 {
		t.Fatal("absent executor received owned-runtime deletion")
	}
	if used, err := a.StorageUsageBytes(ctx); err != nil || used != 0 {
		t.Fatalf("usage=%d %v", used, err)
	}
}
func TestNodeLegacyASCIIJSONReservationCanBeReplayed(t *testing.T) {
	ctx := context.Background()
	f := &nodeFakeBackend{}
	c := newNodeClock()
	a := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), filepath.Join(t.TempDir(), "node.db"), "boot")
	spec := nodeSpec("one", 1)
	spec.SourcePath = "/private/one/café"
	if _, err := a.Reserve(ctx, spec); err != nil {
		t.Fatal(err)
	}
	canonical, err := spec.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	// The canonical execution wire uses Python-style ASCII escaping. Readers must
	// also accept an otherwise identical raw UTF-8 JSON representation.
	utf8JSON := strings.ReplaceAll(string(canonical), string(rune(92))+"u00e9", "é")
	if utf8JSON == string(canonical) {
		t.Fatal("canonical fixture lacks expected ASCII escape")
	}
	for _, stored := range []string{string(canonical), utf8JSON} {
		if _, err = a.db.ExecContext(ctx, "UPDATE executions SET spec=? WHERE execution_key=?", stored, spec.Identity.Key()); err != nil {
			t.Fatal(err)
		}
		if _, err = a.Reserve(ctx, spec); err != nil {
			t.Fatal(err)
		}
	}
	if f.reserveCalls != 1 {
		t.Fatal("legacy replay repeated reservation")
	}
}

func TestNodeComponentGuardSupportsNestedReserveAndPurge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f := &nodeFakeBackend{}
	c := newNodeClock()
	a := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), filepath.Join(t.TempDir(), "node.db"), "boot")
	spec := nodeSpec("one", 1)
	err := a.WithComponentGuardContext(ctx, spec.Identity, false, func(nested context.Context) error {
		_, err := a.Reserve(nested, spec)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.ChargeSharedAuxiliaryBytes(ctx, spec.Identity, 1024); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Release(ctx, spec.Identity); err != nil {
		t.Fatal(err)
	}
	err = a.WithComponentGuardContext(ctx, spec.Identity, true, func(nested context.Context) error {
		// A materializer confirms its own bounded inputs have been removed here.
		_, err := a.PurgeWithAuxiliary(nested, spec.Identity, true)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if used, err := a.StorageUsageBytes(ctx); err != nil || used != 0 {
		t.Fatalf("used=%d %v", used, err)
	}
}
func TestNodeExpiredGuardContextCannotBypassANewOwner(t *testing.T) {
	ctx := context.Background()
	f := &nodeFakeBackend{}
	c := newNodeClock()
	a := nodeAgentForTest(t, f, c, nodeCapacity(1, 2), filepath.Join(t.TempDir(), "node.db"), "boot")
	id := nodeSpec("one", 1).Identity
	var expired context.Context
	if err := a.WithComponentGuardContext(ctx, id, false, func(nested context.Context) error { expired = nested; return nil }); err != nil {
		t.Fatal(err)
	}
	release, err := a.guard(ctx, "component", nodeComponentKey(id))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	deadline, cancel := context.WithTimeout(expired, 30*time.Millisecond)
	defer cancel()
	invoked := false
	err = a.WithComponentGuardContext(deadline, id, false, func(context.Context) error { invoked = true; return nil })
	if !errors.Is(err, context.DeadlineExceeded) || invoked {
		t.Fatalf("expired token bypassed owner: invoked=%v err=%v", invoked, err)
	}
}
