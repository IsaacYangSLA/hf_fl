package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

type ctlFakeExecutor struct {
	releaseErrorOnce                bool
	observed                        map[string]executor.RuntimeObservation
	reserved                        map[string]executor.ExecutionSpec
	calls                           []string
	stopConfirmed, releaseConfirmed bool
	startHook                       func()
	storage                         *ctlFakeStorage
}

func (e *ctlFakeExecutor) Reserve(ctx context.Context, s executor.ExecutionSpec) (executor.Reservation, error) {
	e.calls = append(e.calls, "reserve:"+s.Identity.ComponentID)
	e.reserved[s.Identity.ComponentID] = s
	e.observed[s.Identity.ComponentID] = executor.RuntimeObservation{Identity: s.Identity, State: "RESERVED", PublicationStatus: "none"}
	return executor.Reservation{Identity: s.Identity, Acknowledged: true, State: "RESERVED"}, nil
}
func (e *ctlFakeExecutor) Start(ctx context.Context, id executor.ExecutionIdentity) (executor.RuntimeObservation, error) {
	e.calls = append(e.calls, "start:"+id.ComponentID)
	if e.startHook != nil {
		e.startHook()
	}
	o := executor.RuntimeObservation{Identity: id, State: "RUNNING", PublicationStatus: "none"}
	e.observed[id.ComponentID] = o
	return o, nil
}
func (e *ctlFakeExecutor) Inspect(ctx context.Context, id executor.ExecutionIdentity) (executor.RuntimeObservation, error) {
	o, ok := e.observed[id.ComponentID]
	if !ok {
		o = executor.RuntimeObservation{Identity: id, State: "RUNNING", PublicationStatus: "none"}
	}
	return o, nil
}
func (e *ctlFakeExecutor) Stop(ctx context.Context, id executor.ExecutionIdentity, grace int) (executor.RuntimeObservation, error) {
	e.calls = append(e.calls, "stop:"+id.ComponentID)
	if grace != 60 {
		return executor.RuntimeObservation{}, errors.New("wrong stop grace")
	}
	return executor.RuntimeObservation{Identity: id, State: "STOPPED", TerminationConfirmed: e.stopConfirmed, PublicationStatus: "none"}, nil
}
func (e *ctlFakeExecutor) Renew(context.Context, executor.ExecutionIdentity) error { return nil }
func (e *ctlFakeExecutor) Collect(ctx context.Context, id executor.ExecutionIdentity) ([]executor.CollectedArtifact, error) {
	e.calls = append(e.calls, "collect:"+id.ComponentID)
	if e.storage != nil && !e.storage.reserved {
		return nil, errors.New("collection before storage reservation")
	}
	return []executor.CollectedArtifact{}, nil
}
func (e *ctlFakeExecutor) Release(ctx context.Context, id executor.ExecutionIdentity) (bool, error) {
	e.calls = append(e.calls, "release:"+id.ComponentID)
	if e.releaseErrorOnce {
		e.releaseErrorOnce = false
		return false, domain.Err(503, "execution_unknown")
	}
	if e.storage != nil && !e.storage.retained {
		return false, errors.New("release before retained-state charge")
	}
	return e.releaseConfirmed, nil
}
func (e *ctlFakeExecutor) Purge(ctx context.Context, id executor.ExecutionIdentity) (bool, error) {
	e.calls = append(e.calls, "purge:"+id.ComponentID)
	return e.releaseConfirmed, nil
}

type ctlFakeProvisioner struct {
	round                     int64
	revoked, cleanupConfirmed bool
	publication               PublicationObservation
	calls                     []string
	reconcileHook             func()
	ensureCheck               func() error
}

func (p *ctlFakeProvisioner) CurrentRound(context.Context, map[string]any) (int64, error) {
	return p.round, nil
}
func (p *ctlFakeProvisioner) Plan(ctx context.Context, job, attempt map[string]any, remaining int64) (map[string]executor.ExecutionSpec, error) {
	specs := map[string]executor.ExecutionSpec{}
	for _, value := range array(obj(job["spec_json"])["components"]) {
		component := obj(value)
		resource := obj(component["resources"])
		id := executor.ExecutionIdentity{JobID: str(job["id"]), AttemptID: str(attempt["id"]), ComponentID: str(component["component_id"]), Epoch: num(attempt["epoch"])}
		role := str(component["role"])
		if role == "participant" {
			role = "client"
		}
		specs[id.ComponentID] = executor.ExecutionSpec{Identity: id, PoolID: str(resource["pool_id"]), Role: role, ImageDigest: "sha256:" + strings.Repeat("b", 64), Resources: executor.ResourceLimits{CPUMillis: num(resource["cpu_millicores"]), MemoryBytes: num(resource["memory_bytes"]), DiskBytes: num(resource["disk_bytes"]), PIDs: 128, IOBPS: 16777216}, ProxyEndpoint: "/assigned/proxy.sock", Profile: "runsc-cpu-v1", Argv: []string{"python", "-m", "hf2l_jobs.runtime", "--config", "/run/hf2l/runtime.json"}, LeaseSeconds: 120}
	}
	return specs, nil
}
func (p *ctlFakeProvisioner) Ensure(context.Context, map[string]any, map[string]any, int64) error {
	p.calls = append(p.calls, "ensure")
	if p.ensureCheck != nil {
		return p.ensureCheck()
	}
	return nil
}
func (p *ctlFakeProvisioner) Revoke(context.Context, map[string]any, map[string]any) (bool, error) {
	p.calls = append(p.calls, "revoke")
	return p.revoked, nil
}
func (p *ctlFakeProvisioner) Reconcile(context.Context, map[string]any, map[string]any) (PublicationObservation, error) {
	p.calls = append(p.calls, "reconcile")
	if p.reconcileHook != nil {
		p.reconcileHook()
	}
	return p.publication, nil
}
func (p *ctlFakeProvisioner) Cleanup(context.Context, map[string]any, map[string]any) (bool, error) {
	p.calls = append(p.calls, "cleanup")
	return p.cleanupConfirmed, nil
}
func (p *ctlFakeProvisioner) PurgeJob(context.Context, map[string]any) (bool, error) {
	return p.cleanupConfirmed, nil
}
func (p *ctlFakeProvisioner) ExpireArtifacts(context.Context, map[string]any) (bool, error) {
	return p.cleanupConfirmed, nil
}
func (p *ctlFakeProvisioner) PrepareBuildOutputs(context.Context, map[string]any, map[string]any, map[string][]executor.CollectedArtifact) (bool, error) {
	p.calls = append(p.calls, "build-prepared")
	return true, nil
}

type ctlFakeStorage struct {
	retainHook                          func() error
	retainError                         error
	reserved, stored, retained, deleted bool
	logData                             string
}

func (*ctlFakeStorage) RequestExpiry(context.Context) error { return nil }
func (s *ctlFakeStorage) ReserveCollection(context.Context, map[string]any, map[string]any, map[string]any) error {
	s.reserved = true
	return nil
}
func (s *ctlFakeStorage) StoreCollected(context.Context, map[string]any, map[string]any, map[string]any, []executor.CollectedArtifact) error {
	if !s.reserved {
		return errors.New("missing reservation")
	}
	s.stored = true
	return nil
}
func (s *ctlFakeStorage) RetainExecutionState(context.Context, map[string]any, map[string]any, map[string]any) error {
	if !s.stored {
		return errors.New("missing collection")
	}
	if s.retainHook != nil {
		if e := s.retainHook(); e != nil {
			return e
		}
	}
	if s.retainError != nil {
		return s.retainError
	}
	s.retained = true
	return nil
}
func (*ctlFakeStorage) IngestLogs(context.Context, map[string]any, bool) error { return nil }
func (s *ctlFakeStorage) ConfirmJobDataDeleted(context.Context, string) error {
	s.deleted = true
	return nil
}
func (s *ctlFakeStorage) AppendLogsInTransaction(ctx context.Context, tx *store.Tx, job, attempt, allocation map[string]any, data string) error {
	s.logData = data
	return nil
}

type ctlFixture struct {
	*publicationTestFixture
	c       *Controller
	e       *ctlFakeExecutor
	p       *ctlFakeProvisioner
	storage *ctlFakeStorage
	now     time.Time
}

func newCtlFixture(t *testing.T, state string) *ctlFixture {
	t.Helper()
	f := &ctlFixture{publicationTestFixture: publicationTestFixtureNew(t, false), now: time.Date(2026, 10, 23, 16, 0, 0, 0, time.UTC)}
	f.storage = &ctlFakeStorage{}
	f.e = &ctlFakeExecutor{observed: map[string]executor.RuntimeObservation{}, reserved: map[string]executor.ExecutionSpec{}, stopConfirmed: true, releaseConfirmed: true, storage: f.storage}
	round := int64(0)
	f.p = &ctlFakeProvisioner{revoked: true, cleanupConfirmed: true, publication: PublicationObservation{Known: true, Status: "absent", CurrentRound: &round}}
	f.c = New(f.db, f.e, f.p)
	f.c.Storage = f.storage
	f.c.Clock = func() time.Time { return f.now }
	attemptState := state
	epoch := int64(1)
	if state == "CANCELLING" {
		attemptState = "QUEUED"
		epoch = 0
	}
	if state == "RECONCILING" {
		attemptState = "RUNNING"
	}
	f.update(t, "jm_jobs", "job", map[string]any{"state": state, "epoch": epoch, "deadline_at": f.now.Add(time.Hour), "created_at": f.now, "updated_at": f.now, "phase": "training"})
	values := map[string]any{"state": attemptState, "revocation_confirmed": false, "termination_confirmed": false, "publication_status": "none", "details_json": map[string]any{}}
	if state != "CANCELLING" {
		values["heartbeat_at"] = f.now
	}
	f.update(t, "jm_attempts", "attempt", values)
	f.update(t, "jm_allocations", "allocation", map[string]any{"state": "RESERVED", "acknowledged": false, "termination_confirmed": false})
	if _, e := f.db.Exec(f.ctx, "DELETE FROM jm_provisioning_operations WHERE job_id='job'"); e != nil {
		t.Fatal(e)
	}
	if state == "CANCELLING" {
		if _, e := f.db.Exec(f.ctx, "DELETE FROM jm_allocations WHERE job_id='job'"); e != nil {
			t.Fatal(e)
		}
	}
	return f
}
func (f *ctlFixture) row(t *testing.T, table string) map[string]any {
	t.Helper()
	id := "job"
	if table == "jm_attempts" {
		id = "attempt"
	}
	row, e := f.db.One(f.ctx, "SELECT * FROM "+table+" WHERE id=?", id)
	if e != nil {
		t.Fatal(e)
	}
	return row
}
func (f *ctlFixture) claim(t *testing.T, topic string, payload map[string]any) Claim {
	t.Helper()
	id := fmtNewID()
	owner := f.c.ControllerID + ":" + fmtNewID()
	until := f.now.Add(5 * time.Minute)
	e := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
		return tx.Insert(f.ctx, "jm_outbox", map[string]any{"id": id, "job_id": "job", "attempt_id": "attempt", "attempt_number": int64(1), "topic": topic, "payload_json": payload, "idempotency_key": id, "state": "processing", "lease_owner": owner, "lease_until": until, "created_at": f.now})
	})
	if e != nil {
		t.Fatal(e)
	}
	return Claim{ID: id, JobID: "job", AttemptID: "attempt", AttemptNumber: 1, Topic: topic, Owner: owner, Payload: payload, LeaseUntil: until}
}
func (f *ctlFixture) reserved(t *testing.T) {
	t.Helper()
	f.update(t, "jm_allocations", "allocation", map[string]any{"acknowledged": true, "state": "RUNNING"})
	if e := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
		return tx.Insert(f.ctx, "jm_provisioning_operations", map[string]any{"id": fmtNewID(), "job_id": "job", "attempt_id": "attempt", "component_id": "owner", "operation": "reserve", "idempotency_key": "job:attempt:1:owner:reserve", "state": "confirmed", "desired_json": map[string]any{"epoch": int64(1)}})
	}); e != nil {
		t.Fatal(e)
	}
}
func fmtNewID() string { return domain.NewID() }

func TestControllerDispatchAcknowledgesBeforeProvisioning(t *testing.T) {
	f := newCtlFixture(t, "PROVISIONING")
	f.p.ensureCheck = func() error {
		if len(f.e.reserved) != 1 {
			return errors.New("unacknowledged gang")
		}
		return nil
	}
	done, e := f.c.processClaim(f.ctx, f.claim(t, "dispatch", map[string]any{"epoch": int64(1)}))
	if e != nil || !done {
		t.Fatal(done, e)
	}
	if str(f.row(t, "jm_jobs")["state"]) != "RUNNING" {
		t.Fatal("job not running")
	}
	row, _ := f.db.One(f.ctx, "SELECT * FROM jm_allocations WHERE id='allocation'")
	if !flag(row["acknowledged"]) {
		t.Fatal("acknowledgement missing")
	}
}
func TestControllerUnknownPublicationRetainsCapacity(t *testing.T) {
	f := newCtlFixture(t, "RECONCILING")
	f.reserved(t)
	f.p.publication = PublicationObservation{Known: false, Status: "unknown"}
	done, e := f.c.processClaim(f.ctx, f.claim(t, "fence_stop", map[string]any{"transient": true}))
	if e != nil || !done {
		t.Fatal(done, e)
	}
	if str(f.row(t, "jm_jobs")["state"]) != "NEEDS_ATTENTION" {
		t.Fatal("unknown publication was replayed")
	}
	for _, call := range f.e.calls {
		if strings.HasPrefix(call, "release:") {
			t.Fatal("released unresolved publication")
		}
	}
	row, _ := f.db.One(f.ctx, "SELECT * FROM jm_allocations WHERE id='allocation'")
	if str(row["state"]) == "RELEASED" || row["released_at"] != nil {
		t.Fatal("premature quota release")
	}
}
func TestControllerUnconfirmedFencingRetainsGang(t *testing.T) {
	for _, barrier := range []string{"revocation", "termination"} {
		t.Run(barrier, func(t *testing.T) {
			f := newCtlFixture(t, "RECONCILING")
			f.reserved(t)
			if barrier == "revocation" {
				f.p.revoked = false
			} else {
				f.e.stopConfirmed = false
			}
			_, e := f.c.processClaim(f.ctx, f.claim(t, "fence_stop", map[string]any{}))
			if e != nil {
				t.Fatal(e)
			}
			if barrier == "revocation" && len(f.e.calls) > 0 {
				t.Fatal("stopped before revocation")
			}
			for _, call := range f.p.calls {
				if call == "reconcile" {
					t.Fatal("reconciled unfenced execution")
				}
			}
			row, _ := f.db.One(f.ctx, "SELECT * FROM jm_allocations WHERE id='allocation'")
			if row["released_at"] != nil {
				t.Fatal("unconfirmed execution freed capacity")
			}
		})
	}
}
func TestControllerCollectionAndRetainedStatePrecedeRelease(t *testing.T) {
	f := newCtlFixture(t, "RECONCILING")
	f.reserved(t)
	round := int64(1)
	f.p.publication = PublicationObservation{Known: true, Status: "confirmed", CurrentRound: &round}
	done, e := f.c.processClaim(f.ctx, f.claim(t, "fence_stop", map[string]any{"success": true}))
	if e != nil || !done {
		t.Fatal(done, e)
	}
	if str(f.row(t, "jm_jobs")["state"]) != "SUCCEEDED" || !f.storage.retained {
		t.Fatal("did not retain completion state")
	}
	row, _ := f.db.One(f.ctx, "SELECT * FROM jm_allocations WHERE id='allocation'")
	if str(row["state"]) != "RELEASED" || !flag(row["termination_confirmed"]) {
		t.Fatal("release lacks positive termination")
	}
}
func TestControllerCancellationWinsInflightSuccess(t *testing.T) {
	f := newCtlFixture(t, "RECONCILING")
	f.reserved(t)
	round := int64(1)
	f.p.publication = PublicationObservation{Known: true, Status: "confirmed", CurrentRound: &round}
	f.p.reconcileHook = func() { f.update(t, "jm_jobs", "job", map[string]any{"state": "CANCELLING"}) }
	_, e := f.c.processClaim(f.ctx, f.claim(t, "fence_stop", map[string]any{"success": true}))
	if e != nil {
		t.Fatal(e)
	}
	if str(f.row(t, "jm_jobs")["state"]) != "CANCELLED" {
		t.Fatal("late success overrode cancellation")
	}
}
func TestControllerQueuedCancellationNeedsCompleteAbsenceProof(t *testing.T) {
	for _, tainted := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty-ledger", true: "unknown-effect"}[tainted], func(t *testing.T) {
			f := newCtlFixture(t, "CANCELLING")
			if tainted {
				if e := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
					return tx.Insert(f.ctx, "jm_provisioning_operations", map[string]any{"id": fmtNewID(), "job_id": "job", "attempt_id": "attempt", "component_id": "owner", "operation": "reserve", "idempotency_key": fmtNewID(), "state": "unknown"})
				}); e != nil {
					t.Fatal(e)
				}
			}
			_, e := f.c.processClaim(f.ctx, f.claim(t, "fence_stop", map[string]any{}))
			if e != nil {
				t.Fatal(e)
			}
			expected := "CANCELLED"
			if tainted {
				expected = "NEEDS_ATTENTION"
			}
			if str(f.row(t, "jm_jobs")["state"]) != expected {
				t.Fatal("unsafe absence proof")
			}
			if !tainted {
				attempt := f.row(t, "jm_attempts")
				if !flag(attempt["revocation_confirmed"]) || !flag(attempt["termination_confirmed"]) {
					t.Fatal("absence proof not persisted")
				}
			}
		})
	}
}
func TestControllerReplacedClaimCannotDispatchOrFinish(t *testing.T) {
	f := newCtlFixture(t, "RUNNING")
	claim := f.claim(t, "fence_stop", map[string]any{})
	f.now = f.now.Add(6 * time.Minute)
	other := New(f.db, f.e, f.p)
	other.Clock = f.c.Clock
	successor, e := other.ClaimNext(f.ctx, []string{"fence_stop"})
	if e != nil || successor == nil {
		t.Fatal(e)
	}
	if e = f.c.FinishClaim(f.ctx, claim, true, ""); e != nil {
		t.Fatal(e)
	}
	row, e := f.db.One(f.ctx, "SELECT * FROM jm_outbox WHERE id=?", claim.ID)
	if e != nil {
		t.Fatal(e)
	}
	if str(row["lease_owner"]) != successor.Owner || str(row["state"]) != "processing" {
		t.Fatal("stale finish changed successor")
	}
	job, attempt, _, _ := f.c.snapshot(f.ctx, "job", "attempt")
	called := false
	_, e = f.c.operation(f.ctx, claim, job, attempt, "owner", "never-run", nil, func() (any, error) { called = true; return true, nil })
	if code(e) != "stale_claim" || called {
		t.Fatal("stale claim performed external effect")
	}
}
func TestControllerHeartbeatExpiryNeverReleasesReservation(t *testing.T) {
	f := newCtlFixture(t, "RUNNING")
	f.reserved(t)
	f.now = f.now.Add(181 * time.Second)
	if e := f.c.Monitor(f.ctx); e != nil {
		t.Fatal(e)
	}
	if str(f.row(t, "jm_jobs")["state"]) != "RECONCILING" {
		t.Fatal("expired heartbeat not reconciled")
	}
	row, _ := f.db.One(f.ctx, "SELECT * FROM jm_allocations WHERE id='allocation'")
	if str(row["state"]) != "QUARANTINED" || row["released_at"] != nil {
		t.Fatal("liveness suspicion released capacity")
	}
}
func TestControllerRetryDelaysAndCap(t *testing.T) {
	for retries := int64(0); retries <= 3; retries++ {
		t.Run(string(rune('0'+retries)), func(t *testing.T) {
			f := newCtlFixture(t, "RECONCILING")
			f.update(t, "jm_attempts", "attempt", map[string]any{"revocation_confirmed": true, "termination_confirmed": true, "publication_status": "absent", "details_json": map[string]any{"automatic_retries": retries}})
			queued, e := f.c.retry(f.ctx, "job", false)
			if e != nil || !queued {
				t.Fatal(queued, e)
			}
			job := f.row(t, "jm_jobs")
			if retries == 3 {
				if str(job["state"]) != "FAILED" || str(job["error_code"]) != "retry_exhausted" {
					t.Fatal("fourth automatic retry")
				}
			} else {
				next, ok := moment(job["next_attempt_at"])
				expected, _ := RetryDelay(retries + 1)
				if str(job["state"]) != "QUEUED" || !ok || next.Sub(f.now) != expected || num(job["current_attempt"]) != 2 || num(job["epoch"]) != 1 {
					t.Fatalf("invalid retry snapshot %#v", job)
				}
			}
		})
	}
}
func TestControllerCallbacksFenceIdentityAndIgnoreUntrustedGlobalRound(t *testing.T) {
	f := newCtlFixture(t, "RUNNING")
	ok, e := f.c.CheckAssignment(f.ctx, "foreign", "cpu", "job", "attempt", "owner", 1)
	if e != nil || ok {
		t.Fatal("foreign node admitted")
	}
	ok, e = f.c.CheckAssignment(f.ctx, "node", "cpu", "job", "attempt", "owner", 1)
	if e != nil || !ok {
		t.Fatal("assigned node refused")
	}
	round := int64(500)
	ok, e = f.c.Progress(f.ctx, "job", "attempt", "owner", 2, ProgressReport{CurrentRound: &round})
	if e != nil || ok {
		t.Fatal("stale callback admitted")
	}
	ok, e = f.c.Progress(f.ctx, "job", "attempt", "owner", 1, ProgressReport{CurrentRound: &round, Phase: "running", Metrics: map[string]float64{"loss": 0.5}})
	if e != nil || !ok {
		t.Fatal(ok, e)
	}
	if num(f.row(t, "jm_jobs")["current_round"]) != 0 {
		t.Fatal("worker forged global progress")
	}
	if _, e = f.c.AppendLogs(f.ctx, "job", "attempt", "owner", 1, "hello"); e != nil || f.storage.logData != "hello" {
		t.Fatal("nontransactional log")
	}
	if _, e = f.c.AppendLogs(f.ctx, "job", "attempt", "owner", 1, strings.Repeat("x", 65537)); e == nil {
		t.Fatal("unbounded log")
	}
}
func TestControllerCleanupFailureRetainsOutboxProtection(t *testing.T) {
	f := newCtlFixture(t, "RECONCILING")
	f.update(t, "jm_allocations", "allocation", map[string]any{"state": "RELEASED", "released_at": f.now, "termination_confirmed": true})
	f.update(t, "jm_attempts", "attempt", map[string]any{"revocation_confirmed": true, "termination_confirmed": true})
	f.update(t, "jm_jobs", "job", map[string]any{"state": "FAILED", "cleanup_status": "pending"})
	f.p.cleanupConfirmed = false
	claim := f.claim(t, "cleanup", map[string]any{})
	done, e := f.c.processClaim(f.ctx, claim)
	if e != nil || done {
		t.Fatal(done, e)
	}
	row, e := f.db.One(f.ctx, "SELECT * FROM jm_outbox WHERE id=?", claim.ID)
	if e != nil {
		t.Fatal(e)
	}
	if str(row["state"]) != "pending" || row["next_attempt_at"] == nil || f.storage.deleted {
		t.Fatal("failed cleanup lost protection")
	}
}
func TestControllerPublicationAndRetryBounds(t *testing.T) {
	if _, e := RetryDelay(0); e == nil {
		t.Fatal("zero retry")
	}
	if _, e := RetryDelay(4); e == nil {
		t.Fatal("fourth retry")
	}
	if _, e := RemainingRounds(0, 0); e == nil {
		t.Fatal("invalid target")
	}
	if n, e := RemainingRounds(3, 5); e != nil || n != 0 {
		t.Fatal(n, e)
	}
	if (PublicationObservation{Known: true, Status: "unknown"}).Validate() == nil {
		t.Fatal("contradictory observation")
	}
}

func TestControllerRepeatedIdenticalProgressDoesNotChurnVersion(t *testing.T) {
	f := newCtlFixture(t, "RUNNING")
	round := int64(0)
	report := ProgressReport{CurrentRound: &round, Phase: "running", Metrics: map[string]float64{"loss": 0.5}}
	if _, e := f.c.Progress(f.ctx, "job", "attempt", "owner", 1, report); e != nil {
		t.Fatal(e)
	}
	before := num(f.row(t, "jm_jobs")["version"])
	f.now = f.now.Add(time.Second)
	if _, e := f.c.Progress(f.ctx, "job", "attempt", "owner", 1, report); e != nil {
		t.Fatal(e)
	}
	if after := num(f.row(t, "jm_jobs")["version"]); after != before {
		t.Fatalf("identical progress version %d -> %d", before, after)
	}
}

func TestControllerBuildCompletesBeforeAnyTrainingStarts(t *testing.T) {
	f := newCtlFixture(t, "PROVISIONING")
	// Extend this isolated initial fixture before the controller can act. The
	// production mutation helper deliberately forbids changing immutable specs.
	job := f.row(t, "jm_jobs")
	spec := obj(job["spec_json"])
	components := array(spec["components"])
	owner := obj(components[0])
	build := map[string]any{"component_id": "build", "role": "build", "participant_id": nil, "resources": owner["resources"]}
	spec["components"] = append(components, build)
	encoded, e := domain.CanonicalJSON(spec)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.db.Exec(f.ctx, "UPDATE jm_jobs SET spec_json=? WHERE id='job'", string(encoded)); e != nil {
		t.Fatal(e)
	}
	if e = f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
		return tx.Insert(f.ctx, "jm_allocations", map[string]any{"id": "build-allocation", "job_id": "job", "attempt_id": "attempt", "component_id": "build", "pool_id": "cpu", "cpu_millicores": int64(1000), "memory_bytes": int64(1048576), "disk_bytes": int64(1048576), "epoch": int64(1), "state": "RESERVED"})
	}); e != nil {
		t.Fatal(e)
	}
	done, e := f.c.processClaim(f.ctx, f.claim(t, "dispatch", map[string]any{"epoch": int64(1)}))
	if e != nil || done {
		t.Fatal(done, e)
	}
	for _, call := range f.e.calls {
		if call == "start:owner" {
			t.Fatal("owner started before build finished")
		}
	}
	zero := 0
	f.e.observed["build"] = executor.RuntimeObservation{State: "STOPPED", TerminationConfirmed: true, ExitCode: &zero, PublicationStatus: "none"}
	done, e = f.c.processClaim(f.ctx, f.claim(t, "dispatch", map[string]any{"epoch": int64(1)}))
	if e != nil || !done {
		t.Fatal(done, e)
	}
	if str(f.row(t, "jm_jobs")["state"]) != "RUNNING" {
		t.Fatal("training did not start after build collection")
	}
	sawBuild, sawOwner := false, false
	for _, call := range f.p.calls {
		if call == "build-prepared" {
			sawBuild = true
		}
	}
	for _, call := range f.e.calls {
		if call == "start:owner" {
			sawOwner = true
		}
	}
	if !sawBuild || !sawOwner {
		t.Fatal("build artifacts were not prepared before training")
	}
}
func TestControllerLeaseReplacementDuringEffectCannotConfirmOperation(t *testing.T) {
	f := newCtlFixture(t, "PROVISIONING")
	claim := f.claim(t, "dispatch", map[string]any{"epoch": int64(1)})
	f.e.startHook = func() {
		if _, e := f.db.Exec(f.ctx, "UPDATE jm_outbox SET lease_owner='replacement' WHERE id=?", claim.ID); e != nil {
			t.Fatal(e)
		}
	}
	done, e := f.c.processClaim(f.ctx, claim)
	if e != nil || done {
		t.Fatal(done, e)
	}
	operation, e := f.db.One(f.ctx, "SELECT * FROM jm_provisioning_operations WHERE operation='start'")
	if e != nil {
		t.Fatal(e)
	}
	if operation == nil || str(operation["state"]) == "confirmed" {
		t.Fatal("stale effect was marked confirmed")
	}
	allocation, _ := f.db.One(f.ctx, "SELECT * FROM jm_allocations WHERE id='allocation'")
	if allocation["released_at"] != nil {
		t.Fatal("unknown start released reservation")
	}
}

func TestControllerProgressRejectsCombinedPublicationStatuses(t *testing.T) {
	f := newCtlFixture(t, "RUNNING")
	if _, e := f.c.Progress(f.ctx, "job", "attempt", "owner", 1, ProgressReport{PublicationStatus: "none|absent"}); e == nil {
		t.Fatal("nonfinite publication status accepted")
	}
}

type ctlProxyProvisioner struct {
	*ctlFakeProvisioner
	restored bool
	calls    int
}

func (p *ctlProxyProvisioner) RestoreJobProxies(context.Context, map[string]any, map[string]any) (bool, error) {
	p.calls++
	return p.restored, nil
}
func TestControllerStartupRestoresProxyBeforeMonitoringOrRenewal(t *testing.T) {
	f := newCtlFixture(t, "RUNNING")
	f.p.round = 1
	proxy := &ctlProxyProvisioner{ctlFakeProvisioner: f.p, restored: false}
	f.c.Provisioner = proxy
	stats, e := f.c.RunOnce(f.ctx, 1)
	if e != nil {
		t.Fatal(e)
	}
	if proxy.calls != 1 || stats.Restored != 0 || str(f.row(t, "jm_jobs")["state"]) != "RUNNING" || num(f.row(t, "jm_jobs")["current_round"]) != 0 {
		t.Fatal("monitoring ran before proxy restoration confirmed")
	}
	proxy.restored = true
	f.now = f.now.Add(6 * time.Second)
	claim, e := f.c.ClaimNext(f.ctx, []string{"restore_proxies"})
	if e != nil || claim == nil {
		t.Fatal(e)
	}
	done, e := f.c.processClaim(f.ctx, *claim)
	if e != nil || !done {
		t.Fatal(done, e)
	}
}

func TestControllerEventCapturesCurrentVersionAndEpoch(t *testing.T) {
	f := newCtlFixture(t, "RUNNING")
	if e := f.c.RequestFailure(f.ctx, "job", "runtime_unhealthy", true); e != nil {
		t.Fatal(e)
	}
	event, e := f.db.One(f.ctx, "SELECT * FROM jm_events WHERE job_id='job' ORDER BY sequence DESC LIMIT 1")
	if e != nil {
		t.Fatal(e)
	}
	job := f.row(t, "jm_jobs")
	if num(event["version"]) != num(job["version"]) || num(event["epoch"]) != num(job["epoch"]) {
		t.Fatal("lifecycle event lost version or fencing epoch")
	}
}
