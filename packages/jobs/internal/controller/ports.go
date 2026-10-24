// Package controller reconciles durable lifecycle intents with external effects.
package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

type PublicationObservation struct {
	Known        bool           `json:"known"`
	Status       string         `json:"status"`
	CurrentRound *int64         `json:"current_round,omitempty"`
	Evidence     map[string]any `json:"evidence,omitempty"`
}

func (p PublicationObservation) Validate() error {
	known := map[string]bool{"none": true, "absent": true, "confirmed": true, "published": true}
	unknown := map[string]bool{"unknown": true, "publishing": true, "ambiguous": true}
	if (!known[p.Status] && !unknown[p.Status]) || p.Known != known[p.Status] {
		return fmt.Errorf("invalid publication certainty")
	}
	if p.CurrentRound != nil && *p.CurrentRound < 0 {
		return fmt.Errorf("invalid current round")
	}
	return nil
}
func RemainingRounds(target, current int64) (int64, error) {
	if target < 1 || current < 0 {
		return 0, fmt.Errorf("invalid absolute round boundary")
	}
	if current >= target {
		return 0, nil
	}
	return target - current, nil
}
func RetryDelay(number int64) (time.Duration, error) {
	if number < 1 || number > 3 {
		return 0, fmt.Errorf("at most three automatic retries are permitted")
	}
	return time.Minute * time.Duration(1<<(number-1)), nil
}
func SafeToReuse(revoked, stopped bool, p PublicationObservation) bool {
	return revoked && stopped && p.Validate() == nil && p.Known
}

type Executor interface {
	Reserve(context.Context, executor.ExecutionSpec) (executor.Reservation, error)
	Start(context.Context, executor.ExecutionIdentity) (executor.RuntimeObservation, error)
	Inspect(context.Context, executor.ExecutionIdentity) (executor.RuntimeObservation, error)
	Stop(context.Context, executor.ExecutionIdentity, int) (executor.RuntimeObservation, error)
	Renew(context.Context, executor.ExecutionIdentity) error
	Collect(context.Context, executor.ExecutionIdentity) ([]executor.CollectedArtifact, error)
	Release(context.Context, executor.ExecutionIdentity) (bool, error)
	Purge(context.Context, executor.ExecutionIdentity) (bool, error)
}
type Provisioner interface {
	CurrentRound(context.Context, map[string]any) (int64, error)
	Plan(context.Context, map[string]any, map[string]any, int64) (map[string]executor.ExecutionSpec, error)
	Ensure(context.Context, map[string]any, map[string]any, int64) error
	Revoke(context.Context, map[string]any, map[string]any) (bool, error)
	Reconcile(context.Context, map[string]any, map[string]any) (PublicationObservation, error)
	Cleanup(context.Context, map[string]any, map[string]any) (bool, error)
	PurgeJob(context.Context, map[string]any) (bool, error)
	ExpireArtifacts(context.Context, map[string]any) (bool, error)
}
type ProxyRestorer interface {
	RestoreJobProxies(context.Context, map[string]any, map[string]any) (bool, error)
}
type BuildPreparer interface {
	PrepareBuildOutputs(context.Context, map[string]any, map[string]any, map[string][]executor.CollectedArtifact) (bool, error)
}
type Participants interface {
	RequestStop(context.Context, map[string]any, map[string]any) (bool, error)
	AttemptTerminationConfirmed(context.Context, string, string) (bool, error)
}
type ArtifactStorage interface {
	RequestExpiry(context.Context) error
	ReserveCollection(context.Context, map[string]any, map[string]any, map[string]any) error
	StoreCollected(context.Context, map[string]any, map[string]any, map[string]any, []executor.CollectedArtifact) error
	RetainExecutionState(context.Context, map[string]any, map[string]any, map[string]any) error
	IngestLogs(context.Context, map[string]any, bool) error
	ConfirmJobDataDeleted(context.Context, string) error
}
type Controller struct {
	DB               *store.DB
	Executor         Executor
	Provisioner      Provisioner
	Storage          ArtifactStorage
	Participants     Participants
	Schedule         func(context.Context) (int, error)
	Clock            func() time.Time
	ControllerID     string
	HeartbeatTimeout time.Duration
	RenewInterval    time.Duration
	restored         bool
	runMu            sync.Mutex
}
type Stats struct{ Admitted, Dispatched, Restored int }
type Claim struct {
	ID, JobID, AttemptID, Topic, Owner string
	AttemptNumber                      int64
	Payload                            map[string]any
	LeaseUntil                         time.Time
}
