// Package executor implements fenced, qualified CPU execution and durable local leases.
package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var imageDigest = regexp.MustCompile(`^(?:[a-zA-Z0-9./:_-]+@)?sha256:[a-f0-9]{64}$`)
var loopDevice = regexp.MustCompile(`^/dev/loop[0-9]+$`)
var approvedArgv = []string{"python", "-m", "hf2l_jobs.runtime", "--config", "/run/hf2l/runtime.json"}

const StorageHeadroomBytes int64 = 4 * 1024 * 1024

type ExecutionIdentity struct {
	JobID       string `json:"job_id"`
	AttemptID   string `json:"attempt_id"`
	ComponentID string `json:"component_id"`
	Epoch       int64  `json:"epoch"`
}

func (i ExecutionIdentity) Validate() error {
	if !safeID.MatchString(i.JobID) || !safeID.MatchString(i.AttemptID) || !safeID.MatchString(i.ComponentID) {
		return refused("invalid_identity")
	}
	if i.Epoch < 1 {
		return refused("invalid_epoch")
	}
	return nil
}
func (i ExecutionIdentity) Key() string {
	b, _ := domain.CanonicalJSON(map[string]any{"job_id": i.JobID, "attempt_id": i.AttemptID, "component_id": i.ComponentID, "epoch": i.Epoch})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])[:32]
}

type ResourceLimits struct {
	CPUMillis   int64 `json:"cpu_millis"`
	MemoryBytes int64 `json:"memory_bytes"`
	DiskBytes   int64 `json:"disk_bytes"`
	PIDs        int64 `json:"pids"`
	IOBPS       int64 `json:"io_bps"`
	GPUs        int64 `json:"gpus"`
}

func (r ResourceLimits) Validate() error {
	if r.CPUMillis <= 0 || r.MemoryBytes <= 0 || r.DiskBytes <= 0 || r.PIDs <= 0 || r.IOBPS <= 0 {
		return refused("invalid_resources")
	}
	if r.PIDs > 128 || r.IOBPS > 16*1024*1024 || r.GPUs != 0 {
		return refused("unsupported_profile")
	}
	return nil
}
func (r ResourceLimits) Defaults() ResourceLimits {
	if r.PIDs == 0 {
		r.PIDs = 128
	}
	if r.IOBPS == 0 {
		r.IOBPS = 16 * 1024 * 1024
	}
	return r
}

type ExecutionSpec struct {
	Identity         ExecutionIdentity `json:"identity"`
	ImageDigest      string            `json:"image_digest"`
	SourcePath       string            `json:"source_path"`
	StatePath        string            `json:"state_path"`
	Argv             []string          `json:"argv"`
	ProxyEndpoint    string            `json:"proxy_endpoint"`
	Resources        ResourceLimits    `json:"resources"`
	LeaseSeconds     float64           `json:"lease_seconds"`
	PoolID           string            `json:"pool_id"`
	NodeID           string            `json:"node_id"`
	Deadline         *float64          `json:"deadline"`
	ConfigPath       string            `json:"config_path"`
	Profile          string            `json:"profile"`
	Role             string            `json:"role"`
	SecretPath       string            `json:"secret_path"`
	DatasetBindingID string            `json:"dataset_binding_id"`
	ParticipantID    string            `json:"participant_id"`
	BuildInputPath   string            `json:"build_input_path"`
}

func (s ExecutionSpec) Defaults() ExecutionSpec {
	s.Resources = s.Resources.Defaults()
	if s.LeaseSeconds == 0 {
		s.LeaseSeconds = 120
	}
	if s.Profile == "" {
		s.Profile = "runsc-cpu-v1"
	}
	if s.Role == "" {
		s.Role = "owner"
	}
	if len(s.Argv) == 0 {
		s.Argv = append([]string(nil), approvedArgv...)
	}
	return s
}
func (s ExecutionSpec) Validate() error {
	if e := s.Identity.Validate(); e != nil {
		return e
	}
	if e := s.Resources.Validate(); e != nil {
		return e
	}
	if !imageDigest.MatchString(s.ImageDigest) {
		return refused("image_not_pinned")
	}
	if len(s.Argv) != len(approvedArgv) {
		return refused("invalid_invocation")
	}
	for n, a := range approvedArgv {
		if s.Argv[n] != a {
			return refused("invalid_invocation")
		}
	}
	if math.IsNaN(s.LeaseSeconds) || math.IsInf(s.LeaseSeconds, 0) || s.LeaseSeconds <= 0 || s.LeaseSeconds > 300 {
		return refused("invalid_lease")
	}
	if s.Deadline != nil && (math.IsNaN(*s.Deadline) || math.IsInf(*s.Deadline, 0) || *s.Deadline <= 0) {
		return refused("invalid_deadline")
	}
	if s.Role != "owner" && s.Role != "client" && s.Role != "build" && s.Role != "init" {
		return refused("invalid_invocation")
	}
	if s.ProxyEndpoint == "" && s.Role != "build" {
		return refused("missing_proxy")
	}
	if s.Role == "build" && (s.ProxyEndpoint != "" || s.SecretPath != "" || s.DatasetBindingID != "" || s.BuildInputPath != "") {
		return refused("unsafe_proxy")
	}
	if s.DatasetBindingID != "" && (s.Role != "client" || s.ParticipantID == "") {
		return refused("unsafe_dataset")
	}
	if s.Profile != "runsc-cpu-v1" {
		return refused("unsupported_profile")
	}
	return nil
}
func (s ExecutionSpec) Canonical() ([]byte, error) { return domain.CanonicalASCIIJSON(s.Map()) }

type Reservation struct {
	Identity     ExecutionIdentity `json:"identity"`
	Acknowledged bool              `json:"acknowledged"`
	NodeID       string            `json:"node_id"`
	State        string            `json:"state"`
}
type RuntimeObservation struct {
	Identity             ExecutionIdentity  `json:"identity"`
	State                string             `json:"state"`
	TerminationConfirmed bool               `json:"termination_confirmed"`
	PublicationStatus    string             `json:"publication_status"`
	CurrentRound         *int64             `json:"current_round"`
	ErrorCode            string             `json:"error_code,omitempty"`
	Transient            bool               `json:"transient"`
	ExitCode             *int               `json:"exit_code"`
	Details              map[string]any     `json:"details"`
	Metrics              map[string]float64 `json:"metrics"`
	Phase                string             `json:"phase,omitempty"`
	Readiness            string             `json:"readiness,omitempty"`
}
type CollectedArtifact = domain.CollectedArtifact

type Backend interface {
	Reserve(context.Context, ExecutionSpec) (Reservation, error)
	Start(context.Context, ExecutionIdentity) (RuntimeObservation, error)
	Inspect(context.Context, ExecutionIdentity) (RuntimeObservation, error)
	Stop(context.Context, ExecutionIdentity, int) (RuntimeObservation, error)
	Collect(context.Context, ExecutionIdentity) ([]CollectedArtifact, error)
	Release(context.Context, ExecutionIdentity) (bool, error)
	Purge(context.Context, ExecutionIdentity) (bool, error)
}
type FullBackend interface {
	Backend
	Renew(context.Context, ExecutionIdentity) error
}
type UncertainError struct{ Cause error }

func (e *UncertainError) Error() string { return "execution_unknown" }
func (e *UncertainError) Unwrap() error { return e.Cause }
func uncertain(err error) error         { return &UncertainError{Cause: err} }
func IsUncertain(err error) bool        { var u *UncertainError; return errors.As(err, &u) }
func ErrorCode(err error) string {
	var d *domain.Error
	if errors.As(err, &d) {
		return d.Code
	}
	if IsUncertain(err) {
		return "execution_unknown"
	}
	return "executor_refused"
}
func refused(code string) error { return domain.Err(409, code) }
func canonicalEqual(a, b any) bool {
	aa, e := domain.CanonicalJSON(a)
	if e != nil {
		return false
	}
	bb, e := domain.CanonicalJSON(b)
	return e == nil && string(aa) == string(bb)
}
func decodeJSON(data []byte, target any) error {
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.UseNumber()
	if err := d.Decode(target); err != nil {
		return err
	}
	if d.More() {
		return fmt.Errorf("multiple JSON values")
	}
	return nil
}
func ExecutionStorageBudget(disk int64) (int64, error) {
	if disk <= 0 || disk > (math.MaxInt64-StorageHeadroomBytes)/2 {
		return 0, refused("invalid_resources")
	}
	return disk*2 + StorageHeadroomBytes, nil
}
