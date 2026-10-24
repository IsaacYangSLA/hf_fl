// Package participants implements certificate-bound autonomous participant lifecycle.
package participants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/certificates"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

// Actor is issued by the node-token verifier, then checked against durable enrollment.
type Actor = exchange.NodePrincipal
type NodeGrant = exchange.NodeRequest

type ApprovedNode struct {
	NodeID                string                    `json:"node_id"`
	CertificateThumbprint string                    `json:"certificate_thumbprint"`
	DatasetBindings       map[string]map[string]any `json:"dataset_bindings"`
	Resources             map[string]int64          `json:"resources"`
	Enabled               bool                      `json:"enabled"`
}

func (n ApprovedNode) Validate() error {
	if domain.ValidateIdentifier(n.NodeID) != nil || !validThumbprint(n.CertificateThumbprint) || len(n.DatasetBindings) == 0 {
		return domain.Err(422, "external_node_not_approved")
	}
	for k, v := range n.DatasetBindings {
		if domain.ValidateIdentifier(k) != nil || v == nil {
			return domain.Err(422, "external_node_not_approved")
		}
	}
	if len(n.Resources) != 3 {
		return domain.Err(422, "invalid_external_resources")
	}
	for _, k := range []string{"cpu_millicores", "memory_bytes", "disk_bytes"} {
		v, ok := n.Resources[k]
		if !ok || v < 1 || v > 1<<50 {
			return domain.Err(422, "invalid_external_resources")
		}
	}
	return nil
}

type Snapshot struct {
	Root     string
	Manifest map[string]string
}
type SourceFile struct {
	io.ReadCloser
	SizeBytes int64
	SHA256    string
}

func NewSourceFile(data []byte) *SourceFile {
	sum := sha256.Sum256(data)
	return &SourceFile{ReadCloser: io.NopCloser(bytes.NewReader(data)), SizeBytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
}

// Hooks connect independently implemented provisioning, build and log services.
// Missing required capabilities fail closed; no manager service is invoked in Python.
type Hooks struct {
	WorkloadIssuer   string
	StoragePoolID    string
	Snapshot         func(context.Context, map[string]any, domain.JobSpec) (Snapshot, error)
	SpaceID          func(context.Context, string) (string, error)
	Image            func(context.Context, domain.JobSpec) (string, error)
	SourceLimits     func(context.Context, domain.JobSpec) (map[string]any, error)
	BuiltArtifacts   func(context.Context, Actor, domain.JobSpec) (map[string]any, error)
	OpenBuildProduct func(context.Context, Actor, string) (*SourceFile, error)
	BuildAccessValid func(context.Context, Actor) bool
	SecretOptions    func(context.Context, map[string]any, map[string]any, string) ([]string, error)
	Reconciliation   func(context.Context, string, string, int64) ([]map[string]any, error)
	CreateGrant      func(context.Context, string, map[string]any, string) (map[string]any, error)
	GetGrant         func(context.Context, string, string) (map[string]any, error)
	AppendLogs       func(context.Context, Actor, string, string, map[string]any) (map[string]any, error)
	IssueNode        func(context.Context, NodeGrant) (string, error)
	IssueWorkload    func(context.Context, map[string]any, string, int64) (string, error)
}
type Service struct {
	DB              *store.DB
	Clock           func() time.Time
	Nodes           map[string]ApprovedNode
	Broker          *exchange.Broker
	Issuer          *certificates.Issuer
	Hooks           Hooks
	Dispatch        func(context.Context, string, map[string]any) (map[string]any, error)
	dispatchMu      sync.Mutex
	dispatching     map[string]bool
	dispatchContext context.Context
	dispatchCancel  context.CancelFunc
	dispatchWG      sync.WaitGroup
	closing         bool
}

func NewService(db *store.DB, nodes []ApprovedNode, hooks Hooks, broker *exchange.Broker, issuer *certificates.Issuer) (*Service, error) {
	if db == nil {
		return nil, domain.Err(503, "participant_database_unavailable")
	}
	s := &Service{DB: db, Clock: time.Now, Nodes: map[string]ApprovedNode{}, Hooks: hooks, Broker: broker, Issuer: issuer, dispatching: map[string]bool{}}
	for _, n := range nodes {
		if err := n.Validate(); err != nil {
			return nil, err
		}
		if _, exists := s.Nodes[n.NodeID]; exists {
			return nil, domain.Err(422, "duplicate_external_node")
		}
		s.Nodes[n.NodeID] = n
	}
	return s, nil
}
func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock().UTC()
	}
	return time.Now().UTC()
}
func stableKey(parts ...string) string {
	b, _ := domain.CanonicalJSON(parts)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func ComponentID(participantID string) string { return "participant-" + stableKey(participantID)[:40] }
func validThumbprint(v string) bool {
	if len(v) != 43 {
		return false
	}
	b, e := base64.RawURLEncoding.DecodeString(v)
	return e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == v
}
func mapv(v any) map[string]any {
	if m, ok := v.(map[string]any); ok && m != nil {
		return m
	}
	return map[string]any{}
}
func str(v any) string { s, _ := v.(string); return s }
func number(v any) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	case json.Number:
		i, _ := x.Int64()
		return i
	case float64:
		return int64(x)
	}
	return 0
}
func truth(v any) bool { b, _ := v.(bool); return b }
func contains(v []string, s string) bool {
	for _, x := range v {
		if x == s {
			return true
		}
	}
	return false
}
func active(state string) bool {
	return contains([]string{"PROVISIONING", "STARTING", "RUNNING"}, state)
}
func controlled(state string) bool {
	return active(state) || contains([]string{"CANCELLING", "RECONCILING", "NEEDS_ATTENTION", "CANCELLED", "FAILED", "SUCCEEDED"}, state)
}
func decodeSpec(job map[string]any) (domain.JobSpec, error) {
	b, e := domain.CanonicalJSON(job["spec_json"])
	if e != nil {
		return domain.JobSpec{}, domain.Err(409, "invalid_job_spec")
	}
	return domain.DecodeJobSpec(b)
}
func (s *Service) snapshot(ctx context.Context, job map[string]any, spec domain.JobSpec) (Snapshot, error) {
	if s.Hooks.Snapshot == nil {
		return Snapshot{}, domain.Err(409, "participant_source_unavailable")
	}
	snap, e := s.Hooks.Snapshot(ctx, job, spec)
	if e != nil {
		return Snapshot{}, e
	}
	if snap.Root == "" || len(snap.Manifest) == 0 {
		return Snapshot{}, domain.Err(409, "participant_source_unavailable")
	}
	return snap, nil
}
func (s *Service) issueNode(ctx context.Context, r NodeGrant) (string, error) {
	if s.Hooks.IssueNode != nil {
		return s.Hooks.IssueNode(ctx, r)
	}
	if s.Broker == nil {
		return "", domain.Err(503, "external_node_grant_unavailable")
	}
	return s.Broker.IssueNode(r)
}
func (s *Service) emit(ctx context.Context, tx *store.Tx, job map[string]any, kind, actor string, data map[string]any) error {
	row, e := tx.One(ctx, "SELECT MAX(sequence) AS sequence FROM jm_events WHERE job_id=?", job["id"])
	if e != nil {
		return e
	}
	return tx.Insert(ctx, "jm_events", map[string]any{"id": domain.NewID(), "job_id": job["id"], "sequence": number(row["sequence"]) + 1, "kind": kind, "actor_id": actor, "data_json": data, "created_at": s.now()})
}
func clone(v map[string]any) map[string]any {
	out := map[string]any{}
	for k, x := range v {
		out[k] = x
	}
	return out
}
func (s *Service) saveDetails(ctx context.Context, tx *store.Tx, row map[string]any, data map[string]any) error {
	return tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": row["id"]}, map[string]any{"details_json": data, "updated_at": s.now()})
}
func (s *Service) spaceID(ctx context.Context, job string) (string, error) {
	if s.Hooks.SpaceID == nil {
		return "", domain.Err(409, "participant_assignment_not_ready")
	}
	return s.Hooks.SpaceID(ctx, job)
}
func identity(job, attempt map[string]any, component string) map[string]any {
	return map[string]any{"job_id": job["id"], "attempt_id": attempt["id"], "component_id": component, "epoch": attempt["epoch"]}
}
func deadline(job map[string]any, now time.Time, seconds int64) time.Time {
	if t, ok := store.Time(job["deadline_at"]); ok {
		return t
	}
	return now.Add(time.Duration(seconds) * time.Second)
}
func workloadSubject(job, component, participant string) string {
	b, _ := domain.CanonicalJSON([]string{job, component, participant})
	h := sha256.Sum256(b)
	return "job:" + hex.EncodeToString(h[:])
}
func stableWorkloadPrincipal(issuer, job, component, participant string) string {
	return domain.PrincipalID(issuer, workloadSubject(job, component, participant))
}
func checkScope(actor Actor, scope string) error {
	if !contains(actor.Scopes, scope) {
		return domain.Err(403, "node_scope_required")
	}
	return nil
}
func publicationPath(p string) bool {
	if p == "progress.json" || p == "listener/state.json" {
		return true
	}
	parts := strings.Split(p, "/")
	if len(parts) < 5 || parts[0] != "listener" || parts[1] != "jobs" || len(parts[2]) != 64 || parts[3] != "work" {
		return false
	}
	if _, e := hex.DecodeString(parts[2]); e != nil || strings.ToLower(parts[2]) != parts[2] {
		return false
	}
	tail := strings.Join(parts[4:], "/")
	return tail == "client-publication-intent.json" || tail == "trained_model.exchange-upload.json" || tail == "trained_model/fedavg_submission.json"
}
