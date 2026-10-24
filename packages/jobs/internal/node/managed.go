package node

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math"
	"sort"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/certificates"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/resources"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

type Principal = exchange.NodePrincipal
type ApprovedManagedNode struct {
	NodeID                string `json:"node_id"`
	PoolID                string `json:"pool_id"`
	CertificateThumbprint string `json:"certificate_thumbprint"`
	RegistrationID        string `json:"registration_id"`
	Enabled               bool   `json:"enabled"`
}

func (n ApprovedManagedNode) Validate() error {
	if domain.ValidateIdentifier(n.NodeID) != nil || domain.ValidateIdentifier(n.PoolID) != nil || domain.ValidateIdentifier(n.RegistrationID) != nil {
		return domain.Err(422, "invalid_node_registration")
	}
	return validateThumbprint(n.CertificateThumbprint)
}
func CertificateThumbprint(path string) (string, error) {
	b, e := readTLSFile(path, false)
	if e == nil && len(b) > 16384 {
		return "", domain.Err(422, "invalid_node_certificate")
	}
	if e != nil {
		return "", e
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", domain.Err(422, "invalid_node_certificate")
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return "", domain.Err(422, "invalid_node_certificate")
	}
	return Thumbprint(cert.Raw), nil
}

type AssignmentProvisioner interface {
	PreparedComponent(context.Context, map[string]any, map[string]any, string) (map[string]any, error)
	OwnedSpace(context.Context, string) (string, error)
	ExchangeGrant(context.Context, string, string) (map[string]any, error)
}
type AssignmentConfig struct {
	RegisteredNodes              map[string]ApprovedManagedNode
	ManagerCertificateThumbprint string
	Clock                        func() time.Time
	Provisioner                  AssignmentProvisioner
	IssueCertificate             func(context.Context, string, executor.ExecutionIdentity, string, time.Time) (map[string]any, error)
	ValidatePrepared             func(map[string]any, string) error
}
type AssignmentService struct {
	DB     *store.DB
	Broker *exchange.Broker
	Config AssignmentConfig
	Ledger *resources.Ledger
}

func NewAssignmentService(db *store.DB, broker *exchange.Broker, cfg AssignmentConfig) (*AssignmentService, error) {
	if db == nil || broker == nil || cfg.Provisioner == nil {
		return nil, domain.Err(422, "invalid_managed_node_configuration")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.ManagerCertificateThumbprint != "" && validateThumbprint(cfg.ManagerCertificateThumbprint) != nil {
		return nil, domain.Err(422, "invalid_manager_certificate")
	}
	registry := map[string]ApprovedManagedNode{}
	seen := map[string]bool{}
	for key, n := range cfg.RegisteredNodes {
		if n.Validate() != nil || n.NodeID != key || seen[n.CertificateThumbprint] || n.CertificateThumbprint == cfg.ManagerCertificateThumbprint {
			return nil, domain.Err(422, "invalid_node_registration")
		}
		registry[key] = n
		seen[n.CertificateThumbprint] = true
	}
	cfg.RegisteredNodes = registry
	return &AssignmentService{DB: db, Broker: broker, Config: cfg, Ledger: resources.NewLedger(db)}, nil
}
func (s *AssignmentService) now() time.Time { return s.Config.Clock().UTC() }
func (s *AssignmentService) registration(node, pool string) (ApprovedManagedNode, error) {
	n, ok := s.Config.RegisteredNodes[node]
	if !ok || !n.Enabled || n.PoolID != pool {
		return n, domain.Err(404, "node_assignment_not_found")
	}
	return n, nil
}

type allocationView struct {
	job, attempt, allocation, pool map[string]any
	spec                           domain.JobSpec
	component                      domain.ComponentSpec
	node                           ApprovedManagedNode
}

func valueMap(v any) map[string]any { m, _ := v.(map[string]any); return m }
func valueString(v any) string      { s, _ := v.(string); return s }
func (s *AssignmentService) lookup(ctx context.Context, tx *store.Tx, id executor.ExecutionIdentity, nodeID, poolID string, lock bool) (allocationView, error) {
	var d allocationView
	if id.Validate() != nil {
		return d, domain.Err(404, "node_assignment_not_found")
	}
	suffix := ""
	if lock {
		suffix = tx.ForUpdate()
	}
	var e error
	d.job, e = tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?"+suffix, id.JobID)
	if e != nil {
		return d, e
	}
	q := "SELECT * FROM jm_allocations WHERE job_id = ? AND attempt_id = ? AND component_id = ? AND epoch = ?"
	args := []any{id.JobID, id.AttemptID, id.ComponentID, id.Epoch}
	if poolID != "" {
		q += " AND pool_id = ?"
		args = append(args, poolID)
	}
	d.allocation, e = tx.One(ctx, q+suffix, args...)
	if e != nil {
		return d, e
	}
	d.attempt, e = tx.One(ctx, "SELECT * FROM jm_attempts WHERE id = ?", id.AttemptID)
	if e != nil {
		return d, e
	}
	if d.allocation != nil {
		d.pool, e = tx.One(ctx, "SELECT * FROM jm_pools WHERE id = ?", d.allocation["pool_id"])
		if e != nil {
			return d, e
		}
	}
	if d.job == nil || d.attempt == nil || d.allocation == nil || d.pool == nil || d.attempt["job_id"] != id.JobID || number(d.attempt["epoch"]) != id.Epoch || !liveAllocation(valueString(d.allocation["state"])) && d.allocation["state"] != "RELEASED" {
		return d, domain.Err(404, "node_assignment_not_found")
	}
	details := valueMap(d.allocation["details_json"])
	owned := valueString(details["node_id"])
	if owned == "" {
		if d.allocation["released_at"] != nil || d.allocation["state"] == "RELEASED" {
			return d, domain.Err(404, "node_assignment_not_found")
		}
		owned = valueString(d.pool["node_id"])
	}
	if nodeID != "" && nodeID != owned {
		return d, domain.Err(404, "node_assignment_not_found")
	}
	d.node, e = s.registration(owned, valueString(d.pool["id"]))
	if e != nil {
		return d, e
	}
	registration := valueString(details["registration_id"])
	if registration == "" && d.pool["node_id"] == d.node.NodeID {
		registration = valueString(valueMap(d.pool["details_json"])["registration_id"])
	}
	if registration != "" && registration != d.node.RegistrationID {
		return d, domain.Err(404, "node_assignment_not_found")
	}
	b, e := domain.CanonicalJSON(d.job["spec_json"])
	if e != nil {
		return d, domain.Err(404, "node_assignment_not_found")
	}
	d.spec, e = domain.DecodeJobSpec(b)
	if e != nil {
		return d, domain.Err(404, "node_assignment_not_found")
	}
	digest, e := d.spec.Digest()
	if e != nil || digest != d.job["spec_hash"] {
		return d, domain.Err(404, "node_assignment_not_found")
	}
	found := false
	for _, c := range d.spec.Components {
		if c.ComponentID == id.ComponentID {
			d.component = c
			found = true
			break
		}
	}
	c := d.component
	if !found || c.Resources.PoolID != d.pool["id"] || c.Resources.GPUCount != number(d.allocation["gpu_count"]) || c.Resources.CPUMillicores != number(d.allocation["cpu_millicores"]) || c.Resources.MemoryBytes != number(d.allocation["memory_bytes"]) || c.Resources.DiskBytes != number(d.allocation["disk_bytes"]) {
		return d, domain.Err(404, "node_assignment_not_found")
	}
	return d, nil
}
func liveAllocation(v string) bool {
	return map[string]bool{"RESERVED": true, "ACKNOWLEDGED": true, "STARTING": true, "RUNNING": true, "QUARANTINED": true, "RELEASING": true}[v]
}
func limits(d allocationView) map[string]any {
	return map[string]any{"cpu_millicores": number(d.allocation["cpu_millicores"]), "memory_bytes": number(d.allocation["memory_bytes"]), "disk_bytes": number(d.allocation["disk_bytes"])}
}
func (s *AssignmentService) current(d allocationView) bool {
	deadline, ok := store.Time(d.job["deadline_at"])
	return ok && deadline.After(s.now()) && number(d.job["epoch"]) == number(d.attempt["epoch"]) && number(d.attempt["epoch"]) == number(d.allocation["epoch"]) && number(d.job["current_attempt"]) == number(d.attempt["number"]) && map[string]bool{"PROVISIONING": true, "STARTING": true, "RUNNING": true}[valueString(d.job["state"])] && liveAllocation(valueString(d.allocation["state"]))
}
func poolCurrent(d allocationView) bool {
	r := valueString(valueMap(d.pool["details_json"])["registration_id"])
	return d.pool["node_id"] == d.node.NodeID && (r == "" || r == d.node.RegistrationID)
}
func (s *AssignmentService) requireActive(ctx context.Context, tx *store.Tx, d allocationView, ack bool) error {
	if !s.current(d) || d.pool["healthy"] != true || d.pool["quarantined"] == true || !poolCurrent(d) {
		return domain.Err(409, "node_assignment_not_ready")
	}
	if !ack {
		return nil
	}
	all, e := tx.All(ctx, "SELECT * FROM jm_allocations WHERE job_id = ? AND attempt_id = ? AND epoch = ?", d.job["id"], d.attempt["id"], d.attempt["epoch"])
	if e != nil {
		return e
	}
	if len(all) != len(d.spec.Components) {
		return domain.Err(409, "node_assignment_not_acknowledged")
	}
	wanted := map[string]bool{}
	for _, c := range d.spec.Components {
		wanted[c.ComponentID] = true
	}
	for _, a := range all {
		if !wanted[valueString(a["component_id"])] || a["acknowledged"] != true {
			return domain.Err(409, "node_assignment_not_acknowledged")
		}
		delete(wanted, valueString(a["component_id"]))
	}
	if len(wanted) != 0 {
		return domain.Err(409, "node_assignment_not_acknowledged")
	}
	return nil
}
func principalIdentity(p Principal) executor.ExecutionIdentity {
	return executor.ExecutionIdentity{JobID: p.JobID, AttemptID: p.AttemptID, ComponentID: p.ComponentID, Epoch: p.Epoch}
}
func (s *AssignmentService) actor(ctx context.Context, tx *store.Tx, p Principal, active, nodeOnly, lock bool) (allocationView, error) {
	if principalIdentity(p).Validate() != nil {
		return allocationView{}, domain.Err(401, "invalid_node_access_token")
	}
	d, e := s.lookup(ctx, tx, principalIdentity(p), p.NodeID, p.PoolID, lock)
	if e != nil {
		return d, e
	}
	if p.GrantID != d.allocation["id"] || !numericEqual(p.Resources, limits(d)) || nodeOnly && p.CertificateThumbprint != d.node.CertificateThumbprint || p.CertificateThumbprint != d.node.CertificateThumbprint && p.CertificateThumbprint != s.Config.ManagerCertificateThumbprint {
		return d, domain.Err(401, "invalid_node_access_token")
	}
	if active {
		e = s.requireActive(ctx, tx, d, true)
	}
	return d, e
}
func (s *AssignmentService) CheckNodeGrant(ctx context.Context, p Principal) (bool, error) {
	valid := false
	e := s.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		d, e := s.actor(ctx, tx, p, false, false, false)
		if e != nil {
			return e
		}
		if len(p.Scopes) == 0 {
			return nil
		}
		allowed := map[string]bool{}
		if p.CertificateThumbprint == d.node.CertificateThumbprint {
			for _, k := range []string{"assignment", "acknowledge", "heartbeat", "progress", "logs", "stopped"} {
				allowed[k] = true
			}
		} else {
			if p.CertificateThumbprint != s.Config.ManagerCertificateThumbprint {
				return nil
			}
			for _, k := range []string{"inspect", "stop", "release", "collect", "logs", "heartbeat"} {
				allowed[k] = true
			}
			if s.current(d) && d.pool["healthy"] == true && d.pool["quarantined"] != true && poolCurrent(d) {
				for _, k := range []string{"reserve", "start", "inspect", "stop", "release", "renew", "collect", "logs", "assignment", "heartbeat"} {
					allowed[k] = true
				}
				if d.allocation["acknowledged"] != true {
					delete(allowed, "start")
				}
				if p.HasScope("start") {
					if e = s.requireActive(ctx, tx, d, true); e != nil {
						return e
					}
				}
			}
			if domain.IsTerminal(valueString(d.job["state"])) && d.allocation["state"] == "RELEASED" && d.allocation["termination_confirmed"] == true && (d.job["cleanup_status"] == "purge_pending" || d.job["cleanup_status"] == "expiry_pending") {
				allowed["purge"] = true
			}
		}
		for _, scope := range p.Scopes {
			if !allowed[scope] {
				return nil
			}
		}
		valid = true
		return nil
	})
	var de *domain.Error
	if errors.As(e, &de) {
		return false, nil
	}
	return valid, e
}
func (s *AssignmentService) AuthenticateNode(ctx context.Context, authorization, peer string) (Principal, error) {
	return s.Broker.AuthenticateNode(ctx, authorization, peer, s.CheckNodeGrant)
}
func (s *AssignmentService) Bootstrap(ctx context.Context, peer string, id executor.ExecutionIdentity) (map[string]any, error) {
	if validateThumbprint(peer) != nil {
		return nil, domain.Err(422, "invalid_node_certificate")
	}
	var n ApprovedManagedNode
	found := false
	for _, candidate := range s.Config.RegisteredNodes {
		if candidate.Enabled && subtle.ConstantTimeCompare([]byte(candidate.CertificateThumbprint), []byte(peer)) == 1 {
			n = candidate
			found = true
		}
	}
	if !found {
		return nil, domain.Err(401, "unregistered_node_certificate")
	}
	var d allocationView
	e := s.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		var err error
		d, err = s.lookup(ctx, tx, id, n.NodeID, n.PoolID, false)
		return err
	})
	if e != nil {
		return nil, e
	}
	token, e := s.Broker.IssueNode(exchange.NodeRequest{NodeID: n.NodeID, PoolID: n.PoolID, JobID: id.JobID, AttemptID: id.AttemptID, ComponentID: id.ComponentID, Epoch: id.Epoch, GrantID: valueString(d.allocation["id"]), CertificateThumbprint: peer, Scopes: []string{"assignment"}, Resources: limits(d), TTLSeconds: 300})
	if e != nil {
		return nil, e
	}
	return map[string]any{"token": token, "expires_at": s.now().Unix() + 300}, nil
}
func (s *AssignmentService) IssueControlToken(ctx context.Context, id executor.ExecutionIdentity, nodeID, poolID, scope, certificate string, providedResources map[string]any) (string, error) {
	if certificate == "" {
		certificate = s.Config.ManagerCertificateThumbprint
	}
	if certificate == "" || certificate != s.Config.ManagerCertificateThumbprint {
		return "", domain.Err(401, "invalid_manager_certificate")
	}
	if !map[string]bool{"reserve": true, "start": true, "inspect": true, "stop": true, "release": true, "renew": true, "collect": true, "logs": true, "assignment": true, "heartbeat": true, "purge": true}[scope] {
		return "", domain.Err(403, "node_scope_required")
	}
	var d allocationView
	e := s.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		var err error
		d, err = s.lookup(ctx, tx, id, nodeID, poolID, false)
		return err
	})
	if e != nil {
		return "", e
	}
	resource := limits(d)
	if providedResources != nil && !numericEqual(providedResources, resource) {
		return "", domain.Err(403, "node_resource_binding_mismatch")
	}
	p := Principal{ID: domain.PrincipalID(s.Broker.Issuer(), "node:"+nodeID), Subject: "node:" + nodeID, NodeID: nodeID, PoolID: poolID, JobID: id.JobID, AttemptID: id.AttemptID, ComponentID: id.ComponentID, Epoch: id.Epoch, GrantID: valueString(d.allocation["id"]), CertificateThumbprint: certificate, Scopes: []string{scope}, Resources: resource, IssuedAt: s.now().Unix(), ExpiresAt: s.now().Unix() + 300}
	valid, e := s.CheckNodeGrant(ctx, p)
	if e != nil {
		return "", e
	}
	if !valid {
		return "", domain.Err(409, "node_operation_not_currently_authorized")
	}
	return s.Broker.IssueNode(exchange.NodeRequest{NodeID: p.NodeID, PoolID: p.PoolID, JobID: p.JobID, AttemptID: p.AttemptID, ComponentID: p.ComponentID, Epoch: p.Epoch, GrantID: p.GrantID, CertificateThumbprint: p.CertificateThumbprint, Scopes: p.Scopes, Resources: p.Resources, TTLSeconds: 300})
}

type ValidationRequest struct {
	NodeID                string         `json:"node_id"`
	PoolID                string         `json:"pool_id"`
	GrantID               string         `json:"grant_id"`
	CertificateThumbprint string         `json:"certificate_thumbprint"`
	Scopes                []string       `json:"scopes"`
	Resources             map[string]any `json:"resources"`
}

func (s *AssignmentService) Validate(ctx context.Context, p Principal, v ValidationRequest) (map[string]any, error) {
	if !p.HasScope("assignment") {
		return nil, domain.Err(403, "node_scope_required")
	}
	e := s.DB.WithTx(ctx, false, func(tx *store.Tx) error { _, e := s.actor(ctx, tx, p, false, true, false); return e })
	if e != nil {
		return nil, e
	}
	if v.NodeID != p.NodeID || v.PoolID != p.PoolID || v.GrantID != p.GrantID || v.CertificateThumbprint != s.Config.ManagerCertificateThumbprint || v.Scopes == nil {
		return map[string]any{"valid": false}, nil
	}
	candidate := p
	candidate.CertificateThumbprint = v.CertificateThumbprint
	candidate.Scopes = v.Scopes
	candidate.Resources = v.Resources
	valid, e := s.CheckNodeGrant(ctx, candidate)
	if e != nil {
		return nil, e
	}
	return map[string]any{"valid": valid}, nil
}
func (s *AssignmentService) Assignment(ctx context.Context, p Principal) (map[string]any, error) {
	if !p.HasScope("assignment") {
		return nil, domain.Err(403, "node_scope_required")
	}
	var d allocationView
	e := s.DB.WithTx(ctx, false, func(tx *store.Tx) error { var err error; d, err = s.actor(ctx, tx, p, true, true, false); return err })
	if e != nil {
		return nil, e
	}
	doc, e := s.Config.Provisioner.PreparedComponent(ctx, d.job, d.attempt, d.component.ComponentID)
	if e != nil {
		return nil, e
	}
	if doc["job_id"] != p.JobID || doc["attempt_id"] != p.AttemptID || doc["component_id"] != p.ComponentID || number(doc["epoch"]) != p.Epoch {
		return nil, domain.Err(503, "prepared_assignment_binding_mismatch")
	}
	if e = validatePrepared(doc, d.component.Role, d.spec); e != nil {
		return nil, e
	}
	if s.Config.ValidatePrepared == nil {
		return nil, domain.Err(503, "prepared_assignment_validator_unavailable")
	}
	if e = s.Config.ValidatePrepared(doc, d.component.Role); e != nil {
		return nil, domain.Err(503, "prepared_assignment_contains_unapproved_inputs")
	}
	e = s.DB.WithTx(ctx, false, func(tx *store.Tx) error { _, err := s.actor(ctx, tx, p, true, true, false); return err })
	if e != nil {
		return nil, e
	}
	return doc, nil
}
func validatePrepared(doc map[string]any, role string, spec domain.JobSpec) error {
	if doc["source_dir"] != "/job/source" || doc["state_dir"] != "/job/state" {
		return domain.Err(503, "prepared_assignment_contains_unapproved_inputs")
	}
	if role != "build" && (doc["proxy_socket"] != "/run/hf2l/proxy.sock" || doc["exchange_endpoint"] != "http://proxy") {
		return domain.Err(503, "prepared_assignment_contains_unapproved_inputs")
	}
	b, e := domain.CanonicalJSON(doc["spec"])
	if e != nil {
		return domain.Err(503, "prepared_assignment_contains_unapproved_inputs")
	}
	parsed, e := domain.DecodeJobSpec(b)
	if e != nil {
		return domain.Err(503, "prepared_assignment_contains_unapproved_inputs")
	}
	want, e := spec.Digest()
	if e != nil {
		return e
	}
	got, e := parsed.Digest()
	if e != nil || want != got {
		return domain.Err(503, "prepared_assignment_contains_unapproved_inputs")
	}
	return nil
}
func (s *AssignmentService) IssueCertificate(ctx context.Context, p Principal, csr, space, principal string) (map[string]any, error) {
	if !p.HasScope("assignment") {
		return nil, domain.Err(403, "node_scope_required")
	}
	if s.Config.IssueCertificate == nil {
		return nil, domain.Err(503, "execution_certificate_issuer_unavailable")
	}
	if len(csr) < 1 || len(csr) > 16384 {
		return nil, domain.Err(422, "invalid_execution_csr")
	}
	var d allocationView
	e := s.DB.WithTx(ctx, false, func(tx *store.Tx) error { var err error; d, err = s.actor(ctx, tx, p, true, true, false); return err })
	if e != nil {
		return nil, e
	}
	if d.component.Role == "build" {
		return nil, domain.Err(403, "build_execution_has_no_workload_credentials")
	}
	expectedSpace, e := s.Config.Provisioner.OwnedSpace(ctx, p.JobID)
	if e != nil {
		return nil, e
	}
	expectedPrincipal, e := exchange.StableWorkloadPrincipal(s.Broker.Issuer(), p.JobID, p.ComponentID, d.component.ParticipantID)
	if e != nil {
		return nil, e
	}
	if space == "" || space != expectedSpace || principal != expectedPrincipal {
		return nil, domain.Err(403, "foreign_execution_certificate_binding")
	}
	if _, e := certificates.ValidateCSR([]byte(csr)); e != nil {
		return nil, domain.Err(422, "invalid_execution_csr")
	}

	deadline, ok := store.Time(d.job["deadline_at"])
	if !ok {
		return nil, domain.Err(409, "node_assignment_not_ready")
	}
	hash := sha256.Sum256([]byte(csr))
	csrHash := hex.EncodeToString(hash[:])
	id := principalIdentity(p)
	desired := map[string]any{"job_id": p.JobID, "attempt_id": p.AttemptID, "component_id": p.ComponentID, "epoch": p.Epoch, "node_id": p.NodeID, "space_id": space, "principal_id": principal, "csr_hash": csrHash, "deadline": float64(deadline.Unix()) + float64(deadline.Nanosecond())/1e9}
	receipt, e := s.Ledger.Run(ctx, resources.OperationRequest{JobID: p.JobID, AttemptID: p.AttemptID, ComponentID: p.ComponentID, Operation: "managed_client_certificate", Key: resources.StableKey("managed-client-certificate", id.Key()), Desired: desired}, func(ctx context.Context) (map[string]any, error) {
		return s.Config.IssueCertificate(ctx, csr, id, space, deadline)
	})
	if e != nil {
		if errors.Is(e, resources.ErrUnsafe) || errors.Is(e, resources.ErrBusy) {
			return nil, domain.Err(409, "execution_certificate_binding_immutable")
		}
		if errors.Is(e, certificates.ErrRefused) {
			return nil, domain.Err(503, "execution_certificate_issuer_unavailable")
		}
		return nil, e
	}
	fingerprint := valueString(receipt["certificate_thumbprint"])
	if validateThumbprint(fingerprint) != nil || valueString(receipt["certificate_pem"]) == "" {
		return nil, domain.Err(503, "invalid_execution_certificate_receipt")
	}
	e = s.DB.WithTx(ctx, false, func(tx *store.Tx) error { _, err := s.actor(ctx, tx, p, true, true, false); return err })
	if e != nil {
		return nil, e
	}
	details := map[string]any{}
	for k, v := range receipt {
		details[k] = v
	}
	for k, v := range map[string]any{"csr_hash": csrHash, "space_id": space, "principal_id": principal, "epoch": p.Epoch, "node_id": p.NodeID} {
		details[k] = v
	}
	_, e = s.Ledger.Own(ctx, resources.Ownership{JobID: p.JobID, AttemptID: p.AttemptID, ComponentID: p.ComponentID, Kind: "execution_certificate", ExternalID: id.Key(), Details: details})
	return receipt, e
}
func (s *AssignmentService) Credentials(ctx context.Context, p Principal, fingerprint, audience string) (map[string]any, error) {
	if !p.HasScope("assignment") {
		return nil, domain.Err(403, "node_scope_required")
	}
	if audience != "exchange" && audience != "gateway" {
		return nil, domain.Err(422, "invalid_workload_audience")
	}
	if validateThumbprint(fingerprint) != nil {
		return nil, domain.Err(422, "invalid_node_certificate")
	}
	var d allocationView
	var cert, grant map[string]any
	e := s.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		var err error
		d, err = s.actor(ctx, tx, p, true, true, false)
		if err != nil {
			return err
		}
		if d.component.Role == "build" {
			return domain.Err(403, "build_execution_has_no_workload_credentials")
		}
		cert, err = tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id = ? AND attempt_id = ? AND component_id = ? AND kind = ? AND external_id = ? AND state = ?", p.JobID, p.AttemptID, p.ComponentID, "execution_certificate", principalIdentity(p).Key(), "ready")
		if err != nil {
			return err
		}
		grant, err = tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id = ? AND attempt_id = ? AND component_id = ? AND kind = ? AND state = ?", p.JobID, p.AttemptID, p.ComponentID, "workload_grant", "ready")
		if err != nil {
			return err
		}
		if cert == nil || grant == nil {
			return domain.Err(409, "workload_grant_not_ready")
		}
		if valueMap(cert["details_json"])["certificate_thumbprint"] != fingerprint {
			return domain.Err(403, "foreign_execution_certificate_binding")
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	certFields := valueMap(cert["details_json"])
	grantFields := valueMap(grant["details_json"])
	grantID := valueString(grantFields["grant_id"])
	space := valueString(certFields["space_id"])
	current, e := s.Config.Provisioner.ExchangeGrant(ctx, space, grantID)
	if e != nil {
		return nil, e
	}
	expected := map[string]any{"job_id": p.JobID, "attempt_id": p.AttemptID, "component_id": p.ComponentID, "epoch": p.Epoch, "space_id": space, "principal_id": certFields["principal_id"], "certificate_thumbprint": fingerprint}
	for k, v := range expected {
		if !mapsEqual(current[k], v) {
			return nil, domain.Err(401, "workload_grant_revoked")
		}
	}
	expires := floatValue(current["expires_at"])
	deadline, ok := store.Time(d.job["deadline_at"])
	if current["grant_id"] != grantID || current["enabled"] != true || !ok || math.IsNaN(expires) || math.IsInf(expires, 0) || expires <= float64(s.now().UnixNano())/1e9 {
		return nil, domain.Err(401, "workload_grant_revoked")
	}
	remaining := math.Min(expires-float64(s.now().UnixNano())/1e9, deadline.Sub(s.now()).Seconds())
	ttl := int64(math.Min(300, remaining))
	if ttl < 1 {
		return nil, domain.Err(401, "workload_grant_revoked")
	}
	var token string
	e = s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		if _, err := s.actor(ctx, tx, p, true, true, true); err != nil {
			return err
		}
		var err error
		token, err = s.Broker.IssueWorkload(exchange.WorkloadRequest{JobID: p.JobID, AttemptID: p.AttemptID, ComponentID: p.ComponentID, SpaceID: space, GrantID: grantID, Epoch: p.Epoch, CertificateThumbprint: fingerprint, ParticipantID: d.component.ParticipantID, Audience: audience, TTLSeconds: ttl})
		return err
	})
	if e != nil {
		return nil, e
	}
	return map[string]any{"token": token, "expires_at": s.now().Unix() + ttl}, nil
}
func floatValue(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int64:
		return float64(n)
	case int:
		return float64(n)
	case json.Number:
		f, e := n.Float64()
		if e == nil {
			return f
		}
	}
	return math.NaN()
}
func (s *AssignmentService) CheckRegistration(_ context.Context, p exchange.PlatformNodePrincipal) (bool, error) {
	n, e := s.registration(p.NodeID, p.PoolID)
	return e == nil && n.RegistrationID == p.RegistrationID && p.CertificateThumbprint == s.Config.ManagerCertificateThumbprint && len(p.Scopes) == 1 && p.Scopes[0] == "qualify", nil
}
func (s *AssignmentService) IssuePlatformToken(_ context.Context, nodeID, poolID, registration, certificate string) (string, error) {
	n, e := s.registration(nodeID, poolID)
	if e != nil {
		return "", e
	}
	if certificate == "" {
		certificate = s.Config.ManagerCertificateThumbprint
	}
	if registration != n.RegistrationID || certificate == "" || certificate != s.Config.ManagerCertificateThumbprint {
		return "", domain.Err(403, "node_registration_required")
	}
	return s.Broker.IssueNodePlatform(exchange.PlatformNodeRequest{NodeID: nodeID, PoolID: poolID, RegistrationID: registration, CertificateThumbprint: certificate, TTLSeconds: 300})
}
func (c *CredentialClient) Validate(ctx context.Context, p Principal) (bool, error) {
	scopes := append([]string(nil), p.Scopes...)
	sort.Strings(scopes)
	v, e := c.Request(ctx, principalIdentity(p), "validate", "POST", ValidationRequest{NodeID: p.NodeID, PoolID: p.PoolID, GrantID: p.GrantID, CertificateThumbprint: p.CertificateThumbprint, Scopes: scopes, Resources: p.Resources})
	return v["valid"] == true, e
}
