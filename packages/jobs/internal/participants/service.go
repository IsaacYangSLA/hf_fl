package participants

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/certificates"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/resources"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

type record struct {
	Enrollment, Job, Attempt map[string]any
	Spec                     domain.JobSpec
	Participant              domain.ParticipantSpec
	Node                     ApprovedNode
}

func (s *Service) approved(ctx context.Context, tx *store.Tx, job map[string]any, participantID, nodeID string, enabled bool) (domain.JobSpec, domain.ParticipantSpec, ApprovedNode, error) {
	spec, e := decodeSpec(job)
	if e != nil {
		return spec, domain.ParticipantSpec{}, ApprovedNode{}, e
	}
	var participant domain.ParticipantSpec
	found := false
	for _, p := range spec.Participants {
		if p.ParticipantID == participantID && p.Mode == "external" {
			participant = p
			found = true
			break
		}
	}
	if !found {
		return spec, participant, ApprovedNode{}, domain.Err(404, "participant_not_found")
	}
	binding, e := tx.One(ctx, "SELECT * FROM jm_participant_bindings WHERE id=?", participant.DatasetBinding)
	if e != nil {
		return spec, participant, ApprovedNode{}, e
	}
	node, exists := s.Nodes[nodeID]
	_, dataset := node.DatasetBindings[participant.DatasetBinding]
	if binding == nil || !exists || !dataset || str(binding["project_id"]) != str(job["project_id"]) || str(binding["participant_id"]) != participantID || str(binding["node_id"]) == "" || str(binding["node_id"]) != nodeID || (enabled && (!truth(binding["enabled"]) || !node.Enabled)) {
		return spec, participant, node, domain.Err(403, "external_node_not_approved")
	}
	return spec, participant, node, nil
}
func (s *Service) userJob(ctx context.Context, tx *store.Tx, principal, jobID string, operator, write bool) (map[string]any, error) {
	clause := ""
	if write {
		clause = tx.ForUpdate()
	}
	job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+clause, jobID)
	if e != nil {
		return nil, e
	}
	member, e := tx.One(ctx, "SELECT * FROM jm_job_members WHERE job_id=? AND principal_id=?", jobID, principal)
	if e != nil {
		return nil, e
	}
	role := str(member["role"])
	if job == nil || !contains([]string{"reader", "operator", "admin"}, role) {
		return nil, domain.Err(404, "job_not_found")
	}
	if operator && role == "reader" {
		return nil, domain.Err(403, "job_role_required")
	}
	return job, nil
}
func enrollmentView(row, job map[string]any) map[string]any {
	data := mapv(row["details_json"])
	status := str(data["status"])
	if status == "" {
		status = "enrolled"
	}
	return map[string]any{"id": row["id"], "job_id": job["id"], "participant_id": data["participant_id"], "node_id": data["node_id"], "dataset_binding": data["dataset_binding"], "component_id": row["component_id"], "status": status, "attempt_id": row["attempt_id"], "epoch": data["epoch"], "version": job["version"], "external": true, "manager_allocation": false}
}
func (s *Service) Enroll(ctx context.Context, principal, jobID, participantID, nodeID string, expected int64, key string) (map[string]any, error) {
	if domain.ValidateIdentifier(participantID) != nil || domain.ValidateIdentifier(nodeID) != nil {
		return nil, domain.Err(422, "invalid_participant_binding")
	}
	if key == "" || len(key) > 128 || strings.IndexFunc(key, func(r rune) bool { return r < 32 }) >= 0 {
		return nil, domain.Err(422, "idempotency_key_required")
	}
	var result map[string]any
	e := s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		job, e := s.userJob(ctx, tx, principal, jobID, true, true)
		if e != nil {
			return e
		}
		spec, p, node, e := s.approved(ctx, tx, job, participantID, nodeID, true)
		if e != nil {
			return e
		}
		body := map[string]any{"participant_id": participantID, "node_id": nodeID}
		bodyHash, e := domain.Hash(body)
		if e != nil {
			return e
		}
		scope := "external.enroll:" + jobID
		prior, e := tx.One(ctx, "SELECT * FROM jm_idempotency WHERE principal_id=? AND scope=? AND key=?", principal, scope, key)
		if e != nil {
			return e
		}
		id := stableKey("external-enrollment", jobID, participantID)[:32]
		existing, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id=?", id)
		if e != nil {
			return e
		}
		if prior != nil {
			if str(prior["request_hash"]) != bodyHash {
				return domain.Err(409, "idempotency_conflict")
			}
			if existing == nil {
				return domain.Err(409, "participant_enrollment_not_found")
			}
			result = enrollmentView(existing, job)
			return nil
		}
		if expected < 1 {
			return domain.Err(428, "expected_version_required")
		}
		if expected != number(job["version"]) {
			return domain.Err(409, "job_version_conflict", map[string]any{"current_version": job["version"]})
		}
		end, hasDeadline := store.Time(job["deadline_at"])
		if !(active(str(job["state"])) || str(job["state"]) == "QUEUED") || (hasDeadline && !s.now().Before(end)) {
			return domain.Err(409, "job_not_enrollable")
		}
		if existing != nil {
			data := mapv(existing["details_json"])
			if str(data["node_id"]) != nodeID || str(data["node_certificate_thumbprint"]) != node.CertificateThumbprint {
				return domain.Err(409, "external_node_binding_immutable")
			}
			result = enrollmentView(existing, job)
		} else {
			digest, e := spec.Digest()
			if e != nil {
				return e
			}
			data := map[string]any{"participant_id": participantID, "node_id": nodeID, "node_certificate_thumbprint": node.CertificateThumbprint, "dataset_binding": p.DatasetBinding, "spec_digest": digest, "status": "enrolled", "termination_confirmed": true}
			row := map[string]any{"id": id, "job_id": jobID, "component_id": ComponentID(participantID), "kind": "external_enrollment", "external_id": jobID + ":" + participantID, "state": "ready", "retained": true, "ownership_json": map[string]any{"job_id": jobID, "participant_id": participantID, "component_id": ComponentID(participantID)}, "details_json": data}
			if e = tx.Insert(ctx, "jm_provisioning_resources", row); e != nil {
				return e
			}
			job["version"] = number(job["version"]) + 1
			if e = tx.Update(ctx, "jm_jobs", map[string]any{"id": jobID}, map[string]any{"version": job["version"], "updated_at": s.now()}); e != nil {
				return e
			}
			if e = s.emit(ctx, tx, job, "participant.enrolled", principal, map[string]any{"participant_id": participantID, "node_id": nodeID}); e != nil {
				return e
			}
			result = enrollmentView(row, job)
		}
		return tx.Insert(ctx, "jm_idempotency", map[string]any{"principal_id": principal, "scope": scope, "key": key, "request_hash": bodyHash, "response_json": result, "created_at": s.now()})
	})
	return result, e
}
func (s *Service) GetEnrollment(ctx context.Context, principal, jobID, participantID string) (map[string]any, error) {
	var result map[string]any
	e := s.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		job, e := s.userJob(ctx, tx, principal, jobID, false, false)
		if e != nil {
			return e
		}
		row, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id=?", stableKey("external-enrollment", jobID, participantID)[:32])
		if e != nil {
			return e
		}
		if row == nil {
			return domain.Err(404, "participant_enrollment_not_found")
		}
		result = enrollmentView(row, job)
		return nil
	})
	return result, e
}
func (s *Service) nodeRecord(ctx context.Context, tx *store.Tx, actor Actor, requireActive, write bool) (*record, error) {
	clause := ""
	if write {
		clause = tx.ForUpdate()
	}
	job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+clause, actor.JobID)
	if e != nil {
		return nil, e
	}
	row, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id=?"+clause, actor.GrantID)
	if e != nil {
		return nil, e
	}
	attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id=?", actor.AttemptID)
	if e != nil {
		return nil, e
	}
	if job == nil || row == nil || attempt == nil || str(row["kind"]) != "external_enrollment" || str(row["job_id"]) != actor.JobID || str(attempt["job_id"]) != actor.JobID || number(job["current_attempt"]) != number(attempt["number"]) || number(job["epoch"]) != number(attempt["epoch"]) || actor.Epoch != number(attempt["epoch"]) || str(row["attempt_id"]) != actor.AttemptID || str(row["component_id"]) != actor.ComponentID || actor.PoolID != "external" || str(row["state"]) != "ready" || !controlled(str(job["state"])) || (requireActive && !active(str(job["state"]))) {
		return nil, domain.Err(404, "participant_assignment_not_found")
	}
	data := mapv(row["details_json"])
	if requireActive && (str(data["status"]) == "stopped" || truth(data["stop_requested"])) {
		return nil, domain.Err(404, "participant_assignment_not_found")
	}
	spec, p, node, e := s.approved(ctx, tx, job, str(data["participant_id"]), str(data["node_id"]), requireActive)
	if e != nil {
		return nil, e
	}
	digest, e := spec.Digest()
	if e != nil {
		return nil, e
	}
	end, hasDeadline := store.Time(job["deadline_at"])
	if actor.NodeID != node.NodeID || actor.CertificateThumbprint != node.CertificateThumbprint || str(data["node_certificate_thumbprint"]) != node.CertificateThumbprint || str(data["spec_digest"]) != digest || (requireActive && hasDeadline && !s.now().Before(end)) {
		return nil, domain.Err(404, "participant_assignment_not_found")
	}
	return &record{Enrollment: row, Job: job, Attempt: attempt, Spec: spec, Participant: p, Node: node}, nil
}
func (s *Service) CheckNodeGrant(ctx context.Context, actor Actor) bool {
	if contains(actor.Scopes, "purge") {
		return NewExternalCleanup(s).CheckNodeGrant(ctx, actor)
	}
	return s.DB.WithTx(ctx, false, func(tx *store.Tx) error { _, e := s.nodeRecord(ctx, tx, actor, false, false); return e }) == nil
}
func (s *Service) SourceAccessValid(ctx context.Context, actor Actor) bool {
	if !contains(actor.Scopes, "assignment") {
		return false
	}
	return s.DB.WithTx(ctx, false, func(tx *store.Tx) error { _, e := s.nodeRecord(ctx, tx, actor, true, false); return e }) == nil
}
func (s *Service) BuildAccessValid(ctx context.Context, actor Actor) bool {
	if !s.SourceAccessValid(ctx, actor) {
		return false
	}
	return s.Hooks.BuildAccessValid != nil && s.Hooks.BuildAccessValid(ctx, actor)
}
func (s *Service) logBudget(ctx context.Context, tx *store.Tx, r *record) (map[string]any, error) {
	id := "hf2l-log://" + str(r.Job["id"]) + "/" + fmt.Sprint(number(r.Attempt["number"])) + "/" + str(r.Enrollment["component_id"])
	budget, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id=? AND kind=? AND external_id=?"+tx.ForUpdate(), r.Job["id"], "log_budget", id)
	if e != nil {
		return nil, e
	}
	if budget == nil {
		return nil, domain.Err(409, "participant_log_budget_unavailable")
	}
	d := mapv(budget["details_json"])
	owner := mapv(budget["ownership_json"])
	pool := s.Hooks.StoragePoolID
	if pool == "" {
		for _, c := range r.Spec.Components {
			if c.Role == "owner" {
				pool = c.Resources.PoolID
			}
		}
	}
	digest, e := r.Spec.Digest()
	if e != nil {
		return nil, e
	}
	want := map[string]any{"job_id": r.Job["id"], "component_id": r.Enrollment["component_id"], "kind": "log_budget"}
	a, _ := domain.CanonicalJSON(owner)
	b, _ := domain.CanonicalJSON(want)
	if str(budget["attempt_id"]) != str(r.Attempt["id"]) || str(budget["component_id"]) != str(r.Enrollment["component_id"]) || !contains([]string{"planned", "ready"}, str(budget["state"])) || budget["deleted_at"] != nil || string(a) != string(b) || str(d["spec_digest"]) != digest || str(d["component_id"]) != str(r.Enrollment["component_id"]) || number(d["attempt_number"]) != number(r.Attempt["number"]) || number(d["reservation_max_bytes"]) != 1<<20 || number(d["retention_reservation_bytes"]) != 1<<20 || number(d["retention_charged_bytes"]) != 1<<20 || d["retention_charge_released"] != false || budget["retained"] != true || number(budget["size_bytes"]) != 1<<20 || str(d["pool_id"]) != pool {
		return nil, domain.Err(409, "participant_log_budget_unavailable")
	}
	found, e := tx.One(ctx, "SELECT id FROM jm_pools WHERE id=?", pool)
	if e != nil {
		return nil, e
	}
	if found == nil {
		return nil, domain.Err(409, "participant_log_budget_unavailable")
	}
	return budget, nil
}
func (s *Service) BootstrapCredentials(ctx context.Context, enrollmentID string) (map[string]any, error) {
	var out map[string]any
	e := s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		lookup, e := tx.One(ctx, "SELECT job_id FROM jm_provisioning_resources WHERE id=?", enrollmentID)
		if e != nil {
			return e
		}
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), lookup["job_id"])
		if e != nil {
			return e
		}
		row, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id=?"+tx.ForUpdate(), enrollmentID)
		if e != nil {
			return e
		}
		if row == nil || job == nil || str(row["kind"]) != "external_enrollment" {
			return domain.Err(404, "participant_enrollment_not_found")
		}
		data := clone(mapv(row["details_json"]))
		spec, p, node, e := s.approved(ctx, tx, job, str(data["participant_id"]), str(data["node_id"]), false)
		if e != nil {
			return e
		}
		if str(data["node_certificate_thumbprint"]) != node.CertificateThumbprint {
			return domain.Err(403, "external_node_binding_immutable")
		}
		attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE job_id=? AND number=? AND epoch=?", job["id"], job["current_attempt"], job["epoch"])
		if e != nil {
			return e
		}
		if attempt == nil || !controlled(str(job["state"])) {
			return domain.Err(409, "participant_assignment_not_ready")
		}
		if str(row["attempt_id"]) != str(attempt["id"]) {
			if data["termination_confirmed"] != true {
				return domain.Err(409, "previous_participant_termination_unconfirmed")
			}
			if str(row["attempt_id"]) != "" {
				prior, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id=?", row["attempt_id"])
				if e != nil {
					return e
				}
				if prior == nil || prior["revocation_confirmed"] != true {
					return domain.Err(409, "previous_participant_revocation_unconfirmed")
				}
			}
			data["status"] = "enrolled"
			data["epoch"] = attempt["epoch"]
			data["termination_confirmed"] = true
			for _, k := range []string{"execution_certificate_thumbprint", "proxy_id", "workload_grant", "last_heartbeat", "grant_expires_at", "external_execution_id", "stop_requested", "issued_certificate_thumbprint", "issued_certificate_csr_hash"} {
				delete(data, k)
			}
			row["attempt_id"] = attempt["id"]
			if e = tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": row["id"]}, map[string]any{"attempt_id": attempt["id"], "details_json": data}); e != nil {
				return e
			}
		}
		binding, e := tx.One(ctx, "SELECT * FROM jm_participant_bindings WHERE id=?", p.DatasetBinding)
		if e != nil {
			return e
		}
		scopes := []string{"stopped", "logs", "collect"}
		if active(str(job["state"])) && node.Enabled && truth(binding["enabled"]) && str(data["status"]) != "stopped" && !truth(data["stop_requested"]) {
			scopes = []string{"assignment", "heartbeat", "stopped", "logs", "collect"}
			r := &record{Enrollment: row, Job: job, Attempt: attempt, Spec: spec, Participant: p, Node: node}
			budget, e := s.logBudget(ctx, tx, r)
			if e != nil {
				return e
			}
			execution := executor.ExecutionIdentity{JobID: str(job["id"]), AttemptID: str(attempt["id"]), ComponentID: str(row["component_id"]), Epoch: number(attempt["epoch"])}
			id := stableKey("external-execution", execution.Key())[:32]
			old, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id=?", id)
			if e != nil {
				return e
			}
			digest, e := spec.Digest()
			if e != nil {
				return e
			}
			if old == nil {
				old = map[string]any{"id": id, "job_id": job["id"], "attempt_id": attempt["id"], "component_id": row["component_id"], "kind": "external_execution", "external_id": execution.Key(), "state": "ready", "retained": true, "ownership_json": map[string]any{"job_id": job["id"], "attempt_id": attempt["id"], "component_id": row["component_id"]}, "details_json": map[string]any{"node_id": node.NodeID, "node_certificate_thumbprint": node.CertificateThumbprint, "participant_id": p.ParticipantID, "dataset_binding": p.DatasetBinding, "spec_digest": digest, "epoch": attempt["epoch"], "termination_confirmed": false}}
				if e = tx.Insert(ctx, "jm_provisioning_resources", old); e != nil {
					return e
				}
			} else {
				d := mapv(old["details_json"])
				if str(old["job_id"]) != str(job["id"]) || str(old["attempt_id"]) != str(attempt["id"]) || str(d["node_id"]) != node.NodeID || str(d["node_certificate_thumbprint"]) != node.CertificateThumbprint || (str(d["log_resource_id"]) != "" && str(d["log_resource_id"]) != str(budget["id"])) {
					return domain.Err(409, "external_execution_binding_immutable")
				}
			}
			details := clone(mapv(old["details_json"]))
			details["log_resource_id"] = budget["id"]
			if e = s.saveDetails(ctx, tx, old, details); e != nil {
				return e
			}
			data["log_resource_id"] = budget["id"]
			data["external_execution_id"] = id
			data["termination_confirmed"] = false
			if str(data["status"]) == "enrolled" {
				data["status"] = "dispatching"
			}
			if e = s.saveDetails(ctx, tx, row, data); e != nil {
				return e
			}
		}
		token, e := s.issueNode(ctx, NodeGrant{NodeID: node.NodeID, PoolID: "external", JobID: str(job["id"]), AttemptID: str(attempt["id"]), ComponentID: str(row["component_id"]), GrantID: str(row["id"]), Epoch: number(attempt["epoch"]), CertificateThumbprint: node.CertificateThumbprint, Scopes: scopes, TTLSeconds: 300})
		if e != nil {
			return e
		}
		row["details_json"] = data
		operation := "stop"
		if contains(scopes, "assignment") {
			operation = "start"
		}
		out = map[string]any{"enrollment": enrollmentView(row, job), "node_token": token, "node_certificate_thumbprint": node.CertificateThumbprint, "operation": operation}
		return nil
	})
	return out, e
}
func (s *Service) ControlPlan(ctx context.Context, actor Actor) (map[string]any, error) {
	if e := checkScope(actor, "stopped"); e != nil {
		return nil, e
	}
	var out map[string]any
	e := s.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		r, e := s.nodeRecord(ctx, tx, actor, false, false)
		if e != nil {
			return e
		}
		d := mapv(r.Enrollment["details_json"])
		out = map[string]any{"identity": identity(r.Job, r.Attempt, actor.ComponentID), "node_id": r.Node.NodeID, "status": d["status"], "termination_confirmed": truth(d["termination_confirmed"]), "revocation_confirmed": truth(r.Attempt["revocation_confirmed"])}
		return nil
	})
	return out, e
}
func (s *Service) Heartbeat(ctx context.Context, actor Actor, phase string, currentRound *int64) (map[string]any, error) {
	if e := checkScope(actor, "heartbeat"); e != nil {
		return nil, e
	}
	if !contains([]string{"running", "waiting_initialization", "waiting_for_model", "training", "publishing", "completed", "retry", "needs_attention", "stopped"}, phase) {
		return nil, domain.Err(422, "invalid_participant_phase")
	}
	if currentRound != nil && *currentRound < 0 {
		return nil, domain.Err(422, "invalid_participant_round")
	}
	e := s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		r, e := s.nodeRecord(ctx, tx, actor, true, true)
		if e != nil {
			return e
		}
		d := clone(mapv(r.Enrollment["details_json"]))
		var round any
		if currentRound != nil {
			round = *currentRound
		}
		changed := str(d["phase"]) != phase || (d["current_round"] == nil) != (round == nil) || (round != nil && number(d["current_round"]) != *currentRound)
		d["phase"] = phase
		d["current_round"] = round
		d["last_heartbeat"] = s.now().Format(time.RFC3339Nano)
		if e = s.saveDetails(ctx, tx, r.Enrollment, d); e != nil {
			return e
		}
		if changed {
			return s.emit(ctx, tx, r.Job, "participant.progress", actor.ID, map[string]any{"participant_id": r.Participant.ParticipantID, "phase": phase, "current_round": round})
		}
		return nil
	})
	return map[string]any{"accepted": e == nil}, e
}
func (s *Service) AppendLogs(ctx context.Context, actor Actor, receipt map[string]any) (map[string]any, error) {
	if e := checkScope(actor, "logs"); e != nil {
		return nil, e
	}
	var r *record
	e := s.DB.WithTx(ctx, false, func(tx *store.Tx) error { var e error; r, e = s.nodeRecord(ctx, tx, actor, false, false); return e })
	if e != nil {
		return nil, e
	}
	id := str(mapv(r.Enrollment["details_json"])["external_execution_id"])
	if id == "" {
		return nil, domain.Err(409, "external_execution_binding_immutable")
	}
	if s.Hooks.AppendLogs == nil {
		return nil, domain.Err(503, "participant_log_stream_unavailable")
	}
	return s.Hooks.AppendLogs(ctx, actor, id, r.Node.NodeID, receipt)
}
func (s *Service) ConfirmStopped(ctx context.Context, actor Actor, terminationConfirmed, neverStarted bool) (map[string]any, error) {
	if !terminationConfirmed || !contains(actor.Scopes, "stopped") {
		return nil, domain.Err(403, "confirmed_node_stop_required")
	}
	e := s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		r, e := s.nodeRecord(ctx, tx, actor, false, true)
		if e != nil {
			return e
		}
		d := clone(mapv(r.Enrollment["details_json"]))
		var execution map[string]any
		if id := str(d["external_execution_id"]); id != "" {
			execution, e = tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id=?"+tx.ForUpdate(), id)
			if e != nil {
				return e
			}
			if execution == nil || str(execution["job_id"]) != actor.JobID || str(execution["attempt_id"]) != actor.AttemptID || str(execution["component_id"]) != actor.ComponentID {
				return domain.Err(409, "external_execution_binding_immutable")
			}
		}
		if truth(d["termination_confirmed"]) && str(d["status"]) == "stopped" {
			prior := d
			if execution != nil {
				prior = mapv(execution["details_json"])
			}
			if truth(prior["never_started"]) != neverStarted {
				return domain.Err(409, "external_stop_receipt_immutable")
			}
			return nil
		}
		stopped := s.now().Format(time.RFC3339Nano)
		d["termination_confirmed"] = true
		d["status"] = "stopped"
		d["stopped_at"] = stopped
		d["never_started"] = neverStarted
		if e = s.saveDetails(ctx, tx, r.Enrollment, d); e != nil {
			return e
		}
		if execution != nil {
			prior := clone(mapv(execution["details_json"]))
			prior["termination_confirmed"] = true
			prior["stopped_at"] = stopped
			prior["termination_operation_id"] = "external-stop-" + str(execution["id"])
			prior["never_started"] = neverStarted
			if e = s.saveDetails(ctx, tx, execution, prior); e != nil {
				return e
			}
		}
		return s.emit(ctx, tx, r.Job, "participant.stopped", actor.ID, map[string]any{"participant_id": r.Participant.ParticipantID, "epoch": r.Attempt["epoch"]})
	})
	return map[string]any{"accepted": e == nil}, e
}
func (s *Service) AttemptTerminationConfirmed(ctx context.Context, jobID, attemptID string) (bool, error) {
	rows, e := s.DB.All(ctx, "SELECT details_json FROM jm_provisioning_resources WHERE job_id=? AND attempt_id=? AND kind=?", jobID, attemptID, "external_enrollment")
	if e != nil {
		return false, e
	}
	for _, row := range rows {
		if !truth(mapv(row["details_json"])["termination_confirmed"]) {
			return false, nil
		}
	}
	return true, nil
}
func (s *Service) RequestStop(ctx context.Context, job, attempt map[string]any) (bool, error) {
	ids := []string{}
	e := s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		current, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), job["id"])
		if e != nil {
			return e
		}
		if current == nil {
			return domain.Err(404, "job_not_found")
		}
		rows, e := tx.All(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id=? AND attempt_id=? AND kind=?", job["id"], attempt["id"], "external_enrollment")
		if e != nil {
			return e
		}
		for _, row := range rows {
			d := clone(mapv(row["details_json"]))
			d["stop_requested"] = true
			if !truth(d["termination_confirmed"]) {
				ids = append(ids, str(row["id"]))
			}
			if e = s.saveDetails(ctx, tx, row, d); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		return false, e
	}
	if len(ids) == 0 {
		return true, nil
	}
	if s.Dispatch == nil {
		return false, nil
	}
	// Persisted stop intent is dispatched independently of controller tick.
	if _, e = s.DispatchPending(ctx); e != nil {
		return false, e
	}
	return s.AttemptTerminationConfirmed(ctx, str(job["id"]), str(attempt["id"]))
}
func (s *Service) dispatchOne(ctx context.Context, id string) (bool, error) {
	doc, e := s.BootstrapCredentials(ctx, id)
	if e == nil {
		_, e = s.Dispatch(ctx, str(mapv(doc["enrollment"])["node_id"]), doc)
	}
	code := ""
	if e != nil {
		code = "external_node_dispatch_failed"
		if er, ok := e.(*domain.Error); ok {
			if er.Status == 409 {
				return false, nil
			}
			code = er.Code
		}
	}
	update := s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		lookup, e := tx.One(ctx, "SELECT job_id FROM jm_provisioning_resources WHERE id=?", id)
		if e != nil {
			return e
		}
		if lookup == nil {
			return nil
		}
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), lookup["job_id"])
		if e != nil {
			return e
		}
		row, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id=?"+tx.ForUpdate(), id)
		if e != nil {
			return e
		}
		if job == nil || row == nil {
			return nil
		}
		d := clone(mapv(row["details_json"]))
		if code == "" {
			delete(d, "last_dispatch_error")
			delete(d, "dispatch_retry_at")
		} else {
			changed := str(d["last_dispatch_error"]) != code
			d["last_dispatch_error"] = code
			d["dispatch_retry_at"] = s.now().Add(30 * time.Second).Unix()
			if changed {
				if e = s.emit(ctx, tx, job, "participant.attention", "external-dispatch", map[string]any{"participant_id": d["participant_id"], "node_id": d["node_id"], "code": code}); e != nil {
					return e
				}
			}
		}
		return s.saveDetails(ctx, tx, row, d)
	})
	return code == "", update
}
func (s *Service) DispatchPending(ctx context.Context) (map[string]any, error) {
	if s.Dispatch == nil {
		return nil, domain.Err(503, "external_node_dispatch_unavailable")
	}
	var ids []string
	e := s.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		rows, e := tx.All(ctx, "SELECT r.id,r.details_json,j.state FROM jm_provisioning_resources r JOIN jm_jobs j ON r.job_id=j.id WHERE r.kind=? AND r.state=?", "external_enrollment", "ready")
		if e != nil {
			return e
		}
		for _, row := range rows {
			d := mapv(row["details_json"])
			state := str(row["state"])
			if !controlled(state) || (truth(d["termination_confirmed"]) && (!active(state) || str(d["status"]) == "stopped")) || number(d["dispatch_retry_at"]) > s.now().Unix() {
				continue
			}
			ids = append(ids, str(row["id"]))
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	count := 0
	for _, id := range ids {
		s.dispatchMu.Lock()
		if s.closing {
			s.dispatchMu.Unlock()
			break
		}
		if s.dispatchContext == nil {
			s.dispatchContext, s.dispatchCancel = context.WithCancel(context.Background())
		}
		if s.dispatching == nil {
			s.dispatching = map[string]bool{}
		}
		if s.dispatching[id] || len(s.dispatching) >= 8 {
			s.dispatchMu.Unlock()
			continue
		}
		s.dispatching[id] = true
		s.dispatchWG.Add(1)
		dispatchContext := s.dispatchContext
		s.dispatchMu.Unlock()
		count++
		go func(id string) {
			defer s.dispatchWG.Done()
			defer func() { s.dispatchMu.Lock(); delete(s.dispatching, id); s.dispatchMu.Unlock() }()
			bounded, cancel := context.WithTimeout(dispatchContext, 65*time.Second)
			defer cancel()
			_, _ = s.dispatchOne(bounded, id)
		}(id)
	}
	return map[string]any{"dispatched": count}, nil
}
func (s *Service) AssignmentPlan(ctx context.Context, actor Actor) (map[string]any, error) {
	if e := checkScope(actor, "assignment"); e != nil {
		return nil, e
	}
	var r *record
	var snap Snapshot
	var space string
	e := s.DB.WithTx(ctx, false, func(tx *store.Tx) error { var e error; r, e = s.nodeRecord(ctx, tx, actor, true, false); return e })
	if e != nil {
		return nil, e
	}
	space, e = s.spaceID(ctx, actor.JobID)
	if e != nil {
		return nil, e
	}
	if space == "" {
		return nil, domain.Err(409, "participant_assignment_not_ready")
	}
	snap, e = s.snapshot(ctx, r.Job, r.Spec)
	if e != nil {
		return nil, e
	}
	e = s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		var e error
		r, e = s.nodeRecord(ctx, tx, actor, true, true)
		if e != nil {
			return e
		}
		historical, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id=?", mapv(r.Enrollment["details_json"])["external_execution_id"])
		if e != nil {
			return e
		}
		if historical == nil || str(historical["job_id"]) != actor.JobID || str(historical["attempt_id"]) != actor.AttemptID {
			return domain.Err(409, "external_execution_binding_immutable")
		}
		d := clone(mapv(historical["details_json"]))
		if old := d["source_manifest"]; old != nil {
			a, _ := domain.CanonicalJSON(old)
			b, _ := domain.CanonicalJSON(snap.Manifest)
			if string(a) != string(b) {
				return domain.Err(409, "participant_source_mismatch")
			}
		}
		d["source_manifest"] = snap.Manifest
		return s.saveDetails(ctx, tx, historical, d)
	})
	if e != nil {
		return nil, e
	}
	if s.Hooks.Image == nil || s.Hooks.SourceLimits == nil {
		return nil, domain.Err(503, "participant_source_approval_unavailable")
	}
	image, e := s.Hooks.Image(ctx, r.Spec)
	if e != nil {
		return nil, e
	}
	limits, e := s.Hooks.SourceLimits(ctx, r.Spec)
	if e != nil {
		return nil, e
	}
	built, e := s.builtArtifacts(ctx, actor, r.Spec)
	if e != nil {
		return nil, e
	}
	var end any
	if t, ok := store.Time(r.Job["deadline_at"]); ok {
		end = float64(t.UnixMicro()) / 1e6
	}
	issuer := s.Hooks.WorkloadIssuer
	if issuer == "" && s.Broker != nil {
		issuer = s.Broker.Issuer()
	}
	return map[string]any{"identity": identity(r.Job, r.Attempt, actor.ComponentID), "node_id": r.Node.NodeID, "pool_id": "external", "job_spec": r.Spec.Map(), "image_digest": image, "resources": r.Node.Resources, "lease_seconds": int64(120), "deadline": end, "external_participant_id": r.Participant.ParticipantID, "space_id": space, "principal_id": stableWorkloadPrincipal(issuer, actor.JobID, actor.ComponentID, r.Participant.ParticipantID), "source_manifest": snap.Manifest, "source_limits": limits, "built_artifacts": built}, nil
}
func (s *Service) builtArtifacts(ctx context.Context, actor Actor, spec domain.JobSpec) (map[string]any, error) {
	needed := false
	for _, c := range spec.Components {
		if c.Role == "build" {
			needed = true
		}
	}
	if !needed {
		return map[string]any{}, nil
	}
	if s.Hooks.BuiltArtifacts == nil {
		return nil, domain.Err(503, "participant_build_unavailable")
	}
	return s.Hooks.BuiltArtifacts(ctx, actor, spec)
}
func (s *Service) IssueCertificate(ctx context.Context, actor Actor, csrPEM, spaceID, principalID string) (map[string]any, error) {
	if e := checkScope(actor, "assignment"); e != nil {
		return nil, e
	}
	if s.Issuer == nil {
		return nil, domain.Err(503, "execution_certificate_issuer_unavailable")
	}
	if len(csrPEM) < 1 || len(csrPEM) > 16384 {
		return nil, domain.Err(422, "invalid_execution_csr")
	}
	if _, e := certificates.ValidateCSR([]byte(csrPEM)); e != nil {
		return nil, domain.Err(422, "invalid_execution_csr")
	}
	sum := sha256.Sum256([]byte(csrPEM))
	csrHash := hex.EncodeToString(sum[:])
	var r *record
	var end time.Time
	e := s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		var e error
		r, e = s.nodeRecord(ctx, tx, actor, true, true)
		if e != nil {
			return e
		}
		d := mapv(r.Enrollment["details_json"])
		if old := str(d["issued_certificate_csr_hash"]); old != "" && old != csrHash {
			return domain.Err(409, "participant_execution_binding_immutable")
		}
		end = deadline(r.Job, s.now(), r.Spec.MaxDurationSeconds)
		return nil
	})
	if e != nil {
		return nil, e
	}
	space, e := s.spaceID(ctx, actor.JobID)
	if e != nil {
		return nil, e
	}
	issuer := s.Hooks.WorkloadIssuer
	if issuer == "" && s.Broker != nil {
		issuer = s.Broker.Issuer()
	}
	expected := stableWorkloadPrincipal(issuer, actor.JobID, actor.ComponentID, r.Participant.ParticipantID)
	if space == "" {
		return nil, domain.Err(409, "participant_assignment_not_ready")
	}
	if space != spaceID || expected != principalID {
		return nil, domain.Err(403, "participant_foreign_certificate_binding")
	}
	ident := executor.ExecutionIdentity{JobID: actor.JobID, AttemptID: actor.AttemptID, ComponentID: actor.ComponentID, Epoch: actor.Epoch}
	ledger := resources.NewLedger(s.DB)
	result, e := ledger.Run(ctx, resources.OperationRequest{JobID: actor.JobID, AttemptID: actor.AttemptID, ComponentID: actor.ComponentID, Operation: "external_client_certificate", Key: stableKey("external-client-certificate", ident.Key()), Desired: map[string]any{"identity": identity(r.Job, r.Attempt, actor.ComponentID), "space_id": spaceID, "principal_id": principalID, "csr_hash": csrHash, "deadline": float64(end.UnixMicro()) / 1e6}}, func(ctx context.Context) (map[string]any, error) {
		issued, e := s.Issuer.Issue([]byte(csrPEM), certificates.Binding{JobID: actor.JobID, AttemptID: actor.AttemptID, ComponentID: actor.ComponentID, SpaceID: spaceID, Epoch: actor.Epoch}, end)
		if e != nil {
			return nil, domain.Err(503, "execution_certificate_issuer_unavailable")
		}
		return map[string]any{"certificate_pem": issued.CertificatePEM, "certificate_thumbprint": issued.CertificateThumbprint, "expires_at": issued.ExpiresAt}, nil
	})
	if e != nil {
		return nil, e
	}
	fingerprint := str(result["certificate_thumbprint"])
	if !validThumbprint(fingerprint) || str(result["certificate_pem"]) == "" {
		return nil, domain.Err(503, "invalid_execution_certificate_receipt")
	}
	e = s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		current, e := s.nodeRecord(ctx, tx, actor, true, true)
		if e != nil {
			return e
		}
		d := clone(mapv(current.Enrollment["details_json"]))
		if old := str(d["issued_certificate_csr_hash"]); old != "" && old != csrHash {
			return domain.Err(409, "participant_execution_binding_immutable")
		}
		d["issued_certificate_csr_hash"] = csrHash
		d["issued_certificate_thumbprint"] = fingerprint
		return s.saveDetails(ctx, tx, current.Enrollment, d)
	})
	return result, e
}
func (s *Service) Assignment(ctx context.Context, actor Actor, thumbprint, proxyID string) (map[string]any, error) {
	if e := checkScope(actor, "assignment"); e != nil {
		return nil, e
	}
	if !validThumbprint(thumbprint) {
		return nil, domain.Err(422, "invalid_execution_certificate")
	}
	if domain.ValidateIdentifier(proxyID) != nil {
		return nil, domain.Err(422, "invalid_proxy_id")
	}
	var r *record
	var data map[string]any
	e := s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		var e error
		r, e = s.nodeRecord(ctx, tx, actor, true, true)
		if e != nil {
			return e
		}
		data = clone(mapv(r.Enrollment["details_json"]))
		if thumbprint == r.Node.CertificateThumbprint {
			return domain.Err(403, "execution_certificate_required")
		}
		if s.Issuer != nil && str(data["issued_certificate_thumbprint"]) != thumbprint {
			return domain.Err(403, "approved_execution_certificate_required")
		}
		id := stableKey("external-certificate", thumbprint)[:32]
		existing, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id=?", id)
		if e != nil {
			return e
		}
		if existing != nil {
			if str(existing["job_id"]) != actor.JobID || str(existing["attempt_id"]) != actor.AttemptID || str(existing["component_id"]) != actor.ComponentID {
				return domain.Err(409, "execution_certificate_already_bound")
			}
		} else {
			e = tx.Insert(ctx, "jm_provisioning_resources", map[string]any{"id": id, "job_id": actor.JobID, "attempt_id": actor.AttemptID, "component_id": actor.ComponentID, "kind": "external_execution_certificate", "external_id": thumbprint, "retained": true, "state": "ready", "ownership_json": map[string]any{"job_id": actor.JobID, "attempt_id": actor.AttemptID, "component_id": actor.ComponentID}, "details_json": map[string]any{"certificate_thumbprint": thumbprint}})
			if e != nil {
				return domain.Err(409, "execution_certificate_already_bound")
			}
		}
		if prior := str(data["execution_certificate_thumbprint"]); prior != "" && (prior != thumbprint || str(data["proxy_id"]) != proxyID) {
			return domain.Err(409, "participant_execution_binding_immutable")
		}
		if _, has := data["grant_expires_at"]; !has {
			end := deadline(r.Job, s.now(), r.Spec.MaxDurationSeconds)
			ceiling := s.now().Add(30 * 24 * time.Hour)
			if ceiling.Before(end) {
				end = ceiling
			}
			data["grant_expires_at"] = float64(end.UnixMicro()) / 1e6
		}
		status := "preparing"
		if str(data["status"]) == "assigned" && len(mapv(data["workload_grant"])) > 0 {
			status = "assigned"
		}
		data["execution_certificate_thumbprint"] = thumbprint
		data["proxy_id"] = proxyID
		data["status"] = status
		data["termination_confirmed"] = false
		data["epoch"] = actor.Epoch
		return s.saveDetails(ctx, tx, r.Enrollment, data)
	})
	if e != nil {
		return nil, e
	}
	if s.Hooks.Image == nil || s.Hooks.CreateGrant == nil {
		return nil, domain.Err(503, "participant_assignment_unavailable")
	}
	image, e := s.Hooks.Image(ctx, r.Spec)
	if e != nil {
		return nil, e
	}
	snap, e := s.snapshot(ctx, r.Job, r.Spec)
	if e != nil {
		return nil, e
	}
	space, e := s.spaceID(ctx, actor.JobID)
	if e != nil {
		return nil, e
	}
	if space == "" {
		return nil, domain.Err(409, "participant_assignment_not_ready")
	}
	issuer := s.Hooks.WorkloadIssuer
	if issuer == "" && s.Broker != nil {
		issuer = s.Broker.Issuer()
	}
	principal := stableWorkloadPrincipal(issuer, actor.JobID, actor.ComponentID, r.Participant.ParticipantID)
	body := map[string]any{"subject": workloadSubject(actor.JobID, actor.ComponentID, r.Participant.ParticipantID), "job_id": actor.JobID, "attempt_id": actor.AttemptID, "component_id": actor.ComponentID, "epoch": actor.Epoch, "expires_at": data["grant_expires_at"], "certificate_thumbprint": thumbprint, "roles": []string{"reader", "contributor"}, "bindings": map[string]any{"participant": r.Participant.ParticipantID}}
	key := stableKey("external-grant", actor.JobID, actor.AttemptID, actor.ComponentID, thumbprint)
	desired := clone(body)
	desired["space_id"] = space
	ledger := resources.NewLedger(s.DB)
	grant, e := ledger.Run(ctx, resources.OperationRequest{JobID: actor.JobID, AttemptID: actor.AttemptID, ComponentID: actor.ComponentID, Operation: "external_workload_grant", Key: key, Desired: desired}, func(ctx context.Context) (map[string]any, error) { return s.Hooks.CreateGrant(ctx, space, body, key) })
	if e != nil {
		return nil, e
	}
	if str(grant["principal_id"]) != principal || str(grant["space_id"]) != space {
		return nil, domain.Err(503, "participant_foreign_grant")
	}
	if _, e = ledger.Own(ctx, resources.Ownership{JobID: actor.JobID, AttemptID: actor.AttemptID, ComponentID: actor.ComponentID, Kind: "workload_grant", ExternalID: str(grant["grant_id"]), Details: grant}); e != nil {
		return nil, e
	}
	digest, e := r.Spec.Digest()
	if e != nil {
		return nil, e
	}
	directives := []map[string]any{}
	if s.Hooks.Reconciliation != nil {
		directives, e = s.Hooks.Reconciliation(ctx, actor.JobID, actor.ComponentID, actor.Epoch)
		if e != nil {
			return nil, e
		}
	}
	var end any
	if t, ok := store.Time(r.Job["deadline_at"]); ok {
		end = float64(t.UnixMicro()) / 1e6
	}
	config := map[string]any{"role": "client", "job_id": actor.JobID, "attempt_id": actor.AttemptID, "component_id": actor.ComponentID, "space_id": space, "epoch": actor.Epoch, "spec": r.Spec.Map(), "spec_digest": digest, "participant_id": r.Participant.ParticipantID, "source_manifest": snap.Manifest, "deadline_at": end, "reconciliation": directives, "dataset_bindings": map[string]any{r.Participant.DatasetBinding: r.Node.DatasetBindings[r.Participant.DatasetBinding]}}
	built, e := s.builtArtifacts(ctx, actor, r.Spec)
	if e != nil {
		return nil, e
	}
	if len(built) > 0 {
		config["built_artifacts"] = built
		config["build_dir"] = "/job/build"
	}
	if len(r.Spec.SecretRefs) > 0 {
		if s.Hooks.SecretOptions == nil {
			return nil, domain.Err(503, "participant_secret_approval_unavailable")
		}
		names, e := s.Hooks.SecretOptions(ctx, r.Job, r.Attempt, r.Participant.ParticipantID)
		if e != nil {
			return nil, e
		}
		if len(names) > 0 {
			config["secret_option_names"] = names
			config["secret_options_file"] = "/run/hf2l/secrets.json"
		}
	}
	e = s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		current, e := s.nodeRecord(ctx, tx, actor, true, true)
		if e != nil {
			return e
		}
		d := clone(mapv(current.Enrollment["details_json"]))
		d["status"] = "assigned"
		d["workload_grant"] = grant
		d["last_heartbeat"] = s.now().Format(time.RFC3339Nano)
		if e = s.saveDetails(ctx, tx, current.Enrollment, d); e != nil {
			return e
		}
		return s.emit(ctx, tx, current.Job, "participant.assigned", actor.ID, map[string]any{"participant_id": r.Participant.ParticipantID, "node_id": r.Node.NodeID, "epoch": actor.Epoch})
	})
	if e != nil {
		return nil, e
	}
	credentials, e := s.Credentials(ctx, actor)
	if e != nil {
		return nil, e
	}
	return map[string]any{"identity": identity(r.Job, r.Attempt, actor.ComponentID), "runtime_config": config, "image_digest": image, "resources": r.Node.Resources, "proxy_id": proxyID, "grant": grant, "credentials": credentials}, nil
}
func (s *Service) Credentials(ctx context.Context, actor Actor) (map[string]any, error) {
	if e := checkScope(actor, "assignment"); e != nil {
		return nil, e
	}
	var r *record
	var data, grant map[string]any
	e := s.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		var e error
		r, e = s.nodeRecord(ctx, tx, actor, true, false)
		if e != nil {
			return e
		}
		data = mapv(r.Enrollment["details_json"])
		grant = clone(mapv(data["workload_grant"]))
		if str(data["status"]) != "assigned" || len(grant) == 0 {
			return domain.Err(409, "participant_assignment_not_ready")
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	if s.Hooks.GetGrant == nil {
		return nil, domain.Err(503, "participant_assignment_unavailable")
	}
	current, e := s.Hooks.GetGrant(ctx, str(grant["space_id"]), str(grant["grant_id"]))
	if e != nil {
		return nil, e
	}
	expires := floatNumber(current["expires_at"])
	now := float64(s.now().UnixMicro()) / 1e6
	if !truth(current["enabled"]) || expires <= now {
		return nil, domain.Err(401, "participant_grant_revoked")
	}
	// Bind the current record as well as its expiry. Never mint credentials for
	// another grant returned by a misconfigured trusted transport.
	for _, k := range []string{"space_id", "grant_id"} {
		if value := str(current[k]); value != "" && value != str(grant[k]) {
			return nil, domain.Err(401, "participant_grant_revoked")
		}
	}
	ttl := int64(math.Min(300, expires-now))
	if ttl < 1 {
		return nil, domain.Err(401, "participant_grant_revoked")
	}
	bindings := map[string]any{"job_id": actor.JobID, "attempt_id": actor.AttemptID, "component_id": actor.ComponentID, "space_id": grant["space_id"], "grant_id": grant["grant_id"], "epoch": actor.Epoch, "certificate_thumbprint": data["execution_certificate_thumbprint"], "participant_id": r.Participant.ParticipantID}
	issue := func(audience string) (string, error) {
		if s.Hooks.IssueWorkload != nil {
			return s.Hooks.IssueWorkload(ctx, bindings, audience, ttl)
		}
		if s.Broker == nil {
			return "", domain.Err(503, "participant_grant_unavailable")
		}
		participant := r.Participant.ParticipantID
		return s.Broker.IssueWorkload(exchange.WorkloadRequest{JobID: actor.JobID, AttemptID: actor.AttemptID, ComponentID: actor.ComponentID, SpaceID: str(grant["space_id"]), GrantID: str(grant["grant_id"]), Epoch: actor.Epoch, CertificateThumbprint: str(data["execution_certificate_thumbprint"]), ParticipantID: &participant, Audience: audience, TTLSeconds: ttl})
	}
	exchangeToken, e := issue("exchange")
	if e != nil {
		return nil, e
	}
	gatewayToken, e := issue("gateway")
	if e != nil {
		return nil, e
	}
	return map[string]any{"exchange_token": exchangeToken, "gateway_token": gatewayToken, "expires_at": s.now().Unix() + ttl}, nil
}
func floatNumber(v any) float64 {
	if n, ok := v.(float64); ok {
		return n
	}
	if n, ok := v.(interface{ Float64() (float64, error) }); ok {
		f, _ := n.Float64()
		return f
	}
	return float64(number(v))
}
func (s *Service) OpenSource(ctx context.Context, actor Actor, path string) (*SourceFile, error) {
	if e := checkScope(actor, "assignment"); e != nil {
		return nil, e
	}
	var r *record
	e := s.DB.WithTx(ctx, false, func(tx *store.Tx) error { var e error; r, e = s.nodeRecord(ctx, tx, actor, true, false); return e })
	if e != nil {
		return nil, e
	}
	snap, e := s.snapshot(ctx, r.Job, r.Spec)
	if e != nil {
		return nil, e
	}
	expected, exists := snap.Manifest[path]
	if !exists {
		return nil, domain.Err(404, "participant_source_file_not_found")
	}
	data, e := secureRead(snap.Root, path, 64<<20)
	if e != nil {
		return nil, domain.Err(409, "participant_source_unavailable")
	}
	f := NewSourceFile(data)
	if f.SHA256 != expected {
		return nil, domain.Err(409, "participant_source_mismatch")
	}
	return f, nil
}
func (s *Service) OpenBuildProduct(ctx context.Context, actor Actor, path string) (*SourceFile, error) {
	if !s.BuildAccessValid(ctx, actor) {
		return nil, domain.Err(404, "participant_build_not_found")
	}
	if s.Hooks.OpenBuildProduct == nil {
		return nil, domain.Err(503, "participant_build_unavailable")
	}
	return s.Hooks.OpenBuildProduct(ctx, actor, path)
}
func (s *Service) ReadPublicationState(ctx context.Context, id executor.ExecutionIdentity, path string, maxBytes int64) ([]byte, error) {
	if !publicationPath(path) || maxBytes < 1 || maxBytes > 1<<20 {
		return nil, domain.Err(422, "invalid_publication_state_request")
	}
	var enrollmentID string
	e := s.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		row, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE kind=? AND job_id=? AND attempt_id=? AND component_id=?", "external_enrollment", id.JobID, id.AttemptID, id.ComponentID)
		if e != nil {
			return e
		}
		if row == nil || mapv(row["details_json"])["termination_confirmed"] != true {
			return domain.Err(409, "participant_termination_unconfirmed")
		}
		enrollmentID = str(row["id"])
		return nil
	})
	if e != nil {
		return nil, e
	}
	doc, e := s.BootstrapCredentials(ctx, enrollmentID)
	if e != nil {
		return nil, e
	}
	if s.Broker == nil {
		return nil, domain.Err(503, "external_node_grant_unavailable")
	}
	actor, e := s.Broker.AuthenticateNode(ctx, "Bearer "+str(doc["node_token"]), str(doc["node_certificate_thumbprint"]), func(ctx context.Context, a exchange.NodePrincipal) (bool, error) {
		return s.CheckNodeGrant(ctx, a), nil
	})
	if e != nil {
		return nil, e
	}
	if actor.JobID != id.JobID || actor.AttemptID != id.AttemptID || actor.ComponentID != id.ComponentID || actor.Epoch != id.Epoch {
		return nil, domain.Err(409, "participant_publication_identity_mismatch")
	}
	control, e := s.ControlPlan(ctx, actor)
	if e != nil {
		return nil, e
	}
	if control["termination_confirmed"] != true || control["revocation_confirmed"] != true {
		return nil, domain.Err(409, "participant_publication_fence_unconfirmed")
	}
	if s.Dispatch == nil {
		return nil, domain.Err(503, "external_node_dispatch_unavailable")
	}
	doc["operation"] = "publication-state"
	doc["state_request"] = map[string]any{"path": path, "max_bytes": maxBytes}
	result, e := s.Dispatch(ctx, actor.NodeID, doc)
	if e != nil {
		return nil, e
	}
	a, _ := domain.CanonicalJSON(result["identity"])
	b, _ := domain.CanonicalJSON(control["identity"])
	exists, ok := result["exists"].(bool)
	if !ok || string(a) != string(b) {
		return nil, domain.Err(502, "invalid_publication_state_receipt")
	}
	if !exists {
		return nil, nil
	}
	data, e := base64.StdEncoding.Strict().DecodeString(str(result["content_base64"]))
	if e != nil || int64(len(data)) > maxBytes {
		return nil, domain.Err(502, "invalid_publication_state_receipt")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != str(result["sha256"]) {
		return nil, domain.Err(502, "invalid_publication_state_receipt")
	}
	return data, nil
}
func (s *Service) PurgePlan(ctx context.Context, actor Actor) (map[string]any, error) {
	return NewExternalCleanup(s).PurgePlan(ctx, actor)
}
func (s *Service) ConfirmPurged(ctx context.Context, actor Actor, confirmed bool) (map[string]any, error) {
	return NewExternalCleanup(s).ConfirmPurged(ctx, actor, confirmed)
}
func (s *Service) PurgeJob(ctx context.Context, job map[string]any) (bool, error) {
	return NewExternalCleanup(s).PurgeJob(ctx, str(job["id"]))
}

// Close fences new dispatch and cancels outstanding private node requests.
func (s *Service) Close() {
	s.dispatchMu.Lock()
	s.closing = true
	if s.dispatchCancel != nil {
		s.dispatchCancel()
	}
	s.dispatchMu.Unlock()
	s.dispatchWG.Wait()
}
