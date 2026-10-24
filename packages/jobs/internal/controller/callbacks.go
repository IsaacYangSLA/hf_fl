package controller

import (
	"bytes"
	"context"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

type ProgressReport struct {
	CurrentRound                        *int64
	Phase, PublicationStatus, Readiness string
	Metrics                             map[string]float64
}
type LogAppender interface {
	AppendLogsInTransaction(context.Context, *store.Tx, map[string]any, map[string]any, map[string]any, string) error
}

func (c *Controller) CheckAssignment(ctx context.Context, nodeID, poolID, jobID, attemptID, componentID string, epoch int64) (bool, error) {
	valid := false
	err := c.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?", jobID)
		if e != nil || job == nil {
			return e
		}
		attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id=?", attemptID)
		if e != nil || attempt == nil {
			return e
		}
		pool, e := tx.One(ctx, "SELECT * FROM jm_pools WHERE id=?", poolID)
		if e != nil || pool == nil {
			return e
		}
		if str(attempt["job_id"]) != jobID || num(job["epoch"]) != epoch || num(attempt["epoch"]) != epoch || num(attempt["number"]) != num(job["current_attempt"]) {
			return nil
		}
		allocation, e := tx.One(ctx, "SELECT * FROM jm_allocations WHERE job_id=? AND attempt_id=? AND component_id=? AND pool_id=? AND epoch=? AND state IN "+liveSQL+" LIMIT 1", jobID, attemptID, componentID, poolID, epoch)
		if e != nil || allocation == nil {
			return e
		}
		assigned := str(obj(allocation["details_json"])["node_id"])
		if assigned == "" {
			assigned = str(pool["node_id"])
		}
		valid = assigned == nodeID
		return nil
	})
	return valid, err
}
func (c *Controller) callback(ctx context.Context, jobID, attemptID, componentID string, epoch int64, apply func(*store.Tx, map[string]any, map[string]any, map[string]any) error) (bool, error) {
	accepted := false
	err := c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		hint, e := tx.One(ctx, "SELECT project_id FROM jm_jobs WHERE id=?", jobID)
		if e != nil || hint == nil {
			return e
		}
		if _, e = tx.One(ctx, "SELECT id FROM jm_projects WHERE id=?"+tx.ForUpdate(), hint["project_id"]); e != nil {
			return e
		}
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), jobID)
		if e != nil || job == nil {
			return e
		}
		attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id=?", attemptID)
		if e != nil || attempt == nil {
			return e
		}
		if str(attempt["job_id"]) != jobID || num(job["epoch"]) != epoch || num(attempt["epoch"]) != epoch || num(job["current_attempt"]) != num(attempt["number"]) || terminal(str(job["state"])) {
			return nil
		}
		allocation, e := tx.One(ctx, "SELECT * FROM jm_allocations WHERE job_id=? AND attempt_id=? AND component_id=? AND epoch=? AND state IN "+liveSQL+tx.ForUpdate(), jobID, attemptID, componentID, epoch)
		if e != nil || allocation == nil {
			return e
		}
		if e = apply(tx, job, attempt, allocation); e != nil {
			return e
		}
		accepted = true
		return nil
	})
	return accepted, err
}
func (c *Controller) AckAssignment(ctx context.Context, jobID, attemptID, componentID string, epoch int64) (bool, error) {
	return c.callback(ctx, jobID, attemptID, componentID, epoch, func(tx *store.Tx, job, attempt, allocation map[string]any) error {
		if e := tx.Update(ctx, "jm_allocations", map[string]any{"id": allocation["id"]}, map[string]any{"acknowledged": true, "state": "ACKNOWLEDGED"}); e != nil {
			return e
		}
		return tx.Update(ctx, "jm_attempts", map[string]any{"id": attempt["id"]}, map[string]any{"heartbeat_at": c.now()})
	})
}
func (c *Controller) Heartbeat(ctx context.Context, jobID, attemptID, componentID string, epoch int64) (bool, error) {
	return c.callback(ctx, jobID, attemptID, componentID, epoch, func(tx *store.Tx, job, attempt, allocation map[string]any) error {
		return tx.Update(ctx, "jm_attempts", map[string]any{"id": attempt["id"]}, map[string]any{"heartbeat_at": c.now()})
	})
}
func (c *Controller) StopConfirmation(ctx context.Context, jobID, attemptID, componentID string, epoch int64) (bool, error) {
	return c.callback(ctx, jobID, attemptID, componentID, epoch, func(tx *store.Tx, job, attempt, allocation map[string]any) error {
		return tx.Update(ctx, "jm_allocations", map[string]any{"id": allocation["id"]}, map[string]any{"termination_confirmed": true, "state": "RELEASING"})
	})
}
func (c *Controller) Progress(ctx context.Context, jobID, attemptID, componentID string, epoch int64, report ProgressReport) (bool, error) {
	if report.CurrentRound != nil && *report.CurrentRound < 0 {
		return false, domain.Err(422, "invalid_runtime_progress")
	}
	if report.PublicationStatus != "" && !validPublication(report.PublicationStatus) {
		return false, domain.Err(422, "invalid_runtime_progress")
	}
	phase := report.Phase
	translation := map[string]string{"not_ready": "waiting_participants", "ready": "waiting_participants", "idle": "waiting_participants", "waiting_initialization": "initializing", "initialized": "waiting_participants", "submitted": "waiting_participants", "published": "publishing", "completed": "collecting_results", "skipped": "waiting_participants", "retry": "waiting_participants", "retry_authorized": "initializing", "running": "training", "uncertain": "publishing", "needs_attention": "publishing", "stopped": "collecting_results", "failed": "collecting_results", "duration_exceeded": "collecting_results"}
	if value, ok := translation[phase]; ok {
		phase = value
	}
	allowed := map[string]bool{"fetching": true, "building": true, "initializing": true, "aggregating": true, "waiting_participants": true, "training": true, "publishing": true, "collecting_results": true}
	if phase != "" && !allowed[phase] {
		return false, domain.Err(422, "invalid_runtime_progress")
	}
	if report.Readiness != "" && report.Readiness != "initializing" && report.Readiness != "waiting" && report.Readiness != "ready" && report.Readiness != "training" && report.Readiness != "finished" && report.Readiness != "failed" {
		return false, domain.Err(422, "invalid_runtime_progress")
	}
	if len(report.Metrics) > 32 {
		return false, domain.Err(422, "invalid_runtime_progress")
	}
	for key, value := range report.Metrics {
		if key == "" || utf8.RuneCountInString(key) > 64 || math.IsNaN(value) || math.IsInf(value, 0) {
			return false, domain.Err(422, "invalid_runtime_progress")
		}
	}
	return c.callback(ctx, jobID, attemptID, componentID, epoch, func(tx *store.Tx, job, attempt, allocation map[string]any) error {
		details := copyMap(obj(attempt["details_json"]))
		components := copyMap(obj(details["components"]))
		existing := copyMap(obj(components[componentID]))
		updated := copyMap(existing)
		if report.CurrentRound != nil {
			updated["current_round"] = *report.CurrentRound
		}
		if phase != "" {
			updated["phase"] = phase
		}
		if report.Metrics != nil {
			updated["metrics"] = report.Metrics
		}
		if report.Readiness != "" {
			updated["readiness"] = report.Readiness
		}
		if report.PublicationStatus != "" {
			updated["publication_status"] = report.PublicationStatus
		}
		if report.Phase != "" {
			updated["reported_phase"] = report.Phase
		}
		beforeBytes, be := domain.CanonicalJSON(existing)
		afterBytes, ae := domain.CanonicalJSON(updated)
		if be != nil || ae != nil {
			return domain.Err(422, "invalid_runtime_progress")
		}
		changed := !bytes.Equal(beforeBytes, afterBytes)
		updated["observed_at"] = c.now().Format("2006-01-02T15:04:05.999999999Z07:00")
		components[componentID] = updated
		details["components"] = components
		if e := tx.Update(ctx, "jm_attempts", map[string]any{"id": attemptID}, map[string]any{"details_json": details}); e != nil {
			return e
		}
		if changed {
			role := ""
			for _, item := range array(obj(job["spec_json"])["components"]) {
				component := obj(item)
				if str(component["component_id"]) == componentID {
					role = str(component["role"])
					break
				}
			}
			values := map[string]any{"version": num(job["version"]) + 1, "updated_at": c.now()}
			state := str(job["state"])
			if phase != "" && ((role == "owner" && (state == "RUNNING" || state == "STARTING" || state == "PROVISIONING")) || (role == "build" && state == "PROVISIONING")) {
				values["phase"] = phase
			}
			if e := tx.Update(ctx, "jm_jobs", map[string]any{"id": jobID}, values); e != nil {
				return e
			}
			return c.event(ctx, tx, job, "progress", map[string]any{"component_id": componentID, "current_round": updated["current_round"], "phase": updated["phase"]})
		}
		return nil
	})
}
func (c *Controller) AppendLogs(ctx context.Context, jobID, attemptID, componentID string, epoch int64, data string) (bool, error) {
	if len(data) > 65536 || !utf8.ValidString(data) {
		return false, domain.Err(422, "log_chunk_too_large")
	}
	appender, ok := c.Storage.(LogAppender)
	if !ok {
		return false, domain.Err(503, "storage_unavailable")
	}
	return c.callback(ctx, jobID, attemptID, componentID, epoch, func(tx *store.Tx, job, attempt, allocation map[string]any) error {
		return appender.AppendLogsInTransaction(ctx, tx, job, attempt, allocation, data)
	})
}
func (c *Controller) authoritativeRound(ctx context.Context, jobID string, currentRound int64) error {
	if currentRound < 0 {
		return domain.Err(422, "invalid_runtime_progress")
	}
	return c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), jobID)
		if e != nil || job == nil {
			return e
		}
		if (str(job["state"]) == "RUNNING" || str(job["state"]) == "STARTING") && currentRound > num(job["current_round"]) {
			if e = tx.Update(ctx, "jm_jobs", map[string]any{"id": jobID}, map[string]any{"current_round": currentRound, "version": num(job["version"]) + 1, "updated_at": c.now()}); e != nil {
				return e
			}
			return c.event(ctx, tx, job, "round_confirmed", map[string]any{"current_round": currentRound})
		}
		return nil
	})
}
func (c *Controller) Monitor(ctx context.Context) error {
	rows, e := c.DB.All(ctx, "SELECT id FROM jm_jobs WHERE state IN ('RUNNING','STARTING','PROVISIONING') ORDER BY id")
	if e != nil {
		return e
	}
	for _, row := range rows {
		job, attempt, allocations, e := c.snapshot(ctx, str(row["id"]), "")
		if e != nil {
			return e
		}
		if job == nil || attempt == nil {
			continue
		}
		if deadline, ok := moment(job["deadline_at"]); ok && !c.now().Before(deadline) {
			if e = c.RequestFailure(ctx, str(job["id"]), "deadline_exceeded", false); e != nil {
				return e
			}
			continue
		}
		if str(job["state"]) == "RUNNING" {
			key := fmtRestoreKey(str(job["id"]), num(job["epoch"]))
			pending, e := c.DB.One(ctx, "SELECT id FROM jm_outbox WHERE idempotency_key=? AND state<>'done'", key)
			if e != nil {
				return e
			}
			if pending != nil {
				continue
			}
		}
		if str(job["state"]) == "PROVISIONING" {
			continue
		}
		if heartbeat, ok := moment(attempt["heartbeat_at"]); ok && c.now().Sub(heartbeat) > c.HeartbeatTimeout {
			if e = c.RequestFailure(ctx, str(job["id"]), "heartbeat_expired", true); e != nil {
				return e
			}
			continue
		}
		observe := func() error {
			currentRound, e := c.Provisioner.CurrentRound(ctx, job)
			if e != nil {
				return e
			}
			if e = c.authoritativeRound(ctx, str(job["id"]), currentRound); e != nil {
				return e
			}
			if currentRound >= num(job["target_round"]) {
				return c.RequestCompletion(ctx, str(job["id"]), currentRound)
			}
			for _, allocation := range allocations {
				id := identity(job, attempt, allocation)
				observation, e := c.Executor.Inspect(ctx, id)
				if e != nil {
					return e
				}
				if c.Storage != nil {
					_ = c.Storage.IngestLogs(ctx, allocation, false)
				}
				state := strings.ToUpper(observation.State)
				if observation.ErrorCode != "" || state == "FAILED" || state == "QUARANTINED" || state == "UNKNOWN" {
					failure := observation.ErrorCode
					if failure == "" {
						failure = "execution_unknown"
					}
					return c.RequestFailure(ctx, str(job["id"]), failure, observation.Transient)
				}
				if observation.TerminationConfirmed {
					return c.RequestFailure(ctx, str(job["id"]), "component_stopped_early", observation.Transient)
				}
				if e = c.Executor.Renew(ctx, id); e != nil {
					return e
				}
				if _, e = c.Heartbeat(ctx, id.JobID, id.AttemptID, id.ComponentID, id.Epoch); e != nil {
					return e
				}
				phase := observation.Phase
				if phase == "" {
					phase = str(observation.Details["phase"])
				}
				readiness := observation.Readiness
				if readiness == "" {
					readiness = str(observation.Details["readiness"])
				}
				round := observation.CurrentRound
				if round == nil {
					round = &currentRound
				}
				if _, e = c.Progress(ctx, id.JobID, id.AttemptID, id.ComponentID, id.Epoch, ProgressReport{CurrentRound: round, Phase: phase, PublicationStatus: observation.PublicationStatus, Metrics: observation.Metrics, Readiness: readiness}); e != nil {
					return e
				}
			}
			return nil
		}
		if e = observe(); e != nil {
			failure := "heartbeat_lost"
			transient := true
			if code(e) == "invalid_runtime_progress" {
				failure = "invalid_runtime_progress"
				transient = false
			}
			if e = c.RequestFailure(ctx, str(job["id"]), failure, transient); e != nil {
				return e
			}
		}
	}
	return nil
}
func fmtRestoreKey(jobID string, epoch int64) string {
	return "restore-proxies:" + jobID + ":" + strconv.FormatInt(epoch, 10)
}
