package controller

import (
	"context"
	"sort"
	"strings"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func (c *Controller) dispatch(ctx context.Context, claim Claim) (bool, error) {
	job, attempt, allocations, err := c.snapshot(ctx, claim.JobID, claim.AttemptID)
	if err != nil {
		return false, err
	}
	if job == nil || attempt == nil {
		return true, nil
	}
	if (str(job["state"]) != "PROVISIONING" && str(job["state"]) != "STARTING") || num(job["epoch"]) != num(attempt["epoch"]) {
		return true, nil
	}
	if epoch, ok := claim.Payload["epoch"]; ok && num(epoch) != num(job["epoch"]) {
		return true, nil
	}
	if deadline, ok := moment(job["deadline_at"]); ok && !c.now().Before(deadline) {
		return true, c.RequestFailure(ctx, str(job["id"]), "deadline_exceeded", false)
	}
	currentRound, err := c.Provisioner.CurrentRound(ctx, job)
	if err != nil {
		return false, err
	}
	remaining, err := RemainingRounds(num(job["target_round"]), currentRound)
	if err != nil {
		return false, err
	}
	specs, err := c.Provisioner.Plan(ctx, job, attempt, remaining)
	if err != nil {
		return false, err
	}
	components := map[string]map[string]any{}
	for _, v := range array(obj(job["spec_json"])["components"]) {
		component := obj(v)
		components[str(component["component_id"])] = component
	}
	if len(specs) != len(components) {
		return false, domain.Err(409, "component_plan_mismatch")
	}
	for key := range specs {
		if components[key] == nil {
			return false, domain.Err(409, "component_plan_mismatch")
		}
	}
	if err = c.renewReserved(ctx, claim, job, attempt); err != nil {
		return false, err
	}
	for _, allocation := range allocations {
		cid := str(allocation["component_id"])
		planned, ok := specs[cid]
		if !ok {
			return false, domain.Err(409, "component_plan_mismatch")
		}
		expected := identity(job, attempt, allocation)
		if planned.Identity != expected || planned.PoolID != str(allocation["pool_id"]) {
			return false, domain.Err(409, "execution_binding_mismatch")
		}
		if flag(allocation["acknowledged"]) {
			continue
		}
		observed, err := c.operation(ctx, claim, job, attempt, cid, "reserve", map[string]any{"allocation_id": allocation["id"]}, func() (any, error) { return c.Executor.Reserve(ctx, planned) })
		if err != nil {
			return false, err
		}
		reservation, ok := observed.(executor.Reservation)
		if !ok || !reservation.Acknowledged {
			return false, domain.Err(503, "execution_unknown")
		}
		acknowledged, err := c.AckAssignment(ctx, expected.JobID, expected.AttemptID, expected.ComponentID, expected.Epoch)
		if err != nil {
			return false, err
		}
		if !acknowledged {
			return true, nil
		}
	}
	current, err := c.current(ctx, str(job["id"]), str(attempt["id"]), num(job["epoch"]), "PROVISIONING", "STARTING")
	if err != nil || !current {
		return true, err
	}
	_, err = c.operation(ctx, claim, job, attempt, "owner", "provision", nil, func() (any, error) { e := c.Provisioner.Ensure(ctx, job, attempt, remaining); return e == nil, e })
	if err != nil {
		return false, err
	}
	currentRound, err = c.Provisioner.CurrentRound(ctx, job)
	if err != nil {
		return false, err
	}
	remaining, err = RemainingRounds(num(job["target_round"]), currentRound)
	if err != nil {
		return false, err
	}
	if remaining == 0 {
		return true, c.RequestCompletion(ctx, str(job["id"]), currentRound)
	}
	built, err := c.buildPhase(ctx, claim, job, attempt, specs, components)
	if err != nil || !built {
		return false, err
	}
	_, _, allocations, err = c.snapshot(ctx, str(job["id"]), str(attempt["id"]))
	if err != nil {
		return false, err
	}
	if _, err = c.setPhase(ctx, str(job["id"]), str(attempt["id"]), num(job["epoch"]), "STARTING", "starting"); err != nil {
		return false, err
	}
	sort.Slice(allocations, func(i, j int) bool {
		left, right := str(allocations[i]["component_id"]), str(allocations[j]["component_id"])
		if (str(components[left]["role"]) == "owner") != (str(components[right]["role"]) == "owner") {
			return str(components[left]["role"]) == "owner"
		}
		return left < right
	})
	allRunning := true
	for _, allocation := range allocations {
		cid := str(allocation["component_id"])
		if str(components[cid]["role"]) == "build" {
			continue
		}
		current, err = c.current(ctx, str(job["id"]), str(attempt["id"]), num(job["epoch"]), "STARTING", "PROVISIONING")
		if err != nil || !current {
			return true, err
		}
		id := specs[cid].Identity
		value, err := c.operation(ctx, claim, job, attempt, cid, "start", nil, func() (any, error) { return c.Executor.Start(ctx, id) })
		if err != nil {
			return false, err
		}
		observed, ok := value.(executor.RuntimeObservation)
		if !ok {
			return false, domain.Err(503, "execution_unknown")
		}
		if strings.EqualFold(observed.State, "UNKNOWN") || strings.EqualFold(observed.State, "QUARANTINED") {
			return false, domain.Err(503, "execution_unknown")
		}
		if observed.TerminationConfirmed {
			latest, e := c.Provisioner.CurrentRound(ctx, job)
			if e != nil {
				return false, e
			}
			if latest >= num(job["target_round"]) {
				return true, c.RequestCompletion(ctx, str(job["id"]), latest)
			}
			failure := observed.ErrorCode
			if failure == "" {
				failure = "component_stopped_early"
			}
			return true, c.RequestFailure(ctx, str(job["id"]), failure, observed.Transient)
		}
		allRunning = allRunning && strings.EqualFold(observed.State, "RUNNING")
	}
	phase := "waiting_participants"
	state := "RUNNING"
	if !allRunning {
		state = "STARTING"
		phase = "waiting_components"
	}
	_, err = c.setPhase(ctx, str(job["id"]), str(attempt["id"]), num(job["epoch"]), state, phase)
	return allRunning, err
}
func (c *Controller) renewReserved(ctx context.Context, claim Claim, job, attempt map[string]any) error {
	if err := c.requireClaim(ctx, claim); err != nil {
		return err
	}
	rows, err := c.DB.All(ctx, "SELECT * FROM jm_allocations WHERE attempt_id=? AND acknowledged=? AND termination_confirmed=? AND state IN "+liveSQL, attempt["id"], true, false)
	if err != nil {
		return err
	}
	for _, allocation := range rows {
		if err = c.requireClaim(ctx, claim); err != nil {
			return err
		}
		ok, e := c.current(ctx, str(job["id"]), str(attempt["id"]), num(job["epoch"]), "PROVISIONING", "STARTING")
		if e != nil || !ok {
			return e
		}
		if e = c.Executor.Renew(ctx, identity(job, attempt, allocation)); e != nil {
			return e
		}
	}
	return nil
}
func (c *Controller) buildPhase(ctx context.Context, claim Claim, job, attempt map[string]any, specs map[string]executor.ExecutionSpec, components map[string]map[string]any) (bool, error) {
	buildIDs := []string{}
	for id, component := range components {
		if str(component["role"]) == "build" {
			buildIDs = append(buildIDs, id)
		}
	}
	sort.Strings(buildIDs)
	if len(buildIDs) == 0 {
		return true, nil
	}
	preparer, ok := c.Provisioner.(BuildPreparer)
	if !ok {
		return false, domain.Err(422, "failed_build")
	}
	rows, err := c.DB.All(ctx, "SELECT * FROM jm_allocations WHERE attempt_id=? ORDER BY component_id", attempt["id"])
	if err != nil {
		return false, err
	}
	builds := []map[string]any{}
	for _, row := range rows {
		if str(components[str(row["component_id"])]["role"]) == "build" {
			builds = append(builds, row)
		}
	}
	if len(builds) != len(buildIDs) {
		return false, domain.Err(409, "component_plan_mismatch")
	}
	stored, err := c.DB.One(ctx, "SELECT * FROM jm_attempts WHERE id=?", attempt["id"])
	if err != nil {
		return false, err
	}
	if !flag(obj(stored["details_json"])["build_prepared"]) {
		if _, err = c.setPhase(ctx, str(job["id"]), str(attempt["id"]), num(job["epoch"]), "PROVISIONING", "building"); err != nil {
			return false, err
		}
		outputs := map[string][]executor.CollectedArtifact{}
		allFinished := true
		for _, allocation := range builds {
			cid := str(allocation["component_id"])
			id := specs[cid].Identity
			current, e := c.current(ctx, id.JobID, id.AttemptID, id.Epoch, "PROVISIONING", "STARTING")
			if e != nil || !current {
				return false, e
			}
			value, e := c.operation(ctx, claim, job, attempt, cid, "inspect_build", nil, func() (any, error) { return c.Executor.Inspect(ctx, id) })
			if e != nil {
				return false, e
			}
			observed, ok := value.(executor.RuntimeObservation)
			if !ok {
				return false, domain.Err(503, "execution_unknown")
			}
			if c.Storage != nil {
				_ = c.Storage.IngestLogs(ctx, allocation, false)
			}
			if strings.EqualFold(observed.State, "RESERVED") {
				value, e = c.operation(ctx, claim, job, attempt, cid, "start_build", nil, func() (any, error) { return c.Executor.Start(ctx, id) })
				if e != nil {
					return false, e
				}
				observed, ok = value.(executor.RuntimeObservation)
				if !ok {
					return false, domain.Err(503, "execution_unknown")
				}
			}
			if strings.EqualFold(observed.State, "UNKNOWN") || strings.EqualFold(observed.State, "QUARANTINED") {
				return false, domain.Err(503, "execution_unknown")
			}
			if !observed.TerminationConfirmed {
				allFinished = false
				continue
			}
			if observed.ExitCode == nil {
				return false, domain.Err(503, "execution_unknown")
			}
			if *observed.ExitCode != 0 || observed.ErrorCode != "" {
				return false, domain.Err(422, "failed_build")
			}
			value, e = c.operation(ctx, claim, job, attempt, cid, "stop_build", nil, func() (any, error) { return c.Executor.Stop(ctx, id, 60) })
			if e != nil {
				return false, e
			}
			stopped, ok := value.(executor.RuntimeObservation)
			if !ok || !stopped.TerminationConfirmed {
				return false, domain.Err(503, "execution_unknown")
			}
			if _, e = c.StopConfirmation(ctx, id.JobID, id.AttemptID, id.ComponentID, id.Epoch); e != nil {
				return false, e
			}
			if c.Storage == nil {
				return false, domain.Err(503, "storage_unavailable")
			}
			if e = c.Storage.ReserveCollection(ctx, job, attempt, allocation); e != nil {
				return false, e
			}
			value, e = c.operation(ctx, claim, job, attempt, cid, "collect_build", nil, func() (any, error) { return c.Executor.Collect(ctx, id) })
			if e != nil {
				return false, e
			}
			collected, ok := value.([]executor.CollectedArtifact)
			if !ok {
				return false, domain.Err(422, "unsafe_output")
			}
			if e = c.Storage.StoreCollected(ctx, job, attempt, allocation, collected); e != nil {
				return false, e
			}
			_ = c.Storage.IngestLogs(ctx, allocation, true)
			outputs[cid] = collected
		}
		if !allFinished {
			if e := c.renewReserved(ctx, claim, job, attempt); e != nil {
				return false, e
			}
			return false, nil
		}
		value, e := c.operation(ctx, claim, job, attempt, "owner", "prepare_build_outputs", map[string]any{"build_components": buildIDs}, func() (any, error) { return preparer.PrepareBuildOutputs(ctx, job, attempt, outputs) })
		if e != nil {
			return false, e
		}
		if value != true {
			return false, domain.Err(422, "failed_build")
		}
		if e = c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
			locked, err := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), job["id"])
			if err != nil {
				return err
			}
			if locked == nil || num(locked["epoch"]) != num(attempt["epoch"]) || num(locked["current_attempt"]) != num(attempt["number"]) {
				return domain.Err(409, "stale_epoch")
			}
			row, err := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id=?"+tx.ForUpdate(), attempt["id"])
			if err != nil {
				return err
			}
			if err = c.requireClaimTx(ctx, tx, claim); err != nil {
				return err
			}
			details := copyMap(obj(row["details_json"]))
			details["build_prepared"] = true
			details["build_components"] = buildIDs
			return tx.Update(ctx, "jm_attempts", map[string]any{"id": attempt["id"]}, map[string]any{"details_json": details})
		}); e != nil {
			return false, e
		}
	}
	live := []map[string]any{}
	for _, row := range builds {
		if str(row["state"]) != "RELEASED" {
			live = append(live, row)
		}
	}
	if len(live) > 0 {
		released, e := c.release(ctx, claim, job, attempt, live)
		if e != nil {
			return false, e
		}
		if !released {
			return false, domain.Err(503, "execution_unknown")
		}
	}
	return true, nil
}
