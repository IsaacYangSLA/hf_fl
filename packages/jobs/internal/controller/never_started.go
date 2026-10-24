package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func stableKey(parts ...string) string {
	b, e := domain.CanonicalJSON(parts)
	if e != nil {
		return ""
	}
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:])
}
func hasOnly(m map[string]any, allowed ...string) bool {
	a := map[string]bool{}
	for _, v := range allowed {
		a[v] = true
	}
	for key := range m {
		if !a[key] {
			return false
		}
	}
	return true
}
func defaultString(m map[string]any, key, defaultValue string) string {
	if _, exists := m[key]; !exists {
		return defaultValue
	}
	return str(m[key])
}
func defaultNumber(m map[string]any, key string, defaultValue int64) int64 {
	if _, exists := m[key]; !exists {
		return defaultValue
	}
	return num(m[key])
}

// confirmNeverStarted proves absence from a complete locked operation ledger.
// Missing node replies, unacknowledged reservations and expired leases are never
// interpreted as evidence that an execution did not start.
func (c *Controller) confirmNeverStarted(ctx context.Context, claim Claim, jobID, attemptID string) (bool, error) {
	if e := c.requireClaim(ctx, claim); e != nil {
		return false, e
	}
	proved := false
	err := c.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), jobID)
		if e != nil {
			return e
		}
		attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id=?"+tx.ForUpdate(), attemptID)
		if e != nil {
			return e
		}
		if e = c.requireClaimTx(ctx, tx, claim); e != nil {
			return e
		}
		if job == nil || attempt == nil || str(attempt["job_id"]) != jobID || num(attempt["number"]) != num(job["current_attempt"]) || (num(attempt["epoch"]) != num(job["epoch"]) && num(attempt["epoch"]) != num(job["epoch"])+1) {
			return nil
		}
		state, attemptState := str(job["state"]), str(attempt["state"])
		if (state != "CANCELLING" && state != "CANCELLED" && state != "FAILED") || (attemptState != "QUEUED" && attemptState != "CANCELLED" && attemptState != "FAILED") {
			return nil
		}
		if attempt["started_at"] != nil || attempt["heartbeat_at"] != nil || attempt["node_id"] != nil || len(obj(attempt["resources_json"])) > 0 || !((str(attempt["publication_status"]) == "none") || (str(attempt["publication_status"]) == "absent")) {
			return nil
		}
		details := obj(attempt["details_json"])
		if !hasOnly(details, "desired_terminal", "desired_terminal_reason", "automatic_retries", "never_started_cleanup") {
			return nil
		}
		for _, table := range []string{"jm_allocations", "jm_provisioning_operations", "jm_provisioning_resources"} {
			row, e := tx.One(ctx, "SELECT id FROM "+table+" WHERE job_id=? AND attempt_id=? LIMIT 1", jobID, attemptID)
			if e != nil {
				return e
			}
			if row != nil {
				return nil
			}
		}
		previous, e := tx.All(ctx, "SELECT * FROM jm_attempts WHERE job_id=? AND id<>?", jobID, attemptID)
		if e != nil {
			return e
		}
		prior := map[string]map[string]any{}
		priorIDs := []string{}
		for _, row := range previous {
			if !flag(row["revocation_confirmed"]) || !flag(row["termination_confirmed"]) || !publicationKnown(str(row["publication_status"])) {
				return nil
			}
			prior[str(row["id"])] = row
			priorIDs = append(priorIDs, str(row["id"]))
		}
		sort.Strings(priorIDs)
		allocations, e := tx.All(ctx, "SELECT * FROM jm_allocations WHERE job_id=?", jobID)
		if e != nil {
			return e
		}
		for _, row := range allocations {
			if prior[str(row["attempt_id"])] == nil || str(row["state"]) != "RELEASED" || row["released_at"] == nil || !flag(row["termination_confirmed"]) {
				return nil
			}
		}
		operations, e := tx.All(ctx, "SELECT * FROM jm_provisioning_operations WHERE job_id=?", jobID)
		if e != nil {
			return e
		}
		components := map[string]bool{}
		for _, item := range array(obj(job["spec_json"])["components"]) {
			components[str(obj(item)["component_id"])] = true
		}
		for _, row := range operations {
			old := prior[str(row["attempt_id"])]
			componentID := str(row["component_id"])
			if old == nil || !components[componentID] {
				return nil
			}
			epoch := num(old["epoch"])
			operation := str(row["operation"])
			prefix := fmt.Sprintf("%s:%s:%d:%s:", jobID, str(old["id"]), epoch, componentID)
			key := str(row["idempotency_key"])
			desired := obj(row["desired_json"])
			if str(row["state"]) == "ready" && row["last_error"] == nil {
				if (key == stableKey("hf2l", jobID, str(old["id"]), componentID, operation) || key == stableKey("hf2l", jobID, "", componentID, operation)) && defaultNumber(desired, "epoch", epoch) == epoch {
					continue
				}
				return nil
			}
			if str(row["state"]) == "confirmed" && row["last_error"] == nil {
				if key == prefix+operation && num(desired["epoch"]) == epoch {
					continue
				}
				return nil
			}
			if operation != "reserve" || key != prefix+"reserve" || num(desired["epoch"]) != epoch {
				return nil
			}
			if str(row["state"]) == "refused" && safeRefusal(str(row["last_error"])) {
				continue
			}
			if str(row["state"]) != "unknown" {
				return nil
			}
			var allocation map[string]any
			for _, value := range allocations {
				if str(value["attempt_id"]) == str(old["id"]) && str(value["component_id"]) == componentID && num(value["epoch"]) == epoch {
					allocation = value
					break
				}
			}
			if allocation == nil {
				return nil
			}
			closed := map[string]map[string]any{}
			for _, effect := range operations {
				kind := str(effect["operation"])
				if kind != "stop" && kind != "collect" && kind != "release" {
					continue
				}
				if str(effect["attempt_id"]) == str(old["id"]) && str(effect["component_id"]) == componentID && str(effect["idempotency_key"]) == prefix+kind && num(obj(effect["desired_json"])["epoch"]) == epoch && str(effect["state"]) == "confirmed" && effect["last_error"] == nil {
					closed[kind] = effect
				}
			}
			if len(closed) != 3 || !flag(obj(closed["stop"]["observed_json"])["termination_confirmed"]) || !flag(obj(closed["release"]["observed_json"])["confirmed"]) {
				return nil
			}
		}
		resources, e := tx.All(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id=?", jobID)
		if e != nil {
			return e
		}
		dataKinds := map[string]bool{"source": true, "build_products": true, "component_state": true, "execution_state": true, "retained_output": true, "retained_artifact_root": true, "collection_budget": true, "log_budget": true}
		for _, row := range resources {
			old := prior[str(row["attempt_id"])]
			componentID := str(row["component_id"])
			ownership := obj(row["ownership_json"])
			kind := str(row["kind"])
			if old == nil || !components[componentID] || str(ownership["job_id"]) != jobID || str(ownership["component_id"]) != componentID || defaultString(ownership, "attempt_id", str(old["id"])) != str(old["id"]) || defaultNumber(ownership, "epoch", num(old["epoch"])) != num(old["epoch"]) || defaultString(ownership, "kind", kind) != kind {
				return nil
			}
			if row["deleted_at"] != nil || str(row["state"]) == "deleted" {
				continue
			}
			if !flag(row["retained"]) || !dataKinds[kind] {
				return nil
			}
			if str(row["state"]) == "planned" && (kind == "collection_budget" || kind == "log_budget") {
				pointer := "collection_resource_id"
				if kind == "log_budget" {
					pointer = "log_resource_id"
				}
				found := false
				for _, allocation := range allocations {
					if str(allocation["attempt_id"]) == str(old["id"]) && str(allocation["component_id"]) == componentID && num(allocation["epoch"]) == num(old["epoch"]) && str(obj(allocation["details_json"])[pointer]) == str(row["id"]) {
						found = true
						break
					}
				}
				if !found {
					return nil
				}
			} else if str(row["state"]) != "ready" && str(row["state"]) != "retained" {
				return nil
			}
		}
		retries := num(details["automatic_retries"])
		if retries < 0 || retries > 3 {
			return nil
		}
		outstanding, e := tx.One(ctx, "SELECT id FROM jm_outbox WHERE job_id=? AND topic IN ('dispatch','restore_proxies') AND state<>'done' LIMIT 1", jobID)
		if e != nil {
			return e
		}
		if outstanding != nil {
			return nil
		}
		if flag(attempt["revocation_confirmed"]) && flag(attempt["termination_confirmed"]) {
			proved = true
			return nil
		}
		changed := copyMap(details)
		changed["never_started_cleanup"] = map[string]any{"reason": "never_dispatched", "authority": "manager_operation_ledger", "no_current_attempt_effects": true, "fenced_prior_attempts": priorIDs}
		if e = tx.Update(ctx, "jm_attempts", map[string]any{"id": attemptID}, map[string]any{"revocation_confirmed": true, "termination_confirmed": true, "publication_status": "absent", "details_json": changed}); e != nil {
			return e
		}
		if e = tx.Update(ctx, "jm_jobs", map[string]any{"id": jobID}, map[string]any{"version": num(job["version"]) + 1, "updated_at": c.now()}); e != nil {
			return e
		}
		proved = true
		return c.event(ctx, tx, job, "attempt.never_started_cleanup_confirmed", map[string]any{"attempt_id": attemptID, "reason": "never_dispatched"})
	})
	return proved, err
}
