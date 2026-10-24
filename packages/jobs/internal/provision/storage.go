package provision

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/resources"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/secrets"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/source"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func (p *Provisioner) blobService() *resources.BlobBudgetService {
	return resources.NewBlobBudgetService(p.DB, func(ctx context.Context, rid, jid string) (bool, error) {
		return p.Retention.ConfirmResourceDeleted(ctx, rid, jid)
	})
}
func (p *Provisioner) requireBlobBudget(ctx context.Context, job map[string]any, cleanup bool) (map[string]any, error) {
	return p.blobService().Require(ctx, job, cleanup)
}
func (p *Provisioner) bindBlobSpace(ctx context.Context, job map[string]any, space string, policy map[string]any, cleanup bool) error {
	return p.blobService().BindSpace(ctx, job, space, policy, cleanup)
}
func buildStorageCap(spec domain.JobSpec) int64 {
	var disk, count int64
	for _, c := range spec.Components {
		if c.Role == "build" {
			if disk <= 256*1024*1024 {
				disk += c.Resources.DiskBytes
			}
			count++
		}
	}
	if disk > 256*1024*1024 {
		disk = 256 * 1024 * 1024
	}
	return disk + 8192*(count+4)
}
func (p *Provisioner) AdmissionStorageTx(ctx context.Context, tx *store.Tx, job map[string]any) ([]map[string]any, error) {
	spec, e := JobSpec(job)
	if e != nil {
		return nil, e
	}
	jid := idOf(job)
	if e = domain.ValidateIdentifier(jid); e != nil {
		return nil, e
	}
	registry, _, e := p.validateCatalogTx(ctx, tx, spec)
	if e != nil {
		return nil, e
	}
	approval, e := registry.Authorize(spec.ProjectID, spec.SourceID, spec.SourceCommit)
	if e != nil {
		return nil, e
	}
	owner := ownerComponent(spec)
	pool := p.storagePool(spec)
	rows, e := tx.All(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id = ? ORDER BY id", jid)
	if e != nil {
		return nil, e
	}
	existing := map[string]map[string]any{}
	for _, row := range rows {
		if row["state"] != "deleted" {
			existing[str(row["kind"])+"\x00"+str(row["external_id"])] = row
		}
	}
	result := []map[string]any{}
	add := func(kind, external, cid, poolID string, maximum int64, covered bool, extra map[string]any) error {
		if maximum < 0 {
			return refused("invalid_storage_budget")
		}
		if row := existing[kind+"\x00"+external]; row != nil {
			if !same(ownership(row), map[string]any{"job_id": jid, "component_id": cid, "kind": kind}) {
				return refused("foreign_storage_resource")
			}
			d := details(row)
			if _, charged := d["retention_charged_bytes"]; charged && !truth(d["retention_charge_released"]) {
				return nil
			}
		}
		d := map[string]any{"spec_digest": mustDigest(spec), "pool_id": poolID, "reservation_max_bytes": maximum}
		for k, v := range extra {
			d[k] = v
		}
		plan := map[string]any{"kind": kind, "external_id": external, "component_id": cid, "pool_id": poolID, "max_bytes": maximum, "details": d}
		if covered {
			plan["covered_by_allocation"] = true
			d["covered_by_allocation"] = true
		}
		result = append(result, plan)
		return nil
	}
	sourcePath := filepath.Join(p.Root, jid, "source")
	if e = add("source", sourcePath, owner.ComponentID, pool, approval.MaxBytes+source.MetadataPeakBytes(approval), false, map[string]any{"source_id": spec.SourceID, "commit": spec.SourceCommit}); e != nil {
		return nil, e
	}
	complete := false
	if row := existing["source\x00"+sourcePath]; row != nil {
		complete = truth(details(row)["retention_charge_settled"])
	}
	attempt := num(job["current_attempt"])
	if attempt < 1 {
		attempt = 1
	}
	if !complete {
		if e = add("source_fetch_workspace", filepath.Join(p.Root, jid, "source-fetch", fmt.Sprint(attempt)), owner.ComponentID, pool, source.GitPeakBytes(approval), false, map[string]any{"source_id": spec.SourceID, "commit": spec.SourceCommit}); e != nil {
			return nil, e
		}
	}
	hasBuild := false
	for _, c := range spec.Components {
		if c.Role == "build" {
			hasBuild = true
		}
	}
	if hasBuild {
		if e = add("build_products", filepath.Join(p.Root, jid, "build-products"), owner.ComponentID, pool, buildStorageCap(spec), false, nil); e != nil {
			return nil, e
		}
	}
	for _, c := range spec.Components {
		suffix := jid + "/" + fmt.Sprint(attempt) + "/" + c.ComponentID
		extra := map[string]any{"component_id": c.ComponentID, "attempt_number": attempt}
		if e = add("collection_budget", "hf2l-collection://"+suffix, c.ComponentID, c.Resources.PoolID, c.Resources.DiskBytes+4*1024*1024, false, extra); e != nil {
			return nil, e
		}
		if e = add("log_budget", "hf2l-log://"+suffix, c.ComponentID, pool, 1024*1024, false, extra); e != nil {
			return nil, e
		}
		if e = add("execution_state", "hf2l-state://"+suffix, c.ComponentID, c.Resources.PoolID, c.Resources.DiskBytes, true, extra); e != nil {
			return nil, e
		}
	}
	for _, participant := range spec.Participants {
		if participant.Mode == "external" {
			cid := ExternalComponent(participant.ParticipantID)
			suffix := jid + "/" + fmt.Sprint(attempt) + "/" + cid
			if e = add("log_budget", "hf2l-log://"+suffix, cid, pool, 1024*1024, false, map[string]any{"component_id": cid, "attempt_number": attempt}); e != nil {
				return nil, e
			}
		}
	}
	blobRows := []map[string]any{}
	for _, row := range rows {
		if row["kind"] == "exchange_blob_budget" {
			blobRows = append(blobRows, row)
		}
	}
	plan, e := resources.PlanBlobBudget(job, p.ExchangeStoragePoolID, blobRows)
	if e != nil {
		return nil, e
	}
	if plan["pool_id"] == pool {
		return nil, refused("object_storage_pool_not_distinct")
	}
	for _, c := range spec.Components {
		if plan["pool_id"] == c.Resources.PoolID {
			return nil, refused("object_storage_pool_not_distinct")
		}
	}
	result = append(result, plan)
	if p.AuxiliaryStorageTx != nil {
		additional, e := p.AuxiliaryStorageTx(ctx, tx, job)
		if e != nil {
			return nil, e
		}
		result = append(result, additional...)
	} else if p.AuxiliaryStorage != nil {
		return nil, refused("transactional_auxiliary_storage_unconfigured")
	}
	return result, nil
}
func (p *Provisioner) Cleanup(ctx context.Context, job, attempt map[string]any) (bool, error) {
	jid, aid, spec, e := identity(job, attempt)
	if e != nil {
		return false, e
	}
	if !truth(attempt["termination_confirmed"]) {
		return false, nil
	}
	confirmed, e := p.Revoke(ctx, job, attempt)
	if e != nil || !confirmed {
		return false, e
	}
	rows, e := p.Ledger.Resources(ctx, jid, resources.ResourceFilter{AttemptID: aid})
	if e != nil {
		return false, e
	}
	for _, row := range rows {
		if row["state"] == "deleted" || truth(row["retained"]) {
			continue
		}
		if ownership(row)["job_id"] != jid {
			return false, refused("foreign_cleanup_resource")
		}
		cid := str(row["component_id"])
		binding := secrets.Binding{JobID: jid, AttemptID: aid, ComponentID: cid, Epoch: num(attempt["epoch"])}
		switch row["kind"] {
		case "workload_grant":
		case "runtime_secret":
			if p.SecretResolver == nil {
				return false, nil
			}
			ok, e := p.SecretResolver.Cleanup(ctx, binding, true)
			if e != nil || !ok {
				return false, e
			}
		case "runtime_config":
			expected := filepath.Join(p.Root, jid, "attempts", aid, cid, "runtime.json")
			if row["external_id"] != expected {
				return false, refused("foreign_runtime_configuration")
			}
			parent := filepath.Dir(expected)
			if info, e := os.Lstat(parent); e != nil {
				if !os.IsNotExist(e) {
					return false, e
				}
			} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return false, refused("unsafe_runtime_configuration")
			}
			root, e := os.OpenRoot(filepath.Join(p.Root, jid))
			if e != nil {
				if !os.IsNotExist(e) {
					return false, e
				}
			} else {
				rel := filepath.Join("attempts", aid, cid, "runtime.json")
				info, e := root.Lstat(rel)
				if e == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
					root.Close()
					return false, refused("unsafe_runtime_configuration")
				}
				if e == nil {
					e = root.Remove(rel)
				}
				root.Close()
				if e != nil && !os.IsNotExist(e) {
					return false, e
				}
			}
		default:
			return false, nil
		}
		if e = p.Ledger.Deleted(ctx, idOf(row), jid); e != nil {
			return false, e
		}
	}
	for _, c := range spec.Components {
		if c.Role != "build" {
			if p.ProxyStopper == nil {
				return false, refused("proxy_cleanup_unconfigured")
			}
			ok, e := p.ProxyStopper(ctx, executor.ExecutionIdentity{JobID: jid, AttemptID: aid, ComponentID: c.ComponentID, Epoch: num(attempt["epoch"])}, true)
			if e != nil || !ok {
				return false, e
			}
		}
	}
	return true, nil
}
func (p *Provisioner) confirmRemoteAuxiliary(ctx context.Context, job map[string]any) (bool, error) {
	jid := idOf(job)
	spec, e := JobSpec(job)
	if e != nil {
		return false, e
	}
	rows, e := p.Ledger.Resources(ctx, jid, resources.ResourceFilter{Kind: "remote_auxiliary"})
	if e != nil {
		return false, e
	}
	live := []map[string]any{}
	for _, row := range rows {
		if row["state"] != "deleted" {
			live = append(live, row)
		}
	}
	if len(live) == 0 {
		return true, nil
	}
	if p.RemoteAuxiliaryCleanup == nil {
		return false, nil
	}
	proofs, e := p.RemoteAuxiliaryCleanup(ctx, job, live)
	if e != nil {
		return false, e
	}
	if len(proofs) != len(live) {
		return false, nil
	}
	required := []string{"confirmed", "termination_confirmed", "source_deleted", "config_deleted", "build_deleted", "private_credentials_deleted", "private_secrets_deleted", "retained_deleted", "auxiliary_deleted"}
	for _, row := range live {
		d := details(row)
		cid := str(row["component_id"])
		if !same(ownership(row), map[string]any{"job_id": jid, "component_id": cid, "kind": "remote_auxiliary"}) || d["spec_digest"] != mustDigest(spec) || str(d["node_id"]) == "" || str(d["pool_id"]) == "" {
			return false, refused("foreign_remote_auxiliary")
		}
		allocations, e := p.DB.All(ctx, "SELECT * FROM jm_allocations WHERE job_id = ? AND component_id = ? AND pool_id = ?", jid, cid, d["pool_id"])
		if e != nil {
			return false, e
		}
		expected := map[string]bool{}
		for _, a := range allocations {
			node := obj(a["details_json"])["node_id"]
			if node == nil || node == "" {
				return false, nil
			}
			if node != d["node_id"] {
				continue
			}
			if a["released_at"] == nil || !truth(a["termination_confirmed"]) {
				return false, nil
			}
			expected[str(a["attempt_id"])+":"+fmt.Sprint(num(a["epoch"]))] = true
		}
		if len(expected) == 0 {
			return false, nil
		}
		receipts, ok := proofs[idOf(row)]
		if !ok {
			return false, nil
		}
		seen := map[string]bool{}
		for _, receipt := range receipts {
			epoch, e := strictInteger(receipt["epoch"])
			if e != nil {
				return false, nil
			}
			aid := str(receipt["attempt_id"])
			key := aid + ":" + fmt.Sprint(epoch)
			if seen[key] || !expected[key] {
				return false, nil
			}
			identity := executor.ExecutionIdentity{JobID: jid, AttemptID: aid, ComponentID: cid, Epoch: epoch}
			binding := map[string]any{"job_id": jid, "component_id": cid, "node_id": d["node_id"], "pool_id": d["pool_id"], "spec_digest": mustDigest(spec), "purpose": "managed_node_purge", "operation_id": "purge-" + identity.Key()}
			for k, v := range binding {
				if receipt[k] != v {
					return false, nil
				}
			}
			for _, k := range required {
				if !truth(receipt[k]) {
					return false, nil
				}
			}
			seen[key] = true
		}
		if len(seen) != len(expected) {
			return false, nil
		}
	}
	// Validate the entire receipt set before releasing any independently paid row.
	for _, row := range live {
		e = p.DB.WithTx(ctx, true, func(tx *store.Tx) error {
			current, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?"+tx.ForUpdate(), idOf(row))
			if e != nil {
				return e
			}
			if current == nil || current["job_id"] != jid || !same(ownership(current), ownership(row)) {
				return refused("remote_auxiliary_ownership_changed")
			}
			d := details(current)
			d["purge_receipts"] = proofs[idOf(row)]
			return tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": idOf(row)}, map[string]any{"details_json": d})
		})
		if e != nil {
			return false, e
		}
		if e = p.Ledger.Deleted(ctx, idOf(row), jid); e != nil {
			return false, e
		}
		if _, e = p.Retention.ConfirmResourceDeleted(ctx, idOf(row), jid); e != nil {
			return false, e
		}
	}
	return true, nil
}
func (p *Provisioner) purgeNeverStarted(ctx context.Context, job map[string]any) (bool, error) {
	jid := idOf(job)
	spec, e := JobSpec(job)
	if e != nil {
		return false, e
	}
	result := false
	e = p.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		stored, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?"+tx.ForUpdate(), jid)
		if e != nil {
			return e
		}
		attempts, e := tx.All(ctx, "SELECT * FROM jm_attempts WHERE job_id = ?"+tx.ForUpdate(), jid)
		if e != nil {
			return e
		}
		if stored == nil {
			return refused("job_missing")
		}
		native := []map[string]any{}
		for _, a := range attempts {
			if len(obj(obj(a["details_json"])["never_started_cleanup"])) > 0 {
				native = append(native, a)
			}
		}
		if len(native) == 0 || num(stored["current_attempt"]) != 1 || len(attempts) != 1 {
			return nil
		}
		if len(native) != 1 || num(native[0]["number"]) != 1 {
			return refused("invalid_never_started_proof")
		}
		a := native[0]
		d := obj(a["details_json"])
		proof := obj(d["never_started_cleanup"])
		if stored["spec_hash"] != mustDigest(spec) || !domain.IsTerminal(str(stored["state"])) || num(stored["epoch"]) > 1 || num(a["epoch"]) != 1 || a["started_at"] != nil || a["heartbeat_at"] != nil || a["node_id"] != nil || len(obj(a["resources_json"])) > 0 || !truth(a["revocation_confirmed"]) || !truth(a["termination_confirmed"]) || a["publication_status"] != "absent" || proof["reason"] != "never_dispatched" || proof["authority"] != "manager_operation_ledger" || !truth(proof["no_current_attempt_effects"]) {
			return refused("incomplete_never_started_proof")
		}
		fenced, ok := array(proof["fenced_prior_attempts"])
		if !ok || len(fenced) != 0 {
			return refused("incomplete_never_started_proof")
		}
		for k := range d {
			if k != "desired_terminal" && k != "desired_terminal_reason" && k != "automatic_retries" && k != "never_started_cleanup" {
				return refused("incomplete_never_started_proof")
			}
		}
		for _, table := range []string{"jm_allocations", "jm_provisioning_operations", "jm_provisioning_resources"} {
			row, e := tx.One(ctx, "SELECT id FROM "+table+" WHERE job_id = ? LIMIT 1", jid)
			if e != nil {
				return e
			}
			if row != nil {
				return refused("never_started_resource_uncertain")
			}
		}
		row, e := tx.One(ctx, "SELECT id FROM jm_outbox WHERE job_id = ? AND topic IN (?,?) AND state != ? LIMIT 1", jid, "dispatch", "restore_proxies", "done")
		if e != nil {
			return e
		}
		if row != nil {
			return refused("never_started_dispatch_uncertain")
		}
		dirs, e := resources.NewOwnedDirectories(p.Root)
		if e != nil {
			return e
		}
		defer dirs.Close()
		removed, e := dirs.PurgeEmptyNeverStarted(jid, idOf(a), componentIDs(spec))
		if e != nil {
			return e
		}
		if removed {
			sequence := int64(0)
			rows, e := tx.One(ctx, "SELECT MAX(sequence) AS n FROM jm_events WHERE job_id = ?", jid)
			if e != nil {
				return e
			}
			if rows != nil {
				sequence = num(rows["n"])
			}
			if e = tx.Insert(ctx, "jm_events", map[string]any{"id": domain.NewID(), "job_id": jid, "sequence": sequence + 1, "kind": "cleanup.never_started_empty_skeleton_pruned", "data_json": map[string]any{"attempt_id": idOf(a), "reason": "never_dispatched"}}); e != nil {
				return e
			}
		}
		result = true
		return nil
	})
	return result, e
}
func (p *Provisioner) PurgeJob(ctx context.Context, job map[string]any) (bool, error) {
	jid := idOf(job)
	spec, e := JobSpec(job)
	if e != nil {
		return false, e
	}
	if !domain.IsTerminal(str(job["state"])) {
		return false, refused("purge_requires_terminal_job")
	}
	if p.ArtifactFenceRevoker != nil {
		ok, e := p.ArtifactFenceRevoker(ctx, jid)
		if e != nil || !ok {
			return false, e
		}
	} else {
		// A lost download-grant acknowledgement can leave a live capability
		// before its resource row is recorded. Any known or uncertain namespace
		// therefore requires permanent broker fencing, even without grant rows.
		namespace, e := p.DB.One(ctx, "SELECT id FROM jm_provisioning_resources WHERE job_id = ? AND kind IN (?,?) LIMIT 1", jid, "exchange_space", "workload_grant")
		if e != nil {
			return false, e
		}
		operation, e := p.DB.One(ctx, "SELECT id FROM jm_provisioning_operations WHERE job_id = ? AND operation = ? LIMIT 1", jid, "exchange_space")
		if e != nil {
			return false, e
		}
		if namespace != nil || operation != nil {
			return false, refused("artifact_fencing_unconfigured")
		}
	}
	if ok, e := p.purgeNeverStarted(ctx, job); e != nil || ok {
		return ok, e
	}
	active, e := p.DB.One(ctx, "SELECT id FROM jm_allocations WHERE job_id = ? AND released_at IS NULL LIMIT 1", jid)
	if e != nil {
		return false, e
	}
	if active != nil {
		return false, refused("active_allocation")
	}
	if ok, e := p.confirmRemoteAuxiliary(ctx, job); e != nil || !ok {
		return false, e
	}
	space, e := p.OwnedSpace(ctx, jid)
	if e != nil {
		return false, e
	}
	if space == "" {
		creations, e := p.DB.All(ctx, "SELECT * FROM jm_provisioning_operations WHERE job_id = ? AND operation = ?", jid, "exchange_space")
		if e != nil {
			return false, e
		}
		if len(creations) > 0 {
			if len(creations) != 1 || creations[0]["component_id"] != "owner" {
				return false, refused("foreign_namespace_creation")
			}
			space, e = p.provisionSpace(ctx, job, str(creations[0]["attempt_id"]), true)
			if e != nil {
				return false, e
			}
		} else {
			ok, e := p.blobService().ConfirmUnused(ctx, job)
			if e != nil || !ok {
				return false, e
			}
		}
	}
	rows, e := p.Ledger.Resources(ctx, jid, resources.ResourceFilter{})
	if e != nil {
		return false, e
	}
	if space != "" {
		grantAttempts := map[string]bool{}
		for _, row := range rows {
			if row["kind"] == "workload_grant" {
				if aid := str(details(row)["attempt_id"]); aid != "" {
					grantAttempts[aid] = true
				}
			}
		}
		attempts := make([]string, 0, len(grantAttempts))
		for aid := range grantAttempts {
			attempts = append(attempts, aid)
		}
		sort.Strings(attempts)
		for _, aid := range attempts {
			receipt, e := p.request(ctx, "POST", spacePath(space, "/workload-grants/revoke"), map[string]any{"attempt_id": aid}, resources.StableKey("retention-revoke", jid, aid))
			if e != nil {
				return false, e
			}
			if receipt["attempt_id"] != aid || receipt["revoked_at"] == nil || receipt["revoked_at"] == "" {
				return false, nil
			}
		}
	}
	external := false
	for _, row := range rows {
		if row["state"] != "deleted" {
			switch row["kind"] {
			case "external_enrollment", "external_execution_certificate", "external_execution":
				external = true
			}
		}
	}
	if external {
		if p.ExternalCleanup == nil {
			return false, nil
		}
		ok, e := p.ExternalCleanup(ctx, job)
		if e != nil || !ok {
			return false, e
		}
	}
	if space != "" {
		if _, e = p.request(ctx, "POST", spacePath(space, "/managed/retire"), map[string]any{"job_id": jid}, resources.StableKey("retire-space", jid)); e != nil {
			return false, e
		}
		observed, e := p.request(ctx, "GET", spacePath(space, "/managed"), nil, "")
		if e != nil {
			return false, e
		}
		ok, e := p.blobService().ConfirmCleanup(ctx, job, space, observed)
		if e != nil || !ok {
			return false, e
		}
	}
	dirs, e := resources.NewOwnedDirectories(p.Root)
	if e != nil {
		return false, e
	}
	defer dirs.Close()
	if e = dirs.Purge(jid, mustDigest(spec)); e != nil {
		return false, e
	}
	for _, row := range rows {
		switch row["kind"] {
		case "collection_budget", "log_budget", "execution_state", "exchange_blob_budget":
			continue
		case "exchange_space", "exchange_member":
			e = p.DB.WithTx(ctx, true, func(tx *store.Tx) error {
				current, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?"+tx.ForUpdate(), idOf(row))
				if e != nil {
					return e
				}
				if current == nil || current["job_id"] != jid || ownership(current)["job_id"] != jid {
					return refused("foreign_provenance")
				}
				return tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": idOf(row)}, map[string]any{"state": "retired", "retained": false, "size_bytes": int64(0), "updated_at": p.Clock()})
			})
		default:
			e = p.Ledger.Deleted(ctx, idOf(row), jid)
		}
		if e != nil {
			return false, e
		}
	}
	return true, nil
}
func (p *Provisioner) ExpireArtifacts(ctx context.Context, job map[string]any) (bool, error) {
	return p.PurgeJob(ctx, job)
}

// AdmissionStorage is the out-of-transaction planning convenience. Manager and
// scheduler mutations use AdmissionStorageTx to share their current SQL locks.
func (p *Provisioner) AdmissionStorage(ctx context.Context, job map[string]any) ([]map[string]any, error) {
	var plans []map[string]any
	clone := *p
	clone.AuxiliaryStorage = nil
	err := p.DB.WithTx(ctx, false, func(tx *store.Tx) error { var e error; plans, e = clone.AdmissionStorageTx(ctx, tx, job); return e })
	if err != nil {
		return nil, err
	}
	if p.AuxiliaryStorageTx == nil && p.AuxiliaryStorage != nil {
		extra, e := p.AuxiliaryStorage(ctx, job)
		if e != nil {
			return nil, e
		}
		plans = append(plans, extra...)
	}
	return plans, nil
}
