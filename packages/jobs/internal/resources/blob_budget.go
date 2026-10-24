package resources

import (
	"context"
	"math"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

const BlobBudgetKind = "exchange_blob_budget"

type BlobBudget struct {
	QuotaBytes, PrincipalQuotaBytes int64
	ComponentID                     string
}

func CheckpointBudget(spec domain.JobSpec) (BlobBudget, error) {
	if spec.Validate() != nil {
		return BlobBudget{}, ErrUnsafe
	}
	var disk int64
	component := ""
	for _, item := range spec.Components {
		if item.Role == "owner" {
			disk = item.Resources.DiskBytes
			component = item.ComponentID
			break
		}
	}
	if disk < 1 || spec.TargetRound < 1 {
		return BlobBudget{}, ErrUnsafe
	}
	count := int64(len(spec.Participants))
	if count > 10000 || spec.TargetRound > 1000000 {
		return BlobBudget{}, ErrUnsafe
	}
	multiplier := 1 + spec.TargetRound*(1+count)
	if disk > math.MaxInt64/multiplier || disk > math.MaxInt64/(spec.TargetRound+1) {
		return BlobBudget{}, ErrUnsafe
	}
	budget := BlobBudget{disk * multiplier, disk * (spec.TargetRound + 1), component}
	if budget.PrincipalQuotaBytes < 1 || budget.PrincipalQuotaBytes > budget.QuotaBytes {
		return BlobBudget{}, ErrUnsafe
	}
	return budget, nil
}
func BlobExternalID(jobID string) (string, error) {
	if identifier(jobID) != nil {
		return "", ErrUnsafe
	}
	return "hf2l-exchange-blobs://" + jobID, nil
}
func immutableSpec(job map[string]any) (domain.JobSpec, error) {
	raw := job["spec_json"]
	if raw == nil {
		raw = job["spec"]
	}
	if spec, ok := raw.(domain.JobSpec); ok {
		if err := spec.Validate(); err != nil {
			return spec, ErrUnsafe
		}
		digest, err := spec.Digest()
		if err != nil {
			return spec, err
		}
		if claimed := job["spec_hash"]; claimed != nil && claimed != digest {
			return spec, ErrUnsafe
		}
		return spec, nil
	}
	encoded, err := domain.CanonicalJSON(raw)
	if err != nil {
		return domain.JobSpec{}, ErrUnsafe
	}
	spec, err := domain.DecodeJobSpec(encoded)
	if err != nil {
		return spec, ErrUnsafe
	}
	digest, err := spec.Digest()
	if err != nil {
		return spec, err
	}
	if claimed := job["spec_hash"]; claimed != nil && claimed != digest {
		return spec, ErrUnsafe
	}
	return spec, nil
}
func budgetDetails(job map[string]any, poolID string) (BlobBudget, map[string]any, error) {
	spec, err := immutableSpec(job)
	if err != nil {
		return BlobBudget{}, nil, err
	}
	budget, err := CheckpointBudget(spec)
	if err != nil {
		return budget, nil, err
	}
	digest, err := spec.Digest()
	if err != nil {
		return budget, nil, err
	}
	return budget, map[string]any{"spec_digest": digest, "pool_id": poolID, "quota_bytes": budget.QuotaBytes, "principal_quota_bytes": budget.PrincipalQuotaBytes, "reservation_max_bytes": budget.QuotaBytes, "absolute_target_round": spec.TargetRound, "participant_count": len(spec.Participants)}, nil
}
func verifyBudget(job, row map[string]any) (BlobBudget, map[string]any, error) {
	spec, err := immutableSpec(job)
	if err != nil {
		return BlobBudget{}, nil, err
	}
	budget, err := CheckpointBudget(spec)
	if err != nil {
		return budget, nil, err
	}
	jid := str(job["id"])
	external, err := BlobExternalID(jid)
	if err != nil {
		return budget, nil, err
	}
	own := row["ownership"]
	if own == nil {
		own = row["ownership_json"]
	}
	details := row["details"]
	if details == nil {
		details = row["details_json"]
	}
	d := object(details)
	quota, ok := integer(d["quota_bytes"])
	principal, ok2 := integer(d["principal_quota_bytes"])
	reserved, ok3 := integer(d["reservation_max_bytes"])
	digest, err := spec.Digest()
	if err != nil {
		return budget, nil, err
	}
	if row["kind"] != BlobBudgetKind || row["external_id"] != external || !equal(own, map[string]any{"job_id": jid, "component_id": budget.ComponentID, "kind": BlobBudgetKind}) || row["component_id"] != budget.ComponentID || d["spec_digest"] != digest || !ok || !ok2 || !ok3 || quota != budget.QuotaBytes || principal != budget.PrincipalQuotaBytes || reserved != budget.QuotaBytes || identifier(str(d["pool_id"])) != nil {
		return budget, nil, ErrUnsafe
	}
	return budget, d, nil
}

// PlanBlobBudget is pure: reservations retain their first approved pool binding
// across retries and cannot be revived after confirmed cleanup.
func PlanBlobBudget(job map[string]any, poolID string, rows []map[string]any) (map[string]any, error) {
	filtered := []map[string]any{}
	for _, row := range rows {
		if row["kind"] == BlobBudgetKind {
			filtered = append(filtered, row)
		}
	}
	if len(filtered) > 1 {
		return nil, ErrUnsafe
	}
	var budget BlobBudget
	var details map[string]any
	var err error
	if len(filtered) > 0 {
		budget, details, err = verifyBudget(job, filtered[0])
		if err != nil {
			return nil, err
		}
		if filtered[0]["state"] == "deleted" || details["retention_charge_released"] == true {
			return nil, ErrUnsafe
		}
		poolID = str(details["pool_id"])
	} else {
		if identifier(poolID) != nil {
			return nil, ErrUnsafe
		}
		budget, details, err = budgetDetails(job, poolID)
		if err != nil {
			return nil, err
		}
	}
	external, err := BlobExternalID(str(job["id"]))
	if err != nil {
		return nil, err
	}
	return map[string]any{"kind": BlobBudgetKind, "external_id": external, "component_id": budget.ComponentID, "pool_id": poolID, "max_bytes": budget.QuotaBytes, "details": details}, nil
}

type BlobBudgetService struct {
	DB             *store.DB
	ConfirmDeleted func(context.Context, string, string) (bool, error)
}

func NewBlobBudgetService(db *store.DB, confirm func(context.Context, string, string) (bool, error)) *BlobBudgetService {
	return &BlobBudgetService{DB: db, ConfirmDeleted: confirm}
}
func (b *BlobBudgetService) Require(ctx context.Context, job map[string]any, forCleanup bool) (map[string]any, error) {
	jid := str(job["id"])
	external, err := BlobExternalID(jid)
	if err != nil {
		return nil, err
	}
	spec, err := immutableSpec(job)
	if err != nil {
		return nil, err
	}
	digest, err := spec.Digest()
	if err != nil {
		return nil, err
	}
	rid := StableKey("resource", jid, BlobBudgetKind, external)[:32]
	var result map[string]any
	err = b.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		durable, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?", jid)
		if e != nil {
			return e
		}
		if durable == nil || durable["spec_hash"] != digest {
			return ErrUnsafe
		}
		terminal := domain.IsTerminal(str(durable["state"]))
		active, e := tx.One(ctx, "SELECT id FROM jm_allocations WHERE job_id=? AND released_at IS NULL LIMIT 1", jid)
		if e != nil {
			return e
		}
		if (!forCleanup && terminal) || (forCleanup && (!terminal || active != nil)) {
			return ErrUnsafe
		}
		row, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id=?", rid)
		if e != nil {
			return e
		}
		if row == nil {
			return ErrUnsafe
		}
		budget, details, e := verifyBudget(job, row)
		if e != nil {
			return e
		}
		pool, e := tx.One(ctx, "SELECT * FROM jm_pools WHERE id=?", details["pool_id"])
		if e != nil {
			return e
		}
		if pool == nil {
			return ErrUnsafe
		}
		cpu, _ := integer(pool["cpu_millicores"])
		memory, _ := integer(pool["memory_bytes"])
		uuids, _ := pool["gpu_uuids"].([]any)
		if object(pool["details_json"])["object_store"] != true || cpu != 0 || memory != 0 || len(uuids) != 0 || (!forCleanup && (pool["healthy"] != true || pool["quarantined"] == true)) {
			return ErrUnsafe
		}
		for _, component := range spec.Components {
			if component.Resources.PoolID == pool["id"] {
				return ErrUnsafe
			}
		}
		size, ok := integer(row["size_bytes"])
		charged, ok2 := integer(details["retention_charged_bytes"])
		reserved, ok3 := integer(details["retention_reservation_bytes"])
		if _, has := details["retention_reservation_bytes"]; !has {
			reserved = budget.QuotaBytes
			ok3 = true
		}
		if row["job_id"] != jid || row["state"] == "deleted" || row["deleted_at"] != nil || row["retained"] != true || !ok || size != budget.QuotaBytes || !ok2 || charged != budget.QuotaBytes || details["retention_charge_released"] == true || !ok3 || reserved != budget.QuotaBytes {
			return ErrUnsafe
		}
		result = map[string]any{"resource_id": row["id"], "quota_bytes": budget.QuotaBytes, "principal_quota_bytes": budget.PrincipalQuotaBytes, "pool_id": details["pool_id"], "space_id": details["space_id"]}
		return nil
	})
	return result, err
}
func (b *BlobBudgetService) BindSpace(ctx context.Context, job map[string]any, spaceID string, policy map[string]any, forCleanup bool) error {
	if identifier(spaceID) != nil {
		return ErrUnsafe
	}
	prepaid, err := b.Require(ctx, job, forCleanup)
	if err != nil {
		return err
	}
	quota, ok := integer(policy["quota_bytes"])
	principal, ok2 := integer(policy["principal_quota_bytes"])
	expected, _ := integer(prepaid["quota_bytes"])
	expectedPrincipal, _ := integer(prepaid["principal_quota_bytes"])
	if policy["id"] != spaceID || !ok || !ok2 || quota != expected || principal != expectedPrincipal {
		return ErrUnsafe
	}
	return b.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		row, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id=?"+tx.ForUpdate(), prepaid["resource_id"])
		if e != nil {
			return e
		}
		if row == nil {
			return ErrUnsafe
		}
		space, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id=? AND kind='exchange_space' AND external_id=?", job["id"], spaceID)
		if e != nil {
			return e
		}
		_, details, e := verifyBudget(job, row)
		if e != nil {
			return e
		}
		if row["state"] == "deleted" || row["deleted_at"] != nil || details["retention_charge_released"] == true || space == nil || object(space["ownership_json"])["job_id"] != job["id"] || space["state"] == "deleted" || (details["space_id"] != nil && details["space_id"] != spaceID) {
			return ErrUnsafe
		}
		details["space_id"] = spaceID
		return tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": row["id"]}, map[string]any{"details_json": details, "updated_at": time.Now().UTC()})
	})
}
func (b *BlobBudgetService) ConfirmCleanup(ctx context.Context, job map[string]any, spaceID string, observation map[string]any) (bool, error) {
	jid := str(job["id"])
	if observation["job_id"] != jid || observation["space_id"] != spaceID || observation["status"] != "retired" || observation["cleanup_pending"] != false {
		return false, nil
	}
	return b.confirm(ctx, job, spaceID, false)
}
func (b *BlobBudgetService) ConfirmUnused(ctx context.Context, job map[string]any) (bool, error) {
	return b.confirm(ctx, job, "", true)
}
func (b *BlobBudgetService) confirm(ctx context.Context, job map[string]any, spaceID string, unused bool) (bool, error) {
	if b.ConfirmDeleted == nil {
		return false, ErrUnsafe
	}
	jid := str(job["id"])
	external, err := BlobExternalID(jid)
	if err != nil {
		return false, err
	}
	rid := StableKey("resource", jid, BlobBudgetKind, external)[:32]
	spec, err := immutableSpec(job)
	if err != nil {
		return false, err
	}
	digest, err := spec.Digest()
	if err != nil {
		return false, err
	}
	release := false
	err = b.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		durable, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?"+tx.ForUpdate(), jid)
		if e != nil {
			return e
		}
		if durable == nil || durable["spec_hash"] != digest || !domain.IsTerminal(str(durable["state"])) {
			if unused {
				return nil
			}
			return ErrUnsafe
		}
		active, e := tx.One(ctx, "SELECT id FROM jm_allocations WHERE job_id=? AND released_at IS NULL LIMIT 1", jid)
		if e != nil {
			return e
		}
		if active != nil {
			if unused {
				return nil
			}
			return ErrUnsafe
		}
		if unused {
			space, e := tx.One(ctx, "SELECT id FROM jm_provisioning_resources WHERE job_id=? AND kind='exchange_space' LIMIT 1", jid)
			if e != nil {
				return e
			}
			operation, e := tx.One(ctx, "SELECT id FROM jm_provisioning_operations WHERE job_id=? AND operation='exchange_space' LIMIT 1", jid)
			if e != nil {
				return e
			}
			if space != nil || operation != nil {
				return nil
			}
		}
		row, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id=?"+tx.ForUpdate(), rid)
		if e != nil {
			return e
		}
		if row == nil {
			if unused {
				release = true
				return nil
			}
			return ErrUnsafe
		}
		_, details, e := verifyBudget(job, row)
		if e != nil {
			return e
		}
		if row["job_id"] != jid {
			return ErrUnsafe
		}
		if unused {
			if details["space_id"] != nil {
				return ErrUnsafe
			}
			if row["state"] == "deleted" && details["blob_unused_confirmed"] != true {
				return nil
			}
			details["blob_unused_confirmed"] = true
			details["blob_unused_proof"] = "terminal_no_active_allocation_no_namespace_no_create_operation"
		} else {
			if details["space_id"] != spaceID {
				return ErrUnsafe
			}
			details["blob_cleanup_confirmed"] = true
			details["blob_cleanup_space_id"] = spaceID
		}
		if e = tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": rid}, map[string]any{"details_json": details, "updated_at": time.Now().UTC()}); e != nil {
			return e
		}
		release = true
		return nil
	})
	if err != nil || !release {
		return false, err
	}
	row, err := b.DB.One(ctx, "SELECT id FROM jm_provisioning_resources WHERE id=?", rid)
	if err != nil {
		return false, err
	}
	if row == nil {
		return true, nil
	}
	if err = NewLedger(b.DB).Deleted(ctx, rid, jid); err != nil {
		return false, err
	}
	_, err = b.ConfirmDeleted(ctx, rid, jid)
	return err == nil, err
}
