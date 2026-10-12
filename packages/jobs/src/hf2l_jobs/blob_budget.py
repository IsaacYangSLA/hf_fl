"""Prepaid, job-owned Exchange object budgets; no model bytes are read here.

The full bound covers pending upload reservations and committed checkpoints.
It remains charged across attempts and after termination until Exchange proves
that owned blob cleanup has completed. Namespace and revocation history remain.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from sqlalchemy import select

from .domain import JobSpec, utcnow, validate_identifier
from .models import Allocation, Job, Pool, ProvisioningOperation, ProvisioningResource
from .resources import ResourceError, ResourceLedger, stable_key

KIND = "exchange_blob_budget"
MAX_BYTES = (1 << 63) - 1


def _value(item, name, default=None):
    return item.get(name, default) if isinstance(item, Mapping) else getattr(item, name, default)


def _spec(job):
    raw = _value(job, "spec_json", _value(job, "spec"))
    spec = raw if isinstance(raw, JobSpec) else JobSpec.model_validate(raw)
    if _value(job, "spec_hash", spec.digest) != spec.digest:
        raise ResourceError("Exchange budget immutable specification changed")
    return spec


@dataclass(frozen=True)
class BlobBudget:
    quota_bytes: int
    principal_quota_bytes: int
    component_id: str


def checkpoint_budget(spec: JobSpec) -> BlobBudget:
    """Bound one owner checkpoint per absolute round and every participant input.

    Owner scratch is a conservative bound for one checkpoint. Initial global
    state, target_round global publications, and each participant's target_round
    inputs all fit inside this namespace allowance. Retries share the same bound
    rather than obtaining another allowance. Malicious extra uploads fail the
    existing Exchange atomic namespace/principal quota checks.
    """
    owner = next(component for component in spec.components if component.role == "owner")
    quota = owner.resources.disk_bytes * (1 + spec.target_round * (1 + len(spec.participants)))
    principal = owner.resources.disk_bytes * (spec.target_round + 1)
    if not 1 <= principal <= quota <= MAX_BYTES:
        raise ResourceError("Exchange checkpoint budget exceeds the supported byte range")
    return BlobBudget(quota, principal, owner.component_id)


def external_id(job_id: str) -> str:
    return "hf2l-exchange-blobs://" + validate_identifier(job_id)


def _details(job, pool_id):
    spec = _spec(job)
    budget = checkpoint_budget(spec)
    return spec, budget, {"spec_digest": spec.digest, "pool_id": pool_id,
        "quota_bytes": budget.quota_bytes, "principal_quota_bytes": budget.principal_quota_bytes,
        "reservation_max_bytes": budget.quota_bytes, "absolute_target_round": spec.target_round,
        "participant_count": len(spec.participants)}


def _verify_row(job, row):
    spec = _spec(job)
    budget = checkpoint_budget(spec)
    jid = _value(job, "id")
    ownership = _value(row, "ownership", _value(row, "ownership_json", {}))
    details = _value(row, "details", _value(row, "details_json", {})) or {}
    if (_value(row, "kind") != KIND or _value(row, "external_id") != external_id(jid)
            or ownership != {"job_id": jid, "component_id": budget.component_id, "kind": KIND}
            or _value(row, "component_id") != budget.component_id
            or details.get("spec_digest") != spec.digest
            or details.get("quota_bytes") != budget.quota_bytes
            or details.get("principal_quota_bytes") != budget.principal_quota_bytes
            or details.get("reservation_max_bytes") != budget.quota_bytes
            or not isinstance(details.get("pool_id"), str)):
        raise ResourceError("Exchange model budget belongs to another immutable job")
    validate_identifier(details["pool_id"])
    return budget, details


def plan_blob_budget(job, pool_id: str | None, ledger_rows=()) -> dict:
    """Return the scheduler's pure storage plan, retaining its first pool binding."""
    jid = _value(job, "id")
    rows = [row for row in ledger_rows if _value(row, "kind") == KIND]
    if len(rows) > 1:
        raise ResourceError("Job owns multiple unexpected Exchange model budgets")
    if rows:
        budget, details = _verify_row(job, rows[0])
        if _value(rows[0], "state") == "deleted" or details.get("retention_charge_released"):
            raise ResourceError("Deleted Exchange model budget cannot be reused")
        pool_id = details["pool_id"]
    else:
        if pool_id is None:
            raise ResourceError("An approved Exchange object-storage budget pool is required")
        validate_identifier(pool_id)
        _, budget, details = _details(job, pool_id)
    return {"kind": KIND, "external_id": external_id(jid), "component_id": budget.component_id,
        "pool_id": pool_id, "max_bytes": budget.quota_bytes, "details": dict(details)}


def require_blob_budget(database, job, *, for_cleanup=False) -> dict:
    """Verify the complete prepaid allowance before namespace creation or upload."""
    jid = _value(job, "id")
    identity = stable_key("resource", jid, KIND, external_id(jid))[:32]
    with database.transaction(immediate=False) as session:
        owned_job = session.get(Job, jid)
        if owned_job is None or owned_job.spec_hash != _spec(job).digest:
            raise ResourceError("Exchange budget has no durable immutable job")
        terminal = owned_job.state in {"SUCCEEDED", "FAILED", "CANCELLED"}
        active = session.scalar(select(Allocation.id).where(Allocation.job_id == jid,
            Allocation.released_at.is_(None)).limit(1))
        if (not for_cleanup and terminal) or (for_cleanup and (not terminal or active is not None)):
            raise ResourceError("Exchange budget execution or cleanup lifecycle is not authorized")
        row = session.get(ProvisioningResource, identity)
        if row is None:
            raise ResourceError("Exchange model object budget has not been reserved")
        budget, details = _verify_row(job, row)
        pool = session.get(Pool, details["pool_id"])
        if (pool is None or pool.details_json.get("object_store") is not True
                or pool.cpu_millicores or pool.memory_bytes or pool.gpu_uuids
                or pool.id in {component.resources.pool_id for component in _spec(job).components}
                or (not for_cleanup and (not pool.healthy or pool.quarantined))):
            raise ResourceError("Exchange budget requires a distinct approved object-storage pool")
        if (row.job_id != jid or row.state == "deleted" or row.deleted_at is not None
                or not row.retained or row.size_bytes != budget.quota_bytes
                or details.get("retention_charged_bytes") != budget.quota_bytes
                or details.get("retention_charge_released")
                or details.get("retention_reservation_bytes", budget.quota_bytes) != budget.quota_bytes):
            raise ResourceError("Exchange model object budget has not been fully prepaid")
        return {"resource_id": row.id, "quota_bytes": budget.quota_bytes,
            "principal_quota_bytes": budget.principal_quota_bytes, "pool_id": details["pool_id"],
            "space_id": details.get("space_id")}


def bind_blob_space(database, job, space_id: str, *, space_policy=None, for_cleanup=False) -> None:
    """Bind the reservation to the namespace whose ownership was already recorded."""
    validate_identifier(space_id)
    prepaid = require_blob_budget(database, job, for_cleanup=for_cleanup)
    if (_value(space_policy, "id") != space_id
            or _value(space_policy, "quota_bytes") != prepaid["quota_bytes"]
            or _value(space_policy, "principal_quota_bytes") != prepaid["principal_quota_bytes"]):
        raise ResourceError("Exchange namespace quota differs from its prepaid model budget")
    jid = _value(job, "id")
    with database.transaction() as session:
        row = session.scalar(select(ProvisioningResource).where(
            ProvisioningResource.id == prepaid["resource_id"]).with_for_update())
        space = session.scalar(select(ProvisioningResource).where(
            ProvisioningResource.job_id == jid, ProvisioningResource.kind == "exchange_space",
            ProvisioningResource.external_id == space_id))
        budget, details = _verify_row(job, row)
        if (row.state == "deleted" or row.deleted_at is not None or details.get("retention_charge_released")
                or space is None or space.ownership_json.get("job_id") != jid or space.state == "deleted"
                or details.get("space_id") not in (None, space_id)):
            raise ResourceError("Exchange model budget cannot adopt another namespace")
        row.details_json = {**details, "space_id": space_id}
        row.updated_at = utcnow()


def confirm_blob_cleanup(database, job, space_id: str, observation: Mapping) -> bool:
    """Only an authoritative owned retirement read can release the raw-byte cap."""
    jid = _value(job, "id")
    if (observation.get("job_id") != jid or observation.get("space_id") != space_id
            or observation.get("status") != "retired" or observation.get("cleanup_pending") is not False):
        return False
    identity = stable_key("resource", jid, KIND, external_id(jid))[:32]
    with database.transaction() as session:
        row = session.scalar(select(ProvisioningResource).where(
            ProvisioningResource.id == identity).with_for_update())
        owned_job = session.get(Job, jid)
        if (owned_job is None or owned_job.spec_hash != _spec(job).digest
                or owned_job.state not in {"SUCCEEDED", "FAILED", "CANCELLED"}):
            raise ResourceError("Exchange cleanup requires an owned terminal job")
        if session.scalar(select(Allocation.id).where(Allocation.job_id == jid,
                Allocation.released_at.is_(None)).limit(1)) is not None:
            raise ResourceError("Exchange cleanup requires confirmed allocation release")
        if row is None:
            raise ResourceError("Exchange cleanup has no owned object budget")
        _, details = _verify_row(job, row)
        if row.job_id != jid or details.get("space_id") != space_id:
            raise ResourceError("Exchange cleanup belongs to another namespace")
        # A durable receipt allows an interrupted confirmer to resume its exact
        # release. No response from POST's original idempotent receipt suffices.
        row.details_json = {**details, "blob_cleanup_confirmed": True,
                            "blob_cleanup_space_id": space_id}
        row.updated_at = utcnow()
    ledger = ResourceLedger(database)
    ledger.deleted(identity, jid)
    from .retention import RetentionService
    RetentionService(database).confirm_resource_deleted(identity, jid)
    return True


def confirm_unused_blob_budget(database, job) -> bool:
    """Release a terminal allowance only when no namespace request ever existed.

    An operation row in any state defeats absence proof: even a lost create
    acknowledgement may already have made remote objects possible. Its original
    idempotent request must first be adopted and retired through normal cleanup.
    """
    jid = _value(job, "id")
    identity = stable_key("resource", jid, KIND, external_id(jid))[:32]
    with database.transaction() as session:
        owned_job = session.scalar(select(Job).where(Job.id == jid).with_for_update())
        if (owned_job is None or owned_job.spec_hash != _spec(job).digest
                or owned_job.state not in {"SUCCEEDED", "FAILED", "CANCELLED"}):
            return False
        if session.scalar(select(Allocation.id).where(Allocation.job_id == jid,
                Allocation.released_at.is_(None)).limit(1)) is not None:
            return False
        if session.scalar(select(ProvisioningResource.id).where(ProvisioningResource.job_id == jid,
                ProvisioningResource.kind == "exchange_space").limit(1)) is not None:
            return False
        if session.scalar(select(ProvisioningOperation.id).where(ProvisioningOperation.job_id == jid,
                ProvisioningOperation.operation == "exchange_space").limit(1)) is not None:
            return False
        row = session.scalar(select(ProvisioningResource).where(
            ProvisioningResource.id == identity).with_for_update())
        if row is None:
            return True
        _, details = _verify_row(job, row)
        if row.job_id != jid or details.get("space_id") is not None:
            raise ResourceError("Unused Exchange budget has an unexpected namespace binding")
        if row.state == "deleted" and not details.get("blob_unused_confirmed"):
            return False
        row.details_json = {**details, "blob_unused_confirmed": True,
            "blob_unused_proof": "terminal_no_active_allocation_no_namespace_no_create_operation"}
        row.updated_at = utcnow()
    ResourceLedger(database).deleted(identity, jid)
    from .retention import RetentionService
    RetentionService(database).confirm_resource_deleted(identity, jid)
    return True
