"""Transactional gang scheduling with persistent FIFO backfill protection."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal
from typing import Callable

from sqlalchemy import select, func

from .domain import JobSpec, new_id, utcnow
from .reconciliation import utc

RESOURCE_DIMENSIONS = ("cpu_millicores", "memory_bytes", "disk_bytes", "gpu_count")
LIVE_ALLOCATION_STATES = ("RESERVED", "ACKNOWLEDGED", "STARTING", "RUNNING", "QUARANTINED", "RELEASING")


@dataclass(frozen=True)
class Admission:
    job_id: str
    attempt_id: str
    epoch: int
    allocation_ids: tuple[str, ...]


def requested_by_pool(spec: JobSpec) -> dict[str, dict[str, int]]:
    requests: dict[str, dict[str, int]] = {}
    for component in spec.components:
        request = component.resources
        target = requests.setdefault(request.pool_id, {key: 0 for key in RESOURCE_DIMENSIONS})
        for key in RESOURCE_DIMENSIONS:
            target[key] += getattr(request, key)
    return requests


def _whole_units(value) -> int:
    """PostgreSQL SUM(bigint) uses NUMERIC; keep exact integral budget units."""
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, Decimal) and value.is_finite() and value >= 0 and value == value.to_integral_value():
        return int(value)
    raise ValueError("Resource accounting returned a non-integral quantity")


def pool_capacity(pool) -> dict[str, int]:
    return {key: len(pool.gpu_uuids) if key == "gpu_count" else getattr(pool, key)
            for key in RESOURCE_DIMENSIONS}



def _assign_gpus(requests, pools, occupied):
    """Find an exclusive gang placement even if two pools advertise a UUID."""
    slots = [(pool_id, index) for pool_id, amounts in requests.items()
             for index in range(amounts["gpu_count"])]
    candidates = {slot: sorted(set(pools[slot[0]].gpu_uuids) - set(occupied)) for slot in slots}
    owners = {}
    def place(slot, seen):
        for uuid in candidates[slot]:
            if uuid in seen:
                continue
            seen.add(uuid)
            previous = owners.get(uuid)
            if previous is None or place(previous, seen):
                owners[uuid] = slot
                return True
        return False
    for slot in sorted(slots, key=lambda s: (len(candidates[s]), s)):
        if not place(slot, set()):
            return None
    result = {pool_id: [] for pool_id in requests}
    for uuid, slot in owners.items():
        result[slot[0]].append(uuid)
    return {pool_id: sorted(uuids) for pool_id, uuids in result.items()}

def _quota(project) -> dict[str, int]:
    quota = dict(project.quotas_json or {})
    fields = {"cpu_millicores": "quota_cpu_millicores", "memory_bytes": "quota_memory_bytes",
              "disk_bytes": "quota_disk_bytes", "gpu_count": "quota_gpus", "max_running_jobs": "max_active_jobs"}
    for key, attribute in fields.items():
        value = getattr(project, attribute, None)
        if value is not None:
            quota[key] = min(quota.get(key, value), value)
    return quota


def validate_admission(session, spec: JobSpec) -> None:
    """Reject permanently impossible requests; unhealthy nodes remain queueable."""
    from .domain import Error
    from .models import Pool, Project
    requested = requested_by_pool(spec)
    project = session.get(Project, spec.project_id)
    if project is None:
        raise Error(404, "project_not_found")
    totals = {key: sum(item[key] for item in requested.values()) for key in RESOURCE_DIMENSIONS}
    quota = _quota(project)
    if any(key in quota and totals[key] > quota[key] for key in RESOURCE_DIMENSIONS):
        raise Error(422, "resource_request_exceeds_project_quota")
    for pool_id, amounts in requested.items():
        pool = session.get(Pool, pool_id)
        if pool is None:
            raise Error(422, "resource_pool_not_found")
        capacity = pool_capacity(pool)
        if any(amounts[key] > capacity[key] for key in RESOURCE_DIMENSIONS):
            raise Error(422, "resource_request_exceeds_pool")
    pools = {pool_id: session.get(Pool, pool_id) for pool_id in requested}
    if _assign_gpus(requested, pools, set()) is None:
        raise Error(422, "resource_request_exceeds_pool")
    for component in spec.components:
        pool = session.get(Pool, component.resources.pool_id)
        if component.resources.sandbox_profile not in pool.sandbox_profiles:
            raise Error(422, "sandbox_profile_unavailable")
        if component.resources.gpu_count and component.resources.gpu_profile not in pool.gpu_profiles:
            raise Error(422, "gpu_profile_unavailable")


class Scheduler:
    """All pool locks precede project/job/allocation locks, in stable ID order.

    SQLite uses the database's immediate transaction solely for local tests.
    PostgreSQL row locks are the production admission serialization boundary.
    Quarantined allocations remain charged until authoritative termination.
    """

    def __init__(self, database, *, clock: Callable = utcnow, max_backfills: int = 3, admission_storage=None):
        if max_backfills != 3:
            raise ValueError("The supported queue policy permits exactly three backfills")
        self.database = database
        self.clock = clock
        self.max_backfills = max_backfills
        self.admission_storage = admission_storage

    def schedule(self, *, limit: int = 100) -> list[Admission]:
        from .models import Allocation, Attempt, GpuAllocation, Job, Outbox, Pool, Project, ProvisioningResource
        from .retention import RetentionService
        from .resources import stable_key
        now = utc(self.clock())
        admissions = []
        with self.database.transaction(immediate=True) as session:
            # Lock every affected pool first so two controllers cannot overcommit
            # disjoint components of a gang or deadlock on opposite pool orders.
            pools = {row.id: row for row in session.scalars(
                select(Pool).order_by(Pool.id).with_for_update())}
            projects = {row.id: row for row in session.scalars(
                select(Project).order_by(Project.id).with_for_update())}
            jobs = list(session.scalars(select(Job).where(Job.state == "QUEUED")
                        .order_by(Job.created_at, Job.id).with_for_update()))
            allocations = list(session.scalars(select(Allocation)
                               .where(Allocation.state.in_(LIVE_ALLOCATION_STATES))
                               .order_by(Allocation.pool_id, Allocation.id).with_for_update()))
            active_gpus = list(session.scalars(select(GpuAllocation)
                               .where(GpuAllocation.released_at.is_(None))
                               .order_by(GpuAllocation.pool_id, GpuAllocation.gpu_uuid).with_for_update()))
            used = defaultdict(lambda: {key: 0 for key in RESOURCE_DIMENSIONS})
            project_used = defaultdict(lambda: {key: 0 for key in RESOURCE_DIMENSIONS})
            active_job_ids = set()
            allocation_projects = {row.id: row.project_id for row in session.scalars(
                select(Job).where(Job.id.in_({a.job_id for a in allocations})))}
            for allocation in allocations:
                state_id = (allocation.details_json or {}).get("retained_resource_id")
                prepaid_state = session.get(ProvisioningResource, state_id) if state_id else None
                covered_state = bool(prepaid_state and prepaid_state.job_id == allocation.job_id
                    and prepaid_state.attempt_id == allocation.attempt_id
                    and prepaid_state.component_id == allocation.component_id
                    and prepaid_state.kind == "execution_state"
                    and prepaid_state.size_bytes == allocation.disk_bytes
                    and (prepaid_state.details_json or {}).get("pool_id") == allocation.pool_id
                    and (prepaid_state.details_json or {}).get("covered_by_allocation") is True
                    and (prepaid_state.details_json or {}).get("retention_charged_bytes") == allocation.disk_bytes
                    and not (prepaid_state.details_json or {}).get("retention_charge_released"))
                for key in RESOURCE_DIMENSIONS:
                    amount = getattr(allocation, key)
                    used[allocation.pool_id][key] += amount
                    if key != "disk_bytes" or not covered_state:
                        project_used[allocation_projects[allocation.job_id]][key] += amount
                active_job_ids.add(allocation.job_id)
            gpu_used = {row.gpu_uuid for row in active_gpus}
            for pool_id in pools:
                used[pool_id]["disk_bytes"] = _whole_units(RetentionService.pool_used_bytes(session, pool_id))
            blocked = []
            for job in jobs:
                if len(admissions) >= limit:
                    break
                if job.id in active_job_ids:
                    self._reason(job, "node_quarantine", now)
                    continue
                if job.deadline_at and now >= utc(job.deadline_at):
                    job.state = "CANCELLING"
                    job.phase = "deadline_exceeded"
                    job.updated_at = now
                    job.version += 1
                    self._outbox(session, job, "fence_stop", {"reason": "deadline_exceeded"})
                    continue
                if job.next_attempt_at and now < utc(job.next_attempt_at):
                    self._reason(job, "dependencies", now, available_at=utc(job.next_attempt_at).isoformat())
                    continue
                spec = JobSpec.model_validate(job.spec_json)
                request = requested_by_pool(spec)
                missing = self._eligibility(spec, pools)
                if missing:
                    self._reason(job, missing, now)
                    continue
                storage = []
                resource_links = {}
                covered_existing_bytes = 0
                components = {c.component_id: c for c in spec.components}
                external_components = {"participant-" + stable_key(p.participant_id)[:40]
                    for p in spec.participants if p.mode == "external"}
                if external_components.intersection(components):
                    raise ValueError("External execution identity collides with a declared component")
                storage_unavailable = False
                for planned in (self.admission_storage(job) if self.admission_storage else ()):
                    if (not isinstance(planned, dict) or not isinstance(planned.get("kind"), str)
                            or not 1 <= len(planned["kind"]) <= 64 or not planned["kind"].replace("_", "").isalnum()
                            or planned.get("pool_id") not in pools
                            or (planned.get("component_id") not in components and not (
                                planned.get("kind") == "log_budget"
                                and planned.get("component_id") in external_components
                                and planned.get("max_bytes") == 1024 * 1024))
                            or not isinstance(planned.get("external_id"), str)
                            or type(planned.get("max_bytes")) is not int or planned["max_bytes"] < 0):
                        raise ValueError("Trusted admission storage plan differs from its job")
                    covered = planned.get("covered_by_allocation") is True
                    if planned["kind"] == "execution_state" and not covered:
                        raise ValueError("Execution state must be backed by its immutable allocation")
                    if covered:
                        component = components[planned["component_id"]]
                        if (planned["kind"] != "execution_state"
                                or planned["pool_id"] != component.resources.pool_id
                                or planned["max_bytes"] != component.resources.disk_bytes
                                or planned.get("details", {}).get("covered_by_allocation") is not True):
                            raise ValueError("Covered state budget differs from its immutable allocation")
                    storage_pool = pools[planned["pool_id"]]
                    if not storage_pool.healthy or storage_pool.quarantined:
                        self._reason(job, "node_quarantine", now, pool_id=storage_pool.id)
                        storage_unavailable = True
                        break
                    resource = session.scalar(select(ProvisioningResource).where(
                        ProvisioningResource.kind == planned["kind"],
                        ProvisioningResource.external_id == planned["external_id"]))
                    ownership = {"job_id": job.id, "component_id": planned["component_id"], "kind": planned["kind"]}
                    if resource is not None:
                        if resource.job_id != job.id or resource.ownership_json != ownership:
                            raise ValueError("Storage admission cannot adopt foreign resources")
                        details = resource.details_json or {}
                        if "retention_charged_bytes" in details and not details.get("retention_charge_released"):
                            lifetime_blob = planned["kind"] == "exchange_blob_budget"
                            if lifetime_blob:
                                # One immutable namespace allowance covers every
                                # attempt. Its first pool and full cap stay fixed.
                                from .blob_budget import plan_blob_budget
                                verified = plan_blob_budget(job, planned["pool_id"], (resource,))
                                fields = ("kind", "external_id", "component_id", "pool_id", "max_bytes")
                                if (any(verified[key] != planned[key] for key in fields)
                                        or resource.id != stable_key("resource", job.id, planned["kind"], planned["external_id"])[:32]
                                        or resource.size_bytes != planned["max_bytes"]
                                        or details.get("retention_charged_bytes") != planned["max_bytes"]
                                        or details.get("retention_reservation_bytes") != planned["max_bytes"]):
                                    raise ValueError("Lifetime Exchange allowance changed its immutable binding")
                            if (details.get("pool_id") != planned["pool_id"] or
                                    not lifetime_blob and details.get("attempt_number", job.current_attempt) != job.current_attempt):
                                raise ValueError("Storage admission resource changed its binding")
                            pointer = {"collection_budget": "collection_resource_id", "log_budget": "log_resource_id",
                                       "execution_state": "retained_resource_id"}.get(planned["kind"])
                            if pointer:
                                resource_links.setdefault(planned["component_id"], {})[pointer] = resource.id
                            if covered:
                                covered_existing_bytes += planned["max_bytes"]
                            continue
                    storage.append((planned, resource, ownership))
                    if not covered:
                        request.setdefault(planned["pool_id"], {key: 0 for key in RESOURCE_DIMENSIONS})["disk_bytes"] += planned["max_bytes"]
                if storage_unavailable:
                    continue
                totals = {key: sum(item[key] for item in request.values()) for key in RESOURCE_DIMENSIONS}
                quota = _quota(projects[job.project_id])
                retained_bytes = projects[job.project_id].retained_bytes
                totals["disk_bytes"] += retained_bytes - covered_existing_bytes
                retained_limit = (projects[job.project_id].quotas_json or {}).get("retained_bytes")
                extra_bytes = sum(plan["max_bytes"] for plan, _, _ in storage)
                if retained_limit is not None and retained_bytes + extra_bytes > retained_limit:
                    self._reason(job, "quota", now)
                    continue
                if any(key in quota and project_used[job.project_id][key] + totals[key] > quota[key]
                       for key in RESOURCE_DIMENSIONS):
                    self._reason(job, "quota", now)
                    continue
                if "max_running_jobs" in quota and len({a.job_id for a in allocations
                   if allocation_projects[a.job_id] == job.project_id}) >= quota["max_running_jobs"]:
                    self._reason(job, "quota", now)
                    continue
                shortages = {}
                for pool_id, amounts in request.items():
                    capacity = pool_capacity(pools[pool_id])
                    shortage = {key: amounts[key] - (capacity[key] - used[pool_id][key])
                                for key in RESOURCE_DIMENSIONS
                                if amounts[key] > capacity[key] - used[pool_id][key]}
                    if shortage:
                        shortages[pool_id] = shortage
                gpu_assignment = _assign_gpus(request, pools, gpu_used)
                if gpu_assignment is None:
                    for pool_id, amounts in request.items():
                        if amounts["gpu_count"]:
                            shortages.setdefault(pool_id, {})["gpu_count"] = max(1, amounts["gpu_count"] - len(set(pools[pool_id].gpu_uuids) - gpu_used))
                if shortages:
                    self._reason(job, "capacity", now, shortages=shortages)
                    blocked.append((job, request, shortages))
                    continue
                # A protected request only protects dimensions that are short.
                # Unrelated pools and dimensions can continue making progress.
                protected = [(older, demands, short) for older, demands, short in blocked
                             if older.backfill_count >= self.max_backfills
                             and any(request.get(pid, {}).get(key, 0) > 0
                                     for pid, values in short.items() for key in values)]
                if protected:
                    self._reason(job, "capacity", now, protection="older_request")
                    continue
                attempt = session.scalar(select(Attempt).where(
                    Attempt.job_id == job.id, Attempt.number == job.current_attempt).with_for_update())
                if attempt is None:
                    raise RuntimeError("Queued job is missing its durable attempt")
                job.epoch += 1
                attempt.epoch = job.epoch
                attempt.state = "PROVISIONING"
                attempt.termination_confirmed = False
                job.state = "PROVISIONING"
                job.phase = "reserving"
                job.queue_reason = None
                job.backfill_count = 0
                job.updated_at = now
                job.version += 1
                if job.deadline_at is None:
                    job.deadline_at = now + timedelta(seconds=spec.max_duration_seconds)
                created = []
                for component in spec.components:
                    r = component.resources
                    allocation = Allocation(id=new_id(), job_id=job.id, attempt_id=attempt.id,
                        component_id=component.component_id, pool_id=r.pool_id,
                        cpu_millicores=r.cpu_millicores, memory_bytes=r.memory_bytes,
                        disk_bytes=r.disk_bytes, gpu_count=r.gpu_count, state="RESERVED",
                        epoch=job.epoch, acknowledged=False, termination_confirmed=False, created_at=now,
                        details_json={"node_id": pools[r.pool_id].node_id})
                    session.add(allocation)
                    session.flush()
                    assigned = gpu_assignment[r.pool_id][:r.gpu_count]
                    del gpu_assignment[r.pool_id][:r.gpu_count]
                    for gpu in assigned:
                        session.add(GpuAllocation(id=new_id(), pool_id=r.pool_id, gpu_uuid=gpu,
                            allocation_id=allocation.id))
                        gpu_used.add(gpu)
                    for key in RESOURCE_DIMENSIONS:
                        amount = getattr(r, key)
                        used[r.pool_id][key] += amount
                        project_used[job.project_id][key] += amount
                    created.append(allocation)
                    allocations.append(allocation)
                    allocation_projects[job.id] = job.project_id
                for planned, resource, ownership in storage:
                    if resource is None:
                        resource = ProvisioningResource(
                            id=stable_key("resource", job.id, planned["kind"], planned["external_id"])[:32],
                            job_id=job.id, attempt_id=attempt.id, component_id=planned["component_id"],
                            kind=planned["kind"], external_id=planned["external_id"], ownership_json=ownership,
                            details_json={**planned.get("details", {}), "pool_id": planned["pool_id"],
                                          "component_id": planned["component_id"], "attempt_number": attempt.number,
                                          "reservation_max_bytes": planned["max_bytes"]},
                            state="planned", retained=True, created_at=now, updated_at=now)
                        session.add(resource)
                        session.flush()
                    resource.attempt_id = attempt.id
                    RetentionService.reserve_in_transaction(session, resource, projects[job.project_id],
                        planned["max_bytes"], pools[planned["pool_id"]])
                    if not planned.get("covered_by_allocation"):
                        used[planned["pool_id"]]["disk_bytes"] += planned["max_bytes"]
                    pointer = {"collection_budget": "collection_resource_id", "log_budget": "log_resource_id",
                               "execution_state": "retained_resource_id"}.get(planned["kind"])
                    if pointer:
                        resource_links.setdefault(planned["component_id"], {})[pointer] = resource.id
                # External log budgets have no managed allocation, but their
                # binding is still established before any participant dispatch.
                for links in resource_links.values():
                    for resource_id in links.values():
                        resource = session.get(ProvisioningResource, resource_id)
                        if resource.attempt_id not in {None, attempt.id}:
                            raise ValueError("Prepaid budget belongs to another attempt")
                        resource.attempt_id = attempt.id
                for allocation in created:
                    links = resource_links.get(allocation.component_id, {})
                    allocation.details_json = {**allocation.details_json, **links}
                    if links.get("retained_resource_id"):
                        project_used[job.project_id]["disk_bytes"] -= allocation.disk_bytes
                self._outbox(session, job, "dispatch", {"epoch": job.epoch}, attempt.id)
                self._event(session, job, "admitted", {"epoch": job.epoch, "allocations": len(created)}, now)
                for older, demands, short in blocked:
                    if any(request.get(pid, {}).get(key, 0) > 0 for pid, values in short.items() for key in values):
                        older.backfill_count += 1
                        older.version += 1
                        older.updated_at = now
                admissions.append(Admission(job.id, attempt.id, job.epoch, tuple(a.id for a in created)))
        return admissions

    @staticmethod
    def _eligibility(spec, pools):
        for component in spec.components:
            request = component.resources
            pool = pools.get(request.pool_id)
            if pool is None:
                return "dependencies"
            if pool.quarantined:
                return "node_quarantine"
            if not pool.healthy:
                return "dependencies"
            if request.sandbox_profile not in pool.sandbox_profiles:
                return "unavailable_profile"
            if request.gpu_count and request.gpu_profile not in pool.gpu_profiles:
                return "unavailable_profile"
        return None

    @staticmethod
    def _reason(job, code, now, **details):
        reason = {"code": code, **details}
        if job.queue_reason != reason:
            job.queue_reason = reason
            job.updated_at = now
            job.version += 1

    @staticmethod
    def _outbox(session, job, topic, payload, attempt_id=None):
        from .models import Outbox
        key = f"{topic}:{job.id}:{attempt_id or job.current_attempt}:{job.epoch}:{job.version}"
        session.add(Outbox(id=new_id(), job_id=job.id, attempt_id=attempt_id, attempt_number=job.current_attempt,
                          topic=topic, payload_json=payload, idempotency_key=key,
                          state="pending", attempts=0))

    @staticmethod
    def _event(session, job, kind, payload, now):
        from .models import Event
        sequence = (session.scalar(select(func.max(Event.sequence)).where(Event.job_id == job.id)) or 0) + 1
        session.add(Event(id=new_id(), job_id=job.id, sequence=sequence, kind=kind, data_json=payload,
                          version=job.version, epoch=job.epoch, created_at=now))
        session.flush()

    def queue_reason(self, job_id: str):
        from .models import Job
        with self.database.transaction() as session:
            job = session.get(Job, job_id)
            return dict(job.queue_reason) if job and job.queue_reason else None
