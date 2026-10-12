"""Retention calculations never free storage until deletion is confirmed."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

TERMINAL_STATES = frozenset({"SUCCEEDED", "FAILED", "CANCELLED"})


def utc(value):
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def iso(value):
    value = utc(value)
    return value.isoformat().replace("+00:00", "Z") if value else None


def retention_expiry(job, project):
    if job.terminated_at is None:
        return None
    return utc(job.terminated_at) + timedelta(days=project.retention_days)


def retention_summary(job, now):
    expires_at = utc(job.artifacts_expire_at)
    return {"expires_at": iso(expires_at), "expired": bool(expires_at and expires_at <= utc(now)),
            "cleanup_status": job.cleanup_status, "purged_at": iso(getattr(job, "purged_at", None))}


def artifact_view(artifact, now):
    expires = utc(artifact.expires_at)
    expired = bool(expires and expires <= utc(now)) or artifact.state in {"expired", "deleting", "deleted"}
    return {"id": artifact.id, "attempt_number": artifact.attempt_number, "kind": artifact.kind,
            "name": artifact.name, "size_bytes": artifact.size_bytes, "sha256": artifact.sha256,
            "state": "expired" if expired and artifact.state != "deleted" else artifact.state,
            "created_at": iso(artifact.created_at), "expires_at": iso(expires),
            "deleted_at": iso(artifact.deleted_at), "download_available": not expired and artifact.state in {"available", "retained"}}


class RetentionService:
    """Persist deletion intent for terminal owned data; external cleanup confirms it."""
    def __init__(self, database, clock=None):
        from .domain import utcnow
        self.database = database
        self.clock = clock or utcnow

    def request_expiry(self, limit=100):
        from hashlib import sha256
        from sqlalchemy import func, select
        from .domain import new_id
        from .models import Allocation, Event, Job, Outbox
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Retention scan limit must be between 1 and 1000")
        now = utc(self.clock())
        requested = []
        with self.database.transaction(immediate=True) as session:
            jobs = session.scalars(select(Job).where(Job.state.in_(TERMINAL_STATES),
                Job.purged_at.is_(None), Job.artifacts_expire_at.is_not(None), Job.artifacts_expire_at <= now,
                Job.cleanup_status.not_in({"purge_pending", "expiry_pending", "expired"}))
                .order_by(Job.artifacts_expire_at, Job.id).with_for_update(skip_locked=True).limit(limit)).all()
            for job in jobs:
                active = session.scalar(select(func.count()).select_from(Allocation).where(
                    Allocation.job_id == job.id, Allocation.released_at.is_(None)))
                if active:
                    continue
                key = "retention:" + job.id + ":" + iso(job.artifacts_expire_at)
                existing = session.scalar(select(Outbox).where(Outbox.idempotency_key == key))
                if existing is None:
                    session.add(Outbox(id=sha256(key.encode()).hexdigest()[:32], job_id=job.id,
                        attempt_number=job.current_attempt, topic="expire_artifacts", state="pending",
                        idempotency_key=key, payload_json={"expires_at": iso(job.artifacts_expire_at),
                        "preserve_metadata": True, "confirm_before_release": True}, created_at=now))
                    sequence = (session.scalar(select(func.max(Event.sequence)).where(Event.job_id == job.id)) or 0) + 1
                    session.add(Event(id=new_id(), job_id=job.id, sequence=sequence, kind="retention.expiry_requested",
                        actor_id=None, data_json={"expires_at": iso(job.artifacts_expire_at)}, created_at=now))
                elif existing.state == "done":
                    continue
                job.cleanup_status = "expiry_pending"
                job.version += 1
                job.updated_at = now
                requested.append(job.id)
            session.flush()
        return requested


    @staticmethod
    def _reserve_project_bytes(project, amount):
        from .domain import Error
        if type(amount) is not int or not 0 <= amount <= (1 << 63) - 1:
            raise Error(422, "invalid_retained_size")
        quota = dict(project.quotas_json or {})
        limit = quota.get("retained_bytes", quota.get("disk_bytes", project.quota_disk_bytes))
        if limit is not None and project.retained_bytes + amount > limit:
            raise Error(409, "retained_storage_quota_exceeded")
        project.retained_bytes += amount
        project.version += 1

    @staticmethod
    def charge_in_transaction(session, resource, project, size_bytes):
        """Caller must hold the project row lock before owning job/resource locks."""
        from .domain import Error
        if type(size_bytes) is not int or not 0 <= size_bytes <= (1 << 63) - 1:
            raise Error(422, "invalid_retained_size")
        details = dict(resource.details_json or {})
        if "retention_charged_bytes" in details:
            if details["retention_charged_bytes"] != size_bytes or details.get("retention_charge_released"):
                raise Error(409, "retained_resource_charge_conflict")
            return False
        if resource.state == "deleted" or resource.deleted_at is not None:
            raise Error(409, "retained_resource_already_deleted")
        RetentionService._reserve_project_bytes(project, size_bytes)
        resource.retained = True
        resource.size_bytes = size_bytes
        details["retention_charged_bytes"] = size_bytes
        details["retention_charge_released"] = False
        details["retention_charge_settled"] = True
        details["retention_actual_bytes"] = size_bytes
        resource.details_json = details
        session.flush()
        return True


    @staticmethod
    def _whole_bytes(amount):
        """Convert PostgreSQL NUMERIC sums to exact, JSON-safe byte integers."""
        from decimal import Decimal
        if type(amount) is int and amount >= 0:
            return amount
        if (isinstance(amount, Decimal) and amount.is_finite() and amount >= 0
                and amount == amount.to_integral_value()):
            return int(amount)
        raise ValueError("Retained storage accounting returned non-integral bytes")

    @staticmethod
    def pool_used_bytes(session, pool_id, exclude_resource_id=None):
        """Include active reservations and all confirmed-owned retained copies."""
        from sqlalchemy import func, select
        from .models import Allocation, ProvisioningResource
        aggregate = session.scalar(select(func.coalesce(func.sum(Allocation.disk_bytes), 0)).where(
            Allocation.pool_id == pool_id, Allocation.released_at.is_(None)))
        total = RetentionService._whole_bytes(aggregate)
        for allocation in session.scalars(select(Allocation).where(Allocation.pool_id == pool_id,
                Allocation.state == "RELEASED", Allocation.released_at.is_not(None))):
            details = allocation.details_json or {}
            if details.get("retained_disk_charged") and not details.get("storage_deleted"):
                total += allocation.disk_bytes
        resources = select(ProvisioningResource).where(ProvisioningResource.retained.is_(True),
            ProvisioningResource.state != "deleted", ProvisioningResource.kind != "execution_state")
        if exclude_resource_id is not None:
            resources = resources.where(ProvisioningResource.id != exclude_resource_id)
        for resource in session.scalars(resources):
            if (resource.details_json or {}).get("pool_id") == pool_id:
                total += resource.size_bytes
        return total

    @staticmethod
    def _locked_resource(session, resource_id, job_id):
        """Storage locks follow the scheduler's Pool → Project → Job order."""
        from sqlalchemy import select
        from .domain import Error
        from .models import Job, Pool, Project, ProvisioningResource
        observed = session.get(ProvisioningResource, resource_id)
        if observed is None or observed.job_id != job_id or observed.ownership_json.get("job_id") != job_id:
            raise Error(409, "retained_resource_ownership_mismatch")
        pool_id = (observed.details_json or {}).get("pool_id")
        pool = None
        if pool_id is not None:
            pool = session.scalar(select(Pool).where(Pool.id == pool_id).with_for_update())
            if pool is None:
                raise Error(409, "retained_resource_pool_not_found")
        project_id = session.scalar(select(Job.project_id).where(Job.id == job_id))
        if project_id is None:
            raise Error(404, "job_not_found")
        project = session.scalar(select(Project).where(Project.id == project_id).with_for_update())
        job = session.scalar(select(Job).where(Job.id == job_id).with_for_update())
        resource = session.scalar(select(ProvisioningResource).where(ProvisioningResource.id == resource_id)
            .with_for_update().execution_options(populate_existing=True))
        if (resource is None or resource.job_id != job.id or resource.ownership_json.get("job_id") != job.id or
                (resource.details_json or {}).get("pool_id") != pool_id):
            raise Error(409, "retained_resource_ownership_mismatch")
        return project, job, resource, pool

    @classmethod
    def _reserve_pool_bytes(cls, session, resource, pool, size_bytes):
        from .domain import Error
        if pool is not None and resource.kind != "execution_state":
            used = cls.pool_used_bytes(session, pool.id, exclude_resource_id=resource.id)
            if used + size_bytes > pool.disk_bytes:
                raise Error(409, "retained_pool_storage_unavailable")

    def charge_resource(self, resource_id, job_id, size_bytes):
        from sqlalchemy import select
        from .domain import Error
        from .models import Job, Project, ProvisioningResource
        with self.database.transaction(immediate=True) as session:
            project, job, resource, pool = self._locked_resource(session, resource_id, job_id)
            self._reserve_pool_bytes(session, resource, pool, size_bytes)
            return self.charge_in_transaction(session, resource, project, size_bytes)

    @staticmethod
    def charge_log_in_transaction(session, project, chunk, *, budget=None):
        """Append bounded raw text under its prepaid cap or legacy byte charge.

        Caller holds Project → Job/budget locks (bound Pool first when needed).
        Prepaid logs cannot borrow another runtime or cleanup reservation.
        """
        from .domain import Error
        from .models import Job, LogChunk
        raw = chunk.data.encode("utf-8")
        amount = len(raw)
        if amount > 65536:
            raise Error(422, "log_chunk_exceeds_bound")
        if budget is not None:
            job = session.get(Job, chunk.job_id)
            details = dict(budget.details_json or {})
            ownership = {"job_id": chunk.job_id, "component_id": chunk.component, "kind": "log_budget"}
            if (job is None or job.project_id != project.id or budget.job_id != chunk.job_id
                    or budget.component_id != chunk.component or budget.kind != "log_budget"
                    or budget.ownership_json != ownership
                    or details.get("attempt_number") != chunk.attempt_number
                    or budget.external_id != "hf2l-log://" + chunk.job_id + "/" + str(chunk.attempt_number) + "/" + chunk.component
                    or budget.state == "deleted" or budget.deleted_at is not None
                    or details.get("retention_charge_released") or not budget.retained):
                raise Error(409, "retained_resource_ownership_mismatch")
            maximum = details.get("retention_reservation_bytes")
            charged = details.get("retention_charged_bytes")
            consumed = details.get("log_consumed_bytes", 0)
            last_sequence = details.get("log_last_sequence", 0)
            if (type(maximum) is not int or type(consumed) is not int or type(last_sequence) is not int
                    or not 0 <= consumed <= maximum or charged != maximum or budget.size_bytes != maximum
                    or project.retained_bytes < maximum or maximum > 1024**2):
                raise Error(409, "retained_storage_ledger_inconsistent")
            if chunk.sequence <= last_sequence:
                with session.no_autoflush:
                    previous = session.get(LogChunk, chunk.id) if chunk.id else None
                if (previous is None or previous.job_id != chunk.job_id or previous.component != chunk.component
                        or previous.attempt_number != chunk.attempt_number or previous.charged_bytes != 0):
                    raise Error(409, "retained_log_charge_conflict")
                return False
            if chunk.charged_bytes:
                raise Error(409, "retained_log_charge_conflict")
            remaining = maximum - consumed
            truncated = amount > remaining or bool(details.get("log_budget_exhausted"))
            if details.get("log_budget_exhausted"):
                chunk.data = ""
                amount = 0
            elif truncated:
                marker = "[manager log budget exhausted; further output omitted]\n".encode("utf-8")
                if remaining >= len(marker):
                    prefix = raw[:remaining - len(marker)].decode("utf-8", errors="ignore")
                    chunk.data = prefix + marker.decode("utf-8")
                else:
                    chunk.data = raw[:remaining].decode("utf-8", errors="ignore")
                amount = len(chunk.data.encode("utf-8"))
            consumed += amount
            chunk.charged_bytes = 0
            session.flush()
            details.update({"log_consumed_bytes": consumed, "log_last_sequence": chunk.sequence,
                            "log_last_chunk_id": chunk.id,
                            "log_truncated": bool(details.get("log_truncated")) or truncated,
                            "log_budget_exhausted": bool(details.get("log_budget_exhausted")) or truncated or consumed == maximum})
            budget.details_json = details
            session.flush()
            return True
        previous = chunk.charged_bytes or 0
        if previous:
            if previous != amount:
                raise Error(409, "retained_log_charge_conflict")
            return False
        RetentionService._reserve_project_bytes(project, amount)
        chunk.charged_bytes = amount
        session.flush()
        return True

    def confirm_resource_deleted(self, resource_id, job_id):
        """Release a charge only after the owned-resource ledger confirms deletion."""
        from sqlalchemy import select
        from .domain import Error
        from .models import Job, Project, ProvisioningResource
        with self.database.transaction(immediate=True) as session:
            project, job, resource, pool = self._locked_resource(session, resource_id, job_id)
            if resource.state != "deleted" or resource.deleted_at is None:
                raise Error(409, "resource_deletion_unconfirmed")
            details = dict(resource.details_json or {})
            if details.get("retention_charge_released"):
                return False
            amount = details.get("retention_charged_bytes", 0)
            if project.retained_bytes < amount:
                raise Error(409, "retained_storage_ledger_inconsistent")
            project.retained_bytes -= amount
            project.version += 1
            details["retention_charge_released"] = True
            details["retention_released_at"] = iso(utc(self.clock()))
            resource.details_json = details
            return True

    def confirm_job_data_deleted(self, job_id):
        """Confirm raw DB logs/artifacts after every owned retained resource is gone."""
        from sqlalchemy import func, select
        from .domain import Error, new_id
        from .models import Artifact, Event, Job, LogChunk, Pool, Project, ProvisioningResource
        now = utc(self.clock())
        with self.database.transaction(immediate=True) as session:
            observed = session.scalars(select(ProvisioningResource).where(ProvisioningResource.job_id == job_id)).all()
            pool_ids = sorted({(r.details_json or {}).get("pool_id") for r in observed if (r.details_json or {}).get("pool_id")})
            for pool_id in pool_ids:
                session.scalar(select(Pool).where(Pool.id == pool_id).with_for_update())
            project_id = session.scalar(select(Job.project_id).where(Job.id == job_id))
            if project_id is None:
                raise Error(404, "job_not_found")
            project = session.scalar(select(Project).where(Project.id == project_id).with_for_update())
            job = session.scalar(select(Job).where(Job.id == job_id).with_for_update())
            if job.state not in TERMINAL_STATES:
                raise Error(409, "retention_requires_terminal")
            resources = session.scalars(select(ProvisioningResource).where(ProvisioningResource.job_id == job_id,
                ProvisioningResource.retained.is_(True)).with_for_update()).all()
            def deleted_or_audit_only(row):
                if row.state == "deleted" and row.deleted_at is not None:
                    return True
                return (row.state == "retired" and row.kind in {"exchange_space", "exchange_member"} and
                        row.size_bytes == 0 and not (row.details_json or {}).get("retention_charged_bytes", 0))
            def owned_database_logs(row):
                details = row.details_json or {}
                number = details.get("attempt_number")
                return (row.kind == "log_budget" and type(number) is int and number >= 1
                        and row.ownership_json == {"job_id": job.id, "component_id": row.component_id, "kind": "log_budget"}
                        and row.external_id == "hf2l-log://" + job.id + "/" + str(number) + "/" + row.component_id
                        and type(details.get("retention_reservation_bytes")) is int
                        and details.get("retention_charged_bytes") == details["retention_reservation_bytes"]
                        and row.size_bytes == details["retention_reservation_bytes"])
            if any(not deleted_or_audit_only(row) and not owned_database_logs(row) for row in resources):
                raise Error(409, "resource_deletion_unconfirmed")
            released = 0
            for row in resources:
                details = dict(row.details_json or {})
                if not details.get("retention_charge_released"):
                    released += details.get("retention_charged_bytes", 0)
                    details["retention_charge_released"] = True
                    details["retention_released_at"] = iso(now)
                    row.details_json = details
            logs = session.scalars(select(LogChunk).where(LogChunk.job_id == job_id).with_for_update()).all()
            for chunk in logs:
                released += chunk.charged_bytes
                chunk.charged_bytes = 0
                chunk.data = ""
                chunk.deleted_at = chunk.deleted_at or now
            for row in resources:
                if owned_database_logs(row):
                    row.state = "deleted"
                    row.deleted_at = row.deleted_at or now
            if project.retained_bytes < released:
                raise Error(409, "retained_storage_ledger_inconsistent")
            project.retained_bytes -= released
            project.version += int(released > 0)
            for artifact in session.scalars(select(Artifact).where(Artifact.job_id == job_id).with_for_update()):
                artifact.state = "deleted"
                artifact.deleted_at = artifact.deleted_at or now
            if job.cleanup_status != "expired":
                job.cleanup_status = "expired"
                job.version += 1
                job.updated_at = now
                sequence = (session.scalar(select(func.max(Event.sequence)).where(Event.job_id == job_id)) or 0) + 1
                session.add(Event(id=new_id(), job_id=job_id, sequence=sequence, kind="retention.deletion_confirmed",
                    actor_id=None, data_json={"released_bytes": released, "metadata_retained": True}, created_at=now))
            return released


    @classmethod
    def reserve_in_transaction(cls, session, resource, project, max_bytes, pool=None):
        """Caller holds bound Pool → Project → Job/resource locks for gang admission."""
        from .domain import Error
        if type(max_bytes) is not int or not 0 <= max_bytes <= (1 << 63) - 1:
            raise Error(422, "invalid_retained_size")
        if resource.state == "deleted" or resource.deleted_at is not None:
            raise Error(409, "retained_resource_already_deleted")
        details = dict(resource.details_json or {})
        if details.get("pool_id") is not None and (pool is None or pool.id != details["pool_id"]):
            raise Error(409, "retained_resource_pool_context_required")
        if details.get("retention_charge_released"):
            raise Error(409, "retained_resource_charge_conflict")
        if "retention_charged_bytes" in details:
            if details.get("retention_charge_settled", "retention_reservation_bytes" not in details):
                if details["retention_charged_bytes"] > max_bytes:
                    raise Error(409, "retained_resource_exceeds_reservation")
                return False
            if details.get("retention_reservation_bytes") != max_bytes:
                raise Error(409, "retained_resource_reservation_conflict")
            return False
        cls._reserve_pool_bytes(session, resource, pool, max_bytes)
        cls._reserve_project_bytes(project, max_bytes)
        resource.retained = True
        resource.size_bytes = max_bytes
        details.update({"retention_charged_bytes": max_bytes, "retention_reservation_bytes": max_bytes,
                        "retention_charge_settled": False, "retention_charge_released": False})
        resource.details_json = details
        session.flush()
        return True

    def reserve_resource(self, resource_id, job_id, max_bytes):
        """Reserve a bounded raw-copy budget before materialization can occur."""
        with self.database.transaction(immediate=True) as session:
            project, job, resource, pool = self._locked_resource(session, resource_id, job_id)
            return self.reserve_in_transaction(session, resource, project, max_bytes, pool)

    def settle_resource(self, resource_id, job_id, actual_bytes):
        """Release only unused reserved budget after an immutable copy is measured."""
        from sqlalchemy import select
        from .domain import Error
        from .models import Job, Project, ProvisioningResource
        if type(actual_bytes) is not int or not 0 <= actual_bytes <= (1 << 63) - 1:
            raise Error(422, "invalid_retained_size")
        with self.database.transaction(immediate=True) as session:
            project, job, resource, pool = self._locked_resource(session, resource_id, job_id)
            details = dict(resource.details_json or {})
            if resource.state == "deleted" or resource.deleted_at is not None or details.get("retention_charge_released"):
                raise Error(409, "retained_resource_already_deleted")
            if "retention_charged_bytes" not in details:
                raise Error(409, "retained_resource_reservation_required")
            if details.get("retention_charge_settled", "retention_reservation_bytes" not in details):
                if details["retention_charged_bytes"] != actual_bytes:
                    raise Error(409, "retained_resource_charge_conflict")
                return False
            reserved = details.get("retention_reservation_bytes")
            if type(reserved) is not int or actual_bytes > reserved:
                raise Error(409, "retained_resource_exceeds_reservation")
            release = details["retention_charged_bytes"] - actual_bytes
            if release < 0 or project.retained_bytes < release:
                raise Error(409, "retained_storage_ledger_inconsistent")
            project.retained_bytes -= release
            project.version += int(release > 0)
            details["retention_charged_bytes"] = actual_bytes
            details["retention_actual_bytes"] = actual_bytes
            details["retention_charge_settled"] = True
            resource.size_bytes = actual_bytes
            resource.details_json = details
            session.flush()
            return True


    @classmethod
    def transfer_reserved_in_transaction(cls, session, reservation, project, children, *, retain_unused=False):
        """Transfer a complete collection; optionally retain its physical bound.

        Callers hold Pool → Project → Job/resource locks. Unknown or partial
        copies must keep their full reservation and must not call this helper.
        Conservative collection mode keeps parent + child charges at the cap
        until confirmed purge, even for a one-byte file with physical metadata.
        """
        from .domain import Error
        from .models import Job
        if type(retain_unused) is not bool:
            raise Error(422, "invalid_retained_collection")
        children = list(children)
        if len(children) > 10000 or len({r.id for r in children}) != len(children):
            raise Error(422, "invalid_retained_collection")
        job = session.get(Job, reservation.job_id)
        if (job is None or project.id != job.project_id or reservation.ownership_json.get("job_id") != job.id or
                reservation.state == "deleted" or reservation.deleted_at is not None):
            raise Error(409, "retained_resource_ownership_mismatch")
        details = dict(reservation.details_json or {})
        if "retention_reservation_bytes" not in details or details.get("retention_charge_released"):
            raise Error(409, "retained_resource_reservation_required")
        available = details.get("retention_charged_bytes", 0)
        settled = details.get("retention_charge_settled", False)
        manifest = {}
        for child in children:
            amount = child.size_bytes
            data = dict(child.details_json or {})
            if (child.id == reservation.id or child.job_id != job.id or child.ownership_json.get("job_id") != job.id or
                    child.state == "deleted" or child.deleted_at is not None or child.kind == "execution_state" or
                    type(amount) is not int or not 0 <= amount <= (1 << 63) - 1):
                raise Error(409, "retained_resource_ownership_mismatch")
            if data.get("pool_id") is not None and data["pool_id"] != details.get("pool_id"):
                raise Error(409, "retained_resource_ownership_mismatch")
            manifest[child.id] = amount
        if settled and (details.get("retention_retain_unused", False) != retain_unused
                        or details.get("retention_collection_manifest", manifest) != manifest):
            raise Error(409, "retained_resource_charge_conflict")
        transferred = 0
        for child in children:
            amount = child.size_bytes
            data = dict(child.details_json or {})
            if "retention_charged_bytes" in data:
                if (data["retention_charged_bytes"] != amount or data.get("retention_charge_released") or
                        data.get("retention_reservation_source") != reservation.id):
                    raise Error(409, "retained_resource_charge_conflict")
                continue
            if settled or amount > available:
                raise Error(409, "retained_resource_exceeds_reservation")
            available -= amount
            transferred += amount
            child.retained = True
            data.update({"retention_charged_bytes": amount, "retention_charge_released": False,
                         "retention_charge_settled": True, "retention_actual_bytes": amount,
                         "retention_reservation_source": reservation.id})
            if details.get("pool_id") is not None:
                data["pool_id"] = details["pool_id"]
            child.details_json = data
        if project.retained_bytes < available:
            raise Error(409, "retained_storage_ledger_inconsistent")
        released = available if not settled and not retain_unused else 0
        project.retained_bytes -= released
        project.version += int(released > 0)
        remaining = available if retain_unused else 0
        details.update({"retention_charged_bytes": remaining, "retention_actual_bytes": 0,
                        "retention_charge_settled": True, "retention_retain_unused": retain_unused,
                        "retention_conservative_footprint": retain_unused,
                        "retention_collection_manifest": manifest,
                        "retention_transferred_bytes": details.get("retention_transferred_bytes", 0) + transferred})
        reservation.size_bytes = remaining
        reservation.details_json = details
        session.flush()
        return {"transferred_bytes": transferred, "released_bytes": released}
