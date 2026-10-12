"""Transaction-owned manager commands. Job code is never imported or executed here."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import math

from pydantic import ValidationError
from sqlalchemy import and_, func, or_, select

from . import models
from .authorization import (JOB_ROLES, principal_id, require_job_role, require_submitter,
                            validate_member_id)
from .domain import Error, JobSpec, JobState, canonical_json, new_id, utcnow
from .pagination import CursorSigner, page_limit
from .retention import TERMINAL_STATES, RetentionService, artifact_view, iso, retention_summary, utc

ACTIVE_ALLOCATION_STATES = frozenset({"RESERVED", "ACKNOWLEDGED", "STARTING", "RUNNING", "QUARANTINED", "RELEASING"})


class Manager:
    def __init__(self, database, cursor_secret, clock=None, platform_operator_ids=(), pool_qualifier=None, storage_planner=None):
        self.database = database
        self.engine = database.engine
        self.cursors = CursorSigner(cursor_secret)
        self.clock = clock or utcnow
        self.platform_operator_ids = frozenset(platform_operator_ids)
        self.pool_qualifier = pool_qualifier
        # Trusted pure provisioner planning; called before a new job is persisted.
        self.storage_planner = storage_planner

    def now(self):
        return utc(self.clock())

    @contextmanager
    def transaction(self, principal, job_id, role="reader", write=False):
        actor = principal_id(principal)
        with self.database.transaction(immediate=write) as session:
            query = select(models.JobRecord).where(models.JobRecord.id == job_id)
            if write:
                query = query.with_for_update()
            job = session.scalar(query)
            member = session.get(models.Membership, (job_id, actor)) if job else None
            require_job_role(member, role)
            yield session, job, member

    @staticmethod
    def _key(value):
        if not isinstance(value, str) or not value or len(value) > 128 or any(ord(c) < 32 for c in value):
            raise Error(422, "idempotency_key_required")
        return value

    @staticmethod
    def _version(job, expected):
        if type(expected) is not int or expected < 1:
            raise Error(428, "expected_version_required")
        if expected != job.version:
            raise Error(409, "job_version_conflict", {"current_version": job.version})

    @staticmethod
    def _lock_operation(session, principal, scope, key):
        if session.bind.dialect.name == "postgresql":
            identity = canonical_json([principal, scope, key])
            session.execute(select(func.pg_advisory_xact_lock(func.hashtextextended(identity, 0))))

    def _once(self, session, actor, scope, key, body, action, replay=None):
        key = self._key(key)
        self._lock_operation(session, actor, scope, key)
        digest = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        existing = session.get(models.Idempotency, {"principal_id": actor, "scope": scope, "key": key})
        if existing:
            if existing.request_hash != digest:
                raise Error(409, "idempotency_conflict")
            return replay(existing.response_json) if replay else existing.response_json
        result = action()
        session.add(models.Idempotency(principal_id=actor, scope=scope, key=key,
                                       request_hash=digest, response_json=result, created_at=self.now()))
        session.flush()
        return result

    def _emit(self, session, job, kind, actor, data=None):
        # Writers hold the job lock, so a per-job sequence never reveals foreign events.
        sequence = (session.scalar(select(func.max(models.Event.sequence)).where(models.Event.job_id == job.id)) or 0) + 1
        session.add(models.Event(id=new_id(), job_id=job.id, sequence=sequence, kind=kind,
                                 actor_id=actor, data_json=data or {}, created_at=self.now()))
        session.flush()

    def _outbox(self, session, job, kind, actor, payload=None):
        operation_id = new_id()
        session.add(models.Outbox(id=operation_id, job_id=job.id, attempt_number=job.current_attempt,
                                  kind=kind, payload_json=payload or {}, state="pending",
                                  idempotency_key=operation_id, created_at=self.now()))
        self._emit(session, job, "operation.requested", actor, {"operation_id": operation_id, "operation": kind})
        return operation_id

    def _touch(self, job):
        job.version += 1
        job.updated_at = self.now()

    def _allowed(self, job, member):
        actions = []
        if member.role in {"operator", "admin"} and not getattr(job, "purged_at", None):
            if job.state not in TERMINAL_STATES and job.state != "CANCELLING":
                actions.append("cancel")
            if (job.state == "FAILED" and (not job.deadline_at or utc(job.deadline_at) > self.now()) and
                    job.cleanup_status not in {"purge_pending", "expiry_pending", "expired"} and
                    (not job.artifacts_expire_at or utc(job.artifacts_expire_at) > self.now())):
                actions.append("retry")
            if job.state == "NEEDS_ATTENTION":
                actions.append("reconcile")
        if member.role == "admin":
            actions.append("manage_members")
            if job.state in TERMINAL_STATES and not getattr(job, "purged_at", None):
                actions.append("purge")
        return actions

    def _job_view(self, job, member, detail=False, session=None):
        value = {"id": job.id, "project_id": job.project_id, "name": job.name,
                 "state": job.state, "phase": job.phase, "queue_reason": job.queue_reason,
                 "version": job.version, "current_attempt": job.current_attempt,
                 "target_round": job.target_round, "current_round": job.current_round,
                 "created_at": iso(job.created_at), "updated_at": iso(job.updated_at),
                 "deadline_at": iso(job.deadline_at), "terminated_at": iso(job.terminated_at),
                 "error_code": getattr(job, "error_code", None),
                 "outcome_reason": getattr(job, "outcome_reason", None),
                 "retention": retention_summary(job, self.now()), "role": member.role,
                 "allowed_actions": self._allowed(job, member), "spec_hash": job.spec_hash}
        if not getattr(job, "purged_at", None):
            components = job.spec_json.get("components", [])
            dimensions = ("cpu_millicores", "memory_bytes", "disk_bytes", "gpu_count")
            value["resource_summary"] = {key: sum(component["resources"].get(key, 0) for component in components)
                                         for key in dimensions}
            value["participants_count"] = len(job.spec_json.get("participants", []))
            value["first_reserved_at"] = iso(utc(job.deadline_at) - timedelta(seconds=job.spec_json["max_duration_seconds"])) if job.deadline_at else None
        if getattr(job, "purged_at", None):
            value["name"] = "Purged job"
            value["purged"] = True
        elif detail:
            spec = dict(job.spec_json)
            # Secret references are not dashboard/search content.
            spec.pop("secret_refs", None)
            value["spec"] = spec
            participants = spec.get("participants", [])
            bindings = {}
            if session is not None and participants:
                binding_ids = {p["dataset_binding"] for p in participants}
                bindings = {b.id: b for b in session.scalars(select(models.ParticipantBinding).where(
                    models.ParticipantBinding.project_id == job.project_id,
                    models.ParticipantBinding.id.in_(binding_ids)))}
            enriched = []
            for participant in participants:
                binding = bindings.get(participant["dataset_binding"])
                approved = bool(binding and binding.enabled and binding.participant_id == participant["participant_id"])
                node_id = binding.node_id if approved else None
                can_enroll = (participant["mode"] == "external" and node_id and member.role in {"operator", "admin"} and
                    job.state in {"QUEUED", "PROVISIONING", "STARTING", "RUNNING"} and
                    (not job.deadline_at or utc(job.deadline_at) > self.now()))
                enriched.append({**participant, "node_id": node_id,
                    "allowed_actions": ["enroll_participant"] if can_enroll else []})
                if can_enroll and "enroll_participant" not in value["allowed_actions"]:
                    value["allowed_actions"].append("enroll_participant")
            value["participants"] = enriched
            value["resources"] = [{"component_id": c["component_id"], "role": c["role"],
                                   **c["resources"]} for c in spec.get("components", [])]
            if session is not None:
                self._observations(session, job, value)
        return value

    def _safe_component_report(self, report):
        report = report if isinstance(report, dict) else {}
        metrics = report.get("metrics", {})
        metrics = metrics if isinstance(metrics, dict) else {}
        metrics = {key: number for key, number in list(metrics.items())[:32]
                   if isinstance(key, str) and key and len(key) <= 64 and not any(ord(c) < 32 for c in key)
                   and type(number) in (int, float) and abs(number) <= 1.7976931348623157e308 and math.isfinite(number)}
        readiness = report.get("readiness")
        if not isinstance(readiness, str) or readiness not in {"initializing", "waiting", "ready", "training", "finished", "failed"}:
            readiness = "not_observed"
        observed_at = None
        try:
            raw = report.get("observed_at")
            if isinstance(raw, str) and len(raw) <= 128:
                parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                if parsed.tzinfo is not None:
                    observed_at = utc(parsed)
        except ValueError:
            pass
        age = (self.now() - observed_at).total_seconds() if observed_at else None
        freshness = "not_observed" if age is None else "stale" if age > 300 else "clock_skew" if age < -30 else "current"
        value = {"metrics": metrics, "metrics_status": "observed" if metrics else "not_observed",
                 "readiness": readiness, "observed_at": iso(observed_at), "freshness": freshness}
        round_value = report.get("current_round")
        if type(round_value) is int and 0 <= round_value <= (1 << 63) - 1:
            value["reported_round"] = round_value
        phase = report.get("phase")
        if isinstance(phase, str) and phase in {"fetching", "building", "initializing", "aggregating", "waiting_participants", "training", "publishing", "collecting_results"}:
            value["phase"] = phase
        publication = report.get("publication_status")
        if isinstance(publication, str) and publication in {"none", "absent", "confirmed", "published", "unknown", "publishing", "ambiguous", "not_observed"}:
            value["publication_status"] = publication
        return value

    def _attempt_components(self, job, attempt, include_observations=True):
        details = attempt.details_json if attempt and isinstance(attempt.details_json, dict) else {}
        reports = details.get("components", {}) if include_observations else {}
        reports = reports if isinstance(reports, dict) else {}
        return [{"component_id": spec["component_id"], "role": spec["role"],
                 "participant_id": spec.get("participant_id"),
                 **self._safe_component_report(reports.get(spec["component_id"]))}
                for spec in job.spec_json.get("components", [])[:1024]]

    def _observations(self, session, job, value):
        attempt = session.scalar(select(models.Attempt).where(models.Attempt.job_id == job.id,
            models.Attempt.number == job.current_attempt))
        current_epoch = bool(attempt and attempt.epoch == job.epoch)
        components = self._attempt_components(job, attempt, include_observations=current_epoch)
        by_component = {component["component_id"]: component for component in components}
        owner = next((component for component in components if component["role"] == "owner"), None)
        owner = owner or self._safe_component_report(None)
        value["metrics"] = owner["metrics"]
        value["progress"] = {"attempt_id": attempt.id if attempt else None, "epoch": attempt.epoch if attempt else None,
                             "metrics": owner["metrics"], "metrics_status": owner["metrics_status"],
                             "observed_at": owner["observed_at"], "freshness": owner["freshness"],
                             "components": components}
        allocations = session.scalars(select(models.Allocation).where(models.Allocation.job_id == job.id,
            models.Allocation.attempt_id == attempt.id if attempt else False,
            models.Allocation.epoch == attempt.epoch if attempt else False).order_by(models.Allocation.component_id)).all()
        value["allocations"] = [{"component_id": allocation.component_id, "pool_id": allocation.pool_id,
            "state": allocation.state, "acknowledged": allocation.acknowledged,
            "termination_confirmed": allocation.termination_confirmed,
            "cpu_millicores": allocation.cpu_millicores, "memory_bytes": allocation.memory_bytes,
            "disk_bytes": allocation.disk_bytes, "gpu_count": allocation.gpu_count}
            for allocation in allocations if allocation.component_id in by_component]
        enrollments = session.scalars(select(models.ProvisioningResource).where(
            models.ProvisioningResource.job_id == job.id, models.ProvisioningResource.kind == "external_enrollment")).all()
        external = {}
        for enrollment in enrollments:
            data = enrollment.details_json if isinstance(enrollment.details_json, dict) else {}
            pid = data.get("participant_id")
            ownership = enrollment.ownership_json or {}
            if (isinstance(pid, str) and ownership.get("job_id") == job.id and ownership.get("participant_id") == pid
                    and attempt and enrollment.attempt_id == attempt.id and data.get("epoch") == attempt.epoch):
                external[pid] = (enrollment, data)
        for participant in value["participants"]:
            report = by_component.get(participant.get("component_id")) if participant["mode"] == "managed" else None
            if report:
                participant.update({name: report[name] for name in ("readiness", "metrics", "observed_at", "freshness")})
                continue
            participant.update({"readiness": "not_observed", "metrics": {}, "observed_at": None, "freshness": "not_observed"})
            entry = external.get(participant["participant_id"])
            if participant["mode"] != "external" or not entry:
                continue
            enrollment, data = entry
            if (data.get("dataset_binding") != participant["dataset_binding"] or
                    data.get("node_id") != participant.get("node_id")):
                continue
            status = data.get("status")
            if isinstance(status, str) and status in {"enrolled", "dispatching", "preparing", "assigned", "stopped", "purging", "purged", "failed", "needs_attention"}:
                participant["status"] = status
                participant["enrollment"] = {"status": status, "node_id": participant.get("node_id"),
                    "attempt_id": enrollment.attempt_id, "epoch": data.get("epoch")}
            phase = data.get("phase")
            if isinstance(phase, str) and phase in {"running", "waiting_initialization", "waiting_for_model", "training", "publishing", "completed", "retry", "needs_attention", "stopped"}:
                report = self._safe_component_report({"observed_at": data.get("last_heartbeat")})
                participant.update({"readiness": phase, "observed_at": report["observed_at"], "freshness": report["freshness"]})
        spaces = session.scalars(select(models.ProvisioningResource).where(models.ProvisioningResource.job_id == job.id,
            models.ProvisioningResource.kind == "exchange_space").order_by(models.ProvisioningResource.created_at)).all()
        owned = [space for space in spaces if (space.ownership_json or {}).get("job_id") == job.id and
                 space.state != "deleted" and isinstance(space.external_id, str) and len(space.external_id) <= 256]
        value["space_id"] = owned[0].external_id if len(owned) == 1 else None

    def _approve_spec(self, session, spec):
        source = session.get(models.ApprovedSource, spec.source_id)
        if source is None or not source.enabled or source.status != "approved" or source.project_id not in {None, spec.project_id}:
            raise Error(422, "source_not_approved")
        if source.allowed_commits and spec.source_commit not in source.allowed_commits:
            raise Error(422, "source_commit_not_approved")
        image = session.get(models.RuntimeImage, spec.runtime_image)
        if image is None:
            image = session.scalar(select(models.RuntimeImage).where(models.RuntimeImage.digest == spec.runtime_image,
                                                                     models.RuntimeImage.enabled.is_(True),
                or_(models.RuntimeImage.project_id.is_(None), models.RuntimeImage.project_id == spec.project_id)))
        if image is None or not image.enabled or not image.approved or image.status != "approved" or image.project_id not in {None, spec.project_id}:
            raise Error(422, "runtime_image_not_approved")
        if not isinstance(image.digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", image.digest):
            raise Error(422, "invalid_runtime_image_digest")
        for participant in spec.participants:
            binding = session.get(models.ParticipantBinding, participant.dataset_binding)
            if (binding is None or not binding.enabled or binding.project_id != spec.project_id or
                    binding.participant_id != participant.participant_id or
                    (participant.mode == "external" and not binding.node_id)):
                raise Error(422, "participant_binding_not_approved")
        for reference in spec.secret_refs.values():
            model = getattr(models, "SecretReference", None)
            secret = session.get(model, reference) if model else None
            if secret is None or not secret.enabled or secret.project_id != spec.project_id:
                raise Error(422, "secret_reference_not_approved")
        from .scheduler import validate_admission
        validate_admission(session, spec)
        return image.digest

    def _validate_storage_admission(self, session, job, spec):
        """Reject total-copy requests that cannot fit even on an idle system."""
        if self.storage_planner is None:
            return
        from .resources import ResourceError
        from .scheduler import requested_by_pool, _quota
        try:
            planned = self.storage_planner(job)
        except ResourceError:
            raise Error(422, "storage_plan_unavailable") from None
        if not isinstance(planned, (list, tuple)) or len(planned) > 10000:
            raise ValueError("Trusted storage planner returned an invalid bounded plan")
        requested = requested_by_pool(spec)
        components = {component.component_id for component in spec.components}
        external_components = {"participant-" + hashlib.sha256(canonical_json([participant.participant_id]).encode()).hexdigest()[:40]
                               for participant in spec.participants if participant.mode == "external"}
        if external_components.intersection(components):
            raise ValueError("Trusted external component identity collides with its job")
        identities = set()
        extra_bytes = 0
        for entry in planned:
            if (not isinstance(entry, dict) or not isinstance(entry.get("kind"), str)
                    or not 1 <= len(entry["kind"]) <= 64 or not entry["kind"].replace("_", "").isalnum()
                    or (entry.get("component_id") not in components and not (
                        entry.get("kind") == "log_budget"
                        and entry.get("component_id") in external_components
                        and entry.get("max_bytes") == 1024**2
                        and entry.get("external_id") == "hf2l-log://" + job.id + "/" + str(job.current_attempt) + "/" + entry["component_id"]))
                    or not isinstance(entry.get("pool_id"), str)
                    or not isinstance(entry.get("external_id"), str)
                    or type(entry.get("max_bytes")) is not int
                    or not 0 <= entry["max_bytes"] <= (1 << 63) - 1):
                raise ValueError("Trusted storage plan differs from its immutable job")
            identity = (entry["kind"], entry["external_id"])
            if identity in identities:
                raise ValueError("Trusted storage planner counted an owned copy twice")
            identities.add(identity)
            request = requested.setdefault(entry["pool_id"], {"disk_bytes": 0})
            covered = entry.get("covered_by_allocation", False)
            if covered:
                if covered is not True or entry["kind"] != "execution_state" or entry["component_id"] not in components:
                    raise ValueError("Trusted storage coverage differs from its execution allocation")
                component = next(c for c in spec.components if c.component_id == entry["component_id"])
                if (entry["pool_id"] != component.resources.pool_id
                        or entry["max_bytes"] != component.resources.disk_bytes):
                    raise ValueError("Trusted storage coverage differs from its execution allocation")
            else:
                request["disk_bytes"] += entry["max_bytes"]
            extra_bytes += entry["max_bytes"]
        for pool_id, request in requested.items():
            pool = session.get(models.Pool, pool_id)
            if pool is None:
                raise Error(422, "resource_pool_not_found")
            # Health and current reservations are temporary scheduler conditions.
            if request["disk_bytes"] > pool.disk_bytes:
                raise Error(422, "resource_request_exceeds_pool")
        project = session.get(models.Project, spec.project_id)
        quota = _quota(project)
        disk_bytes = sum(request["disk_bytes"] for request in requested.values())
        if (("disk_bytes" in quota and disk_bytes > quota["disk_bytes"])
                or ("retained_bytes" in quota and extra_bytes > quota["retained_bytes"])):
            raise Error(422, "resource_request_exceeds_project_quota")

    def create_job(self, principal, spec, idempotency_key):
        actor = principal_id(principal)
        self._key(idempotency_key)
        try:
            spec = spec if isinstance(spec, JobSpec) else JobSpec.model_validate(spec)
        except ValidationError:
            raise Error(422, "invalid_job_spec") from None
        with self.database.transaction(immediate=True) as session:
            project = session.scalar(select(models.Project).where(models.Project.id == spec.project_id).with_for_update())
            member = session.get(models.ProjectMember, (spec.project_id, actor)) if project else None
            require_submitter(member)
            def action():
                minimum = spec.options.get("minimum_participants", 2)
                if type(minimum) is not int or not 2 <= minimum <= len(spec.participants):
                    raise Error(422, "invalid_job_spec")
                digest = self._approve_spec(session, spec)
                pinned_spec = JobSpec.model_validate({**spec.to_dict(), "runtime_image": digest})
                now = self.now()
                job = models.JobRecord(id=new_id(), project_id=spec.project_id, creator_id=actor, name=spec.name,
                                       spec_json=pinned_spec.to_dict(), spec_hash=pinned_spec.digest, state="QUEUED", phase="waiting_resources",
                                       queue_reason={"code": "awaiting_scheduler"}, version=1, current_attempt=1, attempt_count=1,
                                       target_round=spec.target_round, current_round=0, cleanup_status="none",
                                       created_at=now, updated_at=now)
                self._validate_storage_admission(session, job, pinned_spec)
                session.add(job)
                session.flush()
                session.add(models.Membership(job_id=job.id, principal_id=actor, role="admin"))
                session.add(models.Attempt(job_id=job.id, number=1, state="QUEUED", epoch=1,
                                           resources_json={}, created_at=now))
                session.flush()
                self._emit(session, job, "job.created", actor, {"spec_hash": pinned_spec.digest})
                return self._job_view(job, session.get(models.Membership, (job.id, actor)), True, session)
            def replay(response):
                job = session.get(models.JobRecord, response["id"])
                current = session.get(models.Membership, (job.id, actor)) if job else None
                require_job_role(current)
                return self._job_view(job, current, True, session)
            return self._once(session, actor, "job.create", idempotency_key, spec.to_dict(), action, replay)

    def get_job(self, principal, job_id):
        with self.transaction(principal, job_id) as (session, job, member):
            return self._job_view(job, member, True, session)

    @staticmethod
    def _filters(filters):
        filters = dict(filters or {})
        if set(filters) - {"view", "state", "project_id", "search"}:
            raise Error(422, "invalid_job_filter")
        if filters.get("view") not in {None, "queued", "current", "history", "all"}:
            raise Error(422, "invalid_job_filter")
        if filters.get("state") is not None and filters["state"] not in {s.value for s in JobState}:
            raise Error(422, "invalid_job_filter")
        if "project_id" in filters and (not isinstance(filters["project_id"], str) or len(filters["project_id"]) > 128):
            raise Error(422, "invalid_job_filter")
        if "search" in filters and (not isinstance(filters["search"], str) or len(filters["search"]) > 200):
            raise Error(422, "invalid_job_filter")
        return filters

    @staticmethod
    def _visible_query(actor):
        return select(models.JobRecord, models.Membership).join(models.Membership,
            and_(models.Membership.job_id == models.JobRecord.id, models.Membership.principal_id == actor))

    def job_counts(self, principal):
        actor = principal_id(principal)
        with self.database.transaction(immediate=False) as session:
            states = session.execute(select(models.JobRecord.state, func.count()).join(models.Membership,
                and_(models.Membership.job_id == models.JobRecord.id, models.Membership.principal_id == actor))
                .where(models.JobRecord.purged_at.is_(None)).group_by(models.JobRecord.state)).all()
            counts = {state: count for state, count in states}
            return {"queued": counts.get("QUEUED", 0), "history": sum(counts.get(s, 0) for s in TERMINAL_STATES),
                    "current": sum(v for s, v in counts.items() if s not in TERMINAL_STATES and s != "QUEUED")}

    def list_jobs(self, principal, filters=None, limit=50, cursor=None):
        actor = principal_id(principal)
        filters = self._filters(filters)
        limit = page_limit(limit)
        position = self.cursors.decode(cursor, actor, "jobs", filters, self.now().timestamp()) if cursor else None
        with self.database.transaction(immediate=False) as session:
            query = self._visible_query(actor).where(models.JobRecord.purged_at.is_(None))
            view = filters.get("view")
            if view == "queued":
                query = query.where(models.JobRecord.state == "QUEUED")
            elif view == "current":
                query = query.where(models.JobRecord.state.not_in(TERMINAL_STATES | {"QUEUED"}))
            elif view == "history":
                query = query.where(models.JobRecord.state.in_(TERMINAL_STATES))
            if filters.get("state"):
                query = query.where(models.JobRecord.state == filters["state"])
            if filters.get("project_id"):
                query = query.where(models.JobRecord.project_id == filters["project_id"])
            if filters.get("search"):
                text = filters["search"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                query = query.where(models.JobRecord.name.ilike("%" + text + "%", escape="\\"))
            total = session.scalar(select(func.count()).select_from(query.subquery()))
            if position is not None:
                try:
                    created = utc(datetime.fromisoformat(position["created_at"].replace("Z", "+00:00")))
                    job_id = position["id"]
                    if set(position) != {"created_at", "id"} or not isinstance(job_id, str):
                        raise ValueError()
                except (TypeError, ValueError, KeyError, AttributeError):
                    raise Error(422, "invalid_cursor") from None
                query = query.where(or_(models.JobRecord.created_at < created,
                    and_(models.JobRecord.created_at == created, models.JobRecord.id < job_id)))
            rows = session.execute(query.order_by(models.JobRecord.created_at.desc(), models.JobRecord.id.desc()).limit(limit + 1)).all()
            items = [self._job_view(job, member) for job, member in rows[:limit]]
            next_cursor = None
            if len(rows) > limit:
                last = rows[limit - 1][0]
                next_cursor = self.cursors.encode(actor, "jobs", filters,
                    {"created_at": iso(last.created_at), "id": last.id}, self.now().timestamp())
            # Counts reuse the same visibility snapshot, never the global inventory.
            states = session.execute(select(models.JobRecord.state, func.count()).join(models.Membership,
                and_(models.Membership.job_id == models.JobRecord.id, models.Membership.principal_id == actor))
                .where(models.JobRecord.purged_at.is_(None)).group_by(models.JobRecord.state)).all()
            by_state = dict(states)
            counts = {"queued": by_state.get("QUEUED", 0), "history": sum(by_state.get(s, 0) for s in TERMINAL_STATES),
                      "current": sum(v for s, v in states if s not in TERMINAL_STATES and s != "QUEUED")}
            return {"items": items, "next_cursor": next_cursor, "total": total, "counts": counts, "counts_by_state": by_state}

    def _command(self, principal, job_id, role, key, expected_version, kind, data, action, allow_purged=False):
        actor = principal_id(principal)
        with self.transaction(principal, job_id, role, write=True) as (session, job, member):
            body = {"expected_version": expected_version, **data}
            def execute():
                self._version(job, expected_version)
                if getattr(job, "purged_at", None) and not allow_purged:
                    raise Error(409, "job_purged")
                action(session, job, actor)
                self._touch(job)
                session.flush()
                self._emit(session, job, kind, actor)
                return self._job_view(job, member, True, session)
            return self._once(session, actor, kind + ":" + job_id, key, body, execute)

    def cancel(self, principal, job_id, expected_version, idempotency_key):
        def action(session, job, actor):
            if job.state in TERMINAL_STATES:
                raise Error(409, "job_already_terminal")
            if job.state != "CANCELLING":
                job.state = "CANCELLING"
                job.phase = "fencing"
                job.queue_reason = None
                self._outbox(session, job, "fence_stop", actor, {"desired_outcome": "CANCELLED", "grace_seconds": 60})
        return self._command(principal, job_id, "operator", idempotency_key, expected_version, "job.cancel_requested", {}, action)

    def retry(self, principal, job_id, expected_version, idempotency_key):
        def action(session, job, actor):
            if job.state != "FAILED":
                raise Error(409, "job_retry_requires_failed")
            if job.deadline_at and utc(job.deadline_at) <= self.now():
                raise Error(409, "job_deadline_expired")
            if job.cleanup_status == "purge_pending":
                raise Error(409, "job_purge_pending")
            if job.cleanup_status in {"expiry_pending", "expired"} or (job.artifacts_expire_at and utc(job.artifacts_expire_at) <= self.now()):
                raise Error(409, "job_artifacts_expired")
            job.state = "RECONCILING"
            job.phase = "retry_pending"
            job.queue_reason = None
            self._outbox(session, job, "prepare_retry", actor, {"next_attempt": job.current_attempt + 1})
        return self._command(principal, job_id, "operator", idempotency_key, expected_version, "job.retry_requested", {}, action)

    def reconcile(self, principal, job_id, expected_version, idempotency_key, evidence):
        if (not isinstance(evidence, dict) or set(evidence) != {"publication_id", "outcome", "evidence_ref"} or
                evidence.get("outcome") not in {"published", "not_published"} or
                any(not isinstance(evidence.get(k), str) or not evidence[k] or len(evidence[k]) > 256
                    for k in ("publication_id", "evidence_ref"))):
            raise Error(422, "reconciliation_evidence_required")
        def action(session, job, actor):
            if job.state != "NEEDS_ATTENTION":
                raise Error(409, "job_reconcile_requires_attention")
            job.state = "RECONCILING"
            job.phase = "verifying_evidence"
            self._outbox(session, job, "reconcile", actor, {"evidence": evidence})
            self._emit(session, job, "reconciliation.evidence_submitted", actor, evidence)
        return self._command(principal, job_id, "operator", idempotency_key, expected_version, "job.reconcile_requested",
                             {"evidence": evidence}, action)

    def purge(self, principal, job_id, expected_version, idempotency_key):
        def action(session, job, actor):
            if job.state not in TERMINAL_STATES:
                raise Error(409, "job_purge_requires_terminal")
            active = session.scalar(select(func.count()).select_from(models.Allocation).where(
                models.Allocation.job_id == job.id, models.Allocation.released_at.is_(None)))
            running = session.scalar(select(func.count()).select_from(models.Attempt).where(
                models.Attempt.job_id == job.id, models.Attempt.state.in_({"PROVISIONING", "STARTING", "RUNNING", "RECONCILING", "CANCELLING"})))
            if active or running:
                raise Error(409, "job_runtime_not_confirmed_stopped")
            if job.cleanup_status != "purge_pending":
                job.cleanup_status = "purge_pending"
                self._outbox(session, job, "purge", actor, {"preserve_audit": True, "confirm_before_release": True})
        return self._command(principal, job_id, "admin", idempotency_key, expected_version, "job.purge_requested", {}, action)

    def list_members(self, principal, job_id):
        with self.transaction(principal, job_id) as (session, _, __):
            members = session.scalars(select(models.Membership).where(models.Membership.job_id == job_id).order_by(models.Membership.principal_id)).all()
            return {"items": [{"principal_id": m.principal_id, "role": m.role} for m in members]}

    def put_member(self, principal, job_id, member_id, role, expected_version, idempotency_key):
        member_id = validate_member_id(member_id)
        if role not in JOB_ROLES:
            raise Error(422, "invalid_job_role")
        def action(session, job, actor):
            member = session.get(models.Membership, (job.id, member_id))
            if member and member.role == "admin" and role != "admin":
                self._preserve_admin(session, job.id)
            if member:
                member.role = role
            else:
                session.add(models.Membership(job_id=job.id, principal_id=member_id, role=role))
            self._emit(session, job, "membership.granted", actor, {"principal_id": member_id, "role": role})
        return self._command(principal, job_id, "admin", idempotency_key, expected_version, "job.membership_updated",
                             {"principal_id": member_id, "role": role}, action, allow_purged=True)

    def delete_member(self, principal, job_id, member_id, expected_version, idempotency_key):
        member_id = validate_member_id(member_id)
        def action(session, job, actor):
            member = session.get(models.Membership, (job.id, member_id))
            if member:
                if member.role == "admin":
                    self._preserve_admin(session, job.id)
                session.delete(member)
                self._emit(session, job, "membership.revoked", actor, {"principal_id": member_id})
        return self._command(principal, job_id, "admin", idempotency_key, expected_version, "job.membership_deleted",
                             {"principal_id": member_id}, action, allow_purged=True)

    @staticmethod
    def _preserve_admin(session, job_id):
        count = session.scalar(select(func.count()).select_from(models.Membership).where(
            models.Membership.job_id == job_id, models.Membership.role == "admin"))
        if count <= 1:
            raise Error(409, "last_job_admin_required")


    def list_attempts(self, principal, job_id):
        with self.transaction(principal, job_id) as (session, job, __):
            rows = session.scalars(select(models.Attempt).where(models.Attempt.job_id == job_id).order_by(models.Attempt.number)).all()
            return {"items": [{"id": row.id, "number": row.number, "epoch": row.epoch, "state": row.state,
                "started_at": iso(row.started_at), "ended_at": iso(row.ended_at), "created_at": iso(row.created_at),
                "heartbeat_at": iso(row.heartbeat_at), "error_code": row.error_code,
                "revocation_confirmed": row.revocation_confirmed,
                "termination_confirmed": row.termination_confirmed,
                "publication_status": row.publication_status, "resources": row.resources_json,
                "components": self._attempt_components(job, row)} for row in rows]}

    def list_events(self, principal, job_id, limit=100, cursor=None):
        actor = principal_id(principal)
        limit = page_limit(limit)
        with self.transaction(principal, job_id) as (session, _, __):
            position = self.cursors.decode(cursor, actor, "events", {"job_id": job_id}, self.now().timestamp()) if cursor else 0
            if type(position) is not int or position < 0:
                raise Error(422, "invalid_cursor")
            rows = session.scalars(select(models.Event).where(models.Event.job_id == job_id,
                models.Event.sequence > position).order_by(models.Event.sequence).limit(limit + 1)).all()
            items = [{"id": row.id, "kind": row.kind, "actor_id": row.actor_id,
                      "data": row.data_json, "created_at": iso(row.created_at)} for row in rows[:limit]]
            next_cursor = self.cursors.encode(actor, "events", {"job_id": job_id}, rows[limit - 1].sequence,
                self.now().timestamp()) if len(rows) > limit else None
            return {"items": items, "next_cursor": next_cursor}

    def list_logs(self, principal, job_id, limit=100, cursor=None, component=None, attempt=None):
        actor = principal_id(principal)
        limit = page_limit(limit)
        if component is not None and (not isinstance(component, str) or not component or len(component) > 128):
            raise Error(422, "invalid_log_filter")
        if attempt is not None and (type(attempt) is not int or attempt < 1):
            raise Error(422, "invalid_log_filter")
        filters = {"job_id": job_id, "component": component, "attempt": attempt}
        with self.transaction(principal, job_id) as (session, job, __):
            position = self.cursors.decode(cursor, actor, "logs", filters, self.now().timestamp()) if cursor else None
            query = select(models.LogChunk).where(models.LogChunk.job_id == job_id)
            if component:
                query = query.where(models.LogChunk.component == component)
            if attempt:
                query = query.where(models.LogChunk.attempt_number == attempt)
            if position:
                try:
                    stamp = utc(datetime.fromisoformat(position["created_at"].replace("Z", "+00:00")))
                    identity = position["id"]
                    if set(position) != {"created_at", "id"} or not isinstance(identity, str):
                        raise ValueError()
                except (ValueError, TypeError, KeyError, AttributeError):
                    raise Error(422, "invalid_cursor") from None
                query = query.where(or_(models.LogChunk.created_at > stamp,
                    and_(models.LogChunk.created_at == stamp, models.LogChunk.id > identity)))
            rows = session.scalars(query.order_by(models.LogChunk.created_at, models.LogChunk.id).limit(limit + 1)).all()
            now = self.now()
            items, bytes_returned, last = [], 0, None
            for row in rows[:limit]:
                expired = bool(row.deleted_at or (row.expires_at and utc(row.expires_at) <= now) or
                    (job.artifacts_expire_at and utc(job.artifacts_expire_at) <= now) or job.purged_at)
                data = "" if expired else row.data
                encoded = data.encode("utf-8")
                if len(encoded) > 65536:
                    raise Error(503, "stored_log_exceeds_bound")
                if items and bytes_returned + len(encoded) > 1_048_576:
                    break
                items.append({"id": row.id, "component": row.component, "attempt_number": row.attempt_number,
                              "data": data, "expired": expired, "created_at": iso(row.created_at), "expires_at": iso(row.expires_at)})
                bytes_returned += len(encoded)
                last = row
            more = len(rows) > len(items)
            next_cursor = self.cursors.encode(actor, "logs", filters,
                {"created_at": iso(last.created_at), "id": last.id}, self.now().timestamp()) if more and last else None
            return {"items": items, "next_cursor": next_cursor, "bytes_returned": bytes_returned}

    def list_artifacts(self, principal, job_id, limit=100, cursor=None):
        actor = principal_id(principal)
        limit = page_limit(limit)
        filters = {"job_id": job_id}
        with self.transaction(principal, job_id) as (session, job, __):
            position = self.cursors.decode(cursor, actor, "artifacts", filters, self.now().timestamp()) if cursor else None
            query = select(models.Artifact).where(models.Artifact.job_id == job_id)
            if position is not None:
                try:
                    stamp = utc(datetime.fromisoformat(position["created_at"].replace("Z", "+00:00")))
                    identity = position["id"]
                    if set(position) != {"created_at", "id"} or not isinstance(identity, str):
                        raise ValueError()
                except (TypeError, ValueError, KeyError, AttributeError):
                    raise Error(422, "invalid_cursor") from None
                query = query.where(or_(models.Artifact.created_at > stamp,
                    and_(models.Artifact.created_at == stamp, models.Artifact.id > identity)))
            rows = session.scalars(query.order_by(models.Artifact.created_at, models.Artifact.id).limit(limit + 1)).all()
            next_cursor = None
            if len(rows) > limit:
                last = rows[limit - 1]
                next_cursor = self.cursors.encode(actor, "artifacts", filters,
                    {"created_at": iso(last.created_at), "id": last.id}, self.now().timestamp())
            return {"items": [self._artifact_view(job, row) for row in rows[:limit]], "next_cursor": next_cursor}

    def get_artifact(self, principal, job_id, artifact_id):
        with self.transaction(principal, job_id) as (session, job, __):
            row = session.scalar(select(models.Artifact).where(models.Artifact.id == artifact_id, models.Artifact.job_id == job_id))
            if row is None:
                raise Error(404, "artifact_not_found")
            return self._artifact_view(job, row)

    def _artifact_view(self, job, artifact):
        value = artifact_view(artifact, self.now())
        locator = getattr(artifact, "locator_json", None)
        if artifact.kind == "source" and isinstance(locator, dict) and locator.get("kind") == "local":
            path = locator.get("relative_path")
            if (isinstance(path, str) and path and len(path) <= 1024 and not path.startswith("/") and
                    "\\" not in path and "\x00" not in path and all(part not in {"", ".", ".."} for part in path.split("/"))):
                value["source_path"] = path
        if job.purged_at or (job.artifacts_expire_at and utc(job.artifacts_expire_at) <= self.now()):
            value["download_available"] = False
            if value["state"] != "deleted":
                value["state"] = "expired"
        return value

    def artifact_storage(self, principal, job_id, artifact_id):
        """For the trusted download broker only; never expose this as JSON."""
        with self.transaction(principal, job_id) as (session, job, __):
            row = session.scalar(select(models.Artifact).where(models.Artifact.id == artifact_id, models.Artifact.job_id == job_id))
            if row is None:
                raise Error(404, "artifact_not_found")
            view = self._artifact_view(job, row)
            if (job.purged_at or (job.artifacts_expire_at and utc(job.artifacts_expire_at) <= self.now()) or
                    not view["download_available"]):
                raise Error(410, "artifact_expired")
            locator = getattr(row, "locator_json", None)
            if not isinstance(locator, dict):
                raise Error(503, "artifact_locator_unavailable")
            kind = locator.get("kind")
            if kind == "exchange":
                if set(locator) != {"kind", "space_id", "record_id", "attachment_id"} or any(
                    not isinstance(locator[k], str) or not locator[k] or len(locator[k]) > 256
                    for k in ("space_id", "record_id", "attachment_id")):
                    raise Error(503, "invalid_artifact_locator")
                owned_space = session.scalar(select(models.ProvisioningResource).where(
                    models.ProvisioningResource.job_id == job_id, models.ProvisioningResource.kind == "exchange_space",
                    models.ProvisioningResource.external_id == locator["space_id"]))
                if (owned_space is None or owned_space.ownership_json.get("job_id") != job_id or
                        owned_space.state in {"deleted", "retired"}):
                    raise Error(503, "invalid_artifact_locator")
            elif kind == "local":
                if set(locator) != {"kind", "resource_id", "relative_path"}:
                    raise Error(503, "invalid_artifact_locator")
                path = locator["relative_path"]
                if (not isinstance(path, str) or not path or len(path) > 1024 or path.startswith("/") or
                    "\\" in path or "\x00" in path or any(part in {"", ".", ".."} for part in path.split("/"))):
                    raise Error(503, "invalid_artifact_locator")
                resource = session.get(models.ProvisioningResource, locator["resource_id"])
                if (resource is None or resource.job_id != job_id or resource.ownership_json.get("job_id") != job_id or
                        resource.state == "deleted" or resource.deleted_at is not None):
                    raise Error(503, "invalid_artifact_locator")
            else:
                raise Error(503, "invalid_artifact_locator")
            return {"locator": dict(locator), **view}

    artifact_download_descriptor = artifact_storage

    def visible_revision(self, principal):
        """A digest of only authorized content; foreign event gaps are invisible."""
        actor = principal_id(principal)
        with self.database.transaction(immediate=False) as session:
            events = select(models.Event.job_id.label("job_id"), func.max(models.Event.sequence).label("sequence"))\
                .join(models.Membership, and_(models.Membership.job_id == models.Event.job_id, models.Membership.principal_id == actor)).group_by(models.Event.job_id).subquery()
            logs = select(models.LogChunk.job_id.label("job_id"), func.max(models.LogChunk.created_at).label("created_at"))\
                .join(models.Membership, and_(models.Membership.job_id == models.LogChunk.job_id, models.Membership.principal_id == actor)).group_by(models.LogChunk.job_id).subquery()
            rows = session.execute(self._visible_query(actor).outerjoin(events, events.c.job_id == models.JobRecord.id)
                .outerjoin(logs, logs.c.job_id == models.JobRecord.id)
                .add_columns(events.c.sequence, logs.c.created_at).order_by(models.JobRecord.id)).all()
            values = [[job.id, job.version, member.role, sequence or 0, iso(log_date), iso(job.purged_at)]
                      for job, member, sequence, log_date in rows]
            return hashlib.sha256(canonical_json(values).encode()).hexdigest()

    def catalog(self, principal):
        actor = principal_id(principal)
        with self.database.transaction(immediate=False) as session:
            projects = session.scalars(select(models.Project).join(models.ProjectMember,
                and_(models.ProjectMember.project_id == models.Project.id, models.ProjectMember.principal_id == actor,
                     models.ProjectMember.role.in_({"submitter", "admin"}))).order_by(models.Project.id)).all()
            ids = [p.id for p in projects]
            sources = session.scalars(select(models.ApprovedSource).where(models.ApprovedSource.enabled.is_(True), models.ApprovedSource.status == "approved",
                or_(models.ApprovedSource.project_id.is_(None), models.ApprovedSource.project_id.in_(ids))).order_by(models.ApprovedSource.id)).all() if ids else []
            images = session.scalars(select(models.RuntimeImage).where(models.RuntimeImage.enabled.is_(True),
                models.RuntimeImage.approved.is_(True), models.RuntimeImage.status == "approved",
                or_(models.RuntimeImage.project_id.is_(None), models.RuntimeImage.project_id.in_(ids))).order_by(models.RuntimeImage.id)).all() if ids else []
            bindings = session.scalars(select(models.ParticipantBinding).where(models.ParticipantBinding.enabled.is_(True),
                models.ParticipantBinding.project_id.in_(ids)).order_by(models.ParticipantBinding.id)).all() if ids else []
            pools = session.scalars(select(models.Pool).order_by(models.Pool.id)).all() if ids else []
            return {"projects": [{"id": p.id, "name": p.name, "retention_days": p.retention_days} for p in projects],
                    "sources": [{"id": s.id, "name": s.name, "project_id": s.project_id, "allowed_commits": s.allowed_commits} for s in sources],
                    "runtime_images": [{"id": i.id, "name": i.name, "project_id": i.project_id, "digest": i.digest} for i in images],
                    "participant_bindings": [{"id": b.id, "project_id": b.project_id, "participant_id": b.participant_id,
                                              "dataset_label": b.dataset_label, "node_id": b.node_id} for b in bindings],
                    "pools": [{"id": p.id, "name": p.name, "sandbox_profiles": p.sandbox_profiles,
                               "gpu_profiles": p.gpu_profiles, "capacity": {"cpu_millicores": p.cpu_millicores,
                               "memory_bytes": p.memory_bytes, "disk_bytes": p.disk_bytes, "gpu_count": len(p.gpu_uuids)}} for p in pools]}

    def _platform(self, principal):
        if principal_id(principal) not in self.platform_operator_ids:
            raise Error(403, "platform_operator_required")

    @staticmethod
    def _pool_view(pool):
        return {name: getattr(pool, name) for name in ("id", "name", "node_id", "cpu_millicores", "memory_bytes",
                "disk_bytes", "gpu_uuids", "gpu_profiles", "sandbox_profiles", "healthy", "quarantined", "version")}

    def list_pools(self, principal):
        self._platform(principal)
        with self.database.transaction(immediate=False) as session:
            pools = session.scalars(select(models.Pool).order_by(models.Pool.id)).all()
            items = []
            for pool in pools:
                value = self._pool_view(pool)
                usage = session.execute(select(func.coalesce(func.sum(models.Allocation.cpu_millicores), 0),
                    func.coalesce(func.sum(models.Allocation.memory_bytes), 0), func.coalesce(func.sum(models.Allocation.disk_bytes), 0),
                    func.coalesce(func.sum(models.Allocation.gpu_count), 0)).where(models.Allocation.pool_id == pool.id,
                    models.Allocation.released_at.is_(None))).one()
                value["reserved"] = dict(zip(("cpu_millicores", "memory_bytes", "disk_bytes", "gpu_count"),
                    (RetentionService._whole_bytes(amount) for amount in usage)))
                value["disk_used_bytes"] = RetentionService.pool_used_bytes(session, pool.id)
                value["retained_disk_bytes"] = value["disk_used_bytes"] - value["reserved"]["disk_bytes"]
                items.append(value)
            return {"items": items}

    def put_pool(self, principal, pool_id, values):
        self._platform(principal)
        allowed = {"name", "node_id", "cpu_millicores", "memory_bytes", "disk_bytes", "gpu_uuids", "gpu_profiles",
                   "sandbox_profiles", "healthy", "quarantined", "expected_version"}
        if not isinstance(values, dict) or not values or set(values) - allowed:
            raise Error(422, "invalid_pool_fields")
        for key in ("cpu_millicores", "memory_bytes", "disk_bytes"):
            if key in values and (type(values[key]) is not int or not 0 <= values[key] <= (1 << 50)):
                raise Error(422, "invalid_pool_capacity")
        for key in ("healthy", "quarantined"):
            if key in values and type(values[key]) is not bool:
                raise Error(422, "invalid_pool_health")
        for key in ("gpu_uuids", "gpu_profiles", "sandbox_profiles"):
            if key in values and (not isinstance(values[key], list) or len(values[key]) > 1024 or
                any(not isinstance(v, str) or not v or len(v) > 128 for v in values[key]) or len(set(values[key])) != len(values[key])):
                raise Error(422, "invalid_pool_profiles")
        for key in ("name", "node_id"):
            if key in values and (not isinstance(values[key], str) or not values[key] or len(values[key]) > 200):
                raise Error(422, "invalid_pool_identity")
        with self.database.transaction(immediate=True) as session:
            pool = session.scalar(select(models.Pool).where(models.Pool.id == pool_id).with_for_update())
            if pool is not None and (pool.details_json or {}).get("manager_storage"):
                raise Error(409, "manager_storage_pool_requires_trusted_cli")
            if pool is not None and (pool.details_json or {}).get("object_store"):
                raise Error(409, "object_store_pool_requires_trusted_cli")
            before = self._pool_view(pool) if pool is not None else None
            if pool is None:
                if not values.get("name") or not values.get("node_id"):
                    raise Error(422, "pool_name_and_node_required")
                pool = models.Pool(id=pool_id, name=values["name"], node_id=values["node_id"], version=1,
                                   cpu_millicores=0, memory_bytes=0, disk_bytes=0, gpu_uuids=[], gpu_profiles=[],
                                   sandbox_profiles=[], healthy=False, quarantined=False)
                session.add(pool)
            elif values.get("expected_version") is not None and values["expected_version"] != pool.version:
                raise Error(409, "pool_version_conflict")
            proposed = {**self._pool_view(pool), **{key: value for key, value in values.items() if key != "expected_version"}}
            expands = (any(proposed[key] > getattr(pool, key) for key in ("cpu_millicores", "memory_bytes", "disk_bytes")) or
                       any(set(proposed[key]) - set(getattr(pool, key)) for key in ("gpu_uuids", "gpu_profiles", "sandbox_profiles")) or
                       proposed["node_id"] != pool.node_id)
            allocations = session.scalars(select(models.Allocation).where(models.Allocation.pool_id == pool_id,
                models.Allocation.released_at.is_(None)).with_for_update()).all()
            for key in ("cpu_millicores", "memory_bytes", "disk_bytes"):
                if key in values and values[key] < sum(getattr(a, key) for a in allocations):
                    raise Error(409, "pool_capacity_below_reserved")
            if "disk_bytes" in values and values["disk_bytes"] < RetentionService.pool_used_bytes(session, pool_id):
                raise Error(409, "pool_capacity_below_retained_storage")
            if allocations and "node_id" in values and values["node_id"] != pool.node_id:
                raise Error(409, "pool_node_has_active_allocations")
            if "gpu_uuids" in values:
                active = set(session.scalars(select(models.GpuAllocation.gpu_uuid).where(
                    models.GpuAllocation.pool_id == pool_id, models.GpuAllocation.released_at.is_(None))))
                if not active.issubset(values["gpu_uuids"]):
                    raise Error(409, "pool_gpu_has_active_allocation")
            if proposed["healthy"] and (expands or not pool.healthy):
                if self.pool_qualifier is None:
                    raise Error(409, "pool_qualification_required")
                if self.pool_qualifier(proposed) is False:
                    raise Error(409, "pool_qualification_required")
            for key, value in values.items():
                if key != "expected_version":
                    setattr(pool, key, value)
            pool.updated_at = self.now()
            pool.version += 1
            session.flush()
            from .admin_audit import record_admin_audit
            record_admin_audit(session, actor_id=principal_id(principal),
                operation="pool.create" if before is None else "pool.update", resource_type="pool",
                resource_id=pool.id, before=before, after=self._pool_view(pool))
            return self._pool_view(pool)
