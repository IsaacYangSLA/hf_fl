"""Approved external-node enrollment and fenced, private participant assignments.

External participants consume their node's local capacity, never a manager pool.
All code/dataset/runtime choices are fixed by immutable job and node approvals.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import math
from dataclasses import dataclass, field
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from typing import Mapping

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from starlette.requests import Request

from . import models
from .authorization import principal_id
from .broker import stable_workload_subject, stable_workload_principal
from .collection import SafeCollector, CollectionError
from .domain import Error, JobSpec, canonical_json, validate_identifier
from .resources import ResourceLedger, ResourceError, stable_key, private_root
from .workflow import DatasetBinding, RuntimeConfig

ACTIVE_STATES = frozenset({"PROVISIONING", "STARTING", "RUNNING"})
CONTROL_STATES = ACTIVE_STATES | {"CANCELLING", "RECONCILING", "NEEDS_ATTENTION", "CANCELLED", "FAILED", "SUCCEEDED"}


def _publication_path(path):
    import re
    return isinstance(path, str) and (path in {"progress.json", "listener/state.json"} or
        re.fullmatch(r"listener/jobs/[a-f0-9]{64}/work/(?:client-publication-intent\.json|trained_model\.exchange-upload\.json|trained_model/fedavg_submission\.json)", path) is not None)


def _thumbprint(value):
    try:
        if not isinstance(value, str) or len(value) != 43:
            raise ValueError()
        raw = base64.urlsafe_b64decode(value + "=")
        if len(raw) != 32 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != value:
            raise ValueError()
    except (ValueError, TypeError):
        raise Error(422, "invalid_execution_certificate") from None
    return value


@dataclass(frozen=True)
class ApprovedExternalNode:
    node_id: str
    certificate_thumbprint: str
    dataset_bindings: Mapping[str, DatasetBinding | dict]
    resources: Mapping[str, int] = field(default_factory=lambda: {
        "cpu_millicores": 1000, "memory_bytes": 1024**3, "disk_bytes": 1024**3})
    enabled: bool = True

    def __post_init__(self):
        validate_identifier(self.node_id)
        _thumbprint(self.certificate_thumbprint)
        if not isinstance(self.dataset_bindings, Mapping) or not self.dataset_bindings:
            raise ValueError("External nodes require locally approved dataset bindings")
        approved = {}
        for key, value in self.dataset_bindings.items():
            validate_identifier(key)
            approved[key] = value if isinstance(value, DatasetBinding) else DatasetBinding.model_validate(value)
        object.__setattr__(self, "dataset_bindings", approved)
        if set(self.resources) != {"cpu_millicores", "memory_bytes", "disk_bytes"} or any(
                type(value) is not int or not 1 <= value <= 1 << 50 for value in self.resources.values()):
            raise ValueError("External resource limits must be fixed positive node approvals")
        object.__setattr__(self, "resources", dict(self.resources))
        if type(self.enabled) is not bool:
            raise ValueError("External node enabled must be a Boolean")


@dataclass
class ExternalSourceFile:
    content: io.BytesIO
    size_bytes: int
    sha256: str

    def chunks(self):
        try:
            while chunk := self.content.read(65536):
                yield chunk
        finally:
            self.close()

    def close(self):
        self.content.close()


class ExternalParticipantService:
    def __init__(self, manager, provisioner, broker, approved_nodes, *, node_dispatch=None, certificate_issuer=None):
        self.manager, self.database = manager, manager.database
        self.provisioner, self.broker = provisioner, broker
        self.nodes = {node.node_id: node for node in approved_nodes.values()} if isinstance(approved_nodes, Mapping) else {
            node.node_id: node for node in approved_nodes}
        self.node_dispatch = node_dispatch
        self.certificate_issuer = certificate_issuer
        self.ledger = ResourceLedger(self.database)
        import threading
        self._dispatch_lock = threading.RLock()
        self._dispatch_pool = None
        self._dispatch_futures = {}

    @staticmethod
    def component_id(participant_id):
        return "participant-" + stable_key(validate_identifier(participant_id))[:40]

    def _approved(self, session, job, participant_id, node_id, *, require_enabled=True):
        spec = JobSpec.model_validate(job.spec_json)
        participant = next((item for item in spec.participants if item.participant_id == participant_id), None)
        if participant is None or participant.mode != "external":
            raise Error(404, "participant_not_found")
        binding = session.get(models.ParticipantBinding, participant.dataset_binding)
        node = self.nodes.get(node_id)
        if (binding is None or (require_enabled and not binding.enabled) or binding.project_id != job.project_id
                or binding.participant_id != participant_id or not binding.node_id or binding.node_id != node_id
                or node is None or (require_enabled and not node.enabled) or participant.dataset_binding not in node.dataset_bindings):
            raise Error(403, "external_node_not_approved")
        return spec, participant, node

    def _current_attempt(self, session, job):
        return session.scalar(select(models.Attempt).where(models.Attempt.job_id == job.id,
            models.Attempt.number == job.current_attempt, models.Attempt.epoch == job.epoch))

    @staticmethod
    def _view(resource, job):
        data = resource.details_json
        return {"id": resource.id, "job_id": job.id, "participant_id": data["participant_id"],
                "node_id": data["node_id"], "dataset_binding": data["dataset_binding"],
                "component_id": resource.component_id, "status": data.get("status", "enrolled"),
                "attempt_id": resource.attempt_id, "epoch": data.get("epoch"), "version": job.version,
                "external": True, "manager_allocation": False}

    def enroll(self, principal, job_id, participant_id, node_id, expected_version, key):
        validate_identifier(participant_id); validate_identifier(node_id)
        with self.manager.transaction(principal, job_id, "operator", write=True) as (session, job, member):
            spec, participant, node = self._approved(session, job, participant_id, node_id)
            actor = principal_id(principal)
            body = {"participant_id": participant_id, "node_id": node_id}
            scope = "external.enroll:" + job_id
            def action():
                self.manager._version(job, expected_version)
                if job.state not in ACTIVE_STATES | {"QUEUED"} or (job.deadline_at and self.manager.now() >= job.deadline_at):
                    raise Error(409, "job_not_enrollable")
                identity = stable_key("external-enrollment", job.id, participant_id)[:32]
                resource = session.get(models.ProvisioningResource, identity)
                if resource is not None:
                    if (resource.details_json["node_id"] != node_id
                            or resource.details_json["node_certificate_thumbprint"] != node.certificate_thumbprint):
                        raise Error(409, "external_node_binding_immutable")
                    return self._view(resource, job)
                resource = models.ProvisioningResource(id=identity, job_id=job.id,
                    component_id=self.component_id(participant_id), kind="external_enrollment",
                    external_id=job.id + ":" + participant_id, state="ready", retained=True,
                    ownership_json={"job_id": job.id, "participant_id": participant_id,
                                    "component_id": self.component_id(participant_id)},
                    details_json={"participant_id": participant_id, "node_id": node_id,
                                  "node_certificate_thumbprint": node.certificate_thumbprint,
                                  "dataset_binding": participant.dataset_binding, "spec_digest": spec.digest,
                                  "status": "enrolled", "termination_confirmed": True})
                session.add(resource)
                job.version += 1; job.updated_at = self.manager.now()
                self.manager._emit(session, job, "participant.enrolled", actor, {
                    "participant_id": participant_id, "node_id": node_id})
                session.flush()
                return self._view(resource, job)
            return self.manager._once(session, actor, scope, key, body, action,
                                      replay=lambda ignored: self._view(session.get(models.ProvisioningResource,
                                          stable_key("external-enrollment", job.id, participant_id)[:32]), job))

    def get_enrollment(self, principal, job_id, participant_id):
        with self.manager.transaction(principal, job_id) as (session, job, member):
            resource = session.get(models.ProvisioningResource,
                                   stable_key("external-enrollment", job_id, participant_id)[:32])
            if resource is None:
                raise Error(404, "participant_enrollment_not_found")
            return self._view(resource, job)

    def _node_record(self, session, actor, *, active=False, write=False):
        query = select(models.Job).where(models.Job.id == getattr(actor, "job_id", ""))
        if write:
            query = query.with_for_update().execution_options(populate_existing=True)
        job = session.scalar(query)
        resource_query = select(models.ProvisioningResource).where(
            models.ProvisioningResource.id == getattr(actor, "grant_id", ""))
        if write:
            # Refresh only after the job writer lock: a blocked callback must not
            # overwrite the stop receipt or other fields with an earlier snapshot.
            resource_query = resource_query.with_for_update().execution_options(populate_existing=True)
        resource = session.scalar(resource_query)
        attempt = session.get(models.Attempt, getattr(actor, "attempt_id", ""))
        if (resource is None or job is None or attempt is None or resource.kind != "external_enrollment"
                or resource.job_id != job.id or attempt.job_id != job.id or job.current_attempt != attempt.number
                or job.epoch != attempt.epoch or attempt.epoch != getattr(actor, "epoch", None)
                or resource.attempt_id != attempt.id or resource.component_id != getattr(actor, "component_id", None)
                or getattr(actor, "pool_id", None) != "external" or resource.state != "ready"
                or job.state not in (ACTIVE_STATES if active else CONTROL_STATES)):
            raise Error(404, "participant_assignment_not_found")
        data = resource.details_json
        if active and (data.get("status") == "stopped" or data.get("stop_requested") is True):
            raise Error(404, "participant_assignment_not_found")
        spec, participant, node = self._approved(session, job, data["participant_id"], data["node_id"],
                                                 require_enabled=active)
        if (getattr(actor, "node_id", None) != node.node_id
                or getattr(actor, "certificate_thumbprint", None) != node.certificate_thumbprint
                or data["node_certificate_thumbprint"] != node.certificate_thumbprint
                or data["spec_digest"] != spec.digest
                or (job.deadline_at is not None and active and self.manager.now() >= job.deadline_at)):
            raise Error(404, "participant_assignment_not_found")
        return resource, job, attempt, spec, participant, node

    def _cleanup(self):
        from .participant_cleanup import ExternalCleanup
        return ExternalCleanup(self)

    def purge_job(self, job):
        return self._cleanup().purge_job(job)

    def purge_plan(self, actor):
        return self._cleanup().purge_plan(actor)

    def confirm_purged(self, actor, *, confirmed=True):
        return self._cleanup().confirm_purged(actor, confirmed=confirmed)

    def check_node_grant(self, actor):
        if "purge" in getattr(actor, "scopes", ()):
            return self._cleanup().check_node_grant(actor)
        try:
            with self.database.transaction(immediate=False) as session:
                self._node_record(session, actor)
            return True
        except (Error, ValueError):
            return False

    def source_access_valid(self, actor):
        try:
            if "assignment" not in getattr(actor, "scopes", ()):
                return False
            with self.database.transaction(immediate=False) as session:
                self._node_record(session, actor, active=True)
            return True
        except (Error, ValueError):
            return False

    def _log_budget(self, session, job, attempt, component_id, spec):
        """Only link the manager storage cap already charged by gang admission."""
        external_id = "hf2l-log://" + job.id + "/" + str(attempt.number) + "/" + component_id
        budget = session.scalar(select(models.ProvisioningResource).where(
            models.ProvisioningResource.job_id == job.id,
            models.ProvisioningResource.kind == "log_budget",
            models.ProvisioningResource.external_id == external_id).with_for_update())
        maximum = 1024**2
        storage_pool_id = (getattr(self.provisioner, "storage_pool_id", None) or
                           next(component.resources.pool_id for component in spec.components if component.role == "owner"))
        if budget is None:
            raise Error(409, "participant_log_budget_unavailable")
        details = budget.details_json or {}
        if (budget.attempt_id != attempt.id or budget.component_id != component_id
                or budget.state not in {"planned", "ready"} or budget.deleted_at is not None
                or budget.ownership_json != {"job_id": job.id, "component_id": component_id, "kind": "log_budget"}
                or details.get("spec_digest") != spec.digest
                or details.get("component_id") != component_id or details.get("attempt_number") != attempt.number
                or details.get("reservation_max_bytes") != maximum
                or details.get("retention_reservation_bytes") != maximum
                or details.get("retention_charged_bytes") != maximum
                or details.get("retention_charge_released") is not False
                or budget.retained is not True or budget.size_bytes != maximum
                or details.get("pool_id") != storage_pool_id):
            raise Error(409, "participant_log_budget_unavailable")
        pool = session.get(models.Pool, details["pool_id"])
        if pool is None:
            raise Error(409, "participant_log_budget_unavailable")
        return budget

    def bootstrap_credentials(self, enrollment_id):
        """Trusted dispatcher only; public enrollment responses contain no tokens."""
        with self.database.transaction() as session:
            job_id = session.scalar(select(models.ProvisioningResource.job_id).where(
                models.ProvisioningResource.id == enrollment_id))
            job = session.scalar(select(models.Job).where(models.Job.id == job_id)
                .with_for_update().execution_options(populate_existing=True)) if job_id else None
            resource = session.scalar(select(models.ProvisioningResource).where(
                models.ProvisioningResource.id == enrollment_id).with_for_update()
                .execution_options(populate_existing=True))
            if resource is None or resource.kind != "external_enrollment" or job is None:
                raise Error(404, "participant_enrollment_not_found")
            spec, participant, node = self._approved(session, job, resource.details_json["participant_id"],
                                                     resource.details_json["node_id"], require_enabled=False)
            if resource.details_json["node_certificate_thumbprint"] != node.certificate_thumbprint:
                raise Error(403, "external_node_binding_immutable")
            participant_binding = session.get(models.ParticipantBinding, participant.dataset_binding)
            attempt = self._current_attempt(session, job)
            if attempt is None or job.state not in CONTROL_STATES:
                raise Error(409, "participant_assignment_not_ready")
            data = dict(resource.details_json)
            if resource.attempt_id != attempt.id:
                if not data.get("termination_confirmed"):
                    raise Error(409, "previous_participant_termination_unconfirmed")
                if resource.attempt_id is not None:
                    previous = session.get(models.Attempt, resource.attempt_id)
                    if previous is None or not previous.revocation_confirmed:
                        raise Error(409, "previous_participant_revocation_unconfirmed")
                data.update({"status": "enrolled", "epoch": attempt.epoch, "termination_confirmed": True})
                for name in ("execution_certificate_thumbprint", "proxy_id", "workload_grant", "last_heartbeat", "grant_expires_at", "external_execution_id", "stop_requested",
                             "issued_certificate_thumbprint", "issued_certificate_csr_hash"):
                    data.pop(name, None)
                resource.attempt_id = attempt.id
                resource.details_json = dict(data)
            scopes = (["assignment", "heartbeat", "stopped", "logs", "collect"]
                      if (job.state in ACTIVE_STATES and node.enabled and participant_binding.enabled
                          and data.get("status") != "stopped" and not data.get("stop_requested")) else ["stopped", "logs", "collect"])
            if "assignment" in scopes:
                from .executor import ExecutionIdentity
                log_budget = self._log_budget(session, job, attempt, resource.component_id, spec)
                execution = ExecutionIdentity(job.id, attempt.id, resource.component_id, attempt.epoch)
                execution_id = stable_key("external-execution", execution.key)[:32]
                record = session.get(models.ProvisioningResource, execution_id)
                if record is None:
                    record = models.ProvisioningResource(id=execution_id, job_id=job.id,
                        attempt_id=attempt.id, component_id=resource.component_id, kind="external_execution",
                        external_id=execution.key, state="ready", retained=True,
                        ownership_json={"job_id": job.id, "attempt_id": attempt.id,
                                        "component_id": resource.component_id},
                        details_json={"node_id": node.node_id, "node_certificate_thumbprint": node.certificate_thumbprint,
                            "participant_id": participant.participant_id, "dataset_binding": participant.dataset_binding,
                            "spec_digest": spec.digest, "epoch": attempt.epoch, "termination_confirmed": False})
                    session.add(record)
                else:
                    recorded = record.details_json
                    if (record.job_id != job.id or record.attempt_id != attempt.id
                            or recorded.get("node_id") != node.node_id
                            or recorded.get("node_certificate_thumbprint") != node.certificate_thumbprint
                            or recorded.get("log_resource_id") not in {None, log_budget.id}):
                        raise Error(409, "external_execution_binding_immutable")
                record.details_json = {**record.details_json, "log_resource_id": log_budget.id}
                data["log_resource_id"] = log_budget.id
                data["external_execution_id"] = execution_id
                # From this point a dispatched node may reserve local capacity.
                # Cancellation must receive an explicit node proof even if the
                # assignment/grant response has not reached the manager yet.
                data["termination_confirmed"] = False
                if data.get("status") == "enrolled":
                    data["status"] = "dispatching"
                resource.details_json = dict(data)
            token = self.broker.issue_node(node_id=node.node_id, pool_id="external", job_id=job.id,
                attempt_id=attempt.id, component_id=resource.component_id, grant_id=resource.id,
                epoch=attempt.epoch, certificate_thumbprint=node.certificate_thumbprint, scopes=scopes)
            return {"enrollment": self._view(resource, job), "node_token": token,
                    "node_certificate_thumbprint": node.certificate_thumbprint,
                    "operation": "start" if "assignment" in scopes else "stop"}

    def enable_async_dispatch(self):
        """Keep slow or unreachable external nodes outside the controller tick."""
        from concurrent.futures import ThreadPoolExecutor
        with self._dispatch_lock:
            if self._dispatch_pool is None:
                self._dispatch_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="participant-dispatch")

    def _dispatch_one(self, identity):
        try:
            document = self.bootstrap_credentials(identity)
            self.node_dispatch(document["enrollment"]["node_id"], document)
        except Error as error:
            if error.status == 409:
                return False
            code = error.code
        except Exception:
            code = "external_node_dispatch_failed"
        else:
            with self.database.transaction() as session:
                job_id = session.scalar(select(models.ProvisioningResource.job_id).where(
                    models.ProvisioningResource.id == identity))
                job = session.scalar(select(models.Job).where(models.Job.id == job_id)
                    .with_for_update().execution_options(populate_existing=True)) if job_id else None
                if job is not None:
                    row = session.scalar(select(models.ProvisioningResource).where(
                        models.ProvisioningResource.id == identity).with_for_update()
                        .execution_options(populate_existing=True))
                    if row is not None and row.job_id == job.id:
                        data = dict(row.details_json)
                        data.pop("last_dispatch_error", None); data.pop("dispatch_retry_at", None)
                        row.details_json = data
            return True
        with self.database.transaction() as session:
            job_id = session.scalar(select(models.ProvisioningResource.job_id).where(
                models.ProvisioningResource.id == identity))
            job = session.scalar(select(models.Job).where(models.Job.id == job_id)
                .with_for_update().execution_options(populate_existing=True)) if job_id else None
            if job is not None:
                row = session.scalar(select(models.ProvisioningResource).where(
                    models.ProvisioningResource.id == identity).with_for_update()
                    .execution_options(populate_existing=True))
                if row is None or row.job_id != job.id:
                    return False
                data = dict(row.details_json)
                changed = data.get("last_dispatch_error") != code
                data.update({"last_dispatch_error": code,
                             "dispatch_retry_at": self.manager.now().timestamp() + 30})
                row.details_json = data
                if changed:
                    self.manager._emit(session, job, "participant.attention", "external-dispatch",
                        {"participant_id": data["participant_id"], "node_id": data["node_id"], "code": code})
        return False

    def dispatch_pending(self):
        """Isolate each node failure; stopped historical jobs need no dispatch."""
        if self.node_dispatch is None:
            raise Error(503, "external_node_dispatch_unavailable")
        with self.database.transaction(immediate=False) as session:
            ids = []
            for row in session.scalars(select(models.ProvisioningResource).where(
                    models.ProvisioningResource.kind == "external_enrollment",
                    models.ProvisioningResource.state == "ready")):
                job = session.get(models.Job, row.job_id)
                data = row.details_json
                if job is None or job.state not in CONTROL_STATES:
                    continue
                if data.get("termination_confirmed") is True and (
                        job.state not in ACTIVE_STATES or data.get("status") == "stopped"):
                    continue
                if data.get("dispatch_retry_at", 0) > self.manager.now().timestamp():
                    continue
                ids.append(row.id)
        if self._dispatch_pool is None:
            return {"dispatched": sum(self._dispatch_one(identity) for identity in ids)}
        submitted = 0
        with self._dispatch_lock:
            for identity, future in tuple(self._dispatch_futures.items()):
                if future.done():
                    future.result()
                    del self._dispatch_futures[identity]
            for identity in ids:
                if identity in self._dispatch_futures or len(self._dispatch_futures) >= 8:
                    continue
                self._dispatch_futures[identity] = self._dispatch_pool.submit(self._dispatch_one, identity)
                submitted += 1
        return {"dispatched": submitted}

    def close(self):
        pool = self._dispatch_pool
        if pool is not None:
            pool.shutdown(wait=True, cancel_futures=True)
        if hasattr(self.node_dispatch, "close"):
            self.node_dispatch.close()

    def attempt_termination_confirmed(self, job_id, attempt_id):
        with self.database.transaction(immediate=False) as session:
            rows = list(session.scalars(select(models.ProvisioningResource).where(
                models.ProvisioningResource.job_id == job_id,
                models.ProvisioningResource.attempt_id == attempt_id,
                models.ProvisioningResource.kind == "external_enrollment")))
            return all(row.details_json.get("termination_confirmed") is True for row in rows)

    def request_stop(self, job, attempt):
        """Persist stop intent; keep the controller tick independent of the node."""
        with self.database.transaction() as session:
            locked = session.scalar(select(models.Job).where(models.Job.id == job.id).with_for_update())
            if locked is None:
                raise Error(404, "job_not_found")
            ids = []
            rows = list(session.scalars(select(models.ProvisioningResource).where(
                models.ProvisioningResource.job_id == job.id,
                models.ProvisioningResource.attempt_id == attempt.id,
                models.ProvisioningResource.kind == "external_enrollment")))
            for resource in rows:
                resource.details_json = {**resource.details_json, "stop_requested": True}
                if resource.details_json.get("termination_confirmed") is not True:
                    ids.append(resource.id)
        if not ids:
            return True
        if self.node_dispatch is None:
            return False
        if self._dispatch_pool is not None:
            self.dispatch_pending()
        else:
            for identity in ids:
                self._dispatch_one(identity)
        return self.attempt_termination_confirmed(job.id, attempt.id)

    def _snapshot(self, job, spec):
        import json
        root = Path(self.provisioner.root) / job.id
        try:
            with SafeCollector(root, max_file_bytes=16 * 1024**2) as reader:
                document = json.loads(reader.read(".source.json"))
        except (CollectionError, OSError, ValueError):
            raise Error(409, "participant_source_unavailable") from None
        if document.get("source_id") != spec.source_id or document.get("commit") != spec.source_commit:
            raise Error(409, "participant_source_mismatch")
        manifest = document.get("manifest")
        if not isinstance(manifest, dict) or not manifest:
            raise Error(409, "participant_source_unavailable")
        return root / "source", manifest

    def control_plan(self, actor):
        """Authorize a stop before the node touches a local execution."""
        if "stopped" not in getattr(actor, "scopes", ()):
            raise Error(403, "node_scope_required")
        with self.database.transaction(immediate=False) as session:
            resource, job, attempt, spec, participant, node = self._node_record(session, actor)
            return {"identity": {"job_id": job.id, "attempt_id": attempt.id,
                                "component_id": actor.component_id, "epoch": attempt.epoch},
                    "node_id": node.node_id, "status": resource.details_json.get("status"),
                    "termination_confirmed": resource.details_json.get("termination_confirmed") is True,
                    "revocation_confirmed": attempt.revocation_confirmed is True}

    def append_logs(self, actor, receipt):
        if "logs" not in getattr(actor, "scopes", ()):
            raise Error(403, "node_scope_required")
        with self.database.transaction(immediate=False) as session:
            resource, job, attempt, spec, participant, node = self._node_record(session, actor)
            historical_id = resource.details_json.get("external_execution_id")
            if not historical_id:
                raise Error(409, "external_execution_binding_immutable")
        from .executor import ExecutionIdentity
        from .log_stream import append_external_logs
        from .executor import ExecutorRefused
        try:
            return append_external_logs(self.database,
                ExecutionIdentity(job.id, attempt.id, resource.component_id, attempt.epoch), receipt,
                resource_id=historical_id, node_id=node.node_id, clock=self.manager.now)
        except ExecutorRefused as error:
            if error.code == "invalid_log_receipt":
                raise Error(422, "invalid_log_receipt") from None
            raise Error(503, "participant_log_stream_unavailable") from None

    def read_publication_state(self, identity, relative_path, max_bytes=1024**2):
        """Read only exact retained publication metadata after stop and revocation."""
        if not _publication_path(relative_path) or type(max_bytes) is not int or not 1 <= max_bytes <= 1024**2:
            raise Error(422, "invalid_publication_state_request")
        with self.database.transaction(immediate=False) as session:
            row = session.scalar(select(models.ProvisioningResource).where(
                models.ProvisioningResource.kind == "external_enrollment",
                models.ProvisioningResource.job_id == identity.job_id,
                models.ProvisioningResource.attempt_id == identity.attempt_id,
                models.ProvisioningResource.component_id == identity.component_id))
            if row is None or row.details_json.get("termination_confirmed") is not True:
                raise Error(409, "participant_termination_unconfirmed")
            enrollment_id = row.id
        document = self.bootstrap_credentials(enrollment_id)
        actor = self.broker.authenticate_node("Bearer " + document["node_token"],
            verified_peer_thumbprint=document["node_certificate_thumbprint"],
            grant_validator=self.check_node_grant)
        if (actor.job_id, actor.attempt_id, actor.component_id, actor.epoch) != (
                identity.job_id, identity.attempt_id, identity.component_id, identity.epoch):
            raise Error(409, "participant_publication_identity_mismatch")
        control = self.control_plan(actor)
        if not control["termination_confirmed"] or not control["revocation_confirmed"]:
            raise Error(409, "participant_publication_fence_unconfirmed")
        document.update({"operation": "publication-state",
                         "state_request": {"path": relative_path, "max_bytes": max_bytes}})
        if self.node_dispatch is None:
            raise Error(503, "external_node_dispatch_unavailable")
        reader = getattr(self.node_dispatch, "read_state", self.node_dispatch)
        result = reader(actor.node_id, document)
        if not isinstance(result, dict) or type(result.get("exists")) is not bool:
            raise Error(502, "invalid_publication_state_receipt")
        if result.get("identity") != control["identity"]:
            raise Error(502, "invalid_publication_state_receipt")
        if not result["exists"]:
            return None
        try:
            content = base64.b64decode(result["content_base64"], validate=True)
        except (ValueError, TypeError, KeyError):
            raise Error(502, "invalid_publication_state_receipt") from None
        if len(content) > max_bytes or hashlib.sha256(content).hexdigest() != result.get("sha256"):
            raise Error(502, "invalid_publication_state_receipt")
        return content

    def heartbeat(self, actor, *, phase="running", current_round=None):
        if "heartbeat" not in getattr(actor, "scopes", ()):
            raise Error(403, "node_scope_required")
        if phase not in {"running", "waiting_initialization", "waiting_for_model", "training",
                         "publishing", "completed", "retry", "needs_attention", "stopped"}:
            raise Error(422, "invalid_participant_phase")
        if current_round is not None and (type(current_round) is not int or current_round < 0):
            raise Error(422, "invalid_participant_round")
        with self.database.transaction() as session:
            resource, job, attempt, spec, participant, node = self._node_record(session, actor, active=True, write=True)
            data = dict(resource.details_json)
            changed = data.get("phase") != phase or data.get("current_round") != current_round
            data.update({"phase": phase, "current_round": current_round,
                         "last_heartbeat": self.manager.now().isoformat()})
            resource.details_json = data
            if changed:
                self.manager._emit(session, job, "participant.progress", actor.id, {
                    "participant_id": participant.participant_id, "phase": phase, "current_round": current_round})
        return {"accepted": True}

    def _build(self):
        from .participant_build import ExternalBuild
        return ExternalBuild(self)

    def open_build_product(self, actor, filename):
        return self._build().open_product(actor, filename)

    def build_access_valid(self, actor):
        return self._build().access_valid(actor)

    def _built_artifacts(self, actor, spec):
        if not any(component.role == "build" for component in spec.components):
            return {}
        return self._build().manifest(actor)

    def _secret_options(self, job, attempt, spec, participant):
        if not spec.secret_refs:
            return ()
        planner = getattr(self.provisioner, "external_secret_options", None)
        if planner is None:
            raise Error(503, "participant_secret_approval_unavailable")
        try:
            return tuple(planner(job, attempt, participant.participant_id))
        except ResourceError:
            raise Error(409, "participant_secret_approval_unavailable") from None

    def assignment_plan(self, actor):
        """Current authorization precedes any node source/proxy/runtime side effect."""
        if "assignment" not in getattr(actor, "scopes", ()):
            raise Error(403, "node_scope_required")
        with self.database.transaction() as session:
            resource, job, attempt, spec, participant, node = self._node_record(
                session, actor, active=True, write=True)
            space_id = self.provisioner._space_id(job.id)
            if not space_id:
                raise Error(409, "participant_assignment_not_ready")
            _, manifest = self._snapshot(job, spec)
            historical = session.get(models.ProvisioningResource, resource.details_json.get("external_execution_id", ""))
            if historical is None or historical.job_id != job.id or historical.attempt_id != attempt.id:
                raise Error(409, "external_execution_binding_immutable")
            old_manifest = historical.details_json.get("source_manifest")
            if old_manifest is not None and old_manifest != manifest:
                raise Error(409, "participant_source_mismatch")
            historical.details_json = {**historical.details_json, "source_manifest": manifest}
        registry = self.provisioner.registry.refreshed()
        image = registry.validate(spec)
        approval = registry.source_registry.authorize(spec.project_id, spec.source_id, spec.source_commit)
        source_limits = {name: getattr(approval, name) for name in
                         ("max_bytes", "max_files", "max_git_bytes", "max_git_files")}
        return {"identity": {"job_id": job.id, "attempt_id": attempt.id,
                            "component_id": actor.component_id, "epoch": attempt.epoch},
                "node_id": node.node_id, "pool_id": "external", "job_spec": spec.to_dict(),
                "image_digest": image, "resources": dict(node.resources), "lease_seconds": 120,
                "deadline": job.deadline_at.timestamp() if job.deadline_at else None,
                "external_participant_id": participant.participant_id, "space_id": space_id,
                "principal_id": stable_workload_principal(self.broker.settings.workload_issuer,
                    job.id, actor.component_id, participant.participant_id),
                "source_manifest": manifest, "source_limits": source_limits,
                "built_artifacts": self._built_artifacts(actor, spec)}

    def issue_certificate(self, actor, *, csr_pem, space_id, principal_id):
        """Sign only a public CSR for the current enrolled execution."""
        if "assignment" not in getattr(actor, "scopes", ()):
            raise Error(403, "node_scope_required")
        if self.certificate_issuer is None:
            raise Error(503, "execution_certificate_issuer_unavailable")
        if not isinstance(csr_pem, str) or not 1 <= len(csr_pem.encode()) <= 16384:
            raise Error(422, "invalid_execution_csr")
        csr_hash = hashlib.sha256(csr_pem.encode()).hexdigest()
        with self.database.transaction() as session:
            resource, job, attempt, spec, participant, node = self._node_record(session, actor, active=True, write=True)
            actual_space = self.provisioner._space_id(job.id)
            expected_principal = stable_workload_principal(
                self.broker.settings.workload_issuer, job.id, actor.component_id, participant.participant_id)
            if not actual_space:
                raise Error(409, "participant_assignment_not_ready")
            if space_id != actual_space or principal_id != expected_principal:
                raise Error(403, "participant_foreign_certificate_binding")
            old_hash = resource.details_json.get("issued_certificate_csr_hash")
            if old_hash and old_hash != csr_hash:
                raise Error(409, "participant_execution_binding_immutable")
            deadline = job.deadline_at.timestamp() if job.deadline_at else (
                self.manager.now().timestamp() + spec.max_duration_seconds)
        from .certificates import validate_csr, CertificateError
        try:
            validate_csr(csr_pem)
        except CertificateError:
            raise Error(422, "invalid_execution_csr") from None
        from .executor import ExecutionIdentity
        identity = ExecutionIdentity(job.id, attempt.id, actor.component_id, attempt.epoch)
        key = stable_key("external-client-certificate", identity.key)
        try:
            result = self.ledger.run(job_id=job.id, attempt_id=attempt.id, component_id=actor.component_id,
                operation="external_client_certificate", key=key,
                desired={"identity": {"job_id": job.id, "attempt_id": attempt.id,
                    "component_id": actor.component_id, "epoch": attempt.epoch},
                    "space_id": space_id, "principal_id": principal_id, "csr_hash": csr_hash, "deadline": deadline},
                action=lambda: self.certificate_issuer.issue(csr_pem, identity=identity,
                    space_id=space_id, deadline=deadline))
        except ResourceError:
            raise Error(409, "participant_execution_binding_immutable") from None
        except CertificateError:
            raise Error(503, "execution_certificate_issuer_unavailable") from None
        fingerprint = _thumbprint(result.get("certificate_thumbprint"))
        if not isinstance(result.get("certificate_pem"), str):
            raise Error(503, "invalid_execution_certificate_receipt")
        with self.database.transaction() as session:
            resource, current_job, _, _, _, _ = self._node_record(session, actor, active=True, write=True)
            details = dict(resource.details_json)
            if details.get("issued_certificate_csr_hash") not in (None, csr_hash):
                raise Error(409, "participant_execution_binding_immutable")
            details.update({"issued_certificate_csr_hash": csr_hash,
                            "issued_certificate_thumbprint": fingerprint})
            resource.details_json = details
        return result

    def assignment(self, actor, *, execution_certificate_thumbprint, proxy_id):
        if "assignment" not in getattr(actor, "scopes", ()):
            raise Error(403, "node_scope_required")
        thumbprint = _thumbprint(execution_certificate_thumbprint)
        validate_identifier(proxy_id)
        with self.database.transaction() as session:
            resource, job, attempt, spec, participant, node = self._node_record(session, actor, active=True, write=True)
            if thumbprint == node.certificate_thumbprint:
                raise Error(403, "execution_certificate_required")
            if self.certificate_issuer is not None and resource.details_json.get(
                    "issued_certificate_thumbprint") != thumbprint:
                raise Error(403, "approved_execution_certificate_required")
            certificate_id = stable_key("external-certificate", thumbprint)[:32]
            certificate = session.get(models.ProvisioningResource, certificate_id)
            if certificate is not None:
                if (certificate.job_id != job.id or certificate.attempt_id != attempt.id
                        or certificate.component_id != resource.component_id):
                    raise Error(409, "execution_certificate_already_bound")
            else:
                session.add(models.ProvisioningResource(id=certificate_id, job_id=job.id,
                    attempt_id=attempt.id, component_id=resource.component_id,
                    kind="external_execution_certificate", external_id=thumbprint, retained=True, state="ready",
                    ownership_json={"job_id": job.id, "attempt_id": attempt.id, "component_id": resource.component_id},
                    details_json={"certificate_thumbprint": thumbprint}))
                try:
                    session.flush()
                except IntegrityError:
                    raise Error(409, "execution_certificate_already_bound") from None
            data = dict(resource.details_json)
            if data.get("execution_certificate_thumbprint") and (
                    data["execution_certificate_thumbprint"] != thumbprint or data["proxy_id"] != proxy_id):
                raise Error(409, "participant_execution_binding_immutable")
            if "grant_expires_at" not in data:
                data["grant_expires_at"] = min(
                    job.deadline_at.timestamp() if job.deadline_at else self.manager.now().timestamp() + spec.max_duration_seconds,
                    self.manager.now().timestamp() + 30 * 86400)
            # Redispatching this immutable execution must keep its existing
            # online proxy authorized while the idempotent grant is checked.
            # credentials() still checks the current Exchange ledger each time.
            status = ("assigned" if data.get("status") == "assigned" and
                      isinstance(data.get("workload_grant"), dict) else "preparing")
            data.update({"execution_certificate_thumbprint": thumbprint, "proxy_id": proxy_id,
                         "status": status, "termination_confirmed": False, "epoch": attempt.epoch})
            resource.details_json = data
            session.expunge(job); session.expunge(attempt)
        self.provisioner.registry.refreshed().validate(spec)
        source_path, manifest = self._snapshot(job, spec)
        space_id = self.provisioner._space_id(job.id)
        if not space_id:
            raise Error(409, "participant_assignment_not_ready")
        principal = stable_workload_principal(self.broker.settings.workload_issuer, job.id,
                                               actor.component_id, participant.participant_id)
        expiry = data["grant_expires_at"]
        body = {"subject": stable_workload_subject(job.id, actor.component_id, participant.participant_id),
                "job_id": job.id, "attempt_id": attempt.id, "component_id": actor.component_id,
                "epoch": attempt.epoch, "expires_at": expiry, "certificate_thumbprint": thumbprint,
                "roles": ["reader", "contributor"], "bindings": {"participant": participant.participant_id}}
        key = stable_key("external-grant", job.id, attempt.id, actor.component_id, thumbprint)
        grant = self.ledger.run(job_id=job.id, attempt_id=attempt.id, component_id=actor.component_id,
            operation="external_workload_grant", key=key, desired={"space_id": space_id, **body},
            action=lambda: self.provisioner.exchange.request("POST",
                self.provisioner.exchange.path(space_id, "/workload-grants"), body=body,
                headers={"Idempotency-Key": key}))
        if grant.get("principal_id") != principal or grant.get("space_id") != space_id:
            raise Error(503, "participant_foreign_grant")
        self.ledger.own(job_id=job.id, attempt_id=attempt.id, component_id=actor.component_id,
                        kind="workload_grant", external_id=grant["grant_id"], details=grant)
        configuration = {"role": "client", "job_id": job.id, "attempt_id": attempt.id,
            "component_id": actor.component_id, "space_id": space_id, "epoch": attempt.epoch,
            "spec": spec.to_dict(), "spec_digest": spec.digest, "participant_id": participant.participant_id,
            "source_manifest": manifest,
            "deadline_at": job.deadline_at.timestamp() if job.deadline_at else None,
            "reconciliation": (tuple(self.provisioner._directives(job.id, actor.component_id, attempt.epoch))
                if callable(getattr(self.provisioner, "_directives", None)) else ()),
            "dataset_bindings": {participant.dataset_binding: node.dataset_bindings[participant.dataset_binding].model_dump(mode="json")}}
        built = self._built_artifacts(actor, spec)
        if built:
            configuration.update({"built_artifacts": built, "build_dir": "/job/build"})
        secret_options = self._secret_options(job, attempt, spec, participant)
        if secret_options:
            configuration.update({"secret_option_names": list(secret_options),
                                  "secret_options_file": "/run/hf2l/secrets.json"})
        config = RuntimeConfig.model_validate(configuration)
        with self.database.transaction() as session:
            current, locked_job, _, _, _, _ = self._node_record(session, actor, active=True, write=True)
            data = dict(current.details_json)
            data.update({"status": "assigned", "workload_grant": grant, "last_heartbeat": self.manager.now().isoformat()})
            current.details_json = data
            self.manager._emit(session, locked_job, "participant.assigned", actor.id,
                {"participant_id": participant.participant_id, "node_id": node.node_id, "epoch": attempt.epoch})
        return {"identity": {"job_id": job.id, "attempt_id": attempt.id, "component_id": actor.component_id, "epoch": attempt.epoch},
                "runtime_config": config.to_dict(), "image_digest": self.provisioner.registry.validate(spec),
                "resources": dict(node.resources), "proxy_id": proxy_id, "grant": grant,
                "credentials": self.credentials(actor)}

    def credentials(self, actor):
        if "assignment" not in getattr(actor, "scopes", ()):
            raise Error(403, "node_scope_required")
        with self.database.transaction(immediate=False) as session:
            resource, job, attempt, spec, participant, node = self._node_record(session, actor, active=True)
            data = resource.details_json
            if data.get("status") != "assigned" or not data.get("workload_grant"):
                raise Error(409, "participant_assignment_not_ready")
            grant = dict(data["workload_grant"])
        current = self.provisioner.exchange.request("GET",
            self.provisioner.exchange.path(grant["space_id"], "/workload-grants/" + grant["grant_id"]))
        if not current.get("enabled") or current.get("expires_at", 0) <= self.manager.now().timestamp():
            raise Error(401, "participant_grant_revoked")
        bindings = {"job_id": job.id, "attempt_id": attempt.id, "component_id": actor.component_id,
                    "space_id": grant["space_id"], "grant_id": grant["grant_id"], "epoch": attempt.epoch,
                    "certificate_thumbprint": data["execution_certificate_thumbprint"],
                    "participant_id": participant.participant_id}
        ttl = min(300, int(current["expires_at"] - self.manager.now().timestamp()))
        if ttl < 1:
            raise Error(401, "participant_grant_revoked")
        return {"exchange_token": self.broker.issue_workload(**bindings, audience="exchange", ttl_seconds=ttl),
                "gateway_token": self.broker.issue_workload(**bindings, audience="gateway", ttl_seconds=ttl),
                "expires_at": int(self.manager.now().timestamp()) + ttl}

    def open_source(self, actor, relative_path):
        if "assignment" not in getattr(actor, "scopes", ()):
            raise Error(403, "node_scope_required")
        with self.database.transaction(immediate=False) as session:
            resource, job, attempt, spec, participant, node = self._node_record(session, actor, active=True)
            path, manifest = self._snapshot(job, spec)
        if relative_path not in manifest:
            raise Error(404, "participant_source_file_not_found")
        with SafeCollector(path) as reader:
            content = reader.read(relative_path)
        digest = hashlib.sha256(content).hexdigest()
        if digest != manifest[relative_path]:
            raise Error(409, "participant_source_mismatch")
        return ExternalSourceFile(io.BytesIO(content), len(content), digest)

    def confirm_stopped(self, actor, *, termination_confirmed=True, never_started=False):
        if ("stopped" not in getattr(actor, "scopes", ()) or termination_confirmed is not True
                or type(never_started) is not bool):
            raise Error(403, "confirmed_node_stop_required")
        with self.database.transaction() as session:
            resource, job, attempt, spec, participant, node = self._node_record(session, actor, write=True)
            data = dict(resource.details_json)
            execution_id = data.get("external_execution_id")
            execution = None
            if execution_id:
                execution = session.scalar(select(models.ProvisioningResource).where(
                    models.ProvisioningResource.id == execution_id).with_for_update()
                    .execution_options(populate_existing=True))
                if (execution is None or execution.job_id != job.id or execution.attempt_id != attempt.id
                        or execution.component_id != resource.component_id):
                    raise Error(409, "external_execution_binding_immutable")
            if data.get("termination_confirmed") is True and data.get("status") == "stopped":
                previous = (execution.details_json if execution is not None else data)
                if previous.get("never_started", False) is not never_started:
                    raise Error(409, "external_stop_receipt_immutable")
                return {"accepted": True}
            stopped_at = self.manager.now().isoformat()
            data.update({"termination_confirmed": True, "status": "stopped",
                         "stopped_at": stopped_at, "never_started": never_started})
            resource.details_json = data
            if execution is not None:
                execution.details_json = {**execution.details_json, "termination_confirmed": True,
                    "stopped_at": stopped_at,
                    "termination_operation_id": "external-stop-" + execution.id,
                    "never_started": never_started}
            self.manager._emit(session, job, "participant.stopped", actor.id, {
                "participant_id": participant.participant_id, "epoch": attempt.epoch})
        return {"accepted": True}


class ExternalManagerClient:
    """Node-owned mTLS client with explicit per-execution authorization."""

    def __init__(self, endpoint, *, ca_file="", certificate_file="", key_file="", http=None):
        from .config import require_tls
        from urllib.parse import urlsplit
        self.endpoint = require_tls(endpoint).rstrip("/")
        parsed = urlsplit(self.endpoint)
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("Manager endpoint must be a fixed HTTPS origin")
        self.owned = http is None
        if http is None:
            import httpx
            from .gateway import tls_context
            context = tls_context(ca_file)
            context.load_cert_chain(certificate_file, key_file)
            http = httpx.Client(verify=context, trust_env=False, follow_redirects=False, timeout=60)
        self.http = http

    @staticmethod
    def prefix(identity):
        from urllib.parse import quote
        pieces = (identity.job_id, identity.attempt_id, identity.component_id, str(identity.epoch))
        for value in pieces[:-1]:
            validate_identifier(value)
        return "/internal/jobs/v1/participants/" + "/".join(quote(value, safe="") for value in pieces)

    def request(self, identity, token, operation, *, body=None, raw=False):
        import json
        import httpx
        method = "GET" if operation in {"plan", "control", "purge-plan"} or operation.startswith("source/") else "POST"
        content = bytearray()
        try:
            with self.http.stream(method, self.endpoint + self.prefix(identity) + "/" + operation,
                                 json=body, headers={"Authorization": "Bearer " + token,
                                                     "Accept-Encoding": "identity"},
                                 timeout=3 if operation == "logs" else 60) as response:
                bound = 64 * 1024**2 if raw else 16 * 1024**2
                for chunk in response.iter_bytes():
                    if len(content) + len(chunk) > bound:
                        raise Error(502, "external_manager_reply_too_large")
                    content.extend(chunk)
                if response.status_code >= 400:
                    try:
                        code = json.loads(content).get("error", {}).get("code", "external_manager_unavailable")
                    except (ValueError, AttributeError):
                        code = "external_manager_unavailable"
                    raise Error(response.status_code, code)
                if 300 <= response.status_code < 400:
                    raise Error(503, "external_manager_redirect_forbidden")
        except httpx.HTTPError:
            raise Error(503, "external_manager_unavailable") from None
        if raw:
            return bytes(content)
        try:
            value = json.loads(content)
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except (ValueError, UnicodeError):
            raise Error(502, "invalid_external_manager_reply") from None

    def close(self):
        if self.owned:
            self.http.close()


class ExternalParticipantAgent:
    """Use the shared node materializer and durable NodeAgent for real execution.

    Source/specs are authorized online before preparation. Tokens remain in
    trusted process memory; only fixed RuntimeConfig enters the sandbox.
    """

    def __init__(self, client, materializer, node_agent, broker, *, node_certificate_thumbprint,
                 proxy_supervisor=None):
        import threading
        self.client, self.materializer, self.node = client, materializer, node_agent
        self.broker = broker
        self.node_certificate_thumbprint = _thumbprint(node_certificate_thumbprint)
        self.proxy_supervisor = proxy_supervisor
        self._tokens = {}
        self._log_identities = {}
        self._log_offsets = {}
        self._log_stop = threading.Event()
        self._log_thread = None
        self._execution_locks = {}
        self._lock = threading.RLock()

    def delegated_token(self, binding, participant_id, audience):
        from .executor import ExecutionIdentity
        def value(name):
            return binding.get(name) if isinstance(binding, Mapping) else getattr(binding, name)
        identity = ExecutionIdentity(value("job_id"), value("attempt_id"), value("component_id"), value("epoch"))
        with self._lock:
            token = self._tokens.get(identity.key)
        if not token:
            raise Error(503, "external_node_grant_unavailable")
        result = self.client.request(identity, token, "credentials", body={})
        return result["exchange_token" if audience == "exchange" else "gateway_token"]

    def poll_logs(self, identity, token, *, max_chunks=1, terminal=False):
        """Forward canonical redacted bytes using the manager's durable cursor."""
        if type(max_chunks) is not int or not 1 <= max_chunks <= 16:
            raise Error(422, "invalid_log_poll_bound")
        with self._lock:
            offset = self._log_offsets.get(identity.key, 0)
        completed = False
        for _ in range(max_chunks):
            receipt = self.node.read_logs(identity, offset=offset, max_bytes=65536)
            response = self.client.request(identity, token, "logs", body=receipt)
            next_offset = response.get("next_offset")
            if (response.get("accepted") is not True or type(next_offset) is not int
                    or not 0 <= next_offset <= 960 * 1024
                    or next_offset < receipt["next_offset"]):
                raise Error(502, "invalid_external_log_acknowledgment")
            with self._lock:
                self._log_offsets[identity.key] = next_offset
            completed = receipt["complete"] is True and response.get("complete") is True
            prior, offset = offset, next_offset
            if completed or offset == prior:
                break
        if terminal and not completed:
            raise Error(503, "participant_terminal_logs_unconfirmed")
        return {"next_offset": offset, "complete": completed}

    def start_log_polling(self, interval_seconds=2):
        """Poll active helpers; bootstrap grants are refreshed by the manager."""
        import threading
        if (not isinstance(interval_seconds, (int, float)) or isinstance(interval_seconds, bool)
                or not 0.05 <= interval_seconds <= 60):
            raise ValueError("A bounded log polling interval is required")
        with self._lock:
            if self._log_thread is not None:
                return
            def run():
                while not self._log_stop.wait(interval_seconds):
                    with self._lock:
                        identities = tuple(self._log_identities.values())
                    for identity in identities:
                        if self._log_stop.is_set():
                            return
                        with self._lock:
                            token = self._tokens.get(identity.key)
                        if not token:
                            continue
                        try:
                            with self._lock:
                                guard = self._execution_locks.setdefault(identity.key, threading.RLock())
                            # A busy start/stop owns the full flow and will
                            # perform terminal catch-up itself.
                            if not guard.acquire(blocking=False):
                                continue
                            try:
                                self.poll_logs(identity, token)
                            finally:
                                guard.release()
                        except Exception:
                            # Cursor advances only after a durable server ACK;
                            # an unavailable endpoint is retried next poll.
                            continue
            self._log_thread = threading.Thread(target=run, name="hf2l-external-logs", daemon=True)
            self._log_thread.start()

    @contextmanager
    def _flow_guard(self, identity):
        """Hold an OS lock shared by all helpers using this local node ledger."""
        import os
        import stat
        import fcntl
        root = Path(self.node.ledger_path).absolute().parent
        guard_root = private_root(root / ("participant-flows-" +
            hashlib.sha256(str(Path(self.node.ledger_path).absolute()).encode()).hexdigest()[:16]))
        path = guard_root / (identity.key + ".lock")
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077):
                raise Error(503, "participant_flow_lock_unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def receive(self, document):
        """Serialize the complete local start/stop flow for one execution."""
        import threading
        from .executor import ExecutionIdentity
        from .broker import BrokerError
        if not isinstance(document, dict) or not isinstance(document.get("node_token"), str):
            raise Error(422, "invalid_participant_dispatch")
        try:
            actor = self.broker.authenticate_node("Bearer " + document["node_token"],
                verified_peer_thumbprint=self.node_certificate_thumbprint,
                grant_validator=lambda value: value.node_id == self.node.node_id and value.pool_id == "external")
        except BrokerError:
            raise Error(401, "invalid_node_grant") from None
        identity = ExecutionIdentity(actor.job_id, actor.attempt_id, actor.component_id, actor.epoch)
        with self._lock:
            guard = self._execution_locks.setdefault(identity.key, threading.RLock())
        with guard, self._flow_guard(identity), self.node.component_resource_guard(identity):
            # Reauthenticate after waiting; an expired dispatch cannot start.
            return self._receive(document)

    def _receive(self, document):
        from .executor import ExecutionIdentity, ResourceLimits, ExecutorRefused
        from .remote_node import RemoteAssignment
        from .broker import BrokerError
        if not isinstance(document, dict) or set(document) - {
                "enrollment", "node_token", "node_certificate_thumbprint", "operation", "state_request"}:
            raise Error(422, "invalid_participant_dispatch")
        token = document.get("node_token")
        if not isinstance(token, str):
            raise Error(401, "invalid_node_grant")
        try:
            actor = self.broker.authenticate_node("Bearer " + token,
                verified_peer_thumbprint=self.node_certificate_thumbprint,
                grant_validator=lambda value: value.node_id == self.node.node_id and value.pool_id == "external")
        except BrokerError:
            raise Error(401, "invalid_node_grant") from None
        identity = ExecutionIdentity(actor.job_id, actor.attempt_id, actor.component_id, actor.epoch)
        with self._lock:
            self._tokens[identity.key] = token
        operation = document.get("operation", "start")
        if operation == "publication-state":
            if "collect" not in actor.scopes:
                raise Error(403, "node_scope_required")
            request = document.get("state_request")
            if (not isinstance(request, dict) or set(request) != {"path", "max_bytes"}
                    or not _publication_path(request["path"]) or type(request["max_bytes"]) is not int
                    or not 1 <= request["max_bytes"] <= 1024**2):
                raise Error(422, "invalid_publication_state_request")
            control = self.client.request(identity, token, "control")
            if (control.get("identity") != {"job_id": identity.job_id, "attempt_id": identity.attempt_id,
                    "component_id": identity.component_id, "epoch": identity.epoch}
                    or control.get("node_id") != self.node.node_id
                    or control.get("termination_confirmed") is not True
                    or control.get("revocation_confirmed") is not True):
                raise Error(409, "participant_publication_fence_unconfirmed")
            observation = self.node.inspect(identity)
            if not observation.termination_confirmed:
                raise Error(409, "participant_termination_unconfirmed")
            root = self.node.reconciliation_root(identity)
            with SafeCollector(root, max_file_bytes=request["max_bytes"],
                               max_total_bytes=request["max_bytes"]) as collector:
                try:
                    content = collector.read(request["path"], max_bytes=request["max_bytes"])
                except CollectionError as error:
                    cause = error
                    while cause.__cause__ is not None:
                        cause = cause.__cause__
                    if isinstance(cause, FileNotFoundError):
                        return {"identity": control["identity"], "exists": False}
                    raise Error(503, "participant_publication_state_unavailable") from None
            if not isinstance(content, bytes) or len(content) > request["max_bytes"]:
                raise Error(502, "invalid_publication_state_receipt")
            return {"identity": control["identity"], "exists": True,
                    "content_base64": base64.b64encode(content).decode(),
                    "sha256": hashlib.sha256(content).hexdigest()}
        if operation == "purge":
            if set(actor.scopes) != {"purge"}:
                raise Error(403, "node_scope_required")
            from .participant_cleanup import purge_assignment
            result = purge_assignment(self, actor, identity, token)
            with self._lock:
                self._tokens.pop(identity.key, None)
                self._log_identities.pop(identity.key, None)
            return result
        if operation == "stop":
            if "stopped" not in actor.scopes:
                raise Error(403, "node_scope_required")
            # Current online authorization precedes a destructive runtime action.
            control = self.client.request(identity, token, "control")
            if control.get("node_id") != self.node.node_id or control.get("identity") != {
                    "job_id": identity.job_id, "attempt_id": identity.attempt_id,
                    "component_id": identity.component_id, "epoch": identity.epoch}:
                raise Error(403, "external_node_assignment_mismatch")
            if control.get("termination_confirmed"):
                with self._lock:
                    self._tokens.pop(identity.key, None)
                    self._log_identities.pop(identity.key, None)
                return {"accepted": True, "state": "stopped"}
            never_started = False
            try:
                prior = self.node.inspect(identity)
                never_started = prior.state == "RESERVED" and prior.termination_confirmed is True
                observation = self.node.stop(identity)
            except ExecutorRefused as error:
                if error.code != "missing_reservation":
                    raise
                proof = getattr(self.node, "confirm_absent", None)
                if proof is None or proof(identity) is not True:
                    raise Error(503, "participant_termination_unconfirmed") from None
                # Absence requires proof from both durable node and executor
                # state under the cross-process execution flow lock.
                observation = None
                never_started = True
            if observation is not None:
                if not observation.termination_confirmed:
                    raise Error(503, "participant_termination_unconfirmed")
                self.poll_logs(identity, token, max_chunks=16, terminal=True)
                self.node.release(identity)
            if self.proxy_supervisor and not self.proxy_supervisor.stop(
                    identity.job_id, identity.attempt_id, identity.component_id, termination_confirmed=True):
                raise Error(503, "participant_proxy_termination_unconfirmed")
            self.client.request(identity, token, "stopped", body={
                "termination_confirmed": True, "never_started": never_started})
            with self._lock:
                self._tokens.pop(identity.key, None)
                self._log_identities.pop(identity.key, None)
            return {"accepted": True, "state": "stopped"}
        if operation != "start" or "assignment" not in actor.scopes:
            raise Error(403, "node_scope_required")
        plan = self.client.request(identity, token, "plan")
        if (plan.get("node_id") != self.node.node_id or plan.get("pool_id") != "external"
                or plan.get("identity") != {"job_id": identity.job_id, "attempt_id": identity.attempt_id,
                    "component_id": identity.component_id, "epoch": identity.epoch}):
            raise Error(403, "external_node_assignment_mismatch")
        limits = plan["resources"]
        resources = ResourceLimits(cpu_millis=limits["cpu_millicores"],
                                    memory_bytes=limits["memory_bytes"], disk_bytes=limits["disk_bytes"])
        assignment = RemoteAssignment(identity=identity, node_id=self.node.node_id, pool_id="external",
            resources=resources, job_spec=JobSpec.model_validate(plan["job_spec"]),
            image_digest=plan["image_digest"], lease_seconds=plan["lease_seconds"],
            deadline=plan["deadline"], external_participant_id=plan["external_participant_id"],
            source_limits=plan["source_limits"])
        # Planning has no job filesystem side effects. Local admission and
        # auxiliary storage ACK precede any recipe/source/proxy persistence.
        with self.node.component_resource_guard(identity), self.materializer.pending_assignment(assignment):
            prepared = self.materializer.plan(assignment)
            self.node.reserve(prepared)
            existing = self.node.inspect(identity)
            if existing.state not in {"EXITED", "STOPPED", "RELEASED"}:
                self.node.charge_auxiliary_bytes(identity, 4 * 1024**2 + 256 * 1024)
                self.materializer.reserve(assignment)
        if existing.state in {"EXITED", "STOPPED", "RELEASED"}:
            if not existing.termination_confirmed:
                raise Error(503, "participant_termination_unconfirmed")
            self.client.request(identity, token, "heartbeat", body={
                "phase": "completed" if existing.state == "EXITED" else "retry"})
            return self._receive({**document, "operation": "stop"})
        binding = dict(self.materializer.binding(identity, plan["space_id"], plan["principal_id"]))
        thumbprint = binding.get("certificate_thumbprint", binding.get("cert_thumbprint"))
        proxy_id = binding.get("proxy_id", binding.get("proxy_identifier"))
        if not proxy_id:
            proxy_id = stable_key("external-proxy", identity.key)[:32]
        result = self.client.request(identity, token, "assignment", body={
            "execution_certificate_thumbprint": thumbprint, "proxy_id": proxy_id})
        expected = RuntimeConfig.model_validate(result["runtime_config"])
        if expected.spec.digest != assignment.job_spec.digest or dict(expected.source_manifest) != plan["source_manifest"]:
            raise Error(409, "participant_source_mismatch")
        built = {name: item.model_dump(mode="json") for name, item in expected.built_artifacts.items()}
        if built != plan.get("built_artifacts", {}):
            raise Error(409, "participant_build_manifest_mismatch")
        if built:
            from .participant_build import stage_products
            if stage_products(self, identity, token, built) != built:
                raise Error(409, "participant_build_manifest_mismatch")
        self.materializer.prepare(identity, expected.to_dict(), execution_binding=binding)
        observed = self.node.inspect(identity)
        if observed.state in {"EXITED", "STOPPED", "RELEASED"}:
            if not observed.termination_confirmed:
                raise Error(503, "participant_termination_unconfirmed")
            self.client.request(identity, token, "heartbeat", body={
                "phase": "completed" if observed.state == "EXITED" else "retry"})
            return self._receive({**document, "operation": "stop"})
        # Source preparation may take time. Recheck current central authority
        # immediately before starting or extending this local execution.
        self.client.request(identity, token, "credentials", body={})
        if observed.state not in {"RUNNING", "STARTING"}:
            observed = self.node.start(identity)
        else:
            self.node.renew(identity, lease_seconds=120)
        self.client.request(identity, token, "heartbeat", body={"phase": "running"})
        with self._lock:
            self._log_identities[identity.key] = identity
        return {"accepted": True, "state": observed.state}

    def close(self):
        self._log_stop.set()
        if self._log_thread is not None:
            self._log_thread.join(timeout=5)
        self.client.close()


def _certificate_thumbprint(path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    certificate = x509.load_pem_x509_certificate(Path(path).read_bytes())
    return base64.urlsafe_b64encode(certificate.fingerprint(hashes.SHA256())).decode().rstrip("=")


class ExternalNodeDispatcher:
    """Deliver only to fixed approved node HTTPS endpoints over mutual TLS."""

    def __init__(self, nodes, *, certificate_file, key_file):
        import httpx
        from .gateway import tls_context
        from .config import require_tls
        self.clients, self.endpoints = {}, {}
        for node_id, value in nodes.items():
            endpoint = require_tls(value["endpoint"]).rstrip("/")
            from urllib.parse import urlsplit
            parsed = urlsplit(endpoint)
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise ValueError("External node endpoint must be an approved origin")
            context = tls_context(value.get("ca_file", ""))
            context.load_cert_chain(certificate_file, key_file)
            self.clients[node_id] = httpx.Client(verify=context, trust_env=False,
                                                follow_redirects=False, timeout=60)
            self.endpoints[node_id] = endpoint

    def __call__(self, node_id, document):
        return self._request(node_id, document, timeout=60)

    def read_state(self, node_id, document):
        # Publication fencing must not block the controller behind an offline
        # participant. Unknown proof keeps the existing attempt quarantined.
        return self._request(node_id, document, timeout=3)

    def _request(self, node_id, document, *, timeout):
        client = self.clients.get(node_id)
        if client is None:
            raise Error(403, "external_node_not_approved")
        import httpx
        try:
            with client.stream("POST", self.endpoints[node_id] +
                    "/internal/nodes/v1/participants", json=document, timeout=timeout,
                    headers={"Accept-Encoding": "identity"}) as response:
                if (not 200 <= response.status_code < 300
                        or response.headers.get("content-encoding", "identity") != "identity"):
                    raise Error(503, "external_node_dispatch_failed")
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > 2 * 1024**2:
                        raise Error(503, "external_node_dispatch_failed")
            result = json.loads(content)
            if not isinstance(result, dict):
                raise ValueError()
            return result
        except (httpx.HTTPError, ValueError, UnicodeError):
            raise Error(503, "external_node_dispatch_failed") from None

    def close(self):
        for client in self.clients.values():
            client.close()


def compose_external_services(settings, database, manager, provisioner, broker, node=None):
    """Trusted manager composition; no job code executes while loading approvals."""
    values = settings.extra.get("participants", {})
    if not isinstance(values, dict) or set(values) - {"nodes", "client_certificate", "client_key", "agent"}:
        raise ValueError("Unknown external participant configuration")
    raw = values.get("nodes", {})
    if not isinstance(raw, dict) or not raw:
        raise ValueError("External participants require explicit approved nodes")
    approved = {}
    for identifier, data in raw.items():
        if not isinstance(data, dict) or set(data) - {"certificate_thumbprint", "certificate_file",
                "dataset_bindings", "resources", "enabled", "endpoint", "ca_file"}:
            raise ValueError("Unknown external node approval field")
        if "certificate_thumbprint" in data and "certificate_file" in data:
            raise ValueError("Approve exactly one node certificate identity")
        fingerprint = data.get("certificate_thumbprint") or _certificate_thumbprint(data["certificate_file"])
        approved[identifier] = ApprovedExternalNode(identifier, fingerprint, data["dataset_bindings"],
            data.get("resources", {"cpu_millicores": 1000, "memory_bytes": 1024**3, "disk_bytes": 1024**3}),
            data.get("enabled", True))
    from .composition import read_secret, section
    from .certificates import CertificateIssuer
    read_secret(values["client_key"])
    certificate_values = section(settings, "provisioner")
    read_secret(certificate_values["client_ca_key"])
    issuer = CertificateIssuer(certificate_values["client_ca_certificate"],
        certificate_values["client_ca_key"], clock=lambda: manager.now().timestamp())
    dispatcher = ExternalNodeDispatcher(raw, certificate_file=values["client_certificate"],
                                        key_file=values["client_key"])
    service = ExternalParticipantService(manager, provisioner, broker, approved,
        node_dispatch=dispatcher, certificate_issuer=issuer)
    service.enable_async_dispatch()
    provisioner.external_cleanup = service.purge_job
    if getattr(provisioner, "publication_observer", None) is not None:
        provisioner.publication_observer.external_state_reader = service.read_publication_state
    return service


def create_participant_node_app(agent, manager_certificate_thumbprints):
    """Separate node ingress requires trusted verified mTLS manager identity."""
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    from starlette.concurrency import run_in_threadpool
    allowed = frozenset(_thumbprint(item) for item in manager_certificate_thumbprints)
    if not allowed:
        raise ValueError("A trusted manager certificate allowlist is required")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/internal/nodes/v1/participants")
    async def receive(request: Request):
        verified = (request.scope.get("hf2l.verified_peer_thumbprint") or
                    request.scope.get("state", {}).get("verified_certificate_thumbprint"))
        if verified not in allowed:
            raise Error(401, "verified_manager_certificate_required")
        lengths = request.headers.getlist("content-length")
        if len(lengths) > 1 or (lengths and (not lengths[0].isdigit() or len(lengths[0]) > 10)):
            raise Error(400, "invalid_content_length")
        if lengths and int(lengths[0]) > 1024**2:
            raise Error(413, "request_too_large")
        content = bytearray()
        async for chunk in request.stream():
            if len(content) + len(chunk) > 1024**2:
                raise Error(413, "request_too_large")
            content.extend(chunk)
        import json
        try:
            document = json.loads(content)
        except ValueError:
            raise Error(422, "invalid_participant_dispatch") from None
        return await run_in_threadpool(agent.receive, document)

    @app.exception_handler(Error)
    async def failed(request, error):
        return JSONResponse({"error": {"code": error.code}}, status_code=error.status)

    return app


def local_participant_catalog(values, dataset_bindings, secret_refs=()):
    """Scope the shared local catalog to this node's approved participant data."""
    from .remote_node import load_node_catalog
    from .composition import _keys
    if not isinstance(values, dict):
        raise ValueError("A local participant catalog is required")
    _keys(values, {"sources", "runtime_images"}, {"allowed_source_hosts"})
    if not isinstance(values["sources"], list) or not 1 <= len(values["sources"]) <= 100:
        raise ValueError("Local source approvals must be a bounded list")
    if not isinstance(values["runtime_images"], dict) or not values["runtime_images"]:
        raise ValueError("Immutable local runtime image approvals are required")
    document = {**values, "datasets": {
        key: [data["participant_id"]] for key, data in dataset_bindings.items()},
        "secret_refs": tuple(secret_refs)}
    registry = load_node_catalog(document)
    registry.dataset_projects = {key: data["project_id"] for key, data in dataset_bindings.items()}
    return registry


def compose_external_agent(settings):
    """Construct an independent node with public keys and local approvals only."""
    import stat
    from types import SimpleNamespace
    from .broker import WorkloadBroker
    from .composition import (section, _keys, _integer, read_secret, _dataset_config)
    from .execution_proxy import ProxySupervisor
    from .remote_node import (RemoteNodeMaterializer, NodeCredentialClient, NodeCertificateProvider,
                              NodeEndpoint, LocalNodeSecrets)
    from .executor import LinuxExecutor, ResourceLimits
    from .node_agent import NodeAgent
    if settings.broker is None or settings.broker.private_key is not None:
        raise ValueError("An external node requires verification-only workload keys")
    values = section(settings, "participants").get("agent")
    if not isinstance(values, dict):
        raise ValueError("Missing external participant agent configuration")
    required = {"manager_endpoint", "manager_ca_file", "node_certificate", "node_key",
                "certificate_ca_file", "managed_exchange_endpoint", "gateway_endpoint",
                "service_ca_file", "manager_certificate_thumbprints", "catalog"}
    _keys(values, required, {"proxy_socket_root"})
    read_secret(values["node_key"])
    node_values = section(settings, "node")
    _keys(node_values, {"node_id", "pool_id", "ledger_path", "capacity", "dataset_bindings"},
          {"identity_certificate", "identity_key", "identity_ca", "service", "secret_refs"})
    node_id = validate_identifier(node_values["node_id"])
    if node_values["pool_id"] != "external":
        raise ValueError("External participant nodes must use the local external pool")
    local_datasets = node_values["dataset_bindings"]
    if not isinstance(local_datasets, dict) or not local_datasets:
        raise ValueError("Explicit local dataset approvals are required")
    for binding_id, data in local_datasets.items():
        validate_identifier(binding_id)
        if not isinstance(data, dict) or not {"project_id", "participant_id"} <= data.keys():
            raise ValueError("Local datasets must bind a project and participant")
        validate_identifier(data["project_id"]); validate_identifier(data["participant_id"])
        _dataset_config(settings, binding_id, data["project_id"], data["participant_id"])
    local_refs = node_values.get("secret_refs", {})
    if not isinstance(local_refs, dict):
        raise ValueError("Local scoped secret approvals must be an explicit mapping")
    registry = local_participant_catalog(values["catalog"], local_datasets, local_refs)
    capacity = node_values["capacity"]
    _keys(capacity, {"cpu_millicores", "memory_bytes", "disk_bytes"}, {"pids", "io_bps"})
    resources = ResourceLimits(cpu_millis=_integer(capacity["cpu_millicores"], 1),
        memory_bytes=_integer(capacity["memory_bytes"], 1),
        disk_bytes=_integer(capacity["disk_bytes"], 32 * 1024**2),
        pids=_integer(capacity.get("pids", 128), 1, 65536),
        io_bps=_integer(capacity.get("io_bps", 16 * 1024**2), 1))
    executor_values = section(settings, "executor")
    _keys(executor_values, {"root", "profile_path"})
    executor_root = Path(executor_values["root"])
    broker, holder = WorkloadBroker(settings.broker), {}
    local_secrets = LocalNodeSecrets(executor_root / "sealed-secrets", local_refs)
    client = ExternalManagerClient(values["manager_endpoint"], ca_file=values["manager_ca_file"],
        certificate_file=values["node_certificate"], key_file=values["node_key"])

    def node_token(identity):
        with holder["agent"]._lock:
            token = holder["agent"]._tokens.get(identity.key)
        if not token:
            raise Error(503, "external_node_grant_unavailable")
        return token

    credential_client = NodeCredentialClient(NodeEndpoint(node_id=node_id,
        origin=values["manager_endpoint"], ca_file=values["manager_ca_file"],
        client_certificate=values["node_certificate"], client_key=values["node_key"]),
        route_prefix="participants", token_provider=lambda identity, operation: node_token(identity),
        http=client.http)
    certificate_provider = NodeCertificateProvider(credential_client,
        workload_issuer=settings.broker.workload_issuer,
        assignment_lookup=lambda identity: holder["materializer"].assignment(identity))

    supervisor = ProxySupervisor(executor_root / "proxies",
        client_ca_certificate=values["certificate_ca_file"], client_ca_key=None,
        certificate_provider=certificate_provider,
        broker=broker, exchange_endpoint=values["managed_exchange_endpoint"],
        gateway_endpoint=values["gateway_endpoint"], service_ca_file=values["service_ca_file"],
        grant_lookup=None, socket_root=values.get("proxy_socket_root"),
        token_provider=lambda binding, participant, audience: holder["agent"].delegated_token(binding, participant, audience))

    def datasets(assignment):
        participant = next(item for item in assignment.job_spec.participants
                           if item.participant_id == assignment.external_participant_id)
        approved = _dataset_config(settings, participant.dataset_binding,
                                    assignment.job_spec.project_id, participant.participant_id)
        document = {"kind": approved["kind"]}
        if approved["kind"] == "npz":
            document["path"] = "/job/data/data.npz"
        return {participant.dataset_binding: DatasetBinding.model_validate(document).model_dump(mode="json")}

    def bindings(assignment, space_id, principal_id):
        return supervisor.binding(
            SimpleNamespace(id=assignment.identity.job_id, deadline_at=assignment.deadline),
            SimpleNamespace(id=assignment.identity.attempt_id, job_id=assignment.identity.job_id,
                            epoch=assignment.identity.epoch),
            SimpleNamespace(component_id=assignment.identity.component_id,
                            participant_id=assignment.external_participant_id), space_id, principal_id)

    materializer = RemoteNodeMaterializer(executor_root, registry, node_id=node_id, pool_id="external",
        proxy_endpoint=supervisor.endpoint, execution_bindings=bindings, dataset_bindings=datasets,
        secret_planner=local_secrets.planned, secret_materializer=local_secrets.materialize,
        auxiliary_reserver=lambda identity, total: holder["node"].charge_auxiliary_bytes(identity, total))
    materializer.workload_issuer = settings.broker.workload_issuer
    materializer.require_source_limits = True
    holder["materializer"] = materializer

    def dataset_authorizer(binding_id, identity, participant_id):
        assignment = materializer.assignment(identity)
        participant = next((item for item in assignment.job_spec.participants
                            if item.participant_id == participant_id), None)
        if (assignment.external_participant_id != participant_id or participant is None
                or participant.mode != "external" or participant.dataset_binding != binding_id
                or assignment.identity != identity or assignment.node_id != node_id
                or identity.component_id != ExternalParticipantService.component_id(participant_id)):
            raise ValueError("Dataset differs from the current local assignment")
        approved = _dataset_config(settings, binding_id, assignment.job_spec.project_id, participant_id)
        if approved["kind"] == "synthetic":
            return {"kind": "synthetic"}
        if approved["kind"] != "npz":
            raise ValueError("Only approved NPZ bindings have a host path")
        path = Path(approved["host_path"])
        if not path.is_absolute() or any(item.is_symlink() for item in (path, *path.parents)):
            raise ValueError("Dataset must be a fixed trusted absolute regular file")
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("Dataset must have a single trusted name")
        return path

    executor = LinuxExecutor(profile_path=executor_values["profile_path"], root=executor_root,
                             dataset_authorizer=dataset_authorizer)
    node = NodeAgent(executor, node_values["ledger_path"], node_id, "external", resources)
    holder["node"] = node
    agent = ExternalParticipantAgent(client, materializer, node, broker,
        node_certificate_thumbprint=_certificate_thumbprint(values["node_certificate"]),
        proxy_supervisor=supervisor)
    agent.local_secrets = local_secrets
    agent.private_cleanup = lambda identity: local_secrets.resolver.cleanup(identity, termination_confirmed=True)
    holder["agent"] = agent
    agent.start_log_polling()

    def close():
        try:
            supervisor.close()
        finally:
            agent.close(); node.close()
    return agent, close


def main(argv=None):
    """Run the external node's private mTLS participant assignment listener."""
    import argparse
    from .composition import load_settings, section, _mtls
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    arguments = parser.parse_args(argv)
    settings = load_settings(arguments.config, component="database")
    agent, close = compose_external_agent(settings)
    try:
        values = section(settings, "participants")["agent"]
        app = create_participant_node_app(agent, values["manager_certificate_thumbprints"])
        boundary = section(settings, "boundaries").get("participants")
        if not isinstance(boundary, dict):
            raise ValueError("Missing private participant mTLS listener")
        _mtls(settings, arguments, app, boundary)
        return 0
    finally:
        close()
