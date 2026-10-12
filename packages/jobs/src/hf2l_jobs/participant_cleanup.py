"""Authorized historical participant storage cleanup, retaining audit fences.

Only a purge-only, certificate-bound historical execution grant authorizes node
deletion. Dataset mounts are input approvals and are never cleanup targets.
"""
from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import stat

from sqlalchemy import select

from . import models
from .collection import CollectionError, SafeCollector, delete_retained
from .domain import Error, JobSpec
from .executor import ExecutionIdentity, ExecutorRefused
from .resources import atomic_json, private_root

_TERMINAL = frozenset({"SUCCEEDED", "FAILED", "CANCELLED"})
_EXTERNAL_KINDS = frozenset({"external_execution", "external_enrollment", "external_execution_certificate"})


class ExternalCleanup:
    """Manager-side dispatch and durable receipts for owned historical nodes."""

    def __init__(self, service):
        self.service = service
        self.database = service.database

    def _authorize_job(self, session, job):
        now = self.service.manager.now()
        expired = job.artifacts_expire_at is not None and job.artifacts_expire_at <= now
        if job.state not in _TERMINAL or not (job.cleanup_status == "purge_pending" or expired):
            raise Error(409, "participant_purge_not_authorized")
        attempts = list(session.scalars(select(models.Attempt).where(models.Attempt.job_id == job.id)))
        if any(attempt.revocation_confirmed is not True or attempt.termination_confirmed is not True
               for attempt in attempts):
            raise Error(409, "participant_purge_termination_unconfirmed")
        executions = list(session.scalars(select(models.ProvisioningResource).where(
            models.ProvisioningResource.job_id == job.id,
            models.ProvisioningResource.kind.in_(("external_execution", "external_enrollment")))))
        if any(row.details_json.get("termination_confirmed") is not True for row in executions):
            raise Error(409, "participant_purge_termination_unconfirmed")
        # A live central allocation also prevents any historical storage purge.
        if session.scalar(select(models.Allocation.id).where(
                models.Allocation.job_id == job.id, models.Allocation.released_at.is_(None))):
            raise Error(409, "participant_purge_termination_unconfirmed")
        return JobSpec.model_validate(job.spec_json)

    def _record(self, session, actor, *, write=False):
        if getattr(actor, "scopes", frozenset()) != frozenset({"purge"}):
            raise Error(403, "node_scope_required")
        query = select(models.Job).where(models.Job.id == getattr(actor, "job_id", ""))
        if write:
            query = query.with_for_update().execution_options(populate_existing=True)
        job = session.scalar(query)
        resource = session.get(models.ProvisioningResource, getattr(actor, "grant_id", ""),
                               populate_existing=write)
        attempt = session.get(models.Attempt, getattr(actor, "attempt_id", ""))
        if (resource is None or job is None or attempt is None or resource.kind != "external_execution"
                or resource.job_id != job.id or attempt.job_id != job.id
                or resource.attempt_id != attempt.id or attempt.epoch != getattr(actor, "epoch", None)
                or resource.component_id != getattr(actor, "component_id", None)
                or getattr(actor, "pool_id", None) != "external"):
            raise Error(404, "participant_purge_not_found")
        spec = self._authorize_job(session, job)
        data, owner = resource.details_json, resource.ownership_json
        participant = next((p for p in spec.participants
                            if p.participant_id == data.get("participant_id") and p.mode == "external"), None)
        node = self.service.nodes.get(data.get("node_id"))
        if (participant is None or node is None
                or resource.component_id != self.service.component_id(participant.participant_id)
                or data.get("epoch") != attempt.epoch or data.get("spec_digest") != spec.digest
                or data.get("termination_confirmed") is not True
                or getattr(actor, "node_id", None) != data.get("node_id")
                or getattr(actor, "certificate_thumbprint", None) != data.get("node_certificate_thumbprint")
                or node.certificate_thumbprint != data.get("node_certificate_thumbprint")
                or owner.get("job_id") != job.id or owner.get("attempt_id") != attempt.id
                or owner.get("component_id") != resource.component_id
                or resource.state not in {"ready", "purge_pending", "deleted"}):
            raise Error(404, "participant_purge_not_found")
        return resource, job, attempt, spec, participant, node

    def check_node_grant(self, actor):
        try:
            with self.database.transaction(immediate=False) as session:
                self._record(session, actor)
            return True
        except (Error, ValueError):
            return False

    def purge_plan(self, actor):
        with self.database.transaction(immediate=False) as session:
            resource, job, attempt, spec, participant, node = self._record(session, actor)
            manifest = resource.details_json.get("source_manifest")
            if manifest is None:
                for previous in session.scalars(select(models.ProvisioningResource).where(
                        models.ProvisioningResource.job_id == job.id,
                        models.ProvisioningResource.component_id == resource.component_id,
                        models.ProvisioningResource.kind == "external_execution")):
                    if previous.details_json.get("spec_digest") == spec.digest and previous.details_json.get("source_manifest") is not None:
                        manifest = previous.details_json["source_manifest"]
                        break
            if manifest is None:
                try:
                    manifest = self.service._snapshot(job, spec)[1]
                except (CollectionError, FileNotFoundError):
                    pass
            return {
                "identity": {"job_id": job.id, "attempt_id": attempt.id,
                             "component_id": resource.component_id, "epoch": attempt.epoch},
                "node_id": node.node_id, "pool_id": "external",
                "participant_id": participant.participant_id, "spec_digest": spec.digest,
                "source_manifest": manifest,
                "termination_confirmed": True, "revocation_confirmed": True,
                "purged": resource.deleted_at is not None
                          and resource.details_json.get("disk_cleanup_confirmed") is True,
                "preserve_dataset_inputs": True,
            }

    def confirm_purged(self, actor, confirmed=True):
        if confirmed is not True:
            raise Error(422, "participant_purge_confirmation_required")
        with self.database.transaction() as session:
            resource, job, attempt, spec, participant, node = self._record(session, actor, write=True)
            if resource.deleted_at is None:
                now = self.service.manager.now()
                resource.state, resource.retained, resource.size_bytes = "deleted", False, 0
                resource.deleted_at = resource.updated_at = now
                resource.details_json = {**resource.details_json, "disk_cleanup_confirmed": True,
                                         "purged_at": now.isoformat()}
                self.service.manager._emit(session, job, "participant.purged", "node:" + node.node_id,
                    {"participant_id": participant.participant_id, "attempt_id": attempt.id,
                     "component_id": resource.component_id})
            return {"confirmed": True, "job_id": job.id, "attempt_id": attempt.id,
                    "component_id": resource.component_id, "epoch": attempt.epoch}

    def purge_job(self, job):
        """Return false until every historical node has acknowledged its deletion."""
        job_id = job["id"] if isinstance(job, dict) else job.id
        with self.database.transaction() as session:
            current = session.scalar(select(models.Job).where(models.Job.id == job_id).with_for_update())
            if current is None:
                raise Error(404, "job_not_found")
            self._authorize_job(session, current)
            rows = list(session.scalars(select(models.ProvisioningResource).where(
                models.ProvisioningResource.job_id == job_id,
                models.ProvisioningResource.kind.in_(_EXTERNAL_KINDS))))
            if any(row.ownership_json.get("job_id") != job_id
                   or row.ownership_json.get("component_id") != row.component_id
                   or (row.kind == "external_execution"
                       and row.ownership_json.get("attempt_id") != row.attempt_id) for row in rows):
                raise Error(409, "participant_cleanup_ownership_mismatch")
            executions = [row for row in rows if row.kind == "external_execution"]
            owned = {(row.attempt_id, row.component_id) for row in executions}
            # Pre-ledger deployments require an operator recovery, never guessed cleanup.
            if any(row.kind == "external_enrollment" and row.attempt_id is not None
                   and (row.attempt_id, row.component_id) not in owned for row in rows):
                return False
            pending = []
            for row in sorted(executions, key=lambda item: (item.details_json.get("source_manifest") is None, item.created_at, item.id)):
                if row.deleted_at is not None and row.details_json.get("disk_cleanup_confirmed") is True:
                    continue
                data = row.details_json
                node = self.service.nodes.get(data.get("node_id"))
                if node is None or node.certificate_thumbprint != data.get("node_certificate_thumbprint"):
                    return False
                token = self.service.broker.issue_node(
                    node_id=node.node_id, pool_id="external", job_id=job_id,
                    attempt_id=row.attempt_id, component_id=row.component_id, grant_id=row.id,
                    epoch=data["epoch"], certificate_thumbprint=node.certificate_thumbprint,
                    scopes=["purge"])
                row.state = "purge_pending"
                pending.append((node.node_id, {
                    "enrollment": {"id": row.id, "job_id": job_id, "attempt_id": row.attempt_id,
                        "component_id": row.component_id, "epoch": data["epoch"],
                        "participant_id": data["participant_id"], "node_id": node.node_id,
                        "status": "purge_pending", "external": True, "manager_allocation": False},
                    "node_token": token, "node_certificate_thumbprint": node.certificate_thumbprint,
                    "operation": "purge",
                }))
        if pending and self.service.node_dispatch is None:
            return False
        for node_id, document in pending:
            try:
                self.service.node_dispatch(node_id, document)
            except Exception:
                # Offline/uncertain nodes retain their resource and disk accounting.
                return False
        with self.database.transaction() as session:
            current = session.scalar(select(models.Job).where(models.Job.id == job_id).with_for_update())
            self._authorize_job(session, current)
            rows = list(session.scalars(select(models.ProvisioningResource).where(
                models.ProvisioningResource.job_id == job_id,
                models.ProvisioningResource.kind.in_(_EXTERNAL_KINDS))))
            if any(row.kind == "external_execution" and
                   (row.deleted_at is None or row.details_json.get("disk_cleanup_confirmed") is not True)
                   for row in rows):
                return False
            now = self.service.manager.now()
            for row in rows:
                # Keep identity/ownership/provenance rows as audit tombstones.
                if row.deleted_at is None:
                    row.state, row.retained, row.size_bytes = "deleted", False, 0
                    row.deleted_at = row.updated_at = now
                    row.details_json = {**row.details_json, "disk_cleanup_confirmed": True}
            return True


def _owned_tree(root, *, max_total_bytes, expected_hashes=None):
    """Manifest-check stopped owned bytes, then delete through directory descriptors."""
    root = Path(root)
    if not root.exists() and not root.is_symlink():
        return True
    bounds = dict(max_files=100000, max_entries=200000,
                  max_file_bytes=max(1, max_total_bytes), max_total_bytes=max(1, max_total_bytes))
    with SafeCollector(root, **bounds) as collector:
        items = collector.collect()
        actual = {item.path: item.sha256 for item in items}
        if expected_hashes is not None and any(expected_hashes.get(path) != digest
                                               for path, digest in actual.items()):
            raise CollectionError("Participant source differs from the pinned ownership manifest")
        manifest = [{**item.as_dict(), "locator": str(root / item.path)} for item in items]
        # delete_retained rejects unexplained empty directories. Prune only empty
        # owned directories; descriptor opens reject links and mount crossings.
        root_info = os.fstat(collector._root_fd)
        if root_info.st_uid != os.geteuid() or root_info.st_mode & 0o022:
            raise CollectionError("Participant cleanup root changed ownership")
        device = root_info.st_dev
        os.fchmod(collector._root_fd, 0o700)
        def prune(descriptor):
            with os.scandir(descriptor) as entries:
                names = [entry.name for entry in entries]
            for name in names:
                info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode):
                    continue
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=descriptor)
                try:
                    current = os.fstat(child)
                    if current.st_dev != device or current.st_uid != os.geteuid() or current.st_mode & 0o022:
                        raise CollectionError("Participant cleanup directory changed ownership")
                    os.fchmod(child, 0o700)
                    prune(child)
                finally:
                    os.close(child)
                try:
                    os.rmdir(name, dir_fd=descriptor)
                except OSError as error:
                    import errno
                    if error.errno not in {errno.ENOTEMPTY, errno.EEXIST}:
                        raise
        prune(collector._root_fd)
    return delete_retained(root, manifest, **bounds)


def _remove_assignment(materializer, identity):
    """Unlink the exact agent-owned assignment using its pinned directory."""
    name = identity.key + ".json"
    with SafeCollector(materializer.assignments, max_file_bytes=4 * 1024**2) as collector:
        try:
            collector.read(name)
        except FileNotFoundError:
            return
        info = os.stat(name, dir_fd=collector._root_fd, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise CollectionError("Participant assignment changed ownership")
        os.unlink(name, dir_fd=collector._root_fd)
        os.fsync(collector._root_fd)


def _purge_private_resources(agent, identity, assignment=None):
    supervisor = getattr(agent, "proxy_supervisor", None)
    if supervisor is not None:
        purge_proxy = getattr(supervisor, "purge", None)
        if purge_proxy is None or purge_proxy(identity, termination_confirmed=True) is not True:
            raise Error(503, "participant_proxy_cleanup_unconfirmed")
    private_cleanup = getattr(agent, "private_cleanup", None)
    if private_cleanup is not None:
        if private_cleanup(identity) is not True:
            raise Error(503, "participant_secret_cleanup_unconfirmed")
    elif agent.materializer.secret_planner is not None:
        if assignment is None or agent.materializer.secret_planner(assignment) is not None:
            raise Error(503, "participant_secret_cleanup_unconfirmed")


def _purge_assignment(agent, actor, identity, token):
    """Purge one online-authorized historical assignment under the agent flow lock."""
    if actor.scopes != frozenset({"purge"}) or identity != ExecutionIdentity(
            actor.job_id, actor.attempt_id, actor.component_id, actor.epoch):
        raise Error(403, "node_scope_required")
    plan = agent.client.request(identity, token, "purge-plan")
    if (plan.get("identity") != asdict(identity) or plan.get("node_id") != agent.node.node_id
            or plan.get("pool_id") != "external" or plan.get("termination_confirmed") is not True
            or plan.get("revocation_confirmed") is not True
            or plan.get("preserve_dataset_inputs") is not True):
        raise Error(403, "external_node_assignment_mismatch")
    materializer = agent.materializer
    purges = private_root(materializer.root / "purges")
    tombstone = purges / (identity.key + ".json")
    expected = {"identity": asdict(identity), "spec_digest": plan.get("spec_digest"),
                "participant_id": plan.get("participant_id"), "node_id": agent.node.node_id}
    prior = None
    if tombstone.exists() or tombstone.is_symlink():
        with SafeCollector(purges, max_file_bytes=16 * 1024**2) as collector:
            prior = json.loads(collector.read(tombstone.name))
        if (not isinstance(prior, dict) or any(prior.get(key) != value for key, value in expected.items())
                or type(prior.get("purged")) is not bool
                or not isinstance(prior.get("source_manifest"), dict)):
            raise Error(409, "participant_cleanup_ownership_mismatch")
        if prior["purged"]:
            assignment_path = materializer.assignments / (identity.key + ".json")
            if assignment_path.exists() or assignment_path.is_symlink():
                assignment = materializer.assignment(identity)
                if assignment.job_spec.digest != expected["spec_digest"]:
                    raise Error(409, "participant_cleanup_ownership_mismatch")
                _remove_assignment(materializer, identity)
            agent.client.request(identity, token, "purged", body={"confirmed": True})
            return {"accepted": True, "state": "purged"}
    assignment_path = materializer.assignments / (identity.key + ".json")
    if assignment_path.exists() or assignment_path.is_symlink():
        assignment = materializer.assignment(identity)
        if (assignment.node_id != agent.node.node_id or assignment.pool_id != "external"
                or assignment.job_spec.digest != plan.get("spec_digest")
                or assignment.external_participant_id != plan.get("participant_id")):
            raise Error(409, "participant_cleanup_ownership_mismatch")
        job = materializer.directories.validate_job(identity.job_id, assignment.job_spec.digest)
        parent = job / "components" / identity.component_id
        attempt = parent / "attempts" / identity.attempt_id / str(identity.epoch)
        manifest = prior["source_manifest"] if prior is not None else plan.get("source_manifest")
        config = attempt / "runtime.json"
        if manifest is None and (config.exists() or config.is_symlink()):
            from .workflow import RuntimeConfig
            with SafeCollector(attempt, max_file_bytes=4 * 1024**2) as collector:
                runtime = RuntimeConfig.model_validate_json(collector.read("runtime.json"))
            if (runtime.job_id, runtime.attempt_id, runtime.component_id, runtime.epoch) != (
                    identity.job_id, identity.attempt_id, identity.component_id, identity.epoch
            ) or runtime.spec.digest != assignment.job_spec.digest:
                raise Error(409, "participant_cleanup_ownership_mismatch")
            manifest = dict(runtime.source_manifest)
        # Every same-component reservation must be released before touching
        # shared source/state, including attempts newer than this purge grant.
        inventories = [row for row in agent.node.inventory()
                       if row["job_id"] == identity.job_id and row["component_id"] == identity.component_id]
        if any(row["state"] != "RELEASED" or not row["stopped"] for row in inventories):
            raise Error(409, "participant_purge_termination_unconfirmed")
        if not any(row["execution_key"] == identity.key for row in inventories):
            if agent.node.confirm_absent(identity) is not True:
                raise Error(409, "participant_cleanup_ownership_missing")
        others = []
        with SafeCollector(materializer.assignments, max_files=100000, max_file_bytes=4 * 1024**2,
                           max_total_bytes=1024**3) as collector:
            for item in collector.collect():
                if not item.path.endswith(".json") or item.path == assignment_path.name:
                    continue
                value = json.loads(collector.read(item.path))
                other = value.get("identity", {})
                if other.get("job_id") == identity.job_id and other.get("component_id") == identity.component_id:
                    if JobSpec.model_validate(value.get("job_spec")).digest != assignment.job_spec.digest:
                        raise Error(409, "participant_cleanup_ownership_mismatch")
                    others.append(other)
        source = parent / "source"
        if manifest is None:
            if source.exists() or source.is_symlink():
                raise Error(409, "participant_source_ownership_missing")
            manifest = {}
        if not isinstance(manifest, dict):
            raise Error(409, "participant_source_ownership_missing")
        atomic_json(tombstone, {**expected, "source_manifest": manifest, "purged": False})
        # The terminal job authorization and component guard prove every
        # attempt stopped. Delete shared materializer inputs in one owned tree,
        # including opaque wheels, immutable configs and staged partial files.
        _owned_tree(source, max_total_bytes=1024**3, expected_hashes=manifest)
        _owned_tree(parent, max_total_bytes=2 * assignment.resources.disk_bytes + 1024**3 + 16 * 1024**2)
        _purge_private_resources(agent, identity, assignment)
        # Node disk accounting is released only after every owned input/config,
        # proxy and sealed-secret copy was deleted, then retained runtime purge.
        try:
            if agent.node.purge(identity, auxiliary_deleted=True) is not True:
                raise Error(503, "participant_disk_cleanup_unconfirmed")
        except ExecutorRefused as error:
            if error.code != "missing_reservation":
                raise
            # No reservation plus a central stopped proof and the full-flow
            # lock permits cleanup of a materializer reservation never launched.
        atomic_json(tombstone, {**expected, "source_manifest": manifest, "purged": True})
        _remove_assignment(materializer, identity)
    else:
        # The local ledger plus absent assignment proves no node reservation
        # happened under the full start/stop/purge lock. Unknown retained node
        # ledgers require recovery and remain charged.
        if any(row["execution_key"] == identity.key for row in agent.node.inventory()):
            raise Error(409, "participant_cleanup_ownership_missing")
        if agent.node.confirm_absent(identity) is not True:
            raise Error(409, "participant_cleanup_ownership_missing")
        component = materializer.directories.job_path(identity.job_id) / "components" / identity.component_id
        # A bootstrap never delivered to this node has no local private bytes.
        # Orphaned source/state/config requires explicit operator recovery.
        for candidate in (component / "source", component / "state", component / "attempts" / identity.attempt_id):
            if candidate.exists() or candidate.is_symlink():
                raise Error(409, "participant_cleanup_ownership_missing")
        _purge_private_resources(agent, identity)
        atomic_json(tombstone, {**expected, "source_manifest": {}, "purged": True})
    agent.client.request(identity, token, "purged", body={"confirmed": True})
    return {"accepted": True, "state": "purged"}


def purge_assignment(agent, actor, identity, token):
    """Exclude later component reservations for the entire confirmed deletion."""
    from contextlib import nullcontext
    component = agent.node.component_resource_guard(identity)
    try:
        with component:
            rows = [row for row in agent.node.inventory()
                    if row["job_id"] == identity.job_id and row["component_id"] == identity.component_id]
            guard_identity = identity
            if rows and not any(row["execution_key"] == identity.key for row in rows):
                first = rows[0]
                guard_identity = ExecutionIdentity(first["job_id"], first["attempt_id"],
                                                   first["component_id"], first["epoch"])
            guard = agent.node.component_purge_guard(guard_identity) if rows else nullcontext()
            with guard:
                return _purge_assignment(agent, actor, identity, token)
    except ExecutorRefused as error:
        if error.code == "runtime_active":
            raise Error(409, "participant_purge_termination_unconfirmed") from None
        raise
