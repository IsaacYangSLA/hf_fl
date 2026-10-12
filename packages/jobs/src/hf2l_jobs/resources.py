"""Trusted resource ownership and durable provisioning operations."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, Callable, Mapping

from sqlalchemy import select
from .domain import canonical_json, new_id, utcnow, validate_identifier


class ResourceError(RuntimeError):
    pass


class ResourceBusy(ResourceError):
    pass


@dataclass(frozen=True)
class ComponentPaths:
    source: Path
    state: Path
    cache: Path
    logs: Path
    artifacts: Path


@dataclass(frozen=True)
class ResourceBundle:
    job_id: str
    attempt_id: str
    space_id: str
    source_path: Path
    source_manifest: Mapping[str, str]
    image_digest: str
    principals: Mapping[str, str]
    component_paths: Mapping[str, ComponentPaths]
    component_specs: Mapping[str, Any] = field(default_factory=dict)
    workload_grants: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    init_required: bool = True


def stable_key(*parts: str) -> str:
    return hashlib.sha256(canonical_json(list(parts)).encode()).hexdigest()


def private_root(path: Path | str) -> Path:
    root = Path(path)
    if not root.is_absolute():
        raise ResourceError("Provisioning root must be absolute")
    for ancestor in (root, *root.parents):
        if ancestor.is_symlink():
            raise ResourceError("Provisioning paths cannot traverse symbolic links")
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not root.is_dir():
        raise ResourceError("Provisioning root is not a directory")
    root.chmod(0o700)
    return root


def atomic_json(path: Path, value: Mapping[str, Any], *, mode: int = 0o600) -> None:
    if path.is_symlink():
        raise ResourceError("Refusing symbolic-link metadata")
    temporary = path.with_name(path.name + ".tmp-" + new_id())
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            os.chmod(temporary, mode)
            stream.write(canonical_json(value))
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


class OwnedDirectories:
    """Ownership metadata stays outside every writable workload mount."""
    def __init__(self, root: Path | str):
        self.root = private_root(root)

    def job_path(self, job_id: str) -> Path:
        return self.root / validate_identifier(job_id)

    def ensure_job(self, job_id: str, spec_digest: str) -> Path:
        path = self.job_path(job_id)
        owner = {"job_id": job_id, "spec_digest": spec_digest, "schema_version": 1}
        if path.exists() or path.is_symlink():
            self.validate_job(job_id, spec_digest)
            return path
        with tempfile.TemporaryDirectory(prefix=".job-pending-", dir=self.root) as staging_root:
            staged = Path(staging_root) / job_id
            staged.mkdir(mode=0o700)
            atomic_json(staged / ".owner.json", owner)
            try:
                staged.rename(path)
            except FileExistsError:
                self.validate_job(job_id, spec_digest)
        return path

    def validate_job(self, job_id: str, spec_digest: str | None = None) -> Path:
        path = self.job_path(job_id)
        marker = path / ".owner.json"
        if path.is_symlink() or marker.is_symlink() or not marker.is_file():
            raise ResourceError("Job directory has no trusted ownership marker")
        try:
            value = json.loads(marker.read_text())
        except (OSError, ValueError) as exc:
            raise ResourceError("Invalid directory ownership") from exc
        if value.get("job_id") != job_id or (spec_digest is not None and value.get("spec_digest") != spec_digest):
            raise ResourceError("Job directory belongs to a different immutable specification")
        return path

    def components(self, job_id: str, component_ids) -> dict[str, ComponentPaths]:
        job = self.validate_job(job_id)
        source = job / "source"
        components = job / "components"
        if components.is_symlink():
            raise ResourceError("Component parent cannot be a symbolic link")
        components.mkdir(mode=0o700, exist_ok=True)
        result = {}
        for component_id in component_ids:
            component = components / validate_identifier(component_id)
            state = component / "state"
            for directory in (component, state, state / "cache", state / "logs", state / "artifacts"):
                if directory.is_symlink():
                    raise ResourceError("Component directory cannot be a symbolic link")
                directory.mkdir(mode=0o700, exist_ok=True)
            result[component_id] = ComponentPaths(source, state, state / "cache", state / "logs", state / "artifacts")
        return result

    def purge(self, job_id: str, spec_digest: str) -> None:
        path = self.job_path(job_id)
        if not path.exists():
            return
        self.validate_job(job_id, spec_digest)
        if not shutil.rmtree.avoids_symlink_attacks:
            raise ResourceError("Platform does not support descriptor-safe resource deletion")
        # Only directories need write permission; unlink never follows workload links.
        for directory, names, _ in os.walk(path, followlinks=False):
            directory_path = Path(directory)
            if directory_path.is_symlink():
                raise ResourceError("Unexpected directory traversal")
            directory_path.chmod(0o700)
            names[:] = [name for name in names if not (directory_path / name).is_symlink()]
        shutil.rmtree(path)


class ResourceLedger:
    def __init__(self, database):
        self.database = database

    def run(self, *, job_id: str, attempt_id: str, component_id: str, operation: str,
            key: str, desired: Mapping[str, Any], action: Callable[[], Mapping[str, Any]]) -> dict[str, Any]:
        from .models import ProvisioningOperation
        now = utcnow()
        with self.database.transaction() as session:
            record = session.scalar(select(ProvisioningOperation).where(ProvisioningOperation.idempotency_key == key).with_for_update())
            if record is None:
                record = ProvisioningOperation(id=stable_key("operation", key)[:32], job_id=job_id, attempt_id=attempt_id,
                                               component_id=component_id, operation=operation, idempotency_key=key,
                                               state="planned", desired_json=dict(desired), observed_json={},
                                               created_at=now, updated_at=now)
                session.add(record)
                session.flush()
            if record.job_id != job_id or record.component_id != component_id or record.desired_json != dict(desired):
                raise ResourceError("Provisioning operation ownership or immutable request changed")
            if record.state == "ready":
                return dict(record.observed_json)
            if record.state == "executing" and record.updated_at + timedelta(minutes=5) > now:
                raise ResourceBusy("Another provisioner owns this operation")
            record.state = "executing"
            record.updated_at = now
        try:
            observed = dict(action())
        except BaseException as exc:
            with self.database.transaction() as session:
                record = session.get(ProvisioningOperation, stable_key("operation", key)[:32])
                record.state = "unknown"
                record.last_error = type(exc).__name__
                record.updated_at = utcnow()
            raise
        with self.database.transaction() as session:
            record = session.get(ProvisioningOperation, stable_key("operation", key)[:32])
            record.state = "ready"
            record.observed_json = observed
            record.last_error = None
            record.updated_at = utcnow()
        return observed

    def own(self, *, job_id: str, attempt_id: str, component_id: str, kind: str, external_id: str,
            details: Mapping[str, Any] | None = None, retained: bool = False):
        from .models import ProvisioningResource
        ownership = {"job_id": job_id, "component_id": component_id, "kind": kind}
        size_bytes = (details or {}).get("size_bytes", 0)
        if type(size_bytes) is not int or size_bytes < 0:
            raise ResourceError("Resource size must be a measured non-negative byte count")
        identity = stable_key("resource", job_id, kind, external_id)[:32]
        with self.database.transaction() as session:
            record = session.scalar(select(ProvisioningResource).where(ProvisioningResource.kind == kind,
                                    ProvisioningResource.external_id == external_id).with_for_update())
            if record is not None and (record.job_id != job_id or record.ownership_json != ownership):
                raise ResourceError("Cannot adopt a foreign resource")
            if record is None:
                record = ProvisioningResource(id=identity, job_id=job_id, attempt_id=attempt_id,
                                              component_id=component_id, kind=kind, external_id=external_id,
                                              ownership_json=ownership, details_json=dict(details or {}),
                                              state="ready", retained=retained, size_bytes=size_bytes, created_at=utcnow(), updated_at=utcnow())
                session.add(record)
            elif record.ownership_json != ownership:
                raise ResourceError("Cannot adopt a foreign resource")
            return identity

    def resources(self, job_id: str, *, attempt_id: str | None = None, kind: str | None = None):
        from .models import ProvisioningResource
        with self.database.transaction(immediate=False) as session:
            query = select(ProvisioningResource).where(ProvisioningResource.job_id == job_id)
            if attempt_id is not None:
                query = query.where(ProvisioningResource.attempt_id == attempt_id)
            if kind is not None:
                query = query.where(ProvisioningResource.kind == kind)
            return [{"id": row.id, "attempt_id": row.attempt_id, "component_id": row.component_id,
                     "kind": row.kind, "external_id": row.external_id, "ownership": row.ownership_json,
                     "details": row.details_json, "state": row.state, "retained": row.retained, "size_bytes": row.size_bytes}
                    for row in session.scalars(query)]

    def deleted(self, resource_id: str, job_id: str):
        from .models import ProvisioningResource
        with self.database.transaction() as session:
            row = session.get(ProvisioningResource, resource_id)
            if row is None or row.job_id != job_id or row.ownership_json.get("job_id") != job_id:
                raise ResourceError("Cannot remove foreign resource")
            row.state = "deleted"
            row.deleted_at = utcnow()
            row.updated_at = utcnow()
