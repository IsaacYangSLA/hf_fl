"""Publish the verified private code snapshot as authorized opaque artifacts.

Source bytes remain in their already charged provisioning resource. Only
hash-bound metadata is added; no archive is unpacked, code is imported, or
second physical copy is created. The existing artifact broker performs current
job ACL and ownership checks before descriptor-relative streaming.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
import re

from sqlalchemy import select

from .collection import CollectionError, SafeCollector
from .domain import ArtifactLocator, utcnow
from .retention import utc
from .models import Artifact, Job, ProvisioningResource
from .resources import ResourceError, stable_key


_MAX_FILES = 100_000
_MAX_BYTES = 1024**3


def publish_source_artifacts(session, *, job_id: str, resource_id: str,
                             job_root: Path | str, manifest: Mapping[str, str],
                             expected_digest: str, max_files: int = _MAX_FILES,
                             max_bytes: int = _MAX_BYTES) -> tuple[str, ...]:
    """Publish one metadata row per exact verified source file, idempotently.

    Call after the source resource's reserved charge has been settled and its
    immutable digest recorded, in the same database transaction. The source
    resource row is locked to serialize retries. The caller owns the job root;
    only its exact ``source`` child is eligible. A verification or metadata
    conflict aborts publication before any row is inserted.
    """
    if (type(max_files) is not int or not 1 <= max_files <= _MAX_FILES or
            type(max_bytes) is not int or not 1 <= max_bytes <= _MAX_BYTES):
        raise ResourceError("Source artifact bounds exceed the supported limits")
    root = Path(job_root)
    if not root.is_absolute() or root.name != job_id or ".." in root.parts or str(root) != str(root.absolute()):
        raise ResourceError("Source artifact root must be the exact owned job directory")
    if not isinstance(manifest, Mapping) or len(manifest) > max_files:
        raise ResourceError("Source artifact manifest exceeds its approved file limit")
    verified = dict(manifest)
    for name, digest in verified.items():
        if (not isinstance(name, str) or not isinstance(digest, str) or
                not re.fullmatch(r"[a-f0-9]{64}", digest) or ".git" in name.split("/")):
            raise ResourceError("Source artifact manifest contains an unsafe file")
        try:
            ArtifactLocator(kind="local", resource_id=resource_id, relative_path=name)
        except ValueError:
            raise ResourceError("Source artifact manifest contains an unsafe path") from None
    digest = hashlib.sha256(json.dumps(verified, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if digest != expected_digest:
        raise ResourceError("Source artifact manifest differs from its immutable digest")
    # Lock Job before Resource, matching lifecycle cleanup. Defer the caller's
    # pending source-detail update until these locks have been acquired.
    with session.no_autoflush:
        job = session.scalar(select(Job).where(Job.id == job_id).with_for_update())
        resource = session.scalar(select(ProvisioningResource).where(
            ProvisioningResource.id == resource_id).with_for_update())
    if (job is None or job.purged_at is not None or
            (job.artifacts_expire_at and utc(job.artifacts_expire_at) <= utcnow())):
        raise ResourceError("Source artifacts cannot be published for an expired or purged job")
    if (resource is None or resource.job_id != job_id or resource.kind != "source" or
            resource.ownership_json.get("job_id") != job_id or
            resource.external_id != str(root / "source") or not resource.retained or
            resource.state in {"deleted", "cleanup_pending", "retired"} or resource.deleted_at is not None):
        raise ResourceError("Source artifacts require the live owned source resource")
    details = resource.details_json or {}
    logical_bytes = details.get("logical_bytes", details.get("size_bytes"))
    if (details.get("sha256") != expected_digest or
            details.get("retention_charge_settled") is not True or
            details.get("retention_charge_released") is not False or
            type(logical_bytes) is not int or not 0 <= logical_bytes <= max_bytes or
            type(resource.size_bytes) is not int or resource.size_bytes < logical_bytes or
            details.get("retention_charged_bytes") != resource.size_bytes):
        raise ResourceError("Source artifact resource has no settled immutable charge")
    try:
        with SafeCollector(root / "source", max_files=max_files,
                           max_file_bytes=max_bytes, max_total_bytes=max_bytes,
                           max_entries=min(2_000_000, max_files * 65), max_depth=64) as collector:
            files = collector.list_files()
    except (CollectionError, OSError):
        raise ResourceError("Source artifacts contain unsafe or changed files") from None
    if ({entry.path: entry.sha256 for entry in files} != verified or
            sum(entry.size_bytes for entry in files) != logical_bytes):
        raise ResourceError("Source artifact files differ from the verified snapshot")
    pending = []
    ids = []
    for entry in files:
        identity = stable_key("source-artifact", job_id, resource_id, entry.path)[:32]
        locator = {"kind": "local", "resource_id": resource_id, "relative_path": entry.path}
        # The authorized public source_path field preserves the exact relative
        # path. The human display/download name remains within its DB bound.
        name = Path(entry.path).name
        storage_key = "source-artifact:" + identity
        existing = session.get(Artifact, identity)
        if existing is not None:
            if (existing.job_id != job_id or existing.kind != "source" or
                    existing.attempt_number is not None or existing.name != name or
                    existing.size_bytes != entry.size_bytes or existing.sha256 != entry.sha256 or
                    existing.storage_key != storage_key or existing.locator_json != locator or
                    existing.state not in {"available", "retained"} or existing.deleted_at is not None):
                raise ResourceError("Immutable source artifact metadata conflicts with its snapshot")
        else:
            pending.append(Artifact(id=identity, job_id=job_id, attempt_number=None,
                kind="source", name=name, size_bytes=entry.size_bytes, sha256=entry.sha256,
                storage_key=storage_key, locator_json=locator, state="available",
                expires_at=job.artifacts_expire_at))
        ids.append(identity)
    session.add_all(pending)
    session.flush()
    return tuple(ids)
