"""Bounded, credential-free administrative policy history.

Callers insert the audit record inside the same database transaction as the
authorized mutation. This module never commits, fetches credentials, serializes
an arbitrary object, or stores complete operational configurations.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping

from .models import AdministrativeAudit

MAX_METADATA_BYTES = 32768
MAX_LIST_ITEMS = 64
_TEXT_FIELDS = {
    "id": 256, "name": 200, "node_id": 200, "principal_id": 256,
    "role": 32, "status": 32, "digest": 128, "source_id": 128,
    "participant_id": 128, "dataset_label": 200,
}
_NUMBER_FIELDS = {
    "retention_days", "version", "cpu_millicores", "memory_bytes",
    "disk_bytes", "gpu_count", "quota_cpu_millicores", "quota_memory_bytes",
    "quota_disk_bytes", "quota_gpus", "max_active_jobs", "max_running_jobs", "retained_bytes",
}
_BOOLEAN_FIELDS = {"healthy", "quarantined", "enabled", "approved"}
_LIST_FIELDS = {"gpu_uuids", "gpu_profiles", "sandbox_profiles", "allowed_commits", "allowed_hosts"}
_QUOTA_FIELDS = {"cpu_millicores", "memory_bytes", "disk_bytes", "gpu_count", "max_active_jobs", "max_running_jobs", "retained_bytes"}
_OPERATION = re.compile(r"[a-zA-Z0-9_.:-]{1,64}\Z")


def _text(value, maximum):
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError("Invalid administrative audit metadata")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Invalid administrative audit metadata")
    # Policy names and opaque identifiers must not become credential storage.
    lowered = value.lower()
    if "-----begin" in lowered or lowered.startswith(("bearer ", "basic ")):
        raise ValueError("Invalid administrative audit metadata")
    return value


def validate_audit_identity(actor_id, operation, resource_type, resource_id):
    _text(actor_id, 256)
    _text(resource_id, 256)
    if not isinstance(operation, str) or not _OPERATION.fullmatch(operation):
        raise ValueError("Invalid administrative audit operation")
    if not isinstance(resource_type, str) or not _OPERATION.fullmatch(resource_type):
        raise ValueError("Invalid administrative audit resource type")


def _number(value):
    if value is None:
        return None
    if type(value) is not int or value < 0 or value > (1 << 63) - 1:
        raise ValueError("Invalid administrative audit metadata")
    return value


def _list(value):
    if not isinstance(value, (tuple, list)) or len(value) > 1024:
        raise ValueError("Invalid administrative audit metadata")
    items = [_text(item, 128) for item in value]
    if len(items) <= MAX_LIST_ITEMS:
        return items
    payload = json.dumps(items, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return {"count": len(items), "sha256": hashlib.sha256(payload).hexdigest()}


def sanitize_policy_metadata(value):
    """Keep known scalar policy fields and bounded summaries, dropping secrets.

    Unknown fields are omitted rather than recursively traversing arbitrary
    operational configuration. Large approved lists retain their count and
    exact canonical SHA-256; historical records never require raw file paths.
    """
    if value is None:
        return None
    if not isinstance(value, Mapping) or len(value) > 128:
        raise ValueError("Invalid administrative audit metadata")
    safe = {}
    for key, item in value.items():
        if key in _TEXT_FIELDS:
            safe[key] = None if item is None else _text(item, _TEXT_FIELDS[key])
        elif key in _NUMBER_FIELDS:
            safe[key] = _number(item)
        elif key in _BOOLEAN_FIELDS:
            if type(item) is not bool:
                raise ValueError("Invalid administrative audit metadata")
            safe[key] = item
        elif key in _LIST_FIELDS:
            # Accept an already sanitized large-list summary at ORM validation.
            if isinstance(item, dict) and set(item) == {"count", "sha256"}:
                if type(item["count"]) is not int or not MAX_LIST_ITEMS < item["count"] <= 1024:
                    raise ValueError("Invalid administrative audit metadata")
                if not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
                    raise ValueError("Invalid administrative audit metadata")
                safe[key] = dict(item)
            else:
                safe[key] = _list(item)
        elif key in {"quotas", "quotas_json"}:
            if not isinstance(item, Mapping) or len(item) > 64:
                raise ValueError("Invalid administrative audit metadata")
            safe[key] = {name: _number(number) for name, number in item.items() if name in _QUOTA_FIELDS}
    if len(json.dumps(safe, separators=(",", ":"), ensure_ascii=False).encode()) > MAX_METADATA_BYTES:
        raise ValueError("Administrative audit metadata is too large")
    return safe


def record_admin_audit(session, *, actor_id, operation, resource_type, resource_id,
                       before=None, after=None):
    """Add one sanitized record to the caller-owned transaction."""
    validate_audit_identity(actor_id, operation, resource_type, resource_id)
    row = AdministrativeAudit(
        actor_id=actor_id, operation=operation, resource_type=resource_type,
        resource_id=resource_id, before_json=sanitize_policy_metadata(before),
        after_json=sanitize_policy_metadata(after),
    )
    session.add(row)
    return row
