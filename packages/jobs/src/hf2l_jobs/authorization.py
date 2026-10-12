"""Current, explicit project/job authorization; platform roles grant no content access."""
from __future__ import annotations

from .domain import Error

JOB_ROLES = frozenset({"reader", "operator", "admin"})
_ROLE_LEVEL = {"reader": 1, "operator": 2, "admin": 3}


def principal_id(principal):
    value = getattr(principal, "id", principal if isinstance(principal, str) else None)
    if not isinstance(value, str) or not value or len(value) > 256:
        raise Error(401, "invalid_principal")
    return value


def require_job_role(member, role="reader"):
    if member is None or getattr(member, "role", None) not in JOB_ROLES:
        raise Error(404, "job_not_found")
    if _ROLE_LEVEL[member.role] < _ROLE_LEVEL[role]:
        raise Error(403, "job_role_required")


def require_submitter(member):
    if member is None or getattr(member, "role", None) not in {"submitter", "admin"}:
        raise Error(403, "project_submitter_required")


def validate_member_id(value):
    if not isinstance(value, str) or not value or len(value) > 256 or any(ord(c) < 32 for c in value):
        raise Error(422, "invalid_member_principal")
    return value
