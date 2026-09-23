"""Stable Exchange values available without server or application dependencies.

These are string enums so existing JSON and persisted string values retain their
meaning. Contract tests check the HTTP and lifecycle implementations against them.
"""
from enum import Enum


class Role(str, Enum):
    READER = "reader"
    CONTRIBUTOR = "contributor"
    PUBLISHER = "publisher"
    ADMIN = "admin"


class RecordState(str, Enum):
    DRAFT = "draft"
    PUBLISHED = "published"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    FAILED = "failed"
    WITHDRAWN = "withdrawn"


class TransferState(str, Enum):
    INITIATING = "initiating"
    UPLOADING = "uploading"
    COMPLETING = "completing"
    VERIFYING = "verifying"
    VERIFIED = "verified"
    CLEANUP = "cleanup"
    CLEANED = "cleaned"
    FAILED = "failed"


ROLES = frozenset(role.value for role in Role)
RECORD_STATES = frozenset(state.value for state in RecordState)
TRANSFER_STATES = frozenset(state.value for state in TransferState)
TERMINAL_RECORD_STATES = frozenset({RecordState.CANCELLED.value, RecordState.EXPIRED.value,
                                    RecordState.FAILED.value, RecordState.WITHDRAWN.value})
