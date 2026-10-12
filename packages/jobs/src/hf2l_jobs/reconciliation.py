"""Publication evidence and fencing decisions shared by lifecycle adapters.

A missing response is never evidence that a publication did not happen.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

KNOWN_PUBLICATIONS = frozenset({"none", "absent", "confirmed", "published"})
UNKNOWN_PUBLICATIONS = frozenset({"unknown", "publishing", "ambiguous"})


@dataclass(frozen=True)
class PublicationObservation:
    known: bool
    status: str
    current_round: int | None = None
    evidence: dict[str, Any] | None = None

    def __post_init__(self):
        if self.status not in KNOWN_PUBLICATIONS | UNKNOWN_PUBLICATIONS:
            raise ValueError("Unsupported publication observation")
        if self.known != (self.status in KNOWN_PUBLICATIONS):
            raise ValueError("Publication certainty and status disagree")
        if self.current_round is not None and (type(self.current_round) is not int or self.current_round < 0):
            raise ValueError("Current round must be a non-negative integer")


def utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def remaining_rounds(target_round: int, current_round: int) -> int:
    if type(target_round) is not int or type(current_round) is not int or target_round < 1 or current_round < 0:
        raise ValueError("Invalid absolute round boundary")
    return max(0, target_round - current_round)


def retry_delay(retry_number: int) -> int:
    if retry_number not in (1, 2, 3):
        raise ValueError("At most three automatic retries are permitted")
    return 60 * (2 ** (retry_number - 1))


def safe_to_reuse(*, revocation_confirmed: bool, termination_confirmed: bool,
                  publication: PublicationObservation) -> bool:
    return revocation_confirmed and termination_confirmed and publication.known
