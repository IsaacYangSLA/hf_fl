"""Validation and loading for participant allowlists."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from hf2l.hub_helpers import read_json


def normalize_allowlist(
    entries: Iterable[tuple[object, object]], *, label: str = "allowlist"
) -> dict[str, str]:
    """Validate a one-to-one mapping and normalize HF usernames for matching."""
    allowlist: dict[str, str] = {}
    participant_to_author: dict[str, str] = {}
    for raw_author, raw_participant in entries:
        author = raw_author.strip() if isinstance(raw_author, str) else ""
        if not author or not isinstance(raw_participant, str):
            raise ValueError(
                "Allowlist entries must map a non-empty HF username to a string"
            )
        participant = raw_participant.strip()
        if not participant:
            raise ValueError(
                f"Allowlist participant must not be empty for author {author!r}"
            )
        normalized_author = author.casefold()
        if normalized_author in allowlist:
            raise ValueError(f"Duplicate HF username in allowlist: {author}")
        if participant in participant_to_author:
            raise ValueError(
                f"Participant {participant!r} is mapped to both "
                f"{participant_to_author[participant]!r} and {author!r}"
            )
        allowlist[normalized_author] = participant
        participant_to_author[participant] = author
    if not allowlist:
        raise ValueError(f"Allowlist must not be empty: {label}")
    return allowlist


def load_allowlist(path: Path) -> dict[str, str]:
    """Load a participant allowlist from a JSON object."""
    return normalize_allowlist(read_json(path).items(), label=str(path))
