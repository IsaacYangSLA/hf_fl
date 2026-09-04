#!/usr/bin/env python3
"""Create a validated HF username-to-participant allowlist."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from hf2l.allowlist import normalize_allowlist
from hf2l.hub_helpers import write_json


def parse_participant(value: str) -> tuple[str, str]:
    """Parse one HF_USERNAME=PARTICIPANT_ID argument."""
    if "=" not in value:
        raise ValueError(f"Participant mapping must be HF_USERNAME=PARTICIPANT_ID: {value!r}")
    author, participant = value.split("=", 1)
    return author, participant


def create_allowlist(values: list[str], output: Path) -> dict[str, str]:
    """Validate mappings and write a new allowlist without overwriting a file."""
    if output.exists():
        raise ValueError(f"Output file already exists: {output}")
    allowlist = normalize_allowlist(
        (parse_participant(value) for value in values), label="--participant"
    )
    write_json(output, allowlist)
    return allowlist


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--participant",
        action="append",
        required=True,
        metavar="HF_USERNAME=PARTICIPANT_ID",
        help="Approved HF username and required manifest participant ID; repeat as needed",
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        allowlist = create_allowlist(args.participant, args.output)
        print(f"allowlist={args.output.resolve()}")
        print(f"participants={len(allowlist)}")
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
