#!/usr/bin/env python3
"""Small helpers shared by the Hugging Face Hub scripts."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from huggingface_hub import HfApi


SUBMISSION_FILE = "fedavg_submission.json"
ROUND_FILE = "fedavg_round.json"
CLIENT_CONTEXT_FILE = "fedavg_client_context.json"
SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_api(explicit_token: str | None) -> HfApi:
    """Use --token, then HF_TOKEN, then the token cached by `hf auth login`."""
    token = explicit_token or os.environ.get("HF_TOKEN")
    return HfApi(token=token)


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"Required file is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def require_new_directory(path: Path) -> None:
    if path.exists():
        raise ValueError(f"Directory already exists; choose a new path: {path}")
    path.mkdir(parents=True)


def normalize_pr(value: str) -> str:
    value = value.strip()
    if value.isdigit():
        return f"refs/pr/{value}"
    if value.startswith("refs/pr/") and value.removeprefix("refs/pr/").isdigit():
        return value
    raise ValueError(f"PR must be a number or refs/pr/N, received {value!r}")
