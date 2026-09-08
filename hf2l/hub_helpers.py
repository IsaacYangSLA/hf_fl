#!/usr/bin/env python3
"""Small protocol and file helpers shared by HF²L commands."""

from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SUBMISSION_FILE = "fedavg_submission.json"
ROUND_FILE = "fedavg_round.json"
CLIENT_CONTEXT_FILE = "fedavg_client_context.json"
SCHEMA_VERSION = 2
SUPPORTED_SCHEMA_VERSIONS = frozenset((1, 2))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def require_supported_schema(value: dict[str, Any], label: str) -> int:
    version = value.get("schema_version")
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError(f"The {label} uses an unsupported schema")
    return int(version)


def base_revision_from(value: dict[str, Any]) -> str:
    """Read a v2 base revision or its schema-v1 base_commit alias."""

    return str(value.get("base_revision") or value.get("base_commit") or "").strip()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_hashes(root: Path, paths: tuple[str, ...] | list[str]) -> dict[str, str]:
    return {path: file_sha256(root / path) for path in paths}


def validate_artifact_hashes(
    root: Path, paths: tuple[str, ...] | list[str], expected: object, label: str
) -> None:
    if not isinstance(expected, dict) or not expected:
        raise ValueError(f"{label} is missing checkpoint_files_sha256")
    normalized = {
        str(path): str(digest)
        for path, digest in expected.items()
        if isinstance(path, str) and isinstance(digest, str)
    }
    actual = artifact_hashes(root, paths)
    if normalized != actual:
        raise ValueError(f"Checkpoint checksum mismatch in {label}")


def regular_file_paths(root: Path) -> list[str]:
    """Return safe relative paths for every regular file under root."""

    paths: list[str] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"Refusing to upload symlink: {path}")
        if path.is_file():
            paths.append(path.relative_to(root).as_posix())
    return sorted(paths)
