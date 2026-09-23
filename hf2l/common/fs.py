"""JSON, file integrity, and safe relative paths shared across application layers."""

from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _nonfinite(value: str) -> None:
    raise ValueError(f"Non-finite JSON number: {value}")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"Non-finite JSON number: {value}")
    return parsed


def read_json(path: Path) -> dict[str, Any]:
    path = Path(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"),
                           object_pairs_hook=_json_pairs, parse_constant=_nonfinite,
                           parse_float=_finite_float)
    except FileNotFoundError as exc:
        raise ValueError(f"Required file is missing: {path}") from exc
    except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    """Replace a JSON document atomically with a separately named temporary file."""
    path = Path(path)
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    encoded = json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def safe_relative_path(value: str) -> str:
    """Accept a canonical relative POSIX path without traversal or control bytes."""
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ValueError("Expected a non-empty relative path of at most 4096 characters")
    if "\\" in value or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"Unsafe relative path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")):
        raise ValueError(f"Unsafe relative path: {value!r}")
    if ":" in path.parts[0]:
        raise ValueError(f"Unsafe relative path: {value!r}")
    return value


def require_new_directory(path: Path) -> None:
    if path.exists():
        raise ValueError(f"Directory already exists; choose a new path: {path}")
    path.mkdir(parents=True)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_hashes(root: Path, paths: tuple[str, ...] | list[str]) -> dict[str, str]:
    return {safe_relative_path(path): file_sha256(root / path) for path in paths}


def validate_artifact_hashes(root: Path, paths: tuple[str, ...] | list[str],
                             expected: object, label: str) -> None:
    if not isinstance(expected, dict) or not expected:
        raise ValueError(f"{label} is missing checkpoint_files_sha256")
    if any(not isinstance(path, str) or not isinstance(digest, str)
           for path, digest in expected.items()):
        raise ValueError(f"Checkpoint checksum mismatch in {label}")
    if expected != artifact_hashes(root, paths):
        raise ValueError(f"Checkpoint checksum mismatch in {label}")


def regular_file_paths(root: Path) -> list[str]:
    """Return safe relative paths for regular files, rejecting symlinks."""
    paths: list[str] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"Refusing to upload symlink: {path}")
        if path.is_file():
            paths.append(safe_relative_path(path.relative_to(root).as_posix()))
    return sorted(paths)


def checked_file_paths(root: Path, paths: tuple[str, ...] | list[str] | None = None) -> list[str]:
    """Validate an upload selection before any provider receives local bytes.

The caller's selection is authoritative. Every selected path must name a regular
file below the root, with no symlink in its relative ancestry. Case-insensitive
collisions are refused to keep snapshots portable across filesystems.
"""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"Upload root must be a real directory: {root}")
    if paths is None:
        paths = regular_file_paths(root)
    result: list[str] = []
    seen: set[str] = set()
    for value in paths:
        relative = safe_relative_path(value)
        key = relative.casefold()
        if any(key == previous or key.startswith(previous + "/") or previous.startswith(key + "/")
               for previous in seen):
            raise ValueError(f"Upload path collision: {relative}")
        seen.add(key)
        source = root
        for component in PurePosixPath(relative).parts:
            source = source / component
            if source.is_symlink():
                raise ValueError(f"Refusing to upload symlink: {source}")
        if not source.is_file():
            raise ValueError(f"Upload path must name a regular file: {relative}")
        result.append(relative)
    return sorted(result)
