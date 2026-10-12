"""Bounded, descriptor-relative collection of untrusted component output.

This module never imports workload code, unpacks an archive, or decodes a model.
A collector pins its root directory descriptor and rejects symbolic links, hard
links, mount crossings, special files, and outputs changed while being read.
Callers must provide a component-owned root and its resolved runtime secrets.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import io
import json
import math
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

_SECRET_KEY = re.compile(
    r"(^|_)(password|passwd|secret|token|credentials|private_key|access_key|api_key)($|_)",
    re.IGNORECASE,
)


class CollectionError(ValueError):
    """Output is unsafe, malformed, or exceeds a configured collection bound."""


@dataclass(frozen=True)
class FileMetadata:
    path: str
    size_bytes: int
    sha256: str

    def as_dict(self) -> dict[str, str | int]:
        return {"path": self.path, "size_bytes": self.size_bytes, "sha256": self.sha256}



@dataclass(frozen=True)
class RetainedFile:
    """Opaque bytes retained outside the ephemeral component volume."""

    path: str
    locator: str
    size_bytes: int
    sha256: str

    def as_dict(self) -> dict[str, str | int]:
        return {
            "path": self.path, "locator": self.locator,
            "size_bytes": self.size_bytes, "sha256": self.sha256,
        }


def _rename_no_replace(name: str, target: str, directory_fd: int) -> None:
    # A plain rename can overwrite a concurrently installed destination. Linux
    # RENAME_NOREPLACE atomically preserves an existing immutable retained file,
    # and avoids link/unlink's crash window where its link count would be two.
    try:
        library = ctypes.CDLL(None, use_errno=True)
        rename = library.renameat2
    except (AttributeError, OSError) as error:
        raise CollectionError("Atomic immutable retention requires Linux renameat2") from error
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    result = rename(
        directory_fd, os.fsencode(name), directory_fd, os.fsencode(target), 1
    )
    if result != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise FileExistsError(code, "Retained output already exists")
        raise OSError(code, "Atomic retained output publication failed")


def _bound(name: str, value: int, *, allow_zero: bool = False) -> int:
    if type(value) is not int or value < (0 if allow_zero else 1):
        raise ValueError(f"{name} must be a {'non-negative' if allow_zero else 'positive'} integer")
    return value


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CollectionError("Duplicate event keys are forbidden")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise CollectionError("Event JSON must contain finite numbers")


class SafeCollector:
    """Read only bounded regular files beneath one pinned component directory.

    collect and list_files return a manifest, never executable content.
    read returns opaque bytes; callers can store them without deserializing
    them. events parses bounded JSONL and omits secret fields, while logs
    redacts known secret values. Redaction cannot identify unknown secrets in
    arbitrary text; supply every resolved workload secret in secret_values.
    """

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        max_files: int = 1000,
        max_file_bytes: int = 64 * 1024 * 1024,
        max_total_bytes: int = 256 * 1024 * 1024,
        max_log_events: int = 10000,
        max_event_bytes: int = 64 * 1024,
        max_entries: int = 10000,
        max_depth: int = 32,
        secret_values: Iterable[str] = (),
    ) -> None:
        self._root_fd = -1
        self.max_files = _bound("max_files", max_files)
        self.max_file_bytes = _bound("max_file_bytes", max_file_bytes)
        self.max_total_bytes = _bound("max_total_bytes", max_total_bytes)
        self.max_log_events = _bound("max_log_events", max_log_events)
        self.max_event_bytes = _bound("max_event_bytes", max_event_bytes)
        self.max_entries = _bound("max_entries", max_entries)
        self.max_depth = _bound("max_depth", max_depth)
        secrets = tuple(secret_values)
        if len(secrets) > 128 or any(
            not isinstance(value, str) or not value or len(value.encode("utf-8")) > 8192
            for value in secrets
        ):
            raise ValueError("secret_values must contain at most 128 bounded non-empty strings")
        self._secret_values = tuple(sorted(set(secrets), key=lambda value: (-len(value), value)))
        if (
            os.name != "posix"
            or not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_DIRECTORY")
            or os.open not in os.supports_dir_fd
            or os.stat not in os.supports_dir_fd
            or os.scandir not in os.supports_fd
        ):
            raise CollectionError("Safe descriptor-relative collection is unavailable on this platform")
        self.root = Path(os.path.abspath(os.fspath(root)))
        self._root_fd = self._open_root()
        self._root_device = os.fstat(self._root_fd).st_dev

    def _open_root(self) -> int:
        # Open every ancestor separately: O_NOFOLLOW on only the final component
        # would still follow a symlink in an earlier component of the root.
        descriptor = -1
        try:
            descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            for part in self.root.parts[1:]:
                next_descriptor = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = next_descriptor
            return descriptor
        except (OSError, ValueError) as error:
            if descriptor >= 0:
                os.close(descriptor)
            raise CollectionError("The collection root must be an existing directory without symlinks") from error

    def close(self) -> None:
        if self._root_fd >= 0:
            os.close(self._root_fd)
            self._root_fd = -1

    def __enter__(self) -> SafeCollector:
        self._require_open()
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self.close()

    def __del__(self) -> None:
        # Initialization may have failed before the root descriptor was opened.
        descriptor = getattr(self, "_root_fd", -1)
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
            self._root_fd = -1

    def _require_open(self) -> None:
        if self._root_fd < 0:
            raise CollectionError("The collector is closed")

    def _parts(self, relative: str | os.PathLike[str]) -> tuple[str, ...]:
        self._require_open()
        value = os.fspath(relative)
        if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
            raise CollectionError("Expected a non-empty relative output path")
        parts = tuple(value.split("/"))
        if value.startswith("/") or any(part in ("", ".", "..") for part in parts):
            raise CollectionError("Absolute paths and traversal are forbidden")
        try:
            oversized = (
                len(parts) > self.max_depth
                or len(value.encode("utf-8")) > 4096
                or any(len(part.encode("utf-8")) > 255 for part in parts)
            )
        except UnicodeError as error:
            raise CollectionError("Output paths must be UTF-8 text") from error
        if oversized:
            raise CollectionError("Output path exceeds collection bounds")
        return parts

    def _directory(self, name: str, parent_fd: int) -> int:
        try:
            descriptor = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_fd,
            )
        except OSError as error:
            raise CollectionError("Output directories cannot be symlinks or special files") from error
        if os.fstat(descriptor).st_dev != self._root_device:
            os.close(descriptor)
            raise CollectionError("Output cannot cross a filesystem boundary")
        return descriptor

    def _read_file(self, name: str, parent_fd: int, limit: int) -> bytes:
        descriptor = -1
        try:
            # NONBLOCK avoids a FIFO/device open blocking before fstat rejects it.
            descriptor = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=parent_fd,
            )
            before = os.fstat(descriptor)
            self._validate_file(before)
            if before.st_size > limit:
                raise CollectionError("Output file exceeds its byte limit")
            chunks: list[bytes] = []
            count = 0
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, limit - count + 1))
                if not chunk:
                    break
                chunks.append(chunk)
                count += len(chunk)
                if count > limit:
                    raise CollectionError("Output file exceeds its byte limit")
            after = os.fstat(descriptor)
            self._validate_file(after)
            if (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns
            ) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
            ) or count != after.st_size:
                raise CollectionError("Output file changed during collection")
            return b"".join(chunks)
        except OSError as error:
            raise CollectionError("Output must be an accessible regular file without links") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _validate_file(self, information: os.stat_result) -> None:
        if not stat.S_ISREG(information.st_mode):
            raise CollectionError("Only regular output files can be collected")
        if information.st_nlink != 1:
            raise CollectionError("Hard-linked output files are forbidden")
        if information.st_dev != self._root_device:
            raise CollectionError("Output cannot cross a filesystem boundary")

    def read(self, relative: str | os.PathLike[str], max_bytes: int | None = None) -> bytes:
        parts = self._parts(relative)
        limit = min(self.max_file_bytes, self.max_total_bytes)
        if max_bytes is not None:
            limit = min(limit, _bound("max_bytes", max_bytes, allow_zero=True))
        descriptor = os.dup(self._root_fd)
        try:
            for part in parts[:-1]:
                next_descriptor = self._directory(part, descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            return self._read_file(parts[-1], descriptor, limit)
        finally:
            os.close(descriptor)

    def list_files(self) -> tuple[FileMetadata, ...]:
        self._require_open()
        files: list[FileMetadata] = []
        total_bytes = 0
        entries = 0

        def visit(descriptor: int, prefix: tuple[str, ...]) -> None:
            nonlocal total_bytes, entries
            # Stop descriptor-relative enumeration at the configured limit;
            # never materialize an unbounded directory before checking it.
            names = []
            with os.scandir(descriptor) as iterator:
                for entry in iterator:
                    if len(names) >= self.max_entries - entries:
                        raise CollectionError("Output tree exceeds its entry limit")
                    names.append(entry.name)
            for name in sorted(names):
                entries += 1
                if entries > self.max_entries:
                    raise CollectionError("Output tree exceeds its entry limit")
                path = (*prefix, name)
                relative = "/".join(path)
                self._parts(relative)
                try:
                    information = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                except OSError as error:
                    raise CollectionError("Output tree changed during collection") from error
                if stat.S_ISDIR(information.st_mode):
                    child = self._directory(name, descriptor)
                    try:
                        visit(child, path)
                    finally:
                        os.close(child)
                else:
                    self._validate_file(information)
                    if len(files) >= self.max_files:
                        raise CollectionError("Output tree exceeds its file limit")
                    content = self._read_file(
                        name, descriptor, min(self.max_file_bytes, self.max_total_bytes - total_bytes)
                    )
                    total_bytes += len(content)
                    files.append(FileMetadata(relative, len(content), hashlib.sha256(content).hexdigest()))

        try:
            visit(self._root_fd, ())
        except OSError as error:
            raise CollectionError("Output tree could not be safely enumerated") from error
        return tuple(files)

    def collect(self) -> tuple[FileMetadata, ...]:
        return self.list_files()


    def _retention_root(self, destination: str | os.PathLike[str]) -> tuple[Path, int]:
        value = os.fspath(destination)
        if (
            not isinstance(value, str) or not value.startswith("/")
            or "\x00" in value or "\\" in value
            or any(part in (".", "..") for part in value.split("/"))
        ):
            raise CollectionError("Retention requires a trusted absolute directory without traversal")
        try:
            if len(value.encode("utf-8")) > 4096 or len(value.split("/")) > 128:
                raise CollectionError("Retention directory exceeds path bounds")
        except UnicodeError as error:
            raise CollectionError("Retention directory must be UTF-8 text") from error
        root = Path(value)
        source_stat = os.fstat(self._root_fd)
        source_identity = (source_stat.st_dev, source_stat.st_ino)
        descriptor = -1
        try:
            descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            for part in root.parts[1:]:
                parent_stat = os.fstat(descriptor)
                if (parent_stat.st_dev, parent_stat.st_ino) == source_identity:
                    raise CollectionError("Retained output cannot be stored inside the source volume")
                try:
                    child = os.open(
                        part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=descriptor,
                    )
                except FileNotFoundError:
                    try:
                        os.mkdir(part, 0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                    os.fsync(descriptor)
                    child = os.open(
                        part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=descriptor,
                    )
                os.close(descriptor)
                descriptor = child
            information = os.fstat(descriptor)
            if (information.st_dev, information.st_ino) == source_identity:
                raise CollectionError("Retained output cannot replace the source volume")
            if information.st_uid != os.geteuid() or information.st_mode & 0o077:
                raise CollectionError("The retained component directory must be privately owned")
            return root, descriptor
        except (OSError, ValueError) as error:
            if descriptor >= 0:
                os.close(descriptor)
            if isinstance(error, CollectionError):
                raise
            raise CollectionError("Retention directories must be trusted directories without links") from error

    def retain(self, destination: str | os.PathLike[str]) -> tuple[RetainedFile, ...]:
        """Durably copy an immutable manifest into one trusted private directory.

        Files are copied as opaque bytes with mode 0600, fsynced, and atomically
        published without replacing existing files. Identical retries reuse the
        same bytes; conflicting content or any linked destination fails closed.
        The destination must be outside the source volume, owned by the node
        agent, and inaccessible to workloads. Returned local locators are for
        the trusted manager only, not redirects to browsers or sandbox mounts.
        """
        self._require_open()
        manifest = self.collect()
        root, descriptor = self._retention_root(destination)
        destination_collector = None
        try:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
            destination_collector = SafeCollector(
                root, max_files=self.max_files, max_file_bytes=self.max_file_bytes,
                max_total_bytes=self.max_total_bytes, max_log_events=self.max_log_events,
                max_event_bytes=self.max_event_bytes, max_entries=self.max_entries,
                max_depth=self.max_depth,
            )
            root_information = os.fstat(descriptor)
            reopened_information = os.fstat(destination_collector._root_fd)
            if (
                root_information.st_dev, root_information.st_ino
            ) != (
                reopened_information.st_dev, reopened_information.st_ino
            ):
                raise CollectionError("Retained root changed during collection")
            results = []
            for metadata in manifest:
                content = self.read(metadata.path)
                if len(content) != metadata.size_bytes or hashlib.sha256(content).hexdigest() != metadata.sha256:
                    raise CollectionError("Source output changed after its manifest was collected")
                parent_fd = os.dup(descriptor)
                temporary_name = None
                temporary_fd = -1
                try:
                    parts = self._parts(metadata.path)
                    for part in parts[:-1]:
                        try:
                            child = destination_collector._directory(part, parent_fd)
                        except CollectionError:
                            # Determine absence without following a link. Every
                            # other directory error remains a hard rejection.
                            try:
                                os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
                            except FileNotFoundError:
                                try:
                                    os.mkdir(part, 0o700, dir_fd=parent_fd)
                                except FileExistsError:
                                    pass
                                os.fsync(parent_fd)
                                child = destination_collector._directory(part, parent_fd)
                            else:
                                raise
                        child_information = os.fstat(child)
                        if child_information.st_uid != os.geteuid() or child_information.st_mode & 0o077:
                            os.close(child)
                            raise CollectionError("Retained subdirectories must be privately owned")
                        os.close(parent_fd)
                        parent_fd = child
                    target = parts[-1]
                    try:
                        os.stat(target, dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        existing = destination_collector._read_file(target, parent_fd, self.max_file_bytes)
                        if (
                            len(existing) != metadata.size_bytes
                            or hashlib.sha256(existing).hexdigest() != metadata.sha256
                        ):
                            raise CollectionError("Retained output conflicts with its immutable manifest")
                        os.fsync(parent_fd)
                        results.append(RetainedFile(
                            metadata.path, str(root / metadata.path), metadata.size_bytes, metadata.sha256
                        ))
                        continue
                    temporary_name = ".hf2l-retain-" + uuid4().hex
                    temporary_fd = os.open(
                        temporary_name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                        0o600, dir_fd=parent_fd,
                    )
                    os.fchmod(temporary_fd, 0o600)
                    remaining = memoryview(content)
                    while remaining:
                        count = os.write(temporary_fd, remaining)
                        if count <= 0:
                            raise CollectionError("Retained file could not be completely written")
                        remaining = remaining[count:]
                    os.fsync(temporary_fd)
                    os.close(temporary_fd)
                    temporary_fd = -1
                    try:
                        _rename_no_replace(temporary_name, target, parent_fd)
                    except FileExistsError:
                        existing = destination_collector._read_file(target, parent_fd, self.max_file_bytes)
                        if (
                            len(existing) != metadata.size_bytes
                            or hashlib.sha256(existing).hexdigest() != metadata.sha256
                        ):
                            raise CollectionError("Retained output conflicts with its immutable manifest")
                    else:
                        temporary_name = None
                    os.fsync(parent_fd)
                    results.append(RetainedFile(
                        metadata.path, str(root / metadata.path), metadata.size_bytes, metadata.sha256
                    ))
                finally:
                    if temporary_fd >= 0:
                        os.close(temporary_fd)
                    if temporary_name is not None:
                        try:
                            os.unlink(temporary_name, dir_fd=parent_fd)
                        except FileNotFoundError:
                            pass
                        os.fsync(parent_fd)
                    os.close(parent_fd)
            os.fsync(descriptor)
            return tuple(results)
        except (ImportError, OSError) as error:
            raise CollectionError("Output could not be durably retained") from error
        finally:
            if destination_collector is not None:
                destination_collector.close()
            os.close(descriptor)

    def _redact(self, value: str, limit: int | None = None) -> str:
        maximum = min(self.max_file_bytes, self.max_total_bytes) if limit is None else limit
        size = len(value.encode("utf-8"))
        for secret in self._secret_values:
            occurrences = value.count(secret)
            size += occurrences * (len(b"[REDACTED]") - len(secret.encode("utf-8")))
            if size > maximum:
                raise CollectionError("Redacted output exceeds its byte limit")
            value = value.replace(secret, "[REDACTED]")
        return value

    def _sanitize(self, value: Any, depth: int = 0) -> Any:
        if depth > 16:
            raise CollectionError("Event JSON nesting exceeds collection bounds")
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                normalized = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
                if _SECRET_KEY.search(normalized):
                    continue
                safe_key = self._redact(key, self.max_event_bytes)
                if safe_key in result:
                    raise CollectionError("Redacted event keys collide")
                result[safe_key] = self._sanitize(item, depth + 1)
            return result
        if isinstance(value, list):
            return [self._sanitize(item, depth + 1) for item in value]
        if isinstance(value, str):
            return self._redact(value, self.max_event_bytes)
        if isinstance(value, float) and not math.isfinite(value):
            raise CollectionError("Event JSON must contain finite numbers")
        return value

    def logs(self, relative: str | os.PathLike[str], max_bytes: int | None = None) -> str:
        try:
            limit = min(self.max_file_bytes, self.max_total_bytes)
            if max_bytes is not None:
                limit = min(limit, _bound("max_bytes", max_bytes, allow_zero=True))
            return self._redact(self.read(relative, max_bytes=max_bytes).decode("utf-8"), limit)
        except UnicodeError as error:
            raise CollectionError("Logs must be UTF-8 text") from error

    def events(self, relative: str | os.PathLike[str]) -> tuple[dict[str, Any], ...]:
        content = self.read(relative)
        events: list[dict[str, Any]] = []
        stream = io.BytesIO(content)
        line_count = 0
        while True:
            line = stream.readline(self.max_event_bytes + 2)
            if not line:
                break
            line_count += 1
            if line_count > self.max_log_events:
                raise CollectionError("Event line count exceeds its collection limit")
            if line.endswith(b"\n"):
                line = line[:-1]
                if line.endswith(b"\r"):
                    line = line[:-1]
            if len(line) > self.max_event_bytes:
                raise CollectionError("Event exceeds its byte limit")
            if not line.strip():
                continue
            try:
                value = json.loads(
                    line.decode("utf-8"), object_pairs_hook=_json_object, parse_constant=_reject_constant
                )
                if not isinstance(value, dict):
                    raise CollectionError("Each event must be a JSON object")
                sanitized = self._sanitize(value)
                rendered = json.dumps(sanitized, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
                if len(rendered.encode("utf-8")) > self.max_event_bytes:
                    raise CollectionError("Sanitized event exceeds its byte limit")
                events.append(sanitized)
            except (UnicodeError, ValueError, RecursionError) as error:
                if isinstance(error, CollectionError):
                    raise
                raise CollectionError("Events must be bounded UTF-8 JSON objects") from error
        return tuple(events)


def delete_retained(
    destination: str | os.PathLike[str],
    manifest: Iterable[RetainedFile | Mapping[str, Any]],
    *,
    max_files: int = 1000,
    max_file_bytes: int = 64 * 1024 * 1024,
    max_total_bytes: int = 256 * 1024 * 1024,
    max_entries: int = 10000,
    max_depth: int = 32,
) -> bool:
    """Delete only immutable manifest-owned files from a trusted retained root.

    The caller must already have confirmed runtime termination and release.
    Missing files/root support retry after a partially acknowledged purge.
    Unexpected files, changed hashes, linked/special files, extra directories,
    or mismatched local locators leave deletion unconfirmed. The initial full
    inventory is checked before any deletion. No archive or model is decoded.
    """
    bounds = {
        "max_files": _bound("max_files", max_files),
        "max_file_bytes": _bound("max_file_bytes", max_file_bytes),
        "max_total_bytes": _bound("max_total_bytes", max_total_bytes),
        "max_entries": _bound("max_entries", max_entries),
        "max_depth": _bound("max_depth", max_depth),
    }
    value = os.fspath(destination)
    if (
        not isinstance(value, str) or not value.startswith("/")
        or "\x00" in value or "\\" in value
        or any(part in (".", "..") for part in value.split("/"))
    ):
        raise CollectionError("Purge requires a trusted absolute directory without traversal")
    root = Path(value)
    if len(root.parts) <= 1:
        raise CollectionError("A filesystem root cannot be purged")
    try:
        if len(value.encode("utf-8")) > 4096 or len(root.parts) > 128:
            raise CollectionError("Purge directory exceeds path bounds")
    except UnicodeError as error:
        raise CollectionError("Purge directory must be UTF-8 text") from error
    expected: dict[str, RetainedFile] = {}
    allowed_directories: set[str] = set()
    total_bytes = 0
    for entry in manifest:
        if len(expected) >= max_files:
            raise CollectionError("Retained manifest exceeds its file limit")
        if isinstance(entry, RetainedFile):
            item = entry
        elif isinstance(entry, Mapping):
            try:
                item = RetainedFile(
                    path=entry["path"], locator=entry["locator"],
                    size_bytes=entry["size_bytes"], sha256=entry["sha256"],
                )
            except KeyError as error:
                raise CollectionError("Retained manifest is missing required ownership metadata") from error
        else:
            raise CollectionError("Retained manifest requires immutable file records")
        if not isinstance(item.path, str):
            raise CollectionError("Retained manifest paths must be strings")
        parts = item.path.split("/")
        if (
            not item.path or item.path.startswith("/") or "\x00" in item.path or "\\" in item.path
            or any(part in ("", ".", "..") for part in parts)
            or len(parts) > max_depth
        ):
            raise CollectionError("Retained manifest path contains traversal or exceeds its limit")
        try:
            if len(item.path.encode("utf-8")) > 4096 or any(len(part.encode("utf-8")) > 255 for part in parts):
                raise CollectionError("Retained manifest path exceeds byte limits")
        except UnicodeError as error:
            raise CollectionError("Retained manifest paths must be UTF-8 text") from error
        if item.locator != str(root / item.path):
            raise CollectionError("Retained locator does not belong to the assigned component root")
        if (
            type(item.size_bytes) is not int or item.size_bytes < 0 or item.size_bytes > max_file_bytes
            or not isinstance(item.sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", item.sha256)
        ):
            raise CollectionError("Retained manifest byte size or hash is invalid")
        total_bytes += item.size_bytes
        if total_bytes > max_total_bytes or item.path in expected:
            raise CollectionError("Retained manifest duplicates files or exceeds its byte limit")
        expected[item.path] = item
        allowed_directories.update("/".join(parts[:index]) for index in range(1, len(parts)))

    parent_fd = -1
    root_fd = -1
    collector = None
    try:
        import fcntl

        parent_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        for part in root.parts[1:-1]:
            try:
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent_fd,
                )
            except FileNotFoundError:
                return True
            os.close(parent_fd)
            parent_fd = child
        try:
            root_fd = os.open(
                root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            return True
        information = os.fstat(root_fd)
        if information.st_uid != os.geteuid() or information.st_mode & 0o077:
            raise CollectionError("The retained component directory must be privately owned")
        fcntl.flock(root_fd, fcntl.LOCK_EX)
        collector = SafeCollector(root, **bounds)
        reopened = os.fstat(collector._root_fd)
        if (information.st_dev, information.st_ino) != (reopened.st_dev, reopened.st_ino):
            raise CollectionError("Retained root changed before purge")
        actual = collector.collect()
        for item in actual:
            owned = expected.get(item.path)
            if owned is None or (owned.size_bytes, owned.sha256) != (item.size_bytes, item.sha256):
                raise CollectionError("Retained inventory does not match its immutable ownership manifest")

        directories: dict[str, tuple[int, int]] = {}
        identities: dict[str, tuple[int, int]] = {}
        count = 0

        def inventory(descriptor: int, prefix: tuple[str, ...]) -> None:
            nonlocal count
            with os.scandir(descriptor) as iterator:
                for entry in iterator:
                    count += 1
                    if count > max_entries:
                        raise CollectionError("Retained inventory exceeds its entry limit")
                    relative = "/".join((*prefix, entry.name))
                    item_stat = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
                    if stat.S_ISDIR(item_stat.st_mode):
                        if relative not in allowed_directories:
                            raise CollectionError("Retained inventory contains an unowned directory")
                        child = collector._directory(entry.name, descriptor)
                        try:
                            child_stat = os.fstat(child)
                            if child_stat.st_uid != os.geteuid() or child_stat.st_mode & 0o077:
                                raise CollectionError("Retained subdirectories must be privately owned")
                            directories[relative] = (child_stat.st_dev, child_stat.st_ino)
                            inventory(child, (*prefix, entry.name))
                        finally:
                            os.close(child)
                    else:
                        collector._validate_file(item_stat)
                        if item_stat.st_uid != os.geteuid() or relative not in expected:
                            raise CollectionError("Retained inventory contains an unowned file")
                        identities[relative] = (item_stat.st_dev, item_stat.st_ino)

        inventory(root_fd, ())

        def open_parent(relative: str) -> tuple[int, str]:
            parts = relative.split("/")
            descriptor = os.dup(root_fd)
            try:
                for part in parts[:-1]:
                    child = collector._directory(part, descriptor)
                    os.close(descriptor)
                    descriptor = child
                return descriptor, parts[-1]
            except BaseException:
                os.close(descriptor)
                raise

        for item in actual:
            descriptor, name = open_parent(item.path)
            try:
                content = collector._read_file(name, descriptor, max_file_bytes)
                if len(content) != item.size_bytes or hashlib.sha256(content).hexdigest() != item.sha256:
                    raise CollectionError("Retained file changed before deletion")
                item_stat = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                collector._validate_file(item_stat)
                if (item_stat.st_dev, item_stat.st_ino) != identities[item.path]:
                    raise CollectionError("Retained file ownership changed before deletion")
                os.unlink(name, dir_fd=descriptor)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        for relative in sorted(directories, key=lambda name: (-name.count("/"), name)):
            descriptor, name = open_parent(relative)
            try:
                item_stat = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(item_stat.st_mode)
                    or (item_stat.st_dev, item_stat.st_ino) != directories[relative]
                ):
                    raise CollectionError("Retained directory ownership changed before deletion")
                os.rmdir(name, dir_fd=descriptor)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        final_stat = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(final_stat.st_mode)
            or (final_stat.st_dev, final_stat.st_ino) != (information.st_dev, information.st_ino)
        ):
            raise CollectionError("Retained root ownership changed before deletion")
        os.rmdir(root.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        return True
    except (ImportError, OSError) as error:
        raise CollectionError("Retained output deletion could not be confirmed") from error
    finally:
        if collector is not None:
            collector.close()
        if root_fd >= 0:
            os.close(root_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
