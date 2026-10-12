"""Bounded redacted execution logs with restart-safe byte cursors.

The node owns a capped append-only canonical stream inside its reserved log
allowance. Managed admission prepays one MiB of database logs per execution;
bounded chunks consume that budget and advance a durable cursor in one
transaction. Legacy streams charge actual bytes. No caller supplies a path.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Callable

from sqlalchemy import func, select

from .domain import Error, utcnow
from .executor import ExecutionIdentity, ExecutorRefused
from .models import Allocation, Attempt, Job, LogChunk, Project
from .retention import RetentionService, utc

MAX_LOG_CHUNK_BYTES = 65536
MAX_CANONICAL_LOG_BYTES = 1024 * 1024
_LOG_GAP = b"\n[log capture gap: earlier rotated output unavailable]\n"
_LOG_LIMIT = b"\n[log output truncated at the execution log limit]\n"


@dataclass(frozen=True)
class LogIngestResult:
    status: str
    chunks: int = 0
    bytes: int = 0
    complete: bool = False
    truncated: bool = False


class CanonicalLogSpool:
    """Append redacted timestamped Docker snapshots under an owned node root.

    The executor must serialize calls with its execution lock, validate the
    container identity, and redact the whole bounded snapshot before calling
    ``update``. A lost rotation overlap is disclosed. Repeated snapshots and
    process restarts never append the same snapshot a second time. Both files
    remain within the existing four MiB daemon/canonical log allowance.
    """
    def __init__(self, root, *, max_bytes=MAX_CANONICAL_LOG_BYTES - 65536):
        if type(max_bytes) is not int or not 256 <= max_bytes <= MAX_CANONICAL_LOG_BYTES:
            raise ValueError("Invalid canonical log limit")
        self.root = Path(root)
        if not self.root.is_absolute() or any(p.is_symlink() for p in (self.root, *self.root.parents)):
            raise ExecutorRefused("Log root is not an owned directory", "unsafe_log_root")
        self.root.mkdir(mode=0o700, exist_ok=True)
        info = self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ExecutorRefused("Log root must remain private", "unsafe_log_root")
        self.max_bytes = max_bytes

    def _directory(self):
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            os.close(descriptor)
            raise ExecutorRefused("Log root changed", "unsafe_log_root")
        return descriptor

    @staticmethod
    def _file(directory, name, flags, *, maximum):
        descriptor = os.open(name, flags | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > maximum):
            os.close(descriptor)
            raise ExecutorRefused("Log file is not an owned bounded regular file", "unsafe_log_file")
        return descriptor

    def _metadata(self, directory):
        try:
            descriptor = self._file(directory, "cursor.json", os.O_RDONLY, maximum=32768)
        except FileNotFoundError:
            return {}
        try:
            raw = os.read(descriptor, 32769)
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("Invalid cursor")
            return data
        except (ValueError, UnicodeError):
            raise ExecutorRefused("Canonical log cursor is invalid", "unsafe_log_file") from None
        finally:
            os.close(descriptor)

    def update(self, redacted_snapshot: str | bytes, *, complete=False):
        if type(complete) is not bool:
            raise ValueError("Invalid completion flag")
        if isinstance(redacted_snapshot, bytes):
            snapshot = redacted_snapshot.decode("utf-8", errors="replace").encode("utf-8")
        elif isinstance(redacted_snapshot, str):
            snapshot = redacted_snapshot.encode("utf-8", errors="replace")
        else:
            raise ValueError("Log snapshot must be redacted text")
        if len(snapshot) > 4 * 1024 * 1024:
            raise ExecutorRefused("Log snapshot exceeds its node bound", "log_snapshot_exceeds_bound")
        directory = self._directory()
        try:
            metadata = self._metadata(directory)
            descriptor = self._file(directory, "stdout.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                                    maximum=self.max_bytes)
            try:
                length = os.fstat(descriptor).st_size
                # Recover an interrupted append by truncating to the last
                # fsynced cursor. Bytes exposed to the manager never precede it.
                committed = metadata.get("length", 0)
                if type(committed) is not int or not 0 <= committed <= length:
                    raise ExecutorRefused("Canonical log cursor changed", "unsafe_log_file")
                if length != committed:
                    os.ftruncate(descriptor, committed)
                    length = committed
                digest = hashlib.sha256(snapshot).hexdigest()
                addition = b""
                truncated = bool(metadata.get("truncated", False))
                if metadata.get("snapshot_sha256") != digest and not metadata.get("limited"):
                    previous_length = metadata.get("snapshot_length", 0)
                    previous_digest = metadata.get("snapshot_sha256")
                    if (previous_digest and type(previous_length) is int and previous_length <= len(snapshot)
                            and hashlib.sha256(snapshot[:previous_length]).hexdigest() == previous_digest):
                        addition = snapshot[previous_length:]
                    elif previous_digest:
                        anchor = metadata.get("snapshot_anchor", "").encode("utf-8")
                        entry_length = metadata.get("snapshot_entry_length", 0)
                        index = snapshot.rfind(anchor) if anchor else -1
                        if (index >= 0 and type(entry_length) is int and entry_length > 0
                                and hashlib.sha256(snapshot[index:index + entry_length]).hexdigest()
                                    == metadata.get("snapshot_entry_sha256")):
                            addition = snapshot[index + entry_length:]
                        else:
                            addition = _LOG_GAP + snapshot
                            truncated = True
                    else:
                        addition = snapshot
                room = self.max_bytes - length
                limited = bool(metadata.get("limited", False))
                if len(addition) > room:
                    limited = truncated = True
                    room = max(0, room - len(_LOG_LIMIT))
                    addition = addition[:room].decode("utf-8", errors="ignore").encode("utf-8")
                    if self.max_bytes - length - len(addition) >= len(_LOG_LIMIT):
                        addition += _LOG_LIMIT
                if addition:
                    view = memoryview(addition)
                    while view:
                        written = os.write(descriptor, view)
                        view = view[written:]
                    os.fsync(descriptor)
                last_start = snapshot.rstrip(b"\n").rfind(b"\n") + 1
                last_entry = snapshot[last_start:]
                metadata = {"length": length + len(addition), "snapshot_sha256": digest,
                    "snapshot_length": len(snapshot),
                    "snapshot_anchor": last_entry[:256].decode("utf-8", errors="ignore"),
                    "snapshot_entry_length": len(last_entry),
                    "snapshot_entry_sha256": hashlib.sha256(last_entry).hexdigest(),
                    "complete": complete or bool(metadata.get("complete")),
                    "truncated": truncated, "limited": limited}
            finally:
                os.close(descriptor)
            self._save_metadata(directory, metadata)
        finally:
            os.close(directory)

    def _save_metadata(self, directory, metadata):
        temporary = "cursor.pending"
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        descriptor = self._file(directory, temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, maximum=32768)
        try:
            raw = json.dumps(metadata, ensure_ascii=False, sort_keys=True).encode("utf-8")
            if len(raw) > 32768:
                raise ExecutorRefused("Canonical log cursor exceeds bound", "unsafe_log_file")
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, "cursor.json", src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)

    def mark_complete(self):
        # Seal an already captured stream after confirmed container removal.
        directory = self._directory()
        try:
            metadata = self._metadata(directory)
            metadata["complete"] = True
            metadata.setdefault("length", 0)
            self._save_metadata(directory, metadata)
        finally:
            os.close(directory)

    def read(self, identity: ExecutionIdentity, offset=0, max_bytes=MAX_LOG_CHUNK_BYTES):
        if type(offset) is not int or offset < 0 or type(max_bytes) is not int or not 4 <= max_bytes <= MAX_LOG_CHUNK_BYTES:
            raise ValueError("Invalid log byte range")
        directory = self._directory()
        try:
            metadata = self._metadata(directory)
            length = metadata.get("length", 0)
            if type(length) is not int or not 0 <= offset <= length <= self.max_bytes:
                raise ExecutorRefused("Log byte cursor changed", "log_cursor_conflict")
            try:
                descriptor = self._file(directory, "stdout.log", os.O_RDONLY, maximum=self.max_bytes)
            except FileNotFoundError:
                if length:
                    raise ExecutorRefused("Canonical log is missing", "unsafe_log_file") from None
                raw = b""
            else:
                try:
                    raw = os.pread(descriptor, min(max_bytes, length - offset), offset)
                    if len(raw) != min(max_bytes, length - offset):
                        raise ExecutorRefused("Canonical log changed", "unsafe_log_file")
                finally:
                    os.close(descriptor)
            try:
                content = raw.decode("utf-8")
            except UnicodeDecodeError as error:
                if error.reason != "unexpected end of data":
                    raise ExecutorRefused("Log cursor does not point to a UTF8 boundary", "log_cursor_conflict") from None
                raw = raw[:error.start]
                content = raw.decode("utf-8")
            next_offset = offset + len(raw)
            return {"identity": asdict(identity), "source_id": identity.key, "offset": offset,
                "next_offset": next_offset, "content": content,
                "complete": bool(metadata.get("complete")) and next_offset == length,
                "truncated": bool(metadata.get("truncated"))}
        finally:
            os.close(directory)



def _log_stamp(session, job_id, clock):
    # Public log pages use (created_at,id). A monotonically increasing ingest
    # time preserves source byte order even for a frozen clock, same-microsecond
    # batches and a controller restart. The project lock serializes writers.
    stamp = utc(clock())
    previous = session.scalar(select(func.max(LogChunk.created_at)).where(LogChunk.job_id == job_id))
    if previous is not None and stamp <= utc(previous):
        stamp = utc(previous) + timedelta(microseconds=1)
    return stamp


def _validate_receipt(receipt, identity, offset):
    if (not isinstance(receipt, dict) or receipt.get("identity") != asdict(identity)
            or receipt.get("source_id") != identity.key or type(receipt.get("offset")) is not int
            or receipt["offset"] != offset or type(receipt.get("next_offset")) is not int
            or not isinstance(receipt.get("content"), str)
            or type(receipt.get("complete")) is not bool or type(receipt.get("truncated")) is not bool):
        raise ExecutorRefused("Node log receipt differs from owned execution", "invalid_log_receipt")
    size = len(receipt["content"].encode("utf-8"))
    if (size > MAX_LOG_CHUNK_BYTES or receipt["next_offset"] != offset + size
            or receipt["next_offset"] > MAX_CANONICAL_LOG_BYTES):
        raise ExecutorRefused("Node log receipt exceeds bounds", "invalid_log_receipt")
    return size



def _owned_log_budget(session, holder, job, attempt):
    from .models import ProvisioningResource
    resource_id = (holder.details_json or {}).get("log_resource_id")
    if resource_id is None:
        return None
    if not isinstance(resource_id, str) or not resource_id:
        raise Error(409, "retained_log_budget_ownership_mismatch")
    budget = session.scalar(select(ProvisioningResource).where(ProvisioningResource.id == resource_id)
        .with_for_update())
    if (budget is None or budget.kind != "log_budget" or budget.job_id != job.id
            or budget.attempt_id != attempt.id or budget.component_id != holder.component_id
            or budget.external_id != "hf2l-log://" + job.id + "/" + str(attempt.number) + "/" + holder.component_id
            or budget.ownership_json.get("job_id") != job.id
            or budget.ownership_json.get("component_id") != holder.component_id
            or budget.ownership_json.get("kind") != "log_budget"
            or (budget.details_json or {}).get("attempt_number") != attempt.number
            or (budget.details_json or {}).get("component_id") != holder.component_id):
        raise Error(409, "retained_log_budget_ownership_mismatch")
    return budget


def _charge_log(session, project, chunk, budget):
    if budget is None:
        RetentionService.charge_log_in_transaction(session, project, chunk)
    else:
        RetentionService.charge_log_in_transaction(session, project, chunk, budget=budget)
    return len(chunk.data.encode("utf-8"))


def ingest_component_logs(database, executor, allocation, *, clock: Callable[[], datetime] = utcnow,
                          terminal=False, max_chunks=1):
    """Read owned node logs without holding SQL locks; commit bytes and cursor.

    Released allocations remain valid historical sources until raw retention is
    requested. The immutable allocation node affinity is retained for routing.
    A concurrent poll that lost the cursor compare-and-swap writes nothing.
    """
    if type(max_chunks) is not int or not 1 <= max_chunks <= 32:
        raise ValueError("Invalid log catch-up bound")
    reader = getattr(executor, "read_logs", None)
    if reader is None:
        return LogIngestResult("unavailable")
    allocation_id = allocation if isinstance(allocation, str) else allocation.id
    chunks = copied = 0
    complete = truncated = False
    for _ in range(max_chunks):
        with database.transaction(immediate=False) as session:
            row = session.get(Allocation, allocation_id)
            if row is None:
                return LogIngestResult("unavailable", chunks, copied, complete, truncated)
            job = session.get(Job, row.job_id)
            if (job is None or job.purged_at is not None or job.cleanup_status in
                    {"purge_pending", "expiry_pending", "expired"}
                    or (job.artifacts_expire_at is not None and utc(job.artifacts_expire_at) <= utc(clock()))):
                return LogIngestResult("expired", chunks, copied, complete, truncated)
            identity = ExecutionIdentity(row.job_id, row.attempt_id, row.component_id, row.epoch)
            cursor = dict((row.details_json or {}).get("log_stream", {}))
            if cursor.get("source_id", identity.key) != identity.key:
                raise ExecutorRefused("Stored log source differs from execution", "log_cursor_conflict")
            offset = cursor.get("offset", 0)
            if type(offset) is not int or not 0 <= offset <= MAX_CANONICAL_LOG_BYTES:
                raise ExecutorRefused("Stored log cursor is invalid", "log_cursor_conflict")
            if cursor.get("complete"):
                return LogIngestResult("complete", chunks, copied, True, bool(cursor.get("truncated")))
            project_id = job.project_id
        receipt = reader(identity, offset=offset, max_bytes=MAX_LOG_CHUNK_BYTES)
        size = _validate_receipt(receipt, identity, offset)
        try:
            with database.transaction() as session:
                project = session.scalar(select(Project).where(Project.id == project_id).with_for_update())
                job = session.scalar(select(Job).where(Job.id == identity.job_id).with_for_update())
                row = session.scalar(select(Allocation).where(Allocation.id == allocation_id).with_for_update())
                if (project is None or job is None or row is None or row.job_id != identity.job_id
                        or row.attempt_id != identity.attempt_id or row.component_id != identity.component_id
                        or row.epoch != identity.epoch or job.purged_at is not None
                        or job.cleanup_status in {"purge_pending", "expiry_pending", "expired"}
                        or (job.artifacts_expire_at is not None and utc(job.artifacts_expire_at) <= utc(clock()))):
                    return LogIngestResult("expired", chunks, copied, complete, truncated)
                current = dict((row.details_json or {}).get("log_stream", {}))
                if current.get("offset", 0) != offset or current.get("source_id", identity.key) != identity.key:
                    return LogIngestResult("concurrent_poll", chunks, copied, complete, truncated)
                stored_size = 0
                budget = None
                if size:
                    attempt = session.get(Attempt, identity.attempt_id)
                    if attempt is None or attempt.job_id != identity.job_id or attempt.epoch != identity.epoch:
                        raise ExecutorRefused("Log attempt is not owned", "invalid_log_receipt")
                    budget = _owned_log_budget(session, row, job, attempt)
                    sequence = (session.scalar(select(func.max(LogChunk.sequence)).where(
                        LogChunk.job_id == identity.job_id, LogChunk.component == identity.component_id)) or 0) + 1
                    chunk = LogChunk(job_id=identity.job_id, attempt_number=attempt.number,
                        component=identity.component_id, sequence=sequence, data=receipt["content"],
                        created_at=_log_stamp(session, identity.job_id, clock), expires_at=job.artifacts_expire_at)
                    session.add(chunk)
                    stored_size = _charge_log(session, project, chunk, budget)
                dropped = size - stored_size
                budget_exhausted = bool(current.get("budget_exhausted")) or dropped > 0
                row.details_json = {**(row.details_json or {}), "log_stream": {
                    "source_id": identity.key, "offset": receipt["next_offset"],
                    "complete": receipt["complete"], "truncated": receipt["truncated"] or budget_exhausted,
                    "dropped_bytes": current.get("dropped_bytes", 0) + dropped,
                    "budget_exhausted": budget_exhausted}}
        except Error as error:
            if error.code == "retained_storage_quota_exceeded":
                return LogIngestResult("quota_exceeded", chunks, copied, complete, truncated)
            raise
        chunks += bool(stored_size)
        copied += stored_size
        complete, truncated = receipt["complete"], receipt["truncated"] or budget_exhausted
        if complete or not size or not terminal:
            break
    return LogIngestResult("limit_reached" if budget_exhausted else "complete" if complete else "caught_up" if not size else "more_available",
                           chunks, copied, complete, truncated)


def append_external_logs(database, identity, receipt, *, resource_id, node_id, clock=utcnow):
    """Commit an authorized external helper receipt against its owned ledger.

    The participant service authenticates current mTLS/node authorization before
    calling this function. This second ownership check binds the historical
    execution resource and immutable approved node. A repeated request returns
    the durable cursor without inserting or charging another copy.
    """
    from .models import ProvisioningResource
    if not isinstance(identity, ExecutionIdentity) or not isinstance(node_id, str) or not node_id:
        raise Error(422, "invalid_log_identity")
    offset = receipt.get("offset") if isinstance(receipt, dict) else None
    if type(offset) is not int or not 0 <= offset <= MAX_CANONICAL_LOG_BYTES:
        raise Error(422, "invalid_log_cursor")
    size = _validate_receipt(receipt, identity, offset)
    with database.transaction() as session:
        project_id = session.scalar(select(Job.project_id).where(Job.id == identity.job_id))
        if project_id is None:
            raise Error(404, "participant_assignment_not_found")
        project = session.scalar(select(Project).where(Project.id == project_id).with_for_update())
        job = session.scalar(select(Job).where(Job.id == identity.job_id).with_for_update())
        resource = session.scalar(select(ProvisioningResource).where(ProvisioningResource.id == resource_id)
            .with_for_update())
        attempt = session.get(Attempt, identity.attempt_id)
        if (resource is None or attempt is None or attempt.job_id != identity.job_id
                or attempt.epoch != identity.epoch or resource.kind != "external_execution"
                or resource.job_id != identity.job_id or resource.attempt_id != identity.attempt_id
                or resource.component_id != identity.component_id or resource.external_id != identity.key
                or resource.ownership_json.get("job_id") != identity.job_id
                or resource.ownership_json.get("attempt_id") != identity.attempt_id
                or resource.ownership_json.get("component_id") != identity.component_id
                or resource.details_json.get("node_id") != node_id
                or resource.details_json.get("epoch") != identity.epoch
                or resource.state == "deleted" or resource.deleted_at is not None):
            raise Error(404, "participant_assignment_not_found")
        if (job.purged_at is not None or job.cleanup_status in {"purge_pending", "expiry_pending", "expired"}
                or (job.artifacts_expire_at is not None and utc(job.artifacts_expire_at) <= utc(clock()))):
            raise Error(410, "job_logs_expired")
        current = dict((resource.details_json or {}).get("log_stream", {}))
        stored_offset = current.get("offset", 0)
        if (current.get("source_id", identity.key) != identity.key or type(stored_offset) is not int
                or not 0 <= stored_offset <= MAX_CANONICAL_LOG_BYTES):
            raise Error(409, "log_cursor_conflict")
        if offset < stored_offset and receipt["next_offset"] <= stored_offset:
            return {"accepted": True, "next_offset": stored_offset,
                    "complete": bool(current.get("complete")), "truncated": bool(current.get("truncated"))}
        if offset != stored_offset:
            raise Error(409, "log_cursor_conflict", {"next_offset": stored_offset})
        if current.get("complete") and size:
            raise Error(409, "log_stream_already_complete")
        stored_size = 0
        if size:
            budget = _owned_log_budget(session, resource, job, attempt)
            sequence = (session.scalar(select(func.max(LogChunk.sequence)).where(
                LogChunk.job_id == identity.job_id, LogChunk.component == identity.component_id)) or 0) + 1
            chunk = LogChunk(job_id=identity.job_id, attempt_number=attempt.number,
                component=identity.component_id, sequence=sequence, data=receipt["content"],
                created_at=_log_stamp(session, identity.job_id, clock), expires_at=job.artifacts_expire_at)
            session.add(chunk)
            stored_size = _charge_log(session, project, chunk, budget)
        dropped = size - stored_size
        budget_exhausted = bool(current.get("budget_exhausted")) or dropped > 0
        complete = receipt["complete"] or bool(current.get("complete"))
        truncated = receipt["truncated"] or bool(current.get("truncated")) or budget_exhausted
        resource.details_json = {**resource.details_json, "log_stream": {
            "source_id": identity.key, "offset": receipt["next_offset"],
            "complete": complete, "truncated": truncated,
            "dropped_bytes": current.get("dropped_bytes", 0) + dropped,
            "budget_exhausted": budget_exhausted}}
        return {"accepted": True, "next_offset": receipt["next_offset"],
                "complete": complete, "truncated": truncated}
