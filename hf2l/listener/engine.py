"""Durable execution shared by client, owner, and other polling workflows.

A subclass decides which work is ready and performs one reconciliation in
``poll_once``. The engine owns locking, configuration binding, state persistence,
retry pacing, and completion counting. Persisted job keys retain the version-one
names ``revision`` and ``source_round`` for compatibility with client listeners;
they identify an immutable input and its nonnegative sequence number.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import time
from abc import ABC, abstractmethod
from pathlib import Path

from hf2l.common.fs import read_json, write_json


class ListenerStateError(ValueError):
    """Local state cannot safely be used with this listener configuration."""


class UncertainOperation(RuntimeError):
    """A remote write may have succeeded and must be reconciled before retrying."""


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _text(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ListenerStateError(f"{label} must be nonempty without surrounding whitespace")
    if len(value) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ListenerStateError(f"Invalid {label}")
    return value


class DurableListener(ABC):
    """Single-worker durable polling with workflow-specific job states.

Use as a context manager. Subclasses must bind all behavior-affecting settings,
including their role, in ``identity``. Exceptions whose remote effects are unknown
must derive from ``UncertainOperation`` so the run loop never retries them.
"""

    statuses = {"pending", "downloading", "publishing", "uncertain", "completed", "skipped"}
    terminal_statuses = {"completed", "skipped"}
    success_status = "completed"
    round_optional_statuses = {"pending", "downloading"}
    uncertain_statuses = {"publishing", "uncertain"}

    def __init__(self, *, state_dir: Path, identity: dict, on_event=None):
        if not isinstance(identity, dict):
            raise ListenerStateError("Listener identity must be a JSON object")
        self.root = Path(state_dir).expanduser().absolute()
        self.identity = json.loads(json.dumps(identity, allow_nan=False))
        self.on_event = on_event
        self.state = None
        self._lock = None

    def _emit(self, event, job=None, **fields):
        if self.on_event is not None:
            details = {"event": event, **fields}
            if job is not None:
                details.update({key: job[key] for key in ("revision", "source_round", "status")})
            self.on_event(details)

    def _safe(self, path: Path) -> Path:
        """Reject symlinks in listener-owned paths, including their parents."""
        for candidate in (path, *path.parents):
            if candidate.is_symlink():
                raise ListenerStateError("Listener state paths must not contain symlinks")
        return path

    def __enter__(self):
        if self._lock is not None:
            raise ListenerStateError("Listener is already open")
        if os.name != "posix":
            raise ListenerStateError("Listener state currently requires POSIX advisory filesystem locks")
        import fcntl

        self._safe(self.root).mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_path = self._safe(self.root / ".lock")
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        self._lock = os.fdopen(descriptor, "a+b")
        try:
            try:
                fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ListenerStateError("Another listener owns this state directory") from exc
            path = self._safe(self.root / "state.json")
            if path.exists():
                try:
                    self.state = read_json(path)
                except ValueError as exc:
                    raise ListenerStateError("Cannot read listener state; preserve it for recovery") from exc
                self._validate_state()
            else:
                # Losing state while keeping job artifacts must not silently
                # repeat remote operations for previously processed inputs.
                jobs = self._safe(self.root / "jobs")
                if jobs.exists() and any(jobs.iterdir()):
                    raise ListenerStateError("Job artifacts exist without state.json; restore the saved state")
                self.state = {"schema_version": 1, "identity": self.identity,
                              "completed_round": -1, "active": None, "jobs": {}}
                self._save()
            self._safe(self.root / "jobs").mkdir(exist_ok=True, mode=0o700)
            active = self.state["active"]
            if active and self.state["jobs"][active]["status"] == "publishing":
                self.state["jobs"][active]["status"] = "uncertain"
                self._save()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        if self._lock is not None:
            self._lock.close()
            self._lock = None
        self.state = None

    def _validate_state(self):
        state = self.state
        if type(state.get("schema_version")) is not int or state["schema_version"] != 1 or state.get("identity") != self.identity:
            raise ListenerStateError("Listener state belongs to a different role, source, participant or workflow configuration")
        completed = state.get("completed_round")
        if type(completed) is not int or completed < -1 or not isinstance(state.get("jobs"), dict):
            raise ListenerStateError("Malformed listener state")
        nonterminal = []
        for revision, job in state["jobs"].items():
            if (not isinstance(revision, str) or not revision or not isinstance(job, dict)
                    or job.get("revision") != revision or not isinstance(job.get("status"), str)
                    or job["status"] not in self.statuses):
                raise ListenerStateError("Malformed listener job")
            source_round = job.get("source_round")
            if source_round is not None and (type(source_round) is not int or source_round < 0):
                raise ListenerStateError("Malformed listener round")
            if source_round is None and job["status"] not in self.round_optional_statuses:
                raise ListenerStateError("Listener job is missing its round")
            if job["status"] not in self.terminal_statuses:
                nonterminal.append(revision)
            if job["status"] == self.success_status and source_round > completed:
                raise ListenerStateError("Listener completion record is inconsistent")
        active = state.get("active")
        if (active is not None and (not isinstance(active, str) or active not in state["jobs"])):
            raise ListenerStateError("Malformed active listener job")
        if nonterminal != ([] if active is None else [active]):
            raise ListenerStateError("Listener active job is inconsistent")

    def _save(self):
        try:
            write_json(self._safe(self.root / "state.json"), self.state)
        except (OSError, ValueError) as exc:
            raise ListenerStateError("Cannot persist listener state; preserve it for recovery") from exc

    def _require_open(self):
        if self._lock is None or self.state is None:
            raise ListenerStateError("Use the listener as a context manager")

    def _job_dir(self, job):
        path = self._safe(self.root / "jobs" / _digest(job["revision"]))
        path.mkdir(exist_ok=True, mode=0o700)
        return path

    def _remove_owned(self, path):
        self._safe(path)
        if path.exists():
            if not path.is_dir():
                raise ListenerStateError("Expected an owned listener work directory")
            shutil.rmtree(path)

    def _set_status(self, job, status):
        job["status"] = status
        self._save()

    def _finish(self, job, status, **fields):
        job.update(status=status, **fields)
        if status == self.success_status:
            self.state["completed_round"] = max(self.state["completed_round"], job["source_round"])
        self.state["active"] = None
        self._save()
        self._emit(status, job)

    @abstractmethod
    def poll_once(self) -> str:
        """Reconcile one job and return its outcome, or raise a safe failure."""

    def run(self, *, poll_interval: float = 30, max_backoff: float = 300,
            once: bool = False, max_rounds: int | None = None) -> int:
        """Poll with bounded exponential backoff for safe workflow failures.

Unknown remote operation outcomes and state failures stop immediately. ``max_rounds``
counts successful jobs in this invocation, not historical completions.
"""
        self._require_open()
        if (not math.isfinite(poll_interval) or poll_interval <= 0
                or not math.isfinite(max_backoff) or max_backoff < poll_interval):
            raise ValueError("Poll interval must be positive and max backoff at least the poll interval")
        if max_rounds is not None and (type(max_rounds) is not int or max_rounds <= 0):
            raise ValueError("max_rounds must be a positive integer")
        completed, delay = 0, poll_interval
        while True:
            try:
                outcome = self.poll_once()
            except (UncertainOperation, ListenerStateError):
                raise
            except Exception as exc:
                if once:
                    raise
                self._emit("retry", error_type=type(exc).__name__, retry_seconds=delay)
                time.sleep(delay)
                delay = min(delay * 2, max_backoff)
                continue
            delay = poll_interval
            completed += outcome == self.success_status
            if once or (max_rounds is not None and completed >= max_rounds):
                return completed
            time.sleep(poll_interval)
