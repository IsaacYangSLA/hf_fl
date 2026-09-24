"""Poll published references and run one recoverable client job at a time.

Provider notifications can eventually wake this controller, but readiness is
always established by resolving and validating the published model reference.
Publication has no portable idempotency contract: an interrupted attempt must
be reconciled explicitly before another upload is permitted.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import tempfile
import time
from pathlib import Path

from hf2l.common.fs import read_json, write_json
from hf2l.core.ports import ModelStore
from hf2l.core.protocol import CLIENT_CONTEXT_FILE, ROUND_FILE, ClientContext, RoundRecord
from hf2l.listener.workflow import download_round, submit_round, train_round, validate_submission


class ListenerStateError(ValueError):
    """Local state cannot safely be used with this listener configuration."""


class UncertainSubmission(RuntimeError):
    """A submission may exist remotely; automatic replay would risk duplicates."""


_STATUSES = {"pending", "downloading", "training", "ready", "publishing",
             "uncertain", "submitted", "skipped"}
_TERMINAL = {"submitted", "skipped"}


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _text(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ListenerStateError(f"{label} must be nonempty without surrounding whitespace")
    if len(value) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ListenerStateError(f"Invalid {label}")
    return value


class ClientListener:
    """One participant and reference, with durable local progress and a lock.

Use as a context manager. The caller owns the store and must close it. State is
bound to the effective provider endpoint and training configuration by hashes;
credentials and plugin options are never copied into the state document.
"""

    def __init__(self, store: ModelStore, *, repo_id: str, participant: str,
                 state_dir: Path, source_id: str, training_id: str, train_model,
                 options: dict | None = None, reference: str = "main", on_event=None):
        self.store = store
        self.repo_id = _text(repo_id, "repo_id")
        self.participant = _text(participant, "participant")
        self.reference = _text(reference, "reference")
        if not isinstance(source_id, str) or not source_id or not isinstance(training_id, str) or not training_id:
            raise ListenerStateError("source_id and training_id are required")
        if not callable(train_model):
            raise ListenerStateError("train_model must be callable")
        self.train_model = train_model
        self.options = json.loads(json.dumps({} if options is None else options, allow_nan=False))
        if not isinstance(self.options, dict):
            raise ListenerStateError("Training options must be a JSON object")
        self.root = Path(state_dir).expanduser().absolute()
        self.identity = {"backend": store.name, "repo_id": repo_id, "participant": participant,
                         "reference": reference, "source_hash": _digest(source_id),
                         "training_hash": _digest(json.dumps(
                             {"trainer": training_id, "options": self.options},
                             sort_keys=True, separators=(",", ":"), allow_nan=False))}
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
                # create fresh submissions for previously processed rounds.
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
            raise ListenerStateError("Listener state belongs to a different source, participant or training configuration")
        completed = state.get("completed_round")
        if type(completed) is not int or completed < -1 or not isinstance(state.get("jobs"), dict):
            raise ListenerStateError("Malformed listener state")
        nonterminal = []
        for revision, job in state["jobs"].items():
            if (not isinstance(revision, str) or not revision or not isinstance(job, dict)
                    or job.get("revision") != revision or not isinstance(job.get("status"), str)
                    or job["status"] not in _STATUSES):
                raise ListenerStateError("Malformed listener job")
            source_round = job.get("source_round")
            if source_round is not None and (type(source_round) is not int or source_round < 0):
                raise ListenerStateError("Malformed listener round")
            if source_round is None and job["status"] not in {"pending", "downloading"}:
                raise ListenerStateError("Listener job is missing its round")
            if job["status"] not in _TERMINAL:
                nonterminal.append(revision)
            if job["status"] == "submitted" and source_round > completed:
                raise ListenerStateError("Listener completion record is inconsistent")
        active = state.get("active")
        if (active is not None and (not isinstance(active, str) or active not in state["jobs"])):
            raise ListenerStateError("Malformed active listener job")
        if nonterminal != ([] if active is None else [active]):
            raise ListenerStateError("Listener active job is inconsistent")

    def _save(self):
        write_json(self._safe(self.root / "state.json"), self.state)

    def _require_open(self):
        if self._lock is None or self.state is None:
            raise ListenerStateError("Use ClientListener as a context manager")

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
        if status == "submitted":
            self.state["completed_round"] = max(self.state["completed_round"], job["source_round"])
        self.state["active"] = None
        self._save()
        self._emit(status, job)

    def _current_revision(self):
        revision = self.store.resolve_reference(self.repo_id, self.reference).revision
        return _text(revision, "resolved revision")

    def _round_metadata(self, revision):
        # Fetch only small metadata until a new round warrants a large transfer.
        with tempfile.TemporaryDirectory(prefix=".probe-", dir=self.root) as temporary:
            destination = Path(temporary)
            self.store.download_snapshot(self.repo_id, revision, destination, allow_patterns=ROUND_FILE)
            document = RoundRecord.from_dict(read_json(destination / ROUND_FILE))
        if document.schema_version >= 2 and document.to_dict().get("backend") != self.store.name:
            raise ValueError("Published round declares a different backend")
        return document.round

    def _is_current(self, job):
        if self._current_revision() == job["revision"]:
            return True
        self._finish(job, "skipped", reason="reference_advanced")
        return False

    def _check_context(self, job, work_dir):
        """A resumed job must not silently use another round's local context."""
        try:
            context = ClientContext.from_dict(read_json(self._safe(work_dir / CLIENT_CONTEXT_FILE)))
        except ValueError as exc:
            raise ListenerStateError("Saved listener context is invalid; preserve the job for recovery") from exc
        expected = (self.store.name, self.repo_id, job["revision"], job["source_round"], "base_model")
        actual = (context.backend, context.repo_id, context.base_revision,
                  context.source_round, context.base_model_dir)
        if actual != expected:
            raise ListenerStateError("Saved client context does not match the scheduled listener job")

    def poll_once(self) -> str:
        """Reconcile current state and submit at most one newly eligible round."""
        self._require_open()
        active = self.state["active"]
        job = self.state["jobs"].get(active)
        if job and job["status"] in {"publishing", "uncertain"}:
            raise UncertainSubmission("Submission outcome is unknown; reconcile it and use --resolve-uncertain submitted or retry")
        revision = self._current_revision()
        if job and job["revision"] != revision:
            self._finish(job, "skipped", reason="reference_advanced")
            job = None
        if job is None:
            if revision in self.state["jobs"]:
                self._emit("idle")
                return "idle"
            source_round = self._round_metadata(revision)
            job = {"revision": revision, "source_round": source_round, "status": "pending"}
            self.state["jobs"][revision] = job
            self.state["active"] = revision
            self._save()
            if source_round <= self.state["completed_round"]:
                self._finish(job, "skipped", reason="round_already_completed")
                return "skipped"

        job_dir = self._job_dir(job)
        work_dir = self._safe(job_dir / "work")
        if job["status"] in {"pending", "downloading"}:
            self._set_status(job, "downloading")
            self._remove_owned(work_dir)
            context = download_round(self.store, self.repo_id, revision, work_dir)
            if context["source_round"] != job["source_round"]:
                raise ValueError("Pinned round metadata changed during download")
            if not self._is_current(job):
                return "skipped"
            self._set_status(job, "training")

        if job["status"] == "training":
            if not self._is_current(job):
                return "skipped"
            self._check_context(job, work_dir)
            self._remove_owned(work_dir / "trained_model")
            self._emit("training", job)
            metadata = train_round(self.train_model, self.options, self.participant, work_dir)
            write_json(self._safe(job_dir / "training-result.json"), metadata)
            self._set_status(job, "ready")

        if not self._is_current(job):
            return "skipped"
        self._check_context(job, work_dir)
        metadata = read_json(self._safe(job_dir / "training-result.json"))
        validate_submission(work_dir, self.participant, metadata)
        # Persist BEFORE calling any remote write. Even process termination or
        # an exception after a successful write leaves a visible recovery fence.
        self._set_status(job, "publishing")
        self._emit("publishing", job)
        try:
            result = submit_round(self.store, work_dir, self.participant, metadata)
        except Exception as exc:
            self._set_status(job, "uncertain")
            self._emit("uncertain", job, error_type=type(exc).__name__)
            raise UncertainSubmission("Submission outcome is unknown; inspect the remote submission before explicit recovery") from exc
        self._finish(job, "submitted", result=result)
        return "submitted"

    def resolve_uncertain(self, action: str) -> None:
        """Record the operator's remote reconciliation, without guessing it."""
        self._require_open()
        if action not in {"submitted", "retry"}:
            raise ListenerStateError("Recovery action must be submitted or retry")
        active = self.state["active"]
        job = self.state["jobs"].get(active)
        if not job or job["status"] not in {"publishing", "uncertain"}:
            raise ListenerStateError("No uncertain submission needs recovery")
        if action == "submitted":
            self._finish(job, "submitted", reconciled=True)
        else:
            self._set_status(job, "ready")
            self._emit("retry_authorized", job)

    def run(self, *, poll_interval: float = 30, max_backoff: float = 300,
            once: bool = False, max_rounds: int | None = None) -> int:
        """Poll with bounded exponential backoff for safe read/training failures.

Unknown upload outcomes and state failures stop immediately. ``max_rounds``
counts successful submissions in this invocation, not historical completions.
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
            except (UncertainSubmission, ListenerStateError):
                raise
            except Exception as exc:
                if once:
                    raise
                self._emit("retry", error_type=type(exc).__name__, retry_seconds=delay)
                time.sleep(delay)
                delay = min(delay * 2, max_backoff)
                continue
            delay = poll_interval
            completed += outcome == "submitted"
            if once or (max_rounds is not None and completed >= max_rounds):
                return completed
            time.sleep(poll_interval)
