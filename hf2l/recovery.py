"""Participant-owned checkpoint storage for explicitly recoverable trainers."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import warnings


_FORMAT = 1
_DEFAULT_BYTES = 4 * 1024 ** 3
_DEFAULT_FILES = 1024
_MAX_RECORD = 8 * 1024 ** 2
_DIGEST = re.compile(r"[0-9a-f]{64}")
_STEP = re.compile(r"step-(0|[1-9][0-9]{0,18})")


class RecoveryError(RuntimeError):
    """Recovery state is unavailable, incompatible, or unsafe to advance."""


class TrainingPaused(RecoveryError):
    """A trainer stopped at a saved update boundary."""

    def __init__(self, completed_steps: int):
        super().__init__(f"Training paused after {completed_steps} completed steps")
        self.completed_steps = completed_steps


class TrainingCancelled(RecoveryError):
    """This work was cancelled by its participant."""


@dataclass(frozen=True)
class Checkpoint:
    path: Path
    step: int
    generation: int


@dataclass(frozen=True)
class Attempt:
    generation: int
    checkpoint: Path | None
    completed_steps: int


@dataclass(frozen=True)
class ReadyResult:
    output_dir: Path
    metadata: dict
    fingerprint: str


def _json(value):
    try:
        return json.dumps(
            value, allow_nan=False, sort_keys=True, separators=(",", ":"),
        ).encode()
    except (TypeError, ValueError, UnicodeError) as exc:
        raise RecoveryError("Recovery data must be finite JSON") from exc


def _object(value):
    if not isinstance(value, dict) or any(not isinstance(k, str) for k in value):
        raise RecoveryError("Recovery data must be a JSON object with string keys")
    data = _json(value)
    if len(data) > _MAX_RECORD:
        raise RecoveryError("Recovery record exceeds its size limit")
    return json.loads(data)


def _digest(value):
    return hashlib.sha256(_json(value)).hexdigest()


def _number(value, minimum=0):
    if type(value) is not int or not minimum <= value < 10 ** 19:
        raise RecoveryError("Invalid recovery counter or size")
    return value


def _limits(max_bytes, max_files):
    _number(max_bytes, 1)
    _number(max_files, 1)
    if max_files > 4096:
        raise RecoveryError("Recovery storage supports at most 4096 entries per artifact")
    return {"max_bytes": max_bytes, "max_files": max_files}


def _directory(path):
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise RecoveryError("Recovery directory must not be a link or special file")


def _fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def _regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RecoveryError("Recovery files must be regular, unlinked files")
        yield handle


def _read(path):
    try:
        with _regular(path) as handle:
            data = handle.read(_MAX_RECORD + 1)
        if len(data) > _MAX_RECORD:
            raise RecoveryError("Recovery record exceeds its size limit")
        value = json.loads(data)
        if not isinstance(value, dict):
            raise RecoveryError("Recovery record is not a JSON object")
        _json(value)
        return value
    except (ValueError, UnicodeError) as exc:
        raise RecoveryError("Invalid recovery record") from exc


def _write(path, value):
    data = _json(value)
    if len(data) > _MAX_RECORD:
        raise RecoveryError("Recovery record exceeds its size limit")
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".record-", delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
            os.replace(temporary, path)
            _fsync_dir(path.parent)
        finally:
            temporary.unlink(missing_ok=True)


@contextmanager
def _lock(path, *, nonblocking=False):
    import fcntl

    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RecoveryError("Invalid recovery lock file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
        except BlockingIOError as exc:
            raise RecoveryError("A supervisor already owns this training work") from exc
        yield
    finally:
        os.close(fd)


@contextmanager
def _stage(parent):
    directory = Path(tempfile.mkdtemp(prefix=".stage-", dir=parent))
    try:
        yield directory
    finally:
        if directory.exists():
            shutil.rmtree(directory)


def _promote(stage, destination):
    _fsync_dir(stage)
    os.rename(stage, destination)
    _fsync_dir(destination.parent)


def _check_capacity(directory, files):
    if sum(item["size"] for item in files.values()) > shutil.disk_usage(directory).free:
        raise RecoveryError("Recovery storage is full; the prior saved state is preserved")


def _file_entry(source, *, limit, destination=None, sync=False):
    digest = hashlib.sha256()
    size = 0
    with _regular(source) as handle:
        if os.fstat(handle.fileno()).st_size > limit:
            raise RecoveryError("Recovery artifact exceeds its byte limit")
        writer = destination.open("xb") if destination else None
        try:
            while block := handle.read(min(1024 * 1024, limit - size + 1)):
                size += len(block)
                if size > limit:
                    raise RecoveryError("Recovery artifact exceeds its byte limit")
                digest.update(block)
                if writer:
                    writer.write(block)
            if writer:
                writer.flush()
                os.fsync(writer.fileno())
            if sync:
                os.fsync(handle.fileno())
        finally:
            if writer:
                writer.close()
    return {"size": size, "sha256": digest.hexdigest()}


def _files(root, *, max_bytes, max_files, destination=None, sync=False):
    """Fingerprint a bounded tree and optionally copy it without following links."""
    manifest = {}
    bytes_left = max_bytes
    entries_left = max_files

    def visit(directory, prefix, target):
        nonlocal bytes_left, entries_left
        _directory(directory)
        with os.scandir(directory) as entries:
            for entry in entries:
                entries_left -= 1
                name = prefix + entry.name
                if entries_left < 0 or len(os.fsencode(name)) > 1024:
                    raise RecoveryError("Recovery artifact exceeds its entry or path limit")
                if any(ord(ch) < 32 or ch == "\\" for ch in name):
                    raise RecoveryError("Recovery artifact contains an unsafe file name")
                source = Path(entry.path)
                output = target / entry.name if target else None
                if entry.is_dir(follow_symlinks=False):
                    if output:
                        output.mkdir()
                    visit(source, name + "/", output)
                else:
                    value = _file_entry(source, limit=bytes_left, destination=output, sync=sync)
                    bytes_left -= value["size"]
                    manifest[name] = value
        if sync:
            _fsync_dir(directory)
        if target:
            _fsync_dir(target)

    visit(root, "", destination)
    if not manifest:
        raise RecoveryError("Recovery artifact contains no files")
    return manifest


def _bundle(path, work_id, limits, *, generation=None, step=None):
    _directory(path)
    value = _read(path / "manifest.json")
    saved_generation = _number(value.get("generation"), 1)
    saved_step = _number(value.get("step"))
    if (
        type(value.get("version")) is not int or value["version"] != _FORMAT
        or value.get("work_id") != work_id
        or (generation is not None and generation != saved_generation)
        or (step is not None and step != saved_step)
    ):
        raise RecoveryError("Checkpoint belongs to incompatible training work")
    if value.get("files") != _files(path / "payload", **limits):
        raise RecoveryError("Checkpoint files failed integrity verification")
    return Checkpoint(path, saved_step, saved_generation), value


def _names(directory):
    _directory(directory)
    names = []
    with os.scandir(directory) as entries:
        for entry in entries:
            names.append(entry.name)
            if len(names) > 4096:
                raise RecoveryError("Recovery directory contains too many entries")
    return names


class TrainingContext:
    """The private save and restore interface for an opt-in training callback.

    A trainer must save step zero before its first update, then save complete
    update boundaries synchronously. The checkpoint payload is the trainer's
    responsibility, including input position, random state, and progress metrics.
    """

    def __init__(
        self, checkpoint_dir, completed_steps, proposal_dir, *,
        work_id, generation, max_bytes=_DEFAULT_BYTES, max_files=_DEFAULT_FILES,
        should_pause=lambda: False,
    ):
        if not isinstance(work_id, str) or not _DIGEST.fullmatch(work_id):
            raise RecoveryError("Invalid recovery work identifier")
        self._limits = _limits(max_bytes, max_files)
        self._work_id = work_id
        self._generation = _number(generation, 1)
        self._proposals = Path(proposal_dir)
        self._proposals.mkdir(parents=True, mode=0o700, exist_ok=True)
        _directory(self._proposals)
        self._should_pause = should_pause
        self.completed_steps = _number(completed_steps)
        self.checkpoint_dir = None
        self.last_saved_step = None
        self.start_mode = "fresh"
        if checkpoint_dir is not None:
            checkpoint, _ = _bundle(
                Path(checkpoint_dir), work_id, self._limits, step=self.completed_steps,
            )
            if checkpoint.generation >= generation:
                raise RecoveryError("A replacement must restore a prior execution's checkpoint")
            self.checkpoint_dir = checkpoint.path / "payload"
            self.last_saved_step = checkpoint.step
            self.start_mode = "resume"
        elif self.completed_steps:
            raise RecoveryError("A fresh execution cannot start at a nonzero step")

    def pause_requested(self):
        return bool(self._should_pause())

    def pause(self):
        if not self.pause_requested() or self.last_saved_step is None:
            raise RecoveryError("A pause requires a request and a complete checkpoint")
        raise TrainingPaused(self.last_saved_step)

    def save(self, completed_step, writer):
        """Save one complete update boundary through the trainer's writer."""
        step = _number(completed_step)
        if self.last_saved_step is None and step != 0:
            raise RecoveryError("Save step zero before performing training updates")
        if self.last_saved_step is not None and step <= self.last_saved_step:
            raise RecoveryError("Checkpoint steps must increase")
        destination = self._proposals / f"step-{step}"
        with _stage(self._proposals) as temporary:
            payload = temporary / "payload"
            payload.mkdir()
            writer(payload)
            files = _files(payload, **self._limits, sync=True)
            _write(temporary / "manifest.json", {
                "version": _FORMAT,
                "work_id": self._work_id,
                "generation": self._generation,
                "step": step,
                "files": files,
            })
            _promote(temporary, destination)
        self.last_saved_step = step
        complete = sorted(
            (int(match[1]), name) for name in _names(self._proposals)
            if (match := _STEP.fullmatch(name))
        )
        for _, name in complete[:-2]:
            shutil.rmtree(self._proposals / name)
        _fsync_dir(self._proposals)
        return destination


class RecoveryStore:
    """Controller-only round journal and verified private checkpoint/result store.

    The caller holds supervise() across worker reconciliation and uses a shared
    filesystem with qualified locking, atomic rename, and durable sync behavior.
    A worker may access only its own proposal area and its read-only restore
    bundle. It must never mount the journal or the whole controller directory.
    """

    def __init__(self, root, identity, *, max_bytes=_DEFAULT_BYTES, max_files=_DEFAULT_FILES):
        self._root = Path(root).absolute()
        self._limits = _limits(max_bytes, max_files)
        self._identity = _object(identity)
        if not self._identity:
            raise RecoveryError("Recovery identity must describe the training work")
        self.work_id = _digest(self._identity)
        self.work_dir = self._root / self.work_id
        self._root.mkdir(parents=True, mode=0o700, exist_ok=True)
        _directory(self._root)
        self.work_dir.mkdir(mode=0o700, exist_ok=True)
        _directory(self.work_dir)
        _fsync_dir(self._root)
        self._record = self.work_dir / "state.json"
        self._journal_lock = self.work_dir / "state.lock"
        self._checkpoint_dir = self.work_dir / "checkpoints"
        self._checkpoint_dir.mkdir(mode=0o700, exist_ok=True)
        _directory(self._checkpoint_dir)
        with _lock(self._journal_lock):
            try:
                self._load()
            except FileNotFoundError:
                _write(self._record, {
                    "version": _FORMAT, "identity": self._identity, "limits": self._limits,
                    "phase": "requested", "desire": "run", "generation": 0,
                    "pod": None, "stopped": False, "activated": False,
                    "execution": None, "restore": None,
                    "checkpoints": [], "result": None, "failures": 0, "failed_generation": None,
                    "paused_generation": None,
                })

    @classmethod
    def open(cls, root, work_id):
        """Open an existing work record without requiring the original identity."""
        if not isinstance(work_id, str) or not _DIGEST.fullmatch(work_id):
            raise RecoveryError("Invalid recovery work identifier")
        path = Path(root) / work_id
        _directory(path)
        record = _read(path / "state.json")
        if _digest(record.get("identity")) != work_id:
            raise RecoveryError("Recovery journal is in the wrong work directory")
        return cls(root, record["identity"], **record["limits"])

    def _load(self):
        state = _read(self._record)
        if (
            type(state.get("version")) is not int or state["version"] != _FORMAT
            or _digest(state.get("identity")) != self.work_id
            or state.get("limits") != self._limits
        ):
            raise RecoveryError("Recovery journal uses a different identity, format, or bound")
        # Older private journals with a recorded worker cannot prove it never ran.
        state.setdefault("activated", state.get("pod") is not None)
        state.setdefault(
            "paused_generation",
            state["generation"] or None
            if state["phase"] in ("paused", "pause-interrupted", "requested") else None,
        )
        return state

    def status(self):
        with _lock(self._journal_lock):
            return self._load()

    def supervise(self):
        return _lock(self.work_dir / "supervisor.lock", nonblocking=True)

    @contextmanager
    def _edit(self):
        with _lock(self._journal_lock):
            state = self._load()
            yield state
            _write(self._record, state)

    def bind_execution(self, spec):
        normalized = _object(spec)
        with self._edit() as state:
            if state["execution"] is not None and state["execution"] != normalized:
                raise RecoveryError("Execution configuration changed for this training work")
            state["execution"] = normalized

    def _checkpoint_path(self, reference):
        generation = _number(reference["generation"], 1)
        step = _number(reference["step"])
        return self._checkpoint_dir / f"g{generation}-step-{step}"

    def _get_checkpoint(self, reference):
        checkpoint, _ = _bundle(
            self._checkpoint_path(reference), self.work_id, self._limits,
            generation=reference["generation"], step=reference["step"],
        )
        return checkpoint

    def _select(self, state):
        for reference in state["checkpoints"]:
            try:
                return self._get_checkpoint(reference)
            except (OSError, RecoveryError):
                warnings.warn(
                    "Ignoring an unreadable or corrupt retained checkpoint",
                    RuntimeWarning, stacklevel=2,
                )
        if state["checkpoints"]:
            raise RecoveryError("No retained checkpoint passed integrity verification")
        return None

    def latest_checkpoint(self):
        """Return the newest verified compatible checkpoint, if any."""
        with _lock(self._journal_lock):
            return self._select(self._load())

    @staticmethod
    def _reference(checkpoint):
        return {"generation": checkpoint.generation, "step": checkpoint.step}

    def _attempt(self, state):
        if not state["generation"]:
            return None
        checkpoint = state["restore"]
        return Attempt(
            state["generation"], self._checkpoint_path(checkpoint) if checkpoint else None,
            checkpoint["step"] if checkpoint else 0,
        )

    def current_attempt(self):
        return self._attempt(self.status())

    @staticmethod
    def _check_generation(state, generation, *, stopped=False):
        if _number(generation, 1) != state["generation"]:
            raise RecoveryError("Execution generation no longer owns this work")
        if stopped and state["pod"] is not None and not state["stopped"]:
            raise RecoveryError("The owned worker must be confirmed stopped first")

    @staticmethod
    def _check_running(state):
        if state["desire"] == "cancel":
            raise TrainingCancelled("This training work was cancelled")
        if state["desire"] != "run":
            raise RecoveryError("Training is paused or a pause has been requested")

    def begin_attempt(self, *, previous_stopped=False):
        """Return an existing attempt, or claim another after proven termination."""
        with self._edit() as state:
            self._check_running(state)
            if state["result"] is not None:
                raise RecoveryError("A verified final result already exists")
            if state["generation"]:
                if not previous_stopped:
                    return self._attempt(state)
                self._check_generation(state, state["generation"], stopped=True)
            checkpoint = self._select(state)
            state.update(
                phase="training", generation=_number(state["generation"] + 1, 1),
                pod=None, stopped=False, activated=False, paused_generation=None,
                restore=self._reference(checkpoint) if checkpoint else None,
            )
            attempt = self._attempt(state)
        self._prune_checkpoints()
        return attempt

    def attach_pod(self, generation, *, name, uid=None, node_name=None):
        if not isinstance(name, str) or not name:
            raise RecoveryError("A worker must have a name")
        with self._edit() as state:
            self._check_generation(state, generation)
            pod = state["pod"]
            if pod is None:
                if state["stopped"]:
                    raise RecoveryError("A stopped execution may not acquire a worker")
                self._check_running(state)
                pod = {"name": name, "uid": None, "node_name": None}
                state["pod"] = pod
            if pod["name"] != name:
                raise RecoveryError("Worker name changed for the current execution")
            for key, value in (("uid", uid), ("node_name", node_name)):
                if value is not None:
                    if not isinstance(value, str) or not value or pod[key] not in (None, value):
                        raise RecoveryError(f"Worker {key} changed for the current execution")
                    pod[key] = value
            return dict(pod)

    def authorize_pod(self, generation):
        """Record that the current attached worker may receive its start permit."""
        with self._edit() as state:
            self._check_generation(state, generation)
            if state["desire"] != "run":
                return False
            if state["stopped"] or not state["pod"] or not state["pod"]["uid"]:
                raise RecoveryError("Authorization requires an attached, active worker identity")
            state["activated"] = True
            return True

    def confirm_stopped(self, generation):
        """Persist the supervisor's proof that the worker process has stopped."""
        with self._edit() as state:
            self._check_generation(state, generation)
            state["stopped"] = True

    def record_failure(self, generation):
        with self._edit() as state:
            self._check_generation(state, generation, stopped=True)
            if generation not in (state["failed_generation"], state["paused_generation"]):
                state["failed_generation"] = generation
                state["failures"] += 1
            return state["failures"]

    def request_pause(self):
        with self._edit() as state:
            if state["desire"] == "cancel" or state["result"] is not None:
                raise RecoveryError("Cannot pause cancelled or completed work")
            state["desire"] = "pause"
            if not state["generation"]:
                state["phase"] = "paused"

    def mark_paused(self, generation, *, graceful=True, expected_step=None):
        with self._edit() as state:
            self._check_generation(state, generation, stopped=True)
            if state["desire"] != "pause" or state["result"] is not None:
                raise RecoveryError("No pause is pending for this training work")
            if graceful:
                checkpoint = self._select(state)
                if checkpoint is None or (
                    expected_step is not None and checkpoint.step != expected_step
                ):
                    raise RecoveryError("The worker's pause checkpoint was not confirmed")
            state["phase"] = "paused" if graceful else "pause-interrupted"
            state["paused_generation"] = generation

    def resume(self):
        with self._edit() as state:
            if state["desire"] != "pause" or state["phase"] not in ("paused", "pause-interrupted"):
                raise RecoveryError("Training must finish pausing before it can resume")
            state.update(desire="run", phase="requested")

    def cancel(self):
        with self._edit() as state:
            if state["result"] is not None:
                raise RecoveryError("Completed training work cannot be cancelled")
            state.update(desire="cancel", phase="cancelled")

    def _prune_checkpoints(self):
        with _lock(self._journal_lock):
            state = self._load()
            references = state["checkpoints"] + ([state["restore"]] if state["restore"] else [])
            keep = {self._checkpoint_path(ref).name for ref in references}
            for name in _names(self._checkpoint_dir):
                if name not in keep and (
                    re.fullmatch(r"g[1-9][0-9]*-step-[0-9]+", name) or name.startswith(".stage-")
                ):
                    shutil.rmtree(self._checkpoint_dir / name)
            _fsync_dir(self._checkpoint_dir)

    def accept_checkpoint(self, generation, proposal_dir):
        """Promote complete proposals from the stopped current worker."""
        proposal_dir = Path(proposal_dir)
        with self._edit() as state:
            self._check_generation(state, generation, stopped=True)
            if state["desire"] == "cancel":
                raise TrainingCancelled("This training work was cancelled")
            restore_step = state["restore"]["step"] if state["restore"] else 0
            try:
                names = _names(proposal_dir)
            except FileNotFoundError:
                names = []
            candidates = sorted((
                (int(match[1]), name) for name in names
                if (match := _STEP.fullmatch(name)) and int(match[1]) >= restore_step
            ), reverse=True)
            accepted = []
            for step, name in candidates:
                try:
                    checkpoint, manifest = _bundle(
                        proposal_dir / name, self.work_id, self._limits,
                        generation=generation, step=step,
                    )
                except (OSError, RecoveryError):
                    warnings.warn("Ignoring an invalid checkpoint proposal", RuntimeWarning, stacklevel=2)
                    continue
                reference = self._reference(checkpoint)
                destination = self._checkpoint_path(reference)
                if destination.exists():
                    _, existing = _bundle(destination, self.work_id, self._limits, generation=generation, step=step)
                    if existing != manifest:
                        raise RecoveryError("Conflicting checkpoint for the same update")
                else:
                    _check_capacity(self._checkpoint_dir, manifest["files"])
                    with _stage(self._checkpoint_dir) as temporary:
                        payload = temporary / "payload"
                        payload.mkdir()
                        copied = _files(checkpoint.path / "payload", **self._limits, destination=payload)
                        if copied != manifest["files"]:
                            raise RecoveryError("Checkpoint changed during promotion")
                        _write(temporary / "manifest.json", manifest)
                        _promote(temporary, destination)
                accepted.append(reference)
                if len(accepted) == 2:
                    break
            if candidates and not accepted and not state["checkpoints"]:
                raise RecoveryError("No committed checkpoint proposal passed validation")
            retained = accepted + [ref for ref in state["checkpoints"] if ref not in accepted]
            retained.sort(key=lambda ref: (ref["generation"], ref["step"]), reverse=True)
            state["checkpoints"] = retained[:2]
            result = self._select(state)
        self._prune_checkpoints()
        return result

    def _ready(self, state):
        if state["result"] is None:
            return None
        result = self.work_dir / "result"
        _directory(result)
        manifest = _read(result / "manifest.json")
        if (
            manifest.get("version") != _FORMAT or manifest.get("work_id") != self.work_id
            or manifest.get("generation") != state["generation"]
            or _digest(manifest) != state["result"]
            or _files(result / "output", **self._limits) != manifest.get("files")
        ):
            raise RecoveryError("Saved final result failed integrity verification")
        return ReadyResult(result / "output", manifest["metadata"], state["result"])

    def accept_result(self, generation, output_dir, metadata):
        """Persist a separate final result before worker resources are removed."""
        with self._edit() as state:
            self._check_generation(state, generation, stopped=True)
            self._check_running(state)
            output_dir = Path(output_dir)
            manifest = {
                "version": _FORMAT, "work_id": self.work_id, "generation": generation,
                "metadata": _object(metadata), "files": _files(output_dir, **self._limits),
            }
            fingerprint = _digest(manifest)
            if state["result"] is not None and state["result"] != fingerprint:
                raise RecoveryError("The worker produced a conflicting final result")
            destination = self.work_dir / "result"
            if destination.exists():
                if _read(destination / "manifest.json") != manifest:
                    raise RecoveryError("A conflicting final result already exists")
            else:
                _check_capacity(self.work_dir, manifest["files"])
                with _stage(self.work_dir) as temporary:
                    payload = temporary / "output"
                    payload.mkdir()
                    copied = _files(output_dir, **self._limits, destination=payload)
                    if copied != manifest["files"]:
                        raise RecoveryError("Final result changed during promotion")
                    _write(temporary / "manifest.json", manifest)
                    _promote(temporary, destination)
            state.update(phase="result-ready", result=fingerprint)
            return self._ready(state)

    def ready_result(self):
        with _lock(self._journal_lock):
            state = self._load()
            return self._ready(state) if state["desire"] == "run" else None

    def materialize_result(self, output_dir):
        """Expose only the immutable final output at its caller's output path."""
        with _lock(self._journal_lock):
            state = self._load()
            self._check_running(state)
            result = self._ready(state)
            if result is None:
                raise RecoveryError("No final result is ready")
            output_dir = Path(output_dir).absolute()
            output_dir.parent.mkdir(parents=True, exist_ok=True)
            manifest = _read(result.output_dir.parent / "manifest.json")
            if output_dir.exists() or output_dir.is_symlink():
                if _files(output_dir, **self._limits) != manifest["files"]:
                    raise RecoveryError("Requested output path contains a different result")
            else:
                _check_capacity(output_dir.parent, manifest["files"])
                with _stage(output_dir.parent) as temporary:
                    if _files(result.output_dir, **self._limits, destination=temporary) != manifest["files"]:
                        raise RecoveryError("Final result changed during collection")
                    _promote(temporary, output_dir)
            return ReadyResult(output_dir, result.metadata, result.fingerprint)
