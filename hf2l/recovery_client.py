"""Participant-side recovery shared by the listener and the manual trainer."""

from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import threading
from urllib.parse import urlsplit, urlunsplit

from hf2l.recovery import RecoveryError, RecoveryStore, TrainingCancelled, TrainingContext, TrainingPaused


def source_identity(store) -> str:
    """Bind state to the constructed store's effective location and local identity.

    Factory defaults and environment configuration have already been resolved by
    this point. Credentials are deliberately absent from the location identity.
    The listener hashes this description before persisting it.
    """
    identity = {"backend": store.name}
    if store.name == "local":
        identity.update(root=str(Path(store.root).resolve()), principal=store.principal)
    else:
        if store.name == "exchange":
            endpoint = store.client.endpoint
        else:
            endpoint = store.api.endpoint
        parts = urlsplit(endpoint)
        # A password or token in a URL must neither identify a repository nor be
        # retained in listener state. Provider endpoints identify their API path.
        authority = parts.netloc.rsplit("@", 1)[-1].lower()
        identity["endpoint"] = urlunsplit((parts.scheme.lower(), authority,
                                            parts.path.rstrip("/"), "", ""))
    return json.dumps(identity, sort_keys=True, separators=(",", ":"))


def _fingerprint(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class RecoveryRunner:
    """Bind a trainer and a private recovery root to verified round inputs."""

    def __init__(self, root, config, trainer, *, source_id, participant, pod=False):
        required = {"study_id", "trainer_version", "dataset_version"}
        allowed = required | {"max_bytes", "max_files", "runtime_path_options"}
        if not isinstance(config, dict) or not required <= config.keys() <= allowed:
            raise ValueError("Recovery configuration must identify the study, trainer and dataset")
        for field in required:
            if not isinstance(config[field], str) or not config[field].strip():
                raise ValueError(f"Recovery configuration requires a nonempty {field}")
        paths = config.get("runtime_path_options", [])
        if (
            not isinstance(paths, list)
            or any(not isinstance(option, str) or not option or option == "participant" for option in paths)
            or len(set(paths)) != len(paths)
        ):
            raise ValueError("runtime_path_options must list distinct path-only option names")
        if not pod and not callable(trainer):
            raise ValueError("Recovery requires a train_recoverable trainer")
        self.root = Path(root).expanduser().resolve()
        self.config = deepcopy(config)
        self.trainer = trainer
        self.trainer_source = None
        self.participant = participant
        self.source_hash = _fingerprint(source_id)
        self.pod = pod
        self.path_options = set(paths) | {"pod_config", "participant"}
        self.limits = dict(
            max_bytes=config.get("max_bytes", 512 * 1024 * 1024),
            max_files=config.get("max_files", 4096),
        )
        for limit, value in self.limits.items():
            if type(value) is not int or value <= 0:
                raise ValueError(f"{limit} must be a positive integer")

    def compatibility(self, options):
        return _fingerprint({
            "study_id": self.config["study_id"],
            "trainer_version": self.config["trainer_version"],
            "trainer_source": self.trainer_source,
            "dataset_version": self.config["dataset_version"],
            "options": {key: value for key, value in options.items() if key not in self.path_options},
            "runtime_path_options": sorted(self.path_options),
        })

    def store(self, work_dir, options):
        from hf2l.listener.workflow import _validate_base

        work_dir = Path(work_dir).resolve()
        if self.root.is_relative_to(work_dir) or work_dir.is_relative_to(self.root):
            raise ValueError("Received-model workspace and private recovery root must be separate")
        context, _, base_hashes = _validate_base(work_dir)
        identity = {
            "study_id": self.config["study_id"],
            "participant": self.participant,
            "source": self.source_hash,
            "repository": context.repo_id,
            "round": context.source_round,
            "base_revision": context.base_revision,
            "base_files": base_hashes,
            "training": self.compatibility(options),
        }
        marker = work_dir / ".hf2l-recovery-work"
        if marker.exists() or marker.is_symlink():
            recovery = RecoveryStore.open(self.root, _read_binding(marker))
        else:
            recovery = RecoveryStore(self.root, identity, **self.limits)
        status = recovery.status()
        if status["identity"] != identity or status["limits"] != self.limits:
            raise RecoveryError("Saved work has a different starting model, trainer, data or configuration")

        # One durable publisher workspace per participant, round and base. The
        # training configuration can change the checkpoint identity, but it
        # must not grant another workspace permission to submit the same round.
        registrations = self.root / ".rounds"
        registrations.mkdir(mode=0o700, exist_ok=True)
        if registrations.is_symlink():
            raise RecoveryError("Round registration directory cannot be a symlink")
        logical_round = {key: value for key, value in identity.items() if key != "training"}
        scope = registrations / _fingerprint(logical_round)
        owner = _fingerprint({"workspace": str(work_dir), "work_id": recovery.work_id})
        _bind_once(scope, owner, "This participant round is bound to a different workspace or training setup")
        _bind_once(marker, recovery.work_id, "Workspace has a different recovery identity")
        return recovery

    def __call__(self, base_dir, output_dir, options):
        recovery = self.store(Path(base_dir).parent, options)
        if self.pod:
            from hf2l.kubernetes_recovery import supervise_recoverable

            return supervise_recoverable(base_dir, output_dir, options, recovery)
        return _run_inline(recovery, self.trainer, Path(base_dir), Path(output_dir), options)

    def cancel_obsolete(self, work_dir, options):
        """Drain an obsolete worker under its original store before admitting newer work."""
        work_dir = Path(work_dir).resolve()
        recovery = self.store(work_dir, options)
        if recovery.ready_result() is None:
            recovery.cancel()
        if self.pod:
            try:
                self(work_dir / "base_model", work_dir / "trained_model", options)
            except TrainingCancelled:
                pass


def _read_binding(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        return stream.read(67).decode("ascii").strip()


def _bind_once(path, value, conflict):
    if not (path.exists() or path.is_symlink()):
        descriptor, temporary = tempfile.mkstemp(prefix=".hf2l-bind-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="ascii") as stream:
                stream.write(value + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, path, follow_symlinks=False)
            except FileExistsError:
                pass
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            os.unlink(temporary)
    if _read_binding(path) != value:
        raise RecoveryError(conflict)


def _attempt_dir(store, generation):
    return store.work_dir / f"inline-{generation}"


def _run_inline(store, trainer, base_dir, output_dir, options):
    # The lock remains held by the process executing synchronous trainer code.
    # A replacement may use it as stop evidence only on qualified storage.
    with store.supervise():
        store.bind_execution({"mode": "inline"})
        ready = store.ready_result()
        if ready is not None:
            return store.materialize_result(output_dir).metadata
        prior = store.current_attempt()
        if prior is not None:
            was_running = not store.status()["stopped"]
            store.confirm_stopped(prior.generation)
            proposals = _attempt_dir(store, prior.generation) / "checkpoints"
            if proposals.is_dir() and store.status()["desire"] != "cancel":
                store.accept_checkpoint(prior.generation, proposals)
            if was_running and store.status()["desire"] == "run":
                store.record_failure(prior.generation)
        state = store.status()
        if state["desire"] == "cancel":
            raise TrainingCancelled("Training was cancelled")
        if state["desire"] == "pause":
            if prior is not None and state["phase"] not in {"paused", "pause-interrupted"}:
                store.mark_paused(prior.generation, graceful=False)
            checkpoint = store.latest_checkpoint()
            raise TrainingPaused(checkpoint.step if checkpoint else 0)
        if state["failures"] >= 5:
            raise RecoveryError("Repeated interruptions stopped automatic recovery")
        attempt = store.begin_attempt(previous_stopped=prior is not None)
        if prior is not None:
            prior_dir = _attempt_dir(store, prior.generation)
            if prior_dir.exists():
                shutil.rmtree(prior_dir)
        attempt_dir = _attempt_dir(store, attempt.generation)
        attempt_dir.mkdir(mode=0o700)
        proposals = attempt_dir / "checkpoints"
        proposals.mkdir(mode=0o700)
        trained = attempt_dir / "output"
        interrupted = False

        def stop_soon(_signal, _frame):
            nonlocal interrupted
            interrupted = True

        # Only the main thread receives process signals. The supervisor handles
        # forced stops and restarts if there is no time for a cooperative save.
        in_main_thread = threading.current_thread() is threading.main_thread()
        handler = signal.signal(signal.SIGTERM, stop_soon) if in_main_thread else None
        try:
            try:
                context = TrainingContext(
                    attempt.checkpoint, attempt.completed_steps, proposals,
                    work_id=store.work_id, generation=attempt.generation,
                    **store.status()["limits"],
                    should_pause=lambda: interrupted or store.status()["desire"] != "run",
                )
                metadata = trainer(base_dir, trained, deepcopy(options), context)
            finally:
                store.confirm_stopped(attempt.generation)
                if store.status()["desire"] != "cancel":
                    store.accept_checkpoint(attempt.generation, proposals)
        except TrainingPaused as exc:
            desire = store.status()["desire"]
            if desire == "cancel":
                raise TrainingCancelled("Training was cancelled") from exc
            if desire == "pause":
                store.mark_paused(attempt.generation, expected_step=exc.completed_steps)
                raise
            if interrupted:
                raise SystemExit(143) from exc
            raise RecoveryError("Trainer paused without a stop request") from exc
        except Exception:
            store.record_failure(attempt.generation)
            raise
        finally:
            if handler is not None:
                signal.signal(signal.SIGTERM, handler)

        desire = store.status()["desire"]
        if desire == "cancel":
            raise TrainingCancelled("Training was cancelled")
        if desire == "pause":
            store.mark_paused(attempt.generation, graceful=False)
            raise TrainingPaused(context.last_saved_step)
        store.accept_result(attempt.generation, trained, metadata)
        shutil.rmtree(attempt_dir)
        if interrupted:
            raise SystemExit(143)
        return store.materialize_result(output_dir).metadata


def add_recovery_arguments(parser):
    parser.add_argument("--recovery-root", type=Path, help="Participant-private durable recovery directory")
    parser.add_argument("--recovery-config", type=Path, help="Immutable training identities and recovery limits")


def make_recovery(args, plugin, source_id):
    root = args.recovery_root
    config = args.recovery_config
    if root is None and config is None:
        return None
    if root is None or config is None:
        raise ValueError("--recovery-root and --recovery-config must be supplied together")
    runner = RecoveryRunner(
        root, json.loads(config.read_text(encoding="utf-8")),
        getattr(plugin, "train_recoverable", None), source_id=source_id,
        participant=args.participant, pod=plugin.__name__ == "hf2l.kubernetes",
    )
    if not runner.pod and getattr(plugin, "__file__", None):
        runner.trainer_source = hashlib.sha256(Path(plugin.__file__).read_bytes()).hexdigest()
    return runner


def main(argv=None):
    parser = argparse.ArgumentParser(description="Control participant-local training recovery")
    parser.add_argument("action", choices=("status", "pause", "resume", "cancel"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--work-id")
    args = parser.parse_args(argv)
    if args.action != "status" and args.work_id is None:
        parser.error("--work-id is required for pause, resume and cancel")
    try:
        if args.work_id:
            work_ids = [args.work_id]
        elif args.root.is_dir():
            work_ids = sorted(path.name for path in args.root.iterdir()
                              if len(path.name) == 64 and path.is_dir() and not path.is_symlink())
        else:
            work_ids = []
        for work_id in work_ids:
            store = RecoveryStore.open(args.root, work_id)
            if args.action == "pause":
                store.request_pause()
            elif args.action == "resume":
                store.resume()
            elif args.action == "cancel":
                store.cancel()
            status = store.status()
            print(json.dumps({
                "work_id": work_id,
                "participant": status["identity"]["participant"],
                "round": status["identity"]["round"],
                "phase": status["phase"],
                "desired": status["desire"],
                "generation": status["generation"],
            }, sort_keys=True))
    except (OSError, ValueError, RecoveryError) as exc:
        print(f"Recovery control failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
