"""Run recovery-aware training in participant-owned, independently running pods."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import tempfile
import time
from urllib.parse import quote

from hf2l.kubernetes import (
    KubernetesError,
    OWNER_LABEL,
    UncertainExecution,
    _config,
    _get_pod,
    _invoke,
    _json,
    _manifest,
    _pod,
    _validate_metadata,
    _validate_outputs,
)
from hf2l.plugin_loader import load_plugin, require_callable
from hf2l.recovery import RecoveryError, TrainingCancelled, TrainingContext, TrainingPaused


_FINALIZER = "hf2l.org/recovery"
_METADATA_LIMIT = 1024 * 1024
_TERMINATION_REASONS = {"Completed", "Error", "OOMKilled", "DeadlineExceeded"}


@dataclass(frozen=True)
class _Volume:
    claim: str
    mount: Path
    image_id: str | None
    pause_grace: int
    max_restarts: int


@dataclass(frozen=True)
class _Paths:
    root: Path

    @property
    def inputs(self):
        return self.root / "inputs"

    @property
    def control(self):
        return self.root / "control"

    @property
    def worker(self):
        return self.root / "worker"

    @property
    def permit(self):
        return self.control / "permit.json"


def _parse_options(options):
    if not isinstance(options, dict) or not isinstance(options.get("pod_config"), (str, Path)):
        raise KubernetesError("Recoverable training requires pod_config")
    config = _config(options["pod_config"], recovery=True)
    volume = config.pop("recovery_volume", None)
    if not isinstance(volume, dict) or set(volume) - {
        "claim", "mount_path", "image_id", "pause_grace_seconds", "max_restarts",
    }:
        raise KubernetesError("pod_config requires a valid recovery_volume object")
    claim = volume.get("claim")
    if not isinstance(claim, str) or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?", claim):
        raise KubernetesError("recovery_volume.claim must be a storage claim name")
    if config.get("dataset_claim") == claim:
        raise KubernetesError("Recovery and private input data must use separate storage claims")
    mount = volume.get("mount_path")
    if not isinstance(mount, str) or not Path(mount).is_absolute() or not Path(mount).is_dir():
        raise KubernetesError("recovery_volume.mount_path must be the mounted claim root")
    image_id = volume.get("image_id")
    if image_id is not None and (
        not isinstance(image_id, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
    ):
        raise KubernetesError("recovery_volume.image_id must be an exact SHA-256 image identifier")
    if image_id is None and re.search(r"@sha256:[0-9a-f]{64}$", config["image"]) is None:
        raise KubernetesError("Recovery requires a digest-pinned image or an exact image_id check")
    pause_grace = volume.get("pause_grace_seconds", 30)
    restarts = volume.get("max_restarts", 2)
    if type(pause_grace) is not int or not 1 <= pause_grace <= 3600:
        raise KubernetesError("pause_grace_seconds must be between 1 and 3600")
    if type(restarts) is not int or not 0 <= restarts <= 10:
        raise KubernetesError("max_restarts must be between 0 and 10")
    return config, _Volume(claim, Path(mount).resolve(), image_id, pause_grace, restarts), {
        key: value for key, value in options.items() if key != "pod_config"
    }


def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_message(path, value):
    data = _json(value).encode()
    if len(data) > _METADATA_LIMIT:
        raise KubernetesError("Recovery message exceeds its size limit")
    descriptor, temporary = tempfile.mkstemp(prefix=".message-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _read_message(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, "rb") as stream:
        mode = os.fstat(stream.fileno())
        if not stat.S_ISREG(mode.st_mode) or mode.st_size > _METADATA_LIMIT:
            raise KubernetesError("Invalid recovery message file")
        data = stream.read(_METADATA_LIMIT + 1)
    if len(data) > _METADATA_LIMIT:
        raise KubernetesError("Recovery message exceeds its size limit")
    result = json.loads(data)
    if not isinstance(result, dict):
        raise KubernetesError("Invalid recovery message")
    return result


def _sync_files(directory):
    for parent, _, names in os.walk(directory, topdown=False):
        for name in names:
            descriptor = os.open(Path(parent) / name, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        _sync_directory(parent)


def _attempt_name(work_id, generation):
    owner = hashlib.sha256(f"{work_id}:{generation}".encode()).hexdigest()[:40]
    return {"pod_name": "hf2l-r-" + owner, "attempt_id": owner}


def _owned_pod(config, name, reference):
    pod = _get_pod(config, name)
    if pod is None:
        return None
    metadata = pod.get("metadata", {})
    if (
        metadata.get("name") != name["pod_name"]
        or metadata.get("namespace") != config["namespace"]
        or metadata.get("labels", {}).get(OWNER_LABEL) != name["attempt_id"]
        or not metadata.get("uid")
        or (reference.get("uid") and reference["uid"] != metadata["uid"])
        or pod.get("spec", {}).get("restartPolicy") != "Never"
    ):
        raise UncertainExecution("The recorded recovery pod no longer matches its owner")
    return pod


def _subpath(path, mount):
    try:
        relative = path.resolve().relative_to(mount)
    except ValueError as exc:
        raise KubernetesError("Recovery work must be inside the configured claim mount") from exc
    if not relative.parts:
        raise KubernetesError("A worker must never mount the entire recovery claim")
    return relative.as_posix()


def _mount_spec(config, volume, name, paths, checkpoint):
    pod = _pod(config, name)
    pod["metadata"]["finalizers"] = [_FINALIZER]
    spec = pod["spec"]
    spec["enableServiceLinks"] = False
    spec["terminationGracePeriodSeconds"] = volume.pause_grace
    spec["activeDeadlineSeconds"] = config["readiness_timeout_seconds"] + config["training_timeout_seconds"]
    spec["volumes"].append({
        "name": "recovery", "persistentVolumeClaim": {"claimName": volume.claim},
    })
    trainer = spec["containers"][0]
    trainer["command"] = ["python", "-m", "hf2l.kubernetes_recovery"]
    trainer["env"] = [
        {"name": "HF2L_POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}},
        {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
    ]
    mounts = [(paths.inputs, "/work/input", True), (paths.control, "/work/control", True),
              (paths.worker, "/work/attempt", False)]
    if checkpoint is not None:
        mounts.append((checkpoint, "/work/restore", True))
    trainer["volumeMounts"].extend({
        "name": "recovery", "mountPath": target, "subPath": _subpath(source, volume.mount),
        "readOnly": read_only,
    } for source, target, read_only in mounts)
    return pod


def _binding(config, volume, options):
    claim = json.loads(_invoke(config, ["get", "pvc", volume.claim, "-o", "json"]))
    if claim.get("status", {}).get("phase") != "Bound" or not claim.get("metadata", {}).get("uid"):
        raise KubernetesError("Recovery storage claim must be bound")
    return {
        "context": config["context"], "namespace": config["namespace"], "image": config["image"],
        "image_id": volume.image_id, "claim": volume.claim, "claim_uid": claim["metadata"]["uid"],
        "dataset_claim": config.get("dataset_claim"), "plugin": config["plugin"], "options": options,
    }


def _stage(paths, config, store, attempt, base_dir, options, expected):
    for directory in (paths.root.parent, paths.root, paths.control, paths.worker, paths.inputs):
        if directory.is_symlink():
            raise KubernetesError("Recovery staging directory must not be a symbolic link")
    paths.root.mkdir(parents=True, mode=0o700, exist_ok=True)
    paths.control.mkdir(mode=0o700, exist_ok=True)
    paths.worker.mkdir(mode=0o700, exist_ok=True)
    if paths.inputs.exists():
        return
    with tempfile.TemporaryDirectory(prefix=".inputs-", dir=paths.root) as staging:
        staged = Path(staging)
        shutil.copytree(base_dir, staged / "base", symlinks=True)
        if _manifest(staged / "base", config["max_transfer_bytes"]) != expected:
            raise KubernetesError("Starting model changed while it was being staged")
        limits = store.status()["limits"]
        _write_message(staged / "request.json", {
            "work_id": store.work_id, "generation": attempt.generation,
            "completed_steps": attempt.completed_steps, "has_checkpoint": attempt.checkpoint is not None,
            "plugin": config["plugin"], "options": options, "base_manifest": expected,
            "max_bytes": config["max_transfer_bytes"], "wait_seconds": config["readiness_timeout_seconds"],
            "checkpoint_limits": {
                "max_bytes": min(config["max_transfer_bytes"], limits["max_bytes"]),
                "max_files": limits["max_files"],
            },
        })
        _sync_files(staged)
        os.rename(staged, paths.inputs)
        _sync_directory(paths.root)


def _trainer_status(pod):
    return next((entry for entry in pod.get("status", {}).get("containerStatuses", [])
                 if entry.get("name") == "trainer"), {})


def _confirmed_terminated(pod):
    status = _trainer_status(pod)
    stopped = status.get("state", {}).get("terminated") or {}
    return (
        stopped.get("reason") in _TERMINATION_REASONS
        and type(stopped.get("exitCode")) is int
        and bool(stopped.get("containerID") or status.get("containerID"))
        and isinstance(stopped.get("finishedAt"), str)
        and not stopped["finishedAt"].startswith("0001-")
        and bool(stopped["finishedAt"])
        and bool(pod.get("spec", {}).get("nodeName"))
    )


def _request_deletion(config, name, uid, grace):
    path = "/api/v1/namespaces/" + quote(config["namespace"], safe="") + "/pods/" + quote(name, safe="")
    _invoke(config, ["delete", "--raw", path, "-f", "-"], input_data=_json({
        "apiVersion": "v1", "kind": "DeleteOptions", "gracePeriodSeconds": grace,
        "preconditions": {"uid": uid},
    }).encode())


def _retire(config, name, reference):
    if not reference.get("stopped"):
        raise UncertainExecution("Cannot remove a recovery pod before its execution is stopped")
    pod = _owned_pod(config, name, reference)
    if pod is None:
        return
    metadata = pod["metadata"]
    uid = metadata["uid"]
    finalizers = metadata.get("finalizers", [])
    if _FINALIZER in finalizers:
        index = finalizers.index(_FINALIZER)
        pointer = f"/metadata/finalizers/{index}"
        _invoke(config, ["patch", "pod", name["pod_name"], "--type=json", "-p", _json([
            {"op": "test", "path": "/metadata/uid", "value": uid},
            {"op": "test", "path": pointer, "value": _FINALIZER},
            {"op": "remove", "path": pointer},
        ])])
    live = _owned_pod(config, name, reference)
    if live is not None and not live["metadata"].get("deletionTimestamp"):
        _request_deletion(config, name["pod_name"], uid, 0)
    deadline = time.monotonic() + config["cleanup_timeout_seconds"]
    while _owned_pod(config, name, reference) is not None:
        if time.monotonic() >= deadline:
            raise KubernetesError("Stopped recovery pod could not be removed")
        time.sleep(0.5)


def _verify_image(pod, volume):
    if volume.image_id is None:
        return
    actual = _trainer_status(pod).get("imageID", "")
    if not actual.endswith(volume.image_id):
        raise KubernetesError("Training pod image differs from the configured recovery image identity")


def _reference(state):
    pod = state.get("pod")
    return None if pod is None else {**pod, "stopped": state["stopped"]}


def _wait_attempt(config, volume, store, attempt, paths, name):
    ready_by = time.monotonic() + config["readiness_timeout_seconds"]
    stop_by = ready_by + config["training_timeout_seconds"] + volume.pause_grace
    while True:
        state = store.status()
        reference = _reference(state) or {}
        if state["stopped"]:
            return
        pod = _owned_pod(config, name, reference)
        permit = _read_message(paths.permit)
        activated = state["activated"]
        if permit is not None and not activated:
            raise UncertainExecution("Recovery permit exists without a durable authorization record")
        desire = state["desire"]
        if pod is None:
            if activated:
                raise UncertainExecution("Recovery pod disappeared without proof its training process stopped")
            if reference.get("uid") or desire != "run":
                store.confirm_stopped(attempt.generation)
                return
            _invoke(config, ["create", "-f", "-", "-o", "json"], input_data=_json(
                _mount_spec(config, volume, name, paths, attempt.checkpoint)
            ).encode())
            continue

        metadata = pod["metadata"]
        uid = metadata["uid"]
        store.attach_pod(
            attempt.generation, name=name["pod_name"], uid=uid, node_name=pod["spec"].get("nodeName"),
        )
        if _confirmed_terminated(pod):
            store.confirm_stopped(attempt.generation)
            return
        if permit is not None and permit != {"pod_uid": uid}:
            raise UncertainExecution("Recovery pod permit does not match the recorded pod")
        phase = pod.get("status", {}).get("phase")
        deleting = bool(metadata.get("deletionTimestamp"))
        if activated and (phase in {"Failed", "Succeeded", "Unknown"} or time.monotonic() >= stop_by):
            raise UncertainExecution("Recovery pod has no trustworthy process termination record")
        if not activated and (desire != "run" or deleting or time.monotonic() >= ready_by):
            # The worker cannot execute training until the controller grants its UID.
            store.confirm_stopped(attempt.generation)
            return
        if desire != "run" and not deleting:
            _write_message(paths.control / "stop.json", {"requested": desire})
            _request_deletion(config, name["pod_name"], uid, volume.pause_grace)
        if permit is None and desire == "run" and not deleting and _trainer_status(pod).get("state", {}).get("running"):
            _verify_image(pod, volume)
            if activated or store.authorize_pod(attempt.generation):
                _write_message(paths.permit, {"pod_uid": uid})
        time.sleep(0.5)


def _finish_attempt(config, store, attempt, paths, name, base_dir):
    generation = attempt.generation
    if not store.status()["stopped"]:
        raise UncertainExecution("Training must be confirmed stopped before accepting results")
    if paths.permit.exists():
        paths.permit.unlink()
        _sync_directory(paths.control)
    while True:
        state = store.status()
        desire = state["desire"]
        if desire == "cancel":
            break
        marker = _read_message(paths.worker / "result.json")
        if marker is not None and marker.get("kind") not in {"complete", "paused"}:
            raise KubernetesError("Malformed saved worker outcome")
        try:
            store.accept_checkpoint(generation, paths.worker / "checkpoints")
            if desire == "pause":
                graceful = bool(marker and marker.get("kind") == "paused")
                step = marker.get("completed_steps") if graceful else None
                if graceful and (type(step) is not int or step < 0):
                    raise KubernetesError("Paused worker did not identify its last complete checkpoint")
                store.mark_paused(generation, graceful=graceful, expected_step=step)
            elif marker and marker.get("kind") == "complete":
                _validate_outputs(base_dir, paths.worker / "output", config["max_transfer_bytes"])
                store.accept_result(generation, paths.worker / "output", _validate_metadata(marker.get("metadata")))
            elif state.get("paused_generation") != generation:
                store.record_failure(generation)
        except RecoveryError:
            if store.status()["desire"] == desire:
                raise
            continue
        break
    _retire(config, name, _reference(store.status()))


def _prune_old_attempts(paths, generation):
    if not paths.root.parent.exists():
        return
    for previous in paths.root.parent.iterdir():
        if previous.name.isascii() and previous.name.isdecimal() and len(previous.name) <= 12:
            if int(previous.name) < generation and previous.is_dir() and not previous.is_symlink():
                shutil.rmtree(previous)


def _paused(store):
    checkpoint = store.latest_checkpoint()
    return TrainingPaused(checkpoint.step if checkpoint else 0)


def supervise_recoverable(base_dir, output_dir, options, recovery_store):
    """Run or reconcile one opted-in worker without keeping an exec connection open."""
    config, volume, training_options = _parse_options(options)
    base_dir = Path(base_dir)
    if base_dir.is_symlink():
        raise KubernetesError("Input directory must not be a symbolic link")
    base_dir = base_dir.resolve()
    store = recovery_store
    _subpath(store.work_dir, volume.mount)
    with store.supervise():
        base_manifest = _manifest(base_dir, config["max_transfer_bytes"])
        binding = _binding(config, volume, training_options)
        binding["base_manifest"] = base_manifest
        store.bind_execution(binding)
        while True:
            state = store.status()
            attempt = store.current_attempt()
            if attempt is not None:
                name = _attempt_name(store.work_id, attempt.generation)
                paths = _Paths(store.work_dir / "pod-attempts" / str(attempt.generation))
            ready = store.ready_result()
            if ready is not None:
                if state.get("pod"):
                    _retire(config, name, _reference(state))
                    if paths.root.is_dir() and not paths.root.is_symlink():
                        shutil.rmtree(paths.root)
                return store.materialize_result(output_dir).metadata
            if state["phase"] in {"paused", "pause-interrupted"}:
                if state.get("pod"):
                    _retire(config, name, _reference(state))
                raise _paused(store)
            if state["desire"] == "cancel" and not state.get("pod"):
                raise TrainingCancelled("Training is cancelled")
            if attempt is None:
                attempt = store.begin_attempt()
                name = _attempt_name(store.work_id, attempt.generation)
                paths = _Paths(store.work_dir / "pod-attempts" / str(attempt.generation))
            if not state["stopped"] or not state.get("pod"):
                _prune_old_attempts(paths, attempt.generation)
                _stage(paths, config, store, attempt, base_dir, training_options, base_manifest)
                store.attach_pod(attempt.generation, name=name["pod_name"])
                _wait_attempt(config, volume, store, attempt, paths, name)
            _finish_attempt(config, store, attempt, paths, name, base_dir)
            state = store.status()
            if state["desire"] == "cancel":
                raise TrainingCancelled("Training is cancelled")
            if state["phase"] in {"paused", "pause-interrupted"}:
                raise _paused(store)
            if store.ready_result() is None:
                if state["failures"] > volume.max_restarts:
                    raise KubernetesError("Automatic worker replacement limit reached; checkpoints retained")
                store.begin_attempt(previous_stopped=True)


def _worker(work_dir=Path("/work")):
    """Wait for authorization, then run exactly one recovery-aware trainer."""
    input_path = work_dir / "input"
    control = work_dir / "control"
    attempt = work_dir / "attempt"
    request = _read_message(input_path / "request.json")
    uid = os.environ["HF2L_POD_UID"]
    terminating = False

    def stop(_signum, _frame):
        nonlocal terminating
        terminating = True

    signal.signal(signal.SIGTERM, stop)
    deadline = time.monotonic() + request["wait_seconds"]
    while _read_message(control / "permit.json") != {"pod_uid": uid}:
        if terminating or time.monotonic() >= deadline:
            raise KubernetesError("Recovery worker did not receive a matching start permit")
        time.sleep(0.25)
    base_dir = input_path / "base"
    if _manifest(base_dir, request["max_bytes"]) != request["base_manifest"]:
        raise KubernetesError("Staged starting model failed verification")
    context = TrainingContext(
        work_dir / "restore" if request["has_checkpoint"] else None, request["completed_steps"],
        attempt / "checkpoints", work_id=request["work_id"], generation=request["generation"],
        **request["checkpoint_limits"],
        should_pause=lambda: terminating or (control / "stop.json").exists(),
    )
    trainer = require_callable(load_plugin(request["plugin"]), "train_recoverable")
    output_dir = attempt / "output"
    try:
        metadata = _validate_metadata(trainer(base_dir, output_dir, request["options"], context))
    except TrainingPaused as exc:
        _write_message(attempt / "result.json", {"kind": "paused", "completed_steps": exc.completed_steps})
        return
    _validate_outputs(base_dir, output_dir, request["max_bytes"])
    _sync_files(output_dir)
    _write_message(attempt / "result.json", {"kind": "complete", "metadata": metadata})


if __name__ == "__main__":
    _worker()
