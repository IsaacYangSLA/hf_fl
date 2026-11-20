"""Organization-local Kubernetes training with durable, fail-closed pod ownership.

Persistent listeners can run directly in pods. This adapter provides the other
lifecycle: prepare a temporary pod, train in it, collect, and delete that pod.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager, redirect_stdout
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from urllib.parse import quote
import uuid

from hf2l.checkpoint.format import discover
from hf2l.checkpoint.layout import validate_compatible
from hf2l.plugin_loader import load_plugin, require_callable

STATE_FILE = ".hf2l-kubernetes-attempt.json"
OWNER_LABEL = "hf2l.org/attempt"
_COMMAND_LIMIT = 8 * 1024 * 1024
_MAX_FILES = 10000


class KubernetesError(RuntimeError):
    """The organization-local pod operation could not safely complete."""


class UncertainExecution(KubernetesError):
    """Training may have executed; this attempt must not execute it again."""


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _positive(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise KubernetesError(f"{name} must be a positive finite number")
    return value


def _config(filename, *, recovery=False):
    path = Path(filename).expanduser().resolve()
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise KubernetesError("pod_config must contain a JSON object")
    allowed = {"kubeconfig", "context", "namespace", "image", "plugin", "dataset_claim", "resources",
               "readiness_timeout_seconds", "training_timeout_seconds", "cleanup_timeout_seconds",
               "request_timeout_seconds", "max_transfer_bytes"}
    if recovery:
        allowed.add("recovery_volume")
    if set(value) - allowed:
        raise KubernetesError("Unsupported pod configuration keys: " + ", ".join(sorted(set(value) - allowed)))
    for key in ("kubeconfig", "context", "namespace", "image", "plugin"):
        if not isinstance(value.get(key), str) or not value[key].strip():
            raise KubernetesError(f"pod_config requires nonempty {key}")
    kubeconfig = Path(value["kubeconfig"]).expanduser()
    if not kubeconfig.is_absolute() or not kubeconfig.is_file():
        raise KubernetesError("kubeconfig must name an existing absolute file")
    value["kubeconfig"] = str(kubeconfig.resolve())
    if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", value["namespace"]):
        raise KubernetesError("namespace must be an explicit Kubernetes namespace name")
    if not value["plugin"].startswith("/") or ".." in PurePosixPath(value["plugin"]).parts:
        raise KubernetesError("plugin must be an absolute trusted file path inside the image")
    if "dataset_claim" in value and (not isinstance(value["dataset_claim"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]|[a-z0-9]", value["dataset_claim"])):
        raise KubernetesError("dataset_claim must be a storage claim name")
    for key, default in (("readiness_timeout_seconds", 180), ("training_timeout_seconds", 3600),
                         ("cleanup_timeout_seconds", 60), ("request_timeout_seconds", 30)):
        value[key] = _positive(value.get(key, default), key)
    limit = value.get("max_transfer_bytes", 2 * 1024**3)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 0 < limit <= 8 * 1024**3:
        raise KubernetesError("max_transfer_bytes must be an integer from 1 through 8589934592")
    value["max_transfer_bytes"] = limit
    resources = value.get("resources", {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "1", "memory": "1Gi"}})
    if not isinstance(resources, dict) or set(resources) - {"requests", "limits"}:
        raise KubernetesError("resources accepts only requests and limits")
    for amounts in resources.values():
        if not isinstance(amounts, dict) or set(amounts) - {"cpu", "memory", "ephemeral-storage"}:
            raise KubernetesError("resource amounts accept only cpu, memory and ephemeral-storage")
        if any(not isinstance(x, str) or not x or len(x) > 128 for x in amounts.values()):
            raise KubernetesError("resource amounts must be nonempty quantity strings")
    value["resources"] = resources
    return value


def _state_path(base_dir):
    return Path(base_dir).resolve().parent / STATE_FILE


@contextmanager
def _locked(base_dir):
    import fcntl
    path = _state_path(base_dir).with_suffix(".lock")
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise KubernetesError("Another process owns this training attempt") from exc
        yield
    finally:
        os.close(fd)


def _save(base_dir, state):
    path = _state_path(base_dir)
    fd, temporary = tempfile.mkstemp(prefix=".hf2l-attempt-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(_json(state) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _load(base_dir):
    path = _state_path(base_dir)
    if path.is_symlink():
        raise KubernetesError("Attempt record must not be a symbolic link")
    state = json.loads(path.read_text())
    if state.get("base_dir") != str(Path(base_dir).resolve()) or state.get("version") != 1:
        raise KubernetesError("Attempt record belongs to different input")
    return state


def _manifest(directory, limit):
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise KubernetesError("Checkpoint directory must be a real directory")
    result = {}
    total = 0
    for path in sorted(directory.rglob("*")):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise KubernetesError("Checkpoint contains a link or special file")
        if not stat.S_ISREG(mode):
            continue
        total += path.stat().st_size
        if total > limit or len(result) >= _MAX_FILES:
            raise KubernetesError("Checkpoint exceeds the transfer budget")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        result[path.relative_to(directory).as_posix()] = {"size": path.stat().st_size, "sha256": digest.hexdigest()}
    if not result:
        raise KubernetesError("Checkpoint is empty")
    return result


def _validate_metadata(metadata):
    if not isinstance(metadata, dict):
        raise KubernetesError("train_model must return a metadata dictionary")
    count = metadata.get("num_examples")
    if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
        raise KubernetesError("train_model must return a positive integer num_examples")
    try:
        if len(_json(metadata).encode()) > 1024 * 1024:
            raise KubernetesError("Training metadata exceeds its one MiB safety limit")
    except (ValueError, TypeError) as exc:
        raise KubernetesError("Training metadata must contain finite JSON values") from exc
    return metadata


def _validate_outputs(base_dir, output_dir, limit):
    _manifest(output_dir, limit)
    validate_compatible(discover(Path(base_dir)), discover(Path(output_dir)))


def _kubectl(config, *, streaming=False):
    request_timeout = "0" if streaming else str(config["request_timeout_seconds"]) + "s"
    return ["kubectl", "--kubeconfig=" + config["kubeconfig"], "--context=" + config["context"],
            "--namespace=" + config["namespace"], "--request-timeout=" + request_timeout]


def _invoke(config, args, *, input_data=None, timeout=None):
    timeout = timeout or config["request_timeout_seconds"] + 5
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(_kubectl(config, streaming=bool(args and args[0] == "exec")) + list(args), stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                                   stdout=output, stderr=errors)
        deadline = time.monotonic() + timeout
        first = True
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(process.args, timeout)
                try:
                    process.communicate(input=input_data if first else None, timeout=min(0.2, remaining))
                    break
                except subprocess.TimeoutExpired:
                    first = False
                    if max(os.fstat(output.fileno()).st_size, os.fstat(errors.fileno()).st_size) > _COMMAND_LIMIT:
                        raise KubernetesError("kubectl command output exceeded its safety limit")
            if max(os.fstat(output.fileno()).st_size, os.fstat(errors.fileno()).st_size) > _COMMAND_LIMIT:
                raise KubernetesError("kubectl command output exceeded its safety limit")
            output.seek(0)
            errors.seek(0)
            if process.returncode:
                message = errors.read(_COMMAND_LIMIT).decode("utf-8", "replace")[-2000:]
                raise KubernetesError(f"kubectl {args[0]} failed: {message}")
            return output.read(_COMMAND_LIMIT)
        except BaseException:
            process.kill()
            process.wait()
            raise


def _pod(config, state):
    volumes = [{"name": "work", "emptyDir": {}}, {"name": "temporary", "emptyDir": {}}]
    mounts = [{"name": "work", "mountPath": "/work"}, {"name": "temporary", "mountPath": "/tmp"}]
    if config.get("dataset_claim"):
        volumes.append({"name": "data", "persistentVolumeClaim": {"claimName": config["dataset_claim"], "readOnly": True}})
        mounts.append({"name": "data", "mountPath": "/data", "readOnly": True})
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": state["pod_name"], "namespace": config["namespace"], "labels": {OWNER_LABEL: state["attempt_id"]}},
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001, "fsGroup": 10001, "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "trainer", "image": config["image"], "command": ["python", "-c", "import signal; signal.pause()"],
                                     "workingDir": "/work", "resources": config["resources"], "volumeMounts": mounts,
                                     "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}}],
                     "volumes": volumes}}


def _get_pod(config, state):
    raw = _invoke(config, ["get", "pod", state["pod_name"], "--ignore-not-found", "-o", "json"])
    return json.loads(raw) if raw.strip() else None


def _owned(config, state, *, allow_missing=False, persist_identity=True):
    pod = _get_pod(config, state)
    if pod is None:
        if allow_missing:
            return None
        raise KubernetesError("The attempt's pod is missing")
    metadata = pod.get("metadata", {})
    if metadata.get("labels", {}).get(OWNER_LABEL) != state["attempt_id"]:
        raise KubernetesError("Pod ownership changed; refusing access or deletion")
    uid = metadata.get("uid")
    if not isinstance(uid, str) or not uid or state.get("pod_uid") not in (None, uid):
        raise KubernetesError("Pod identity changed; refusing access or deletion")
    if state.get("pod_uid") is None:
        state["pod_uid"] = uid
        if persist_identity:
            _save(state["base_dir"], state)
    return pod


class _BoundedTarInfo(tarfile.TarInfo):
    @classmethod
    def frombuf(cls, buffer, encoding, errors):
        member = super().frombuf(buffer, encoding, errors)
        extended = {tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK}
        if member.type in extended and member.size > 65536:
            raise KubernetesError("Archive metadata header exceeds its safety limit")
        if member.type == tarfile.GNUTYPE_SPARSE:
            raise KubernetesError("Sparse archive entries are not supported")
        return member

    def _proc_pax(self, archive):
        # Python 3.14's internal header constructor bypasses frombuf overrides.
        # Enforce the budget at the payload boundary as well on every version.
        if self.size > 65536:
            raise KubernetesError("Archive metadata header exceeds its safety limit")
        return super()._proc_pax(archive)

    def _proc_gnulong(self, archive):
        if self.size > 65536:
            raise KubernetesError("Archive metadata header exceeds its safety limit")
        return super()._proc_gnulong(archive)

    def _proc_sparse(self, archive):
        raise KubernetesError("Sparse archive entries are not supported")


class _BoundedArchiveReader:
    def __init__(self, stream, limit):
        self.stream = stream
        self.remaining = limit

    def read(self, size=-1):
        if size < 0:
            size = 65536
        data = self.stream.read(min(size, self.remaining + 1, 65536))
        self.remaining -= len(data)
        if self.remaining < 0:
            raise KubernetesError("Raw archive exceeds its safety limit")
        return data


def _safe_extract(stream, destination, max_bytes):
    """Extract an uncompressed bounded archive without links or unsafe paths."""
    reader = _BoundedArchiveReader(stream, max_bytes + _MAX_FILES * 2048 + 65536)
    try:
        _extract_archive(reader, destination, max_bytes)
    except tarfile.TarError as exc:
        raise KubernetesError("Malformed or truncated checkpoint archive") from exc


def _extract_archive(stream, destination, max_bytes):
    """Accept only bounded regular files and directories."""
    destination = Path(destination)
    if destination.is_symlink() or not destination.is_dir():
        raise KubernetesError("Archive destination must be a real directory")
    seen = set()
    total = 0
    with tarfile.open(fileobj=stream, mode="r|", tarinfo=_BoundedTarInfo) as archive:
        for member in archive:
            name = member.name
            parts = name.split("/")
            if not name or name.startswith("/") or "\\" in name or ".." in parts or "\x00" in name or name in seen:
                raise KubernetesError("Unsafe or duplicate archive path")
            if len(seen) >= _MAX_FILES or not (member.isfile() or member.isdir()):
                raise KubernetesError("Archive contains a link, special file, or too many entries")
            seen.add(name)
            total += member.size
            if member.size < 0 or total > max_bytes:
                raise KubernetesError("Archive exceeds the transfer budget")
            path = destination.joinpath(*PurePosixPath(name).parts)
            if path != destination and destination not in path.parents:
                raise KubernetesError("Archive path escapes destination")
            if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent == destination or destination in parent.parents):
                raise KubernetesError("Archive path traverses an existing symbolic link")
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source, path.open("xb") as output:
                remaining = member.size
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise KubernetesError("Archive file is truncated")
                    output.write(chunk)
                    remaining -= len(chunk)


_EXTRACT = """import sys,tarfile,pathlib
root=pathlib.Path('/work')
with tarfile.open(fileobj=sys.stdin.buffer,mode='r|') as a:
 for m in a:
  p=pathlib.PurePosixPath(m.name)
  if p.is_absolute() or '..' in p.parts or not(m.isdir() or m.isfile()):raise ValueError('unsafe archive')
  d=root.joinpath(*p.parts)
  if m.isdir():d.mkdir(parents=True,exist_ok=True)
  else:
   d.parent.mkdir(parents=True,exist_ok=True)
   with a.extractfile(m) as src,d.open('xb') as out:
    while True:
     b=src.read(1048576)
     if not b:break
     out.write(b)
"""
_ARCHIVE = """import sys,tarfile,pathlib
root=pathlib.Path('/work')
with tarfile.open(fileobj=sys.stdout.buffer,mode='w|') as a:
 a.add(root/'metadata.json',arcname='metadata.json',recursive=False)
 a.add(root/'integrity.json',arcname='integrity.json',recursive=False)
 a.add(root/'output',arcname='output',recursive=False)
 for p in sorted((root/'output').rglob('*')):a.add(p,arcname='output/'+p.relative_to(root/'output').as_posix(),recursive=False)
"""


def _stream_to_pod(config, state, base_dir, training_options):
    manifest = _manifest(base_dir, config["max_transfer_bytes"])
    if manifest != state["base_manifest"]:
        raise KubernetesError("Base checkpoint changed before staging")
    with tempfile.TemporaryFile() as payload, tempfile.TemporaryFile() as errors:
        with tarfile.open(fileobj=payload, mode="w") as archive:
            for name in manifest:
                archive.add(Path(base_dir) / name, arcname="base/" + name, recursive=False)
            import io
            for name, value in (("options.json", training_options), ("base-manifest.json", state["base_manifest"])):
                data = _json(value).encode()
                header = tarfile.TarInfo(name)
                header.size = len(data)
                archive.addfile(header, io.BytesIO(data))
        payload.seek(0)
        process = subprocess.Popen(_kubectl(config, streaming=True) + ["exec", "-i", state["pod_name"], "--", "python", "-c", _EXTRACT], stdin=payload, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            process.wait(timeout=config["readiness_timeout_seconds"])
            if process.returncode:
                raise KubernetesError("Failed to stage the checkpoint into the pod")
        except BaseException:
            process.kill()
            process.wait()
            raise
    if _manifest(base_dir, config["max_transfer_bytes"]) != state["base_manifest"]:
        raise KubernetesError("Base checkpoint changed during staging")


def _read_bounded(path, limit):
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise KubernetesError("Result metadata exceeds its safety limit")
    return data


def _collect(config, state, destination):
    destination = Path(destination)
    with tempfile.TemporaryDirectory(prefix=".hf2l-collection-", dir=destination.parent) as temporary, tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(_kubectl(config, streaming=True) + ["exec", state["pod_name"], "--", "python", "-c", _ARCHIVE], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        timer = threading.Timer(config["readiness_timeout_seconds"], process.kill)
        timer.start()
        try:
            with process.stdout:
                _safe_extract(process.stdout, Path(temporary), config["max_transfer_bytes"])
            process.wait(timeout=config["request_timeout_seconds"] + 5)
            if process.returncode:
                raise KubernetesError("Failed to collect complete pod outputs")
            metadata_bytes = _read_bounded(Path(temporary) / "metadata.json", 1024 * 1024)
            metadata = _validate_metadata(json.loads(metadata_bytes))
            integrity = json.loads(_read_bounded(Path(temporary) / "integrity.json", 16 * 1024 * 1024))
            output = Path(temporary) / "output"
            if not output.is_dir():
                raise KubernetesError("Pod did not produce a checkpoint directory")
            if integrity.get("metadata_sha256") != hashlib.sha256(metadata_bytes).hexdigest() or integrity.get("output_manifest") != _manifest(output, config["max_transfer_bytes"]):
                raise KubernetesError("Collected outputs do not match the worker's integrity receipt")
            shutil.copytree(output, destination, dirs_exist_ok=True)
            return metadata
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()
            process.wait()


def _cleanup(state):
    _verify_config(state)
    config = state["config"]
    pod = _owned(config, state, allow_missing=True, persist_identity=False)
    if pod is None and state.get("creation_requested") and not state.get("creation_confirmed"):
        raise UncertainExecution("Pod creation outcome is unresolved; retain this attempt and retry its cleanup after restoring cluster access")
    if pod is not None:
        uid = state["pod_uid"]
        api_path = "/api/v1/namespaces/" + quote(config["namespace"], safe="") + "/pods/" + quote(state["pod_name"], safe="")
        body = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}, "gracePeriodSeconds": 0, "propagationPolicy": "Foreground"}
        _invoke(config, ["delete", "--raw", api_path, "-f", "-"], input_data=_json(body).encode(), timeout=config["cleanup_timeout_seconds"])
        deadline = time.monotonic() + config["cleanup_timeout_seconds"]
        while _owned(config, state, allow_missing=True, persist_identity=False) is not None:
            if time.monotonic() >= deadline:
                raise KubernetesError("Timed out waiting for the owned pod to be deleted")
            time.sleep(0.2)
    state["cleaned"] = True
    _save(state["base_dir"], state)


def _failed(base_dir, state, error, *, uncertain=False):
    state["phase"] = "uncertain" if uncertain else "failed"
    state["failure_type"] = type(error).__name__
    try:
        _save(base_dir, state)
    except BaseException as record_error:
        error.add_note("Could not persist the failed attempt; cleanup will still be attempted: " + str(record_error))
    try:
        _cleanup(state)
    except BaseException as cleanup_error:
        error.add_note("Pod cleanup also failed; run cleanup for the saved attempt after restoring access: " + str(cleanup_error))


def _verify_config(state):
    config = state["config"]
    if hashlib.sha256(_json(config).encode()).hexdigest() != state["config_sha256"] or hashlib.sha256(Path(config["kubeconfig"]).read_bytes()).hexdigest() != state["kubeconfig_sha256"]:
        raise KubernetesError("Cluster configuration no longer matches the frozen attempt")


def _unchanged(state):
    _verify_config(state)
    if _manifest(state["base_dir"], state["config"]["max_transfer_bytes"]) != state["base_manifest"]:
        raise KubernetesError("Base checkpoint no longer matches the frozen attempt")


def prepare(base_dir, output_dir, options):
    """Prepare exactly one owned pod; an existing attempt cannot be silently replaced."""
    if Path(base_dir).is_symlink() or Path(output_dir).is_symlink():
        raise KubernetesError("Input and output must not be symbolic links")
    base_dir = Path(base_dir).resolve()
    output_dir = Path(output_dir).resolve()
    if base_dir == output_dir or base_dir in output_dir.parents or output_dir in base_dir.parents:
        raise KubernetesError("Input and output directories must be separate")
    if not isinstance(options, dict) or not isinstance(options.get("pod_config"), (str, Path)):
        raise KubernetesError("pod_config must name an organization-local JSON configuration file")
    config = _config(options["pod_config"])
    training_options = {key: value for key, value in options.items() if key != "pod_config"}
    _json(training_options)
    manifest = _manifest(base_dir, config["max_transfer_bytes"])
    discover(base_dir)
    if output_dir.exists() and (not output_dir.is_dir() or any(output_dir.iterdir())):
        raise KubernetesError("Training output must be absent or empty")
    with _locked(base_dir):
        if _state_path(base_dir).exists():
            previous = _load(base_dir)
            if previous.get("phase") in ("running", "uncertain"):
                raise UncertainExecution("A previous attempt may have trained; cleanup or reconcile it, then use a new work directory")
            raise KubernetesError("This work directory already has a training attempt; use a new work directory")
        attempt = uuid.uuid4().hex
        state = {"version": 1, "attempt_id": attempt, "pod_name": "hf2l-train-" + attempt[:20], "pod_uid": None,
                 "phase": "preparing", "cleaned": False, "creation_requested": False, "creation_confirmed": False, "base_dir": str(base_dir), "output_dir": str(output_dir),
                 "config": config, "config_sha256": hashlib.sha256(_json(config).encode()).hexdigest(),
                 "kubeconfig_sha256": hashlib.sha256(Path(config["kubeconfig"]).read_bytes()).hexdigest(),
                 "base_manifest": manifest, "options": training_options}
        _save(base_dir, state)
        try:
            state["creation_requested"] = True
            _save(base_dir, state)
            raw = _invoke(config, ["create", "-f", "-", "-o", "json"], input_data=_json(_pod(config, state)).encode())
            created = json.loads(raw)
            state["creation_confirmed"] = True
            state["pod_uid"] = created.get("metadata", {}).get("uid")
            _save(base_dir, state)
            _owned(config, state)
            _invoke(config, ["wait", "--for=condition=Ready", "pod/" + state["pod_name"], "--timeout=" + str(config["readiness_timeout_seconds"]) + "s"], timeout=config["readiness_timeout_seconds"] + 5)
            _owned(config, state)
            _stream_to_pod(config, state, base_dir, training_options)
            state["phase"] = "prepared"
            _save(base_dir, state)
            return dict(state)
        except BaseException as exc:
            _failed(base_dir, state, exc)
            raise


def train(base_dir):
    """Execute training once. An interrupted execution is never automatically retried."""
    with _locked(base_dir):
        state = _load(base_dir)
        if state["phase"] in ("running", "uncertain"):
            raise UncertainExecution("Training may already have run; this attempt cannot be repeated")
        if state["phase"] != "prepared" or state.get("cleaned"):
            raise KubernetesError("Training requires a prepared, unused pod")
        config = state["config"]
        try:
            _unchanged(state)
            _owned(config, state)
            state["phase"] = "running"
            _save(base_dir, state)
            _invoke(config, ["exec", state["pod_name"], "--", "python", "-m", "hf2l.kubernetes", "worker", "--base-dir", "/work/base", "--output-dir", "/work/output", "--options-file", "/work/options.json", "--plugin", config["plugin"], "--metadata-file", "/work/metadata.json", "--base-manifest-file", "/work/base-manifest.json"], timeout=config["training_timeout_seconds"])
            _owned(config, state)
            _unchanged(state)
            state["phase"] = "trained"
            _save(base_dir, state)
        except BaseException as exc:
            uncertain = state.get("phase") == "running"
            _failed(base_dir, state, exc, uncertain=uncertain)
            if uncertain and not isinstance(exc, (KeyboardInterrupt, SystemExit, UncertainExecution)):
                raise UncertainExecution("Training did not finish with a confirmed result; the saved attempt will not run again") from exc
            raise


def post(base_dir):
    """Validate and collect outputs, delete the owned pod, then atomically expose results."""
    with _locked(base_dir):
        state = _load(base_dir)
        if state["phase"] != "trained" or state.get("cleaned"):
            raise KubernetesError("Post-training collection requires confirmed successful training")
        config = state["config"]
        output_dir = Path(state["output_dir"])
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=".hf2l-output-", dir=output_dir.parent))
        try:
            _unchanged(state)
            _owned(config, state)
            state["phase"] = "collecting"
            _save(base_dir, state)
            metadata = _validate_metadata(_collect(config, state, temporary))
            _validate_outputs(base_dir, temporary, config["max_transfer_bytes"])
            hashes = _manifest(temporary, config["max_transfer_bytes"])
            _unchanged(state)
            _owned(config, state)
            _cleanup(state)
            if output_dir.exists():
                if not output_dir.is_dir() or any(output_dir.iterdir()):
                    raise KubernetesError("Output changed during training; refusing to overwrite it")
                output_dir.rmdir()
            os.replace(temporary, output_dir)
            state["phase"] = "succeeded"
            state["output_manifest"] = hashes
            state["metadata"] = metadata
            _save(base_dir, state)
            return metadata
        except BaseException as exc:
            _failed(base_dir, state, exc)
            raise
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)


def cleanup(base_dir):
    """Idempotently remove only the pod identified by this attempt's saved UID."""
    with _locked(base_dir):
        state = _load(base_dir)
        _cleanup(state)
        if state["phase"] not in ("succeeded", "failed", "uncertain"):
            state["phase"] = "cleaned"
            _save(base_dir, state)


def train_model(base_dir, output_dir, options):
    prepare(base_dir, output_dir, options)
    train(base_dir)
    return post(base_dir)


def _worker(base_dir, output_dir, options_file, plugin, metadata_file, base_manifest_file=None):
    options = json.loads(Path(options_file).read_text())
    if not isinstance(options, dict) or "pod_config" in options:
        raise KubernetesError("Worker options must exclude cluster configuration")
    before = _manifest(base_dir, 8 * 1024**3)
    if base_manifest_file is not None and json.loads(Path(base_manifest_file).read_text()) != before:
        raise KubernetesError("Staged base checkpoint differs from the frozen input")
    output_dir = Path(output_dir)
    if output_dir.exists() and any(output_dir.iterdir()):
        raise KubernetesError("Worker output directory must be empty")
    with redirect_stdout(sys.stderr):
        trainer = require_callable(load_plugin(plugin), "train_model")
        metadata = _validate_metadata(trainer(Path(base_dir), output_dir, options))
    if _manifest(base_dir, 8 * 1024**3) != before:
        raise KubernetesError("Training changed the base checkpoint")
    _validate_outputs(base_dir, output_dir, 8 * 1024**3)
    metadata_bytes = (_json(metadata) + "\n").encode()
    with Path(metadata_file).open("xb") as stream:
        stream.write(metadata_bytes)
    integrity = {"metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(), "output_manifest": _manifest(output_dir, 8 * 1024**3)}
    with Path(metadata_file).with_name("integrity.json").open("x") as stream:
        stream.write(_json(integrity) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("pre", "train", "post", "cleanup", "run", "worker"):
        sub = subparsers.add_parser(command)
        sub.add_argument("--base-dir", type=Path, required=True)
        if command in ("pre", "run", "worker"):
            sub.add_argument("--output-dir", type=Path, required=True)
            sub.add_argument("--options-file", type=Path, required=True)
        if command == "worker":
            sub.add_argument("--plugin", required=True)
            sub.add_argument("--metadata-file", type=Path, required=True)
            sub.add_argument("--base-manifest-file", type=Path)
    args = parser.parse_args(argv)
    if args.command in ("pre", "run"):
        options = json.loads(args.options_file.read_text())
        result = prepare(args.base_dir, args.output_dir, options) if args.command == "pre" else train_model(args.base_dir, args.output_dir, options)
        if args.command == "run":
            print(_json(result))
    elif args.command == "train":
        train(args.base_dir)
    elif args.command == "post":
        print(_json(post(args.base_dir)))
    elif args.command == "cleanup":
        cleanup(args.base_dir)
    else:
        _worker(args.base_dir, args.output_dir, args.options_file, args.plugin, args.metadata_file, args.base_manifest_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
