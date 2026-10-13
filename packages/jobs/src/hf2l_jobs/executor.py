"""Fenced Linux OCI execution with no ordinary-container fallback.

All paths/configuration in this module are supplied by a trusted node agent.
Job specifications cannot override mounts, networking, runtime, or flags.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import threading
import tempfile
import time
from typing import Any, Callable, Protocol, Sequence

class ExecutorRefused(RuntimeError):
    """The requested execution cannot be safely admitted."""
    def __init__(self, message: str, code: str = "executor_refused"):
        super().__init__(message)
        self.code = code

class UncertainExecution(RuntimeError):
    """An operation's effect is unknown; retain and quarantine allocation."""
    code = "execution_unknown"

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_DIGEST = re.compile(r"^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$")
_IMAGE_ID = re.compile(r"^sha256:[a-f0-9]{64}$")

@dataclass(frozen=True)
class ExecutionIdentity:
    job_id: str
    attempt_id: str
    component_id: str
    epoch: int
    def __post_init__(self):
        for value in (self.job_id, self.attempt_id, self.component_id):
            if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
                raise ExecutorRefused("Invalid execution identity", "invalid_identity")
        if type(self.epoch) is not int or self.epoch < 1:
            raise ExecutorRefused("Epoch must be positive", "invalid_epoch")
    @property
    def key(self) -> str:
        raw = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

@dataclass(frozen=True)
class ResourceLimits:
    cpu_millis: int
    memory_bytes: int
    disk_bytes: int
    pids: int = 128
    io_bps: int = 16 * 1024 * 1024
    gpus: int = 0
    def __post_init__(self):
        for name in ("cpu_millis", "memory_bytes", "disk_bytes", "pids", "io_bps"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ExecutorRefused("Resource limits must be positive integers", "invalid_resources")
        if self.pids > 128 or self.io_bps > 16 * 1024 * 1024:
            raise ExecutorRefused("Resource caps exceed the qualified CPU profile", "unsupported_profile")
        if self.gpus != 0:
            raise ExecutorRefused("CPU profile does not support GPU allocation", "unsupported_profile")

@dataclass(frozen=True)
class ExecutionSpec:
    identity: ExecutionIdentity
    image_digest: str
    source_path: str
    state_path: str
    argv: tuple[str, ...]
    proxy_endpoint: str | None
    resources: ResourceLimits
    lease_seconds: float = 120
    pool_id: str = ""
    node_id: str = ""
    deadline: float | None = None
    config_path: str | None = None
    profile: str = "runsc-cpu-v1"
    role: str = "owner"
    secret_path: str | None = None
    dataset_binding_id: str | None = None
    participant_id: str | None = None
    build_input_path: str | None = None
    def __post_init__(self):
        if not (_DIGEST.fullmatch(self.image_digest) or _IMAGE_ID.fullmatch(self.image_digest)):
            raise ExecutorRefused("Runtime image must be pinned to a digest", "image_not_pinned")
        allowed = ("python", "-m", "hf2l_jobs.runtime", "--config", "/run/hf2l/runtime.json")
        if self.argv != allowed:
            raise ExecutorRefused("Only the approved managed worker can be invoked", "invalid_invocation")
        if isinstance(self.lease_seconds, bool) or not isinstance(self.lease_seconds, (int, float)) or not 0 < self.lease_seconds <= 300:
            raise ExecutorRefused("Execution lease must be at most 300 seconds", "invalid_lease")
        if self.deadline is not None and (isinstance(self.deadline, bool) or not isinstance(self.deadline, (int, float)) or not math.isfinite(self.deadline) or self.deadline <= 0):
            raise ExecutorRefused("Invalid job deadline", "invalid_deadline")
        if self.role not in ("owner", "client", "build", "init"):
            raise ExecutorRefused("Unsupported component role", "invalid_invocation")
        if not self.proxy_endpoint and self.role != "build":
            raise ExecutorRefused("FL execution requires its assigned proxy", "missing_proxy")
        if self.role == "build" and (self.proxy_endpoint or self.secret_path or self.dataset_binding_id or self.build_input_path):
            raise ExecutorRefused("Build components cannot receive workload credentials", "unsafe_proxy")
        if self.dataset_binding_id and (self.role != "client" or not self.participant_id):
            raise ExecutorRefused("Dataset requires its assigned participant client", "unsafe_dataset")
        if self.profile != "runsc-cpu-v1":
            raise ExecutorRefused("Unsupported sandbox profile", "unsupported_profile")

@dataclass(frozen=True)
class Reservation:
    identity: ExecutionIdentity
    acknowledged: bool
    node_id: str = ""
    state: str = "RESERVED"

@dataclass(frozen=True)
class RuntimeObservation:
    identity: ExecutionIdentity
    state: str
    termination_confirmed: bool = False
    publication_status: str = "unknown"
    current_round: int | None = None
    error_code: str | None = None
    transient: bool = False
    exit_code: int | None = None
    details: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, float] = field(default_factory=dict)
    phase: str | None = None
    readiness: str | None = None

class Executor(Protocol):
    def reserve(self, spec: ExecutionSpec) -> Reservation: ...
    def start(self, identity: ExecutionIdentity) -> RuntimeObservation: ...
    def inspect(self, identity: ExecutionIdentity) -> RuntimeObservation: ...
    def stop(self, identity: ExecutionIdentity, grace_seconds: int = 60) -> RuntimeObservation: ...
    def collect(self, identity: ExecutionIdentity) -> Any: ...
    def release(self, identity: ExecutionIdentity) -> bool: ...

def run_command(argv: Sequence[str], *, timeout: float = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, check=False)

class LinuxExecutor:
    """Task-owned Docker daemon using qualified gVisor and network-less jobs.

    A fixed-size ext4 filesystem bounds each writable state volume. No writable
    host directory is mounted. Container logs are separately rotated and bounded.
    Unknown external effects are never interpreted as confirmation of cleanup.
    """
    def __init__(self, profile_path: str | Path, root: str | Path,
                 runner: Callable[..., Any] = run_command, *, validate: bool = True,
                 dataset_authorizer=None, dataset_bindings=None):
        self.profile_path = Path(profile_path)
        self.root = Path(root).absolute()
        self.runner = runner
        self.dataset_authorizer = dataset_authorizer
        self.dataset_bindings = dataset_bindings or {}
        self.lock = threading.RLock()
        self._operations = {}
        self._lock_depth = threading.local()
        self.lease_guard = None
        try:
            st = self.profile_path.stat()
            if st.st_mode & stat.S_IWOTH:
                raise ExecutorRefused("Qualification profile is world-writable", "unqualified_profile")
            self.profile = json.loads(self.profile_path.read_text())
        except (OSError, ValueError) as exc:
            raise ExecutorRefused("Missing qualified sandbox profile", "unqualified_profile") from exc
        self.prefix = self.profile.get("docker_command", ["sudo", "-n", "docker", "-H", self.profile.get("docker_host", "")])
        self.system_prefix = self.profile.get("system_command", ["sudo", "-n"])
        uid = self.profile.get("sandbox_uid", os.getuid() or 65532)
        gid = self.profile.get("sandbox_gid", os.getgid() or 65532)
        if not isinstance(uid, int) or not isinstance(gid, int) or uid <= 0 or gid <= 0:
            raise ExecutorRefused("Sandbox identity must be non-root", "unsafe_runtime")
        self.user = str(uid) + ":" + str(gid)
        required = {
            "runtime": "runsc", "network": "none", "proxy_transport": "unix",
            "bounded_volumes": "loop-ext4", "runsc_network": "sandbox",
            "runsc_host_uds": "open",
        }
        for key, expected in required.items():
            if self.profile.get(key) != expected:
                raise ExecutorRefused("Required runtime isolation profile is unavailable: " + key, "unqualified_profile")
        if self.profile.get("qualified") is not True:
            raise ExecutorRefused("Sandbox has not passed qualification", "unqualified_profile")
        self.owned_root = Path(self.profile.get("owned_root", str(self.root))).resolve()
        if self.root != self.owned_root and self.owned_root not in self.root.parents:
            raise ExecutorRefused("Executor root must belong to qualified node", "unsafe_root")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if validate:
            self.qualify_health()

    def _command(self, argv: Sequence[str], *, timeout: float = 60,
                 uncertain: bool = False, allow_failure: bool = False):
        try:
            result = self.runner(list(argv), timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            if uncertain:
                raise UncertainExecution("Node command outcome unknown") from exc
            raise ExecutorRefused("Node command failed", "runtime_unhealthy") from exc
        if result.returncode and not allow_failure:
            if uncertain:
                raise UncertainExecution("Node command failed after dispatch")
            raise ExecutorRefused("Node command rejected", "runtime_unhealthy")
        return result

    def _docker(self, args: Sequence[str], **kwargs):
        return self._command([*self.prefix, *args], **kwargs)

    def _system(self, args: Sequence[str], **kwargs):
        return self._command([*self.system_prefix, *args], **kwargs)

    def qualify_health(self):
        info = json.loads(self._docker(["info", "--format", "{{json .}}"]).stdout)
        if "runsc" not in info.get("Runtimes", {}) or info.get("CgroupVersion") != "2":
            raise ExecutorRefused("gVisor/cgroup-v2 runtime health check failed", "runtime_unhealthy")
        daemon_config = self.profile.get("daemon_config")
        if not daemon_config:
            raise ExecutorRefused("Qualified daemon configuration is missing", "unqualified_profile")
        config_bytes = Path(daemon_config).read_bytes()
        if hashlib.sha256(config_bytes).hexdigest() != self.profile.get("daemon_config_sha256"):
            raise ExecutorRefused("Qualified daemon configuration changed", "runtime_unhealthy")
        config = json.loads(config_bytes)
        if info.get("DockerRootDir") != self.profile.get("docker_data_root") or info.get("Containerd", {}).get("Address") != self.profile.get("containerd_socket"):
            raise ExecutorRefused("Docker/containerd identity differs from qualification", "runtime_unhealthy")
        unit = self.profile.get("daemon_unit")
        if not unit:
            raise ExecutorRefused("Qualified daemon identity is missing", "unqualified_profile")
        pid = self._system(["systemctl", "show", unit, "--property=MainPID", "--value"]).stdout.strip()
        if not re.fullmatch(r"[1-9][0-9]*", pid):
            raise ExecutorRefused("Qualified daemon is not running", "runtime_unhealthy")
        runtime_environment = self.profile.get("runtime_environment")
        if runtime_environment is not None:
            if runtime_environment != {"GOMAXPROCS": "2"} or not self.profile.get("containerd_unit"):
                raise ExecutorRefused("Qualified runtime threading policy is invalid", "unqualified_profile")
            affinity = self.profile.get("runtime_cpu_affinity")
            cpu_count = self.profile.get("runtime_cpu_count")
            if (not isinstance(affinity, list) or not affinity
                    or type(cpu_count) is not int or cpu_count < len(affinity)
                    or any(type(cpu) is not int or cpu < 0 for cpu in affinity)
                    or sorted(set(affinity)) != affinity):
                raise ExecutorRefused("Qualified runtime CPU affinity is invalid", "unqualified_profile")
            policy_path = self.profile.get("runtime_cpu_policy")
            if not isinstance(policy_path, str) or not Path(policy_path).is_absolute():
                raise ExecutorRefused("Qualified runtime CPU policy is missing", "unqualified_profile")
            policy_file = Path(policy_path)
            try:
                metadata = policy_file.lstat()
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                        or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077
                        or metadata.st_size > 64 * 1024
                        or any(parent.is_symlink() for parent in policy_file.parents)):
                    raise ValueError("Unsafe CPU policy file")
                policy_bytes = policy_file.read_bytes()
                policy = json.loads(policy_bytes)
            except (OSError, ValueError) as exc:
                raise ExecutorRefused("Qualified runtime CPU policy is unavailable", "runtime_unhealthy") from exc
            if (hashlib.sha256(policy_bytes).hexdigest() != self.profile.get("runtime_cpu_policy_sha256")
                    or policy != {"cpu_count": cpu_count, "cpu_affinity": affinity}):
                raise ExecutorRefused("Qualified runtime CPU policy changed", "runtime_unhealthy")
            for runtime_unit in (unit, self.profile["containerd_unit"]):
                environment = self._system(["systemctl", "show", runtime_unit,
                                            "--property=Environment", "--value"]).stdout.split()
                if "GOMAXPROCS=2" not in environment:
                    raise ExecutorRefused("Qualified runtime threading settings changed", "runtime_unhealthy")
                runtime_pid = self._system(["systemctl", "show", runtime_unit,
                                            "--property=MainPID", "--value"]).stdout.strip()
                if not re.fullmatch(r"[1-9][0-9]*", runtime_pid):
                    raise ExecutorRefused("Qualified runtime process is missing", "runtime_unhealthy")
                if sorted(os.sched_getaffinity(int(runtime_pid))) != affinity:
                    raise ExecutorRefused("Qualified runtime host CPU affinity changed", "runtime_unhealthy")
        net = self._system(["readlink", "/proc/" + pid + "/ns/net"]).stdout.strip()
        host_net = self._system(["readlink", "/proc/1/ns/net"]).stdout.strip()
        if not net or net == host_net:
            raise ExecutorRefused("Daemon escaped its qualified private network namespace", "runtime_unhealthy")
        runtime = config.get("runtimes", {}).get("runsc", {})
        args = runtime.get("runtimeArgs", [])
        if "--network=sandbox" not in args or "--host-uds=open" not in args:
            raise ExecutorRefused("runsc network/UDS configuration changed", "runtime_unhealthy")
        runtime_files = self.profile.get("runtime_files_sha256")
        if not isinstance(runtime_files, dict) or not runtime_files:
            raise ExecutorRefused("Qualified runtime sidecar manifest is missing", "unqualified_profile")
        for filename, digest in runtime_files.items():
            file = Path(filename)
            if not file.is_absolute() or any(parent.is_symlink() for parent in (file, *file.parents)):
                raise ExecutorRefused("Qualified runtime path is unsafe", "runtime_unhealthy")
            metadata = file.stat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_mode & 0o022:
                raise ExecutorRefused("Qualified runtime file permissions changed", "runtime_unhealthy")
            if hashlib.sha256(file.read_bytes()).hexdigest() != digest:
                raise ExecutorRefused("Qualified runtime sidecar has changed", "runtime_unhealthy")
        expected_binary = self.profile.get("runsc_sha256")
        binary = runtime.get("path")
        if not binary or not expected_binary:
            raise ExecutorRefused("Runtime binary is not qualified", "unqualified_profile")
        if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != expected_binary:
            raise ExecutorRefused("Runtime binary has changed", "runtime_unhealthy")
        devices = self._qualified_backing_devices()
        for path in (self.owned_root, self.profile["docker_data_root"]):
            if self._backing_device(path) not in devices:
                raise ExecutorRefused("Node/runtime storage differs from physical I/O qualification", "runtime_unhealthy")

    def _backing_device(self, value: str | Path) -> dict:
        """Derive a physical device from trusted host paths, never from job fields."""
        path = Path(value)
        try:
            device_number = path.stat().st_dev
        except PermissionError:
            raw = self._system(["stat", "--format=%d", "--", str(path)]).stdout.strip()
            if not raw.isdigit():
                raise ExecutorRefused("Cannot establish trusted filesystem backing", "unsupported_backing")
            device_number = int(raw)
        except OSError as exc:
            raise ExecutorRefused("Trusted backing path is unavailable", "unsupported_backing") from exc
        sysfs = Path("/sys/dev/block") / (str(os.major(device_number)) + ":" + str(os.minor(device_number)))
        try:
            resolved = sysfs.resolve(strict=True)
            if Path("/sys/devices") not in resolved.parents:
                raise ValueError("Nonphysical filesystem")
            while (resolved / "partition").exists():
                resolved = resolved.parent
            major_minor = (resolved / "dev").read_text().strip()
            if not re.fullmatch(r"[0-9]+:[0-9]+", major_minor):
                raise ValueError("Invalid kernel device identity")
            major, minor = (int(part) for part in major_minor.split(":"))
            if (resolved / "slaves").exists() and any((resolved / "slaves").iterdir()):
                raise ValueError("Stacked device needs a separate qualified profile")
            if resolved.name.startswith(("loop", "ram", "zram", "dm-")):
                raise ValueError("Unsupported backing device")
            device_path = Path("/dev") / resolved.name
            metadata = device_path.lstat()
            if not stat.S_ISBLK(metadata.st_mode) or metadata.st_rdev != os.makedev(major, minor):
                raise ValueError("Device node differs from kernel identity")
            return {"path": str(device_path), "major": major, "minor": minor, "sysfs_path": str(resolved)}
        except (OSError, ValueError) as exc:
            raise ExecutorRefused("Filesystem has no qualified physical block backing", "unsupported_backing") from exc

    @staticmethod
    def _validate_device_evidence(item: dict) -> None:
        sysfs = Path("/sys/dev/block") / (str(item["major"]) + ":" + str(item["minor"]))
        try:
            resolved = sysfs.resolve(strict=True)
            device = Path(item["path"])
            metadata = device.lstat()
            if (item["sysfs_path"] != str(resolved) or Path("/sys/devices") not in resolved.parents
                    or (resolved / "partition").exists() or (resolved / "dev").read_text().strip() !=
                    str(item["major"]) + ":" + str(item["minor"]) or device != Path("/dev") / resolved.name
                    or not stat.S_ISBLK(metadata.st_mode)
                    or metadata.st_rdev != os.makedev(item["major"], item["minor"])):
                raise ValueError("Qualified physical device identity changed")
        except (OSError, ValueError) as exc:
            raise ExecutorRefused("Qualified backing device changed", "runtime_unhealthy") from exc

    def _qualified_backing_devices(self) -> list[dict]:
        devices = self.profile.get("backing_devices")
        if self.profile.get("backing_io_qualified") is not True or not isinstance(devices, list) or not devices:
            raise ExecutorRefused("Readonly physical I/O isolation is not qualified", "unqualified_profile")
        result = []
        for item in devices:
            if not isinstance(item, dict) or set(item) != {"path", "major", "minor", "sysfs_path"}:
                raise ExecutorRefused("Physical I/O evidence is invalid", "unqualified_profile")
            if type(item["major"]) is not int or type(item["minor"]) is not int or item["major"] < 0 or item["minor"] < 0:
                raise ExecutorRefused("Physical I/O device identity is invalid", "unqualified_profile")
            self._validate_device_evidence(item)
            if item in result:
                raise ExecutorRefused("Duplicate physical I/O evidence", "unqualified_profile")
            result.append(item)
        return result

    def _io_devices(self, spec: ExecutionSpec, dataset_path: Path | None = None) -> list[str]:
        approved = self._qualified_backing_devices()
        paths = [self.root, self.profile["docker_data_root"], spec.source_path, spec.state_path]
        paths += [path for path in (spec.config_path, spec.secret_path, spec.build_input_path, dataset_path) if path]
        devices = set()
        for path in paths:
            device = self._backing_device(path)
            if device not in approved:
                raise ExecutorRefused("Trusted mount backing device is not qualified", "unqualified_backing")
            devices.add(device["path"])
        return sorted(devices)

    @contextmanager
    def _operation_lock(self, identity: ExecutionIdentity):
        with self.lock:
            mutex = self._operations.setdefault(identity.key, threading.RLock())
        with mutex:
            depths = getattr(self._lock_depth, "depths", {})
            self._lock_depth.depths = depths
            if depths.get(identity.key, 0):
                depths[identity.key] += 1
                try: yield
                finally: depths[identity.key] -= 1
                return
            directory = self.root / "locks"
            directory.mkdir(mode=0o700, exist_ok=True)
            descriptor = os.open(directory / (identity.key + ".lock"),
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ExecutorRefused("Execution operation lock is unsafe", "unsafe_root")
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                depths[identity.key] = 1
                try: yield
                finally:
                    depths.pop(identity.key, None)
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _directory(self, identity: ExecutionIdentity) -> Path:
        return self.root / identity.key

    def _record(self, identity: ExecutionIdentity) -> Path:
        return self._directory(identity) / "execution.json"

    def _load(self, identity: ExecutionIdentity) -> dict:
        try:
            record = json.loads(self._record(identity).read_text())
        except (OSError, ValueError) as exc:
            raise ExecutorRefused("No acknowledged execution reservation", "missing_reservation") from exc
        if record["identity"] != asdict(identity):
            raise ExecutorRefused("Execution identity differs from ledger", "identity_mismatch")
        return record

    def _save(self, identity: ExecutionIdentity, record: dict):
        path = self._record(identity)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump(record, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, path)
            dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(dfd)
            finally: os.close(dfd)
        finally:
            if tmp.exists(): tmp.unlink()

    def _trusted_path(self, value: str, *, kind: str) -> Path:
        if not isinstance(value, str) or not Path(value).is_absolute() or any(part in (".", "..") for part in value.split("/")) or any(char in value for char in (",", "\n", "\r", "\x00", "\\")):
            raise ExecutorRefused("Invalid mount path", "unsafe_mount")
        path = Path(value).absolute()
        root = self.owned_root
        if root not in path.parents:
            raise ExecutorRefused("Mount path is outside the private node resource root", "unsafe_mount")
        current = root
        if root.is_symlink():
            raise ExecutorRefused("Private resource root cannot be a symlink", "unsafe_mount")
        for part in path.relative_to(root).parts:
            current = current / part
            if current.is_symlink():
                raise ExecutorRefused("Mount path cannot traverse symlinks", "unsafe_mount")
        try: st = path.stat()
        except OSError as exc:
            raise ExecutorRefused("Private resource is missing", "missing_resource") from exc
        if kind == "directory" and not stat.S_ISDIR(st.st_mode):
            raise ExecutorRefused("Expected private directory", "unsafe_mount")
        if kind == "socket" and (not stat.S_ISSOCK(st.st_mode) or st.st_nlink != 1):
            raise ExecutorRefused("Assigned proxy must be a Unix socket", "unsafe_proxy")
        if kind == "file" and (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1):
            raise ExecutorRefused("Expected private regular configuration file", "unsafe_mount")
        return path

    def _dataset_path(self, spec: ExecutionSpec) -> Path | None:
        if not spec.dataset_binding_id:
            return None
        if self.dataset_authorizer:
            value = self.dataset_authorizer(spec.dataset_binding_id, spec.identity, spec.participant_id)
        else:
            binding = self.dataset_bindings.get(spec.dataset_binding_id, {})
            if (binding.get("participant_id") != spec.participant_id or
                    spec.identity.job_id not in binding.get("job_ids", ())):
                raise ExecutorRefused("Dataset is not locally approved for this job participant", "dataset_not_approved")
            value = binding.get("path")
        if value == {"kind": "synthetic"}:
            return None
        if not value:
            raise ExecutorRefused("Dataset binding has no approved local resource", "dataset_not_approved")
        path = Path(value).absolute()
        if any(part in (".", "..") for part in str(value).split("/")):
            raise ExecutorRefused("Approved dataset path cannot traverse directories", "unsafe_dataset")
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in path.parts[1:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor); descriptor = next_fd
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
            try:
                metadata = os.fstat(fd)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ExecutorRefused("Dataset must be a private regular file", "unsafe_dataset")
            finally:
                os.close(fd)
        except OSError as exc:
            raise ExecutorRefused("Dataset path is unsafe or unavailable", "unsafe_dataset") from exc
        finally:
            os.close(descriptor)
        return path

    def _proxy_path(self, spec: ExecutionSpec) -> Path | None:
        if spec.proxy_endpoint is None:
            return None
        expected = self.owned_root / "p" / spec.identity.key / "s"
        if spec.proxy_endpoint != str(expected):
            raise ExecutorRefused("Proxy socket is not bound to this execution", "unsafe_proxy")
        return expected

    def confirm_absent(self, identity: ExecutionIdentity) -> bool:
        with self._operation_lock(identity):
            directory = self._directory(identity)
            if directory.exists() or directory.is_symlink():
                return False
            self.qualify_health()
            container = "hf2l-" + identity.key
            result = self._docker(["inspect", "--type", "container", container], allow_failure=True)
            if result.returncode != 1:
                return False
            message = getattr(result, "stderr", "")
            return ("No such object: " + container in message
                    or "No such container: " + container in message)

    def reserve(self, spec: ExecutionSpec) -> Reservation:
        self._proxy_path(spec)
        self._dataset_path(spec)
        with self._operation_lock(spec.identity):
            directory = self._directory(spec.identity)
            if self._record(spec.identity).exists():
                existing = self._load(spec.identity)
                if existing["spec"] != self._serialize_spec(spec):
                    raise ExecutorRefused("Idempotent reservation payload changed", "reservation_conflict")
                return Reservation(spec.identity, True, spec.node_id, existing["state"])
            if spec.resources.disk_bytes < 36 * 1024 * 1024:
                raise ExecutorRefused("Fixed volume and logs require at least 36MiB", "invalid_resources")
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            record = {"identity": asdict(spec.identity), "spec": self._serialize_spec(spec),
                      "state": "RESERVED", "container": "hf2l-" + spec.identity.key,
                      "mounted": False, "loop_device": None, "retained": False}
            self._save(spec.identity, record)
            return Reservation(spec.identity, True, spec.node_id)

    @staticmethod
    def _serialize_spec(spec: ExecutionSpec) -> dict:
        result = asdict(spec)
        result["argv"] = list(spec.argv)
        return result

    @staticmethod
    def _spec(record: dict) -> ExecutionSpec:
        spec = dict(record["spec"])
        spec["identity"] = ExecutionIdentity(**spec["identity"])
        spec["resources"] = ResourceLimits(**spec["resources"])
        spec["argv"] = tuple(spec["argv"])
        return ExecutionSpec(**spec)

    def _prepare_volume(self, identity: ExecutionIdentity, record: dict):
        spec = self._spec(record)
        directory = self._directory(identity)
        image = directory / "state.ext4"
        mount = directory / "state"
        mount.mkdir(exist_ok=True, mode=0o700)
        if not image.exists():
            # Truncate is bounded, and the loop filesystem has no route to grow.
            with image.open("wb") as stream: stream.truncate(spec.resources.disk_bytes)
            self._system(["mkfs.ext4", "-q", "-F", str(image)], timeout=120)
        if not record["mounted"]:
            loop = self._system(["losetup", "--find", "--show", str(image)], uncertain=True).stdout.strip()
            if not re.fullmatch(r"/dev/loop[0-9]+", loop):
                raise UncertainExecution("Loop device assignment cannot be confirmed")
            record["loop_device"] = loop
            self._save(identity, record)
            self._system(["mount", "-t", "ext4", "-o", "nodev,nosuid,noexec", loop, str(mount)], uncertain=True)
            record["mounted"] = True
            self._save(identity, record)
            self._system(["chown", self.user, str(mount)])
            self._system(["rmdir", str(mount / "lost+found")])
            # State source is provisioner-owned; never follow symlink or copy links.
            from .collection import SafeCollector
            with SafeCollector(spec.state_path, max_total_bytes=spec.resources.disk_bytes // 2) as collector:
                for item in collector.list_files():
                    target = mount / item.path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    data = collector.read(item.path)
                    with target.open("xb") as output: output.write(data)
                    self._system(["chown", self.user, str(target)])
            self._system(["chown", "-R", self.user, str(mount)])
        return mount

    def start(self, identity: ExecutionIdentity) -> RuntimeObservation:
        with self._operation_lock(identity):
            self.qualify_health()
            record = self._load(identity)
            if record["state"] in ("RUNNING", "STARTING"):
                return self.inspect(identity)
            if record["state"] not in ("RESERVED", "PREPARING"):
                raise ExecutorRefused("Execution is not startable", "invalid_execution_state")
            record["state"] = "PREPARING"
            self._save(identity, record)
            spec = self._spec(record)
            self._trusted_path(spec.source_path, kind="directory")
            self._trusted_path(spec.state_path, kind="directory")
            if spec.proxy_endpoint: self._trusted_path(spec.proxy_endpoint, kind="socket")
            if spec.config_path: self._trusted_path(spec.config_path, kind="file")
            if spec.secret_path:
                self._trusted_path(spec.secret_path, kind="file")
                if identity.job_id not in Path(spec.secret_path).parts:
                    raise ExecutorRefused("Secrets are not bound to the current job", "unsafe_mount")
            dataset_path = self._dataset_path(spec)
            if spec.build_input_path:
                self._trusted_path(spec.build_input_path, kind="directory")
                if identity.job_id not in Path(spec.build_input_path).parts:
                    raise ExecutorRefused("Build products are not bound to this job", "unsafe_mount")
                from .collection import SafeCollector
                with SafeCollector(spec.build_input_path, max_total_bytes=spec.resources.disk_bytes) as build_inputs:
                    build_inputs.list_files()
            self._proxy_path(spec)
            for value in (spec.source_path, spec.state_path):
                if identity.job_id not in Path(value).parts:
                    raise ExecutorRefused("Mount is not bound to this job", "unsafe_mount")
            backing_devices = self._io_devices(spec, dataset_path)
            record["backing_io_devices"] = backing_devices
            self._save(identity, record)
            mount = self._prepare_volume(identity, record)
            loop = record["loop_device"]
            labels = {"hf2l.managed": "true", **{"hf2l." + k: str(v) for k, v in asdict(identity).items()}}
            args = ["create", "--name", record["container"], "--runtime", "runsc",
                    "--entrypoint", "python", "--workdir", "/job/state",
                    "--network", "none", "--read-only", "--user", self.user,
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                    "--cpus", str(spec.resources.cpu_millis / 1000),
                    "--memory", str(spec.resources.memory_bytes),
                    "--memory-swap", str(spec.resources.memory_bytes),
                    "--pids-limit", str(spec.resources.pids), "--shm-size", "16777216",
                    "--ulimit", "nproc=64:64",
                    "--device-read-bps", loop + ":" + str(spec.resources.io_bps),
                    "--device-write-bps", loop + ":" + str(spec.resources.io_bps),
                    "--log-driver", "local", "--log-opt", "max-size=1m",
                    "--log-opt", "max-file=3",
                    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777",
                    "--mount", "type=bind,src=" + spec.source_path + ",dst=/job/source,readonly",
                    "--mount", "type=bind,src=" + str(mount) + ",dst=/job/state",
                    "--env", "HF2L_STATE_DIR=/job/state",
                    "--env", "HOME=/job/state/home",
                    "--env", "OMP_NUM_THREADS=1", "--env", "OPENBLAS_NUM_THREADS=1"]
            if spec.proxy_endpoint:
                args += ["--mount", "type=bind,src=" + spec.proxy_endpoint + ",dst=/run/hf2l/proxy.sock,readonly",
                         "--env", "HF2L_PROXY_UDS=/run/hf2l/proxy.sock"]
            if spec.config_path:
                args += ["--mount", "type=bind,src=" + spec.config_path + ",dst=/run/hf2l/runtime.json,readonly"]
            if spec.secret_path:
                args += ["--mount", "type=bind,src=" + spec.secret_path + ",dst=/run/hf2l/secrets.json,readonly"]
            if dataset_path:
                args += ["--mount", "type=bind,src=" + str(dataset_path) + ",dst=/job/data/data.npz,readonly"]
                record["dataset_path"] = str(dataset_path)
            if spec.build_input_path:
                args += ["--mount", "type=bind,src=" + spec.build_input_path + ",dst=/job/build,readonly"]
            if spec.role == "build":
                if not spec.config_path or json.loads(Path(spec.config_path).read_text()).get("role") != "build":
                    raise ExecutorRefused("Build isolation requires a trusted build manifest", "invalid_invocation")
            for device in backing_devices:
                args += ["--device-read-bps", device + ":" + str(spec.resources.io_bps),
                         "--device-write-bps", device + ":" + str(spec.resources.io_bps)]
            for key, value in labels.items(): args += ["--label", key + "=" + value]
            args += [spec.image_digest, *spec.argv[1:]]
            record["state"] = "STARTING"
            self._save(identity, record)
            result = self._docker(args, uncertain=True)
            record["container_id"] = result.stdout.strip()
            self._save(identity, record)
            # Inspect the actual OCI configuration before any untrusted code runs.
            self._verify_container(record)
            if self.lease_guard is not None and not self.lease_guard(identity):
                raise ExecutorRefused("Execution lease expired before launch", "lease_expired")
            self._docker(["start", record["container"]], uncertain=True)
            record["state"] = "RUNNING"
            self._save(identity, record)
            return self.inspect(identity)

    def _verify_container(self, record: dict):
        raw = json.loads(self._docker(["inspect", record["container"]], uncertain=True).stdout)[0]
        host = raw["HostConfig"]
        spec = self._spec(record)
        expected_io_devices = set(record.get("backing_io_devices", ())) | {record["loop_device"]}
        actual_read = {item.get("Path"): item.get("Rate") for item in host.get("BlkioDeviceReadBps", [])}
        actual_write = {item.get("Path"): item.get("Rate") for item in host.get("BlkioDeviceWriteBps", [])}
        expected_io = {device: spec.resources.io_bps for device in expected_io_devices}
        checks = (actual_read == expected_io, actual_write == expected_io,
                  host.get("Runtime") == "runsc", host.get("NetworkMode") == "none",
                  host.get("ReadonlyRootfs") is True, not host.get("Privileged"),
                  host.get("Memory") == spec.resources.memory_bytes,
                  host.get("MemorySwap") == spec.resources.memory_bytes,
                  host.get("PidsLimit") == spec.resources.pids,
                  host.get("NanoCpus") == spec.resources.cpu_millis * 1000000,
                  host.get("ShmSize") == 16777216,
                  host.get("Tmpfs", {}).get("/tmp") == "rw,noexec,nosuid,nodev,size=16777216,mode=1777",
                  any(x.get("Path") == record["loop_device"] and x.get("Rate") == spec.resources.io_bps for x in host.get("BlkioDeviceReadBps", [])),
                  any(x.get("Path") == record["loop_device"] and x.get("Rate") == spec.resources.io_bps for x in host.get("BlkioDeviceWriteBps", [])),
                  raw["Config"].get("User") == self.user,
                  raw["Config"].get("Entrypoint") == ["python"],
                  raw["Config"].get("Cmd") == list(spec.argv[1:]),
                  "ALL" in (host.get("CapDrop") or []),
                  any("no-new-privileges" in x for x in host.get("SecurityOpt", [])),
                  not host.get("Devices"), not host.get("CapAdd"))
        if not all(checks):
            raise ExecutorRefused("Observed container configuration violates qualification", "unsafe_runtime")
        expected_mounts = {"/job/source": (spec.source_path, False),
                           "/job/state": (str(self._directory(spec.identity) / "state"), True)}
        if spec.proxy_endpoint:
            expected_mounts["/run/hf2l/proxy.sock"] = (spec.proxy_endpoint, False)
        if spec.config_path:
            expected_mounts["/run/hf2l/runtime.json"] = (spec.config_path, False)
        if spec.secret_path:
            expected_mounts["/run/hf2l/secrets.json"] = (spec.secret_path, False)
        if record.get("dataset_path"):
            expected_mounts["/job/data/data.npz"] = (record["dataset_path"], False)
        if spec.build_input_path:
            expected_mounts["/job/build"] = (spec.build_input_path, False)
        mounts = raw.get("Mounts", [])
        if any(m.get("Type") not in ("bind", "tmpfs") or (m.get("Type") == "tmpfs" and m.get("Destination") != "/tmp") for m in mounts):
            raise ExecutorRefused("Image introduced unbounded or foreign volumes", "unsafe_mount")
        if raw["Config"].get("Volumes"):
            raise ExecutorRefused("Managed runtime images cannot declare writable volumes", "unsafe_mount")
        actual = {m["Destination"]: (m["Source"], m["RW"]) for m in mounts if m.get("Type") == "bind"}
        if actual != expected_mounts:
            raise ExecutorRefused("Observed container mounts differ from private assignment", "unsafe_mount")
        expected_labels = {"hf2l." + k: str(v) for k, v in asdict(spec.identity).items()}
        if any(raw["Config"].get("Labels", {}).get(k) != v for k, v in expected_labels.items()):
            raise ExecutorRefused("Container ownership differs from assignment", "identity_mismatch")

    def inspect(self, identity: ExecutionIdentity) -> RuntimeObservation:
        record = self._load(identity)
        if record.get("never_started") or record.get("container_removed"):
            return RuntimeObservation(identity, record["state"], True)
        if record["state"] in ("RESERVED", "PREPARING", "RELEASED"):
            return RuntimeObservation(identity, record["state"], True)
        result = self._docker(["inspect", record["container"]], allow_failure=True, uncertain=True)
        if result.returncode:
            # Missing is only confirmed if no create was ever dispatched or an
            # owned remove was acknowledged. An unknown failed inspect is unsafe.
            raise UncertainExecution("Assigned runtime observation is unavailable")
        raw = json.loads(result.stdout)[0]
        self._verify_container(record)
        state = raw["State"]
        running = bool(state.get("Running"))
        status = "RUNNING" if running else "STOPPED"
        progress = self._runtime_progress(record)
        code = state.get("ExitCode")
        error = "oom_killed" if state.get("OOMKilled") else ("publication_unknown" if code == 4 else None)
        return RuntimeObservation(identity, status, not running, exit_code=code,
                                  current_round=progress.get("current_round"),
                                  publication_status="unknown" if code == 4 else "not_observed",
                                  error_code=error, details=progress,
                                  metrics=progress.get("metrics", {}),
                                  phase=progress.get("phase"), readiness=progress.get("readiness"))

    def _runtime_progress(self, record: dict) -> dict:
        """Bounded workload-reported telemetry; publication truth stays Exchange."""
        from .collection import SafeCollector, CollectionError
        identity = ExecutionIdentity(**record["identity"])
        root = self._directory(identity) / ("state" if record.get("mounted") else "retained/state")
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result: raise ValueError("Duplicate telemetry keys")
                result[key] = value
            return result
        try:
            with SafeCollector(root, max_file_bytes=65536) as collector:
                data = json.loads(collector.read("runtime-status.json", max_bytes=65536),
                                  object_pairs_hook=pairs,
                                  parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
            if not isinstance(data, dict) or data.get("schema_version") != 1:
                return {}
            if any(data.get(key) != value for key, value in asdict(identity).items()):
                return {}
            metrics = data.get("metrics", {})
            if not isinstance(metrics, dict) or len(metrics) > 32:
                return {}
            for key, value in metrics.items():
                if not isinstance(key, str) or len(key) > 64 or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", key) or isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or abs(value) > 1e100:
                    return {}
            if data.get("readiness") not in (None, "initializing", "waiting", "ready", "training", "finished", "failed"):
                return {}
            result = {"reported": True, "metrics": metrics}
            for key in ("current_round", "target_round", "source_round", "eligible_count", "minimum_participants"):
                value = data.get(key)
                if type(value) is int and value >= 0:
                    result[key] = value
            for key in ("phase", "readiness", "revision", "role", "participant_id", "observed_at"):
                value = data.get(key)
                if isinstance(value, str) and len(value) <= 200 and not any(ord(c) < 32 for c in value):
                    result[key] = value
            return result
        except (OSError, ValueError, CollectionError):
            return {}

    def stop(self, identity: ExecutionIdentity, grace_seconds: int = 60) -> RuntimeObservation:
        with self._operation_lock(identity):
            record = self._load(identity)
            if record["state"] == "RELEASED" or record.get("container_removed"):
                return self.inspect(identity)
            if record["state"] in ("RESERVED", "PREPARING"):
                record["state"] = "STOPPED"
                record["never_started"] = True
                self._save(identity, record)
                return RuntimeObservation(identity, "STOPPED", True)
            if record.get("never_started"):
                return RuntimeObservation(identity, "STOPPED", True)
            self._verify_container(record)
            self._docker(["stop", "--time", str(max(0, min(60, grace_seconds))), record["container"]],
                         timeout=max(1, min(60, grace_seconds)) + 15, uncertain=True)
            observed = self.inspect(identity)
            if not observed.termination_confirmed:
                raise UncertainExecution("Runtime termination is not confirmed")
            record["state"] = "STOPPED"
            self._save(identity, record)
            return observed

    def read_logs(self, identity: ExecutionIdentity, offset: int = 0, max_bytes: int = 65536) -> dict:
        """Stable cursor over a bounded canonical redacted stream for this identity."""
        with self._operation_lock(identity):
            record = self._load(identity)
            if record.get("disk_deleted"):
                raise ExecutorRefused("Execution log storage was purged", "artifact_unavailable")
            from .log_stream import CanonicalLogSpool
            spool = CanonicalLogSpool(self._directory(identity) / "canonical-logs")
            if record.get("container_removed") or record["state"] == "RELEASED":
                if not (spool.root / "stdout.log").exists():
                    manifest = self.collect(identity)
                    item = next((item for item in manifest if item.path == "runtime/stdout.log"), None)
                    data = self.read_artifact(identity, item.path, 4 * 1024 * 1024) if item else b""
                    spool.update(data, complete=True)
                else:
                    spool.mark_complete()
            elif record["state"] in ("RESERVED", "PREPARING") or record.get("never_started"):
                spool.update("", complete=bool(record.get("never_started")))
            else:
                self._verify_container(record)
                result = self._docker(["logs", "--timestamps", "--tail", "10000", record["container"]], uncertain=True)
                lines = (result.stdout + getattr(result, "stderr", "")).splitlines(keepends=True)
                # Docker timestamped stdout/stderr are separate CLI pipes.
                # Merge by their trusted timestamp before stable overlap checks.
                if any(not re.match(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[^ ]+ ", line) for line in lines):
                    raise ExecutorRefused("Docker logs lack stable timestamps", "invalid_log_snapshot")
                lines.sort(key=lambda line: line.split(" ", 1)[0])
                raw = "".join(lines)
                if len(raw.encode("utf-8", errors="replace")) > 4 * 1024 * 1024:
                    raise ExecutorRefused("Docker log snapshot exceeds its bound", "log_snapshot_exceeds_bound")
                from .collection import SafeCollector
                with SafeCollector(self._directory(identity), max_file_bytes=4*1024*1024,
                                   max_total_bytes=4*1024*1024, secret_values=self._secret_values(self._spec(record))) as redactor:
                    redacted = redactor._redact(raw, 4 * 1024 * 1024)
                spool.update(redacted, complete=self.inspect(identity).termination_confirmed)
            return spool.read(identity, offset=offset, max_bytes=max_bytes)

    def reconciliation_root(self, identity: ExecutionIdentity) -> Path:
        if not self.inspect(identity).termination_confirmed:
            raise ExecutorRefused("Cannot inspect mutable state before termination", "runtime_active")
        record = self._load(identity)
        if record.get("mounted"):
            return self._directory(identity) / "state"
        root = self._directory(identity) / "retained" / "state"
        if not root.exists():
            raise ExecutorRefused("Reconciliation state is not available", "missing_resource")
        return root

    def _secret_values(self, spec: ExecutionSpec) -> tuple[str, ...]:
        if not spec.secret_path:
            return ()
        self._trusted_path(spec.secret_path, kind="file")
        from .secrets import read_secret_manifest
        manifest = read_secret_manifest(spec.secret_path, spec.identity)
        return tuple(manifest["options"].values())

    def collect(self, identity: ExecutionIdentity):
        with self._operation_lock(identity):
            return self._collect(identity)

    def _collect(self, identity: ExecutionIdentity):
        record = self._load(identity)
        if record.get("disk_deleted"):
            return ()
        if not self.inspect(identity).termination_confirmed:
            raise ExecutorRefused("Collect only after confirmed termination", "runtime_active")
        if record.get("never_started") or record["state"] in ("RESERVED", "PREPARING"):
            return ()
        if record.get("artifacts_collected"):
            from .collection import RetainedFile
            return tuple(RetainedFile(**item) for item in record["retained_artifacts"])
        from .collection import SafeCollector, RetainedFile
        spec = self._spec(record)
        root = self._directory(identity) / "state"
        destination = self._directory(identity) / "retained" / "state"
        with SafeCollector(root, max_total_bytes=spec.resources.disk_bytes) as collector:
            retained = list(collector.retain(destination))
        # Canonical logs are redacted before their stable cursor is exposed.
        # Final refresh happens before Docker removal can discard rotated logs.
        self.read_logs(identity, offset=0, max_bytes=65536)
        log_root = self._directory(identity) / "canonical-logs"
        with SafeCollector(log_root, max_total_bytes=1024*1024) as logs:
            clean = logs.read("stdout.log")
        log_source = self._directory(identity) / "collected-logs"
        log_source.mkdir(mode=0o700, exist_ok=True)
        log_path = log_source / "stdout.log"
        with log_path.open("wb") as output: output.write(clean)
        os.chmod(log_path, 0o600)
        with SafeCollector(log_source, max_total_bytes=1024*1024) as logs:
            for item in logs.retain(self._directory(identity) / "retained" / "runtime"):
                retained.append(RetainedFile("runtime/" + item.path, item.locator, item.size_bytes, item.sha256))
        log_path.unlink()
        log_source.rmdir()
        record["retained_artifacts"] = [item.as_dict() for item in retained]
        record["artifacts_collected"] = True
        record["retained_bytes"] = sum(item.size_bytes for item in retained)
        self._save(identity, record)
        return tuple(retained)

    def _reconcile_volume_handles(self, identity: ExecutionIdentity, record: dict):
        image = self._directory(identity) / "state.ext4"
        if not image.exists():
            if record.get("mounted") or record.get("loop_device") or record.get("owned_loop_devices"):
                # A crash after image unlink but before its ledger commit must
                # never act on a device name that Linux may already have reused.
                mounted = self._system(["findmnt", "--mountpoint", str(self._directory(identity) / "state"),
                    "--noheadings", "--output", "SOURCE"], allow_failure=True, uncertain=True)
                if mounted.returncode != 1:
                    raise UncertainExecution("Missing scratch image still has a mount or unknown observation")
                loops = json.loads(self._system(["losetup", "--list", "--json",
                    "--output", "NAME,BACK-FILE"], uncertain=True).stdout).get("loopdevices", [])
                if any(item.get("back-file") in (str(image), str(image) + " (deleted)") for item in loops):
                    raise UncertainExecution("Deleted scratch image still has an associated loop")
                record["mounted"] = False
                record["loop_device"] = None
                record["owned_loop_devices"] = []
                self._save(identity, record)
            return
        loops = json.loads(self._system(["losetup", "--json", "--associated", str(image),
                                        "--output", "NAME,BACK-FILE"], uncertain=True).stdout).get("loopdevices", [])
        owned = []
        for item in loops:
            name = item.get("name", "")
            if item.get("back-file") != str(image) or not re.fullmatch(r"/dev/loop[0-9]+", name):
                raise UncertainExecution("Private volume backing device is not attributable")
            owned.append(name)
        mounted = self._system(["findmnt", "--mountpoint", str(self._directory(identity) / "state"),
                                "--noheadings", "--output", "SOURCE"], allow_failure=True, uncertain=True)
        if mounted.returncode not in (0, 1):
            raise UncertainExecution("Private volume mount observation failed")
        if mounted.returncode == 0:
            source = mounted.stdout.strip()
            if source not in owned:
                raise UncertainExecution("Private mount does not match owned backing image")
            record["mounted"] = True
            record["loop_device"] = source
        else:
            # An interrupted cleanup may have acknowledged umount/detach but
            # not its ledger update. Never act on a stale device name: Linux may
            # already have reused it for a completely unrelated resource.
            record["mounted"] = False
            record["loop_device"] = record.get("loop_device") if record.get("loop_device") in owned else (owned[0] if owned else None)
        record["owned_loop_devices"] = owned
        self._save(identity, record)

    def release(self, identity: ExecutionIdentity) -> bool:
        with self._operation_lock(identity):
            record = self._load(identity)
            if record["state"] == "RELEASED": return True
            self._reconcile_volume_handles(identity, record)
            if record["state"] in ("RESERVED", "PREPARING"):
                self.stop(identity, grace_seconds=0)
                record = self._load(identity)
            if not record.get("never_started"):
                observation = self.inspect(identity)
                if not observation.termination_confirmed:
                    raise UncertainExecution("Capacity cannot be released before confirmed stop")
                # Collect while the stopped container's bounded logs still exist.
                if record.get("mounted") and not record.get("artifacts_collected"):
                    self.collect(identity)
                    record = self._load(identity)
                if not record.get("container_removed"):
                    self._verify_container(record)
                    self._docker(["rm", record["container"]], uncertain=True)
                    record["container_removed"] = True
                    self._save(identity, record)
            if record.get("mounted"):
                self._system(["umount", str(self._directory(identity) / "state")], uncertain=True)
                record["mounted"] = False
                self._save(identity, record)
            devices = record.get("owned_loop_devices", [])
            for device in devices:
                try:
                    self._system(["losetup", "--detach", device], uncertain=True)
                except UncertainExecution:
                    # Closing the final runtime/gofer descriptor can finish an
                    # auto-clear detach between inventory and LOOP_CLR_FD.
                    # The next authoritative image association check remains
                    # mandatory before storage capacity can be released.
                    record["detach_request_uncertain"] = True
            record["loop_device"] = None
            record["owned_loop_devices"] = []
            image = self._directory(identity) / "state.ext4"
            if image.exists():
                # LOOP_CLR_FD acknowledgement can precede asynchronous kernel
                # device teardown. Wait for authoritative disappearance; an
                # acknowledged request alone never releases storage capacity.
                detach_wait_started = time.monotonic()
                until = detach_wait_started + 30
                while True:
                    remaining = json.loads(self._system(["losetup", "--json", "--associated", str(image),
                        "--output", "NAME,BACK-FILE"], uncertain=True).stdout).get("loopdevices", [])
                    if not remaining:
                        record["detach_confirmation_seconds"] = time.monotonic() - detach_wait_started
                        break
                    if time.monotonic() >= until:
                        record["detach_wait_seconds"] = time.monotonic() - detach_wait_started
                        self._save(identity, record)
                        raise UncertainExecution("Backing device detachment is not confirmed")
                    time.sleep(0.1)
            if image.exists():
                if not record.get("artifacts_collected") and not record.get("never_started"):
                    raise UncertainExecution("Cannot delete scratch volume before immutable retention")
                image.unlink()
                directory_fd = os.open(image.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try: os.fsync(directory_fd)
                finally: os.close(directory_fd)
            record["fixed_volume_deleted"] = True
            self._save(identity, record)
            # Rebuild restart state only after the scratch image is gone.
            # Immutable retained bytes are the verified recovery source.
            if not record.get("state_copied") and not record.get("never_started"):
                from .collection import SafeCollector
                spec = self._spec(record)
                destination = self._trusted_path(spec.state_path, kind="directory")
                for temporary_name in record.get("copy_tempfiles", []):
                    temporary = destination / temporary_name
                    self._trusted_path(str(temporary.parent), kind="directory")
                    if temporary.exists():
                        metadata = temporary.lstat()
                        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                            raise ExecutorRefused("Restart-state staging path changed", "unsafe_output")
                        temporary.unlink()
                record["copy_tempfiles"] = []
                self._save(identity, record)
                source = self._directory(identity) / "retained" / "state"
                expected = {}
                for retained in record.get("retained_artifacts", []):
                    locator = Path(retained["locator"])
                    try: relative = str(locator.relative_to(source))
                    except ValueError: continue
                    if relative != retained["path"] or relative in expected:
                        raise ExecutorRefused("Restart-state manifest identity changed", "unsafe_output")
                    expected[relative] = (retained["size_bytes"], retained["sha256"])
                with SafeCollector(source, max_total_bytes=spec.resources.disk_bytes) as collector:
                    files = collector.list_files()
                    actual = {item.path: (item.size_bytes, item.sha256) for item in files}
                    if actual != expected:
                        raise ExecutorRefused("Restart-state bytes differ from retained manifest", "unsafe_output")
                    for item in files:
                        target = destination / item.path
                        parent = destination
                        for part in Path(item.path).parts[:-1]:
                            parent = parent / part
                            if parent.is_symlink():
                                raise ExecutorRefused("Retained state traverses a symlink", "unsafe_output")
                            parent.mkdir(exist_ok=True, mode=0o700)
                        if target.exists() and (target.is_symlink() or not target.is_file() or target.stat().st_nlink != 1):
                            raise ExecutorRefused("Retained state destination is unsafe", "unsafe_output")
                        fd, temporary_name = tempfile.mkstemp(prefix=".hf2l-", dir=target.parent)
                        temporary = Path(temporary_name)
                        relative = str(temporary.relative_to(destination))
                        record["copy_tempfiles"].append(relative)
                        self._save(identity, record)
                        try:
                            with os.fdopen(fd, "wb") as stream:
                                stream.write(collector.read(item.path))
                                stream.flush()
                                os.fsync(stream.fileno())
                            os.replace(temporary, target)
                            parent_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                            try: os.fsync(parent_fd)
                            finally: os.close(parent_fd)
                        finally:
                            if temporary.exists(): temporary.unlink()
                        record["copy_tempfiles"].remove(relative)
                        self._save(identity, record)
                record["state_copied"] = True
                self._save(identity, record)
            record["state"] = "RELEASED"
            record["retained"] = bool(record.get("state_copied"))
            self._save(identity, record)
            return True

    def read_artifact(self, identity: ExecutionIdentity, path: str, max_bytes: int = 64 * 1024 * 1024) -> bytes:
        """Read an exact retained manifest entry; no caller-supplied host locator."""
        if not isinstance(path, str) or type(max_bytes) is not int or not 1 <= max_bytes <= 256 * 1024 * 1024:
            raise ExecutorRefused("Invalid retained artifact read", "unsafe_output")
        with self._operation_lock(identity):
            record = self._load(identity)
            if record.get("disk_deleted") or not self.inspect(identity).termination_confirmed:
                raise ExecutorRefused("Retained artifact is unavailable", "artifact_unavailable")
            matches = [item for item in self.collect(identity) if item.path == path]
            if len(matches) != 1:
                raise ExecutorRefused("Artifact is absent or ambiguous in the execution manifest", "artifact_unavailable")
            item = matches[0]
            if item.size_bytes > max_bytes:
                raise ExecutorRefused("Artifact exceeds the approved read bound", "output_too_large")
            root = self._directory(identity) / "retained"
            locator = Path(item.locator)
            allowed = {root / "state" / path}
            if path == "runtime/stdout.log": allowed.add(root / path)
            if locator not in allowed:
                raise ExecutorRefused("Retained artifact locator differs from execution ownership", "unsafe_output")
            from .collection import SafeCollector, CollectionError
            try:
                with SafeCollector(root, max_file_bytes=max_bytes, max_total_bytes=max_bytes) as collector:
                    data = collector.read(str(locator.relative_to(root)))
            except CollectionError as exc:
                raise ExecutorRefused("Retained artifact filesystem validation failed", "unsafe_output") from exc
            if len(data) != item.size_bytes or hashlib.sha256(data).hexdigest() != item.sha256:
                raise ExecutorRefused("Retained artifact differs from its immutable manifest", "unsafe_output")
            return data

    def purge(self, identity: ExecutionIdentity) -> bool:
        """Delete only this ledger-owned, already detached retained filesystem."""
        with self._operation_lock(identity):
            record = self._load(identity)
            if record["state"] != "RELEASED" or record.get("mounted") or record.get("loop_device"):
                raise ExecutorRefused("Retained volume is still in use", "runtime_active")
            image = self._directory(identity) / "state.ext4"
            if image.is_symlink():
                raise ExecutorRefused("Retained filesystem changed ownership", "unsafe_output")
            if image.exists(): image.unlink()
            from .collection import SafeCollector, delete_retained
            for name in ("state", "runtime"):
                root = self._directory(identity) / "retained" / name
                if root.exists():
                    if record.get("retained_artifacts"):
                        manifest = []
                        for item in record["retained_artifacts"]:
                            locator = Path(item["locator"])
                            try: relative = locator.relative_to(root)
                            except ValueError: continue
                            copy = dict(item); copy["path"] = str(relative)
                            manifest.append(copy)
                    else:
                        # Upgrade pre-manifest node ledgers without interpreting
                        # content. Audit ownership already binds this root.
                        with SafeCollector(root, max_total_bytes=self._spec(record).resources.disk_bytes) as collector:
                            manifest = [{"path": item.path, "locator": str(root / item.path),
                                         "size_bytes": item.size_bytes, "sha256": item.sha256}
                                        for item in collector.list_files()]
                    delete_retained(root, manifest, max_total_bytes=self._spec(record).resources.disk_bytes)
            retained_parent = self._directory(identity) / "retained"
            if retained_parent.exists(): retained_parent.rmdir()
            logs = self._directory(identity) / "collected-logs"
            if logs.exists():
                with SafeCollector(logs, max_total_bytes=4*1024*1024) as collector:
                    manifest = [{"path": item.path, "locator": str(logs / item.path),
                                 "size_bytes": item.size_bytes, "sha256": item.sha256}
                                for item in collector.list_files()]
                delete_retained(logs, manifest, max_total_bytes=4*1024*1024)
            canonical = self._directory(identity) / "canonical-logs"
            if canonical.exists():
                with SafeCollector(canonical, max_files=3, max_total_bytes=1024*1024) as collector:
                    manifest = [{"path": item.path, "locator": str(canonical / item.path),
                                 "size_bytes": item.size_bytes, "sha256": item.sha256}
                                for item in collector.list_files()]
                delete_retained(canonical, manifest, max_files=3, max_total_bytes=1024*1024)
            record["retained"] = False
            record["disk_deleted"] = True
            self._save(identity, record)
            return True
