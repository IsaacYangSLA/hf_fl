#!/usr/bin/env python3
"""Qualify uncached readonly backing I/O on an already qualified runsc node.

Only task-private synthetic files and containers are used. This does not clear
global caches, pull images, alter shared daemons, or read participant data.
The original isolation profile is promoted only after every check and cleanup
passes. An immutable parent tag is retained to protect the selected base image.
"""
from __future__ import annotations

import argparse
import datetime
import fcntl
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import time

SETUP_SPEC = importlib.util.spec_from_file_location("hf2l_runtime_io_setup", Path(__file__).with_name("setup.py"))
SETUP = importlib.util.module_from_spec(SETUP_SPEC)
SETUP_SPEC.loader.exec_module(SETUP)

MIB = 1024 * 1024
FILE_BYTES = 64 * MIB
LIMITS = (8 * MIB, 16 * MIB)
IMAGE_ID = re.compile(r"^sha256:[a-f0-9]{64}$")
IMAGE_DIGEST = re.compile(r"^[A-Za-z0-9./:_-]+@sha256:[a-f0-9]{64}$")

READ_PROBE = r"""
import json,os,time
print(json.dumps({"ready":True}),flush=True)
while not os.path.exists("/control/start"):time.sleep(.02)
for kind,path in [
    ("source","/job/source/blob"),
    ("dataset","/job/data/data.npz"),
    ("build","/job/build/blob"),
    ("image","/run/hf2l-qualification-image.bin"),
]:
    begin=time.monotonic();total=0
    with open(path,"rb",buffering=0) as handle:
        while True:
            part=handle.read(1024*1024)
            if not part:break
            total+=len(part)
    elapsed=time.monotonic()-begin
    print(json.dumps({"kind":kind,"bytes":total,"elapsed":elapsed,
                      "bytes_per_second":total/elapsed}),flush=True)
print(json.dumps({"finished":True}),flush=True)
while not os.path.exists("/control/stop"):time.sleep(.02)
"""
SIBLING_PROBE = r"""
import json,os,time
print(json.dumps({"ready":True}),flush=True)
counter=0
while not os.path.exists("/control/stop"):
    counter+=1;print(json.dumps({"heartbeat":counter}),flush=True);time.sleep(.1)
"""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def command(args, *, check=True, timeout=60):
    result = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError("Command failed: " + repr(list(args)[:4]) + "\n" + result.stderr[-2000:])
    return result


def private_path(path, *, directory=False, hashed_evidence=False):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Trusted paths must be absolute without traversal")
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError("Trusted paths cannot contain symlinks")
    metadata = path.stat()
    wanted = stat.S_ISDIR if directory else stat.S_ISREG
    if not wanted(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ValueError("Trusted path must be owned by the node agent")
    if metadata.st_mode & (0o002 if hashed_evidence else 0o022):
        raise ValueError("Trusted path cannot be writable by another user: " + str(path))
    if not directory and metadata.st_nlink != 1:
        raise ValueError("Trusted files cannot have hardlinks")
    return path


def atomic_write(path, data, mode=0o600):
    temporary = path.with_name(path.name + ".partial-" + secrets.token_hex(6))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)



def write_canary_file(path: Path, size_bytes: int) -> None:
    """Make a readable synthetic COPY input inside the private canary root.

    Docker COPY assigns root ownership, so relying on the caller's umask would
    make a 0600 file unreadable to the required non-root sandbox user.
    """
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
    try:
        os.fchmod(descriptor, 0o644)
        chunk = os.urandom(min(MIB, size_bytes))
        remaining = size_bytes
        while remaining:
            view = memoryview(chunk[:remaining])
            while view:
                view = view[os.write(descriptor, view):]
            remaining -= min(len(chunk), remaining)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def load_executor():
    checkout = Path(__file__).resolve().parents[3]
    source = checkout / "packages/jobs/src"
    if source.is_dir():
        sys.path.insert(0, str(source))
    from hf2l_jobs.executor import LinuxExecutor, ExecutionIdentity, ExecutionSpec, ResourceLimits, ExecutorRefused
    return LinuxExecutor, ExecutionIdentity, ExecutionSpec, ResourceLimits, ExecutorRefused


class Qualification:
    def __init__(self, args):
        if os.getuid() == 0 or os.getgid() == 0:
            raise ValueError("Run as the trusted non-root node agent user")
        self.profile_path = private_path(args.profile)
        self.original_bytes = self.profile_path.read_bytes()
        self.profile = json.loads(self.original_bytes)
        self.owned_root = private_path(self.profile["owned_root"], directory=True)
        self.output_root = Path(args.root)
        if (not self.output_root.is_absolute() or ".." in self.output_root.parts
                or any(parent.is_symlink() for parent in (self.output_root, *self.output_root.parents))):
            raise ValueError("--root must be absolute without symlinks or traversal")
        if self.output_root != self.owned_root and self.owned_root not in self.output_root.parents:
            raise ValueError("--root must be within the qualified node owned_root")
        self.output_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        private_path(self.output_root, directory=True)
        if not (IMAGE_ID.fullmatch(args.base_image) or IMAGE_DIGEST.fullmatch(args.base_image)):
            raise ValueError("--base-image must be an immutable local image ID or digest")
        self.base_image = args.base_image
        self.owner = "readonly-io-" + secrets.token_hex(6)
        self.run_root = self.output_root / self.owner
        self.run_root.mkdir(mode=0o700)
        self.docker = ["sudo", "-n", "docker", "-H", self.profile["docker_host"]]
        self.containers = []
        self.derived_image = None
        self.parent_tag = None
        self.input_roots = []
        self.executor_classes = load_executor()
        self.report = {
            "schema_version": 1, "owner": self.owner, "qualified": False,
            "scope": "uncached readonly physical backing I/O and production executor configuration",
            "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "checks": [], "runs": [], "cleanup": {},
            "original_profile_sha256": digest(self.original_bytes),
            "qualifier_sha256": digest(Path(__file__).read_bytes()),
            "base_qualification_path": self.profile["qualification_path"],
            "base_qualification_sha256": self.profile["qualification_sha256"],
            "base_qualification_checks": self.profile["qualification_checks"],
            "profile_path": str(self.profile_path), "run_root": str(self.run_root),
        }

    def check(self, name, passed, **evidence):
        self.report["checks"].append({"name": name, "passed": bool(passed), **evidence})
        if not passed:
            raise AssertionError(name)

    def docker_call(self, *args, **kwargs):
        return command([*self.docker, *args], **kwargs)

    def docker_json(self, *args):
        return json.loads(self.docker_call(*args).stdout)

    def verify_runtime(self):
        p = self.profile
        if p.get("qualified") is not True or p.get("profile") != "runsc-cpu-v1":
            raise ValueError("Original runsc isolation qualification must pass first")
        for key, value in {
            "runtime": "runsc", "network": "none", "runsc_network": "sandbox",
            "runsc_host_uds": "open", "proxy_transport": "unix",
            "bounded_volumes": "loop-ext4", "read_only": True,
        }.items():
            if p.get(key) != value:
                raise ValueError("Isolation profile is incompatible: " + key)
        if p.get("docker_command") != self.docker or p.get("system_command") != ["sudo", "-n"]:
            raise ValueError("Qualification requires the exact trusted local command prefixes")
        runtime_root = self.profile_path.parent
        cpu_policy = SETUP.runtime_cpu_policy(runtime_root)
        if any(p.get(key) != value for key, value in cpu_policy.items()):
            raise ValueError("Qualified runtime CPU policy changed")
        if (p["docker_host"] != "unix://" + str(runtime_root / "docker.sock")
                or p["docker_data_root"] != str(runtime_root / "data")
                or p["containerd_socket"] != str(runtime_root / "containerd.sock")
                or p["daemon_config"] != str(runtime_root / "daemon.json")):
            raise ValueError("Runtime paths differ from the qualified private node runtime")
        config_bytes = private_path(p["daemon_config"]).read_bytes()
        if digest(config_bytes) != p["daemon_config_sha256"]:
            raise ValueError("Qualified daemon configuration changed")
        config = json.loads(config_bytes)
        files = p.get("runtime_files_sha256")
        if not isinstance(files, dict) or not files:
            raise ValueError("Qualified runtime file manifest is missing")
        for filename, expected in files.items():
            path = Path(filename)
            if any(parent.is_symlink() for parent in (path, *path.parents)):
                raise ValueError("Runtime files cannot contain symlinks")
            metadata = path.stat()
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or metadata.st_mode & 0o022 or digest(path.read_bytes()) != expected):
                raise ValueError("Qualified runtime file changed")
        runtime = config.get("runtimes", {}).get("runsc", {})
        if (digest(Path(runtime["path"]).read_bytes()) != p["runsc_sha256"]
                or "--network=sandbox" not in runtime.get("runtimeArgs", [])
                or "--host-uds=open" not in runtime.get("runtimeArgs", [])):
            raise ValueError("Qualified runsc identity changed")
        info = self.docker_json("info", "--format", "{{json .}}")
        if ("runsc" not in info.get("Runtimes", {}) or str(info.get("CgroupVersion")) != "2"
                or info.get("DockerRootDir") != p["docker_data_root"]
                or info.get("Containerd", {}).get("Address") != p["containerd_socket"]):
            raise ValueError("Docker/containerd identity differs from qualification")
        pid = command(["sudo", "-n", "systemctl", "show", p["daemon_unit"], "--property=MainPID", "--value"]).stdout.strip()
        if p.get("runtime_environment") != {"GOMAXPROCS": "2"}:
            raise ValueError("Qualified runtime threading settings are missing")
        for unit in (p["daemon_unit"], p["containerd_unit"]):
            environment = command(["sudo", "-n", "systemctl", "show", unit,
                                   "--property=Environment", "--value"]).stdout.split()
            if "GOMAXPROCS=2" not in environment:
                raise ValueError("Qualified runtime threading settings changed")
            runtime_pid = command(["sudo", "-n", "systemctl", "show", unit, "--property=MainPID", "--value"]).stdout.strip()
            if sorted(os.sched_getaffinity(int(runtime_pid))) != p.get("runtime_cpu_affinity"):
                raise ValueError("Qualified runtime host CPU affinity changed")
        if not re.fullmatch(r"[1-9][0-9]*", pid):
            raise ValueError("Qualified private daemon is not running")
        node_net = command(["sudo", "-n", "readlink", "/proc/" + pid + "/ns/net"]).stdout.strip()
        host_net = command(["sudo", "-n", "readlink", "/proc/1/ns/net"]).stdout.strip()
        if not node_net or node_net == host_net:
            raise ValueError("Daemon escaped its private network namespace")
        previous_report = private_path(p["qualification_path"], hashed_evidence=True)
        if digest(previous_report.read_bytes()) != p["qualification_sha256"]:
            raise ValueError("Original isolation qualification evidence changed")
        image = self.docker_json("image", "inspect", self.base_image)[0]
        if image.get("Config", {}).get("OnBuild"):
            raise ValueError("Qualification image cannot contain implicit build hooks")
        if not IMAGE_ID.fullmatch(image["Id"]):
            raise ValueError("Selected local image has no immutable ID")
        self.base_image = image["Id"]
        self.parent_tag = "hf2l-jobs-io-parent:" + self.base_image.split(":")[1]
        old = self.docker_call("image", "inspect", self.parent_tag, check=False)
        if old.returncode == 0 and json.loads(old.stdout)[0]["Id"] != self.base_image:
            raise ValueError("Immutable qualification parent tag already names a different image")
        self.docker_call("image", "tag", self.base_image, self.parent_tag)
        self.report.update({
            "base_image": self.base_image, "retained_parent_tag": self.parent_tag,
            "runtime_identity": {
                key: p[key] for key in (
                    "owned_root", "docker_host", "docker_data_root", "containerd_socket",
                    "daemon_config", "daemon_config_sha256", "daemon_unit", "containerd_unit",
                    "runtime_environment", "runtime_cpu_affinity", "runtime_cpu_count",
                    "runtime_cpu_policy", "runtime_cpu_policy_sha256",
                    "runsc_sha256", "runtime_files_sha256", "sandbox_uid", "sandbox_gid",
                    "profile", "runtime", "network", "runsc_network", "runsc_host_uds",
                    "proxy_transport", "bounded_volumes", "read_only",
                )
            },
        })
        LinuxExecutor = self.executor_classes[0]
        self.deriver = LinuxExecutor(self.profile_path, self.run_root / "derivation", validate=False)
        devices = [self.deriver._backing_device(x) for x in (self.run_root, self.owned_root, p["docker_data_root"])]
        self.devices = sorted({json.dumps(x, sort_keys=True): x for x in devices}.values(), key=lambda x: x["path"])
        run_device = self.deriver._backing_device(self.run_root)
        image_device = self.deriver._backing_device(p["docker_data_root"])
        if any(x not in (run_device, image_device) for x in self.devices):
            raise ValueError("Every required device needs a canary root or image-root read proof")
        self.report["backing_devices"] = self.devices
        self.role_devices = {kind: run_device for kind in ("source", "dataset", "build")}
        self.role_devices["image"] = image_device
        if shutil.disk_usage(self.run_root).free < 512 * MIB:
            raise ValueError("At least 512 MiB free space is required for bounded synthetic canaries")

    def prepare_inputs(self):
        for label in ("source", "dataset", "build", "image"):
            directory = self.run_root / label
            directory.mkdir(mode=0o755)
            self.input_roots.append(directory)
            filename = "data.npz" if label == "dataset" else "blob"
            write_canary_file(directory / filename, FILE_BYTES)
        self.context_path = self.run_root / "context.tar"
        with tarfile.open(self.context_path, "w") as archive:
            dockerfile = ("FROM " + self.parent_tag + "\nCOPY blob /run/hf2l-qualification-image.bin\n").encode()
            entry = tarfile.TarInfo("Dockerfile")
            entry.size = len(dockerfile)
            archive.addfile(entry, io.BytesIO(dockerfile))
            archive.add(self.run_root / "image/blob", arcname="blob")
        with self.context_path.open("rb") as stream:
            built = subprocess.run([
                *self.docker, "build", "--network", "none", "--memory", str(512 * MIB),
                "--memory-swap", str(512 * MIB), "--cpu-period", "100000",
                "--cpu-quota", "50000", "--quiet", "-t", self.owner, "-",
            ], stdin=stream, capture_output=True, text=True, timeout=120)
        if built.returncode:
            raise RuntimeError("Private synthetic image build failed: " + built.stderr[-2000:])
        self.derived_image = built.stdout.strip().splitlines()[-1]
        data = self.docker_json("image", "inspect", self.derived_image)[0]["GraphDriver"]["Data"]
        layers = [data["UpperDir"], *data["LowerDir"].split(":")]
        self.image_file = next(
            Path(layer) / "run/hf2l-qualification-image.bin" for layer in layers
            if command(["sudo", "-n", "test", "-f", str(Path(layer) / "run/hf2l-qualification-image.bin")], check=False).returncode == 0
        )
        if self.deriver._backing_device(self.image_file) != self.role_devices["image"]:
            raise ValueError("Private image layer is on an unexpected physical device")

    def cgroup(self, inspected):
        relative = Path("/proc/" + str(inspected["State"]["Pid"]) + "/cgroup").read_text().split("0::", 1)[1].strip()
        if ".." in Path(relative).parts:
            raise ValueError("Invalid kernel cgroup path")
        root = Path("/sys/fs/cgroup") / relative.lstrip("/")
        return {"path": str(root), **{name: (root / name).read_text() for name in ("io.max", "io.stat")}}

    def probe_evidence(self, name, result=None):
        if result is None:
            result = self.docker_call("logs", name, check=False)
        inspection = self.docker_call("inspect", name, check=False)
        state = json.loads(inspection.stdout)[0]["State"] if inspection.returncode == 0 else {}
        evidence = {"name": name, "stdout": result.stdout[-64 * 1024:],
                    "stderr": result.stderr[-64 * 1024:], "state": state}
        if state.get("Pid", 0):
            cgroup = self.cgroup({"State": state})
            evidence["cgroup"] = cgroup
        return evidence

    def wait_log(self, name, wanted, timeout=75):
        until = time.monotonic() + timeout
        result = None
        while time.monotonic() < until:
            result = self.docker_call("logs", name)
            if len(result.stdout) > 64 * 1024 or len(result.stderr) > 64 * 1024:
                self.report.setdefault("probe_failures", []).append(self.probe_evidence(name, result))
                raise RuntimeError("Synthetic probe log exceeded its bound")
            if wanted in result.stdout:
                return result.stdout
            evidence = self.probe_evidence(name, result)
            if evidence["state"].get("Running") is False:
                self.report.setdefault("probe_failures", []).append(evidence)
                raise RuntimeError("Synthetic probe exited before " + wanted)
            time.sleep(.1)
        self.report.setdefault("probe_failures", []).append(self.probe_evidence(name, result))
        raise RuntimeError("Synthetic probe did not reach " + wanted)

    @staticmethod
    def counters(text):
        values = {}
        for line in text.splitlines():
            words = line.split()
            if words:
                values[words[0]] = {key: int(value) for key, value in (word.split("=") for word in words[1:])}
        return values

    def run_limit(self, bps):
        controls = []
        own_containers = []
        run = {"limit_bps": bps, "file_bytes": FILE_BYTES}
        self.report["runs"].append(run)
        for index, script in enumerate((READ_PROBE, SIBLING_PROBE)):
            control = self.run_root / ("control-" + str(bps) + "-" + str(index))
            control.mkdir(mode=0o755)
            controls.append(control)
            name = self.owner + "-" + str(bps) + "-" + str(index)
            args = [
                "create", "--name", name, "--label", "hf2l.jobs.readonly-io=" + self.owner,
                "--runtime", "runsc", "--network", "none", "--read-only",
                "--user", str(self.profile["sandbox_uid"]) + ":" + str(self.profile["sandbox_gid"]),
                "--cpus", "0.5", "--memory", str(512 * MIB), "--memory-swap", str(512 * MIB),
                "--pids-limit", "64", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--log-driver", "local", "--log-opt", "max-size=256k", "--log-opt", "max-file=2",
                "--mount", "type=bind,src=" + str(control) + ",dst=/control",
                "--tmpfs", "/tmp:size=33554432,noexec,nosuid,nodev",
                "--entrypoint", "python",
            ]
            for device in self.devices:
                args += ["--device-read-bps", device["path"] + ":" + str(bps),
                         "--device-write-bps", device["path"] + ":" + str(bps)]
            if index == 0:
                for label, target in (("source", "/job/source"), ("dataset", "/job/data"), ("build", "/job/build")):
                    args += ["--mount", "type=bind,src=" + str(self.run_root / label) + ",dst=" + target + ",readonly"]
            cid = self.docker_call(*args, self.derived_image, "-u", "-c", script).stdout.strip()
            self.containers.append(name)
            own_containers.append(name)
            self.docker_call("start", name)
            self.wait_log(name, '"ready": true', timeout=30)
        reader = self.docker_json("inspect", own_containers[0])[0]
        before = self.cgroup(reader)
        run["before"] = before
        caps = {}
        for line in before["io.max"].splitlines():
            words = line.split()
            caps[words[0]] = dict(word.split("=") for word in words[1:])
        correct = all(caps.get(str(d["major"]) + ":" + str(d["minor"]), {}).get("rbps") == str(bps)
                      and caps.get(str(d["major"]) + ":" + str(d["minor"]), {}).get("wbps") == str(bps)
                      for d in self.devices)
        self.check("physical_cgroup_caps_" + str(bps), correct)
        paths = [self.run_root / "source/blob", self.run_root / "dataset/data.npz",
                 self.run_root / "build/blob", self.image_file]
        # This operator action touches only four new canary files, never global caches.
        script = "import json,os\nfor p in json.loads(" + repr(json.dumps([str(x) for x in paths])) + "):\n f=os.open(p,os.O_RDONLY);os.posix_fadvise(f,0,0,os.POSIX_FADV_DONTNEED);os.close(f)\n"
        command(["sudo", "-n", "python3", "-c", script])
        self.check("task_files_only_fadvise_" + str(bps), True, files=[str(x) for x in paths])
        (controls[0] / "start").touch()
        logs = self.wait_log(own_containers[0], '"finished": true')
        readings = [json.loads(x) for x in logs.splitlines() if x.startswith("{")]
        readings = [x for x in readings if "kind" in x]
        run["readings"] = readings
        self.check("four_input_readings_" + str(bps), len(readings) == 4)
        for record in readings:
            self.check(record["kind"] + "_bounded_uncached_" + str(bps),
                       record["bytes"] == FILE_BYTES and FILE_BYTES / bps * .65 <= record["elapsed"] <= 30
                       and record["bytes_per_second"] <= bps * 1.2, **record)
        after = self.cgroup(self.docker_json("inspect", own_containers[0])[0])
        run["after"] = after
        old, new = self.counters(before["io.stat"]), self.counters(after["io.stat"])
        expected = {}
        for device in self.role_devices.values():
            key = str(device["major"]) + ":" + str(device["minor"])
            expected[key] = expected.get(key, 0) + FILE_BYTES
        delta = {key: new.get(key, {}).get("rbytes", 0) - old.get(key, {}).get("rbytes", 0) for key in expected}
        run["physical_read_bytes_delta"] = delta
        self.check("physical_read_accounting_" + str(bps), all(delta[k] >= expected[k] * .85 for k in expected), expected=expected, actual=delta)
        sibling = self.docker_json("inspect", own_containers[1])[0]
        heartbeats = sum("heartbeat" in line for line in self.docker_call("logs", own_containers[1]).stdout.splitlines())
        run["sibling_heartbeats"] = heartbeats
        self.check("responsive_sibling_" + str(bps), sibling["State"]["Running"] and heartbeats >= 50)
        for control in controls:
            (control / "stop").touch()
        for name in own_containers:
            self.remove_container(name)

    def remove_container(self, name):
        result = self.docker_call("rm", "--force", name, check=False)
        absent = self.docker_call("inspect", name, check=False).returncode != 0
        self.report["cleanup"][name] = {"removed": result.returncode == 0, "absent": absent}
        if result.returncode == 0 and absent:
            self.containers.remove(name)

    def adapter_check(self, candidate):
        LinuxExecutor, Identity, Spec, Resources, Refused = self.executor_classes
        job_id = self.owner + "-adapter"
        job = self.run_root / job_id
        job.mkdir(mode=0o700)
        source, state = job / "source", job / "state"
        source.mkdir(mode=0o700)
        state.mkdir(mode=0o700)
        config = job / "runtime.json"
        config.write_text('{"role":"build"}')
        config.chmod(0o600)
        identity = Identity(job_id, "attempt-1", "build", 1)
        executor = LinuxExecutor(candidate, self.run_root / "adapter-executor")
        spec = Spec(identity, self.base_image, str(source), str(state),
                    ("python", "-m", "hf2l_jobs.runtime", "--config", "/run/hf2l/runtime.json"),
                    None, Resources(500, 512 * MIB, 64 * MIB, pids=64),
                    config_path=str(config), role="build")
        reserved = False
        try:
            expected_paths = sorted({d["path"] for d in (
                executor._backing_device(source), executor._backing_device(self.profile["docker_data_root"])
            )})
            self.check("adapter_derived_trusted_devices", executor._io_devices(spec) == expected_paths)
            try:
                executor._backing_device("/dev/shm")
            except Refused as exc:
                denied = exc.code == "unsupported_backing"
            else:
                denied = False
            self.check("adapter_unknown_nonblock_denied", denied)
            executor.reserve(spec)
            reserved = True
            executor.start(identity)
            until = time.monotonic() + 30
            while time.monotonic() < until:
                observation = executor.inspect(identity)
                if observation.termination_confirmed:
                    break
                time.sleep(.1)
            record = executor._load(identity)
            actual = json.loads(executor._docker(["inspect", record["container"]]).stdout)[0]
            caps = {record["loop_device"]: 16 * MIB, **{p: 16 * MIB for p in expected_paths}}
            self.check("adapter_actual_physical_and_loop_caps",
                       {x["Path"]: x["Rate"] for x in actual["HostConfig"]["BlkioDeviceReadBps"]} == caps
                       and {x["Path"]: x["Rate"] for x in actual["HostConfig"]["BlkioDeviceWriteBps"]} == caps)
            self.check("adapter_fixed_isolated_command",
                       actual["HostConfig"]["Runtime"] == "runsc"
                       and actual["HostConfig"]["NetworkMode"] == "none"
                       and actual["Path"] == "python" and actual["Args"] == list(spec.argv[1:])
                       and observation.termination_confirmed and observation.exit_code == 1,
                       scope="intentional invalid build manifest exit1; no FL success claim")
            released = executor.release(identity)
            loop_backing = Path("/sys/block") / Path(record["loop_device"]).name / "loop/backing_file"
            still_owned = loop_backing.exists() and loop_backing.read_text().strip().lstrip("/") == str(executor._directory(identity) / "state.ext4").lstrip("/")
            self.check("adapter_confirmed_resource_cleanup", released and not still_owned
                       and not (executor._directory(identity) / "state.ext4").exists()
                       and executor._docker(["inspect", record["container"]], allow_failure=True).returncode != 0)
        finally:
            if reserved:
                executor.stop(identity, grace_seconds=1)
                if not executor.release(identity):
                    raise RuntimeError("Adapter resources were not confirmed released")

    def cleanup(self):
        for control in self.run_root.glob("control-*"):
            (control / "stop").touch()
        for name in list(self.containers):
            self.remove_container(name)
        if self.derived_image:
            result = self.docker_call("image", "rm", "--no-prune", self.derived_image, check=False)
            absent = self.docker_call("image", "inspect", self.derived_image, check=False).returncode != 0
            self.report["cleanup"]["derived_image"] = {"removed": result.returncode == 0, "absent": absent}
        for directory in self.input_roots:
            shutil.rmtree(directory)
        if hasattr(self, "context_path"):
            self.context_path.unlink(missing_ok=True)
        for path in self.run_root.glob("candidate-profile.json"):
            path.unlink()
        self.report["cleanup"]["synthetic_input_bytes_removed"] = all(not p.exists() for p in self.input_roots)
        self.report["cleanup"]["retained_parent_tag"] = self.parent_tag
        if self.containers or any(not x["removed"] or not x["absent"] for x in self.report["cleanup"].values() if isinstance(x, dict)):
            raise RuntimeError("Task-owned probe cleanup was not confirmed")

    def execute(self):
        failure = None
        try:
            self.verify_runtime()
            self.prepare_inputs()
            for limit in LIMITS:
                self.run_limit(limit)
            candidate = dict(self.profile)
            candidate.update(backing_io_qualified=True, backing_devices=self.devices)
            candidate_path = self.run_root / "candidate-profile.json"
            atomic_write(candidate_path, (json.dumps(candidate, indent=2) + "\n").encode())
            self.adapter_check(candidate_path)
        except BaseException as exc:
            failure = exc
            self.report["error"] = type(exc).__name__ + ": " + str(exc)
            self.report["failed_probe_evidence"] = []
            for name in self.containers:
                try:
                    self.report["failed_probe_evidence"].append(self.probe_evidence(name))
                except BaseException as diagnostic_error:
                    self.report["failed_probe_evidence"].append({
                        "name": name, "capture_error": type(diagnostic_error).__name__ + ": " + str(diagnostic_error)})
        finally:
            try:
                self.cleanup()
            except BaseException as exc:
                failure = failure or exc
                self.report["cleanup_error"] = type(exc).__name__ + ": " + str(exc)
            self.report["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.report["qualified"] = failure is None and bool(self.report["checks"]) and all(x["passed"] for x in self.report["checks"])
            report_path = self.run_root / "qualification.json"
            report_bytes = (json.dumps(self.report, indent=2) + "\n").encode()
            atomic_write(report_path, report_bytes)
        if failure:
            raise RuntimeError("Readonly I/O qualification failed; original profile preserved; evidence " + str(report_path)) from failure
        promoted = dict(self.profile)
        for name in list(promoted):
            if name.startswith("backing_io_"):
                del promoted[name]
        promoted.update({
            "backing_io_qualified": True, "backing_devices": self.devices,
            "backing_io_qualification_path": str(report_path),
            "backing_io_qualification_sha256": digest(report_bytes),
            "backing_io_qualification_checks": len(self.report["checks"]),
            "backing_io_qualified_at": self.report["completed_at"],
        })
        lock_path = self.profile_path.with_name(self.profile_path.name + ".readonly-qualification.lock")
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            if self.profile_path.read_bytes() != self.original_bytes:
                raise RuntimeError("Profile changed during qualification; evidence retained but promotion refused")
            atomic_write(self.profile_path, (json.dumps(promoted, indent=2) + "\n").encode())
        finally:
            os.close(descriptor)
        return {
            "qualified": True, "profile_path": str(self.profile_path),
            "profile_sha256": digest(self.profile_path.read_bytes()),
            "qualification_path": str(report_path),
            "qualification_sha256": digest(report_bytes),
            "checks": len(self.report["checks"]), "retained_parent_tag": self.parent_tag,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, help="trusted executor-profile.json from original isolation qualification")
    parser.add_argument("--root", required=True, help="private evidence directory within profile owned_root; only a new random child is used")
    parser.add_argument("--base-image", required=True, help="already local immutable Python-capable image ID/digest; no pulls")
    args = parser.parse_args()
    try:
        result = Qualification(args).execute()
    except (OSError, ValueError, RuntimeError, KeyError, AssertionError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
