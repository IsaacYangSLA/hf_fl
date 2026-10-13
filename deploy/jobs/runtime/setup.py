#!/usr/bin/env python3
"""Install and control a dedicated, networkless gVisor validation Docker daemon.

This is an explicit administrator tool. It never changes /etc/docker, the
system Docker service, networking, or unrelated containers. Workloads must
still be launched by the trusted node agent using approved specifications.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import tarfile
import time
import urllib.request

RELEASE = "20261005.0"
ARCHIVE_SHA512 = "79869ae9a589355a46d46fdac068d9a954e741741ffe77c64e38c56ea955498c1cb04e9bce44e1cce5155333e6b76bee72347c6661bb7c78fd2fe3aad198c8fe"
BASE_URL = f"https://storage.googleapis.com/gvisor/releases/release/{RELEASE}/x86_64"
MARKER = ".hf2l-jobs-runtime"
MARKER_CONTENT = "hf2l-owned-isolated-runtime-v1\n"
RUNTIME_ENVIRONMENT = {"GOMAXPROCS": "2"}
DEFAULT_RUNTIME_CPU_COUNT = 2


def call(args: list[str], **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {result.stderr.strip()}")
    return result


def owned_root(value: str, create: bool = False) -> Path:
    requested = Path(value)
    if not requested.is_absolute() or requested.is_symlink():
        raise ValueError("runtime root must be an absolute, non-symlink path")
    root = requested.resolve()
    if len(root.parts) < 4 or root in (Path("/var/lib/docker"), Path("/run/docker")):
        raise ValueError("refusing system or filesystem root")
    if len(str(root / "exec/containerd/containerd.sock")) >= 105:
        raise ValueError("runtime path too long for Unix sockets")
    marker = root / MARKER
    if create and not marker.exists():
        root.mkdir(parents=True, exist_ok=True)
        if any(x.name not in {"bin", "gvisor.tar.bz2"} for x in root.iterdir()):
            raise ValueError("runtime root is not empty or owned")
        marker.write_text(MARKER_CONTENT)
    if not marker.exists() or marker.read_text() != MARKER_CONTENT:
        raise ValueError("runtime ownership marker is missing or invalid")
    return root


def docker(root: Path, *args: str):
    return call(["sudo", "-n", "docker", "-H", f"unix://{root / 'docker.sock'}", *args])


def install(root: Path) -> dict:
    if unit_pid(root, "dockerd") or unit_pid(root, "containerd"):
        raise ValueError("stop the owned runtime services before reinstalling binaries")
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("qualified setup supports Linux x86_64 only")
    archive = root / "gvisor.tar.bz2"
    url = BASE_URL + "/gvisor.tar.bz2"
    if not archive.exists():
        temporary = root / "gvisor.tar.bz2.partial"
        with urllib.request.urlopen(url, timeout=60) as source, temporary.open("wb") as output:
            while chunk := source.read(1024 * 1024):
                output.write(chunk)
        temporary.replace(archive)
    digest = hashlib.sha512(archive.read_bytes()).hexdigest()
    if digest != ARCHIVE_SHA512:
        raise ValueError("official pinned gVisor archive checksum mismatch")
    official = urllib.request.urlopen(url + ".sha512", timeout=30).read().decode().split()[0]
    if official != ARCHIVE_SHA512:
        raise ValueError("official release checksum differs from pinned value")
    target = root / "bin"
    target.mkdir(exist_ok=True)
    with tarfile.open(archive, "r:bz2") as source:
        for entry in source.getmembers():
            relative = Path(entry.name)
            if relative.is_absolute() or ".." in relative.parts or not (entry.isfile() or entry.isdir()):
                raise ValueError("unsafe runtime archive member")
            destination = target / relative
            if destination.is_symlink():
                raise ValueError("unsafe existing extraction destination")
        source.extractall(target, filter="data")
        verified_files = [target / entry.name for entry in source.getmembers() if entry.isfile()]
    version = call([str(target / "runsc"), "--version"]).stdout.strip()
    if f"release-{RELEASE}" not in version:
        raise ValueError("gVisor binary version mismatch")
    # Readable/executable to the unprivileged sentry and gofer subprocesses.
    for directory in [root, target, target / "gvisor-bin"]:
        directory.chmod(0o755)
    for executable in verified_files:
        if executable.is_file():
            executable.chmod(0o755)
    public = Path("/opt") / ("hf2l-jobs-runtime-" + hashlib.sha256(str(root).encode()).hexdigest()[:12])
    call(["sudo", "-n", "install", "-d", "-m", "755", str(public), str(public / "gvisor-bin")])
    files = {}
    for executable in verified_files:
        if executable.is_file():
            relative = executable.relative_to(target)
            destination = public / relative
            call(["sudo", "-n", "install", "-m", "755", str(executable), str(destination)])
            files[str(destination)] = hashlib.sha256(destination.read_bytes()).hexdigest()
    evidence = {"binary_directory": str(public), "runtime_files_sha256": files, "release": RELEASE, "archive_url": url, "archive_sha512": digest,
                "verification": "hard-coded SHA512 and official HTTPS checksum; not a signature",
                "version": version, "runsc_sha256": hashlib.sha256((target / "runsc").read_bytes()).hexdigest()}
    (root / "installation.json").write_text(json.dumps(evidence, indent=2) + "\n")
    return evidence


def configuration(root: Path) -> dict:
    return {
        "data-root": str(root / "data"),
        "exec-root": str(root / "exec"),
        "pidfile": str(root / "dockerd.pid"),
        "containerd": str(root / "containerd.sock"),
        "containerd-namespace": "hf2l-jobs-" + hashlib.sha256(str(root).encode()).hexdigest()[:12],
        "containerd-plugins-namespace": "hf2l-jobs-plugins-" + hashlib.sha256(str(root).encode()).hexdigest()[:12],
        "hosts": [f"unix://{root / 'docker.sock'}"],
        "bridge": "none", "iptables": False, "ip6tables": False,
        "ip-forward": False, "ip-masq": False,
        "default-runtime": "runsc",
        "runtimes": {"runsc": {
            "path": str(Path(json.loads((root / "installation.json").read_text())["binary_directory"]) / "runsc"),
            "runtimeArgs": ["--network=sandbox", "--host-uds=open", "--platform=systrap",
                            "--allow-flag-override=false", "--net-raw=false",
                            "--allow-packet-socket-write=false", "--directfs=false",
                            "--overlay2=none", "--gofer-network-namespace=new",
                            "--host-settings=check", "--sidecar-usage-policy=STRICT"]}},
        "features": {"containerd-snapshotter": False},
        "storage-driver": "overlay2",
        "exec-opts": ["native.cgroupdriver=systemd"],
        "log-driver": "local", "log-opts": {"max-size": "4m", "max-file": "2"},
        "default-shm-size": "16m",
        "default-cgroupns-mode": "private",
        "live-restore": False,
        "labels": [f"hf2l.jobs.runtime={root}"],
    }


def process_matches(root: Path, pid: int) -> bool:
    try:
        command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except (FileNotFoundError, PermissionError):
        return False
    return (b"/usr/bin/dockerd" in command or b"dockerd" in command) and str(root / "daemon.json").encode() in command


def unit(root: Path, component: str) -> str:
    return "hf2l-jobs-" + component + "-" + hashlib.sha256(str(root).encode()).hexdigest()[:12]


def unit_pid(root: Path, component: str) -> int:
    result = subprocess.run(["sudo", "-n", "systemctl", "show", "--value",
                             "--property=MainPID", unit(root, component)],
                            text=True, capture_output=True)
    return int(result.stdout.strip() or "0")



def runtime_cpu_affinity(cpu_count: int = DEFAULT_RUNTIME_CPU_COUNT) -> list[int]:
    """Select at most the requested number of CPUs available to this operator."""
    if type(cpu_count) is not int or cpu_count < 1:
        raise ValueError("runtime CPU count must be a positive integer")
    available = sorted(os.sched_getaffinity(0))
    if not available:
        raise ValueError("runtime requires at least one available host CPU")
    return available[:cpu_count]


def runtime_cpu_policy(root: Path, cpu_count: int | None = None, *, create: bool = False) -> dict:
    """Keep daemon startup and qualification bound to one explicit CPU policy."""
    path = root / "runtime-policy.json"
    if cpu_count is not None:
        runtime_cpu_affinity(cpu_count)  # Validate before reading or writing policy.
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077
                or metadata.st_size > 64 * 1024):
            raise ValueError("runtime CPU policy must be a private regular file")
        policy = json.loads(path.read_text())
        if not isinstance(policy, dict):
            raise ValueError("runtime CPU policy is invalid")
        count = policy.get("cpu_count")
        affinity = policy.get("cpu_affinity")
        if (set(policy) != {"cpu_count", "cpu_affinity"}
                or type(count) is not int or count < 1
                or not isinstance(affinity, list) or not affinity or len(affinity) > count
                or any(type(cpu) is not int or cpu < 0 for cpu in affinity)
                or sorted(set(affinity)) != affinity):
            raise ValueError("runtime CPU policy is invalid")
        if cpu_count is not None and cpu_count != count:
            raise ValueError("existing CPU policy differs; use a new runtime root and requalify")
        if not set(affinity).issubset(os.sched_getaffinity(0)):
            raise ValueError("configured runtime CPUs are unavailable to this operator")
    elif create:
        count = DEFAULT_RUNTIME_CPU_COUNT if cpu_count is None else cpu_count
        policy = {"cpu_count": count, "cpu_affinity": runtime_cpu_affinity(count)}
        path.write_text(json.dumps(policy, indent=2) + "\n")
        path.chmod(0o600)
    else:
        raise ValueError("runtime CPU policy is missing; restart with an explicit qualified policy")
    return {"runtime_cpu_count": policy["cpu_count"],
            "runtime_cpu_affinity": policy["cpu_affinity"],
            "runtime_cpu_policy": str(path),
            "runtime_cpu_policy_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def launch_service(root: Path, component: str, command: list[str], *, private_network: bool = True) -> None:
    call(["sudo", "-n", "systemd-run", "--quiet", "--collect",
          "--unit=" + unit(root, component),
          *(["--property=PrivateNetwork=yes"] if private_network else []),
          "--property=CPUQuota=200%",
          "--property=Environment=GOMAXPROCS=2",
          "--property=CPUAffinity=" + " ".join(str(cpu) for cpu in runtime_cpu_policy(root)["runtime_cpu_affinity"]),
          "--property=MemoryMax=2G",
          "--property=TasksMax=4096",
          "--property=StandardOutput=append:" + str(root / (component + ".log")),
          "--property=StandardError=append:" + str(root / (component + ".log")),
          *command])


def start(root: Path, cpu_count: int | None = None) -> dict:
    runtime_cpu_policy(root, cpu_count, create=True)
    if not (root / "installation.json").exists():
        install(root)
    if (root / "docker.sock").exists():
        try:
            return status(root)
        except RuntimeError:
            pidfile = root / "dockerd.pid"
            if pidfile.exists() and process_matches(root, int(pidfile.read_text())):
                raise
            (root / "docker.sock").unlink()
    path = root / "daemon.json"
    config = configuration(root)
    if path.exists() and json.loads(path.read_text()) != config:
        raise ValueError("existing daemon configuration differs; inspect rather than overwrite")
    path.write_text(json.dumps(config, indent=2) + "\n")
    path.chmod(0o600)
    call(["sudo", "-n", "dockerd", "--validate", "--config-file", str(path)])
    containerd_config = root / "containerd.toml"
    containerd_config.write_text(
        'version = 3\n'
        'disabled_plugins = ["io.containerd.grpc.v1.cri", "io.containerd.cri.v1.images", "io.containerd.cri.v1.runtime"]\n'
        + 'root = ' + json.dumps(str(root / "containerd-data")) + '\n'
        + 'state = ' + json.dumps(str(root / "containerd-exec")) + '\n'
        + '[grpc]\naddress = ' + json.dumps(str(root / "containerd.sock")) + '\n')
    if not unit_pid(root, "containerd"):
        launch_service(root, "containerd", ["/usr/bin/containerd", "--config", str(containerd_config)])
    for _ in range(100):
        if (root / "containerd.sock").exists():
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("task containerd failed to start; inspect containerd.log")
    containerd_pid = unit_pid(root, "containerd")
    if not containerd_pid:
        raise RuntimeError("owned containerd process is missing")
    launch_service(root, "dockerd", ["/usr/bin/nsenter", "--target", str(containerd_pid),
                   "--mount", "--net", "/usr/bin/dockerd", "--config-file", str(path)], private_network=False)
    for _ in range(100):
        try:
            return status(root)
        except (RuntimeError, FileNotFoundError):
            time.sleep(0.2)
    raise RuntimeError("task dockerd startup failed; inspect task dockerd.log")


def status(root: Path) -> dict:
    info = json.loads(docker(root, "info", "--format", "{{json .}}").stdout)
    if info["DockerRootDir"] != str(root / "data"):
        raise ValueError("socket connects to a foreign Docker daemon")
    config = json.loads((root / "daemon.json").read_text())
    if config != configuration(root):
        raise ValueError("daemon configuration policy mismatch")
    runtime = info.get("Runtimes", {}).get("runsc", {})
    if info.get("DefaultRuntime") != "runsc" or runtime.get("path") != str(Path(json.loads((root / "installation.json").read_text())["binary_directory"]) / "runsc"):
        raise ValueError("required gVisor runtime is not active")
    if info.get("Containerd", {}).get("Address") != str(root / "containerd.sock"):
        raise ValueError("daemon is connected to a foreign containerd service")
    if info.get("Containerd", {}).get("Namespaces", {}).get("Containers") != config["containerd-namespace"]:
        raise ValueError("daemon is using a foreign containerd namespace")
    if info.get("CgroupVersion") != "2":
        raise ValueError("required cgroup v2 is missing")
    daemon_pid = unit_pid(root, "dockerd")
    if not daemon_pid or not process_matches(root, daemon_pid):
        raise ValueError("daemon is not the task-owned isolated systemd service")
    host_network = call(["sudo", "-n", "readlink", "/proc/1/ns/net"]).stdout.strip()
    daemon_network = call(["sudo", "-n", "readlink", f"/proc/{daemon_pid}/ns/net"]).stdout.strip()
    if host_network == daemon_network:
        raise ValueError("daemon shares host network namespace")
    containerd_pid = unit_pid(root, "containerd")
    cpu_policy = runtime_cpu_policy(root)
    for component in ("dockerd", "containerd"):
        environment = call(["sudo", "-n", "systemctl", "show", "--value",
                            "--property=Environment", unit(root, component)]).stdout.split()
        if "GOMAXPROCS=2" not in environment:
            raise ValueError("owned runtime must explicitly bound Go startup threading")
        component_pid = unit_pid(root, component)
        if sorted(os.sched_getaffinity(component_pid)) != cpu_policy["runtime_cpu_affinity"]:
            raise ValueError("owned runtime host CPU affinity changed")
    containerd_network = call(["sudo", "-n", "readlink", f"/proc/{containerd_pid}/ns/net"]).stdout.strip()
    daemon_mount = call(["sudo", "-n", "readlink", f"/proc/{daemon_pid}/ns/mnt"]).stdout.strip()
    containerd_mount = call(["sudo", "-n", "readlink", f"/proc/{containerd_pid}/ns/mnt"]).stdout.strip()
    if daemon_network != containerd_network or daemon_mount != containerd_mount:
        raise ValueError("Docker and containerd must share their private mount/network namespaces")
    evidence = {"status": "ready_for_qualification", "docker_host": f"unix://{root / 'docker.sock'}",
                "docker_prefix": ["sudo", "-n", "docker", "-H", f"unix://{root / 'docker.sock'}"],
                "daemon_config": str(root / "daemon.json"), "runtime": "runsc",
                "runtime_args": config["runtimes"]["runsc"]["runtimeArgs"],
                "network": "none", "proxy_transport": "unix", "bounded_volumes": "loop-ext4",
                "read_only": True, "docker_version": info["ServerVersion"],
                "cgroup_version": info["CgroupVersion"], "qualified": False,
                "runtime_environment": RUNTIME_ENVIRONMENT,
                **cpu_policy,
                "daemon_pid": daemon_pid, "host_network_namespace": host_network,
                "daemon_network_namespace": daemon_network, "containerd_socket": config["containerd"],
                "containerd_pid": containerd_pid, "daemon_mount_namespace": daemon_mount}
    (root / "profile.json").write_text(json.dumps(evidence, indent=2) + "\n")
    return evidence


def stop(root: Path) -> dict:
    running = docker(root, "ps", "-q").stdout.strip()
    if running:
        raise ValueError("refusing daemon stop while workloads are running; stop owned workloads first")
    pid = int((root / "dockerd.pid").read_text())
    if not process_matches(root, pid):
        raise ValueError("PID does not identify the owned daemon")
    if unit_pid(root, "dockerd") == pid:
        call(["sudo", "-n", "systemctl", "stop", unit(root, "dockerd")])
    else:
        # Only for migration from the previously verified, owned direct process.
        call(["sudo", "-n", "kill", "-TERM", str(pid)])
    for _ in range(100):
        if not process_matches(root, pid):
            containerd_pid = unit_pid(root, "containerd")
            if containerd_pid:
                command = Path(f"/proc/{containerd_pid}/cmdline").read_bytes().split(b"\0")
                if str(root / "containerd.toml").encode() not in command:
                    raise ValueError("refusing to stop a foreign containerd service")
                call(["sudo", "-n", "systemctl", "stop", unit(root, "containerd")])
            return {"status": "stopped", "root": str(root), "retained_data": True}
        time.sleep(0.2)
    raise RuntimeError("owned daemon did not stop within 20 seconds")


def preserve_readonly_qualification(path: Path, profile: dict) -> dict:
    """Carry forward only current, hash-bound physical I/O qualification."""
    if not path.exists() and not path.is_symlink():
        return profile
    if path.is_symlink():
        raise ValueError("existing executor profile cannot be a symlink")
    metadata = path.stat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077
            or metadata.st_size > 2 * 1024**2):
        raise ValueError("existing executor profile must be a private regular file")
    previous = json.loads(path.read_text())
    if previous.get("backing_io_qualified") is not True:
        return profile
    identity = ("owned_root", "docker_host", "docker_data_root", "containerd_socket",
                "daemon_config", "daemon_config_sha256", "daemon_unit", "runsc_sha256",
                "runtime_files_sha256", "sandbox_uid", "sandbox_gid", "profile", "runtime",
                "network", "runsc_network", "runsc_host_uds", "proxy_transport",
                "bounded_volumes", "read_only")
    if "runtime_environment" in profile:
        if (profile.get("runtime_environment") != RUNTIME_ENVIRONMENT
                or not isinstance(profile.get("containerd_unit"), str)
                or not profile["containerd_unit"]
                or not isinstance(profile.get("runtime_cpu_affinity"), list)
                or not profile["runtime_cpu_affinity"]
                or type(profile.get("runtime_cpu_count")) is not int
                or profile["runtime_cpu_count"] < len(profile["runtime_cpu_affinity"])
                or not isinstance(profile.get("runtime_cpu_policy"), str)
                or not isinstance(profile.get("runtime_cpu_policy_sha256"), str)
                or not re.fullmatch(r"[a-f0-9]{64}", profile["runtime_cpu_policy_sha256"])
                or any(type(cpu) is not int or cpu < 0 for cpu in profile["runtime_cpu_affinity"])
                or sorted(set(profile["runtime_cpu_affinity"])) != profile["runtime_cpu_affinity"]):
            raise ValueError("new runtime qualification identity is incomplete or invalid")
        identity += ("containerd_unit", "runtime_environment", "runtime_cpu_affinity",
                     "runtime_cpu_count", "runtime_cpu_policy", "runtime_cpu_policy_sha256")
    if (previous.get("qualification_sha256") != profile.get("qualification_sha256")
            or any(previous.get(key) != profile.get(key) for key in identity)):
        # Changed runtime or ownership requires fresh supplemental qualification.
        return profile
    report_path = Path(previous.get("backing_io_qualification_path", ""))
    if (not report_path.is_absolute() or ".." in report_path.parts
            or any(p.is_symlink() for p in (report_path, *report_path.parents))):
        raise ValueError("readonly qualification report path is unsafe")
    metadata = report_path.stat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077
            or not 0 < metadata.st_size <= 2 * 1024**2):
        raise ValueError("readonly qualification report must be a private regular file")
    report_bytes = report_path.read_bytes()
    expected = previous.get("backing_io_qualification_sha256", "")
    if (not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected)
            or hashlib.sha256(report_bytes).hexdigest() != expected):
        raise ValueError("readonly qualification evidence changed")
    report = json.loads(report_bytes)
    checks = report.get("checks")
    devices = previous.get("backing_devices")
    if (report.get("qualified") is not True or not isinstance(checks, list) or not checks
            or not all(isinstance(check, dict) and check.get("passed") is True for check in checks)
            or report.get("runtime_identity") != {key: profile[key] for key in identity}
            or report.get("base_qualification_sha256") != profile["qualification_sha256"]
            or not isinstance(devices, list) or not devices
            or report.get("backing_devices") != devices
            or not isinstance(report.get("completed_at"), str)):
        raise ValueError("readonly qualification does not match this runtime")
    for device in devices:
        if (not isinstance(device, dict) or set(device) != {"path", "major", "minor", "sysfs_path"}
                or type(device["major"]) is not int or type(device["minor"]) is not int
                or min(device["major"], device["minor"]) < 0
                or not isinstance(device["path"], str) or not device["path"].startswith("/dev/")
                or not isinstance(device["sysfs_path"], str) or not device["sysfs_path"].startswith("/sys/")):
            raise ValueError("readonly qualification device evidence is invalid")
    if len({json.dumps(device, sort_keys=True) for device in devices}) != len(devices):
        raise ValueError("readonly qualification device evidence is duplicated")
    profile.update(
        backing_io_qualified=True, backing_devices=devices,
        backing_io_qualification_path=str(report_path),
        backing_io_qualification_sha256=expected,
        backing_io_qualification_checks=len(checks),
        backing_io_qualified_at=report["completed_at"],
    )
    return profile


def publish_profile(root: Path, qualification: str, resource_root: str) -> dict:
    status(root)  # Verify the currently running daemon, not only saved evidence.
    cpu_policy = runtime_cpu_policy(root)
    report_path = Path(qualification)
    if report_path.is_symlink() or not report_path.is_file():
        raise ValueError("qualification must be a trusted regular report")
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)
    checks = report.get("checks", [])
    if report.get("qualified") is not True or not checks or not all(x.get("passed") is True for x in checks):
        raise ValueError("runtime qualification has not passed every check")
    config_bytes = (root / "daemon.json").read_bytes()
    runtime = report.get("runtime", {})
    installation = json.loads((root / "installation.json").read_text())
    if any(runtime.get(key) != value for key, value in cpu_policy.items()):
        raise ValueError("qualification tested a different runtime CPU policy")
    if runtime.get("runtime_environment") != RUNTIME_ENVIRONMENT:
        raise ValueError("qualification tested different runtime threading settings")
    if runtime.get("binary_sha256") != installation["runsc_sha256"]:
        raise ValueError("qualification tested a different runtime binary")
    if runtime.get("sha256") != hashlib.sha256(config_bytes).hexdigest():
        raise ValueError("qualification tested a different daemon configuration")
    if report.get("docker_info", {}).get("DockerRootDir") != str(root / "data"):
        raise ValueError("qualification tested a different Docker daemon")
    resources = Path(resource_root).resolve(strict=True)
    if resources == Path("/") or resources not in root.parents:
        raise ValueError("private resource root must contain the owned runtime")
    if os.getuid() == 0 or os.getgid() == 0:
        raise ValueError("publish as the trusted non-root node agent user")
    profile = {
        "profile": "runsc-cpu-v1", "runtime": "runsc", "qualified": True,
        "network": "none", "runsc_network": "sandbox", "runsc_host_uds": "open",
        "proxy_transport": "unix", "bounded_volumes": "loop-ext4",
        "read_only": True, "sandbox_uid": os.getuid(), "sandbox_gid": os.getgid(),
        "owned_root": str(resources),
        "docker_host": f"unix://{root / 'docker.sock'}",
        "docker_command": ["sudo", "-n", "docker", "-H", f"unix://{root / 'docker.sock'}"],
        "system_command": ["sudo", "-n"],
        "daemon_config": str(root / "daemon.json"),
        "daemon_config_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "docker_data_root": str(root / "data"),
        "containerd_socket": str(root / "containerd.sock"),
        "daemon_unit": unit(root, "dockerd") + ".service",
        "containerd_unit": unit(root, "containerd") + ".service",
        "runtime_environment": RUNTIME_ENVIRONMENT,
        **cpu_policy,
        "runsc_sha256": installation["runsc_sha256"],
        "runsc_release": RELEASE, "runtime_files_sha256": installation["runtime_files_sha256"],
        "qualification_path": str(report_path.resolve()),
        "qualification_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "qualified_at": report.get("completed_at"),
        "qualification_checks": len(checks),
        "qualification_image": report.get("image", {}).get("id"),
    }
    path = root / "executor-profile.json"
    profile = preserve_readonly_qualification(path, profile)
    temporary = root / "executor-profile.json.partial"
    temporary.write_text(json.dumps(profile, indent=2) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)
    return {"profile_path": str(path), **profile}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["install", "start", "status", "stop", "publish-profile"])
    parser.add_argument("--root", required=True)
    parser.add_argument("--cpu-count", type=int, help="Maximum host CPUs for a new runtime (default: 2); requires requalification")
    parser.add_argument("--qualification", help="Successful trusted qualify.py report")
    parser.add_argument("--resource-root", help="Private parent for provisioner and executor resources")
    args = parser.parse_args()
    if args.action == "publish-profile" and not (args.qualification and args.resource_root):
        parser.error("publish-profile requires --qualification and --resource-root")
    if args.cpu_count is not None and (args.action != "start" or args.cpu_count < 1):
        parser.error("--cpu-count must be positive and is only accepted by start")
    root = owned_root(args.root, create=args.action == "install")
    with (root / ".setup.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        result = (publish_profile(root, args.qualification, args.resource_root)
                  if args.action == "publish-profile" else
                  start(root, args.cpu_count) if args.action == "start" else globals()[args.action](root))
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
