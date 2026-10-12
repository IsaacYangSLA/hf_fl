#!/usr/bin/env python3
"""Adversarial qualification of a task-owned CPU runsc deployment.

Runs only synthetic jobs against the explicitly selected Docker daemon. Evidence
is written outside the repository. No global daemon or unrelated container is
changed. A failed check leaves the profile unqualified and the process exits 1.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import subprocess
import sys
import threading
import tempfile
import time
import traceback

LABEL = "hf2l.jobs.qualification"
MIB = 1024 * 1024

PROBE = r"""
import errno, json, os, pathlib, socket, sys, time
job, foreign, host_pid, host_secret, foreign_source, foreign_state, foreign_socket, daemon_socket, host_ip, host_port, abstract_name = sys.argv[1:]
checks = []
def add(name, passed, **detail):
    checks.append(dict(name=name, passed=bool(passed), **detail))
def rejected_read(name, path):
    try:
        with open(path, "rb") as handle:
            handle.read(128)
    except OSError as exc:
        add(name, True, errno=exc.errno, path=path)
    else:
        add(name, False, path=path)
for name, path in [
    ("foreign_source", foreign_source + "/identity"),
    ("foreign_state", foreign_state + "/state/identity"),
    ("foreign_cache", foreign_state + "/cache/identity"),
    ("foreign_logs", foreign_state + "/logs/identity"),
    ("host_secret", host_secret),
    ("host_proc_root", "/proc/" + host_pid + "/root" + host_secret),
    ("init_proc_root_host", "/proc/1/root" + host_secret),
    ("runtime_socket", daemon_socket),
    ("global_docker_socket", "/var/run/docker.sock"),
    ("task_containerd_socket", str(pathlib.Path(daemon_socket).with_name("containerd.sock"))),
    ("global_containerd_socket", "/run/containerd/containerd.sock"),
    ("host_home", "/localhome/local-isaacy/.ssh/authorized_keys"),
    ("host_block_device", "/dev/sda"),
]:
    rejected_read(name, path)
    if name not in {"foreign_source", "foreign_state", "foreign_cache", "foreign_logs", "host_secret", "host_proc_root", "init_proc_root_host"}:
        continue
    try:
        with open(path, "wb") as handle:
            handle.write(b"attempted foreign write")
    except OSError as exc:
        add(name + "_write", True, errno=exc.errno, path=path)
    else:
        add(name + "_write", False, path=path)
for name, path in [
    ("readonly_source", "/job/source/identity"),
    ("readonly_runtime", "/etc/hf2l-qualification"),
]:
    try:
        with open(path, "wb") as handle:
            handle.write(b"attempted modification")
    except OSError as exc:
        add(name, exc.errno in (errno.EROFS, errno.EACCES, errno.EPERM), errno=exc.errno)
    else:
        add(name, False)
for name, path in [
    ("source_traversal", "/job/source/../../localhome/local-isaacy"),
    ("foreign_proxy_path", foreign_socket),
]:
    add(name, not os.path.exists(path), path=path)
for area in ("state", "cache", "logs"):
    path = pathlib.Path("/job") / area / "identity"
    path.write_text(job)
    add("private_" + area, path.read_text() == job)
add("own_source", pathlib.Path("/job/source/identity").read_text() == job)
add("source_has_no_git", not pathlib.Path("/job/source/.git").exists())
def proxy_call(wanted):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(3)
    client.connect("/job/proxy.sock")
    client.sendall(json.dumps(dict(job=wanted, operation="identity")).encode() + b"\n")
    data = b""
    while b"\n" not in data:
        part = client.recv(1024)
        if not part:
            break
        data += part
    client.close()
    return json.loads(data)
own = proxy_call(job)
add("assigned_proxy", own.get("job") == job and own.get("ok") is True)
foreign_reply = proxy_call(foreign)
add("foreign_proxy_request", foreign_reply.get("ok") is False)
try:
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(1)
    client.connect(foreign_socket)
except OSError as exc:
    add("foreign_proxy_connect", True, errno=exc.errno)
else:
    client.close()
    add("foreign_proxy_connect", False)
try:
    abstract = socket.socket(socket.AF_UNIX)
    abstract.settimeout(1)
    abstract.connect("\0" + abstract_name)
except OSError as exc:
    add("host_abstract_socket", True, errno=exc.errno)
else:
    abstract.close()
    add("host_abstract_socket", False)
for name, address, port in [
    ("host_network", host_ip, int(host_port)),
    ("host_loopback", "127.0.0.1", int(host_port)),
    ("docker_gateway", "172.17.0.1", int(host_port)),
    ("metadata_network", "169.254.169.254", 80),
    ("internet_network", "1.1.1.1", 443),
]:
    try:
        client = socket.create_connection((address, port), timeout=0.5)
    except OSError as exc:
        add(name, True, errno=exc.errno, address=address, port=port)
    else:
        client.close()
        add(name, False, address=address, port=port)
status = pathlib.Path("/proc/self/status").read_text()
values = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
add("zero_capabilities", int(values.get("CapEff", "0"), 16) == 0)
try:
    version = pathlib.Path("/proc/version").read_text()
except OSError:
    version = ""
add("gvisor_kernel", "gvisor" in version.lower(), version=version.strip())
print(json.dumps(dict(job=job, checks=checks)), flush=True)
while True:
    time.sleep(1)
"""


IO_PROBE = r"""
import json, os, pathlib, time
path = pathlib.Path("/job/state/io-exhaustion")
written = 0
start = time.monotonic()
try:
    with path.open("wb", buffering=0) as handle:
        for _ in range(32):
            written += handle.write(b"x" * (1024 * 1024))
            os.fsync(handle.fileno())
finally:
    path.unlink(missing_ok=True)
elapsed = time.monotonic() - start
rate = written / elapsed
print(json.dumps(dict(written=written, wall_seconds=elapsed, bytes_per_second=rate, passed=rate <= 16777216 * 1.25)))
"""

DISK_PROBE = r"""
import errno, json, os, pathlib
path = pathlib.Path("/job/state/disk-exhaustion")
written = 0
failure = None
try:
    with path.open("wb", buffering=0) as handle:
        for _ in range(160):
            written += handle.write(b"x" * (1024 * 1024))
        os.fsync(handle.fileno())
except OSError as exc:
    failure = exc.errno
finally:
    path.unlink(missing_ok=True)
print(json.dumps(dict(errno=failure, written=written, passed=failure == errno.ENOSPC)))
"""
TMPFS_PROBE = r"""
import errno, json, pathlib
path = pathlib.Path("/tmp/tmpfs-exhaustion")
written = 0
failure = None
try:
    with path.open("wb", buffering=0) as handle:
        for _ in range(48):
            written += handle.write(b"x" * (1024 * 1024))
except OSError as exc:
    failure = exc.errno
finally:
    path.unlink(missing_ok=True)
print(json.dumps(dict(errno=failure, written=written, passed=failure == errno.ENOSPC)))
"""
PID_PROBE = r"""
import errno, json, os, resource, signal, time
children = []
failure = None
try:
    for _ in range(160):
        try:
            pid = os.fork()
        except OSError as exc:
            failure = exc.errno
            break
        if pid == 0:
            time.sleep(120)
            os._exit(0)
        children.append(pid)
finally:
    for pid in children:
        try: os.kill(pid, signal.SIGKILL)
        except ProcessLookupError: pass
    for pid in children:
        try: os.waitpid(pid, 0)
        except ChildProcessError: pass
print(json.dumps(dict(errno=failure, children=len(children), nproc=list(resource.getrlimit(resource.RLIMIT_NPROC)), passed=failure == errno.EAGAIN and len(children) < 160)))
"""
CPU_PROBE = r"""
import json, multiprocessing, time
def burn():
    start = time.monotonic()
    value = 0
    while time.monotonic() - start < 3:
        value = (value + 1) % 1000000
start = time.monotonic()
children = [multiprocessing.get_context("fork").Process(target=burn) for _ in range(3)]
for process in children: process.start()
for process in children: process.join()
print(json.dumps(dict(wall_seconds=time.monotonic() - start, exit_codes=[p.exitcode for p in children])))
"""
MEMORY_PROBE = r"""
import time
values = []
for _ in range(1024):
    values.append(bytearray(1024 * 1024))
    time.sleep(0.003)
"""

class ProxyHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(3)
        raw = self.rfile.readline(4097)
        try:
            request = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            request = {}
        ok = len(raw) <= 4096 and request == {"job": self.server.job, "operation": "identity"}
        reply = {"ok": ok}
        if ok:
            reply["job"] = self.server.job
        self.wfile.write(json.dumps(reply).encode() + b"\n")

class ProxyServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

class HostListener(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False

class HostHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"synthetic host endpoint")

def run(command, *, timeout=60, check=True):
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {command!r}\n{result.stderr[-4000:]}")
    return result

class Qualification:
    def __init__(self, args):
        self.args = args
        self.root = Path(args.output_dir).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.token = secrets.token_hex(5)
        self.owner = "qualification-" + self.token
        self.proxy_root = Path(tempfile.mkdtemp(prefix="hf2l-qual-" + self.token + "-"))
        self.docker = ["sudo", "-n", "docker", "-H", args.docker_host]
        self.containers = []
        self.mounts = []
        self.servers = []
        self.abstract_socket = None
        self.report = {
            "schema_version": 1, "owner": self.owner, "profile": "cpu-runsc-uds",
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "docker_host": args.docker_host, "checks": [], "jobs": {}, "cleanup": {},
        }

    def check(self, name, passed, **evidence):
        self.report["checks"].append({"name": name, "passed": bool(passed), **evidence})

    def docker_json(self, *arguments):
        return json.loads(run(self.docker + list(arguments)).stdout)

    def configure(self):
        config_path = Path(self.args.daemon_config).resolve()
        data = config_path.read_bytes()
        config = json.loads(data)
        runtime = config.get("runtimes", {}).get("runsc", {})
        runtime_args = runtime.get("runtimeArgs", [])
        self.check("explicit_netstack", "--network=sandbox" in runtime_args or "--network=none" in runtime_args)
        self.check("no_host_network_passthrough", "--network=host" not in runtime_args)
        self.check("controlled_host_uds_open", "--host-uds=open" in runtime_args)
        self.check("systrap_platform", "--platform=systrap" in runtime_args)
        self.report["runtime"] = {
            "binary_sha256": hashlib.sha256(Path(runtime["path"]).read_bytes()).hexdigest(),
            "config": str(config_path), "sha256": hashlib.sha256(data).hexdigest(),
            "runtime_path": runtime.get("path"), "runtime_args": runtime_args,
            "version": run(["sudo", "-n", runtime["path"], "--version"]).stdout.strip(),
        }
        image = self.docker_json("image", "inspect", self.args.image)[0]
        self.report["image"] = {"id": image["Id"], "repo_digests": image.get("RepoDigests", [])}
        self.args.image = image["Id"]
        info = self.docker_json("info", "--format", "{{json .}}")
        self.check("runsc_registered", "runsc" in info.get("Runtimes", {}))
        self.check("cgroup_v2", str(info.get("CgroupVersion")) == "2")
        self.check("selected_daemon_config_matches", str(Path(config.get("data-root", "")).resolve()) == info.get("DockerRootDir"))
        self.report["docker_info"] = {
            key: info.get(key) for key in ("ID", "ServerVersion", "CgroupVersion", "CgroupDriver", "DockerRootDir")
        }
        daemon_pid = Path(config["pidfile"]).read_text().strip()
        host_netns = run(["readlink", "/proc/self/ns/net"]).stdout.strip()
        daemon_netns = run(["sudo", "-n", "readlink", f"/proc/{daemon_pid}/ns/net"]).stdout.strip()
        self.report["network_namespaces"] = {"host": host_netns, "daemon": daemon_netns}
        self.check("daemon_private_network_namespace", bool(daemon_netns) and daemon_netns != host_netns)
        if not all(item["passed"] for item in self.report["checks"]):
            raise RuntimeError("required runtime profile configuration is unavailable")

    def create_volume(self, job):
        base = self.root / self.owner / job
        source = base / "source"
        mount = base / "volume"
        source.mkdir(parents=True)
        mount.mkdir()
        (source / "identity").write_text(job)
        (source / "private-code.py").write_text(f"JOB = {job!r}\n")
        image = base / "volume.ext4"
        run(["truncate", "-s", "64M", str(image)])
        run(["mkfs.ext4", "-q", "-F", "-m", "0", str(image)])
        self.mounts.append(mount)
        run(["sudo", "-n", "mount", "-o", "loop,nodev,nosuid,noexec", str(image), str(mount)])
        for component in ("state", "cache", "logs"):
            run(["sudo", "-n", "mkdir", str(mount / component)])
            run(["sudo", "-n", "chown", f"{self.args.sandbox_uid}:{self.args.sandbox_gid}", str(mount / component)])
            run(["sudo", "-n", "chmod", "700", str(mount / component)])
            run(["sudo", "-n", "install", "-o", str(self.args.sandbox_uid), "-g", str(self.args.sandbox_gid), "-m", "600", str(source / "identity"), str(mount / component / "identity")])
        proxy_path = self.proxy_root / (job + ".sock")
        server = ProxyServer(str(proxy_path), ProxyHandler)
        server.job = job
        os.chmod(proxy_path, 0o600)
        run(["sudo", "-n", "chown", f"{self.args.sandbox_uid}:{self.args.sandbox_gid}", str(proxy_path)])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.servers.append(server)
        device = run(["findmnt", "-n", "-o", "SOURCE", "--target", str(mount)]).stdout.strip()
        return {"base": base, "source": source, "mount": mount, "socket": proxy_path, "device": device}

    def start(self, job, own, foreign, host_port, host_secret, memory_bytes=256 * MIB):
        name = f"hf2l-{self.token}-{job}"
        command = self.docker + [
            "run", "-d", "--name", name, "--label", f"{LABEL}={self.owner}",
            "--runtime", "runsc", "--network", "none", "--read-only", "--user", f"{self.args.sandbox_uid}:{self.args.sandbox_gid}",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
            "--cpus", "0.5", "--memory", str(memory_bytes), "--memory-swap", str(memory_bytes),
            "--pids-limit", "128", "--ulimit", "nproc=64:64",
            "--device-read-bps", f"{own['device']}:16777216",
            "--device-write-bps", f"{own['device']}:16777216",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777",
            "--shm-size", "16m", "--log-driver", "local", "--log-opt", "max-size=1m",
            "--log-opt", "max-file=2",
            "--mount", f"type=bind,src={own['source']},dst=/job/source,readonly",
            "--mount", f"type=bind,src={own['socket']},dst=/job/proxy.sock,readonly",
        ]
        for component in ("state", "cache", "logs"):
            command += ["--mount", f"type=bind,src={own['mount'] / component},dst=/job/{component}"]
        command += [
            "--entrypoint", "python", self.args.image, "-u", "-c", PROBE,
            job, "B" if job == "A" else "A", str(os.getpid()), str(host_secret),
            str(foreign["source"]), str(foreign["mount"]), str(foreign["socket"]),
            self.args.docker_host.removeprefix("unix://"), self.args.host_ip, str(host_port), "hf2l-qual-" + self.token,
        ]
        self.containers.append(name)
        container_id = run(command, timeout=90).stdout.strip()
        return name, container_id

    def inspect(self, name):
        return self.docker_json("inspect", name)[0]

    def cgroup(self, inspected):
        pid = inspected["State"]["Pid"]
        relative = Path(f"/proc/{pid}/cgroup").read_text().split("0::", 1)[1].strip()
        return Path("/sys/fs/cgroup") / relative.lstrip("/")

    def attest(self, job, name, container_id, memory_bytes=256 * MIB):
        inspected = self.inspect(name)
        host = inspected["HostConfig"]
        config = inspected["Config"]
        sentry_pid = inspected["State"]["Pid"]
        sentry_command = run(["sudo", "-n", "cat", f"/proc/{sentry_pid}/cmdline"]).stdout.replace("\0", " ")
        self.check(f"{job}_actual_sentry_runsc", "runsc" in sentry_command and "boot" in sentry_command, command=sentry_command)
        expected = {
            "Runtime": "runsc", "NetworkMode": "none", "ReadonlyRootfs": True,
            "Privileged": False, "Memory": memory_bytes, "MemorySwap": memory_bytes,
            "NanoCpus": 500000000, "PidsLimit": 128,
        }
        for key, value in expected.items():
            self.check(f"{job}_runtime_{key}", host.get(key) == value, observed=host.get(key))
        self.check(f"{job}_nonroot", config.get("User") == f"{self.args.sandbox_uid}:{self.args.sandbox_gid}")
        self.check(f"{job}_no_new_privileges", "no-new-privileges=true" in host.get("SecurityOpt", []))
        self.check(f"{job}_capabilities_removed", host.get("CapDrop") == ["ALL"])
        self.check(f"{job}_bounded_logs", host.get("LogConfig", {}).get("Config") == {"max-size": "1m", "max-file": "2"})
        cg = self.cgroup(inspected)
        values = {}
        for file in ("cpu.max", "memory.max", "memory.swap.max", "pids.max", "cpu.stat", "memory.events", "pids.events", "io.max", "io.stat"):
            values[file] = (cg / file).read_text().strip()
        self.check(f"{job}_cgroup_cpu", values["cpu.max"] == "50000 100000", value=values["cpu.max"])
        self.check(f"{job}_cgroup_memory", values["memory.max"] == str(memory_bytes), value=values["memory.max"])
        self.check(f"{job}_cgroup_swap", values["memory.swap.max"] == "0", value=values["memory.swap.max"])
        self.check(f"{job}_cgroup_pids", values["pids.max"] == "128", value=values["pids.max"])
        self.check(f"{job}_cgroup_io_bandwidth", "rbps=16777216" in values["io.max"] and "wbps=16777216" in values["io.max"], value=values["io.max"])
        self.report["jobs"][job] = {
            "name": name, "id": container_id, "inspect": inspected, "sentry_command": sentry_command, "cgroup": str(cg), "cgroup_limits": values,
        }
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            raw = run(self.docker + ["logs", name], check=False).stdout
            if raw.strip():
                break
            time.sleep(0.3)
        (self.root / f"{self.owner}-{job}-logs.txt").write_text(raw)
        probe = json.loads(raw.splitlines()[0])
        self.report["jobs"][job]["probe"] = probe
        for item in probe["checks"]:
            self.check(f"{job}_{item['name']}", item["passed"], **{key: value for key, value in item.items() if key not in ("name", "passed")})
        return cg

    def execute_probe(self, job, name, title, program, timeout=60):
        result = run(self.docker + ["exec", name, "python", "-u", "-c", program], timeout=timeout, check=False)
        evidence = {
            "exit_code": result.returncode, "stdout": result.stdout[-4000:], "stderr": result.stderr[-4000:],
        }
        try:
            value = json.loads(result.stdout)
        except ValueError:
            value = {}
        self.report["jobs"][job][title] = evidence | value
        self.check(f"{job}_{title}", result.returncode == 0 and value.get("passed") is True, **evidence)
        return result, value

    def stress(self, names, cgroups, jobs, host_port, host_secret):
        name_a, name_b = names
        self.execute_probe("A", name_a, "IO_bandwidth", IO_PROBE, timeout=45)
        self.execute_probe("A", name_a, "disk_ENOSPC", DISK_PROBE)
        self.execute_probe("A", name_a, "tmpfs_ENOSPC", TMPFS_PROBE)
        before = dict(line.split() for line in (cgroups[0] / "cpu.stat").read_text().splitlines())
        cpu = run(self.docker + ["exec", name_a, "python", "-u", "-c", CPU_PROBE], timeout=30, check=False)
        after = dict(line.split() for line in (cgroups[0] / "cpu.stat").read_text().splitlines())
        delta = int(after.get("nr_throttled", 0)) - int(before.get("nr_throttled", 0))
        self.report["jobs"]["A"]["CPU_stress"] = {
            "before": before, "after": after, "exit_code": cpu.returncode,
            "stdout": cpu.stdout, "stderr": cpu.stderr,
        }
        self.check("A_CPU_throttling", cpu.returncode == 0 and delta > 0, throttled_periods=delta)
        fixture = self.create_volume("C")
        pid_name, pid_id = self.start("C", fixture, jobs["B"], host_port, host_secret, memory_bytes=2 * 1024 * MIB)
        pid_cgroup = self.attest("C", pid_name, pid_id, memory_bytes=2 * 1024 * MIB)
        observations = []
        observer_stop = threading.Event()
        def observe_pids():
            while not observer_stop.is_set():
                try:
                    item = {
                        "at_monotonic": time.monotonic(),
                        "pids_current": int((pid_cgroup / "pids.current").read_text()),
                        "pids_events": dict(line.split() for line in (pid_cgroup / "pids.events").read_text().splitlines()),
                        "memory_events": dict(line.split() for line in (pid_cgroup / "memory.events").read_text().splitlines()),
                    }
                    observations.append(item)
                except OSError:
                    break
                observer_stop.wait(0.01)
        observer = threading.Thread(target=observe_pids, daemon=True)
        observer.start()
        try:
            pid_result, pid_value = self.execute_probe("C", pid_name, "PID_exhaustion", PID_PROBE)
        finally:
            observer_stop.set()
            observer.join(timeout=2)
        final_state = self.inspect(pid_name)["State"]
        if pid_result.returncode:
            deadline = time.monotonic() + 5
            while final_state["Running"] and time.monotonic() < deadline:
                time.sleep(0.1)
                final_state = self.inspect(pid_name)["State"]
        peak = max((item["pids_current"] for item in observations), default=0)
        hits = max((int(item["pids_events"].get("max", 0)) for item in observations), default=0)
        oom = max((int(item["memory_events"].get("oom_kill", 0)) for item in observations), default=0)
        cap_enforced = (
            bool(observations) and peak <= 128 and hits > 0 and oom == 0 and
            not final_state.get("OOMKilled") and
            ((pid_result.returncode == 0 and pid_value.get("passed") is True) or not final_state["Running"])
        )
        existing = next(item for item in reversed(self.report["checks"]) if item["name"] == "C_PID_exhaustion")
        existing.update(name="C_PID_cap_enforced", passed=cap_enforced, peak_host_tasks=peak,
                        pid_limit_events=hits, oom_kills=oom, runtime_terminated=not final_state["Running"],
                        graceful_guest_EAGAIN=pid_result.returncode == 0 and pid_value.get("passed") is True)
        self.report["jobs"]["C"]["pid_observations"] = observations
        self.report["jobs"]["C"]["final_state"] = final_state
        self.check("B_survives_C_PID_exhaustion", self.inspect(name_b)["State"]["Running"])
        sibling_pid = run(self.docker + ["exec", name_b, "python", "-c",
            "from pathlib import Path; p=Path('/job/state/pid-sibling-survived'); p.write_text('B'); print(p.read_text())"], check=False)
        self.check("B_state_usable_after_C_PID_exhaustion", sibling_pid.returncode == 0 and sibling_pid.stdout.strip() == "B")
        memory = run(self.docker + ["exec", name_a, "python", "-u", "-c", MEMORY_PROBE], timeout=45, check=False)
        after_inspect = self.inspect(name_a)
        events = (cgroups[0] / "memory.events").read_text().strip() if cgroups[0].exists() else ""
        self.report["jobs"]["A"]["memory_exhaustion"] = {
            "exit_code": memory.returncode, "stderr": memory.stderr[-2000:],
            "state": after_inspect["State"], "events": events,
        }
        killed = dict(line.split() for line in events.splitlines()).get("oom_kill", "0")
        self.check("A_memory_limit_enforced", after_inspect["State"].get("OOMKilled") or int(killed) > 0,
                   exit_code=memory.returncode, events=events, OOMKilled=after_inspect["State"].get("OOMKilled"))
        self.check("B_survives_A_exhaustion", self.inspect(name_b)["State"]["Running"])
        sibling = run(self.docker + ["exec", name_b, "python", "-c",
            "from pathlib import Path; p=Path('/job/state/sibling-survived'); p.write_text('B'); print(p.read_text())"], check=False)
        self.check("B_state_usable_after_A_exhaustion", sibling.returncode == 0 and sibling.stdout.strip() == "B")

    def cleanup(self):
        failures = []
        for name in reversed(self.containers):
            inspected = run(self.docker + ["inspect", name], check=False)
            if inspected.returncode:
                continue
            final = json.loads(inspected.stdout)[0]
            for job, detail in self.report["jobs"].items():
                if detail["name"] == name:
                    detail["cleanup_observed_state"] = final["State"]
            identity = final["Config"]["Labels"].get(LABEL)
            if identity != self.owner:
                failures.append(f"refused foreign container {name}")
                continue
            result = run(self.docker + ["rm", "-f", name], timeout=45, check=False)
            if result.returncode:
                failures.append(f"container {name}: {result.stderr[-1000:]}")
        for server in self.servers:
            server.shutdown()
            server.server_close()
            if isinstance(server.server_address, str):
                Path(server.server_address).unlink(missing_ok=True)
        if self.abstract_socket is not None:
            self.abstract_socket.close()
        for mount in reversed(self.mounts):
            if run(["mountpoint", "-q", str(mount)], check=False).returncode:
                continue
            result = run(["sudo", "-n", "umount", str(mount)], check=False)
            if result.returncode:
                failures.append(f"mount {mount}: {result.stderr[-1000:]}")
        try:
            self.proxy_root.rmdir()
        except OSError as exc:
            failures.append(f"proxy root {self.proxy_root}: {exc}")
        remaining = run(self.docker + ["ps", "-aq", "--filter", f"label={LABEL}={self.owner}"], check=False).stdout.strip()
        self.report["cleanup"] = {"remaining_containers": remaining.splitlines() if remaining else [], "failures": failures}
        self.check("owned_resources_cleanup", not failures and not remaining)

    def execute(self):
        try:
            self.configure()
            host_secret = self.root / self.owner / "host-only-secret"
            host_secret.parent.mkdir(parents=True, exist_ok=True)
            host_secret.write_text("synthetic-" + secrets.token_hex(16))
            jobs = {job: self.create_volume(job) for job in ("A", "B")}
            host = HostListener(("0.0.0.0", 0), HostHandler)
            self.servers.append(host)
            threading.Thread(target=host.serve_forever, daemon=True).start()
            host_port = host.server_address[1]
            self.abstract_socket = socket.socket(socket.AF_UNIX)
            self.abstract_socket.bind("\0hf2l-qual-" + self.token)
            self.abstract_socket.listen(2)
            connection = socket.create_connection((self.args.host_ip, host_port), timeout=2)
            self.check("host_endpoint_reachable_outside_sandbox", bool(connection.recv(128)))
            connection.close()
            names, ids = [], []
            for job in ("A", "B"):
                name, identity = self.start(job, jobs[job], jobs["B" if job == "A" else "A"], host_port, host_secret)
                names.append(name)
                ids.append(identity)
            self.check("two_jobs_concurrent", all(self.inspect(name)["State"]["Running"] for name in names))
            cgroups = [self.attest(job, name, identity) for job, name, identity in zip(("A", "B"), names, ids)]
            for job in ("A", "B"):
                own, foreign = jobs[job], jobs["B" if job == "A" else "A"]
                inspected = self.inspect(names[0 if job == "A" else 1])
                mount_sources = [item["Source"] for item in inspected["Mounts"]]
                self.check(f"{job}_only_owned_mounts", all(
                    value == str(own["source"]) or value == str(own["socket"]) or
                    value.startswith(str(own["mount"]) + "/") for value in mount_sources),
                    sources=mount_sources)
            self.stress(names, cgroups, jobs, host_port, host_secret)
        except Exception as exc:
            self.report["error"] = str(exc)
            self.report["traceback"] = traceback.format_exc()
            self.check("qualification_completed", False, error=str(exc))
        finally:
            try:
                self.cleanup()
            except Exception as exc:
                self.report["cleanup"] = {"error": str(exc)}
                self.check("owned_resources_cleanup", False, error=str(exc))
            self.report["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self.report["qualified"] = all(item["passed"] for item in self.report["checks"])
            output = self.root / "qualification.json"
            output.write_text(json.dumps(self.report, indent=2) + "\n")
            print(json.dumps({
                "qualified": self.report["qualified"], "checks": len(self.report["checks"]),
                "failed": [item["name"] for item in self.report["checks"] if not item["passed"]],
                "evidence": str(output),
            }), flush=True)
        return 0 if self.report["qualified"] else 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker-host", required=True)
    parser.add_argument("--daemon-config", required=True)
    parser.add_argument("--image", required=True, help="Approved image digest or local immutable image ID")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--host-ip", required=True)
    parser.add_argument("--sandbox-uid", type=int, default=os.getuid())
    parser.add_argument("--sandbox-gid", type=int, default=os.getgid())
    args = parser.parse_args()
    if not args.docker_host.startswith("unix:///"):
        parser.error("qualification requires an explicit local Unix Docker socket")
    if args.sandbox_uid <= 0 or args.sandbox_gid <= 0:
        parser.error("sandbox UID and GID must both be nonzero")
    return Qualification(args).execute()

if __name__ == "__main__":
    sys.exit(main())
