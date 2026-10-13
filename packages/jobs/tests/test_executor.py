import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from dataclasses import replace
from hf2l_jobs.executor import (LinuxExecutor, ExecutionIdentity, ExecutionSpec,
    ResourceLimits, ExecutorRefused, UncertainExecution, Reservation, RuntimeObservation)
from hf2l_jobs.node_agent import NodeAgent, execution_storage_budget_bytes

def identity(job="job-a", epoch=1, attempt="attempt-a"):
    return ExecutionIdentity(job, attempt, "owner", epoch)

def spec(job="job-a", epoch=1, attempt="attempt-a", **kwargs):
    values = dict(identity=identity(job, epoch, attempt),
                  image_digest="sha256:" + "a" * 64,
                  source_path="/private/" + job + "/source",
                  state_path="/private/" + job + "/state",
                  argv=("python", "-m", "hf2l_jobs.runtime", "--config", "/run/hf2l/runtime.json"),
                  proxy_endpoint="/private/" + job + "/proxy.sock",
                  resources=ResourceLimits(500, 64*1024*1024, 64*1024*1024),
                  lease_seconds=120, node_id="node-a", pool_id="pool-a")
    values.update(kwargs)
    return ExecutionSpec(**values)

class FakeExecutor:
    def __init__(self):
        self.states = {}
        self.unknown = False
        self.stop_count = 0
    def reserve(self, request):
        self.states[request.identity.key] = "RESERVED"
        return Reservation(request.identity, True)
    def start(self, key):
        self.states[key.key] = "RUNNING"
        return RuntimeObservation(key, "RUNNING")
    def inspect(self, key):
        if self.unknown: raise UncertainExecution("lost node")
        state = self.states[key.key]
        return RuntimeObservation(key, state, state != "RUNNING")
    def stop(self, key, grace_seconds=60):
        self.stop_count += 1
        if self.unknown: raise UncertainExecution("lost node")
        self.states[key.key] = "STOPPED"
        return RuntimeObservation(key, "STOPPED", True)
    def collect(self, key): return ()
    def confirm_absent(self, key): return key.key not in self.states
    def purge(self, key): return True
    def release(self, key):
        if self.unknown: raise UncertainExecution("lost node")
        self.states[key.key] = "RELEASED"
        return True

class NodeLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "node.sqlite"
        self.clock = [100.0]
        self.wall = [1000.0]
        self.fake = FakeExecutor()
        self.agent = NodeAgent(self.fake, self.path, "node-a", "pool-a",
                               ResourceLimits(1000, 128*1024*1024, 512*1024*1024),
                               clock=lambda: self.clock[0], wall_clock=lambda: self.wall[0], boot_id="boot-a")
    def tearDown(self):
        self.agent.close()
        self.tmp.cleanup()
    def test_two_jobs_and_third_waits_until_confirmed_release(self):
        a, b, c = spec(), spec("job-b"), spec("job-c")
        self.agent.reserve(a); self.agent.reserve(b)
        self.agent.start(a.identity); self.agent.start(b.identity)
        with self.assertRaises(ExecutorRefused) as cm: self.agent.reserve(c)
        self.assertEqual(cm.exception.code, "capacity")
        self.agent.stop(a.identity)
        with self.assertRaises(ExecutorRefused): self.agent.reserve(c)
        self.agent.release(a.identity)
        self.assertTrue(self.agent.reserve(c).acknowledged)
        self.assertEqual(len(self.agent.inventory()), 3)
    def test_stop_after_confirmed_release_is_idempotent(self):
        a = spec()
        self.agent.reserve(a); self.agent.stop(a.identity); self.agent.release(a.identity)
        self.assertTrue(self.agent.stop(a.identity).termination_confirmed)
        self.assertEqual(self.agent.inventory()[0]["state"], "RELEASED")
        self.assertEqual(self.fake.stop_count, 1)

    def test_missing_node_row_needs_positive_private_executor_absence(self):
        a = spec()
        self.assertTrue(self.agent.confirm_absent(a.identity))
        self.fake.reserve(a)
        self.assertFalse(self.agent.confirm_absent(a.identity))
        del self.fake.states[a.identity.key]
        self.agent.reserve(a)
        self.assertFalse(self.agent.confirm_absent(a.identity))

    def test_reservation_intent_is_durable_before_executor_effect(self):
        original = self.fake.reserve
        observed = []
        def crash_after_effect(request):
            db = __import__("sqlite3").connect(self.path)
            try:
                observed.append(db.execute("SELECT state FROM executions WHERE execution_key=?",
                                           (request.identity.key,)).fetchone()[0])
            finally: db.close()
            original(request)
            raise UncertainExecution("crashed after private executor reservation")
        self.fake.reserve = crash_after_effect
        a = spec()
        with self.assertRaises(UncertainExecution): self.agent.reserve(a)
        self.assertEqual(observed, ["RESERVING"])
        self.assertEqual(self.agent.inventory()[0]["state"], "QUARANTINED")
        self.assertFalse(self.agent.confirm_absent(a.identity))
        self.agent.stop(a.identity); self.agent.release(a.identity)
        self.assertEqual(self.agent.inventory()[0]["state"], "RELEASED")

    def test_crash_before_executor_effect_requires_positive_absence_before_release(self):
        a = spec()
        def fail_before_effect(request):
            raise UncertainExecution("node crash before executor reservation effect")
        self.fake.reserve = fail_before_effect
        with self.assertRaises(UncertainExecution): self.agent.reserve(a)
        def missing(*args, **kwargs):
            raise ExecutorRefused("No private executor record", "missing_reservation")
        self.fake.stop = missing
        self.fake.inspect = missing
        self.assertTrue(self.agent.stop(a.identity).termination_confirmed)
        self.assertEqual(self.agent.collect(a.identity), ())
        self.assertTrue(self.agent.release(a.identity))
        self.assertTrue(self.agent.purge(a.identity))
        self.assertEqual(self.agent.inventory()[0]["state"], "RELEASED")

    def test_component_guard_excludes_second_node_process(self):
        import threading
        second = NodeAgent(self.fake, self.path, "node-a", "pool-a", self.agent.capacity,
                           clock=lambda:100, wall_clock=lambda:1000, boot_id="boot-a")
        started, completed = threading.Event(), threading.Event()
        def contender():
            started.set()
            with second.component_resource_guard(identity()): completed.set()
        try:
            with self.agent.component_resource_guard(identity()):
                thread = threading.Thread(target=contender); thread.start()
                self.assertTrue(started.wait(1)); self.assertFalse(completed.wait(.1))
            self.assertTrue(completed.wait(2)); thread.join()
        finally: second.close()

    def test_retained_disk_is_charged_until_confirmed_purge(self):
        self.agent.capacity = ResourceLimits(1000,128*1024*1024,132*1024*1024)
        a=spec()
        self.agent.reserve(a);self.agent.stop(a.identity);self.agent.release(a.identity)
        with self.assertRaises(ExecutorRefused): self.agent.reserve(spec("job-b"))
        self.agent.purge(a.identity)
        self.assertTrue(self.agent.reserve(spec("job-b")).acknowledged)
    def test_release_keeps_physical_caps_instead_of_logical_file_sum(self):
        a = spec()
        budget = execution_storage_budget_bytes(a.resources.disk_bytes)
        self.agent.capacity = ResourceLimits(1000, 128*1024*1024, budget * 2 - 1)
        logical_bytes = 37646616  # Measured corpus: 107438080 physical bytes across two copies.
        self.fake.collect = lambda key: (SimpleNamespace(size_bytes=logical_bytes),)
        self.agent.reserve(a)
        self.agent.stop(a.identity)
        self.agent.release(a.identity)
        row = self.agent.inventory()[0]
        self.assertEqual(row["retained_output_bytes"], logical_bytes)
        self.assertEqual(self.agent.storage_usage_bytes(), budget)
        with self.assertRaises(ExecutorRefused) as error:
            self.agent.reserve(spec("job-b"))
        self.assertEqual(error.exception.code, "capacity")
        self.fake.purge = lambda key: False
        with self.assertRaises(UncertainExecution): self.agent.purge(a.identity)
        self.assertEqual(self.agent.storage_usage_bytes(), budget)
        self.fake.purge = lambda key: True
        self.assertTrue(self.agent.purge(a.identity))
        self.assertEqual(self.agent.storage_usage_bytes(), 0)
        self.assertTrue(self.agent.reserve(spec("job-b")).acknowledged)

    def test_storage_metadata_headroom_is_prepaid_once_per_execution(self):
        a = spec()
        budget = execution_storage_budget_bytes(a.resources.disk_bytes)
        self.agent.capacity = ResourceLimits(1000, 128*1024*1024, budget - 1)
        with self.assertRaises(ExecutorRefused): self.agent.reserve(a)
        self.agent.capacity = replace(self.agent.capacity, disk_bytes=budget + 100)
        self.agent.reserve(a)
        self.agent.charge_auxiliary_bytes(a.identity, 40)
        self.agent.charge_shared_auxiliary_bytes(a.identity, 60)
        self.assertEqual(self.agent.storage_usage_bytes(), budget + 100)
        self.agent.stop(a.identity); self.agent.release(a.identity)
        self.assertEqual(self.agent.storage_usage_bytes(), budget + 100)
        self.assertTrue(self.agent.purge(a.identity, auxiliary_deleted=True))
        self.assertEqual(self.agent.storage_usage_bytes(), 0)

    def test_cross_process_reservations_cannot_both_spend_same_storage_headroom(self):
        import threading
        a, b = spec(), spec("job-b")
        budget = execution_storage_budget_bytes(a.resources.disk_bytes)
        capacity = ResourceLimits(1000, 128*1024*1024, budget * 2 - 1)
        self.agent.capacity = capacity
        second = NodeAgent(self.fake, self.path, "node-a", "pool-a", capacity,
                           clock=lambda:100, wall_clock=lambda:1000, boot_id="boot-a")
        barrier, outcomes = threading.Barrier(2), []
        def reserve(agent, request):
            barrier.wait()
            try: outcomes.append(agent.reserve(request).acknowledged)
            except ExecutorRefused as error: outcomes.append(error.code)
        try:
            threads = [threading.Thread(target=reserve, args=(self.agent,a)),
                       threading.Thread(target=reserve, args=(second,b))]
            for thread in threads: thread.start()
            for thread in threads: thread.join(timeout=5)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertCountEqual(outcomes, [True, "capacity"])
            self.assertEqual(self.agent.storage_usage_bytes(), budget)
        finally: second.close()

    def test_shared_source_budget_is_reserved_once_across_attempts(self):
        a = spec()
        self.agent.reserve(a)
        self.agent.charge_shared_auxiliary_bytes(a.identity, 64*1024*1024)
        self.assertEqual(self.agent.storage_usage_bytes(), 196*1024*1024)
        self.agent.stop(a.identity); self.agent.release(a.identity)
        b = spec(epoch=2, attempt="attempt-b")
        self.agent.reserve(b)
        before = self.agent.storage_usage_bytes()
        self.agent.charge_shared_auxiliary_bytes(b.identity, 64*1024*1024)
        self.assertEqual(self.agent.storage_usage_bytes(), before)
        with self.assertRaises(ExecutorRefused): self.agent.purge(a.identity, auxiliary_deleted=True)
        self.agent.stop(b.identity); self.agent.release(b.identity)
        self.agent.purge(a.identity, auxiliary_deleted=True)
        self.assertEqual(self.agent.storage_usage_bytes(), 132*1024*1024)
        self.agent.purge(b.identity)
        self.assertEqual(self.agent.storage_usage_bytes(), 0)

    def test_auxiliary_storage_is_charged_before_write_until_confirmed_cleanup(self):
        self.agent.capacity = ResourceLimits(1000, 128*1024*1024, 256*1024*1024)
        a = spec()
        self.agent.reserve(a)
        self.assertTrue(self.agent.charge_auxiliary_bytes(a.identity, 64*1024*1024))
        self.assertTrue(self.agent.charge_auxiliary_bytes(a.identity, 1))
        self.assertEqual(self.agent.inventory()[0]["auxiliary_bytes"], 64*1024*1024)
        with self.assertRaises(ExecutorRefused): self.agent.reserve(spec("job-b"))
        with self.assertRaises(ExecutorRefused):
            self.agent.charge_auxiliary_bytes(a.identity, 129*1024*1024)
        self.agent.stop(a.identity); self.agent.release(a.identity)
        with self.assertRaises(ExecutorRefused) as error: self.agent.purge(a.identity)
        self.assertEqual(error.exception.code, "auxiliary_storage_retained")
        self.assertTrue(self.agent.purge(a.identity, auxiliary_deleted=True))
        self.assertEqual(self.agent.inventory()[0]["auxiliary_bytes"], 0)
        self.assertTrue(self.agent.reserve(spec("job-b")).acknowledged)

    def test_reservation_payload_is_idempotent_and_immutable(self):
        a = spec()
        self.agent.reserve(a)
        self.assertTrue(self.agent.reserve(a).acknowledged)
        with self.assertRaises(ExecutorRefused):
            self.agent.reserve(replace(a, resources=ResourceLimits(700,64*1024*1024,64*1024*1024)))
    def test_background_watchdog_operates_without_controller_poll(self):
        import time
        a=spec()
        self.agent.reserve(a);self.agent.start(a.identity)
        self.clock[0]=221
        deadline=time.monotonic()+2
        while self.agent.inventory()[0]["state"]!="STOPPED" and time.monotonic()<deadline:
            time.sleep(.02)
        self.assertEqual(self.agent.inventory()[0]["state"],"STOPPED")
        self.assertGreater(self.fake.stop_count,0)
    def test_expiry_stops_but_never_frees_capacity(self):
        a, b = spec(), spec("job-b")
        self.agent.reserve(a); self.agent.reserve(b)
        self.agent.start(a.identity)
        self.clock[0] = 221
        self.assertEqual(len(self.agent.watchdog_once()), 2)
        self.assertEqual(self.fake.stop_count, 2)
        self.assertTrue(all(r["state"] == "STOPPED" for r in self.agent.inventory()))
        with self.assertRaises(ExecutorRefused): self.agent.reserve(spec("job-c"))
        with self.assertRaises(ExecutorRefused): self.agent.renew(a.identity)
    def test_unknown_stop_quarantines_and_blocks_reuse(self):
        a = spec()
        self.agent.reserve(a); self.agent.start(a.identity)
        self.fake.unknown = True
        self.clock[0] = 221
        self.agent.watchdog_once()
        self.assertEqual(self.agent.inventory()[0]["state"], "QUARANTINED")
        with self.assertRaises(UncertainExecution): self.agent.release(a.identity)
        with self.assertRaises(ExecutorRefused): self.agent.reserve(spec(epoch=2,attempt="attempt-b"))
    def test_new_epoch_requires_confirmed_old_release(self):
        a = spec()
        self.agent.reserve(a)
        with self.assertRaises(ExecutorRefused): self.agent.reserve(spec(epoch=2,attempt="attempt-b"))
        self.agent.stop(a.identity); self.agent.release(a.identity)
        b = spec(epoch=2,attempt="attempt-b")
        self.agent.reserve(b)
        with self.assertRaises(ExecutorRefused): self.agent.start(a.identity)
        self.assertTrue(self.agent.purge(a.identity))
    def test_component_purge_requires_every_epoch_released(self):
        a = spec()
        self.agent.reserve(a)
        self.assertFalse(self.agent.component_purge_allowed(a.identity))
        self.agent.stop(a.identity); self.agent.release(a.identity)
        self.assertTrue(self.agent.component_purge_allowed(a.identity))
        b = spec(epoch=2, attempt="attempt-b")
        self.agent.reserve(b)
        self.assertFalse(self.agent.component_purge_allowed(a.identity))
        with self.assertRaises(ExecutorRefused):
            with self.agent.component_purge_guard(a.identity): pass
        self.agent.stop(b.identity); self.agent.release(b.identity)
        self.assertTrue(self.agent.component_purge_allowed(a.identity))

    def test_component_purge_guard_excludes_new_reservation(self):
        import threading
        a = spec()
        self.agent.reserve(a); self.agent.stop(a.identity); self.agent.release(a.identity)
        started, completed = threading.Event(), threading.Event()
        failures = []
        def reserve_later():
            started.set()
            try: self.agent.reserve(spec(epoch=2, attempt="attempt-b"))
            except BaseException as exc: failures.append(exc)
            finally: completed.set()
        with self.agent.component_purge_guard(a.identity):
            thread = threading.Thread(target=reserve_later); thread.start()
            self.assertTrue(started.wait(1))
            self.assertFalse(completed.wait(.1))
            self.assertTrue(self.agent.purge(a.identity))
        self.assertTrue(completed.wait(2)); thread.join()
        self.assertEqual(failures, [])

    def test_deadline_immutable_wall_clock_budget(self):
        with self.assertRaises(ExecutorRefused):
            self.agent.reserve(spec(deadline=999))
        a = spec(deadline=1001)
        self.agent.reserve(a)
        self.wall[0] = 1002
        with self.assertRaises(ExecutorRefused): self.agent.start(a.identity)
        self.assertEqual(self.agent.watchdog_once(), (a.identity,))
    def test_restart_preserves_ack_and_reboot_expires_leases(self):
        a = spec()
        self.agent.reserve(a); self.agent.start(a.identity)
        self.agent.close()
        self.agent = NodeAgent(self.fake,self.path,"node-a","pool-a",
            ResourceLimits(1000,128*1024*1024,128*1024*1024),clock=lambda:100,
            wall_clock=lambda:1000,boot_id="boot-b")
        self.assertEqual(self.agent.watchdog_once(), (a.identity,))
        self.assertEqual(self.agent.inventory()[0]["state"], "STOPPED")
    def test_foreign_node_and_pool_rejected(self):
        with self.assertRaises(ExecutorRefused): self.agent.reserve(spec(node_id="node-b"))
        with self.assertRaises(ExecutorRefused): self.agent.reserve(spec(pool_id="pool-b"))
    def test_positive_limits_gpu_and_digest_gate(self):
        with self.assertRaises(ExecutorRefused): ResourceLimits(True,1,1)
        with self.assertRaises(ExecutorRefused): ResourceLimits(1,1,1,gpus=1)
        with self.assertRaises(ExecutorRefused): spec(image_digest="python:latest")
        with self.assertRaises(ExecutorRefused): spec(profile="plain-container")
        with self.assertRaises(ExecutorRefused): spec(lease_seconds=301)
        with self.assertRaises(ExecutorRefused): spec(lease_seconds=True)
        with self.assertRaises(ExecutorRefused): identity(epoch=1.5)
        with self.assertRaises(ExecutorRefused): spec(deadline=float("nan"))

class RuntimeProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.bin = self.root / "runsc"
        self.bin.write_bytes(b"qualified runtime")
        self.bin.chmod(0o600)
        self.config = self.root / "daemon.json"
        self.config.write_text(json.dumps({"runtimes":{"runsc":{"path":str(self.bin),
           "runtimeArgs":["--network=sandbox","--host-uds=open"]}}}))
        self.profile = self.root / "profile.json"
        self.backing_fixture = {"path":"/dev/qualified", "major":8, "minor":0,
                                "sysfs_path":"/sys/devices/qualified/block/qualified"}
        backing = dict(self.backing_fixture)
        self.docker_data = self.root / "docker-data"; self.docker_data.mkdir()
        self.data = dict(backing_io_qualified=True, backing_devices=[backing], runtime="runsc",network="none",proxy_transport="unix",
           bounded_volumes="loop-ext4",runsc_network="sandbox",runsc_host_uds="open",
           qualified=True,owned_root=str(self.root),daemon_config=str(self.config),
           runsc_sha256=hashlib.sha256(self.bin.read_bytes()).hexdigest(),
           runtime_files_sha256={str(self.bin):hashlib.sha256(self.bin.read_bytes()).hexdigest()},
           sandbox_uid=1000,sandbox_gid=1000,docker_command=["docker"],system_command=[],
           daemon_config_sha256=hashlib.sha256(self.config.read_bytes()).hexdigest(),
           docker_data_root=str(self.docker_data),containerd_socket="/qualified/containerd.sock",
           daemon_unit="qualified-docker")
        self.profile.write_text(json.dumps(self.data))
        self.calls=[]
        def runner(argv,timeout=60):
            self.calls.append(argv)
            if argv[1:3]==["info","--format"]:
                return SimpleNamespace(returncode=0,stdout=json.dumps({"Runtimes":{"runsc":{}},"CgroupVersion":"2",
                    "DockerRootDir":str(self.docker_data),"Containerd":{"Address":"/qualified/containerd.sock"}}))
            if argv[0]=="systemctl": return SimpleNamespace(returncode=0,stdout="123")
            if argv[0]=="readlink": return SimpleNamespace(returncode=0,stdout="net:private" if "/proc/123/" in argv[1] else "net:host")
            return SimpleNamespace(returncode=0,stdout="")
        self.runner=runner
    def tearDown(self): self.tmp.cleanup()
    def executor(self):
        from unittest.mock import patch
        with patch.object(LinuxExecutor, "_backing_device", return_value=dict(self.backing_fixture)), \
             patch.object(LinuxExecutor, "_validate_device_evidence", return_value=None):
            executor = LinuxExecutor(self.profile,self.root/"runtime",self.runner)
        executor._validate_device_evidence = lambda item: None
        executor._backing_device = lambda path: (
            LinuxExecutor._backing_device(executor, path) if str(path)=="/dev/shm"
            else dict(self.backing_fixture))
        return executor
    def test_qualified_threading_and_effective_affinity_fail_closed_on_tamper(self):
        from unittest.mock import patch
        ex = self.executor()
        policy = self.root / "runtime-policy.json"
        policy.write_text(json.dumps({"cpu_count": 2, "cpu_affinity": [3]}))
        policy.chmod(0o600)
        ex.profile.update(runtime_environment={"GOMAXPROCS": "2"},
                          runtime_cpu_affinity=[3], runtime_cpu_count=2,
                          runtime_cpu_policy=str(policy),
                          runtime_cpu_policy_sha256=hashlib.sha256(policy.read_bytes()).hexdigest(),
                          containerd_unit="qualified-containerd")
        original_system = ex._system
        tampered_unit = [None]
        def system(args, **kwargs):
            if "--property=Environment" in args:
                return SimpleNamespace(returncode=0, stdout=(
                    "GOMAXPROCS=192" if args[2] == tampered_unit[0] else "GOMAXPROCS=2"))
            return original_system(args, **kwargs)
        ex._system = system
        with patch("hf2l_jobs.executor.os.sched_getaffinity", return_value={3}):
            ex.qualify_health()
            for unit in ("qualified-docker", "qualified-containerd"):
                tampered_unit[0] = unit
                with self.assertRaises(ExecutorRefused) as failure:
                    ex.qualify_health()
                self.assertEqual(failure.exception.code, "runtime_unhealthy")
            tampered_unit[0] = None
        with patch("hf2l_jobs.executor.os.sched_getaffinity", return_value={3, 4}):
            with self.assertRaises(ExecutorRefused) as failure:
                ex.qualify_health()
            self.assertEqual(failure.exception.code, "runtime_unhealthy")
        policy.write_text(json.dumps({"cpu_count": 3, "cpu_affinity": [3]}))
        with self.assertRaises(ExecutorRefused) as failure:
            ex.qualify_health()
        self.assertEqual(failure.exception.code, "runtime_unhealthy")
        policy.write_text(json.dumps({"cpu_count": 2, "cpu_affinity": [3]}))
        del ex.profile["runtime_cpu_affinity"]
        with self.assertRaises(ExecutorRefused) as failure:
            ex.qualify_health()
        self.assertEqual(failure.exception.code, "unqualified_profile")

    def test_restart_copy_closes_source_directory_descriptor_even_on_refusal(self):
        import os
        from hf2l_jobs.collection import CollectionError
        for unsafe in (False, True):
            with self.subTest(unsafe=unsafe):
                ex = self.executor()
                job = "job-unsafe" if unsafe else "job-safe"
                source = self.root / job / "restart"
                source.mkdir(parents=True)
                if unsafe: (source / "linked").symlink_to("/etc/passwd")
                else: (source / "checkpoint").write_bytes(b"opaque restart bytes")
                request = spec(job, state_path=str(source),
                               proxy_endpoint=str(self.root/"p"/identity(job).key/"s"))
                ex.reserve(request)
                # Only privileged mount commands are injected here; directory
                # descriptors and bounded copies use the real filesystem.
                ex._system = lambda argv, **kw: SimpleNamespace(
                    returncode=0, stdout="/dev/loop999" if argv[0]=="losetup" else "")
                record = ex._load(request.identity)
                if unsafe:
                    with self.assertRaises(CollectionError):
                        ex._prepare_volume(request.identity, record)
                else:
                    mount = ex._prepare_volume(request.identity, record)
                    self.assertEqual((mount/"checkpoint").read_bytes(), b"opaque restart bytes")
                pinned = []
                for entry in Path("/proc/self/fd").iterdir():
                    try:
                        if os.readlink(entry) == str(source): pinned.append(entry.name)
                    except FileNotFoundError: pass
                self.assertEqual(pinned, [], "Restart collector left an owned source FD open")

    def test_qualified_profile_and_reservation_before_resources(self):
        ex=self.executor()
        request=spec(proxy_endpoint=str(self.root/"p"/identity().key/"s"))
        reservation=ex.reserve(request)
        self.assertTrue(reservation.acknowledged)
        self.assertEqual(ex.reserve(request).state,"RESERVED")
        self.assertEqual(ex.collect(request.identity),())
        self.assertTrue(ex.release(request.identity))
        self.assertEqual(ex.stop(request.identity).state, "RELEASED")
        self.assertTrue(ex.purge(request.identity))
        with self.assertRaises(ExecutorRefused): ex.start(request.identity)
    def test_proxy_binding_checks_full_identity_before_ack(self):
        ex = self.executor()
        own = identity()
        request = spec(proxy_endpoint=str(self.root/"p"/own.key/"s"))
        self.assertTrue(ex.reserve(request).acknowledged)
        foreign = (
            identity("job-b"),
            identity(attempt="attempt-b"),
            identity(epoch=2),
            ExecutionIdentity("job-a", "attempt-a", "client-a", 1),
        )
        for other in foreign:
            with self.subTest(identity=other):
                with self.assertRaises(ExecutorRefused) as error:
                    ex.reserve(replace(request, proxy_endpoint=str(self.root/"p"/other.key/"s")))
                self.assertEqual(error.exception.code, "unsafe_proxy")
        with self.assertRaises(ExecutorRefused):
            ex.reserve(replace(request, proxy_endpoint=str(self.root/"job-a"/"proxy.sock")))

    def test_artifact_reader_requires_owned_manifest_and_valid_bytes(self):
        from hf2l_jobs.collection import RetainedFile
        ex = self.executor()
        request = spec(proxy_endpoint=str(self.root/"p"/identity().key/"s"))
        ex.reserve(request)
        root = ex._directory(request.identity)/"retained"/"state"
        root.mkdir(parents=True)
        (root/"wheel.whl").write_bytes(b"opaque wheel")
        item = RetainedFile("wheel.whl", str(root/"wheel.whl"), 12,
                            hashlib.sha256(b"opaque wheel").hexdigest())
        record = ex._load(request.identity)
        record.update(state="RELEASED", container_removed=True, artifacts_collected=True,
                      retained_artifacts=[item.as_dict()])
        ex._save(request.identity, record)
        self.assertEqual(ex.read_artifact(request.identity, "wheel.whl", 12), b"opaque wheel")
        with self.assertRaises(ExecutorRefused): ex.read_artifact(request.identity, "wheel.whl", 11)
        with self.assertRaises(ExecutorRefused): ex.read_artifact(request.identity, "../wheel.whl", 12)
        (root/"wheel.whl").write_bytes(b"changed bytes")
        with self.assertRaises(ExecutorRefused): ex.read_artifact(request.identity, "wheel.whl", 12)

    def test_dangling_private_execution_link_cannot_prove_absence(self):
        ex = self.executor()
        directory = ex._directory(identity())
        directory.symlink_to(self.root/"missing-owned-resource", target_is_directory=True)
        self.assertFalse(ex.confirm_absent(identity()))

    def test_release_deletes_scratch_before_atomic_restart_copy(self):
        from hf2l_jobs.collection import RetainedFile
        from unittest.mock import patch
        ex = self.executor()
        destination = self.root/"job-a"/"state"; destination.mkdir(parents=True)
        request = spec(proxy_endpoint=str(self.root/"p"/identity().key/"s"), state_path=str(destination))
        ex.reserve(request)
        retained = ex._directory(request.identity)/"retained"/"state"; retained.mkdir(parents=True)
        (retained/"checkpoint.bin").write_bytes(b"verified restart bytes")
        item = RetainedFile("checkpoint.bin", str(retained/"checkpoint.bin"), 22,
                            hashlib.sha256(b"verified restart bytes").hexdigest())
        image = ex._directory(request.identity)/"state.ext4"; image.write_bytes(b"bounded scratch fixture")
        record = ex._load(request.identity)
        record.update(state="STOPPED", container_removed=True, artifacts_collected=True,
                      retained_artifacts=[item.as_dict()])
        ex._save(request.identity, record)
        def system(args, **kwargs):
            if args[0]=="losetup": return SimpleNamespace(returncode=0, stdout='{"loopdevices":[]}')
            if args[0]=="findmnt": return SimpleNamespace(returncode=1, stdout="")
            raise AssertionError(args)
        ex._system=system
        original = tempfile.mkstemp
        def after_scratch_deleted(*args, **kwargs):
            self.assertFalse(image.exists())
            return original(*args, **kwargs)
        with patch("hf2l_jobs.executor.tempfile.mkstemp", side_effect=after_scratch_deleted):
            self.assertTrue(ex.release(request.identity))
        self.assertEqual((destination/"checkpoint.bin").read_bytes(), b"verified restart bytes")
        self.assertEqual((retained/"checkpoint.bin").read_bytes(), b"verified restart bytes")
        record = ex._load(request.identity)
        self.assertTrue(record["fixed_volume_deleted"])
        self.assertTrue(record["state_copied"])

    def test_missing_image_never_detaches_reused_stale_loop_name(self):
        ex = self.executor()
        request = spec(proxy_endpoint=str(self.root/"p"/identity().key/"s"))
        ex.reserve(request)
        record = ex._load(request.identity)
        record.update(loop_device="/dev/loop19", owned_loop_devices=["/dev/loop19"])
        ex._save(request.identity, record)
        calls=[]
        def system(args, **kwargs):
            calls.append(args)
            if args[0]=="findmnt": return SimpleNamespace(returncode=1, stdout="")
            if args[0]=="losetup" and "--list" in args:
                return SimpleNamespace(returncode=0, stdout='{"loopdevices":[{"name":"/dev/loop19","back-file":"/unrelated/image"}]}')
            raise AssertionError(args)
        ex._system=system
        self.assertTrue(ex.release(request.identity))
        self.assertFalse(any("--detach" in call for call in calls))
        self.assertIsNone(ex._load(request.identity)["loop_device"])

    def test_no_profile_or_unqualified_runtime_never_falls_back(self):
        with self.assertRaises(ExecutorRefused): LinuxExecutor(self.root/"missing",self.root,self.runner)
        self.data["qualified"]=False; self.profile.write_text(json.dumps(self.data))
        with self.assertRaises(ExecutorRefused): self.executor()
    def test_unqualified_or_unknown_physical_backing_refused(self):
        ex = self.executor()
        self.assertEqual(ex._backing_device(self.root), self.data["backing_devices"][0])
        with self.assertRaises(ExecutorRefused): ex._backing_device("/dev/shm")
        ex.profile["backing_io_qualified"] = False
        with self.assertRaises(ExecutorRefused): ex.qualify_health()
        ex.profile["backing_io_qualified"] = True
        ex.profile["backing_devices"][0]["minor"] += 1
        with self.assertRaises(ExecutorRefused): ex.qualify_health()

    def test_changed_binary_or_host_network_refused(self):
        ex=self.executor()
        self.bin.write_bytes(b"changed")
        with self.assertRaises(ExecutorRefused): ex.qualify_health()
        self.bin.write_bytes(b"qualified runtime")
        self.config.write_text(json.dumps({"runtimes":{"runsc":{"path":str(self.bin),"runtimeArgs":["--network=host","--host-uds=open"]}}}))
        with self.assertRaises(ExecutorRefused): ex.qualify_health()
    def test_approved_dataset_is_regular_and_bound_to_job_participant(self):
        from dataclasses import replace
        data=self.root/"data.npz";data.write_bytes(b"opaque local data")
        ex=self.executor()
        ex.dataset_bindings={"local-a":{"path":str(data),"participant_id":"alice","job_ids":["job-a"]}}
        request=spec(role="client",dataset_binding_id="local-a",participant_id="alice")
        self.assertEqual(ex._dataset_path(request),data)
        with self.assertRaises(ExecutorRefused): ex._dataset_path(replace(request,participant_id="bob"))
        with self.assertRaises(ExecutorRefused): ex._dataset_path(replace(request,identity=identity("job-b")))
        link=self.root/"alias.npz";link.symlink_to(data)
        ex.dataset_bindings["local-a"]["path"]=str(link)
        with self.assertRaises(ExecutorRefused): ex._dataset_path(request)
        link.unlink();link.hardlink_to(data)
        ex.dataset_bindings["local-a"]["path"]=str(data)
        with self.assertRaises(ExecutorRefused): ex._dataset_path(request)
    def test_synthetic_dataset_requires_explicit_trusted_approval(self):
        ex=self.executor()
        request=spec(role="client",dataset_binding_id="synthetic-a",participant_id="alice",
                     proxy_endpoint=str(self.root/"p"/identity().key/"s"))
        ex.dataset_authorizer=lambda *args: {"kind":"synthetic"}
        self.assertIsNone(ex._dataset_path(request))
        self.assertTrue(ex.reserve(request).acknowledged)
        ex.dataset_authorizer=lambda *args: None
        with self.assertRaises(ExecutorRefused): ex._dataset_path(request)
    def test_build_has_neither_proxy_nor_secret_or_dataset(self):
        request=spec(role="build",proxy_endpoint=None)
        self.assertIsNone(request.proxy_endpoint)
        with self.assertRaises(ExecutorRefused): spec(role="build")
        with self.assertRaises(ExecutorRefused): spec(role="build",proxy_endpoint=None,secret_path="/private/job-a/secret")
        with self.assertRaises(ExecutorRefused): spec(role="owner",dataset_binding_id="local-a",participant_id="alice")
    def test_live_logs_are_redacted_stable_cursors_and_purged(self):
        ex = self.executor()
        request = spec(proxy_endpoint=str(self.root/"p"/identity().key/"s"))
        ex.reserve(request)
        record = ex._load(request.identity); record["state"] = "RUNNING"; ex._save(request.identity, record)
        snapshot = ["2026-10-09T00:00:00.000000001Z secret=topsecret\n"]
        complete = [False]
        ex._verify_container = lambda record: None
        ex._secret_values = lambda spec: ("topsecret",)
        ex.inspect = lambda identity: RuntimeObservation(identity, "STOPPED" if complete[0] else "RUNNING", complete[0])
        def docker(args, **kwargs):
            self.assertEqual(args[:3], ["logs", "--timestamps", "--tail"])
            return SimpleNamespace(returncode=0, stdout=snapshot[0], stderr="")
        ex._docker = docker
        first = ex.read_logs(request.identity)
        self.assertNotIn("topsecret", first["content"])
        self.assertIn("[REDACTED]", first["content"])
        self.assertFalse(first["complete"])
        repeat = ex.read_logs(request.identity, offset=first["next_offset"])
        self.assertEqual(repeat["content"], "")
        snapshot[0] += "2026-10-09T00:00:00.000000002Z trained\n"
        second = ex.read_logs(request.identity, offset=first["next_offset"])
        self.assertIn("trained", second["content"])
        self.assertNotIn("secret=", second["content"])
        complete[0] = True
        terminal = ex.read_logs(request.identity, offset=second["next_offset"])
        self.assertTrue(terminal["complete"])
        record = ex._load(request.identity)
        record.update(state="RELEASED", container_removed=True, artifacts_collected=True, retained_artifacts=[])
        ex._save(request.identity, record)
        self.assertTrue(ex.read_logs(request.identity, offset=second["next_offset"])["complete"])
        self.assertTrue(ex.purge(request.identity))
        self.assertFalse((ex._directory(request.identity)/"canonical-logs").exists())

    def test_runtime_progress_is_bounded_and_identity_bound(self):
        ex=self.executor();request=spec(proxy_endpoint=str(self.root/"p"/identity().key/"s"));ex.reserve(request)
        record=ex._load(request.identity);record["mounted"]=True
        state=ex._directory(request.identity)/"state";state.mkdir()
        status=state/"runtime-status.json"
        data={"schema_version":1,"job_id":"job-a","attempt_id":"attempt-a","component_id":"owner","epoch":1,
              "current_round":2,"target_round":3,"phase":"waiting_participants","readiness":"ready","metrics":{"loss":0.5}}
        status.write_text(json.dumps(data))
        self.assertEqual(ex._runtime_progress(record)["current_round"],2)
        self.assertEqual(ex._runtime_progress(record)["metrics"],{"loss":0.5})
        data["job_id"]="job-b";status.write_text(json.dumps(data))
        self.assertEqual(ex._runtime_progress(record),{})
        status.write_text("x"*65537)
        self.assertEqual(ex._runtime_progress(record),{})
    def test_mount_escape_symlink_and_flag_injection_refused(self):
        ex=self.executor()
        with self.assertRaises(ExecutorRefused): ex._trusted_path("/etc",kind="directory")
        with self.assertRaises(ExecutorRefused): ex._trusted_path(str(self.root/"jobs"/"job-a"/".." / ".."/"other"),kind="directory")
        with self.assertRaises(ExecutorRefused): ex._trusted_path("relative/path",kind="directory")
        target=self.root/"safe";target.mkdir()
        (self.root/"link").symlink_to(target,target_is_directory=True)
        with self.assertRaises(ExecutorRefused): ex._trusted_path(str(self.root/"link"),kind="directory")
        with self.assertRaises(ExecutorRefused): ex._trusted_path(str(self.root/"safe,readonly=false"),kind="directory")
    def test_file_locks_fence_duplicate_agents_without_blocking_other_jobs(self):
        import threading
        first=self.executor();second=self.executor()
        acquired=threading.Event();released=threading.Event()
        def contender():
            with second._operation_lock(identity()):
                acquired.set()
            released.set()
        with first._operation_lock(identity()):
            with first._operation_lock(identity()):
                thread=threading.Thread(target=contender)
                thread.start()
                self.assertFalse(acquired.wait(.1))
                with second._operation_lock(identity("job-b")):
                    pass
        self.assertTrue(released.wait(1));thread.join(1)
    def test_no_root_sandbox_user(self):
        self.data["sandbox_uid"]=0;self.profile.write_text(json.dumps(self.data))
        with self.assertRaises(ExecutorRefused): self.executor()

if __name__ == "__main__": unittest.main()

class NodeAPITests(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        from hf2l_jobs.node_agent import create_node_app
        self.tmp = tempfile.TemporaryDirectory()
        self.fake = FakeExecutor()
        self.agent = NodeAgent(self.fake,Path(self.tmp.name)/"node.sqlite","node-a","pool-a",
             ResourceLimits(1000,128*1024*1024,264*1024*1024),boot_id="boot-a")
        self.principal = SimpleNamespace(node_id="node-a",pool_id="pool-a",job_id="job-a",
            attempt_id="attempt-a",component_id="owner",epoch=1,
            resources={"cpu_millicores":500,"memory_bytes":64*1024*1024,"disk_bytes":64*1024*1024})
        def authenticate(request,scope):
            data=dict(vars(self.principal))
            data["job_id"]=request.headers.get("x-test-job",self.principal.job_id)
            return SimpleNamespace(**data)
        self.client=TestClient(create_node_app(self.agent,authenticate))
    def tearDown(self):
        self.client.close();self.agent.close();self.tmp.cleanup()
    def test_bound_node_can_reserve_and_start_only_own_execution(self):
        from dataclasses import asdict
        a=spec()
        reply=self.client.post("/internal/nodes/v1/reserve",json={"spec":asdict(a)})
        self.assertEqual(reply.status_code,200,reply.text)
        reply=self.client.post("/internal/nodes/v1/start",json={"identity":asdict(a.identity)})
        self.assertEqual(reply.status_code,200,reply.text)
        self.assertEqual(reply.json()["state"],"RUNNING")
        reply=self.client.post("/internal/nodes/v1/inspect",json={"identity":asdict(identity("job-b"))})
        self.assertEqual(reply.status_code,403)
    def test_slow_http_start_does_not_block_other_jobs_http_renew(self):
        from dataclasses import asdict
        import threading
        a,b=spec(),spec("job-b")
        self.agent.reserve(a);self.agent.reserve(b)
        entered=threading.Event();finish=threading.Event();replied=threading.Event()
        original=self.fake.start
        def slow(identity):
            entered.set()
            finish.wait(2)
            return original(identity)
        self.fake.start=slow
        starter=threading.Thread(target=lambda:self.client.post("/internal/nodes/v1/start",json={"identity":asdict(a.identity)}))
        starter.start();self.assertTrue(entered.wait(1))
        results=[]
        def renew():
            results.append(self.client.post("/internal/nodes/v1/renew",headers={"x-test-job":"job-b"},
                 json={"identity":asdict(b.identity),"lease_seconds":120}))
            replied.set()
        renewer=threading.Thread(target=renew);renewer.start()
        try:
            self.assertTrue(replied.wait(.5),"Other job HTTP renew blocked behind start")
            self.assertEqual(results[0].status_code,200,results[0].text)
        finally:
            finish.set();starter.join(2);renewer.join(2)
    def test_node_resources_cannot_exceed_grant_and_no_insecure_app(self):
        from dataclasses import asdict
        from hf2l_jobs.node_agent import create_node_app
        self.principal.resources["cpu_millicores"]=100
        reply=self.client.post("/internal/nodes/v1/reserve",json={"spec":asdict(spec())})
        self.assertEqual(reply.status_code,403)
        with self.assertRaises(ExecutorRefused): create_node_app(self.agent,None)
