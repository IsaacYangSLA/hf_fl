"""Resource and lifecycle regression tests use clocks and independent adapters."""
from __future__ import annotations

import unittest
import tempfile
from urllib.parse import quote
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sqlalchemy import select

from hf2l_jobs.database import create_database
from hf2l_jobs.domain import Error, JobSpec
from hf2l_jobs import models
from hf2l_jobs.scheduler import Scheduler, validate_admission
from hf2l_jobs.controller import Controller
from hf2l_jobs.executor import (ExecutionIdentity, ExecutionSpec, ResourceLimits,
    Reservation, RuntimeObservation, ExecutorRefused, UncertainExecution)
from hf2l_jobs.reconciliation import PublicationObservation, remaining_rounds, retry_delay


class Clock:
    def __init__(self):
        self.value = datetime(2026, 10, 9, tzinfo=timezone.utc)
    def __call__(self):
        return self.value
    def advance(self, seconds):
        self.value += timedelta(seconds=seconds)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hf2l-controller-test-")
        self.db = create_database("sqlite:///" + self.temporary.name + "/manager.sqlite")
        self.clock = Clock()
        with self.db.transaction() as session:
            session.add(models.Project(id="project", name="Project", retention_days=90))
            session.flush()
            session.add(models.Pool(id="server", name="Server", node_id="node",
                cpu_millicores=4000, memory_bytes=4000, disk_bytes=64 * 1024 * 1024,
                gpu_uuids=[], gpu_profiles=[], sandbox_profiles=["runsc-cpu-v1"],
                healthy=True, quarantined=False))
        self.scheduler = Scheduler(self.db, clock=self.clock)
    def tearDown(self):
        self.db.close()
        self.temporary.cleanup()
    def job(self, name, *, cpu=1000, pool="server", created_offset=0, target=3, duration=3600,
            participants=(), components=None, gpu_count=0, gpu_profile=None):
        resource = {"pool_id": pool, "cpu_millicores": cpu, "memory_bytes": cpu,
                    "disk_bytes": 1000, "gpu_count": gpu_count, "gpu_profile": gpu_profile}
        spec = JobSpec.model_validate({"project_id": "project", "name": name, "source_id": "source",
            "source_commit": "a" * 40, "runtime_image": "sha256:" + "b" * 64, "plugin": "plugin",
            "target_round": target, "max_duration_seconds": duration, "participants": list(participants),
            "components": components or [{"component_id": "owner", "role": "owner", "resources": resource}]})
        with self.db.transaction() as session:
            job = models.Job(id=name, project_id="project", creator_id="creator", name=name,
                spec_json=spec.to_dict(), spec_hash=spec.digest, state="QUEUED", current_attempt=1,
                attempt_count=1, epoch=0, target_round=target,
                created_at=self.clock() + timedelta(seconds=created_offset), updated_at=self.clock())
            session.add(job)
            session.flush()
            session.add(models.Attempt(id=name + "-a1", job_id=name, number=1, epoch=1, state="QUEUED"))
        return name
    def read(self, job_id):
        with self.db.transaction() as session:
            job = session.get(models.Job, job_id)
            session.expunge(job)
            return job
    def pool(self, name, cpu=4000, gpus=()):
        with self.db.transaction() as session:
            session.add(models.Pool(id=name, name=name, node_id=name + "-node",
                cpu_millicores=cpu, memory_bytes=cpu, disk_bytes=64 * 1024 * 1024,
                gpu_uuids=list(gpus), gpu_profiles=["gpu"], sandbox_profiles=["runsc-cpu-v1"],
                healthy=True, quarantined=False))


class SchedulerTests(Fixture):
    def test_two_jobs_run_third_queues(self):
        for index in range(3):
            self.job("job" + str(index), cpu=2000, created_offset=index)
        admitted = self.scheduler.schedule()
        self.assertEqual([a.job_id for a in admitted], ["job0", "job1"])
        self.assertEqual(self.read("job2").queue_reason["code"], "capacity")
        with self.db.transaction() as session:
            rows = list(session.scalars(select(models.Allocation)))
            self.assertEqual(sum(a.cpu_millicores for a in rows), 4000)

    def test_repeated_admission_is_idempotent(self):
        self.job("job")
        self.assertEqual(len(self.scheduler.schedule()), 1)
        self.assertEqual(self.scheduler.schedule(), [])
        with self.db.transaction() as session:
            self.assertEqual(len(list(session.scalars(select(models.Allocation)))), 1)
            self.assertEqual(len(list(session.scalars(select(models.Outbox)))), 1)

    def source_planner(self, job):
        return [{"kind": "source", "external_id": "/owned/" + job.id + "/source",
                 "component_id": "owner", "pool_id": "server", "max_bytes": 1500,
                 "details": {"source_id": "source", "commit": "a" * 40}}]

    def test_source_copy_cap_is_reserved_with_gang_before_provisioning(self):
        from hf2l_jobs.retention import RetentionService
        self.job("first")
        self.job("second", created_offset=1)
        with self.db.transaction() as session:
            session.get(models.Pool, "server").disk_bytes = 4000
        scheduler = Scheduler(self.db, clock=self.clock, admission_storage=self.source_planner)
        self.assertEqual([a.job_id for a in scheduler.schedule()], ["first"])
        with self.db.transaction() as session:
            resource = session.scalar(select(models.ProvisioningResource))
            self.assertEqual(resource.kind, "source")
            self.assertEqual(resource.size_bytes, 1500)
            self.assertFalse(resource.details_json["retention_charge_settled"])
            self.assertEqual(resource.ownership_json, {"job_id": "first", "component_id": "owner", "kind": "source"})
            self.assertEqual(session.get(models.Project, "project").retained_bytes, 1500)
            resource_id = resource.id
        restarted = Scheduler(self.db, clock=self.clock, admission_storage=self.source_planner)
        self.assertEqual(restarted.schedule(), [])
        self.assertEqual(self.read("second").queue_reason["code"], "capacity")
        RetentionService(self.db).settle_resource(resource_id, "first", 500)
        self.assertEqual([a.job_id for a in restarted.schedule()], ["second"])

    def test_source_copy_cap_queues_before_compute_or_storage_side_effects(self):
        self.job("job")
        with self.db.transaction() as session:
            session.get(models.Project, "project").quota_disk_bytes = 2000
        scheduler = Scheduler(self.db, clock=self.clock, admission_storage=self.source_planner)
        self.assertEqual(scheduler.schedule(), [])
        self.assertEqual(self.read("job").queue_reason["code"], "quota")
        with self.db.transaction() as session:
            self.assertEqual(list(session.scalars(select(models.Allocation))), [])
            self.assertEqual(list(session.scalars(select(models.ProvisioningResource))), [])
            self.assertEqual(session.get(models.Project, "project").retained_bytes, 0)

    def test_storage_only_pool_is_reserved_without_compute_assignment(self):
        self.pool("manager-storage")
        self.job("job")
        def planner(job):
            return [{"kind": "source_workspace", "external_id": "/manager/" + job.id + "/source",
                     "component_id": "owner", "pool_id": "manager-storage", "max_bytes": 1500}]
        scheduler = Scheduler(self.db, clock=self.clock, admission_storage=planner)
        self.assertEqual([a.job_id for a in scheduler.schedule()], ["job"])
        with self.db.transaction() as session:
            allocations = list(session.scalars(select(models.Allocation)))
            self.assertEqual([a.pool_id for a in allocations], ["server"])
            resource = session.scalar(select(models.ProvisioningResource))
            self.assertEqual(resource.details_json["pool_id"], "manager-storage")
            self.assertEqual(resource.size_bytes, 1500)

    def test_external_participant_receives_only_immutable_prepaid_log_cap(self):
        from hf2l_jobs.resources import stable_key
        cid = "participant-" + stable_key("alice")[:40]
        self.job("job", participants=[{"participant_id": "alice", "mode": "external", "dataset_binding": "data"}])
        def planner(job):
            return [{"kind": "log_budget", "external_id": "hf2l-log://" + job.id + "/1/" + cid,
                "component_id": cid, "pool_id": "server", "max_bytes": 1024 * 1024,
                "details": {"attempt_number": 1, "component_id": cid}}]
        scheduler = Scheduler(self.db, clock=self.clock, admission_storage=planner)
        self.assertEqual([a.job_id for a in scheduler.schedule()], ["job"])
        with self.db.transaction() as session:
            resource = session.scalar(select(models.ProvisioningResource))
            self.assertEqual((resource.kind, resource.component_id, resource.attempt_id, resource.size_bytes),
                ("log_budget", cid, "job-a1", 1024 * 1024))
            allocations = list(session.scalars(select(models.Allocation)))
            self.assertEqual([a.component_id for a in allocations], ["owner"])
            self.assertNotIn("log_resource_id", allocations[0].details_json)

    def test_existing_external_log_budget_is_adopted_without_second_charge(self):
        from hf2l_jobs.resources import stable_key
        from hf2l_jobs.retention import RetentionService
        cid = "participant-" + stable_key("alice")[:40]
        self.job("job", participants=[{"participant_id": "alice", "mode": "external", "dataset_binding": "data"}])
        external = "hf2l-log://job/1/" + cid
        with self.db.transaction() as session:
            resource = models.ProvisioningResource(id="prepaid-external-log", job_id="job", component_id=cid,
                kind="log_budget", external_id=external,
                ownership_json={"job_id": "job", "component_id": cid, "kind": "log_budget"},
                details_json={"pool_id": "server", "component_id": cid, "attempt_number": 1}, state="planned")
            session.add(resource)
            session.flush()
            RetentionService.reserve_in_transaction(session, resource, session.get(models.Project, "project"),
                1024 * 1024, session.get(models.Pool, "server"))
        planner = lambda job: [{"kind": "log_budget", "external_id": external,
            "component_id": cid, "pool_id": "server", "max_bytes": 1024 * 1024}]
        self.assertEqual(len(Scheduler(self.db, clock=self.clock, admission_storage=planner).schedule()), 1)
        with self.db.transaction() as session:
            resource = session.get(models.ProvisioningResource, "prepaid-external-log")
            self.assertEqual(resource.attempt_id, "job-a1")
            self.assertEqual(session.get(models.Project, "project").retained_bytes, 1024 * 1024)
            self.assertEqual(len(list(session.scalars(select(models.ProvisioningResource)))), 1)

    def test_external_log_planning_rejects_foreign_identity_and_excess_cap(self):
        from hf2l_jobs.resources import stable_key
        cid = "participant-" + stable_key("alice")[:40]
        self.job("job", participants=[{"participant_id": "alice", "mode": "external", "dataset_binding": "data"}])
        for kind, component, cap in (("collection_budget", cid, 1024 * 1024),
                ("log_budget", "participant-" + stable_key("foreign")[:40], 1024 * 1024),
                ("log_budget", cid, 1024 * 1024 + 1)):
            with self.subTest(kind=kind, component=component, cap=cap):
                planner = lambda job: [{"kind": kind, "external_id": "owned", "component_id": component,
                    "pool_id": "server", "max_bytes": cap}]
                with self.assertRaises(ValueError):
                    Scheduler(self.db, clock=self.clock, admission_storage=planner).schedule()
        with self.db.transaction() as session:
            self.assertEqual(list(session.scalars(select(models.Allocation))), [])
            self.assertEqual(list(session.scalars(select(models.ProvisioningResource))), [])
            self.assertEqual(session.get(models.Project, "project").retained_bytes, 0)

    def test_lifetime_blob_retry_preserves_exact_capacity_pool_and_single_charge(self):
        from hf2l_jobs.blob_budget import plan_blob_budget
        self.pool("objects")
        self.pool("replacement")
        self.job("job")
        desired_pool = ["objects"]
        def planner(job):
            with self.db.transaction(immediate=False) as session:
                rows = list(session.scalars(select(models.ProvisioningResource).where(
                    models.ProvisioningResource.job_id == job.id,
                    models.ProvisioningResource.kind == "exchange_blob_budget")))
                session.expunge_all()
            return [plan_blob_budget(job, desired_pool[0], rows)]
        with self.db.transaction() as session:
            session.get(models.Pool, "objects").disk_bytes = 4000
            session.get(models.Pool, "replacement").disk_bytes = 0
            session.get(models.Project, "project").quotas_json = {"disk_bytes": 5000, "retained_bytes": 4000}
        scheduler = Scheduler(self.db, clock=self.clock, admission_storage=planner)
        self.assertEqual(len(scheduler.schedule()), 1)
        with self.db.transaction() as session:
            resource = session.scalar(select(models.ProvisioningResource))
            first = (resource.id, resource.attempt_id, resource.size_bytes)
            self.assertEqual(resource.details_json["attempt_number"], 1)
            allocation = session.scalar(select(models.Allocation))
            allocation.state = "RELEASED"
            allocation.released_at = self.clock()
            allocation.termination_confirmed = True
            job = session.get(models.Job, "job")
            job.state, job.current_attempt, job.attempt_count = "QUEUED", 2, 2
            session.get(models.Attempt, "job-a1").state = "FAILED"
            session.add(models.Attempt(id="job-a2", job_id="job", number=2, epoch=2, state="QUEUED"))
        desired_pool[0] = "replacement"
        self.assertEqual([a.attempt_id for a in scheduler.schedule()], ["job-a2"])
        with self.db.transaction() as session:
            rows = list(session.scalars(select(models.ProvisioningResource)))
            self.assertEqual([(r.id, r.attempt_id, r.size_bytes) for r in rows], [first])
            self.assertEqual(rows[0].details_json["pool_id"], "objects")
            self.assertEqual(session.get(models.Project, "project").retained_bytes, 4000)
            from hf2l_jobs.retention import RetentionService
            self.assertEqual(RetentionService.pool_used_bytes(session, "objects"), 4000)
            self.assertEqual(RetentionService.pool_used_bytes(session, "replacement"), 0)

    def test_attempt_log_budget_cannot_be_adopted_by_successor(self):
        from hf2l_jobs.retention import RetentionService
        self.job("job")
        with self.db.transaction() as session:
            resource = models.ProvisioningResource(id="old-log-budget", job_id="job", attempt_id="job-a1",
                component_id="owner", kind="log_budget", external_id="hf2l-log://job/1/owner",
                ownership_json={"job_id": "job", "component_id": "owner", "kind": "log_budget"},
                details_json={"pool_id": "server", "component_id": "owner", "attempt_number": 1}, state="planned")
            session.add(resource)
            session.flush()
            RetentionService.reserve_in_transaction(session, resource, session.get(models.Project, "project"),
                1024 * 1024, session.get(models.Pool, "server"))
            job = session.get(models.Job, "job")
            job.current_attempt, job.attempt_count = 2, 2
            session.add(models.Attempt(id="job-a2", job_id="job", number=2, epoch=2, state="QUEUED"))
        planner = lambda job: [{"kind": "log_budget", "external_id": "hf2l-log://job/1/owner",
            "component_id": "owner", "pool_id": "server", "max_bytes": 1024 * 1024}]
        with self.assertRaises(ValueError):
            Scheduler(self.db, clock=self.clock, admission_storage=planner).schedule()
        with self.db.transaction() as session:
            self.assertEqual(list(session.scalars(select(models.Allocation))), [])
            self.assertEqual(session.get(models.Project, "project").retained_bytes, 1024 * 1024)

    def test_postgres_numeric_sum_becomes_integer_queue_shortage(self):
        import json
        from decimal import Decimal
        from unittest.mock import patch
        from hf2l_jobs.retention import RetentionService
        self.job("first")
        self.scheduler.schedule()
        self.job("second")
        with self.db.transaction() as session:
            session.get(models.Pool, "server").disk_bytes = 1500
        pool_used = RetentionService.pool_used_bytes
        def postgres_sum(session, pool_id, exclude_resource_id=None):
            return Decimal(pool_used(session, pool_id, exclude_resource_id))
        with patch.object(RetentionService, "pool_used_bytes", postgres_sum):
            self.assertEqual(self.scheduler.schedule(), [])
        reason = self.read("second").queue_reason
        self.assertEqual(reason["shortages"]["server"]["disk_bytes"], 500)
        self.assertIs(type(reason["shortages"]["server"]["disk_bytes"]), int)
        self.assertEqual(json.loads(json.dumps(reason)), reason)

    def test_gang_not_partially_allocated(self):
        self.pool("participant", cpu=1000)
        components = [
            {"component_id": "owner", "role": "owner", "resources": {
             "pool_id": "server", "cpu_millicores": 1000, "memory_bytes": 1000, "disk_bytes": 1000}},
            {"component_id": "client", "role": "participant", "participant_id": "alice", "resources": {
             "pool_id": "participant", "cpu_millicores": 1000, "memory_bytes": 1000, "disk_bytes": 1000}}]
        self.job("busy", cpu=1000, pool="participant", created_offset=-1)
        self.job("gang", components=components, participants=[
            {"participant_id": "alice", "dataset_binding": "data", "mode": "managed", "component_id": "client"}])
        self.scheduler.schedule()
        with self.db.transaction() as session:
            self.assertEqual(list(session.scalars(select(models.Allocation).where(models.Allocation.job_id == "gang"))), [])

    def test_static_impossibility_rejected(self):
        self.job("impossible", cpu=5000)
        with self.db.transaction() as session:
            spec = JobSpec.model_validate(session.get(models.Job, "impossible").spec_json)
            with self.assertRaises(Error) as error:
                validate_admission(session, spec)
            self.assertEqual(error.exception.code, "resource_request_exceeds_pool")

    def test_unsupported_profile_rejected(self):
        self.job("unsupported")
        with self.db.transaction() as session:
            session.get(models.Pool, "server").sandbox_profiles = []
        with self.db.transaction() as session:
            with self.assertRaises(Error):
                validate_admission(session, JobSpec.model_validate(session.get(models.Job, "unsupported").spec_json))

    def test_quota_blocked_job_does_not_block_unrelated_project(self):
        self.job("job", cpu=1000)
        with self.db.transaction() as session:
            session.get(models.Project, "project").quota_cpu_millicores = 500
        self.assertEqual(self.scheduler.schedule(), [])
        self.assertEqual(self.read("job").queue_reason["code"], "quota")

    def test_quarantine_never_frees_capacity(self):
        self.job("busy", cpu=4000, created_offset=-1)
        self.job("waiting", cpu=1000)
        self.scheduler.schedule()
        with self.db.transaction() as session:
            for row in session.scalars(select(models.Allocation)):
                row.state = "QUARANTINED"
        self.clock.advance(86400)
        self.assertEqual(self.scheduler.schedule(), [])
        self.assertEqual(self.read("waiting").queue_reason["code"], "capacity")

    def test_deadline_set_once_at_first_reservation(self):
        self.job("job", duration=3600)
        self.assertIsNone(self.read("job").deadline_at)
        self.scheduler.schedule()
        deadline = self.read("job").deadline_at
        self.clock.advance(60)
        self.scheduler.schedule()
        self.assertEqual(self.read("job").deadline_at, deadline)

    def test_three_backfill_counter_persists_and_protects(self):
        self.job("busy", cpu=3000, created_offset=-10)
        self.scheduler.schedule()
        self.job("oldest", cpu=2000)
        for index in range(4):
            self.job("younger" + str(index), cpu=1000, created_offset=index + 1)
            admissions = self.scheduler.schedule()
            if index < 3:
                self.assertEqual([a.job_id for a in admissions], ["younger" + str(index)])
                with self.db.transaction() as session:
                    job = session.get(models.Job, "younger" + str(index))
                    job.state = "SUCCEEDED"
                    for a in session.scalars(select(models.Allocation).where(models.Allocation.job_id == job.id)):
                        a.state = "RELEASED"; a.released_at = self.clock()
            else:
                self.assertEqual(admissions, [])
            self.assertEqual(self.read("oldest").backfill_count, min(index + 1, 3))
        self.assertEqual(self.read("younger3").queue_reason.get("protection"), "older_request")

    def test_unrelated_pool_does_not_consume_backfill_budget(self):
        self.pool("other")
        self.job("busy", cpu=4000, created_offset=-10)
        self.scheduler.schedule()
        self.job("older", cpu=1000)
        self.job("elsewhere", pool="other", created_offset=1)
        self.assertEqual([a.job_id for a in self.scheduler.schedule()], ["elsewhere"])
        self.assertEqual(self.read("older").backfill_count, 0)

    def test_whole_gpu_uuid_is_exclusive(self):
        with self.db.transaction() as session:
            pool = session.get(models.Pool, "server")
            pool.gpu_uuids = ["GPU-one"]; pool.gpu_profiles = ["gpu"]
        self.job("first", gpu_count=1, gpu_profile="gpu", created_offset=-1)
        self.job("second", gpu_count=1, gpu_profile="gpu")
        self.assertEqual([a.job_id for a in self.scheduler.schedule()], ["first"])
        with self.db.transaction() as session:
            self.assertEqual([g.gpu_uuid for g in session.scalars(select(models.GpuAllocation))], ["GPU-one"])


    def test_global_gpu_uuid_cannot_be_allocated_through_other_pool(self):
        with self.db.transaction() as session:
            server = session.get(models.Pool, "server")
            server.gpu_uuids = ["GPU-shared"]; server.gpu_profiles = ["gpu"]
        self.pool("other", gpus=("GPU-shared",))
        self.job("first", gpu_count=1, gpu_profile="gpu", created_offset=-1)
        self.job("second", pool="other", gpu_count=1, gpu_profile="gpu")
        self.assertEqual([a.job_id for a in self.scheduler.schedule()], ["first"])
        self.assertEqual(self.read("second").queue_reason["code"], "capacity")

    def test_global_gpu_matching_finds_feasible_gang(self):
        with self.db.transaction() as session:
            server = session.get(models.Pool, "server")
            server.gpu_uuids = ["GPU-shared", "GPU-exclusive"]; server.gpu_profiles = ["gpu"]
        self.pool("other", gpus=("GPU-shared",))
        components = [{"component_id": "owner", "role": "owner", "resources": {
            "pool_id": "server", "cpu_millicores": 1000, "memory_bytes": 1000, "disk_bytes": 1000,
            "gpu_count": 1, "gpu_profile": "gpu"}},
            {"component_id": "client", "role": "participant", "participant_id": "alice", "resources": {
            "pool_id": "other", "cpu_millicores": 1000, "memory_bytes": 1000, "disk_bytes": 1000,
            "gpu_count": 1, "gpu_profile": "gpu"}}]
        self.job("gang", components=components, participants=[{"participant_id": "alice", "dataset_binding": "data",
                  "mode": "managed", "component_id": "client"}])
        self.assertEqual([a.job_id for a in self.scheduler.schedule()], ["gang"])
        with self.db.transaction() as session:
            self.assertEqual({g.gpu_uuid for g in session.scalars(select(models.GpuAllocation))},
                             {"GPU-shared", "GPU-exclusive"})

class FakeExecutor:
    def __init__(self):
        self.states = {}
        self.specs = {}
        self.started = []
        self.calls = []
        self.refuse_component = None
        self.stop_unknown = False
        self.collected = ()
    def reserve(self, spec):
        self.calls.append(("reserve", spec.identity.component_id))
        if spec.identity.component_id == self.refuse_component:
            raise ExecutorRefused("Local refusal", "capacity")
        self.specs[spec.identity.key] = spec
        self.states.setdefault(spec.identity.key, "RESERVED")
        return Reservation(spec.identity, True, spec.node_id)
    def start(self, identity):
        self.calls.append(("start", identity.component_id))
        self.started.append(identity)
        self.states[identity.key] = "RUNNING"
        return self.inspect(identity)
    def inspect(self, identity):
        state = self.states.get(identity.key, "STOPPED")
        return RuntimeObservation(identity, state, termination_confirmed=state in {"STOPPED", "RELEASED"},
                                  publication_status="none")
    def stop(self, identity, grace_seconds=60):
        self.calls.append(("stop", identity.component_id))
        if self.stop_unknown:
            raise UncertainExecution("Partition")
        self.states[identity.key] = "STOPPED"
        return self.inspect(identity)
    def collect(self, identity):
        return self.collected
    def release(self, identity):
        self.calls.append(("release", identity.component_id))
        if not self.inspect(identity).termination_confirmed:
            return False
        self.states[identity.key] = "RELEASED"
        return True
    def renew(self, identity):
        return True
    def purge(self, identity):
        return True


class FakeProvisioner:
    def __init__(self):
        self.rounds = {}
        self.calls = []
        self.revoke_confirmed = True
        self.publication_known = True
    def current_round(self, job):
        return self.rounds.get(job.id, 0)
    def plan(self, job, attempt, remaining_rounds=None):
        self.calls.append(("plan", job.id))
        specs = {}
        for component in job.spec_json["components"]:
            r = component["resources"]
            identity = ExecutionIdentity(job.id, attempt.id, component["component_id"], job.epoch)
            specs[component["component_id"]] = ExecutionSpec(identity=identity,
                image_digest="sha256:" + "b" * 64, source_path="/owned/" + job.id + "/source",
                state_path="/owned/" + job.id + "/state", argv=("python", "-m", "hf2l_jobs.runtime",
                "--config", "/run/hf2l/runtime.json"), proxy_endpoint=None if component["role"] == "build" else "/owned/" + job.id + "/proxy.sock",
                role="build" if component["role"] == "build" else "client" if component["role"] == "participant" else "owner",
                resources=ResourceLimits(r["cpu_millicores"], r["memory_bytes"], r["disk_bytes"]),
                pool_id=r["pool_id"], node_id="node", deadline=job.deadline_at.timestamp())
        return SimpleNamespace(component_specs=specs)
    def ensure(self, job, attempt, remaining_rounds=None):
        self.calls.append(("ensure", job.id))
        return self.plan(job, attempt, remaining_rounds)
    def revoke(self, job, attempt):
        self.calls.append(("revoke", job.id))
        return self.revoke_confirmed
    def reconcile(self, job, attempt):
        self.calls.append(("reconcile", job.id))
        return PublicationObservation(self.publication_known,
             "confirmed" if self.publication_known else "unknown", self.current_round(job))
    def cleanup(self, job, attempt):
        self.calls.append(("cleanup", job.id))
        return True
    def purge_job(self, job):
        return True
    def expire_artifacts(self, job):
        return True


class ControllerTests(Fixture):
    prepaid_attempt_bytes = 2 * 1000 + 5 * 1024 * 1024

    def setUp(self):
        super().setUp()
        self.executor = FakeExecutor()
        self.provisioner = FakeProvisioner()
        self.controller = Controller(self.db, self.executor, self.provisioner, clock=self.clock)
    def cancel(self, job_id):
        with self.db.transaction() as session:
            job = session.get(models.Job, job_id)
            job.state = "CANCELLING"; job.phase = "fencing"; job.version += 1
            Scheduler._outbox(session, job, "fence_stop", {})
    def test_actual_dispatch_invokes_adapters(self):
        self.job("job")
        self.controller.run_once()
        self.assertEqual(self.read("job").state, "RUNNING")
        self.assertEqual([kind for kind, _ in self.executor.calls], ["reserve", "start"])

    def test_all_gang_acks_precede_any_start(self):
        components = [{"component_id": "owner", "role": "owner", "resources": {
            "pool_id": "server", "cpu_millicores": 1000, "memory_bytes": 1000, "disk_bytes": 1000}},
            {"component_id": "client", "role": "participant", "participant_id": "alice", "resources": {
            "pool_id": "server", "cpu_millicores": 1000, "memory_bytes": 1000, "disk_bytes": 1000}}]
        self.job("gang", components=components, participants=[{"participant_id": "alice", "dataset_binding": "data",
                  "mode": "managed", "component_id": "client"}])
        self.controller.run_once()
        kinds = [kind for kind, _ in self.executor.calls]
        self.assertEqual(kinds[:2], ["reserve", "reserve"])
        self.assertEqual(kinds[2:], ["start", "start"])

    def test_local_gang_refusal_never_starts_partial_job(self):
        components = [{"component_id": "owner", "role": "owner", "resources": {
            "pool_id": "server", "cpu_millicores": 1000, "memory_bytes": 1000, "disk_bytes": 1000}},
            {"component_id": "client", "role": "participant", "participant_id": "alice", "resources": {
            "pool_id": "server", "cpu_millicores": 1000, "memory_bytes": 1000, "disk_bytes": 1000}}]
        self.job("gang", components=components, participants=[{"participant_id": "alice", "dataset_binding": "data",
                  "mode": "managed", "component_id": "client"}])
        self.executor.refuse_component = "client"
        self.controller.run_once()
        self.assertEqual(self.executor.started, [])
        self.assertEqual(self.read("gang").state, "QUEUED")

    def test_queued_cancel_without_reservation_finishes(self):
        self.job("queued")
        self.cancel("queued")
        self.controller.run_once()
        self.assertEqual(self.read("queued").state, "CANCELLED")
        self.assertEqual(self.executor.started, [])

    def test_cancel_fences_stops_and_reconciles_before_release(self):
        self.job("job")
        self.controller.run_once()
        self.cancel("job")
        self.controller.run_once()
        self.assertEqual(self.read("job").state, "CANCELLED")
        self.assertIn(("revoke", "job"), self.provisioner.calls)
        self.assertIn(("reconcile", "job"), self.provisioner.calls)
        self.assertEqual(self.executor.calls[-2:], [("stop", "owner"), ("release", "owner")])

    def test_unknown_stop_keeps_capacity_quarantined(self):
        self.job("job", cpu=4000)
        self.controller.run_once()
        self.cancel("job")
        self.executor.stop_unknown = True
        self.controller.run_once()
        with self.db.transaction() as session:
            allocation = session.scalar(select(models.Allocation))
            self.assertEqual(allocation.state, "QUARANTINED")
            self.assertIsNone(allocation.released_at)
        self.assertNotEqual(self.read("job").state, "CANCELLED")

    def test_unknown_publication_requires_attention_without_retry(self):
        self.job("job")
        self.controller.run_once()
        self.provisioner.publication_known = False
        self.controller._request_failure("job", "node_partition", transient=True)
        self.controller.run_once()
        self.assertEqual(self.read("job").state, "NEEDS_ATTENTION")
        self.assertEqual(self.read("job").current_attempt, 1)

    def test_unconfirmed_revocation_never_releases(self):
        self.job("job")
        self.controller.run_once()
        self.cancel("job")
        self.provisioner.revoke_confirmed = False
        self.controller.run_once()
        self.assertEqual(self.read("job").state, "NEEDS_ATTENTION")
        self.assertNotIn(("release", "owner"), self.executor.calls)

    def test_lost_final_ack_does_not_launch_an_extra_owner(self):
        self.job("job", target=3)
        self.provisioner.rounds["job"] = 3
        self.controller.run_once()
        self.assertEqual(self.read("job").state, "SUCCEEDED")
        self.assertEqual(self.executor.started, [])

    def test_transient_retry_preserves_deadline_and_round_target(self):
        self.job("job")
        self.controller.run_once()
        deadline = self.read("job").deadline_at
        self.controller._request_failure("job", "node_partition", transient=True)
        self.controller.run_once()
        retried = self.read("job")
        self.assertEqual(retried.state, "QUEUED")
        self.assertEqual(retried.current_attempt, 2)
        self.assertEqual(retried.deadline_at, deadline)
        self.assertEqual(retried.target_round, 3)
        self.assertEqual(retried.next_attempt_at, self.clock() + timedelta(seconds=60))
        self.assertEqual(self.scheduler.schedule(), [])

    def test_plugin_errors_fail_without_automatic_retry(self):
        self.job("job")
        self.controller.run_once()
        self.controller._request_failure("job", "plugin_error", transient=False)
        self.controller.run_once()
        self.assertEqual(self.read("job").state, "FAILED")
        self.assertEqual(self.read("job").current_attempt, 1)

    def test_deadline_expiry_is_failed_not_success(self):
        self.job("job", duration=60)
        self.controller.run_once()
        self.clock.advance(61)
        self.controller.run_once()
        self.assertEqual(self.read("job").state, "FAILED")
        self.assertEqual(self.read("job").outcome_reason, "deadline_exceeded")

    def test_stale_callbacks_do_not_change_progress_or_events(self):
        self.job("job")
        self.controller.run_once()
        with self.db.transaction() as session:
            before = len(list(session.scalars(select(models.Event))))
        self.assertFalse(self.controller.progress("job", "job-a1", "owner", 999, current_round=900))
        self.assertFalse(self.controller.heartbeat("job", "job-a1", "owner", 999))
        self.assertFalse(self.controller.stop_confirmation("job", "job-a1", "owner", 999))
        with self.db.transaction() as session:
            self.assertEqual(len(list(session.scalars(select(models.Event)))), before)
        self.assertEqual(self.read("job").current_round, 0)

    def test_node_assignment_is_bound_to_pool_and_node(self):
        self.job("job")
        self.controller.run_once()
        self.assertTrue(self.controller.check_assignment("node", "server", "job", "job-a1", "owner", 1))
        self.assertFalse(self.controller.check_assignment("foreign", "server", "job", "job-a1", "owner", 1))

    def test_assignment_remains_bound_to_admitted_node_after_pool_reassignment(self):
        self.job("job")
        self.controller.run_once()
        with self.db.transaction() as session:
            allocation = session.scalar(select(models.Allocation))
            self.assertEqual(allocation.details_json["node_id"], "node")
            session.get(models.Pool, "server").node_id = "replacement"
        self.assertTrue(self.controller.check_assignment("node", "server", "job", "job-a1", "owner", 1))
        self.assertFalse(self.controller.check_assignment("replacement", "server", "job", "job-a1", "owner", 1))

    def test_offline_external_participant_waiting_telemetry_keeps_owner_running(self):
        from dataclasses import replace
        inspect = self.executor.inspect
        self.executor.inspect = lambda identity: replace(inspect(identity), current_round=0,
            details={"phase": "not_ready", "readiness": "waiting", "role": "owner"})
        self.job("job", participants=[{"participant_id": "alice", "dataset_binding": "private-data", "mode": "external"}])
        self.controller.run_once()
        self.clock.advance(30)
        self.controller.run_once()
        job = self.read("job")
        self.assertEqual(job.state, "RUNNING")
        self.assertEqual(job.phase, "waiting_participants")
        self.assertEqual(job.current_round, 0)
        self.assertIsNone(job.error_code)
        self.assertEqual(len(self.executor.started), 1)
        with self.db.transaction() as session:
            report = session.get(models.Attempt, "job-a1").details_json["components"]["owner"]
            self.assertEqual(report["readiness"], "waiting")
            self.assertEqual(report["phase"], "waiting_participants")

    def test_known_worker_events_map_to_canonical_manager_phases(self):
        self.job("job")
        self.controller.run_once()
        expected = {"ready": "waiting_participants", "initialized": "waiting_participants",
                    "idle": "waiting_participants", "waiting_initialization": "initializing",
                    "submitted": "waiting_participants", "published": "publishing",
                    "completed": "collecting_results", "skipped": "waiting_participants",
                    "retry": "waiting_participants", "retry_authorized": "initializing",
                    "running": "training", "uncertain": "publishing", "needs_attention": "publishing",
                    "stopped": "collecting_results", "failed": "collecting_results",
                    "duration_exceeded": "collecting_results"}
        for reported, canonical in expected.items():
            with self.subTest(phase=reported):
                self.assertTrue(self.controller.progress("job", "job-a1", "owner", 1, phase=reported))
                self.assertEqual(self.read("job").phase, canonical)
                with self.db.transaction() as session:
                    report = session.get(models.Attempt, "job-a1").details_json["components"]["owner"]
                    self.assertEqual(report["reported_phase"], reported)
                    self.assertEqual(report["phase"], canonical)

    def test_unrecognized_runtime_phase_still_fails_validation(self):
        from dataclasses import replace
        inspect = self.executor.inspect
        self.executor.inspect = lambda identity: replace(inspect(identity),
            details={"phase": "invented_runtime_phase", "readiness": "waiting"})
        self.job("job")
        self.controller.run_once()
        self.controller.run_once()
        self.assertEqual(self.read("job").state, "FAILED")
        self.assertEqual(self.read("job").outcome_reason, "invalid_runtime_progress")

    def test_untrusted_progress_cannot_confirm_success(self):
        self.job("job")
        self.controller.run_once()
        self.controller.progress("job", "job-a1", "owner", 1, current_round=999)
        self.controller._request_failure("job", "plugin_error", transient=False)
        self.controller.run_once()
        self.assertEqual(self.read("job").state, "FAILED")

    def test_expired_heartbeat_does_not_revive_grant(self):
        self.job("job")
        self.controller.run_once()
        self.clock.advance(181)
        self.controller.run_once()
        self.assertEqual(self.read("job").state, "QUEUED")

    def test_duration_retry_after_deadline_fails(self):
        self.job("job", duration=60)
        self.controller.run_once()
        self.controller._request_failure("job", "node_partition", transient=True)
        self.clock.advance(61)
        self.controller.run_once()
        self.assertEqual(self.read("job").state, "FAILED")
        self.assertEqual(self.read("job").current_attempt, 1)

    def test_retry_delays_and_absolute_round_helper(self):
        self.assertEqual([retry_delay(n) for n in (1, 2, 3)], [60, 120, 240])
        with self.assertRaises(ValueError):
            retry_delay(4)
        self.assertEqual(remaining_rounds(3, 2), 1)
        self.assertEqual(remaining_rounds(3, 4), 0)


    def test_retained_disk_stays_charged_until_confirmed_purge(self):
        self.job("job")
        self.controller.run_once()
        self.provisioner.rounds["job"] = 3
        self.controller.run_once()
        with self.db.transaction() as session:
            self.assertEqual(session.get(models.Project, "project").retained_bytes, self.prepaid_attempt_bytes)
            state = session.scalar(select(models.ProvisioningResource).where(
                models.ProvisioningResource.kind == "execution_state"))
            self.assertEqual(state.details_json["retention_charged_bytes"], 1000)
            job = session.get(models.Job, "job")
            Scheduler._outbox(session, job, "purge", {})
        self.controller.run_once()
        with self.db.transaction() as session:
            self.assertEqual(session.get(models.Project, "project").retained_bytes, 0)
            self.assertIsNotNone(session.get(models.Job, "job").purged_at)

    def historical_node_service(self):
        import base64
        import hashlib
        from cryptography.hazmat.primitives.asymmetric import rsa
        from hf2l_jobs.broker import BrokerSettings, WorkloadBroker
        from hf2l_jobs.managed_nodes import ApprovedManagedNode, NodeAssignmentService
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        thumb = lambda value: base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).rstrip(b"=").decode()
        broker = WorkloadBroker(BrokerSettings("https://jobs.example.test/workloads", "managed-exchange",
            "managed-transfer", "managed-nodes", key.public_key(), key),
            clock=lambda: int(self.clock().timestamp()))
        with self.db.transaction() as session:
            session.get(models.Pool, "server").details_json = {"registration_id": "test-node"}
        return NodeAssignmentService(self.db, self.provisioner, broker,
            {"node": ApprovedManagedNode("node", "server", thumb("node"), "test-node")},
            manager_certificate_thumbprint=thumb("manager"), clock=self.clock)

    def request_owned_purge(self, key):
        from hf2l_jobs.application import Manager
        with self.db.transaction() as session:
            if session.get(models.Membership, ("job", "creator")) is None:
                session.add(models.Membership(job_id="job", principal_id="creator", role="admin"))
        return Manager(self.db, b"x" * 32, clock=self.clock).purge(
            "creator", "job", self.read("job").version, key)

    def test_old_cleanup_cannot_clear_manager_purge_intent_or_node_grant(self):
        self.job("job")
        self.controller.run_once()
        self.provisioner.cleanup = lambda job, attempt: False
        self.provisioner.rounds["job"] = 3
        self.controller.run_once()
        service = self.historical_node_service()
        self.clock.advance(5)
        old_claim = self.controller._claim(topics=("cleanup",))
        self.assertIsNotNone(old_claim)
        def raced_cleanup(job, attempt):
            self.request_owned_purge("purge-during-old-cleanup")
            return False
        self.provisioner.cleanup = raced_cleanup
        self.assertTrue(self.controller._process_claim(old_claim))
        self.assertEqual(self.read("job").cleanup_status, "purge_pending")
        identity = ExecutionIdentity("job", "job-a1", "owner", 1)
        self.assertIsInstance(service.issue_control_token(identity, node_id="node", pool_id="server", scope="purge"), str)
        with self.assertRaises(Error):
            service.issue_control_token(identity, node_id="node", pool_id="server", scope="start")
        self.controller.run_once()
        self.assertEqual(self.read("job").state, "SUCCEEDED")
        self.assertIsNotNone(self.read("job").purged_at)

    def test_lost_purge_ack_and_grant_refusal_keep_exact_intent_and_budget(self):
        self.job("job")
        self.controller.run_once()
        self.provisioner.rounds["job"] = 3
        self.controller.run_once()
        service = self.historical_node_service()
        self.request_owned_purge("retry-owned-purge")
        calls = []
        def purging(identity):
            calls.append(identity)
            service.issue_control_token(identity, node_id="node", pool_id="server", scope="purge")
            if len(calls) == 1:
                raise Error(409, "node_operation_not_currently_authorized")
            if len(calls) == 2:
                raise UncertainExecution("Deletion completed but its acknowledgement was lost")
            return True
        self.executor.purge = purging
        for expected in ("node_operation_not_currently_authorized", "execution_unknown"):
            self.controller.run_once()
            job = self.read("job")
            self.assertEqual((job.state, job.cleanup_status, job.purged_at), ("SUCCEEDED", "purge_pending", None))
            with self.db.transaction() as session:
                item = session.scalar(select(models.Outbox).where(models.Outbox.topic == "purge"))
                self.assertEqual((item.state, item.last_error), ("pending", expected))
                self.assertEqual(item.next_attempt_at, self.clock() + timedelta(seconds=5))
                self.assertEqual(session.get(models.Project, "project").retained_bytes, self.prepaid_attempt_bytes)
                self.assertFalse(session.scalar(select(models.Allocation)).details_json.get("storage_deleted", False))
            self.clock.advance(5)
        self.controller.run_once()
        self.assertEqual(len(calls), 3)
        self.assertEqual(self.read("job").state, "SUCCEEDED")
        self.assertIsNotNone(self.read("job").purged_at)
        with self.db.transaction() as session:
            self.assertEqual(session.get(models.Project, "project").retained_bytes, 0)
            self.assertEqual(session.scalar(select(models.Outbox).where(models.Outbox.topic == "purge")).state, "done")

    def test_expiry_retains_job_history_without_purge_tombstone(self):
        self.job("job")
        self.controller.run_once()
        self.provisioner.rounds["job"] = 3
        self.controller.run_once()
        self.clock.advance(91 * 86400)
        self.controller.run_once()
        self.assertEqual(self.read("job").state, "SUCCEEDED")
        self.assertIsNone(self.read("job").purged_at)
        self.assertEqual(self.read("job").cleanup_status, "expired")
        with self.db.transaction() as session:
            self.assertEqual(session.get(models.Project, "project").retained_bytes, 0)

    def test_live_logs_deduplicate_and_terminal_logs_catch_up(self):
        from dataclasses import asdict
        source = [b"first\n"]
        def read_logs(identity, offset=0, max_bytes=65536):
            data = source[0][offset:offset + max_bytes]
            return {"identity": asdict(identity), "source_id": identity.key, "offset": offset,
                "next_offset": offset + len(data), "content": data.decode(),
                "complete": self.executor.states.get(identity.key) in {"STOPPED", "RELEASED"},
                "truncated": False}
        self.executor.read_logs = read_logs
        self.job("job")
        self.controller.run_once()
        self.controller.run_once()
        self.controller.run_once()
        with self.db.transaction() as session:
            self.assertEqual([chunk.data for chunk in session.scalars(select(models.LogChunk))], ["first\n"])
        source[0] += b"last\n"
        self.provisioner.rounds["job"] = 3
        self.controller.run_once()
        with self.db.transaction() as session:
            chunks = list(session.scalars(select(models.LogChunk).order_by(models.LogChunk.sequence)))
            self.assertEqual([chunk.data for chunk in chunks], ["first\n", "last\n"])
            allocation = session.scalar(select(models.Allocation))
            self.assertEqual(allocation.details_json["log_stream"]["offset"], len(source[0]))
            self.assertEqual(session.get(models.Project, "project").retained_bytes, self.prepaid_attempt_bytes)

    def test_terminal_logs_use_own_prepaid_budget_with_no_free_quota(self):
        from dataclasses import asdict
        def read_logs(identity, offset=0, max_bytes=65536):
            data = b"last\n"[offset:]
            return {"identity": asdict(identity), "source_id": identity.key, "offset": offset,
                "next_offset": offset + len(data), "content": data.decode(),
                "complete": True, "truncated": False}
        self.executor.read_logs = read_logs
        self.job("job")
        with self.db.transaction() as session:
            session.get(models.Project, "project").quotas_json = {"retained_bytes": self.prepaid_attempt_bytes}
        self.controller.run_once()
        self.provisioner.rounds["job"] = 3
        self.controller.run_once()
        self.assertEqual(self.read("job").state, "SUCCEEDED")
        with self.db.transaction() as session:
            self.assertEqual([chunk.data for chunk in session.scalars(select(models.LogChunk))], ["last\n"])
            self.assertEqual(session.get(models.Project, "project").retained_bytes, self.prepaid_attempt_bytes)

    def test_collection_manifest_keeps_conservative_unused_physical_budget(self):
        from hf2l_jobs.collection import RetainedFile
        self.job("job")
        self.controller.run_once()
        def paid_collection(identity):
            with self.db.transaction() as session:
                budget = session.scalar(select(models.ProvisioningResource).where(
                    models.ProvisioningResource.kind == "collection_budget"))
                self.assertEqual(budget.size_bytes, 1000 + 4 * 1024 * 1024)
                self.assertEqual(session.get(models.Project, "project").retained_bytes, self.prepaid_attempt_bytes)
            return (RetainedFile("result.bin", "/owned/retained/result.bin", 6, "a" * 64),)
        self.executor.collect = paid_collection
        self.provisioner.rounds["job"] = 3
        self.controller.run_once()
        self.assertEqual(self.read("job").state, "SUCCEEDED")
        with self.db.transaction() as session:
            budget = session.scalar(select(models.ProvisioningResource).where(
                models.ProvisioningResource.kind == "collection_budget"))
            self.assertEqual(budget.size_bytes, 1000 + 4 * 1024 * 1024 - 6)
            self.assertTrue(budget.details_json["retention_charge_settled"])
            self.assertEqual(session.get(models.Project, "project").retained_bytes, self.prepaid_attempt_bytes)

    def test_insufficient_future_copy_quota_queues_before_any_node_write(self):
        self.job("job")
        copied = []
        self.executor.collect = lambda identity: copied.append(identity) or ()
        with self.db.transaction() as session:
            session.get(models.Project, "project").quotas_json = {"retained_bytes": 0}
        self.controller.run_once()
        self.assertEqual(copied, [])
        self.assertEqual(self.executor.started, [])
        self.assertEqual(self.read("job").state, "QUEUED")
        self.assertEqual(self.read("job").queue_reason["code"], "quota")
        with self.db.transaction() as session:
            self.assertEqual(list(session.scalars(select(models.Allocation))), [])
            self.assertEqual(list(session.scalars(select(models.ProvisioningResource))), [])
            self.assertEqual(session.get(models.Project, "project").retained_bytes, 0)

    def test_unknown_copy_keeps_its_full_budget_until_known_manifest(self):
        self.job("job")
        self.controller.run_once()
        def uncertain_copy(identity):
            raise UncertainExecution("Collector response was lost after copy")
        self.executor.collect = uncertain_copy
        self.provisioner.rounds["job"] = 3
        self.controller.run_once()
        with self.db.transaction() as session:
            budget = session.scalar(select(models.ProvisioningResource).where(
                models.ProvisioningResource.kind == "collection_budget"))
            self.assertEqual(budget.size_bytes, 1000 + 4 * 1024 * 1024)
            self.assertEqual(session.get(models.Project, "project").retained_bytes, self.prepaid_attempt_bytes)
            self.assertFalse(budget.details_json["retention_charge_settled"])
            self.assertIsNone(session.scalar(select(models.Allocation)).released_at)
        self.executor.collect = lambda identity: ()
        self.clock.advance(5)
        self.controller.run_once()
        self.assertEqual(self.read("job").state, "SUCCEEDED")
        with self.db.transaction() as session:
            self.assertEqual(session.get(models.Project, "project").retained_bytes, self.prepaid_attempt_bytes)

    def test_collect_persists_downloadable_owned_locator(self):
        from hf2l_jobs.collection import RetainedFile
        self.executor.collected = (RetainedFile("result/checkpoint.bin", "/owned/retained/result/checkpoint.bin", 6, "a" * 64),)
        self.job("job")
        self.controller.run_once()
        self.provisioner.rounds["job"] = 3
        self.controller.run_once()
        with self.db.transaction() as session:
            artifact = session.scalar(select(models.Artifact))
            self.assertEqual(artifact.locator_json["kind"], "local")
            self.assertEqual(artifact.locator_json["relative_path"], "result/checkpoint.bin")
            root = session.get(models.ProvisioningResource, artifact.locator_json["resource_id"])
            self.assertEqual(root.kind, "retained_artifact_root")
            self.assertEqual(root.external_id, "/owned/retained")
            self.assertEqual(artifact.expires_at, session.get(models.Job, "job").artifacts_expire_at)
            self.assertEqual(session.get(models.Project, "project").retained_bytes, self.prepaid_attempt_bytes)

    def test_raw_log_bytes_are_charged_and_deleted_on_expiry(self):
        self.job("job")
        self.controller.run_once()
        self.assertTrue(self.controller.append_logs("job", "job-a1", "owner", 1, data="hello"))
        with self.db.transaction() as session:
            self.assertEqual(session.get(models.Project, "project").retained_bytes, self.prepaid_attempt_bytes)
        self.provisioner.rounds["job"] = 3
        self.controller.run_once()
        self.clock.advance(91 * 86400)
        self.controller.run_once()
        with self.db.transaction() as session:
            chunk = session.scalar(select(models.LogChunk))
            self.assertEqual(chunk.data, "")
            self.assertEqual(chunk.charged_bytes, 0)
            self.assertEqual(session.get(models.Project, "project").retained_bytes, 0)

    def test_completed_job_disk_does_not_make_new_capacity_available(self):
        with self.db.transaction() as session:
            session.get(models.Pool, "server").disk_bytes = self.prepaid_attempt_bytes
        self.job("first")
        self.controller.run_once()
        self.provisioner.rounds["first"] = 3
        self.controller.run_once()
        self.assertEqual(self.read("first").state, "SUCCEEDED")
        self.job("second")
        self.assertEqual(self.controller.scheduler.schedule(), [])
        self.assertEqual(self.read("second").queue_reason["code"], "capacity")

    def test_full_idle_pool_and_project_budget_guarantee_completion(self):
        from hf2l_jobs.collection import RetainedFile
        from hf2l_jobs.retention import RetentionService
        self.job("job")
        with self.db.transaction() as session:
            session.get(models.Pool, "server").disk_bytes = self.prepaid_attempt_bytes
            session.get(models.Project, "project").quotas_json = {
                "retained_bytes": self.prepaid_attempt_bytes, "disk_bytes": self.prepaid_attempt_bytes}
        def assert_prepaid(identity):
            with self.db.transaction() as session:
                allocation = session.scalar(select(models.Allocation))
                for pointer, kind, cap in (
                    ("retained_resource_id", "execution_state", 1000),
                    ("collection_resource_id", "collection_budget", 1000 + 4 * 1024 * 1024),
                    ("log_resource_id", "log_budget", 1024 * 1024)):
                    resource = session.get(models.ProvisioningResource, allocation.details_json[pointer])
                    self.assertEqual((resource.kind, resource.size_bytes, resource.attempt_id),
                                     (kind, cap, identity.attempt_id))
                project = session.get(models.Project, "project")
                self.assertEqual(project.retained_bytes, self.prepaid_attempt_bytes)
                self.assertEqual(RetentionService.pool_used_bytes(session, "server"), self.prepaid_attempt_bytes)
            return (RetainedFile("result.bin", "/owned/retained/result.bin", 1, "a" * 64),)
        self.executor.collect = assert_prepaid
        self.controller.run_once()
        self.assertEqual(self.read("job").state, "RUNNING")
        self.assertTrue(self.controller.append_logs("job", "job-a1", "owner", 1, data="bounded log"))
        self.provisioner.rounds["job"] = 3
        self.controller.run_once()
        self.assertEqual(self.read("job").state, "SUCCEEDED")
        with self.db.transaction() as session:
            self.assertEqual(session.get(models.Project, "project").retained_bytes, self.prepaid_attempt_bytes)
            self.assertEqual(RetentionService.pool_used_bytes(session, "server"), self.prepaid_attempt_bytes)
            allocation = session.scalar(select(models.Allocation))
            self.assertIsNotNone(allocation.released_at)
            Scheduler._outbox(session, session.get(models.Job, "job"), "purge", {})
        self.controller.run_once()
        with self.db.transaction() as session:
            self.assertEqual(session.get(models.Project, "project").retained_bytes, 0)
            self.assertEqual(RetentionService.pool_used_bytes(session, "server"), 0)

    def test_provisioning_keepalive_renews_before_launch(self):
        import time
        self.executor.renewed = []
        self.executor.renew = lambda identity: self.executor.renewed.append(identity)
        original = self.provisioner.ensure
        def slow(job, attempt, remaining_rounds=None):
            time.sleep(0.08)
            return original(job, attempt, remaining_rounds)
        self.provisioner.ensure = slow
        self.controller.renew_interval = 0.01
        self.job("job")
        self.controller.run_once()
        self.assertTrue(self.executor.renewed)
        self.assertEqual(self.read("job").state, "RUNNING")

    def test_self_reported_rounds_do_not_change_global_round(self):
        self.job("job")
        self.controller.run_once()
        self.controller.progress("job", "job-a1", "owner", 1, current_round=999,
                                 metrics={"local_loss": 0.2}, readiness="training")
        self.assertEqual(self.read("job").current_round, 0)
        with self.db.transaction() as session:
            attempt = session.get(models.Attempt, "job-a1")
            self.assertEqual(attempt.details_json["components"]["owner"]["current_round"], 999)

    def test_restart_restores_proxy_before_inspect_or_renew(self):
        self.job("job")
        self.controller.run_once()
        recovered = {"ready": False}
        def restore(job, attempt):
            recovered["ready"] = True
            return True
        self.provisioner.restore_job_proxies = restore
        inspect = self.executor.inspect
        def require_recovered(identity):
            self.assertTrue(recovered["ready"])
            return inspect(identity)
        self.executor.inspect = require_recovered
        self.executor.renew = lambda identity: self.assertTrue(recovered["ready"])
        restarted = Controller(self.db, self.executor, self.provisioner, clock=self.clock)
        outcome = restarted.run_once()
        self.assertEqual(outcome["restored"], 1)
        self.assertEqual(self.read("job").state, "RUNNING")
        with self.db.transaction() as session:
            operation = session.scalar(select(models.Outbox).where(models.Outbox.topic == "restore_proxies"))
            self.assertEqual(operation.state, "done")

    def test_remote_artifact_locator_matches_registered_node_and_execution(self):
        from hf2l_jobs.collection import RetainedFile
        identity = ExecutionIdentity("job", "job-a1", "owner", 1)
        filename = "result α #1%.bin"
        locator = "hf2l-node://node/" + identity.key + "/" + quote(filename, safe="/")
        self.executor.collected = (RetainedFile(filename, locator, 6, "a" * 64),)
        self.job("job")
        self.controller.run_once()
        self.provisioner.rounds["job"] = 3
        self.controller.run_once()
        with self.db.transaction() as session:
            artifact = session.scalar(select(models.Artifact))
            root = session.get(models.ProvisioningResource, artifact.locator_json["resource_id"])
            self.assertEqual(root.external_id, "hf2l-node://node/" + identity.key)

    def test_historical_artifacts_keep_original_node_after_pool_reassignment(self):
        from hf2l_jobs.collection import RetainedFile
        identity = ExecutionIdentity("job", "job-a1", "owner", 1)
        self.executor.collected = (RetainedFile("result.bin",
            "hf2l-node://node/" + identity.key + "/result.bin", 6, "a" * 64),)
        self.job("job")
        self.controller.run_once()
        self.provisioner.rounds["job"] = 3
        self.controller.run_once()
        with self.db.transaction() as session:
            session.get(models.Pool, "server").node_id = "replacement"
            allocation = session.scalar(select(models.Allocation))
            self.assertEqual(allocation.state, "RELEASED")
            self.assertEqual(allocation.details_json["node_id"], "node")
            job = session.get(models.Job, "job")
            attempt = session.get(models.Attempt, "job-a1")
            for item in (allocation, job, attempt):
                session.expunge(item)
        self.controller._store_collected(job, attempt, allocation, self.executor.collected)
        with self.db.transaction() as session:
            artifacts = list(session.scalars(select(models.Artifact)))
            self.assertEqual(len(artifacts), 1)
            root = session.get(models.ProvisioningResource, artifacts[0].locator_json["resource_id"])
            self.assertEqual(root.external_id, "hf2l-node://node/" + identity.key)
            self.assertEqual(root.details_json["node_id"], "node")

    def test_remote_artifact_locator_cannot_select_a_foreign_node(self):
        from hf2l_jobs.collection import RetainedFile
        identity = ExecutionIdentity("job", "job-a1", "owner", 1)
        self.executor.collected = (RetainedFile("result.bin",
            "hf2l-node://foreign/" + identity.key + "/result.bin", 6, "a" * 64),)
        self.job("job")
        self.controller.run_once()
        self.provisioner.rounds["job"] = 3
        self.controller.run_once()
        with self.db.transaction() as session:
            self.assertEqual(list(session.scalars(select(models.Artifact))), [])
            self.assertIsNone(session.scalar(select(models.Allocation)).released_at)

    def test_dead_proxy_mount_retry_preserves_absolute_target_and_deadline(self):
        self.job("job", target=3)
        self.controller.run_once()
        deadline = self.read("job").deadline_at
        self.provisioner.rounds["job"] = 1
        def dead_socket(job, attempt):
            raise ExecutorRefused("Running container retains a dead proxy mount", "proxy_restart_required")
        self.provisioner.restore_job_proxies = dead_socket
        restarted = Controller(self.db, self.executor, self.provisioner, clock=self.clock)
        restarted.run_once()
        job = self.read("job")
        self.assertEqual(job.state, "QUEUED")
        self.assertEqual(job.current_attempt, 2)
        self.assertEqual(job.target_round, 3)
        self.assertEqual(job.deadline_at, deadline)
        self.assertEqual(job.next_attempt_at, self.clock() + timedelta(seconds=60))
        with self.db.transaction() as session:
            previous = session.get(models.Attempt, "job-a1")
            self.assertTrue(previous.revocation_confirmed)
            self.assertTrue(previous.termination_confirmed)
            self.assertEqual(previous.details_json["transient"], True)
            self.assertEqual(session.scalar(select(models.Allocation)).state, "RELEASED")
        self.clock.advance(60)
        restarted.run_once()
        self.assertEqual(self.read("job").state, "RUNNING")
        self.assertEqual(self.read("job").epoch, 2)
        self.assertEqual(self.read("job").deadline_at, deadline)


class BuildExecutor(FakeExecutor):
    def __init__(self):
        super().__init__()
        self.exit_codes = {}
        self.immediate_build = None
    def inspect(self, identity):
        observed = super().inspect(identity)
        return RuntimeObservation(identity, observed.state, observed.termination_confirmed,
                                  publication_status="not_observed",
                                  exit_code=self.exit_codes.get(identity.key))
    def start(self, identity):
        self.calls.append(("start", identity.component_id))
        self.started.append(identity)
        self.states[identity.key] = "RUNNING"
        if identity.component_id == "builder" and self.immediate_build is not None:
            self.states[identity.key] = "STOPPED"
            self.exit_codes[identity.key] = self.immediate_build
        return self.inspect(identity)
    def finish_build(self, code=0):
        identity = next(item for item in self.started if item.component_id == "builder")
        self.states[identity.key] = "STOPPED"
        self.exit_codes[identity.key] = code


class BuildControllerTests(Fixture):
    def setUp(self):
        super().setUp()
        self.executor = BuildExecutor()
        self.provisioner = FakeProvisioner()
        self.prepared = []
        def prepare(job, attempt, outputs):
            self.prepared.append(tuple(outputs))
            return {"built_artifacts": {"package.whl": {"sha256": "a" * 64, "size_bytes": 6}}}
        self.provisioner.prepare_build_outputs = prepare
        self.controller = Controller(self.db, self.executor, self.provisioner, clock=self.clock)
        components = [
            {"component_id": "owner", "role": "owner", "resources": {
                "pool_id": "server", "cpu_millicores": 1000, "memory_bytes": 1000, "disk_bytes": 1000}},
            {"component_id": "builder", "role": "build", "resources": {
                "pool_id": "server", "cpu_millicores": 1000, "memory_bytes": 1000, "disk_bytes": 1000}}]
        self.job("job", components=components)

    def test_build_runs_before_training_and_preparation_is_confirmed(self):
        self.executor.immediate_build = 0
        self.controller.run_once()
        self.assertEqual([identity.component_id for identity in self.executor.started], ["builder", "owner"])
        self.assertEqual(self.prepared, [("builder",)])
        self.assertEqual(self.read("job").state, "RUNNING")
        calls = self.executor.calls
        self.assertLess(calls.index(("release", "builder")), calls.index(("start", "owner")))
        with self.db.transaction() as session:
            builder = session.scalar(select(models.Allocation).where(models.Allocation.component_id == "builder"))
            self.assertEqual(builder.state, "RELEASED")
            self.assertTrue(builder.termination_confirmed)
            self.assertTrue(session.get(models.Attempt, "job-a1").details_json["build_prepared"])

    def test_pending_build_holds_gang_without_starting_owner(self):
        self.controller.run_once()
        self.assertEqual([identity.component_id for identity in self.executor.started], ["builder"])
        self.assertEqual(self.read("job").state, "PROVISIONING")
        self.assertEqual(self.read("job").phase, "building")
        self.assertEqual(self.prepared, [])
        with self.db.transaction() as session:
            self.assertTrue(all(allocation.released_at is None for allocation in session.scalars(select(models.Allocation))))
        self.executor.finish_build()
        self.clock.advance(5)
        self.controller.run_once()
        self.assertEqual([identity.component_id for identity in self.executor.started], ["builder", "owner"])
        self.assertEqual(self.read("job").state, "RUNNING")

    def test_failed_build_is_permanent_and_owner_never_starts(self):
        self.executor.immediate_build = 7
        self.controller.run_once()
        self.assertEqual([identity.component_id for identity in self.executor.started], ["builder"])
        self.assertEqual(self.read("job").state, "FAILED")
        self.assertEqual(self.read("job").outcome_reason, "failed_build")
        self.assertEqual(self.read("job").current_attempt, 1)
        self.assertEqual(self.prepared, [])

    def test_unverified_outputs_never_start_training(self):
        self.executor.immediate_build = 0
        def invalid_outputs(job, attempt, outputs):
            raise ValueError("Build report does not match its immutable source")
        self.provisioner.prepare_build_outputs = invalid_outputs
        self.controller.run_once()
        self.assertEqual([identity.component_id for identity in self.executor.started], ["builder"])
        self.assertEqual(self.read("job").state, "FAILED")
        self.assertEqual(self.read("job").outcome_reason, "failed_build")

    def test_restart_adopts_completed_build_without_building_twice(self):
        self.controller.run_once()
        self.executor.finish_build()
        self.clock.advance(5)
        restarted = Controller(self.db, self.executor, self.provisioner, clock=self.clock)
        restarted.run_once()
        self.assertEqual([identity.component_id for identity in self.executor.started], ["builder", "owner"])
        self.assertEqual(self.prepared, [("builder",)])
        self.assertEqual(self.read("job").state, "RUNNING")

if __name__ == "__main__":
    unittest.main()
