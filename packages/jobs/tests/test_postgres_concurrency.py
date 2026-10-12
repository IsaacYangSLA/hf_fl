"""Real PostgreSQL admission races and durable queue policy acceptance tests.

Set JOBS_TEST_DATABASE_URL to an expendable PostgreSQL database whose user may
create schemas. Each test creates and drops only a random owned schema. An
explicitly configured but broken PostgreSQL fixture fails rather than skips.
These tests prove ledger transactions, not sandbox or publication isolation.
"""
from __future__ import annotations

import dataclasses
import multiprocessing
import os
import traceback
import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError

from hf2l_jobs.database import create_database
from hf2l_jobs.domain import ComponentSpec, JobSpec, ResourceRequest
from hf2l_jobs.models import Allocation, Attempt, GpuAllocation, Job, Outbox, Pool, Project
from hf2l_jobs.scheduler import LIVE_ALLOCATION_STATES, Scheduler

_NOW = datetime(2026, 10, 9, 12, tzinfo=timezone.utc)


def _clock():
    return _NOW


def _schedule_worker(url, barrier, output):
    """A separate interpreter and connection pool exercise real row locks."""
    database = None
    try:
        database = create_database(url, initialize=False, isolation_level="READ COMMITTED")
        with database.transaction(immediate=False) as session:
            isolation = session.scalar(text("SHOW transaction_isolation"))
        output.put({"stage": "ready", "isolation": isolation, "pid": os.getpid()})
        barrier.wait(timeout=30)
        result = Scheduler(database, clock=_clock).schedule(limit=1)
        output.put({"stage": "result", "admissions": [dataclasses.asdict(item) for item in result]})
    except BaseException:
        output.put({"stage": "error", "traceback": traceback.format_exc()})
    finally:
        if database is not None:
            database.close()


@unittest.skipUnless(os.environ.get("JOBS_TEST_DATABASE_URL"), "JOBS_TEST_DATABASE_URL is not configured")
class PostgreSQLConcurrencyTests(unittest.TestCase):
    def setUp(self):
        supplied = make_url(os.environ["JOBS_TEST_DATABASE_URL"])
        if supplied.get_backend_name() != "postgresql":
            self.fail("JOBS_TEST_DATABASE_URL must select PostgreSQL")
        self.schema = "jm_concurrency_" + uuid4().hex
        self.admin = create_engine(supplied, pool_pre_ping=True)
        self.addCleanup(self.admin.dispose)
        with self.admin.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{self.schema}"'))
        self.addCleanup(self._drop_schema)
        # Bound accidental deadlocks and keep all connections inside this test.
        options = f"-csearch_path={self.schema} -clock_timeout=10000 -cstatement_timeout=20000"
        self.url = supplied.update_query_dict({"options": options}).render_as_string(hide_password=False)
        self.database = create_database(self.url, isolation_level="READ COMMITTED")
        self.addCleanup(self.database.close)
        with self.database.transaction() as session:
            session.add(Project(id="project", name="Concurrency acceptance", quotas_json={}))
            session.flush()

    def _drop_schema(self):
        with self.admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{self.schema}" CASCADE'))

    def _pool(self, pool_id="cpu", cpu=1000, *, gpu_uuids=()):
        with self.database.transaction() as session:
            session.add(Pool(
                id=pool_id, name=pool_id, node_id="test-node-" + pool_id,
                cpu_millicores=cpu, memory_bytes=100_000, disk_bytes=100_000,
                gpu_uuids=list(gpu_uuids),
                gpu_profiles=["qualified-test"] if gpu_uuids else [],
                sandbox_profiles=["runsc-cpu-v1"], healthy=True, quarantined=False,
            ))

    def _job(self, name, cpu=1000, *, pool="cpu", created=0, extra=(), gpu_count=0):
        components = [ComponentSpec(
            component_id="owner", role="owner", resources=ResourceRequest(
                pool_id=pool, cpu_millicores=cpu, memory_bytes=100, disk_bytes=100,
                gpu_count=gpu_count, gpu_profile="qualified-test" if gpu_count else None,
            ))]
        for index, (pool_id, amount) in enumerate(extra):
            components.append(ComponentSpec(
                component_id="build-" + str(index), role="build",
                resources=ResourceRequest(
                    pool_id=pool_id, cpu_millicores=amount, memory_bytes=100, disk_bytes=100,
                )))
        spec = JobSpec(
            project_id="project", name=name, source_id="approved-source",
            source_commit="a" * 40, runtime_image="approved-runtime",
            plugin="examples.lenet_plugin", components=tuple(components),
            target_round=3, max_duration_seconds=100_000,
        )
        job_id, attempt_id = uuid4().hex, uuid4().hex
        with self.database.transaction() as session:
            session.add(Job(
                id=job_id, project_id="project", creator_id="test-creator", name=name,
                spec_json=spec.to_dict(), spec_hash=spec.digest, target_round=3,
                state="QUEUED", current_attempt=1, attempt_count=1, epoch=0,
                created_at=_NOW + timedelta(seconds=created), updated_at=_NOW,
            ))
            session.flush()
            session.add(Attempt(
                id=attempt_id, job_id=job_id, number=1, epoch=1, state="QUEUED",
            ))
        return job_id

    def _race(self):
        context = multiprocessing.get_context("spawn")
        barrier = context.Barrier(3)
        output = context.Queue()
        workers = [context.Process(target=_schedule_worker, args=(self.url, barrier, output))
                   for _ in range(2)]

        def stop_owned_workers():
            for worker in workers:
                if worker.is_alive():
                    worker.terminate()
                worker.join(timeout=5)
            output.close()
            output.join_thread()

        self.addCleanup(stop_owned_workers)
        for worker in workers:
            worker.start()
        ready = [output.get(timeout=30) for _ in workers]
        self.assertTrue(all(item["stage"] == "ready" for item in ready), ready)
        self.assertEqual({item["isolation"] for item in ready}, {"read committed"})
        self.assertEqual(len({item["pid"] for item in ready}), 2)
        barrier.wait(timeout=30)
        results = [output.get(timeout=45) for _ in workers]
        self.assertTrue(all(item["stage"] == "result" for item in results), results)
        for worker in workers:
            worker.join(timeout=10)
            self.assertFalse(worker.is_alive(), "Owned scheduler process did not finish")
            self.assertEqual(worker.exitcode, 0)
        return [admission for item in results for admission in item["admissions"]]

    def _release_fixture_job(self, job_id):
        """Simulate independently confirmed termination, solely for queue tests."""
        with self.database.transaction() as session:
            allocations = list(session.scalars(select(Allocation).where(
                Allocation.job_id == job_id, Allocation.released_at.is_(None))))
            for allocation in allocations:
                allocation.state = "RELEASED"
                allocation.termination_confirmed = True
                allocation.released_at = _NOW
                for gpu in session.scalars(select(GpuAllocation).where(
                    GpuAllocation.allocation_id == allocation.id,
                    GpuAllocation.released_at.is_(None))):
                    gpu.released_at = _NOW
            job = session.get(Job, job_id)
            attempt = session.scalar(select(Attempt).where(
                Attempt.job_id == job_id, Attempt.number == job.current_attempt))
            attempt.termination_confirmed = True
            attempt.revocation_confirmed = True
            job.state = "SUCCEEDED"

    def test_two_processes_cannot_overallocate_one_pool(self):
        self._pool()
        first = self._job("first", created=0)
        second = self._job("second", created=1)
        admissions = self._race()
        self.assertEqual([item["job_id"] for item in admissions], [first])
        with self.database.transaction() as session:
            allocations = list(session.scalars(select(Allocation).where(
                Allocation.state.in_(LIVE_ALLOCATION_STATES))))
            self.assertEqual(len(allocations), 1)
            self.assertEqual(sum(item.cpu_millicores for item in allocations), 1000)
            self.assertEqual(session.get(Job, first).epoch, 1)
            self.assertEqual(session.get(Job, second).state, "QUEUED")
            reason = session.get(Job, second).queue_reason
            self.assertEqual(reason["code"], "capacity")
            self.assertEqual(reason["shortages"], {"cpu": {"cpu_millicores": 1000}})
            self.assertEqual(session.scalar(select(func.count()).select_from(Outbox)), 1)

    def test_opposite_component_order_gangs_are_atomic(self):
        self._pool("pool-a")
        self._pool("pool-b")
        first = self._job("first-gang", pool="pool-a", extra=(("pool-b", 1000),), created=0)
        second = self._job("opposite-gang", pool="pool-b", extra=(("pool-a", 1000),), created=1)
        admissions = self._race()
        self.assertEqual([item["job_id"] for item in admissions], [first])
        with self.database.transaction() as session:
            allocations = list(session.scalars(select(Allocation)))
            self.assertEqual({item.job_id for item in allocations}, {first})
            self.assertEqual({item.pool_id for item in allocations}, {"pool-a", "pool-b"})
            self.assertEqual(len(allocations), 2)
            self.assertEqual(session.get(Job, second).state, "QUEUED")
            self.assertEqual(session.scalar(select(func.count()).select_from(Outbox)), 1)

    def test_project_job_quota_survives_concurrent_controllers(self):
        self._pool(cpu=4000)
        with self.database.transaction() as session:
            session.get(Project, "project").quotas_json = {"max_running_jobs": 1}
        first = self._job("first-quota", created=0)
        second = self._job("second-quota", created=1)
        admissions = self._race()
        self.assertEqual([item["job_id"] for item in admissions], [first])
        with self.database.transaction() as session:
            self.assertEqual(session.get(Job, second).queue_reason, {"code": "quota"})
            self.assertEqual(session.scalar(select(func.count()).select_from(Allocation)), 1)

    def test_gpu_reservation_race_and_database_uniqueness(self):
        self._pool(cpu=4000, gpu_uuids=("GPU-test-0001",))
        first = self._job("first-gpu", created=0, gpu_count=1)
        second = self._job("second-gpu", created=1, gpu_count=1)
        admissions = self._race()
        self.assertEqual([item["job_id"] for item in admissions], [first])
        with self.database.transaction() as session:
            gpu = session.scalar(select(GpuAllocation).where(GpuAllocation.released_at.is_(None)))
            allocation_id = gpu.allocation_id
            self.assertEqual(gpu.gpu_uuid, "GPU-test-0001")
            self.assertEqual(session.get(Job, second).queue_reason["shortages"],
                             {"cpu": {"gpu_count": 1}})
        with self.assertRaises(IntegrityError):
            with self.database.transaction() as session:
                session.add(GpuAllocation(
                    id=uuid4().hex, allocation_id=allocation_id, pool_id="cpu",
                    gpu_uuid="GPU-test-0001",
                ))
                session.flush()
        with self.database.transaction() as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(GpuAllocation)), 1)

    def test_three_backfills_persist_across_controllers_and_protect_oldest(self):
        self._pool()
        self._pool("unrelated")
        blocker = self._job("already-running", cpu=500, created=-1)
        self.assertEqual(Scheduler(self.database, clock=_clock).schedule(limit=1)[0].job_id, blocker)
        older = self._job("oldest-needs-whole-pool", cpu=1000, created=0)
        younger = [self._job(f"younger-{index}", cpu=250, created=index + 1) for index in range(4)]
        unrelated = self._job("different-pool", cpu=250, pool="unrelated", created=6)
        for count, job_id in enumerate(younger[:3], start=1):
            # Constructing a fresh controller cannot reset durable protection.
            admitted = Scheduler(self.database, clock=_clock).schedule(limit=1)
            self.assertEqual([item.job_id for item in admitted], [job_id])
            with self.database.transaction() as session:
                self.assertEqual(session.get(Job, older).backfill_count, count)
                self.assertEqual(session.get(Job, older).queue_reason,
                                 {"code": "capacity", "shortages": {"cpu": {"cpu_millicores": 500}}})
            self._release_fixture_job(job_id)
        admitted = Scheduler(self.database, clock=_clock).schedule()
        self.assertEqual([item.job_id for item in admitted], [unrelated])
        with self.database.transaction() as session:
            self.assertEqual(session.get(Job, older).backfill_count, 3)
            self.assertEqual(session.get(Job, younger[3]).queue_reason,
                             {"code": "capacity", "protection": "older_request"})
        self._release_fixture_job(blocker)
        admitted = Scheduler(self.database, clock=_clock).schedule()
        self.assertEqual([item.job_id for item in admitted], [older])
        with self.database.transaction() as session:
            self.assertEqual(session.get(Job, older).backfill_count, 0)
            self.assertEqual(session.get(Job, younger[3]).state, "QUEUED")

    def test_failed_admission_rolls_back_allocations_epoch_and_outbox(self):
        self._pool()
        job_id = self._job("atomic-dispatch")
        scheduler = Scheduler(self.database, clock=_clock)

        def fail_event(*args, **kwargs):
            raise RuntimeError("Synthetic failure after allocation and outbox construction")

        scheduler._event = fail_event
        with self.assertRaisesRegex(RuntimeError, "Synthetic failure"):
            scheduler.schedule()
        with self.database.transaction() as session:
            job = session.get(Job, job_id)
            self.assertEqual((job.state, job.epoch, job.version), ("QUEUED", 0, 1))
            self.assertIsNone(job.deadline_at)
            self.assertEqual(session.scalar(select(func.count()).select_from(Allocation)), 0)
            self.assertEqual(session.scalar(select(func.count()).select_from(Outbox)), 0)
        self.assertEqual(len(Scheduler(self.database, clock=_clock).schedule()), 1)

    def test_quarantined_allocation_remains_charged_after_controller_restart(self):
        self._pool()
        first = self._job("suspect-running", created=0)
        self.assertEqual(len(Scheduler(self.database, clock=_clock).schedule()), 1)
        second = self._job("must-not-reuse", created=1)
        with self.database.transaction() as session:
            allocation = session.scalar(select(Allocation).where(Allocation.job_id == first))
            allocation.state = "QUARANTINED"
            session.get(Job, first).state = "NEEDS_ATTENTION"
        self.assertEqual(Scheduler(self.database, clock=_clock).schedule(), [])
        with self.database.transaction() as session:
            self.assertEqual(session.get(Job, second).queue_reason["code"], "capacity")
            allocation = session.scalar(select(Allocation).where(Allocation.job_id == first))
            self.assertIsNone(allocation.released_at)
            self.assertFalse(allocation.termination_confirmed)


    def test_stale_epoch_callbacks_cannot_change_durable_assignment(self):
        from hf2l_jobs.controller import Controller

        self._pool()
        job_id = self._job("fenced-assignment")
        admission = Scheduler(self.database, clock=_clock).schedule()[0]
        controller = Controller(self.database, object(), object(), clock=_clock)
        self.assertTrue(controller.ack_assignment(job_id, admission.attempt_id, "owner", admission.epoch))
        self.assertTrue(controller.heartbeat(job_id, admission.attempt_id, "owner", admission.epoch))
        with self.database.transaction() as session:
            job = session.scalar(select(Job).where(Job.id == job_id).with_for_update())
            job.epoch += 1
            job.state = "RECONCILING"
            job.version += 1
        self.assertFalse(controller.check_assignment(
            "test-node-cpu", "cpu", job_id, admission.attempt_id, "owner", admission.epoch))
        self.assertFalse(controller.ack_assignment(job_id, admission.attempt_id, "owner", admission.epoch))
        self.assertFalse(controller.heartbeat(job_id, admission.attempt_id, "owner", admission.epoch))
        self.assertFalse(controller.progress(
            job_id, admission.attempt_id, "owner", admission.epoch, current_round=3, phase="publishing"))
        self.assertFalse(controller.stop_confirmation(
            job_id, admission.attempt_id, "owner", admission.epoch))
        self.assertFalse(controller.append_logs(
            job_id, admission.attempt_id, "owner", admission.epoch, data="stale attempt output"))
        with self.database.transaction() as session:
            job = session.get(Job, job_id)
            allocation = session.scalar(select(Allocation).where(Allocation.job_id == job_id))
            self.assertEqual((job.epoch, job.current_round, job.state), (2, 0, "RECONCILING"))
            self.assertFalse(allocation.termination_confirmed)
            self.assertIsNone(allocation.released_at)

    def test_successor_assignment_is_blocked_until_predecessor_release(self):
        self._pool()
        job_id = self._job("predecessor-barrier")
        admission = Scheduler(self.database, clock=_clock).schedule()[0]
        successor_attempt_id = uuid4().hex
        with self.database.transaction() as session:
            session.add(Attempt(
                id=successor_attempt_id, job_id=job_id, number=2, epoch=2, state="QUEUED"))
            predecessor = session.get(Allocation, admission.allocation_ids[0])
            predecessor.state = "QUARANTINED"
        def successor():
            return Allocation(
                id=uuid4().hex, job_id=job_id, attempt_id=successor_attempt_id,
                component_id="owner", pool_id="cpu", cpu_millicores=1000,
                memory_bytes=100, disk_bytes=100, gpu_count=0, epoch=2,
                state="RESERVED", acknowledged=False, termination_confirmed=False)
        with self.assertRaises(IntegrityError):
            with self.database.transaction() as session:
                session.add(successor())
                session.flush()
        with self.database.transaction() as session:
            predecessor = session.get(Allocation, admission.allocation_ids[0])
            self.assertIsNone(predecessor.released_at)
            self.assertFalse(predecessor.termination_confirmed)
        # The database uniqueness predicate permits the successor only after an
        # explicit release; these fixture confirmations are not executor proof.
        self._release_fixture_job(job_id)
        with self.database.transaction() as session:
            session.add(successor())
            session.flush()
        with self.database.transaction() as session:
            live = list(session.scalars(select(Allocation).where(Allocation.released_at.is_(None))))
            self.assertEqual(len(live), 1)
            self.assertEqual(live[0].attempt_id, successor_attempt_id)


if __name__ == "__main__":
    unittest.main()
