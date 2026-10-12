"""Checkpoint storage cannot escape project/pool quotas or free on termination."""
from __future__ import annotations

from copy import deepcopy
from datetime import timedelta
import unittest

from sqlalchemy import select

from hf2l_jobs.blob_budget import (KIND, bind_blob_space, checkpoint_budget,
    confirm_blob_cleanup, confirm_unused_blob_budget, external_id, plan_blob_budget, require_blob_budget)
from hf2l_jobs.database import create_database
from hf2l_jobs.domain import Error, JobSpec, utcnow
from hf2l_jobs.models import Allocation, Attempt, Job, Pool, Project, ProvisioningOperation, ProvisioningResource
from hf2l_jobs.resources import ResourceError, ResourceLedger
from hf2l_jobs.retention import RetentionService
from hf2l_jobs.scheduler import Scheduler


def spec(*, disk=10, target=2, participants=2):
    return JobSpec.model_validate({"project_id": "project", "name": "Budget job",
        "source_id": "approved", "source_commit": "a" * 40, "runtime_image": "runtime",
        "plugin": "plugin", "target_round": target, "max_duration_seconds": 600,
        "participants": [{"participant_id": "p" + str(i), "dataset_binding": "data" + str(i)}
                         for i in range(participants)],
        "components": [{"component_id": "leader", "role": "owner", "resources": {
            "pool_id": "compute", "cpu_millicores": 10, "memory_bytes": 10, "disk_bytes": disk}}]})


class BlobBudgetTests(unittest.TestCase):
    def setUp(self):
        self.database = create_database("sqlite://")
        self.addCleanup(self.database.close)
        self.ledger = ResourceLedger(self.database)
        self.retention = RetentionService(self.database)
        with self.database.transaction() as session:
            session.add(Project(id="project", name="Project", quotas_json={"disk_bytes": 1000, "retained_bytes": 1000}))
            session.add(Pool(id="compute", name="Compute", node_id="node", cpu_millicores=1000,
                memory_bytes=1000, disk_bytes=1000, sandbox_profiles=["runsc-cpu-v1"], healthy=True))
            session.add(Pool(id="objects", name="Approved object capacity", node_id="object-service",
                cpu_millicores=0, memory_bytes=0, disk_bytes=140, healthy=True, details_json={"object_store": True}))
            session.flush()
        self.job = self.new_job("job")

    def new_job(self, jid):
        specification = spec()
        with self.database.transaction() as session:
            job = Job(id=jid, project_id="project", creator_id="human", name="Budget job",
                spec_json=specification.to_dict(), spec_hash=specification.digest,
                state="QUEUED", target_round=2, current_attempt=1, attempt_count=1,
                created_at=utcnow() + timedelta(seconds=1 if jid != "job" else 0))
            session.add(job)
            session.flush()
            session.add(Attempt(id="attempt-" + jid, job_id=jid, number=1, epoch=1))
        return job

    def reserve(self, job=None):
        job = job or self.job
        plan = plan_blob_budget(job, "objects", self.ledger.resources(job.id))
        rid = self.ledger.own(job_id=job.id, attempt_id="attempt-" + job.id,
            component_id=plan["component_id"], kind=KIND, external_id=plan["external_id"],
            details=plan["details"], retained=True)
        self.retention.reserve_resource(rid, job.id, plan["max_bytes"])
        return rid

    def bind(self, job=None):
        job = job or self.job
        sid = "space-" + job.id
        self.ledger.own(job_id=job.id, attempt_id="attempt-" + job.id, component_id="leader",
            kind="exchange_space", external_id=sid, details={"job_id": job.id}, retained=True)
        bind_blob_space(self.database, job, sid, space_policy={"id": sid, "quota_bytes": 70, "principal_quota_bytes": 30})
        return sid

    def terminal(self, job=None):
        job = job or self.job
        with self.database.transaction() as session:
            current = session.get(Job, job.id)
            current.state = "SUCCEEDED"
            current.terminated_at = utcnow()
            for row in session.scalars(select(Allocation).where(Allocation.job_id == job.id)):
                row.state = "RELEASED"
                row.released_at = utcnow()
                row.termination_confirmed = True
                row.details_json = {**row.details_json, "storage_deleted": True}
        job.state = "SUCCEEDED"

    def held(self, expected=70):
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.get(Project, "project").retained_bytes, expected)
            self.assertEqual(RetentionService.pool_used_bytes(session, "objects"), expected)

    def test_absolute_rounds_include_initial_global_and_all_external_inputs(self):
        budget = checkpoint_budget(spec(disk=10, target=2, participants=2))
        self.assertEqual((budget.quota_bytes, budget.principal_quota_bytes, budget.component_id), (70, 30, "leader"))
        self.assertEqual(checkpoint_budget(spec(disk=10, target=1, participants=0)).quota_bytes, 20)

    def test_budget_overflow_is_rejected_without_wrapping_or_float_rounding(self):
        with self.assertRaisesRegex(ResourceError, "byte range"):
            checkpoint_budget(spec(disk=1 << 50, target=1_000_000))

    def test_an_operator_must_approve_object_storage_pool(self):
        with self.assertRaisesRegex(ResourceError, "approved Exchange"):
            plan_blob_budget(self.job, None)

    def test_retry_retains_first_pool_and_exact_cap(self):
        self.reserve()
        plan = plan_blob_budget(self.job, "different-approved-pool", self.ledger.resources("job"))
        self.assertEqual((plan["pool_id"], plan["max_bytes"]), ("objects", 70))
        self.assertEqual(require_blob_budget(self.database, self.job)["quota_bytes"], 70)
        self.held()

    def test_tampered_budget_or_foreign_ownership_cannot_be_adopted(self):
        self.reserve()
        original = self.ledger.resources("job")
        for field, value in (("quota_bytes", 71), ("principal_quota_bytes", 31), ("spec_digest", "b" * 64)):
            rows = deepcopy(original)
            rows[0]["details"][field] = value
            with self.subTest(field=field), self.assertRaises(ResourceError):
                plan_blob_budget(self.job, "objects", rows)
        rows = deepcopy(original)
        rows[0]["ownership"]["job_id"] = "foreign"
        with self.assertRaises(ResourceError):
            plan_blob_budget(self.job, "objects", rows)

    def test_namespace_cannot_exist_before_full_prepaid_reservation(self):
        with self.assertRaisesRegex(ResourceError, "not been reserved"):
            require_blob_budget(self.database, self.job)
        rid = self.reserve()
        with self.database.transaction() as session:
            row = session.get(ProvisioningResource, rid)
            row.size_bytes = 69
        with self.assertRaisesRegex(ResourceError, "fully prepaid"):
            require_blob_budget(self.database, self.job)

    def test_project_quota_refusal_leaves_no_charge(self):
        with self.database.transaction() as session:
            session.get(Project, "project").quotas_json = {"retained_bytes": 69}
        with self.assertRaises(Error) as caught:
            self.reserve()
        self.assertEqual(caught.exception.code, "retained_storage_quota_exceeded")
        self.held(0)

    def test_object_store_capacity_refusal_leaves_no_charge(self):
        with self.database.transaction() as session:
            session.get(Pool, "objects").disk_bytes = 69
        with self.assertRaises(Error) as caught:
            self.reserve()
        self.assertEqual(caught.exception.code, "retained_pool_storage_unavailable")
        self.held(0)

    def test_retirement_with_pending_cleanup_keeps_the_whole_budget(self):
        self.reserve()
        sid = self.bind()
        self.terminal()
        receipt = {"space_id": sid, "job_id": "job", "status": "retired", "cleanup_pending": True}
        self.assertFalse(confirm_blob_cleanup(self.database, self.job, sid, receipt))
        self.held()
        self.assertEqual(require_blob_budget(self.database, self.job, for_cleanup=True)["space_id"], sid)

    def test_foreign_or_incomplete_cleanup_receipt_never_releases(self):
        self.reserve()
        sid = self.bind()
        self.terminal()
        receipt = {"space_id": sid, "job_id": "job", "status": "retired", "cleanup_pending": False}
        for field, value in (("space_id", "foreign"), ("job_id", "foreign"), ("status", "active"),
                             ("cleanup_pending", 0), ("cleanup_pending", None)):
            with self.subTest(field=field, value=value):
                self.assertFalse(confirm_blob_cleanup(self.database, self.job, sid, {**receipt, field: value}))
                self.held()

    def test_running_job_cannot_release_even_a_retired_namespace(self):
        self.reserve()
        sid = self.bind()
        receipt = {"space_id": sid, "job_id": "job", "status": "retired", "cleanup_pending": False}
        with self.assertRaisesRegex(ResourceError, "terminal"):
            confirm_blob_cleanup(self.database, self.job, sid, receipt)
        self.held()

    def test_terminal_label_does_not_override_live_allocation_barrier(self):
        self.reserve()
        sid = self.bind()
        self.terminal()
        with self.database.transaction() as session:
            session.add(Allocation(id="still-live", job_id="job", attempt_id="attempt-job", component_id="leader",
                pool_id="compute", cpu_millicores=10, memory_bytes=10, disk_bytes=10,
                state="QUARANTINED", epoch=1))
        receipt = {"space_id": sid, "job_id": "job", "status": "retired", "cleanup_pending": False}
        with self.assertRaisesRegex(ResourceError, "allocation release"):
            confirm_blob_cleanup(self.database, self.job, sid, receipt)
        self.assertFalse(confirm_unused_blob_budget(self.database, self.job))
        self.held()

    def test_namespace_binding_rejects_foreign_and_changed_owned_spaces(self):
        self.reserve()
        with self.assertRaisesRegex(ResourceError, "another namespace"):
            bind_blob_space(self.database, self.job, "foreign-space", space_policy={"id": "foreign-space", "quota_bytes": 70, "principal_quota_bytes": 30})
        sid = self.bind()
        bind_blob_space(self.database, self.job, sid, space_policy={"id": sid, "quota_bytes": 70, "principal_quota_bytes": 30})
        self.ledger.own(job_id="job", attempt_id="attempt-job", component_id="leader", kind="exchange_space",
            external_id="changed-space", details={"job_id": "job"})
        with self.assertRaisesRegex(ResourceError, "another namespace"):
            bind_blob_space(self.database, self.job, "changed-space", space_policy={"id": "changed-space", "quota_bytes": 70, "principal_quota_bytes": 30})
        self.held()

    def test_confirmed_deletion_releases_once_and_preserves_neighbor_budget(self):
        first_id = self.reserve()
        sid = self.bind()
        other = self.new_job("neighbor")
        self.reserve(other)
        other_sid = self.bind(other)
        self.held(140)
        self.terminal()
        receipt = {"space_id": sid, "job_id": "job", "status": "retired", "cleanup_pending": False}
        self.assertTrue(confirm_blob_cleanup(self.database, self.job, sid, receipt))
        self.assertTrue(confirm_blob_cleanup(self.database, self.job, sid, receipt))
        self.held()
        self.assertEqual(require_blob_budget(self.database, other)["space_id"], other_sid)
        with self.database.transaction(immediate=False) as session:
            row = session.get(ProvisioningResource, first_id)
            self.assertEqual(row.state, "deleted")
            self.assertTrue(row.details_json["blob_cleanup_confirmed"])
            self.assertTrue(row.details_json["retention_charge_released"])

    def test_completed_job_blocks_queue_until_confirmed_owned_blob_cleanup(self):
        second = self.new_job("queued")
        with self.database.transaction() as session:
            session.get(Pool, "objects").disk_bytes = 100
        planner = lambda job: [plan_blob_budget(job, "objects", self.ledger.resources(job.id))]
        scheduler = Scheduler(self.database, admission_storage=planner)
        admitted = scheduler.schedule(limit=2)
        self.assertEqual([row.job_id for row in admitted], ["job"])
        sid = self.bind()
        self.terminal()
        self.assertEqual(scheduler.schedule(limit=2), [])
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.get(Job, second.id).queue_reason["code"], "capacity")
        receipt = {"space_id": sid, "job_id": "job", "status": "retired", "cleanup_pending": False}
        self.assertTrue(confirm_blob_cleanup(self.database, self.job, sid, receipt))
        self.assertEqual([row.job_id for row in scheduler.schedule(limit=2)], [second.id])

    def test_namespace_actual_quota_must_match_prepaid_cap(self):
        self.reserve()
        sid = self.bind()
        for field, value in (("id", "foreign"), ("quota_bytes", 71), ("principal_quota_bytes", 31)):
            policy = {"id": sid, "quota_bytes": 70, "principal_quota_bytes": 30, field: value}
            with self.subTest(field=field), self.assertRaisesRegex(ResourceError, "namespace quota"):
                bind_blob_space(self.database, self.job, sid, space_policy=policy)
        self.held()

    def test_unused_budget_releases_only_terminal_job_with_no_create_request(self):
        self.reserve()
        self.assertFalse(confirm_unused_blob_budget(self.database, self.job))
        self.held()
        self.terminal()
        self.assertTrue(confirm_unused_blob_budget(self.database, self.job))
        self.assertTrue(confirm_unused_blob_budget(self.database, self.job))
        self.held(0)

    def test_any_durable_create_operation_prevents_unused_release(self):
        self.reserve()
        self.terminal()
        with self.database.transaction() as session:
            operation = ProvisioningOperation(id="create-operation", job_id="job", attempt_id="attempt-job",
                component_id="leader", operation="exchange_space", idempotency_key="original-key",
                state="planned", desired_json={"name": "hf2l-job"}, observed_json={})
            session.add(operation)
        for state in ("planned", "executing", "unknown", "ready"):
            with self.subTest(state=state):
                with self.database.transaction() as session:
                    session.get(ProvisioningOperation, "create-operation").state = state
                self.assertFalse(confirm_unused_blob_budget(self.database, self.job))
                self.held()

    def test_any_historical_namespace_prevents_unused_release(self):
        self.reserve()
        self.bind()
        self.terminal()
        self.assertFalse(confirm_unused_blob_budget(self.database, self.job))
        self.held()

    def test_compute_pool_cannot_impersonate_approved_object_capacity(self):
        self.reserve()
        with self.database.transaction() as session:
            session.get(Pool, "objects").details_json = {"object_store": False}
        with self.assertRaisesRegex(ResourceError, "distinct approved"):
            require_blob_budget(self.database, self.job)
        self.held()


if __name__ == "__main__":
    unittest.main()
