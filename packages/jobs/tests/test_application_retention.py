"""Durable storage accounting: expiration alone never releases bytes."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from sqlalchemy import func, select, update

from hf2l_jobs import models
from hf2l_jobs.application import Manager
from hf2l_jobs.database import create_database
from hf2l_jobs.domain import Error
from hf2l_jobs.retention import RetentionService


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db = create_database("sqlite:///" + str(Path(self.directory.name) / "jobs.db"))
        self.now = datetime(2026, 10, 9, tzinfo=timezone.utc)
        self.retention = RetentionService(self.db, lambda: self.now)
        self.manager = Manager(self.db, b"c" * 32, clock=lambda: self.now)
        with self.db.transaction() as session:
            session.add(models.Project(id="project", name="Project", quotas_json={"retained_bytes": 1000}))
            session.flush()
            session.add(models.Job(id="job", project_id="project", creator_id="alice", name="Completed",
                spec_json={"max_duration_seconds": 3600, "components": [], "participants": []}, spec_hash="a" * 64,
                state="SUCCEEDED", target_round=2, current_round=2, current_attempt=1,
                terminated_at=self.now - timedelta(days=90), artifacts_expire_at=self.now))
            session.flush()
            session.add(models.JobMember(job_id="job", principal_id="alice", role="admin"))
            session.add(models.ProvisioningResource(id="resource", job_id="job", component_id="owner",
                kind="code_snapshot", external_id="trusted-owned-root", ownership_json={"job_id": "job"},
                state="ready", retained=True))
            session.add(models.Event(job_id="job", sequence=1, kind="job.succeeded", data_json={}))

    def tearDown(self):
        self.db.close(); self.directory.cleanup()

    def budget(self):
        with self.db.transaction() as session:
            return session.get(models.Project, "project").retained_bytes

    def test_actual_retained_copy_is_charged_once(self):
        self.assertTrue(self.retention.charge_resource("resource", "job", 600))
        self.assertFalse(self.retention.charge_resource("resource", "job", 600))
        self.assertEqual(self.budget(), 600)
        with self.assertRaises(Error) as result:
            self.retention.charge_resource("resource", "job", 601)
        self.assertEqual(result.exception.code, "retained_resource_charge_conflict")
        self.assertEqual(self.budget(), 600)

    def test_quota_failure_rolls_back_resource_and_counter(self):
        with self.assertRaises(Error) as result:
            self.retention.charge_resource("resource", "job", 1001)
        self.assertEqual(result.exception.code, "retained_storage_quota_exceeded")
        self.assertEqual(self.budget(), 0)
        with self.db.transaction() as session:
            self.assertNotIn("retention_charged_bytes", session.get(models.ProvisioningResource, "resource").details_json)

    def test_ownership_and_confirmed_deletion_are_required(self):
        self.retention.charge_resource("resource", "job", 500)
        with self.assertRaises(Error) as result:
            self.retention.confirm_resource_deleted("resource", "job")
        self.assertEqual(result.exception.code, "resource_deletion_unconfirmed")
        self.assertEqual(self.budget(), 500)
        with self.db.transaction() as session:
            row = session.get(models.ProvisioningResource, "resource")
            row.state = "deleted"; row.deleted_at = self.now
        self.assertTrue(self.retention.confirm_resource_deleted("resource", "job"))
        self.assertFalse(self.retention.confirm_resource_deleted("resource", "job"))
        self.assertEqual(self.budget(), 0)

    def test_expiry_enqueues_once_without_releasing_storage_or_metadata(self):
        self.retention.charge_resource("resource", "job", 600)
        self.assertEqual(self.retention.request_expiry(), ["job"])
        self.assertEqual(self.retention.request_expiry(), [])
        self.assertEqual(self.budget(), 600)
        with self.db.transaction() as session:
            job = session.get(models.Job, "job")
            self.assertEqual(job.cleanup_status, "expiry_pending")
            self.assertIsNone(job.purged_at)
            operation = session.scalar(select(models.Outbox))
            self.assertEqual(operation.topic, "expire_artifacts")
            self.assertEqual(session.scalar(select(func.count()).select_from(models.Outbox)), 1)

    def test_nonterminal_or_future_expiry_never_deletes(self):
        with self.db.transaction() as session:
            job = session.get(models.Job, "job"); job.state = "RECONCILING"
        self.assertEqual(self.retention.request_expiry(), [])
        with self.db.transaction() as session:
            job = session.get(models.Job, "job"); job.state = "SUCCEEDED"; job.artifacts_expire_at = self.now + timedelta(seconds=1)
        self.assertEqual(self.retention.request_expiry(), [])

    def test_database_logs_are_byte_charged_and_wiped_only_after_owned_cleanup(self):
        self.retention.charge_resource("resource", "job", 600)
        with self.db.transaction() as session:
            project = session.get(models.Project, "project")
            chunk = models.LogChunk(job_id="job", component="owner", sequence=1, data="é" * 100)
            session.add(chunk)
            self.retention.charge_log_in_transaction(session, project, chunk)
            session.add(models.Artifact(id="artifact", job_id="job", kind="checkpoint", name="result.npz",
                size_bytes=600, sha256="b" * 64, storage_key="opaque", state="available"))
        self.assertEqual(self.budget(), 800)
        with self.assertRaises(Error) as result:
            self.retention.confirm_job_data_deleted("job")
        self.assertEqual(result.exception.code, "resource_deletion_unconfirmed")
        self.assertEqual(self.budget(), 800)
        with self.db.transaction() as session:
            resource = session.get(models.ProvisioningResource, "resource")
            resource.state = "deleted"; resource.deleted_at = self.now
        self.assertEqual(self.retention.confirm_job_data_deleted("job"), 800)
        self.assertEqual(self.retention.confirm_job_data_deleted("job"), 0)
        self.assertEqual(self.budget(), 0)
        with self.db.transaction() as session:
            job = session.get(models.Job, "job")
            self.assertEqual(job.name, "Completed")
            self.assertEqual(job.cleanup_status, "expired")
            self.assertIsNone(job.purged_at)
            self.assertEqual(session.get(models.Artifact, "artifact").sha256, "b" * 64)
            self.assertEqual(session.get(models.Artifact, "artifact").state, "deleted")
            chunk = session.scalar(select(models.LogChunk)); self.assertEqual(chunk.data, ""); self.assertEqual(chunk.charged_bytes, 0)
            self.assertIsNotNone(session.get(models.JobMember, ("job", "alice")))
            self.assertGreater(session.scalar(select(func.count()).select_from(models.Event)), 1)

    def test_log_quota_rejection_rolls_back_new_chunk(self):
        self.retention.charge_resource("resource", "job", 950)
        with self.assertRaises(Error):
            with self.db.transaction() as session:
                project = session.get(models.Project, "project")
                chunk = models.LogChunk(job_id="job", component="owner", sequence=1, data="x" * 100)
                session.add(chunk); self.retention.charge_log_in_transaction(session, project, chunk)
        self.assertEqual(self.budget(), 950)
        with self.db.transaction() as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(models.LogChunk)), 0)

    def test_artifact_locator_must_be_owned_and_confined(self):
        with self.db.transaction() as session:
            session.get(models.Job, "job").artifacts_expire_at = self.now + timedelta(days=90)
            session.add(models.Artifact(id="artifact", job_id="job", kind="checkpoint", name="result.npz",
                size_bytes=10, sha256="b" * 64, storage_key="never-return-me", state="available",
                locator_json={"kind": "local", "resource_id": "resource", "relative_path": "outputs/result.npz"}))
        descriptor = self.manager.artifact_storage("alice", "job", "artifact")
        self.assertNotIn("storage_key", descriptor)
        self.assertEqual(descriptor["locator"]["resource_id"], "resource")
        for path in ("../foreign/result", "/host/result", "a//b", "a/./b", "a\\b"):
            with self.db.transaction() as session:
                # Simulate a malformed legacy/trusted-store row that bypassed ORM validation.
                session.execute(update(models.Artifact).where(models.Artifact.id == "artifact").values(
                    locator_json={"kind": "local", "resource_id": "resource", "relative_path": path}))
            with self.assertRaises(Error) as result:
                self.manager.artifact_storage("alice", "job", "artifact")
            self.assertEqual(result.exception.code, "invalid_artifact_locator")


    def test_zero_byte_retired_exchange_provenance_survives_expiration(self):
        self.retention.charge_resource("resource", "job", 600)
        with self.db.transaction() as session:
            source = session.get(models.ProvisioningResource, "resource")
            source.state = "deleted"; source.deleted_at = self.now
            session.add(models.ProvisioningResource(id="space", job_id="job", component_id="owner",
                kind="exchange_space", external_id="space-id", ownership_json={"job_id": "job"},
                state="retired", retained=True, size_bytes=0))
        self.assertEqual(self.retention.confirm_job_data_deleted("job"), 600)
        with self.db.transaction() as session:
            row = session.get(models.ProvisioningResource, "space")
            self.assertEqual(row.state, "retired")
            self.assertIsNone(row.deleted_at)
            self.assertEqual(session.get(models.Job, "job").name, "Completed")

    def test_retired_raw_source_is_not_accepted_as_confirmed_deletion(self):
        self.retention.charge_resource("resource", "job", 600)
        with self.db.transaction() as session:
            session.get(models.ProvisioningResource, "resource").state = "retired"
        with self.assertRaises(Error) as result:
            self.retention.confirm_job_data_deleted("job")
        self.assertEqual(result.exception.code, "resource_deletion_unconfirmed")
        self.assertEqual(self.budget(), 600)

    def test_job_expiry_disables_artifact_with_no_individual_expiry(self):
        with self.db.transaction() as session:
            session.add(models.Artifact(id="artifact", job_id="job", kind="checkpoint", name="result.npz",
                size_bytes=10, sha256="b" * 64, storage_key="opaque", state="available", expires_at=None))
        view = self.manager.get_artifact("alice", "job", "artifact")
        self.assertFalse(view["download_available"])
        self.assertEqual(view["state"], "expired")
        self.assertFalse(self.manager.list_artifacts("alice", "job")["items"][0]["download_available"])


    def test_source_budget_is_reserved_before_copy_and_settled_idempotently(self):
        self.assertTrue(self.retention.reserve_resource("resource", "job", 900))
        self.assertEqual(self.budget(), 900)
        self.assertFalse(self.retention.reserve_resource("resource", "job", 900))
        self.assertTrue(self.retention.settle_resource("resource", "job", 600))
        self.assertEqual(self.budget(), 600)
        self.assertFalse(self.retention.settle_resource("resource", "job", 600))
        self.assertFalse(self.retention.reserve_resource("resource", "job", 900))
        self.assertEqual(self.budget(), 600)
        with self.db.transaction() as session:
            row = session.get(models.ProvisioningResource, "resource")
            self.assertEqual(row.size_bytes, 600)
            self.assertEqual(row.details_json["retention_reservation_bytes"], 900)
            self.assertTrue(row.details_json["retention_charge_settled"])

    def test_copy_exceeding_reservation_cannot_free_budget(self):
        self.retention.reserve_resource("resource", "job", 900)
        with self.assertRaises(Error) as result:
            self.retention.settle_resource("resource", "job", 901)
        self.assertEqual(result.exception.code, "retained_resource_exceeds_reservation")
        self.assertEqual(self.budget(), 900)
        with self.db.transaction() as session:
            row = session.get(models.ProvisioningResource, "resource")
            row.state = "deleted"; row.deleted_at = self.now
        self.retention.confirm_resource_deleted("resource", "job")
        self.assertEqual(self.budget(), 0)

    def test_bound_pool_budget_includes_active_and_retained_storage_before_copy(self):
        with self.db.transaction() as session:
            session.add(models.Pool(id="pool", name="Pool", node_id="node", cpu_millicores=2000,
                memory_bytes=1000, disk_bytes=800, sandbox_profiles=["runsc-cpu-v1"]))
            resource = session.get(models.ProvisioningResource, "resource")
            resource.details_json = {"pool_id": "pool"}
            attempt = models.Attempt(id="attempt", job_id="job", number=1, epoch=1, state="RUNNING")
            session.add(attempt); session.flush()
            session.add(models.Allocation(job_id="job", attempt_id=attempt.id, component_id="owner", pool_id="pool",
                cpu_millicores=100, memory_bytes=100, disk_bytes=200, epoch=1, state="QUARANTINED"))
        with self.assertRaises(Error) as result:
            self.retention.reserve_resource("resource", "job", 700)
        self.assertEqual(result.exception.code, "retained_pool_storage_unavailable")
        self.assertEqual(self.budget(), 0)
        self.retention.reserve_resource("resource", "job", 600)
        with self.db.transaction() as session:
            self.assertEqual(self.retention.pool_used_bytes(session, "pool"), 800)
        self.retention.settle_resource("resource", "job", 400)
        with self.db.transaction() as session:
            self.assertEqual(self.retention.pool_used_bytes(session, "pool"), 600)

    def test_failed_materialization_keeps_conservative_charge_until_confirmed_cleanup(self):
        self.retention.reserve_resource("resource", "job", 900)
        with self.assertRaises(Error):
            self.retention.confirm_job_data_deleted("job")
        self.assertEqual(self.budget(), 900)
        with self.db.transaction() as session:
            row = session.get(models.ProvisioningResource, "resource")
            row.state = "deleted"; row.deleted_at = self.now
        self.assertEqual(self.retention.confirm_job_data_deleted("job"), 900)
        self.assertEqual(self.budget(), 0)


    def test_prepaid_collection_transfers_to_actual_copies_once_without_double_charge(self):
        self.retention.reserve_resource("resource", "job", 900)
        with self.db.transaction() as session:
            parent = session.get(models.ProvisioningResource, "resource")
            project = session.get(models.Project, "project")
            children = [models.ProvisioningResource(id="copy1", job_id="job", component_id="owner", kind="retained_output",
                external_id="copy-one", ownership_json={"job_id": "job"}, state="ready", size_bytes=300),
                models.ProvisioningResource(id="copy2", job_id="job", component_id="owner", kind="retained_output",
                external_id="copy-two", ownership_json={"job_id": "job"}, state="ready", size_bytes=400)]
            session.add_all(children)
            result = self.retention.transfer_reserved_in_transaction(session, parent, project, children)
            self.assertEqual(result, {"transferred_bytes": 700, "released_bytes": 200})
        self.assertEqual(self.budget(), 700)
        with self.db.transaction() as session:
            parent = session.get(models.ProvisioningResource, "resource")
            children = [session.get(models.ProvisioningResource, key) for key in ("copy1", "copy2")]
            result = self.retention.transfer_reserved_in_transaction(session, parent, session.get(models.Project, "project"), children)
            self.assertEqual(result, {"transferred_bytes": 0, "released_bytes": 0})
            self.assertEqual(parent.size_bytes, 0)
            for child in children:
                self.assertEqual(child.details_json["retention_reservation_source"], "resource")
        self.assertEqual(self.budget(), 700)
        with self.db.transaction() as session:
            for key in ("resource", "copy1", "copy2"):
                row = session.get(models.ProvisioningResource, key); row.state = "deleted"; row.deleted_at = self.now
        self.assertEqual(self.retention.confirm_job_data_deleted("job"), 700)
        self.assertEqual(self.budget(), 0)

    def test_over_budget_collection_rolls_back_every_transfer_and_keeps_reservation(self):
        self.retention.reserve_resource("resource", "job", 900)
        with self.assertRaises(Error) as result:
            with self.db.transaction() as session:
                child = models.ProvisioningResource(id="copy", job_id="job", component_id="owner", kind="retained_output",
                    external_id="oversize", ownership_json={"job_id": "job"}, state="ready", size_bytes=901)
                session.add(child)
                self.retention.transfer_reserved_in_transaction(session, session.get(models.ProvisioningResource, "resource"),
                    session.get(models.Project, "project"), [child])
        self.assertEqual(result.exception.code, "retained_resource_exceeds_reservation")
        self.assertEqual(self.budget(), 900)
        with self.db.transaction() as session:
            self.assertIsNone(session.get(models.ProvisioningResource, "copy"))
            self.assertFalse(session.get(models.ProvisioningResource, "resource").details_json["retention_charge_settled"])

    def test_postgresql_numeric_aggregate_is_exact_json_integer_not_fractional(self):
        from decimal import Decimal
        from unittest.mock import patch
        import json
        with self.db.transaction() as session:
            with patch.object(session, "scalar", return_value=Decimal("9007199254740993")):
                used = RetentionService.pool_used_bytes(session, "cpu")
                self.assertIs(type(used), int)
                self.assertEqual(json.loads(json.dumps({"used_bytes": used}))["used_bytes"], 9007199254740993)
            for invalid in (Decimal("1.5"), Decimal("NaN"), Decimal("-1"), 1.0, True):
                with patch.object(session, "scalar", return_value=invalid):
                    with self.assertRaises(ValueError):
                        RetentionService.pool_used_bytes(session, "cpu")

    def test_one_byte_collection_keeps_conservative_physical_cap_until_confirmed_purge(self):
        self.retention.reserve_resource("resource", "job", 900)
        with self.db.transaction() as session:
            parent = session.get(models.ProvisioningResource, "resource")
            parent.kind = "collection_budget"
            child = models.ProvisioningResource(id="one-byte", job_id="job", component_id="owner",
                kind="retained_output", external_id="owned-result", ownership_json={"job_id": "job"},
                state="ready", retained=True, size_bytes=1)
            session.add(child)
            result = self.retention.transfer_reserved_in_transaction(session, parent,
                session.get(models.Project, "project"), [child], retain_unused=True)
            self.assertEqual(result, {"transferred_bytes": 1, "released_bytes": 0})
            self.assertEqual(parent.size_bytes, 899)
            self.assertEqual(parent.details_json["retention_charged_bytes"], 899)
            self.assertTrue(parent.details_json["retention_conservative_footprint"])
        self.assertEqual(self.budget(), 900)
        with self.db.transaction() as session:
            parent = session.get(models.ProvisioningResource, "resource")
            child = session.get(models.ProvisioningResource, "one-byte")
            self.assertEqual(self.retention.transfer_reserved_in_transaction(session, parent,
                session.get(models.Project, "project"), [child], retain_unused=True),
                {"transferred_bytes": 0, "released_bytes": 0})
            session.add(models.ProvisioningResource(id="another", job_id="job", component_id="owner",
                kind="retained_output", external_id="other-root", ownership_json={"job_id": "job"}, state="ready"))
        with self.assertRaises(Error) as result:
            self.retention.charge_resource("another", "job", 101)
        self.assertEqual(result.exception.code, "retained_storage_quota_exceeded")
        with self.assertRaises(Error):
            with self.db.transaction() as session:
                self.retention.transfer_reserved_in_transaction(session,
                    session.get(models.ProvisioningResource, "resource"), session.get(models.Project, "project"),
                    [], retain_unused=True)
        with self.assertRaises(Error):
            self.retention.confirm_job_data_deleted("job")
        self.assertEqual(self.budget(), 900)
        with self.db.transaction() as session:
            for resource in session.scalars(select(models.ProvisioningResource)):
                resource.state = "deleted"; resource.deleted_at = self.now
        self.assertEqual(self.retention.confirm_job_data_deleted("job"), 900)
        self.assertEqual(self.budget(), 0)

    def log_budget(self, maximum=900):
        with self.db.transaction() as session:
            row = session.get(models.ProvisioningResource, "resource")
            row.kind = "log_budget"
            row.external_id = "hf2l-log://job/1/owner"
            row.ownership_json = {"job_id": "job", "component_id": "owner", "kind": "log_budget"}
            row.details_json = {"attempt_number": 1}
        self.retention.reserve_resource("resource", "job", maximum)

    def test_prepaid_logs_keep_cap_without_double_charge_and_bound_utf8_overflow(self):
        self.log_budget()
        with self.db.transaction() as session:
            budget = session.get(models.ProvisioningResource, "resource")
            chunk = models.LogChunk(id="first", job_id="job", attempt_number=1, component="owner", sequence=1, data="é" * 100)
            session.add(chunk)
            self.assertTrue(self.retention.charge_log_in_transaction(session, session.get(models.Project, "project"), chunk, budget=budget))
            self.assertEqual(chunk.charged_bytes, 0)
            self.assertEqual(budget.details_json["log_consumed_bytes"], 200)
        self.assertEqual(self.budget(), 900)
        with self.db.transaction() as session:
            budget = session.get(models.ProvisioningResource, "resource")
            self.assertFalse(self.retention.charge_log_in_transaction(session, session.get(models.Project, "project"),
                session.get(models.LogChunk, "first"), budget=budget))
            chunk = models.LogChunk(id="overflow", job_id="job", attempt_number=1, component="owner", sequence=2, data="x" * 1000)
            session.add(chunk)
            self.retention.charge_log_in_transaction(session, session.get(models.Project, "project"), chunk, budget=budget)
            self.assertLessEqual(len(chunk.data.encode("utf-8")), 700)
            self.assertIn("manager log budget exhausted", chunk.data)
            self.assertTrue(budget.details_json["log_truncated"])
            self.assertTrue(budget.details_json["log_budget_exhausted"])
            after = models.LogChunk(id="after", job_id="job", attempt_number=1, component="owner", sequence=3, data="omitted")
            session.add(after)
            self.retention.charge_log_in_transaction(session, session.get(models.Project, "project"), after, budget=budget)
            self.assertEqual(after.data, "")
            self.assertEqual(after.charged_bytes, 0)
        self.assertEqual(self.budget(), 900)

    def test_prepaid_logs_refuse_foreign_component_without_writing_or_charging(self):
        self.log_budget()
        with self.assertRaises(Error) as result:
            with self.db.transaction() as session:
                chunk = models.LogChunk(job_id="job", attempt_number=1, component="foreign", sequence=1, data="secret")
                session.add(chunk)
                self.retention.charge_log_in_transaction(session, session.get(models.Project, "project"), chunk,
                    budget=session.get(models.ProvisioningResource, "resource"))
        self.assertEqual(result.exception.code, "retained_resource_ownership_mismatch")
        self.assertEqual(self.budget(), 900)
        with self.db.transaction() as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(models.LogChunk)), 0)

    def test_prepaid_log_deletion_and_budget_release_are_atomic_after_other_cleanup(self):
        self.log_budget()
        with self.db.transaction() as session:
            chunk = models.LogChunk(job_id="job", attempt_number=1, component="owner", sequence=1, data="retained raw output")
            session.add(chunk)
            self.retention.charge_log_in_transaction(session, session.get(models.Project, "project"), chunk,
                budget=session.get(models.ProvisioningResource, "resource"))
            session.add(models.ProvisioningResource(id="unknown", job_id="job", component_id="owner",
                kind="source", external_id="owned-source", ownership_json={"job_id": "job"}, retained=True, state="ready"))
        with self.assertRaises(Error):
            self.retention.confirm_job_data_deleted("job")
        with self.db.transaction() as session:
            self.assertEqual(session.scalar(select(models.LogChunk)).data, "retained raw output")
            self.assertNotEqual(session.get(models.ProvisioningResource, "resource").state, "deleted")
            other = session.get(models.ProvisioningResource, "unknown")
            other.state = "deleted"; other.deleted_at = self.now
        self.assertEqual(self.retention.confirm_job_data_deleted("job"), 900)
        with self.db.transaction() as session:
            self.assertEqual(session.scalar(select(models.LogChunk)).data, "")
            self.assertIsNotNone(session.scalar(select(models.LogChunk)).deleted_at)
            self.assertEqual(session.get(models.ProvisioningResource, "resource").state, "deleted")
        self.assertEqual(self.retention.confirm_job_data_deleted("job"), 0)
