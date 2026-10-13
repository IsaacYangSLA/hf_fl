"""Queued cancellation must prove absence of effects before acknowledging cleanup."""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from sqlalchemy import select

import test_application as application_fixture
from hf2l_jobs import models
from hf2l_jobs.controller import Controller
from hf2l_jobs.provisioning import Provisioner


class StrictManagedCleanup(Provisioner):
    """The production managed adapter requires both proofs before private cleanup."""
    def cleanup(self, job, attempt):
        if not attempt.revocation_confirmed or not attempt.termination_confirmed:
            return False
        completed = super().cleanup(job, attempt)
        if completed and getattr(self, "supervisor", None) is not None:
            for component in job.spec_json["components"]:
                if component["role"] != "build" and not self.supervisor.stop(
                        job.id, attempt.id, component["component_id"], termination_confirmed=True):
                    return False
        return completed


class QueuedCancellationCleanupTests(unittest.TestCase):
    def setUp(self):
        self.fixture = application_fixture.ApplicationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.database = self.fixture.db
        self.manager = self.fixture.manager
        self.exchange = Mock()
        self.executor = Mock()
        self.provisioner = StrictManagedCleanup(
            self.database, self.exchange, SimpleNamespace(),
            Path(self.fixture.directory.name) / "resources",
            workload_issuer="https://manager.example.invalid/workloads")
        self.controller = Controller(self.database, self.executor, self.provisioner,
                                     clock=lambda: self.fixture.now)
        # Keep the scheduler from adding execution effects while testing cancellation.
        with self.database.transaction() as session:
            session.get(models.Pool, "cpu").healthy = False

    def create(self, key="create"):
        job = self.fixture.create(key=key)
        with self.database.transaction(immediate=False) as session:
            attempt = session.scalar(select(models.Attempt).where(
                models.Attempt.job_id == job["id"]))
            session.expunge(attempt)
        return job, attempt

    def read(self, job_id):
        with self.database.transaction(immediate=False) as session:
            job = session.get(models.Job, job_id)
            attempt = session.scalar(select(models.Attempt).where(models.Attempt.job_id == job_id, models.Attempt.number == job.current_attempt))
            events = list(session.scalars(select(models.LifecycleEvent).where(
                models.LifecycleEvent.job_id == job_id)))
            session.expunge_all()
        return job, attempt, events

    def cancel_and_run(self, job):
        self.manager.cancel("alice", job["id"], job["version"], "cancel-" + job["id"])
        self.controller.run_once()
        return self.read(job["id"])

    def assert_no_synthetic_proof(self, job_id):
        job, attempt, events = self.read(job_id)
        self.assertNotEqual(job.cleanup_status, "complete")
        self.assertNotIn("never_started_cleanup", attempt.details_json)
        self.assertFalse(any(event.kind == "attempt.never_started_cleanup_confirmed" for event in events))

    def operation(self, job, attempt, operation, state):
        with self.database.transaction() as session:
            session.add(models.ProvisioningOperation(
                job_id=job["id"], attempt_id=attempt.id, component_id="owner",
                operation=operation, idempotency_key=f"{job['id']}:{attempt.id}:{attempt.epoch}:owner:{operation}",
                state=state, desired_json={}, observed_json={}, last_error="capacity" if state == "refused" else None))

    def test_queued_cancel_completes_real_private_cleanup_without_external_effects(self):
        job, _ = self.create()
        result, attempt, events = self.cancel_and_run(job)
        self.assertEqual((result.state, result.cleanup_status), ("CANCELLED", "complete"))
        self.assertTrue(attempt.revocation_confirmed)
        self.assertTrue(attempt.termination_confirmed)
        self.assertEqual(attempt.publication_status, "absent")
        self.assertEqual(sum(event.kind == "attempt.never_started_cleanup_confirmed" for event in events), 1)
        self.assertEqual(self.exchange.mock_calls, [])
        self.assertEqual(self.executor.mock_calls, [])
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(list(session.scalars(select(models.Allocation))), [])
            self.assertEqual(list(session.scalars(select(models.ProvisioningResource))), [])
            self.assertEqual(list(session.scalars(select(models.ProvisioningOperation))), [])
            self.assertEqual(session.get(models.Project, "project").retained_bytes, 0)

    def test_restarting_controller_preserves_one_durable_proof_and_complete_cleanup(self):
        job, _ = self.create()
        self.cancel_and_run(job)
        restarted = Controller(self.database, self.executor, self.provisioner,
                               clock=lambda: self.fixture.now)
        restarted.run_once()
        result, attempt, events = self.read(job["id"])
        self.assertEqual((result.state, result.cleanup_status), ("CANCELLED", "complete"))
        self.assertTrue(attempt.termination_confirmed and attempt.revocation_confirmed)
        self.assertEqual(sum(event.kind == "attempt.never_started_cleanup_confirmed" for event in events), 1)
        self.assertEqual(self.exchange.mock_calls, [])
        self.assertEqual(self.executor.mock_calls, [])

    def test_historical_queued_cancel_with_missing_flags_recovers_cleanup(self):
        job, attempt = self.create()
        self.controller._terminal(job["id"], "CANCELLED", "cancelled")
        result, before, _ = self.read(job["id"])
        self.assertFalse(before.termination_confirmed or before.revocation_confirmed)
        self.controller.run_once()
        result, after, events = self.read(job["id"])
        self.assertEqual(result.cleanup_status, "complete")
        self.assertTrue(after.termination_confirmed and after.revocation_confirmed)
        self.assertEqual(sum(event.kind == "attempt.never_started_cleanup_confirmed" for event in events), 1)

    def test_any_reserve_intent_prevents_synthetic_cleanup(self):
        for state in ("planned", "executing", "refused", "unknown", "ready"):
            with self.subTest(state=state):
                job, attempt = self.create("reserve-" + state)
                self.operation(job, attempt, "reserve", state)
                self.controller._terminal(job["id"], "CANCELLED", "cancelled")
                self.controller.run_once()
                self.assert_no_synthetic_proof(job["id"])
                _, attempt, _ = self.read(job["id"])
                self.assertFalse(attempt.termination_confirmed or attempt.revocation_confirmed)

    def test_unknown_namespace_effect_prevents_queued_cancellation_shortcut(self):
        job, attempt = self.create()
        self.operation(job, attempt, "exchange_space", "unknown")
        self.cancel_and_run(job)
        self.assert_no_synthetic_proof(job["id"])

    def test_existing_namespace_or_grant_resource_prevents_synthetic_cleanup(self):
        for kind in ("exchange_space", "workload_grant", "runtime_secret"):
            with self.subTest(kind=kind):
                job, attempt = self.create("resource-" + kind)
                with self.database.transaction() as session:
                    session.add(models.ProvisioningResource(job_id=job["id"], attempt_id=attempt.id,
                        component_id="owner", kind=kind, external_id=kind + "-" + job["id"],
                        ownership_json={"job_id": job["id"]}, details_json={}, retained=True))
                self.controller._terminal(job["id"], "CANCELLED", "cancelled")
                self.controller.run_once()
                self.assert_no_synthetic_proof(job["id"])

    def test_previous_released_allocation_is_not_proof_of_never_dispatch(self):
        job, attempt = self.create()
        with self.database.transaction() as session:
            session.add(models.Allocation(job_id=job["id"], attempt_id=attempt.id, component_id="owner",
                pool_id="cpu", epoch=attempt.epoch, cpu_millicores=1000, memory_bytes=1024,
                disk_bytes=1024, state="RELEASED", termination_confirmed=True, released_at=self.fixture.now))
        self.controller._terminal(job["id"], "CANCELLED", "cancelled")
        self.controller.run_once()
        self.assert_no_synthetic_proof(job["id"])

    def test_started_or_heartbeat_or_assigned_attempt_cannot_be_synthetically_cleaned(self):
        for field, value in (("started_at", self.fixture.now), ("heartbeat_at", self.fixture.now),
                             ("node_id", "node"), ("resources_json", {"cpu": 1000})):
            with self.subTest(field=field):
                job, attempt = self.create("attempt-" + field)
                with self.database.transaction() as session:
                    setattr(session.get(models.Attempt, attempt.id), field, value)
                self.controller._terminal(job["id"], "CANCELLED", "cancelled")
                self.controller.run_once()
                self.assert_no_synthetic_proof(job["id"])

    def retry_fixture(self, key):
        job, previous = self.create(key)
        with self.database.transaction() as session:
            stored = session.get(models.Job, job["id"])
            stored.current_attempt = 2
            stored.attempt_count = 2
            stored.epoch = previous.epoch
            stored.state = "QUEUED"
            prior = session.get(models.Attempt, previous.id)
            prior.state = "FAILED"
            prior.revocation_confirmed = prior.termination_confirmed = True
            prior.publication_status = "absent"
            prior.ended_at = self.fixture.now
            current = models.Attempt(job_id=job["id"], number=2, epoch=2,
                                     state="QUEUED", resources_json={})
            session.add(current)
            session.flush()
            session.expunge(current)
        job = self.manager.get_job("alice", job["id"])
        return job, previous, current

    def historical_allocation(self, job, attempt):
        with self.database.transaction() as session:
            session.add(models.Allocation(job_id=job["id"], attempt_id=attempt.id, component_id="owner",
                pool_id="cpu", epoch=attempt.epoch, cpu_millicores=1000, memory_bytes=1024,
                disk_bytes=1024, state="RELEASED", termination_confirmed=True, released_at=self.fixture.now))

    def historical_operation(self, job, attempt, operation, state, observed=None, epoch=None):
        with self.database.transaction() as session:
            epoch = attempt.epoch if epoch is None else epoch
            session.add(models.ProvisioningOperation(
                job_id=job["id"], attempt_id=attempt.id, component_id="owner",
                operation=operation,
                idempotency_key=f"{job['id']}:{attempt.id}:{epoch}:owner:{operation}",
                state=state, desired_json={"epoch": epoch}, observed_json=observed or {}))

    def test_queued_retry_without_current_effects_uses_explicit_predecessor_proofs(self):
        job, previous, current = self.retry_fixture("clean-retry")
        result, attempt, events = self.cancel_and_run(job)
        self.assertEqual((result.state, result.cleanup_status), ("CANCELLED", "complete"))
        self.assertEqual(attempt.id, current.id)
        self.assertTrue(attempt.revocation_confirmed and attempt.termination_confirmed)
        self.assertEqual(attempt.details_json["never_started_cleanup"]["fenced_prior_attempts"], [previous.id])
        self.assertEqual(self.exchange.mock_calls, [])
        self.assertEqual(self.executor.mock_calls, [])

    def test_historical_reserve_without_confirmed_closure_blocks_retry_cleanup(self):
        for state in ("pending", "unknown"):
            with self.subTest(state=state):
                job, previous, _ = self.retry_fixture("historical-reserve-" + state)
                self.historical_allocation(job, previous)
                self.historical_operation(job, previous, "reserve", state)
                self.cancel_and_run(job)
                self.assert_no_synthetic_proof(job["id"])
                _, current, _ = self.read(job["id"])
                self.assertFalse(current.revocation_confirmed or current.termination_confirmed)

    def test_historical_namespace_mutation_unknown_or_pending_blocks_retry_cleanup(self):
        for state in ("pending", "unknown"):
            with self.subTest(state=state):
                job, previous, _ = self.retry_fixture("historical-namespace-" + state)
                self.historical_operation(job, previous, "exchange_space", state)
                self.cancel_and_run(job)
                self.assert_no_synthetic_proof(job["id"])

    def test_retained_flag_on_historical_credentials_never_makes_them_safe_data(self):
        for kind in ("workload_grant", "runtime_secret"):
            for state in ("ready", "retained"):
                with self.subTest(kind=kind, state=state):
                    job, previous, _ = self.retry_fixture("historical-" + kind + "-" + state)
                    with self.database.transaction() as session:
                        session.add(models.ProvisioningResource(job_id=job["id"], attempt_id=previous.id,
                            component_id="owner", kind=kind, external_id=kind + "-" + job["id"],
                            ownership_json={"job_id": job["id"], "component_id": "owner", "kind": kind},
                            details_json={}, state=state, retained=True))
                    self.cancel_and_run(job)
                    self.assert_no_synthetic_proof(job["id"])

    def test_historical_lost_reserve_reply_is_safe_after_exact_confirmed_closure(self):
        job, previous, _ = self.retry_fixture("closed-historical-reserve")
        self.historical_allocation(job, previous)
        self.historical_operation(job, previous, "reserve", "unknown")
        self.historical_operation(job, previous, "stop", "confirmed", {"termination_confirmed": True})
        # Successful collection may return an empty tuple, whose production
        # observation has confirmed:false; operation state is its acknowledgement.
        self.historical_operation(job, previous, "collect", "confirmed", {"confirmed": False})
        self.historical_operation(job, previous, "release", "confirmed", {"confirmed": True})
        result, current, _ = self.cancel_and_run(job)
        self.assertEqual((result.state, result.cleanup_status), ("CANCELLED", "complete"))
        self.assertTrue(current.revocation_confirmed and current.termination_confirmed)
        self.assertEqual(self.exchange.mock_calls, [])
        self.assertEqual(self.executor.mock_calls, [])

    def test_closure_for_other_epoch_cannot_close_unknown_historical_reserve(self):
        job, previous, _ = self.retry_fixture("foreign-closure-epoch")
        self.historical_allocation(job, previous)
        self.historical_operation(job, previous, "reserve", "unknown")
        self.historical_operation(job, previous, "stop", "confirmed", {"termination_confirmed": True}, epoch=9)
        self.historical_operation(job, previous, "collect", "confirmed", {"confirmed": False}, epoch=9)
        self.historical_operation(job, previous, "release", "confirmed", {"confirmed": True}, epoch=9)
        self.cancel_and_run(job)
        self.assert_no_synthetic_proof(job["id"])

    def test_confirmed_historical_operation_requires_exact_execution_binding(self):
        for mismatch in ("key", "epoch", "component"):
            with self.subTest(mismatch=mismatch):
                job, previous, _ = self.retry_fixture("confirmed-binding-" + mismatch)
                with self.database.transaction() as session:
                    component = "foreign" if mismatch == "component" else "owner"
                    key = f"{job['id']}:{previous.id}:{previous.epoch}:{component}:stop"
                    if mismatch == "key":
                        key = "unrelated-job:" + key
                    session.add(models.ProvisioningOperation(
                        job_id=job["id"], attempt_id=previous.id, component_id=component,
                        operation="stop", idempotency_key=key, state="confirmed",
                        desired_json={"epoch": 99 if mismatch == "epoch" else previous.epoch},
                        observed_json={"termination_confirmed": True}))
                self.cancel_and_run(job)
                self.assert_no_synthetic_proof(job["id"])

    def test_retained_historical_namespace_is_not_a_data_resource(self):
        job, previous, _ = self.retry_fixture("retained-historical-namespace")
        with self.database.transaction() as session:
            session.add(models.ProvisioningResource(job_id=job["id"], attempt_id=previous.id,
                component_id="owner", kind="exchange_space", external_id="namespace-" + job["id"],
                ownership_json={"job_id": job["id"], "component_id": "owner", "kind": "exchange_space"},
                details_json={}, state="ready", retained=True))
        self.cancel_and_run(job)
        self.assert_no_synthetic_proof(job["id"])

    def purge_and_run(self, job_id, key):
        current = self.manager.get_job("alice", job_id)
        self.manager.purge("alice", job_id, current["version"], key)
        self.controller.run_once()
        return self.read(job_id)[0]

    def test_cancelled_never_admitted_job_purges_without_creating_job_resources(self):
        job, _ = self.create()
        self.cancel_and_run(job)
        job_path = self.provisioner.root / job["id"]
        self.assertFalse(job_path.exists())
        result = self.purge_and_run(job["id"], "purge-unused")
        self.assertIsNotNone(result.purged_at)
        self.assertEqual(result.cleanup_status, "complete")
        self.assertFalse(job_path.exists())
        self.assertEqual(self.exchange.mock_calls, [])
        self.assertEqual(self.executor.mock_calls, [])
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(list(session.scalars(select(models.Allocation))), [])
            self.assertEqual(list(session.scalars(select(models.ProvisioningResource))), [])
            self.assertEqual(list(session.scalars(select(models.ProvisioningOperation))), [])
            self.assertEqual(session.get(models.Project, "project").retained_bytes, 0)
        self.assertTrue(self.provisioner.purge_job(result), "Unused purge remains idempotent")

    def test_existing_unmarked_job_directory_cannot_use_unused_purge_shortcut(self):
        job, _ = self.create()
        self.cancel_and_run(job)
        job_path = self.provisioner.root / job["id"]
        job_path.mkdir(parents=True)
        sentinel = job_path / "unowned-content"
        sentinel.write_text("preserve unowned data")
        result = self.purge_and_run(job["id"], "purge-unmarked")
        self.assertIsNone(result.purged_at)
        self.assertEqual(result.cleanup_status, "purge_pending")
        self.assertEqual(sentinel.read_text(), "preserve unowned data")

    def test_dangling_job_symlink_cannot_count_as_owned_directory_absence(self):
        job, _ = self.create()
        self.cancel_and_run(job)
        self.provisioner.root.mkdir(parents=True)
        job_path = self.provisioner.root / job["id"]
        job_path.symlink_to(self.provisioner.root / "unavailable-foreign-directory", target_is_directory=True)
        result = self.purge_and_run(job["id"], "purge-symlink")
        self.assertIsNone(result.purged_at)
        self.assertEqual(result.cleanup_status, "purge_pending")
        self.assertTrue(job_path.is_symlink())

    def test_missing_directory_with_unresolved_reserve_intent_is_not_unused(self):
        job, attempt = self.create()
        self.cancel_and_run(job)
        self.operation(job, attempt, "reserve", "unknown")
        result = self.purge_and_run(job["id"], "purge-unknown-reserve")
        self.assertIsNone(result.purged_at)
        self.assertEqual(result.cleanup_status, "purge_pending")
        with self.database.transaction(immediate=False) as session:
            operation = session.scalar(select(models.ProvisioningOperation).where(
                models.ProvisioningOperation.job_id == job["id"]))
            self.assertEqual(operation.state, "unknown")

    def test_missing_directory_with_owned_unconfirmed_resource_is_not_unused(self):
        job, attempt = self.create()
        self.cancel_and_run(job)
        with self.database.transaction() as session:
            session.add(models.ProvisioningResource(job_id=job["id"], attempt_id=attempt.id,
                component_id="owner", kind="runtime_secret", external_id="unconfirmed-secret-" + job["id"],
                ownership_json={"job_id": job["id"], "component_id": "owner", "kind": "runtime_secret"},
                details_json={}, retained=False, state="ready"))
        result = self.purge_and_run(job["id"], "purge-unconfirmed-resource")
        self.assertIsNone(result.purged_at)
        self.assertEqual(result.cleanup_status, "purge_pending")
        with self.database.transaction(immediate=False) as session:
            resource = session.scalar(select(models.ProvisioningResource).where(
                models.ProvisioningResource.job_id == job["id"]))
            self.assertIsNone(resource.deleted_at)
            self.assertEqual(resource.state, "ready")

    def test_real_managed_proxy_cleanup_does_not_create_unowned_job_tree_before_purge(self):
        from hf2l_jobs.execution_proxy import ProxySupervisor
        from test_gateway import certificate_bundle
        bundle = certificate_bundle(Path(self.fixture.directory.name))
        supervisor = ProxySupervisor(self.provisioner.root,
            client_ca_certificate=bundle["ca"][2], client_ca_key=bundle["ca"][3],
            broker=Mock(), exchange_endpoint="https://exchange.example.invalid",
            gateway_endpoint="https://gateway.example.invalid",
            service_ca_file=bundle["ca"][2], grant_lookup=Mock())
        self.addCleanup(supervisor.close)
        self.provisioner.supervisor = supervisor
        job, _ = self.create()
        result, attempt, _ = self.cancel_and_run(job)
        self.assertEqual(result.cleanup_status, "complete")
        job_path = self.provisioner.root / job["id"]
        self.assertFalse(job_path.exists(), "Stopping an absent proxy must not materialize an unowned tree")
        result = self.purge_and_run(job["id"], "purge-after-real-proxy-cleanup")
        self.assertIsNotNone(result.purged_at)
        self.assertEqual(result.cleanup_status, "complete")
        self.assertFalse(job_path.exists())

    def test_legacy_exact_empty_proxy_skeleton_is_removed_with_current_never_started_proof(self):
        job, attempt = self.create()
        self.cancel_and_run(job)
        current = self.provisioner.root
        for part in (job["id"], "attempts", attempt.id, "owner"):
            current = current / part
            current.mkdir(parents=True, exist_ok=True, mode=0o700)
            current.chmod(0o700)
        result = self.purge_and_run(job["id"], "purge-legacy-empty-proxy-skeleton")
        self.assertIsNotNone(result.purged_at)
        self.assertEqual(result.cleanup_status, "complete")
        self.assertFalse((self.provisioner.root / job["id"]).exists())
        self.assertEqual(self.exchange.mock_calls, [])
        self.assertEqual(self.executor.mock_calls, [])

    def test_legacy_skeleton_with_unexpected_empty_directories_is_preserved(self):
        for foreign in ("attempt", "component", "nested"):
            with self.subTest(foreign=foreign):
                job, attempt = self.create("legacy-foreign-" + foreign)
                self.cancel_and_run(job)
                current = self.provisioner.root
                for part in (job["id"], "attempts", attempt.id, "owner"):
                    current = current / part
                    current.mkdir(parents=True, exist_ok=True, mode=0o700)
                    current.chmod(0o700)
                job_path = self.provisioner.root / job["id"]
                extra = {"attempt": job_path / "attempts" / "foreign-attempt",
                         "component": job_path / "attempts" / attempt.id / "foreign-component",
                         "nested": current / "unknown-child"}[foreign]
                extra.mkdir(mode=0o700)
                result = self.purge_and_run(job["id"], "purge-legacy-foreign-" + foreign)
                self.assertIsNone(result.purged_at)
                self.assertEqual(result.cleanup_status, "purge_pending")
                self.assertTrue(extra.is_dir(), "Unknown directories must not be swept by skeleton repair")

    def test_queued_retry_purge_uses_normal_owned_marker_after_current_absence_proof(self):
        from hf2l_jobs.resources import OwnedDirectories
        job, _, current = self.retry_fixture("marker-bound-retry-purge")
        result, attempt, _ = self.cancel_and_run(job)
        self.assertEqual((result.state, result.cleanup_status), ("CANCELLED", "complete"))
        self.assertEqual(attempt.id, current.id)
        directories = OwnedDirectories(self.provisioner.root)
        job_path = directories.ensure_job(job["id"], result.spec_hash)
        self.assertTrue((job_path / ".owner.json").is_file())
        result = self.purge_and_run(job["id"], "purge-marker-bound-retry")
        self.assertIsNotNone(result.purged_at)
        self.assertEqual(result.cleanup_status, "complete")
        self.assertFalse(job_path.exists())
        self.assertEqual(self.exchange.mock_calls, [])
        self.assertEqual(self.executor.mock_calls, [])

    def test_new_unknown_attempt_evidence_invalidates_prior_unused_purge_proof(self):
        job, initial = self.create()
        self.cancel_and_run(job)
        with self.database.transaction() as session:
            attempt = session.get(models.Attempt, initial.id)
            self.assertTrue(attempt.termination_confirmed and attempt.revocation_confirmed)
            attempt.details_json = {**attempt.details_json, "unconfirmed_node_start": True}
        result = self.purge_and_run(job["id"], "purge-new-unknown-attempt-evidence")
        self.assertIsNone(result.purged_at)
        self.assertEqual(result.cleanup_status, "purge_pending")
        self.assertFalse((self.provisioner.root / job["id"]).exists())

    def test_unrecognized_attempt_effect_evidence_blocks_proof(self):
        job, attempt = self.create()
        with self.database.transaction() as session:
            session.get(models.Attempt, attempt.id).details_json = {"unconfirmed_node_start": True}
        self.controller._terminal(job["id"], "CANCELLED", "cancelled")
        self.controller.run_once()
        self.assert_no_synthetic_proof(job["id"])
        _, stored, _ = self.read(job["id"])
        self.assertFalse(stored.termination_confirmed or stored.revocation_confirmed)

    def test_in_flight_dispatch_prevents_synthetic_never_started_proof(self):
        job, attempt = self.create()
        with self.database.transaction() as session:
            session.add(models.Outbox(job_id=job["id"], attempt_id=attempt.id,
                attempt_number=attempt.number, topic="dispatch", state="processing",
                lease_owner="other-controller", lease_until=self.fixture.now.replace(year=2027),
                idempotency_key="pending-dispatch"))
        self.controller._terminal(job["id"], "CANCELLED", "cancelled")
        self.controller.run_once()
        self.assert_no_synthetic_proof(job["id"])


if __name__ == "__main__":
    unittest.main()
