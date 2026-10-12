"""Adversarial lifecycle acceptance: missing replies never prove missing effects.

These tests drive the real database/controller/provisioner decision boundaries.
Fault adapters model a reply lost *after* a local effect and decisions committed
while external effects are running, rather than mirroring lifecycle internals.
Actual sandbox and PostgreSQL concurrency qualification live in separate suites.
"""
from __future__ import annotations

import tempfile
import json
import threading
from dataclasses import asdict
import unittest
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import select

from hf2l_jobs import models
from hf2l_jobs.controller import Controller
from hf2l_jobs.node_agent import NodeAgent
from hf2l_jobs.executor import (UncertainExecution, LinuxExecutor, ExecutionIdentity,
                               ExecutionSpec, ResourceLimits, ExecutorRefused)
from hf2l_jobs.provisioning import Provisioner
from hf2l_jobs.retention import RetentionService
from hf2l_jobs.resources import ResourceLedger, OwnedDirectories
from hf2l_jobs.scheduler import Scheduler

from test_scheduler_controller import Fixture, FakeExecutor, FakeProvisioner


class FaultExecutor(FakeExecutor):
    def __init__(self):
        super().__init__()
        self.lose_reserve_reply = False
        self.purged = []
        self.purge_confirmed = True
        self.on_reserve = None
        self.collect_confirmed = True

    def reserve(self, spec):
        result = super().reserve(spec)
        if self.on_reserve:
            callback, self.on_reserve = self.on_reserve, None
            callback()
        if self.lose_reserve_reply:
            self.lose_reserve_reply = False
            raise UncertainExecution("Local reservation committed, response lost")
        return result

    def collect(self, identity):
        self.calls.append(("collect", identity.component_id))
        if not self.collect_confirmed:
            raise UncertainExecution("Retention copy completion unknown")
        return ()

    def purge(self, identity):
        self.purged.append(identity)
        return self.purge_confirmed


class FaultProvisioner(FakeProvisioner):
    def __init__(self):
        super().__init__()
        self.on_reconcile = None
        self.on_ensure = None
        self.delete_confirmed = True
        self.deleted_jobs = []

    def ensure(self, job, attempt, remaining_rounds=None):
        if self.on_ensure:
            callback, self.on_ensure = self.on_ensure, None
            callback()
        return super().ensure(job, attempt, remaining_rounds)

    def reconcile(self, job, attempt):
        if self.on_reconcile:
            callback, self.on_reconcile = self.on_reconcile, None
            callback()
        return super().reconcile(job, attempt)

    def purge_job(self, job):
        self.deleted_jobs.append(job.id)
        return self.delete_confirmed

    expire_artifacts = purge_job


class LifecycleAcceptance(Fixture):
    def setUp(self):
        super().setUp()
        self.executor = FaultExecutor()
        self.provisioner = FaultProvisioner()
        self.controller = Controller(self.db, self.executor, self.provisioner, clock=self.clock)

    def request_cancel(self, job_id):
        with self.db.transaction() as session:
            job = session.get(models.Job, job_id)
            job.state, job.phase = "CANCELLING", "fencing"
            job.version += 1
            Scheduler._outbox(session, job, "fence_stop", {"desired_outcome": "CANCELLED"})

    def request_reconciliation(self, job_id):
        with self.db.transaction() as session:
            job = session.get(models.Job, job_id)
            job.state, job.phase = "RECONCILING", "verifying_evidence"
            job.version += 1
            Scheduler._outbox(session, job, "reconcile", {"evidence": {
                "publication_id": "stable-revision", "outcome": "not_published",
                "evidence_ref": "verified-exchange-observation"}})

    def request_purge(self, job_id):
        with self.db.transaction() as session:
            job = session.get(models.Job, job_id)
            job.cleanup_status = "purge_pending"
            job.version += 1
            Scheduler._outbox(session, job, "purge", {"confirm_before_release": True})

    def retained_bytes(self):
        with self.db.transaction() as session:
            return session.get(models.Project, "project").retained_bytes

    def allocation(self, job_id):
        with self.db.transaction() as session:
            row = session.scalar(select(models.Allocation).where(models.Allocation.job_id == job_id))
            session.expunge(row)
            return row

    def job_retained_bytes(self, job_id):
        with self.db.transaction() as session:
            resources = session.scalars(select(models.ProvisioningResource).where(
                models.ProvisioningResource.job_id == job_id))
            return sum(row.details_json.get("retention_charged_bytes", 0) for row in resources
                       if not row.details_json.get("retention_charge_released"))

    def assert_execution_cap_retained(self, job_id):
        allocation = self.allocation(job_id)
        with self.db.transaction() as session:
            state = session.get(models.ProvisioningResource, allocation.details_json["retained_resource_id"])
            self.assertEqual(state.job_id, job_id)
            self.assertEqual(state.kind, "execution_state")
            self.assertEqual(state.size_bytes, allocation.disk_bytes)
            self.assertEqual(state.details_json["retention_charged_bytes"], allocation.disk_bytes)
            self.assertFalse(state.details_json["retention_charge_released"])
        self.assertGreaterEqual(self.job_retained_bytes(job_id), allocation.disk_bytes)

    def test_lost_reservation_reply_still_charges_confirmed_retained_volume(self):
        self.job("lost-ack")
        self.executor.lose_reserve_reply = True
        self.controller.run_once()
        self.assertEqual(self.read("lost-ack").state, "QUEUED")
        allocation = self.allocation("lost-ack")
        self.assertFalse(allocation.acknowledged, "This exercises a genuinely missing manager ACK")
        self.assertEqual(allocation.state, "RELEASED")
        self.assert_execution_cap_retained("lost-ack")

    def test_purge_deletes_retained_volume_even_when_reservation_reply_was_lost(self):
        self.job("lost-ack")
        self.executor.lose_reserve_reply = True
        self.controller.run_once()
        self.request_cancel("lost-ack")
        self.controller.run_once()
        self.request_purge("lost-ack")
        self.controller.run_once()
        self.assertEqual(len(self.executor.purged), 1,
                         "Missing manager ACK must not skip a known retained execution volume")
        self.assertEqual(self.executor.purged[0].attempt_id, "lost-ack-a1")
        self.assertEqual(self.retained_bytes(), 0)

    def test_capacity_refusal_without_local_effect_never_collects_uncreated_storage(self):
        self.job("refused")
        self.executor.refuse_component = "owner"
        self.controller.run_once()
        self.assertEqual(self.read("refused").state, "QUEUED")
        self.assertEqual(self.executor.specs, {})
        self.assertNotIn(("collect", "owner"), self.executor.calls)
        self.assertNotIn(("ensure", "refused"), self.provisioner.calls)
        # Pure gang budgets can remain conservatively reserved until their
        # independently owned deletion/absence evidence is confirmed.
        self.assertGreater(self.job_retained_bytes("refused"), 0)

    def test_cancel_during_reservation_never_starts_a_partial_gang(self):
        self.job("cancelled")
        self.executor.on_reserve = lambda: self.request_cancel("cancelled")
        self.controller.run_once()
        self.assertEqual(self.read("cancelled").state, "CANCELLED")
        self.assertEqual(self.executor.started, [])
        self.assertNotIn(("ensure", "cancelled"), self.provisioner.calls)
        self.assert_execution_cap_retained("cancelled")

    def test_cancel_commit_during_final_publication_observation_wins(self):
        self.job("cancelled", target=3)
        self.controller.run_once()
        self.provisioner.rounds["cancelled"] = 3
        self.provisioner.on_reconcile = lambda: self.request_cancel("cancelled")
        self.controller.run_once()
        self.assertEqual(self.read("cancelled").state, "CANCELLED")
        self.assertEqual(self.read("cancelled").outcome_reason, "cancelled")

    def test_cancel_intent_survives_unknown_publication_and_explicit_reconcile(self):
        self.job("cancelled")
        self.controller.run_once()
        self.request_cancel("cancelled")
        self.provisioner.publication_known = False
        self.controller.run_once()
        self.assertEqual(self.read("cancelled").state, "NEEDS_ATTENTION")
        self.assertEqual(self.allocation("cancelled").state, "RELEASING")
        self.assertIsNone(self.allocation("cancelled").released_at)
        self.request_reconciliation("cancelled")
        self.provisioner.publication_known = True
        self.controller.run_once()
        self.assertEqual(self.read("cancelled").state, "CANCELLED",
                         "Reconciliation must complete the already accepted cancel decision")

    def test_provisioning_time_counts_against_absolute_deadline(self):
        self.job("provisioning", duration=60)
        self.controller.run_once(dispatch_limit=0)
        self.assertEqual(self.read("provisioning").state, "PROVISIONING")
        self.clock.advance(61)
        self.controller.run_once(dispatch_limit=0)
        self.assertEqual(self.read("provisioning").state, "RECONCILING",
                         "An undelivered provisioning action must not suspend the duration budget")
        self.assertEqual(self.read("provisioning").error_code, "deadline_exceeded")

    def test_unknown_retention_collection_keeps_compute_and_disk_charged(self):
        self.job("collect-unknown", cpu=4000)
        self.controller.run_once()
        self.request_cancel("collect-unknown")
        self.executor.collect_confirmed = False
        self.controller.run_once()
        allocation = self.allocation("collect-unknown")
        self.assertEqual(allocation.state, "QUARANTINED")
        self.assertIsNone(allocation.released_at)
        self.job("waiting", created_offset=1)
        self.assertEqual(self.scheduler.schedule(), [])
        self.assertEqual(self.read("waiting").queue_reason["code"], "capacity")

    def test_storage_quota_released_only_after_both_owned_deletions_confirm(self):
        self.job("owned")
        self.job("foreign", created_offset=1)
        self.controller.run_once()
        self.request_cancel("owned")
        self.controller.run_once()
        owned_charge = self.job_retained_bytes("owned")
        foreign_charge = self.job_retained_bytes("foreign")
        self.assertGreaterEqual(owned_charge, 1000)
        self.assertGreater(foreign_charge, 0)
        self.assertEqual(self.retained_bytes(), owned_charge + foreign_charge)
        self.request_purge("owned")
        self.provisioner.delete_confirmed = False
        self.controller.run_once()
        self.assertEqual(self.job_retained_bytes("owned"), owned_charge)
        self.assertEqual(self.job_retained_bytes("foreign"), foreign_charge)
        self.assertEqual(self.retained_bytes(), owned_charge + foreign_charge)
        self.assertIsNone(self.read("owned").purged_at)
        self.assertEqual(self.read("foreign").state, "RUNNING")
        self.clock.advance(5)
        self.provisioner.delete_confirmed = True
        self.controller.run_once()
        self.assertEqual(self.job_retained_bytes("owned"), 0)
        self.assertEqual(self.job_retained_bytes("foreign"), foreign_charge)
        self.assertEqual(self.retained_bytes(), foreign_charge)
        self.assertIsNotNone(self.read("owned").purged_at)
        self.assertEqual(set(self.provisioner.deleted_jobs), {"owned"})
        self.assertTrue(all(identity.job_id == "owned" for identity in self.executor.purged))

    def test_retention_scan_is_idempotent_and_preserves_history(self):
        self.job("expired")
        self.controller.run_once()
        self.request_cancel("expired")
        self.controller.run_once()
        self.clock.advance(91 * 86400)
        scanner = RetentionService(self.db, clock=self.clock)
        self.assertEqual(scanner.request_expiry(), ["expired"])
        self.assertEqual(scanner.request_expiry(), [])
        with self.db.transaction() as session:
            events_before = session.scalar(select(models.Event).where(models.Event.job_id == "expired").limit(1)).id
        self.controller.run_once()
        self.assertEqual(self.read("expired").cleanup_status, "expired")
        self.assertEqual(self.retained_bytes(), 0)
        with self.db.transaction() as session:
            self.assertIsNotNone(session.get(models.Event, events_before))
            self.assertIsNotNone(session.get(models.Attempt, "expired-a1"))


    def test_three_automatic_retries_then_failure_preserves_original_budget(self):
        self.job("bounded-retries", duration=3600)
        self.controller.run_once()
        original_deadline = self.read("bounded-retries").deadline_at
        for failure in range(4):
            self.controller._request_failure("bounded-retries", "runtime_unhealthy", transient=True)
            self.controller.run_once()
            job = self.read("bounded-retries")
            self.assertEqual(job.deadline_at, original_deadline)
            self.assertEqual(job.target_round, 3)
            if failure < 3:
                delay = (60, 120, 240)[failure]
                self.assertEqual(job.current_attempt, failure + 2)
                self.assertEqual(job.next_attempt_at, self.clock() + timedelta(seconds=delay))
                self.clock.advance(delay)
                self.controller.run_once()
                self.assertEqual(self.read("bounded-retries").state, "RUNNING")
            else:
                self.assertEqual(job.state, "FAILED")
                self.assertEqual(job.outcome_reason, "retry_exhausted")
                self.assertEqual(job.current_attempt, 4)
        self.assertEqual(len(self.executor.started), 4)

    def test_deadline_decision_survives_unknown_publication_reconciliation(self):
        self.job("expired-unknown", duration=60)
        self.controller.run_once()
        self.provisioner.publication_known = False
        self.clock.advance(61)
        self.controller.run_once()
        self.assertEqual(self.read("expired-unknown").state, "NEEDS_ATTENTION")
        self.request_reconciliation("expired-unknown")
        self.provisioner.publication_known = True
        self.controller.run_once()
        self.assertEqual(self.read("expired-unknown").state, "FAILED")
        self.assertEqual(self.read("expired-unknown").outcome_reason, "deadline_exceeded")

    def test_stale_fence_outbox_never_revokes_or_stops_a_successor_attempt(self):
        self.job("successor")
        self.controller.run_once()
        self.controller._request_failure("successor", "runtime_unhealthy", transient=True)
        self.controller.run_once()
        self.clock.advance(60)
        self.controller.run_once()
        self.assertEqual(self.read("successor").current_attempt, 2)
        self.assertEqual(self.read("successor").state, "RUNNING")
        stop_calls = sum(kind == "stop" for kind, _ in self.executor.calls)
        revoke_calls = sum(kind == "revoke" for kind, _ in self.provisioner.calls)
        with self.db.transaction() as session:
            session.add(models.Outbox(id="delayed-old-fence", job_id="successor", attempt_id="successor-a1",
                attempt_number=1, topic="fence_stop", payload_json={"epoch": 1},
                idempotency_key="delayed-old-fence", state="pending", attempts=0, created_at=self.clock()))
        self.controller.run_once()
        self.assertEqual(self.read("successor").state, "RUNNING")
        self.assertEqual(sum(kind == "stop" for kind, _ in self.executor.calls), stop_calls)
        self.assertEqual(sum(kind == "revoke" for kind, _ in self.provisioner.calls), revoke_calls)

    def test_retained_copy_is_not_written_before_its_project_budget_is_reserved(self):
        self.job("no-retention-budget")
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "checkpoint.pt"
            original = self.executor.collect
            def physical_collect(identity):
                copied.write_bytes(b"retained bytes must have a prepaid budget")
                return original(identity)
            self.executor.collect = physical_collect
            with self.db.transaction() as session:
                session.get(models.Project, "project").quotas_json = {"retained_bytes": 0}
            self.controller.run_once()
            self.assertEqual(self.read("no-retention-budget").state, "QUEUED")
            self.assertEqual(self.executor.specs, {})
            self.request_cancel("no-retention-budget")
            self.controller.run_once()
            self.assertFalse(copied.exists(),
                             "Storage quota refusal must occur before any retained copy is written")
            self.assertNotIn(("collect", "owner"), self.executor.calls)

    def test_dispatch_claim_taken_over_during_setup_cannot_start_from_old_claim(self):
        self.job("claim-taken-over")
        def transfer_claim():
            with self.db.transaction() as session:
                item = session.scalar(select(models.Outbox).where(
                    models.Outbox.job_id == "claim-taken-over", models.Outbox.topic == "dispatch"))
                item.lease_owner = "replacement-controller:current-claim"
                item.lease_until = self.clock() + timedelta(minutes=5)
        self.provisioner.on_ensure = transfer_claim
        self.controller.run_once()
        self.assertEqual(self.executor.started, [],
                         "The old claimant must recheck durable operation ownership after slow setup")
        with self.db.transaction() as session:
            item = session.scalar(select(models.Outbox).where(
                models.Outbox.job_id == "claim-taken-over", models.Outbox.topic == "dispatch"))
            self.assertEqual(item.lease_owner, "replacement-controller:current-claim")
            self.assertEqual(item.state, "processing")

    def test_retired_zero_byte_exchange_provenance_does_not_block_raw_deletion(self):
        self.job("provenance")
        self.controller.run_once()
        self.request_cancel("provenance")
        self.controller.run_once()
        with self.db.transaction() as session:
            session.add(models.ProvisioningResource(id="retired-space", job_id="provenance", attempt_id="provenance-a1",
                component_id="owner", kind="exchange_space", external_id="owned-space", state="retired",
                retained=True, size_bytes=0, ownership_json={"job_id": "provenance"}, details_json={}))
        self.request_purge("provenance")
        self.controller.run_once()
        self.assertIsNotNone(self.read("provenance").purged_at,
                             "Raw deletion should retain zero-byte retirement/provenance tombstones")
        self.assertEqual(self.retained_bytes(), 0)
        with self.db.transaction() as session:
            self.assertEqual(session.get(models.ProvisioningResource, "retired-space").state, "retired")


class IndependentNodeLeaseAcceptance(unittest.TestCase):
    def test_slow_start_does_not_block_another_jobs_lease_renewal(self):
        entered, finish, renewed = threading.Event(), threading.Event(), threading.Event()
        errors = []
        class SlowExecutor(FakeExecutor):
            def start(self, identity):
                entered.set()
                if not finish.wait(5):
                    raise RuntimeError("Test did not release slow start")
                return super().start(identity)
        with tempfile.TemporaryDirectory() as temporary:
            agent = NodeAgent(SlowExecutor(), Path(temporary) / "node.sqlite", "node", "server",
                ResourceLimits(4000, 256 * 1024**2, 264 * 1024**2), boot_id="stable-test-boot")
            def spec_for(job):
                return ExecutionSpec(ExecutionIdentity(job, job + "-attempt", "owner", 1),
                    "sha256:" + "a" * 64, "/private/" + job + "/source", "/private/" + job + "/state",
                    ("python", "-m", "hf2l_jobs.runtime", "--config", "/run/hf2l/runtime.json"),
                    "/private/" + job + "/proxy.sock", ResourceLimits(1000, 64 * 1024**2, 64 * 1024**2),
                    node_id="node", pool_id="server")
            slow, other = spec_for("slow"), spec_for("other")
            agent.reserve(slow)
            agent.reserve(other)
            def start():
                try: agent.start(slow.identity)
                except BaseException as error: errors.append(error)
            def renew():
                try:
                    agent.renew(other.identity)
                    renewed.set()
                except BaseException as error: errors.append(error)
            start_thread = threading.Thread(target=start)
            renew_thread = threading.Thread(target=renew)
            start_thread.start()
            try:
                self.assertTrue(entered.wait(2), "Slow start must be in its external operation")
                renew_thread.start()
                timely = renewed.wait(0.5)
            finally:
                finish.set()
                start_thread.join(2)
                if renew_thread.ident is not None: renew_thread.join(2)
                agent.close()
            self.assertFalse(errors, errors)
            self.assertTrue(timely, "A different job's lease must renew while an external start is blocked")


class PhysicalRetentionAcceptance(unittest.TestCase):
    """Exercise real descriptor/FS deletion without claiming a sandbox qualification."""
    def test_confirmed_executor_purge_removes_raw_retained_copies_only_for_its_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "profile.json"
            profile.write_text(json.dumps({"runtime": "runsc", "network": "none", "proxy_transport": "unix",
                "bounded_volumes": "loop-ext4", "runsc_network": "sandbox", "runsc_host_uds": "open",
                "qualified": True, "owned_root": str(root), "sandbox_uid": 1000, "sandbox_gid": 1000}))
            executor = LinuxExecutor(profile, root / "runtime", validate=False)
            identity = ExecutionIdentity("owned-job", "owned-attempt", "owner", 1)
            spec = ExecutionSpec(identity, "sha256:" + "a" * 64, str(root / "owned-job/source"),
                str(root / "owned-job/state"), ("python", "-m", "hf2l_jobs.runtime", "--config", "/run/hf2l/runtime.json"),
                str(root / "owned-job/proxy.sock"), ResourceLimits(1000, 64 * 1024**2, 64 * 1024**2))
            directory = executor._directory(identity)
            retained = directory / "retained/state/artifacts"
            retained.mkdir(parents=True, mode=0o700)
            for owned in (directory, directory / "retained", directory / "retained/state", retained):
                owned.chmod(0o700)
            raw = retained / "checkpoint.pt"
            raw.write_bytes(b"private model bytes")
            foreign = root / "other-job-checkpoint.pt"
            foreign.write_bytes(b"must remain")
            executor._save(identity, {"identity": asdict(identity), "spec": asdict(spec), "state": "RELEASED",
                "mounted": False, "loop_device": None, "retained": True, "state_copied": True})
            self.assertTrue(executor.purge(identity))
            self.assertFalse(raw.exists(), "Success must mean the retained raw model was actually deleted")
            self.assertEqual(foreign.read_bytes(), b"must remain")
            self.assertTrue(executor._record(identity).exists(), "Small audit identity may be retained")


class AdmissionCostAcceptance(Fixture):
    def manager_with_real_storage_plan(self):
        from hf2l_jobs.application import Manager
        from hf2l_jobs.source import SourceApproval, SourceRegistry
        with self.db.transaction() as session:
            session.add(models.ProjectMember(project_id="project", principal_id="creator", role="submitter"))
            session.add(models.ApprovedSource(id="source", project_id="project",
                url="https://github.com/example/code.git", allowed_commits=["a" * 40], enabled=True))
            session.add(models.RuntimeImage(id="runtime", digest="sha256:" + "b" * 64, enabled=True))
            session.add(models.Pool(id="object-store", name="Object Storage", node_id="exchange-store",
                cpu_millicores=0, memory_bytes=0, disk_bytes=2 * 1024**3, gpu_uuids=[],
                healthy=True, details_json={"object_store": True}))
            for participant in ("alice", "bob"):
                session.add(models.ParticipantBinding(id="data-" + participant, project_id="project",
                    participant_id=participant, node_id="approved-" + participant,
                    dataset_label="Approved " + participant, enabled=True))
        approval = SourceApproval("source", frozenset({"project"}), url="https://github.com/example/code.git",
            commits=frozenset({"a" * 40}), max_bytes=1024**2, max_git_bytes=1024**2,
            max_files=8, max_git_files=128)
        catalog = SimpleNamespace(source_registry=SourceRegistry([approval]))
        catalog.refreshed = lambda: catalog
        root = Path(self.temporary.name) / "private-planner-root"
        provisioner = Provisioner(self.db, None, catalog, root,
                                  workload_issuer="https://workload.example.test",
                                  exchange_storage_pool_id="object-store")
        manager = Manager(self.db, b"c" * 32, clock=self.clock)
        manager.storage_planner = provisioner.admission_storage
        spec = {"project_id": "project", "name": "full-storage-budget", "source_id": "source",
            "source_commit": "a" * 40, "runtime_image": "runtime", "plugin": "plugin",
            "target_round": 3, "max_duration_seconds": 3600,
            "participants": [{"participant_id": participant, "dataset_binding": "data-" + participant,
                              "mode": "external"} for participant in ("alice", "bob")],
            "components": [{"component_id": "owner", "role": "owner", "resources": {
                    "pool_id": "server", "cpu_millicores": 1000, "memory_bytes": 1000, "disk_bytes": 1000}}]}
        return manager, provisioner, root, spec

    def test_public_create_rejects_component_fit_but_impossible_source_workspace_cost(self):
        from hf2l_jobs.domain import Error
        manager, _, root, spec = self.manager_with_real_storage_plan()
        with self.db.transaction() as session:
            session.get(models.Pool, "server").disk_bytes = 1024
        with self.assertRaises(Error) as refused:
            manager.create_job("creator", spec, "impossible-full-budget")
        self.assertEqual((refused.exception.status, refused.exception.code),
                         (422, "resource_request_exceeds_pool"))
        with self.db.transaction() as session:
            self.assertEqual(list(session.scalars(select(models.Job))), [])
            self.assertEqual(list(session.scalars(select(models.Attempt))), [])
            self.assertEqual(list(session.scalars(select(models.ProvisioningResource))), [])
        self.assertFalse(root.exists(), "Pure admission validation must precede private directory creation")

    def test_public_create_checks_same_jobs_retained_copy_peak_against_idle_pool_and_project(self):
        from hf2l_jobs.domain import Error
        from hf2l_jobs.source import metadata_peak_bytes, git_peak_bytes
        manager, provisioner, root, spec = self.manager_with_real_storage_plan()
        approval = provisioner.registry.source_registry.authorize("project", "source", "a" * 40)
        input_and_compute = (spec["components"][0]["resources"]["disk_bytes"] + approval.max_bytes
                             + metadata_peak_bytes(approval) + git_peak_bytes(approval))
        with self.db.transaction() as session:
            session.get(models.Pool, "server").disk_bytes = input_and_compute
        with self.assertRaises(Error) as refused_pool:
            manager.create_job("creator", spec, "idle-pool-output-copy-peak")
        self.assertEqual((refused_pool.exception.status, refused_pool.exception.code),
                         (422, "resource_request_exceeds_pool"))
        with self.db.transaction() as session:
            session.get(models.Pool, "server").disk_bytes = 64 * 1024**2
            session.get(models.Project, "project").quota_disk_bytes = input_and_compute
        with self.assertRaises(Error) as refused_project:
            manager.create_job("creator", spec, "idle-project-output-copy-peak")
        self.assertEqual((refused_project.exception.status, refused_project.exception.code),
                         (422, "resource_request_exceeds_project_quota"))
        with self.db.transaction() as session:
            self.assertEqual(list(session.scalars(select(models.Allocation))), [])
            self.assertEqual(list(session.scalars(select(models.Job))), [])
            self.assertEqual(list(session.scalars(select(models.ProvisioningResource))), [])
        self.assertFalse(root.exists())

    def test_public_create_preaccounts_future_retained_execution_cap(self):
        from hf2l_jobs.domain import Error, JobSpec
        manager, provisioner, root, spec = self.manager_with_real_storage_plan()
        spec["components"][0]["resources"]["disk_bytes"] = 64 * 1024**2
        pinned = JobSpec.model_validate({**spec, "runtime_image": "sha256:" + "b" * 64})
        preview = SimpleNamespace(id="quota-preview", current_attempt=1, spec_json=pinned.to_dict(),
                                  spec_hash=pinned.digest)
        planned = provisioner.admission_storage(preview)
        # Snapshot/Git + immutable-copy plans do not include the original
        # execution volume's future retained restart-state cap.
        copy_limit = sum(entry["max_bytes"] for entry in planned if entry["kind"] != "execution_state")
        with self.db.transaction() as session:
            session.get(models.Pool, "server").disk_bytes = 512 * 1024**2
            session.get(models.Project, "project").quotas_json = {"retained_bytes": copy_limit}
        with self.assertRaises(Error) as refused:
            manager.create_job("creator", spec, "future-retained-volume-cap")
        self.assertEqual((refused.exception.status, refused.exception.code),
                         (422, "resource_request_exceeds_project_quota"))
        with self.db.transaction() as session:
            self.assertEqual(list(session.scalars(select(models.Job))), [])
            self.assertEqual(list(session.scalars(select(models.ProvisioningResource))), [])
        self.assertFalse(root.exists())

    def test_job_at_exact_prepaid_pool_and_project_budget_collects_without_new_capacity(self):
        from hf2l_jobs.domain import JobSpec
        from hf2l_jobs.collection import RetainedFile
        import hashlib
        manager, provisioner, _, spec = self.manager_with_real_storage_plan()
        spec["components"][0]["resources"]["disk_bytes"] = 64 * 1024**2
        pinned = JobSpec.model_validate({**spec, "runtime_image": "sha256:" + "b" * 64})
        preview = SimpleNamespace(id="saturated-preview", current_attempt=1, spec_json=pinned.to_dict(),
                                  spec_hash=pinned.digest)
        plan = provisioner.admission_storage(preview)
        retained_cap = sum(entry["max_bytes"] for entry in plan)
        pool_cap = 64 * 1024**2 + sum(entry["max_bytes"] for entry in plan
                                    if entry["pool_id"] == "server" and not entry.get("covered_by_allocation"))
        project_cap = 64 * 1024**2 + sum(entry["max_bytes"] for entry in plan
                                       if not entry.get("covered_by_allocation"))
        with self.db.transaction() as session:
            session.get(models.Pool, "server").disk_bytes = pool_cap
            project = session.get(models.Project, "project")
            project.quota_disk_bytes = project_cap
            project.quotas_json = {"retained_bytes": retained_cap}
        created = manager.create_job("creator", spec, "exact-all-prepaid-caps")
        fake_provisioner = FakeProvisioner()
        fake_provisioner.admission_storage = provisioner.admission_storage
        executor = FaultExecutor()
        controller = Controller(self.db, executor, fake_provisioner, clock=self.clock)
        controller.run_once()
        self.assertEqual(manager.get_job("creator", created["id"])["state"], "RUNNING")
        with self.db.transaction() as session:
            allocation = session.scalar(select(models.Allocation).where(models.Allocation.job_id == created["id"]))
            prepaid_id = allocation.details_json["collection_resource_id"]
            prepaid = session.get(models.ProvisioningResource, prepaid_id)
            self.assertEqual(prepaid.size_bytes, allocation.disk_bytes + 4 * 1024**2)
            self.assertEqual(RetentionService.pool_used_bytes(session, "server"), pool_cap)
            self.assertEqual(session.get(models.Project, "project").retained_bytes, retained_cap)
        observed_charge = []
        raw = Path(self.temporary.name) / "trusted-retained-copy" / "checkpoint.bin"
        def collect(identity):
            with self.db.transaction() as session:
                observed_charge.append(session.get(models.Project, "project").retained_bytes)
            raw.parent.mkdir(mode=0o700, exist_ok=True)
            raw.write_bytes(b"x")
            return (RetainedFile("checkpoint.bin", str(raw), 1, hashlib.sha256(b"x").hexdigest()),)
        executor.collect = collect
        version = manager.get_job("creator", created["id"])["version"]
        manager.cancel("creator", created["id"], version, "cancel-at-full-budget")
        controller.run_once()
        self.assertEqual(manager.get_job("creator", created["id"])["state"], "CANCELLED")
        self.assertTrue(raw.exists())
        self.assertTrue(observed_charge)
        self.assertTrue(all(amount == retained_cap for amount in observed_charge))
        with self.db.transaction() as session:
            allocation = session.scalar(select(models.Allocation).where(models.Allocation.job_id == created["id"]))
            self.assertEqual(allocation.state, "RELEASED")
            self.assertEqual(allocation.details_json["collection_resource_id"], prepaid_id)
            self.assertEqual(session.get(models.Project, "project").retained_bytes, retained_cap)
            self.assertEqual(RetentionService.pool_used_bytes(session, "server"), pool_cap)

    def test_public_create_accepts_static_fit_while_existing_job_temporarily_occupies_pool(self):
        manager, provisioner, root, spec = self.manager_with_real_storage_plan()
        with self.db.transaction() as session:
            session.get(models.Pool, "server").disk_bytes = 64 * 1024**2
        self.job("occupying-job", cpu=4000)
        self.assertEqual([item.job_id for item in self.scheduler.schedule()], ["occupying-job"])
        created = manager.create_job("creator", spec, "temporarily-busy-pool")
        self.assertEqual(created["state"], "QUEUED")
        scheduler = Scheduler(self.db, clock=self.clock, admission_storage=provisioner.admission_storage)
        self.assertEqual(scheduler.schedule(), [])
        self.assertEqual(manager.get_job("creator", created["id"])["queue_reason"]["code"], "capacity")
        self.assertFalse(root.exists())


class SourcePhysicalPrepaymentAcceptance(Fixture):
    def test_actual_git_object_workspace_is_prepaid_before_snapshot_materialization(self):
        # Reuse the real-Git setup helper without rediscovering its test suite.
        from test_source_provisioning import SourceTests
        source_case = SourceTests("test_pinned_snapshot_has_no_history_or_executed_hooks")
        source_case.setUp()
        try:
            registry = source_case.registry(max_bytes=32, max_git_bytes=65536,
                                            max_files=8, max_git_files=128)
            approval = registry.authorize("project", "src", source_case.commit)
            from hf2l_jobs.domain import JobSpec
            spec = JobSpec.model_validate({"project_id": "project", "name": "actual-source", "source_id": "src",
                "source_commit": source_case.commit, "runtime_image": "sha256:" + "b" * 64, "plugin": "plugin",
                "target_round": 3, "max_duration_seconds": 3600, "components": [{"component_id": "owner",
                "role": "owner", "resources": {"pool_id": "server", "cpu_millicores": 1000,
                "memory_bytes": 1000, "disk_bytes": 1000}}]})
            with self.db.transaction() as session:
                session.get(models.Pool, "server").disk_bytes = 32 * 1024**2
                session.add(models.Pool(id="source-object-store", name="Source Object Storage",
                    node_id="exchange-store", cpu_millicores=0, memory_bytes=0, disk_bytes=1024**2,
                    gpu_uuids=[], healthy=True, details_json={"object_store": True}))
                session.add(models.Job(id="actual-source", project_id="project", creator_id="creator",
                    name="actual-source", spec_json=spec.to_dict(), spec_hash=spec.digest, state="QUEUED",
                    current_attempt=1, attempt_count=1, epoch=0, target_round=3,
                    created_at=self.clock(), updated_at=self.clock()))
                session.flush()
                session.add(models.Attempt(id="actual-source-a1", job_id="actual-source", number=1,
                                           epoch=1, state="QUEUED"))
            catalog = SimpleNamespace(source_registry=registry, validate=lambda spec: None)
            catalog.refreshed = lambda: catalog
            provisioning_root = source_case.root / "owned-jobs"
            directories = OwnedDirectories(provisioning_root)
            directories.ensure_job("actual-source", spec.digest)
            provisioner = Provisioner(self.db, None, catalog, provisioning_root,
                                      workload_issuer="https://workload.example.test",
                                      exchange_storage_pool_id="source-object-store")
            admission = Scheduler(self.db, clock=self.clock, admission_storage=provisioner.admission_storage)
            self.assertEqual([item.job_id for item in admission.schedule()], ["actual-source"])
            charged_before_writes = []
            materialize = registry.materialize
            def observed_materialize(*args, **kwargs):
                with self.db.transaction() as session:
                    charged_before_writes.append(session.get(models.Project, "project").retained_bytes)
                return materialize(*args, **kwargs)
            registry.materialize = observed_materialize
            document = provisioner._source("actual-source", "actual-source-a1", spec, directories)
            self.assertEqual(len(charged_before_writes), 1)
            self.assertGreaterEqual(charged_before_writes[0], approval.max_bytes + approval.max_git_bytes,
                "The simultaneous copied Git object store needs prepaid capacity as well as the source tree")
            self.assertTrue((provisioning_root / "actual-source/source/plugin.py").is_file())
            with self.db.transaction() as session:
                charged_after = session.get(models.Project, "project").retained_bytes
            self.assertGreaterEqual(charged_after, document["bytes"])
            pending_workspace = [row for row in provisioner.ledger.resources("actual-source", kind="source_fetch_workspace")
                                 if row["state"] != "deleted"]
            self.assertEqual(pending_workspace, [],
                "Provisioning must adopt the admitted workspace identity and release it after real Git cleanup")
        finally:
            source_case.tearDown()


class RecordedStopProofAcceptance(unittest.TestCase):
    def test_acknowledged_owned_container_removal_is_reusable_termination_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "profile.json"
            profile.write_text(json.dumps({"runtime": "runsc", "network": "none", "proxy_transport": "unix",
                "bounded_volumes": "loop-ext4", "runsc_network": "sandbox", "runsc_host_uds": "open",
                "qualified": True, "owned_root": str(root), "sandbox_uid": 1000, "sandbox_gid": 1000}))
            commands = []
            def refused_command(argv, **kwargs):
                commands.append(argv)
                raise AssertionError("A recorded acknowledged removal does not need another missing-container query")
            executor = LinuxExecutor(profile, root / "runtime", runner=refused_command, validate=False)
            identity = ExecutionIdentity("owned-job", "owned-attempt", "owner", 1)
            directory = executor._directory(identity)
            directory.mkdir(parents=True, mode=0o700)
            executor._save(identity, {"identity": asdict(identity), "state": "STOPPED",
                "container": "hf2l-" + identity.key, "container_removed": True,
                "mounted": True, "loop_device": "/dev/loop999"})
            for _ in range(2):
                observed = executor.stop(identity)
                self.assertTrue(observed.termination_confirmed)
                self.assertEqual(observed.identity, identity)
            self.assertEqual(commands, [])
            # Even a copied receipt in another execution directory cannot attest
            # that foreign identity's process termination.
            foreign = ExecutionIdentity("foreign-job", "foreign-attempt", "owner", 1)
            executor._directory(foreign).mkdir(parents=True, mode=0o700)
            executor._record(foreign).write_bytes(executor._record(identity).read_bytes())
            with self.assertRaises(ExecutorRefused) as rejected:
                executor.stop(foreign)
            self.assertEqual(rejected.exception.code, "identity_mismatch")
            self.assertEqual(commands, [])


class RemotePurgeProofAcceptance(unittest.TestCase):
    def test_wire_receipt_requires_explicit_complete_owned_deletion_evidence(self):
        import httpx
        from hf2l_jobs.remote_node import RemoteExecutor, NodeEndpoint, NodeRoute, NodePurgeReceipt

        identity = ExecutionIdentity("purge-job", "purge-attempt", "owner", 3)
        digest = "a" * 64
        route = NodeRoute("owned-node", "owned-pool", ResourceLimits(1000, 1024**2, 1024**2))
        endpoint = NodeEndpoint("owned-node", "https://node.example.test", "/unused-ca",
                                "/unused-certificate", "/unused-key")
        complete = NodePurgeReceipt(**asdict(identity), node_id=route.node_id, pool_id=route.pool_id,
                                   spec_digest=digest, operation_id="purge-" + identity.key).as_dict()
        reply = dict(complete)
        requests = []
        def respond(request):
            requests.append(json.loads(request.content))
            return httpx.Response(200, json=reply)
        executor = RemoteExecutor({route.node_id: endpoint}, route=lambda *_: route,
            assignment_provider=lambda *_: None, token_provider=lambda *_: "approved-test-grant",
            client_factory=lambda _: httpx.Client(transport=httpx.MockTransport(respond)))
        try:
            self.assertEqual(executor.purge_receipt(identity, spec_digest=digest), complete)
            # Absence of a flag must never become positive deletion proof through
            # the dataclass defaults used by the node internal receipt builder.
            for field in ("purpose", "termination_confirmed", "source_deleted", "config_deleted",
                          "build_deleted", "private_credentials_deleted", "private_secrets_deleted",
                          "retained_deleted", "auxiliary_deleted", "confirmed"):
                with self.subTest(missing=field):
                    reply.clear()
                    reply.update({key: value for key, value in complete.items() if key != field})
                    with self.assertRaises(UncertainExecution):
                        executor.purge_receipt(identity, spec_digest=digest)
            for field, wrong in (("job_id", "foreign-job"), ("node_id", "foreign-node"),
                                 ("pool_id", "foreign-pool"), ("spec_digest", "b" * 64),
                                 ("retained_deleted", False), ("auxiliary_deleted", False)):
                with self.subTest(changed=field):
                    reply.clear()
                    reply.update({**complete, field: wrong})
                    with self.assertRaises(UncertainExecution):
                        executor.purge_receipt(identity, spec_digest=digest)
            self.assertTrue(all(request["identity"] == asdict(identity) and request["spec_digest"] == digest
                                for request in requests))
        finally:
            executor.close()


class AuthoritativePublicationAcceptance(Fixture):
    def provisioner(self):
        result = Provisioner(self.db, None, None, Path(tempfile.gettempdir()) / "not-created-hf2l-lifecycle",
                             workload_issuer="https://workload.example.test")
        result.current_round = lambda job: 0
        result._space_id = lambda job_id: "owned-space"
        return result

    def snapshot(self, status="none"):
        self.job("uncertain")
        with self.db.transaction() as session:
            job = session.get(models.Job, "uncertain")
            job.state, job.epoch = "RECONCILING", 1
            attempt = session.get(models.Attempt, "uncertain-a1")
            attempt.state, attempt.publication_status = "STOPPED", status
            attempt.started_at = self.clock()
            attempt.termination_confirmed = attempt.revocation_confirmed = True
            session.flush()
            session.expunge_all()
            return job, attempt

    def test_missing_initial_callback_is_not_evidence_of_absent_publication(self):
        job, attempt = self.snapshot("none")
        observation = self.provisioner().reconcile(job, attempt)
        self.assertFalse(observation.known,
                         "A default status cannot prove that a started worker did not publish before a lost reply")

    def test_stale_callback_does_not_resolve_a_later_lost_publication_ack(self):
        job, attempt = self.snapshot("confirmed")
        observation = self.provisioner().reconcile(job, attempt)
        self.assertFalse(observation.known,
                         "One earlier confirmed publication callback does not prove later intents are resolved")


class NamespaceFaultAdapter:
    """A namespace create can commit before its reply; retirement POST is cached."""
    def __init__(self, job_id):
        self.job_id = job_id
        self.policies, self.keys, self.creates = {}, {}, []
        self.lose_create_reply = False
        self.cleanup_pending = True

    def create_space(self, name, *, profile, quota_bytes, principal_quota_bytes, idempotency_key):
        self.creates.append((name, profile, quota_bytes, principal_quota_bytes, idempotency_key))
        space = self.keys.setdefault(idempotency_key, "space-" + self.job_id)
        self.policies.setdefault(space, SimpleNamespace(id=space, quota_bytes=quota_bytes,
                                                       principal_quota_bytes=principal_quota_bytes))
        if self.lose_create_reply:
            self.lose_create_reply = False
            raise ConnectionError("Namespace created but acknowledgement lost")
        return self.policies[space]

    def get_space(self, space):
        return self.policies[space]

    @staticmethod
    def path(space, suffix):
        return "/spaces/" + space + suffix

    def request(self, method, path, **kwargs):
        space = path.split("/")[2]
        if method == "PUT":
            return {"space_id": space, "job_id": self.job_id, "status": "active"}
        # A cached POST receipt is deliberately insufficient to free any charge.
        return {"space_id": space, "job_id": self.job_id, "status": "retired",
                "cleanup_pending": self.cleanup_pending if method == "GET" else False}


class BlobLifecycleAcceptance(Fixture):
    def setup_paid_job(self):
        manager, provisioner, root, spec = AdmissionCostAcceptance.manager_with_real_storage_plan(self)
        created = manager.create_job("creator", spec, "paid-object-lifecycle")
        self.manager, self.provisioner = manager, provisioner
        self.scheduler = Scheduler(self.db, clock=self.clock, admission_storage=provisioner.admission_storage)
        self.assertEqual([row.job_id for row in self.scheduler.schedule()], [created["id"]])
        job = self.read(created["id"])
        self.exchange = NamespaceFaultAdapter(job.id)
        provisioner.exchange = self.exchange
        rows = provisioner.ledger.resources(job.id, kind="exchange_blob_budget")
        self.assertEqual(len(rows), 1)
        return job, rows[0]

    def finish_execution(self, job_id):
        with self.db.transaction() as session:
            job = session.get(models.Job, job_id)
            job.state = "CANCELLED"
            for allocation in session.scalars(select(models.Allocation).where(models.Allocation.job_id == job_id)):
                allocation.state = "RELEASED"
                allocation.released_at = self.clock()
                allocation.termination_confirmed = True
                allocation.details_json = {**allocation.details_json, "retained_disk_charged": True}
        return self.read(job_id)

    def charges(self):
        with self.db.transaction() as session:
            return (session.get(models.Project, "project").retained_bytes,
                    RetentionService.pool_used_bytes(session, "object-store"))

    def test_lost_namespace_ack_is_adopted_before_retirement_and_fresh_pending_read_holds_budget(self):
        from hf2l_jobs.blob_budget import confirm_unused_blob_budget
        job, budget = self.setup_paid_job()
        self.exchange.lose_create_reply = True
        with self.assertRaises(ConnectionError):
            self.provisioner._provision_space(job, budget["attempt_id"])
        self.assertEqual(len(self.exchange.policies), 1)
        self.assertEqual(self.provisioner.ledger.resources(job.id, kind="exchange_space"), [])
        job = self.finish_execution(job.id)
        before = self.charges()
        self.assertFalse(confirm_unused_blob_budget(self.db, job))
        self.assertEqual(self.charges(), before)
        # The real purge path must recover the exact unknown operation rather
        # than create a second namespace or trust POST's old completion receipt.
        self.assertFalse(self.provisioner.purge_job(job))
        self.assertEqual(len(self.exchange.policies), 1)
        self.assertEqual(self.exchange.creates[0], self.exchange.creates[1])
        self.assertEqual(self.charges(), before)
        self.exchange.cleanup_pending = False
        self.assertTrue(self.provisioner.purge_job(job))
        after = self.charges()
        self.assertEqual(after, (before[0] - budget["size_bytes"], 0))
        self.assertTrue(self.provisioner.purge_job(job))
        self.assertEqual(self.charges(), after)

    def test_retirement_requires_exact_owned_explicit_complete_observation_and_released_execution(self):
        from hf2l_jobs.blob_budget import confirm_blob_cleanup
        from hf2l_jobs.resources import ResourceError
        job, budget = self.setup_paid_job()
        space = self.provisioner._provision_space(job, budget["attempt_id"])
        complete = {"job_id": job.id, "space_id": space, "status": "retired", "cleanup_pending": False}
        before = self.charges()
        with self.db.transaction() as session:
            session.get(models.Job, job.id).state = "CANCELLED"
        job = self.read(job.id)
        with self.assertRaises(ResourceError):
            confirm_blob_cleanup(self.db, job, space, complete)
        self.assertEqual(self.charges(), before)
        job = self.finish_execution(job.id)
        for changed in ({"job_id": "foreign-job"}, {"space_id": "foreign-space"},
                        {"status": "active"}, {"cleanup_pending": True},
                        {"cleanup_pending": 0}, {"cleanup_pending": "false"}):
            with self.subTest(observation=changed):
                self.assertFalse(confirm_blob_cleanup(self.db, job, space, {**complete, **changed}))
                self.assertEqual(self.charges(), before)
        self.assertFalse(confirm_blob_cleanup(self.db, job, space,
                         {key: value for key, value in complete.items() if key != "cleanup_pending"}))
        self.assertEqual(self.charges(), before)
        self.assertTrue(confirm_blob_cleanup(self.db, job, space, complete))
        after = self.charges()
        self.assertEqual(after, (before[0] - budget["size_bytes"], 0))
        self.assertTrue(confirm_blob_cleanup(self.db, job, space, complete))
        self.assertEqual(self.charges(), after)

    def test_retry_at_exact_combined_project_capacity_reuses_frozen_object_pool_and_single_charge(self):
        job, budget = self.setup_paid_job()
        before = self.charges()
        source_before = self.provisioner.ledger.resources(job.id, kind="source")
        self.assertEqual(len(source_before), 1)
        self.finish_execution(job.id)
        with self.db.transaction() as session:
            session.get(models.Pool, "object-store").disk_bytes = budget["size_bytes"]
            session.add(models.Pool(id="replacement-object-store", name="Replacement Object Storage",
                node_id="other-exchange-store", cpu_millicores=0, memory_bytes=0, disk_bytes=0,
                gpu_uuids=[], healthy=True, details_json={"object_store": True}))
            stored = session.get(models.Job, job.id)
            stored.state, stored.current_attempt, stored.attempt_count = "QUEUED", 2, 2
            session.add(models.Attempt(id=job.id + "-a2", job_id=job.id, number=2, epoch=2, state="QUEUED"))
        self.provisioner.exchange_storage_pool_id = "replacement-object-store"
        retry = self.read(job.id)
        plan = self.provisioner.admission_storage(retry)
        blobs = [row for row in plan if row["kind"] == "exchange_blob_budget"]
        self.assertEqual(len(blobs), 1)
        self.assertEqual((blobs[0]["external_id"], blobs[0]["pool_id"], blobs[0]["max_bytes"]),
                         (budget["external_id"], "object-store", budget["size_bytes"]))
        additional = sum(row["max_bytes"] for row in plan if row["kind"] != "exchange_blob_budget")
        with self.db.transaction() as session:
            project = session.get(models.Project, "project")
            project.quota_disk_bytes = before[0] + additional
            project.quotas_json = {"retained_bytes": before[0] + additional}
        self.assertEqual([row.job_id for row in self.scheduler.schedule()], [job.id])
        after = self.charges()
        self.assertEqual(after, (before[0] + additional, budget["size_bytes"]))
        rows = self.provisioner.ledger.resources(job.id, kind="exchange_blob_budget")
        self.assertEqual([(row["id"], row["size_bytes"]) for row in rows],
                         [(budget["id"], budget["size_bytes"])])
        source_after = self.provisioner.ledger.resources(job.id, kind="source")
        self.assertEqual([(row["id"], row["size_bytes"], row["details"]["retention_charged_bytes"])
                          for row in source_after],
                         [(row["id"], row["size_bytes"], row["details"]["retention_charged_bytes"])
                          for row in source_before])


class InflightProviderRetirementAcceptance(unittest.TestCase):
    def test_actual_gateway_upload_keeps_retirement_pending_until_known_provider_completion(self):
        import asyncio
        import hashlib
        import importlib.util
        import time
        from dataclasses import replace
        import httpx
        from test_gateway import GatewayFixture
        from hf2l_exchange.auth import Authenticator
        from hf2l_exchange.transfers import TransferService
        from hf2l_exchange.models import TransferAttempt, Space
        from hf2l_exchange.worker import tick

        # Load only the provider adapter; avoid collecting its independent tests.
        fixture_path = Path(__file__).resolve().parents[2] / "exchange/tests/test_transfers.py"
        module_spec = importlib.util.spec_from_file_location("_lifecycle_storage_adapter", fixture_path)
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        GatewayFixture.setUpClass()
        case = GatewayFixture("runTest")
        case.setUp()
        entered, finish = threading.Event(), threading.Event()
        replies, errors = [], []
        thread = None
        try:
            workload = Authenticator(replace(case.auth,
                workload_audience=case.gateway_settings.gateway_audience)).authenticate(
                    case.authorization()["Authorization"], managed=True,
                    certificate_thumbprint=case.thumbprint)
            revision = case.service.register_type(case.provisioner, case.sid, "document",
                {"schema": {"type": "object"}}, "held-upload-type")
            record = case.service.create_record(workload, case.sid, {
                "kind": "document", "schema_revision_id": revision["id"], "metadata": {},
                "attachments": [{"path": "checkpoint.bin", "size": 8,
                    "sha256": hashlib.sha256(b"abcdefgh").hexdigest()}]}, "held-upload-record")
            attachment = record["attachments"][0]["id"]
            transfers = TransferService(case.service, module.FakeStore())
            transfers.settings = replace(transfers.settings,
                storage=replace(transfers.settings.storage, grant_seconds=1))
            transfers.initiate(case.sid, record["id"], attachment, workload)
            case.backend.transfers = transfers
            async def delayed_origin(request):
                await request.aread()
                entered.set()
                if not await asyncio.to_thread(finish.wait, 8):
                    raise AssertionError("Isolated provider overlap exceeded its bound")
                return httpx.Response(200, headers={"ETag": '"held-part"'})
            case.origin_handler = delayed_origin
            def put():
                try:
                    replies.append(case.client.put(
                        f"/transfers/v1/spaces/{case.sid}/records/{record['id']}/attachments/{attachment}/parts/1",
                        content=b"abcdefgh", headers=case.authorization()).status_code)
                except Exception as error:
                    errors.append(type(error).__name__)
            thread = threading.Thread(target=put)
            thread.start()
            self.assertTrue(entered.wait(4), "The legitimate actual gateway must reach the provider")
            case.service.revoke_workload_grants(case.provisioner, case.sid,
                {"attempt_id": "attempt-a"}, "held-upload-revoke")
            case.service.retire_managed_space(case.provisioner, case.sid,
                {"job_id": "job-a"}, "held-upload-retire")
            # Natural signed expiry cannot prove completion of a request already
            # admitted by the provider. Keep actual draft and reclaiming evidence.
            time.sleep(2)
            tick(transfers)
            self.assertTrue(thread.is_alive())
            self.assertTrue(case.service.get_managed_space(case.provisioner, case.sid)["cleanup_pending"])
            with case.service.sessions.begin() as session:
                self.assertEqual(session.get(Space, case.sid).reclaiming, 8)
            finish.set()
            thread.join(4)
            self.assertFalse(thread.is_alive())
            self.assertEqual((replies, errors), ([204], []))
            with case.service.sessions.begin() as session:
                attempt = session.scalar(select(TransferAttempt).where(TransferAttempt.blob_id == attachment))
                # Only make a known completed request immediately due; never
                # erase expiry, a mutation marker, or physical absence evidence.
                attempt.next_attempt = 0
            self.assertEqual(tick(transfers)["cleaned"], 1)
            self.assertFalse(case.service.get_managed_space(case.provisioner, case.sid)["cleanup_pending"])
        finally:
            finish.set()
            if thread:
                thread.join(4)
            case.doCleanups()


if __name__ == "__main__":
    unittest.main()
