"""Durable command, authorization, pagination and retained-history regressions."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace

from sqlalchemy import select, func, update, inspect

from hf2l_jobs import models
from hf2l_jobs.application import Manager
from hf2l_jobs.database import create_database
from hf2l_jobs.domain import Error, JobSpec
from hf2l_jobs.pagination import CursorSigner


class ApplicationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.url = "sqlite:///" + str(Path(self.directory.name) / "jobs.sqlite")
        self.db = create_database(self.url)
        self.now = datetime(2026, 10, 9, 12, tzinfo=timezone.utc)
        self.manager = Manager(self.db, b"c" * 32, clock=lambda: self.now, platform_operator_ids=("platform",))
        with self.db.transaction() as session:
            session.add_all([models.Project(id="project", name="Project", retention_days=90),
                             models.Project(id="foreign", name="Foreign")])
            session.flush()
            session.add_all([models.ProjectMember(project_id="project", principal_id="alice", role="submitter"),
                             models.ProjectMember(project_id="project", principal_id="bob", role="submitter")])
            session.add(models.ApprovedSource(id="source", project_id="project", url="https://github.com/example/code.git",
                                               allowed_commits=["a" * 40], enabled=True))
            session.add(models.RuntimeImage(id="runtime", digest="sha256:" + "b" * 64, enabled=True))
            session.add_all([models.ParticipantBinding(id="default-" + name, project_id="project",
                participant_id="participant-" + name, node_id="node-" + name, dataset_label="Approved Dataset")
                for name in ("a", "b")])
            session.add(models.Pool(id="cpu", name="CPU", node_id="node", cpu_millicores=4000,
                memory_bytes=8 << 30, disk_bytes=8 << 30, healthy=True, sandbox_profiles=["runsc-cpu-v1"]))

    def tearDown(self):
        self.db.close()
        self.directory.cleanup()

    def spec(self, name="Job"):
        return {"project_id": "project", "name": name, "source_id": "source", "source_commit": "a" * 40,
                "runtime_image": "runtime", "plugin": "examples.lenet", "target_round": 5,
                "max_duration_seconds": 3600,
                "participants": [{"participant_id": "participant-" + name, "dataset_binding": "default-" + name,
                                  "mode": "external"} for name in ("a", "b")],
                "components": [{"component_id": "owner", "role": "owner",
                "resources": {"pool_id": "cpu", "cpu_millicores": 1000, "memory_bytes": 1 << 30,
                              "disk_bytes": 1 << 30}}]}

    def create(self, actor="alice", key="create", name="Job"):
        return self.manager.create_job(actor, self.spec(name), key)

    def assert_error(self, status, code, call):
        with self.assertRaises(Error) as result:
            call()
        self.assertEqual((result.exception.status, result.exception.code), (status, code))

    def test_create_replay_and_conflict_are_durable_across_manager_restart(self):
        first = self.create()
        self.db.close()
        self.db = create_database(self.url)
        self.manager = Manager(self.db, b"c" * 32, clock=lambda: self.now)
        self.assertEqual(first, self.create())
        self.assert_error(409, "idempotency_conflict", lambda: self.create(name="Changed"))
        with self.db.transaction() as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(models.Job)), 1)
            self.assertEqual(session.scalar(select(func.count()).select_from(models.Attempt)), 1)
            self.assertEqual(session.scalar(select(func.count()).select_from(models.Event)), 1)

    def test_create_replay_checks_current_job_membership(self):
        job = self.create()
        with self.db.transaction() as session:
            session.add(models.JobMember(job_id=job["id"], principal_id="bob", role="admin"))
            session.delete(session.get(models.JobMember, (job["id"], "alice")))
        self.assert_error(404, "job_not_found", self.create)

    def test_source_and_runtime_approvals_are_project_bound(self):
        with self.db.transaction() as session:
            session.add(models.ApprovedSource(id="other-source", project_id="foreign", url="https://github.com/example/secret.git"))
            session.add(models.RuntimeImage(id="other-image", project_id="foreign", digest="sha256:" + "d" * 64))
        for field, value, code in [("source_id", "other-source", "source_not_approved"),
                                   ("runtime_image", "other-image", "runtime_image_not_approved"),
                                   ("source_commit", "f" * 40, "source_commit_not_approved")]:
            spec = self.spec(); spec[field] = value
            self.assert_error(422, code, lambda: self.manager.create_job("alice", spec, "bad-" + field))
        with self.db.transaction() as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(models.Job)), 0)

    def test_unapproved_inline_secret_and_host_options_are_rejected(self):
        for options in ({"token": "sensitive"}, {"mounts": ["/host"]}, {"value": float("nan")}):
            spec = self.spec(); spec["options"] = options
            self.assert_error(422, "invalid_job_spec", lambda: self.manager.create_job("alice", spec, "bad"))
        spec = self.spec(); spec["secret_refs"] = {"checkpoint-key": "secret"}
        self.assert_error(422, "secret_reference_not_approved", lambda: self.manager.create_job("alice", spec, "ref"))

    def test_source_mutation_is_impossible_and_new_job_is_required(self):
        job = self.create()
        with self.assertRaises(ValueError):
            with self.db.transaction() as session:
                row = session.get(models.Job, job["id"])
                row.spec_json = {**row.spec_json, "source_commit": "b" * 40}
        self.assertEqual(self.manager.get_job("alice", job["id"])["spec"]["source_commit"], "a" * 40)

    def test_cancel_is_an_outbox_intent_not_premature_resource_release(self):
        job = self.create()
        cancelled = self.manager.cancel("alice", job["id"], 1, "cancel")
        self.assertEqual(cancelled["state"], "CANCELLING")
        self.assertEqual(cancelled["version"], 2)
        self.assertEqual(cancelled, self.manager.cancel("alice", job["id"], 1, "cancel"))
        with self.db.transaction() as session:
            operation = session.scalar(select(models.Outbox))
            self.assertEqual(operation.topic, "fence_stop")
            self.assertEqual(operation.payload_json["grace_seconds"], 60)
            self.assertEqual(session.scalar(select(func.count()).select_from(models.Outbox)), 1)

    def test_expected_version_conflict_rolls_back_everything(self):
        job = self.create()
        self.assert_error(409, "job_version_conflict", lambda: self.manager.cancel("alice", job["id"], 2, "cancel"))
        self.assertEqual(self.manager.get_job("alice", job["id"])["state"], "QUEUED")
        with self.db.transaction() as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(models.Outbox)), 0)

    def test_reader_cannot_mutate_and_platform_operator_has_no_content(self):
        job = self.create()
        self.manager.put_member("alice", job["id"], "bob", "reader", 1, "grant")
        self.assert_error(403, "job_role_required", lambda: self.manager.cancel("bob", job["id"], 2, "cancel"))
        self.assert_error(404, "job_not_found", lambda: self.manager.get_job("platform", job["id"]))
        self.assertEqual(self.manager.list_jobs("platform")["total"], 0)
        self.assertEqual(len(self.manager.list_pools("platform")["items"]), 1)

    def test_last_admin_cannot_revoke_or_demote_self(self):
        job = self.create()
        self.assert_error(409, "last_job_admin_required", lambda: self.manager.delete_member("alice", job["id"], "alice", 1, "remove"))
        self.assert_error(409, "last_job_admin_required", lambda: self.manager.put_member("alice", job["id"], "alice", "reader", 1, "demote"))
        self.assertEqual(self.manager.get_job("alice", job["id"])["version"], 1)

    def test_revocation_prevents_reads_and_cached_command_replays(self):
        job = self.create()
        value = self.manager.put_member("alice", job["id"], "bob", "operator", 1, "grant")
        cancelled = self.manager.cancel("bob", job["id"], value["version"], "cancel")
        self.manager.delete_member("alice", job["id"], "bob", cancelled["version"], "revoke")
        self.assert_error(404, "job_not_found", lambda: self.manager.cancel("bob", job["id"], value["version"], "cancel"))
        self.assert_error(404, "job_not_found", lambda: self.manager.list_events("bob", job["id"]))

    def test_pagination_counts_and_literal_search_do_not_include_foreign_jobs(self):
        jobs = [self.create(key="a" + str(i), name="Literal%_ " + str(i)) for i in range(3)]
        self.create("bob", "foreign", "Foreign secret")
        page = self.manager.list_jobs("alice", {"search": "%_"}, limit=1)
        self.assertEqual(page["total"], 3)
        ids = [page["items"][0]["id"]]
        while page["next_cursor"]:
            page = self.manager.list_jobs("alice", {"search": "%_"}, limit=1, cursor=page["next_cursor"])
            ids += [item["id"] for item in page["items"]]
        self.assertEqual(set(ids), {job["id"] for job in jobs})
        self.assertEqual(self.manager.job_counts("alice"), {"queued": 3, "current": 0, "history": 0})

    def test_cursor_cannot_cross_principal_filter_or_be_tampered(self):
        for i in range(2): self.create(key=str(i))
        cursor = self.manager.list_jobs("alice", {"view": "queued"}, limit=1)["next_cursor"]
        self.assert_error(422, "invalid_cursor", lambda: self.manager.list_jobs("bob", {"view": "queued"}, cursor=cursor))
        self.assert_error(422, "invalid_cursor", lambda: self.manager.list_jobs("alice", {"view": "history"}, cursor=cursor))
        self.assert_error(422, "invalid_cursor", lambda: self.manager.list_jobs("alice", {"view": "queued"}, cursor="X" + cursor[1:]))
        self.now += timedelta(hours=2)
        self.assert_error(409, "cursor_expired", lambda: self.manager.list_jobs("alice", {"view": "queued"}, cursor=cursor))

    def test_retry_keeps_deadline_target_and_history_until_fencing_barrier(self):
        job = self.create()
        deadline = self.now + timedelta(minutes=30)
        with self.db.transaction() as session:
            row = session.get(models.Job, job["id"])
            row.state = "FAILED"; row.deadline_at = deadline; row.terminated_at = self.now
            attempt = session.scalar(select(models.Attempt).where(models.Attempt.job_id == job["id"]))
            attempt.state = "FAILED"; attempt.termination_confirmed = True
        retried = self.manager.retry("alice", job["id"], 1, "retry")
        self.assertEqual(retried["state"], "RECONCILING")
        self.assertEqual(retried["target_round"], 5)
        self.assertEqual(retried["deadline_at"], deadline.isoformat().replace("+00:00", "Z"))
        self.assertEqual(len(self.manager.list_attempts("alice", job["id"])["items"]), 1)
        with self.db.transaction() as session:
            op = session.scalar(select(models.Outbox))
            self.assertEqual((op.topic, op.payload_json["next_attempt"]), ("prepare_retry", 2))

    def test_expired_deadline_retry_rejected_without_new_attempt(self):
        job = self.create()
        with self.db.transaction() as session:
            row = session.get(models.Job, job["id"]); row.state = "FAILED"; row.deadline_at = self.now
        self.assert_error(409, "job_deadline_expired", lambda: self.manager.retry("alice", job["id"], 1, "retry"))
        self.assertEqual(len(self.manager.list_attempts("alice", job["id"])["items"]), 1)

    def test_reconciliation_evidence_is_verified_async_and_never_blind_replay(self):
        job = self.create()
        with self.db.transaction() as session:
            session.get(models.Job, job["id"]).state = "NEEDS_ATTENTION"
        self.assert_error(422, "reconciliation_evidence_required", lambda: self.manager.reconcile("alice", job["id"], 1, "resolve", {}))
        result = self.manager.reconcile("alice", job["id"], 1, "resolve", {"publication_id": "record", "outcome": "published", "evidence_ref": "durable-proof"})
        self.assertEqual(result["phase"], "verifying_evidence")
        with self.db.transaction() as session:
            self.assertEqual(session.scalar(select(models.Outbox)).topic, "reconcile")

    def test_purge_retains_audit_and_budget_until_confirmed_cleanup(self):
        job = self.create()
        with self.db.transaction() as session:
            row = session.get(models.Job, job["id"]); row.state = "SUCCEEDED"
            attempt = session.scalar(select(models.Attempt).where(models.Attempt.job_id == job["id"])); attempt.state = "SUCCEEDED"
            session.get(models.Project, "project").retained_bytes = 123
        value = self.manager.purge("alice", job["id"], 1, "purge")
        self.assertEqual(value["retention"]["cleanup_status"], "purge_pending")
        self.assertIsNone(value["retention"]["purged_at"])
        with self.db.transaction() as session:
            self.assertEqual(session.get(models.Project, "project").retained_bytes, 123)
            self.assertGreater(session.scalar(select(func.count()).select_from(models.Event)), 1)

    def test_purge_rejects_live_or_quarantined_allocation(self):
        job = self.create()
        with self.db.transaction() as session:
            row = session.get(models.Job, job["id"]); row.state = "FAILED"
            attempt = session.scalar(select(models.Attempt).where(models.Attempt.job_id == job["id"])); attempt.state = "FAILED"
            session.add(models.Allocation(job_id=job["id"], attempt_id=attempt.id, component_id="owner", pool_id="cpu",
                cpu_millicores=1000, memory_bytes=1 << 30, disk_bytes=1 << 30, epoch=1, state="QUARANTINED"))
        self.assert_error(409, "job_runtime_not_confirmed_stopped", lambda: self.manager.purge("alice", job["id"], 1, "purge"))

    def test_log_bytes_are_bounded_and_expired_data_is_not_returned(self):
        job = self.create()
        with self.db.transaction() as session:
            for i in range(20):
                session.add(models.LogChunk(job_id=job["id"], component="owner", sequence=i + 1,
                    data="x" * 65536, created_at=self.now + timedelta(seconds=i)))
        page = self.manager.list_logs("alice", job["id"])
        self.assertEqual(page["bytes_returned"], 1 << 20)
        self.assertEqual(len(page["items"]), 16)
        self.assertIsNotNone(page["next_cursor"])
        tail = self.manager.list_logs("alice", job["id"], cursor=page["next_cursor"])
        self.assertEqual(len(tail["items"]), 4)
        with self.db.transaction() as session:
            session.get(models.Job, job["id"]).artifacts_expire_at = self.now
        expired = self.manager.list_logs("alice", job["id"])
        self.assertTrue(all(item["expired"] and item["data"] == "" for item in expired["items"]))

    def test_artifact_descriptors_hide_origin_keys_and_preserve_expired_hashes(self):
        job = self.create()
        with self.db.transaction() as session:
            session.add(models.Artifact(id="artifact", job_id=job["id"], kind="checkpoint", name="weights.npz",
                size_bytes=10, sha256="c" * 64, storage_key="private/origin/key", expires_at=self.now + timedelta(days=90)))
        value = self.manager.get_artifact("alice", job["id"], "artifact")
        self.assertNotIn("storage_key", value)
        self.assertTrue(value["download_available"])
        self.now += timedelta(days=91)
        value = self.manager.get_artifact("alice", job["id"], "artifact")
        self.assertEqual(value["sha256"], "c" * 64)
        self.assertFalse(value["download_available"])
        self.assert_error(410, "artifact_expired", lambda: self.manager.artifact_storage("alice", job["id"], "artifact"))

    def test_operational_capacity_cannot_hide_live_reservations(self):
        job = self.create()
        with self.db.transaction() as session:
            attempt = session.scalar(select(models.Attempt).where(models.Attempt.job_id == job["id"]))
            session.add(models.Allocation(job_id=job["id"], attempt_id=attempt.id, component_id="owner", pool_id="cpu",
                cpu_millicores=1000, memory_bytes=1 << 30, disk_bytes=1 << 30, epoch=1, state="QUARANTINED"))
        self.assert_error(409, "pool_capacity_below_reserved", lambda: self.manager.put_pool("platform", "cpu", {"cpu_millicores": 500}))
        self.assert_error(409, "pool_node_has_active_allocations", lambda: self.manager.put_pool("platform", "cpu", {"node_id": "different"}))
        self.assert_error(403, "platform_operator_required", lambda: self.manager.list_pools("alice"))

    def test_foreign_events_do_not_change_authorized_invalidation_revision(self):
        self.create()
        before = self.manager.visible_revision("alice")
        self.create("bob", "foreign")
        self.assertEqual(before, self.manager.visible_revision("alice"))


    def test_pool_health_and_profile_expansion_require_actual_qualification(self):
        self.assert_error(409, "pool_qualification_required", lambda: self.manager.put_pool("platform", "cpu", {"cpu_millicores": 5000}))
        self.assert_error(409, "pool_qualification_required", lambda: self.manager.put_pool("platform", "cpu", {"sandbox_profiles": ["runsc-cpu-v1", "unknown"]}))
        with self.db.transaction() as session:
            session.get(models.Pool, "cpu").healthy = False
        self.assert_error(409, "pool_qualification_required", lambda: self.manager.put_pool("platform", "cpu", {"healthy": True}))
        calls = []
        self.manager.pool_qualifier = lambda values: calls.append(values["node_id"])
        value = self.manager.put_pool("platform", "cpu", {"healthy": True})
        self.assertTrue(value["healthy"])
        self.assertEqual(calls, ["node"])


    def test_artifact_pages_are_bounded_and_job_scoped(self):
        job = self.create()
        other = self.create(key="other")
        with self.db.transaction() as session:
            for i in range(5):
                session.add(models.Artifact(id="artifact" + str(i), job_id=job["id"], kind="checkpoint",
                    name="weights.npz", size_bytes=10, sha256="a" * 64, storage_key="private", created_at=self.now))
        page = self.manager.list_artifacts("alice", job["id"], limit=2)
        ids = [item["id"] for item in page["items"]]
        first_cursor = page["next_cursor"]
        while page["next_cursor"]:
            page = self.manager.list_artifacts("alice", job["id"], limit=2, cursor=page["next_cursor"])
            ids += [item["id"] for item in page["items"]]
        self.assertEqual(ids, ["artifact" + str(i) for i in range(5)])
        self.assert_error(422, "invalid_cursor", lambda: self.manager.list_artifacts("alice", other["id"], cursor=first_cursor))
        self.assert_error(404, "job_not_found", lambda: self.manager.list_artifacts("bob", job["id"], cursor=first_cursor))


    def test_runtime_alias_is_pinned_and_retry_never_selects_changed_catalog_image(self):
        from hf2l_jobs.domain import JobSpec
        from hf2l_jobs.source import RegistryCatalog, SourceError
        submitted = self.spec()
        job = self.manager.create_job("alice", submitted, "pinned")
        original_digest = "sha256:" + "b" * 64
        self.assertEqual(job["spec"]["runtime_image"], original_digest)
        self.assertEqual(job["spec_hash"], JobSpec.model_validate({**submitted, "runtime_image": original_digest}).digest)
        self.assertNotEqual(job["spec_hash"], JobSpec.model_validate(submitted).digest)
        with self.db.transaction() as session:
            row = session.get(models.Job, job["id"])
            row.state = "FAILED"; row.deadline_at = self.now + timedelta(minutes=30)
            # Emulate an old mutable catalog database, bypassing new ORM/CLI immutability guards.
            session.execute(update(models.RuntimeImage).where(models.RuntimeImage.id == "runtime")
                            .values(digest="sha256:" + "c" * 64))
        replayed = self.manager.create_job("alice", submitted, "pinned")
        self.assertEqual(replayed["id"], job["id"])
        self.assertEqual(replayed["spec"]["runtime_image"], original_digest)
        retry = self.manager.retry("alice", job["id"], 1, "retry-pinned")
        self.assertEqual(retry["spec"]["runtime_image"], original_digest)
        with self.db.transaction() as session:
            stored_spec = JobSpec.model_validate(session.get(models.Job, job["id"]).spec_json)
        with self.assertRaises(SourceError):
            RegistryCatalog.from_database(self.db).validate(stored_spec)
        # Retirement also preserves idempotent retrieval of the pinned job.
        with self.db.transaction() as session:
            session.get(models.RuntimeImage, "runtime").enabled = False
        self.assertEqual(self.manager.create_job("alice", submitted, "pinned")["spec"]["runtime_image"], original_digest)

    def test_invalid_runtime_catalog_digest_is_rejected_before_job_creation(self):
        with self.db.transaction() as session:
            session.execute(update(models.RuntimeImage).where(models.RuntimeImage.id == "runtime").values(digest="latest"))
        self.assert_error(422, "invalid_runtime_image_digest", lambda: self.create())
        with self.db.transaction() as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(models.Job)), 0)

    def test_job_operator_without_submitter_catalog_can_see_approved_external_node(self):
        with self.db.transaction() as session:
            session.add(models.ParticipantBinding(id="data", project_id="project", participant_id="alice-data",
                node_id="approved-node", dataset_label="Locally approved data", enabled=True))
        submitted = self.spec()
        submitted["participants"] = [{"participant_id": "alice-data", "dataset_binding": "data", "mode": "external"},
                                     submitted["participants"][1]]
        job = self.manager.create_job("alice", submitted, "external")
        granted = self.manager.put_member("alice", job["id"], "operator-only", "operator", 1, "grant-op")
        self.assertEqual(self.manager.catalog("operator-only")["participant_bindings"], [])
        detail = self.manager.get_job("operator-only", job["id"])
        self.assertEqual(detail["participants"][0]["node_id"], "approved-node")
        self.assertIn("enroll_participant", detail["allowed_actions"])
        self.assertIn("enroll_participant", detail["participants"][0]["allowed_actions"])
        self.manager.put_member("alice", job["id"], "reader-only", "reader", granted["version"], "grant-reader")
        reader = self.manager.get_job("reader-only", job["id"])
        self.assertEqual(reader["participants"][0]["allowed_actions"], [])
        self.assertNotIn("enroll_participant", reader["allowed_actions"])


    def test_current_attempt_telemetry_reaches_dashboard_without_overriding_confirmed_round(self):
        with self.db.transaction() as session:
            session.add(models.ParticipantBinding(id="data", project_id="project", participant_id="participant",
                node_id="node", dataset_label="Approved", enabled=True))
        submitted = self.spec()
        submitted["participants"] = [{"participant_id": "participant", "dataset_binding": "data", "mode": "managed", "component_id": "client"},
                                     submitted["participants"][1]]
        submitted["components"].append({"component_id": "client", "role": "participant", "participant_id": "participant",
            "resources": dict(submitted["components"][0]["resources"])})
        job = self.manager.create_job("alice", submitted, "telemetry")
        with self.db.transaction() as session:
            record = session.get(models.Job, job["id"])
            record.state = "RUNNING"; record.epoch = 1; record.current_round = 1
            attempt = session.scalar(select(models.Attempt).where(models.Attempt.job_id == job["id"]))
            attempt.state = "RUNNING"
            attempt.details_json = {"components": {
                "owner": {"metrics": {"accuracy": .8, "loss": .2}, "readiness": "ready", "current_round": 99,
                    "observed_at": self.now.isoformat(), "host_path": "/must-not-leak", "token": "must-not-leak"},
                "client": {"metrics": {"loss": .4}, "readiness": "training", "observed_at": self.now.isoformat()},
                "foreign-component": {"metrics": {"private": 123}, "readiness": "ready"}}}
            for component_id in ("owner", "client"):
                session.add(models.Allocation(job_id=job["id"], attempt_id=attempt.id, component_id=component_id,
                    pool_id="cpu", cpu_millicores=1000, memory_bytes=1 << 30, disk_bytes=1 << 30, epoch=1, state="RUNNING"))
            session.add(models.ProvisioningResource(id="owned-space", job_id=job["id"], component_id="owner",
                kind="exchange_space", external_id="space", state="ready", ownership_json={"job_id": job["id"]}))
        detail = self.manager.get_job("alice", job["id"])
        self.assertEqual(detail["current_round"], 1)
        self.assertEqual(detail["metrics"], {"accuracy": .8, "loss": .2})
        self.assertEqual(detail["participants"][0]["readiness"], "training")
        self.assertEqual(detail["participants"][0]["metrics"], {"loss": .4})
        self.assertEqual(detail["progress"]["freshness"], "current")
        self.assertEqual(detail["space_id"], "space")
        self.assertEqual(len(detail["allocations"]), 2)
        self.assertNotIn("must-not-leak", str(detail))
        self.assertNotIn("foreign-component", str(detail))
        self.assertEqual(self.manager.list_attempts("alice", job["id"])["items"][0]["components"][0]["metrics"], detail["metrics"])
        self.now += timedelta(minutes=6)
        self.assertEqual(self.manager.get_job("alice", job["id"])["progress"]["freshness"], "stale")

    def test_missing_or_foreign_attempt_reports_are_explicitly_not_observed(self):
        job = self.create()
        with self.db.transaction() as session:
            attempt = session.scalar(select(models.Attempt).where(models.Attempt.job_id == job["id"]))
            attempt.details_json = {"components": {"owner": {"metrics": {"accuracy": .9}, "readiness": "ready"}}}
            session.get(models.Job, job["id"]).epoch = 2
        detail = self.manager.get_job("alice", job["id"])
        self.assertEqual(detail["metrics"], {})
        self.assertEqual(detail["progress"]["metrics_status"], "not_observed")
        self.assertEqual(detail["progress"]["components"][0]["readiness"], "not_observed")
        self.assertIsNone(detail["space_id"])

    def test_reader_revocation_remains_possible_on_historical_purged_tombstone(self):
        job = self.create()
        granted = self.manager.put_member("alice", job["id"], "bob", "reader", 1, "reader")
        with self.db.transaction() as session:
            record = session.get(models.Job, job["id"])
            record.state = "SUCCEEDED"; record.purged_at = self.now
        self.assertTrue(self.manager.get_job("bob", job["id"])["purged"])
        self.manager.delete_member("alice", job["id"], "bob", granted["version"], "revoke-past")
        for read in (lambda: self.manager.get_job("bob", job["id"]),
                     lambda: self.manager.list_attempts("bob", job["id"]),
                     lambda: self.manager.list_events("bob", job["id"]),
                     lambda: self.manager.list_artifacts("bob", job["id"])):
            self.assert_error(404, "job_not_found", read)
        current = self.manager.get_job("alice", job["id"])
        self.assertIn("manage_members", current["allowed_actions"])
        self.assert_error(409, "last_job_admin_required", lambda: self.manager.delete_member("alice", job["id"], "alice", current["version"], "last-admin"))
        self.assert_error(409, "job_purged", lambda: self.manager.retry("alice", job["id"], current["version"], "retry-purged"))

    def test_combined_planned_storage_rejects_permanently_impossible_job_before_writes(self):
        calls = []
        def plan(job):
            calls.append(job)
            self.assertEqual(job.spec_json["runtime_image"], "sha256:" + "b" * 64)
            self.assertEqual(job.spec_hash, JobSpec.model_validate(job.spec_json).digest)
            self.assertIsNone(inspect(job).session)
            return [{"kind": "source", "external_id": "owned-source", "component_id": "owner",
                     "pool_id": "cpu", "max_bytes": 22216704}]
        self.manager.storage_planner = plan
        with self.db.transaction() as session:
            session.get(models.Pool, "cpu").disk_bytes = (1 << 30) + 1024
        self.assert_error(422, "resource_request_exceeds_pool", self.create)
        self.assertEqual(len(calls), 1)
        with self.db.transaction() as session:
            for model in (models.Job, models.Attempt, models.Event, models.ProvisioningResource, models.Idempotency):
                self.assertEqual(session.scalar(select(func.count()).select_from(model)), 0)

    def test_static_storage_admission_preserves_busy_unhealthy_queue_and_stable_replay(self):
        other = self.create(key="other")
        with self.db.transaction() as session:
            pool = session.get(models.Pool, "cpu")
            pool.healthy = False
            pool.quarantined = True
            attempt = session.scalar(select(models.Attempt).where(models.Attempt.job_id == other["id"]))
            session.add(models.Allocation(job_id=other["id"], attempt_id=attempt.id, component_id="owner",
                pool_id="cpu", cpu_millicores=1000, memory_bytes=1 << 30, disk_bytes=pool.disk_bytes,
                state="QUARANTINED", epoch=1))
        def plan(job):
            return [{"kind": "source", "external_id": "owned-source", "component_id": "owner",
                     "pool_id": "cpu", "max_bytes": 1024}]
        self.manager.storage_planner = plan
        result = self.create(key="queued")
        self.assertEqual(result["state"], "QUEUED")
        self.manager.storage_planner = lambda job: (_ for _ in ()).throw(AssertionError("replay must not replan"))
        self.assertEqual(self.create(key="queued")["id"], result["id"])

    def test_planned_storage_only_pool_and_absolute_project_quota_are_checked(self):
        with self.db.transaction() as session:
            session.add(models.Pool(id="storage", name="Storage", node_id="storage-node", disk_bytes=1024,
                cpu_millicores=1, memory_bytes=1, healthy=False))
        self.manager.storage_planner = lambda job: [{"kind": "source", "external_id": "owned-source",
            "component_id": "owner", "pool_id": "storage", "max_bytes": 1025}]
        self.assert_error(422, "resource_request_exceeds_pool", self.create)
        self.manager.storage_planner = lambda job: [{"kind": "source", "external_id": "owned-source",
            "component_id": "owner", "pool_id": "storage", "max_bytes": 1024}]
        with self.db.transaction() as session:
            session.get(models.Project, "project").quotas_json = {"disk_bytes": (1 << 30) + 1023}
        self.assert_error(422, "resource_request_exceeds_project_quota", self.create)

    def test_manager_storage_pool_cannot_be_mutated_or_reclassified_by_generic_api(self):
        with self.db.transaction() as session:
            session.add(models.Pool(id="storage", name="Owned Storage", node_id="manager", disk_bytes=1024,
                cpu_millicores=0, memory_bytes=0, sandbox_profiles=[], healthy=True,
                details_json={"manager_storage": True, "root_device": 10, "root_inode": 20}))
        self.manager.pool_qualifier = lambda proposed: True
        for values in ({"healthy": False}, {"quarantined": True}, {"disk_bytes": 2048},
                       {"cpu_millicores": 1000, "memory_bytes": 1024, "sandbox_profiles": ["runsc-cpu-v1"]}):
            self.assert_error(409, "manager_storage_pool_requires_trusted_cli",
                              lambda: self.manager.put_pool("platform", "storage", values))
        with self.db.transaction() as session:
            storage = session.get(models.Pool, "storage")
            self.assertEqual((storage.cpu_millicores, storage.memory_bytes, storage.disk_bytes), (0, 0, 1024))
            self.assertEqual(storage.sandbox_profiles, [])
            self.assertTrue(storage.healthy)
            self.assertEqual(session.scalar(select(func.count()).select_from(models.AdministrativeAudit)), 0)

    def test_future_execution_retention_cap_is_preaccounted_without_pool_double_count(self):
        def plan(job):
            return [{"kind": "execution_state", "external_id": "owned-state", "component_id": "owner",
                     "pool_id": "cpu", "max_bytes": 1 << 30, "covered_by_allocation": True},
                    {"kind": "collection_budget", "external_id": "owned-copy", "component_id": "owner",
                     "pool_id": "cpu", "max_bytes": 1024}]
        self.manager.storage_planner = plan
        with self.db.transaction() as session:
            session.get(models.Pool, "cpu").disk_bytes = (1 << 30) + 1024
            session.get(models.Project, "project").quotas_json = {"retained_bytes": 1024}
        self.assert_error(422, "resource_request_exceeds_project_quota", self.create)
        with self.db.transaction() as session:
            session.get(models.Project, "project").quotas_json = {"retained_bytes": (1 << 30) + 1024}
        self.assertEqual(self.create()["state"], "QUEUED")

    def test_invalid_explicit_managed_quorum_is_rejected_before_rows_resources_or_planning(self):
        planned = []
        self.manager.storage_planner = lambda candidate: planned.append(candidate) or []
        for minimum in (0, 1, -1, 3, True, False, 2.0, "2", None):
            spec = self.spec()
            spec["participants"] = [{"participant_id": name, "dataset_binding": name + "-binding", "mode": "external"}
                                    for name in ("alice", "bob")]
            spec["options"] = {"minimum_participants": minimum}
            with self.subTest(minimum=minimum):
                self.assert_error(422, "invalid_job_spec", lambda: self.manager.create_job("alice", spec, "bad-quorum"))
        self.assertEqual(planned, [])
        with self.db.transaction() as session:
            for model in (models.Job, models.Attempt, models.Event, models.ProvisioningResource, models.Idempotency):
                self.assertEqual(session.scalar(select(func.count()).select_from(model)), 0)

    def test_valid_explicit_managed_quorum_keeps_other_plugin_options_opaque(self):
        with self.db.transaction() as session:
            session.add_all([models.ParticipantBinding(id=name + "-binding", project_id="project",
                participant_id=name, node_id=name + "-node", dataset_label="Dataset") for name in ("alice", "bob")])
        spec = self.spec()
        spec["participants"] = [{"participant_id": name, "dataset_binding": name + "-binding", "mode": "external"}
                                for name in ("alice", "bob")]
        spec["options"] = {"minimum_participants": 2, "round_cfg": {"minimum_participants": 1},
                           "custom": {"epochs": 3}}
        job = self.manager.create_job("alice", spec, "valid-quorum")
        self.assertEqual(job["state"], "QUEUED")
        self.assertEqual(job["spec"]["options"], spec["options"])

    def test_object_store_pool_cannot_be_mutated_or_reclassified_by_generic_api(self):
        with self.db.transaction() as session:
            session.add(models.Pool(id="objects", name="Approved Object Store", node_id="object-service", disk_bytes=1024,
                cpu_millicores=0, memory_bytes=0, sandbox_profiles=[], healthy=True,
                details_json={"object_store": True, "backend_id": "immutable-backend", "capacity_bound_bytes": 1024}))
        self.manager.pool_qualifier = lambda proposed: True
        for values in ({"healthy": False}, {"quarantined": True}, {"disk_bytes": 2048},
                       {"cpu_millicores": 1000, "memory_bytes": 1024, "sandbox_profiles": ["runsc-cpu-v1"]},
                       {"node_id": "another-service"}):
            self.assert_error(409, "object_store_pool_requires_trusted_cli",
                              lambda: self.manager.put_pool("platform", "objects", values))
        self.assert_error(422, "invalid_pool_fields", lambda: self.manager.put_pool("platform", "new-objects",
            {"name": "Objects", "node_id": "service", "details_json": {"object_store": True}}))
        with self.db.transaction() as session:
            pool = session.get(models.Pool, "objects")
            self.assertEqual((pool.cpu_millicores, pool.memory_bytes, pool.disk_bytes), (0, 0, 1024))
            self.assertEqual(pool.node_id, "object-service")
            self.assertEqual(pool.details_json["backend_id"], "immutable-backend")
            self.assertEqual(session.scalar(select(func.count()).select_from(models.AdministrativeAudit)), 0)

    def test_default_quorum_rejects_zero_or_one_participant_before_any_creation(self):
        planned = []
        self.manager.storage_planner = lambda candidate: planned.append(candidate) or []
        for count in (0, 1):
            spec = self.spec()
            spec["participants"] = spec["participants"][:count]
            self.assertEqual(len(JobSpec.model_validate(spec).participants), count)  # Historical parsing remains possible.
            self.assert_error(422, "invalid_job_spec", lambda: self.manager.create_job("alice", spec, "default-quorum"))
        self.assertEqual(planned, [])
        with self.db.transaction() as session:
            for model in (models.Job, models.Attempt, models.Event, models.ProvisioningResource, models.Idempotency):
                self.assertEqual(session.scalar(select(func.count()).select_from(model)), 0)

    def test_default_quorum_accepts_two_approved_immutable_participants(self):
        job = self.create()
        self.assertEqual(job["state"], "QUEUED")
        self.assertEqual(len(job["spec"]["participants"]), 2)
        self.assertNotIn("minimum_participants", job["spec"]["options"])
        self.assertEqual({item["node_id"] for item in job["participants"]}, {"node-a", "node-b"})

    def test_reserved_external_component_identity_collision_is_rejected_precreation(self):
        import hashlib
        from hf2l_jobs.domain import canonical_json
        reserved = "participant-" + hashlib.sha256(canonical_json(["participant-a"]).encode()).hexdigest()[:40]
        for role in ("owner", "build"):
            spec = self.spec()
            if role == "owner":
                spec["components"][0]["component_id"] = reserved
            else:
                spec["components"].append({"component_id": reserved, "role": "build",
                    "resources": dict(spec["components"][0]["resources"])})
            self.assert_error(422, "invalid_job_spec", lambda: self.manager.create_job("alice", spec, "cid-collision"))
        with self.db.transaction() as session:
            for model in (models.Job, models.Attempt, models.Event, models.ProvisioningResource, models.Idempotency):
                self.assertEqual(session.scalar(select(func.count()).select_from(model)), 0)

    def test_canonical_external_prepaid_log_plan_is_admitted_on_approved_storage_pool(self):
        import hashlib
        from hf2l_jobs.domain import canonical_json
        with self.db.transaction() as session:
            session.add(models.Pool(id="manager-storage", name="Approved Storage", node_id="manager", disk_bytes=2 * 1024**2,
                cpu_millicores=0, memory_bytes=0, details_json={"manager_storage": True}))
        def plan(job):
            entries = []
            for name in ("a", "b"):
                component = "participant-" + hashlib.sha256(canonical_json(["participant-" + name]).encode()).hexdigest()[:40]
                entries.append({"kind": "log_budget", "external_id": "hf2l-log://" + job.id + "/1/" + component,
                                "component_id": component, "pool_id": "manager-storage", "max_bytes": 1024**2})
            return entries
        self.manager.storage_planner = plan
        job = self.create()
        self.assertEqual(job["state"], "QUEUED")
        with self.db.transaction() as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(models.Job)), 1)
            self.assertEqual(session.scalar(select(func.count()).select_from(models.ProvisioningResource)), 0)

    def test_external_storage_plan_cannot_claim_foreign_component_kind_size_or_job(self):
        import hashlib
        from hf2l_jobs.domain import canonical_json
        component = "participant-" + hashlib.sha256(canonical_json(["participant-a"]).encode()).hexdigest()[:40]
        for override in ({"component_id": "foreign-component"}, {"kind": "source"},
                         {"max_bytes": 1024**2 - 1}, {"external_id": "hf2l-log://foreign/1/" + component},
                         {"covered_by_allocation": True}):
            def plan(job):
                return [{"kind": "log_budget", "external_id": "hf2l-log://" + job.id + "/1/" + component,
                         "component_id": component, "pool_id": "cpu", "max_bytes": 1024**2, **override}]
            self.manager.storage_planner = plan
            with self.subTest(override=override), self.assertRaises(ValueError):
                self.create()
        with self.db.transaction() as session:
            for model in (models.Job, models.Attempt, models.Event, models.ProvisioningResource, models.Idempotency):
                self.assertEqual(session.scalar(select(func.count()).select_from(model)), 0)
