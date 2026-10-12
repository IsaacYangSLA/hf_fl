"""Actual durable cursors, quota rollback, redaction boundaries and safe files."""
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import tempfile
import unittest

from sqlalchemy import select

from hf2l_jobs.database import create_database
from hf2l_jobs.executor import ExecutionIdentity, ExecutorRefused
from hf2l_jobs.log_stream import CanonicalLogSpool, ingest_component_logs
from hf2l_jobs import models


class CanonicalLogTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "logs"
        self.identity = ExecutionIdentity("job", "attempt", "owner", 1)
        self.spool = CanonicalLogSpool(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def read(self, offset=0, maximum=65536):
        return self.spool.read(self.identity, offset=offset, max_bytes=maximum)

    def test_append_restart_and_repeated_snapshot_never_duplicate(self):
        first = "2026-10-10T01:00:00.000000001Z hello\n"
        second = first + "2026-10-10T01:00:01.000000001Z hello\n"
        self.spool.update(first)
        receipt = self.read()
        self.assertEqual(receipt["content"], first)
        self.spool = CanonicalLogSpool(self.root)
        self.spool.update(first)
        self.assertEqual(self.read(receipt["next_offset"])["content"], "")
        self.spool.update(second, complete=True)
        remainder = self.read(receipt["next_offset"])
        self.assertEqual(remainder["content"], second[len(first):])
        self.assertTrue(remainder["complete"])
        self.assertFalse(remainder["truncated"])

    def test_rotation_overlap_preserves_stable_offsets_and_gap_is_visible(self):
        records = [f"2026-10-10T01:00:{i:02}.000000001Z line{i} " + "a" * 4500 + "\n" for i in range(4)]
        self.spool.update(records[0] + records[1])
        offset = self.read()["next_offset"]
        self.spool.update(records[1] + records[2])
        receipt = self.read(offset)
        self.assertEqual(receipt["content"], records[2])
        self.assertFalse(receipt["truncated"])
        self.spool.update(records[3], complete=True)
        gap = self.read(receipt["next_offset"])
        self.assertIn("log capture gap", gap["content"])
        self.assertTrue(gap["truncated"])
        self.assertTrue(gap["complete"])

    def test_completion_after_container_removal_preserves_canonical_bytes(self):
        self.spool.update("2026-10-10T01:00:00Z finished\n")
        before = self.read()
        self.spool = CanonicalLogSpool(self.root)
        self.spool.mark_complete()
        after = self.read()
        self.assertTrue(after["complete"])
        self.assertFalse(after["truncated"])
        self.assertEqual(after["content"], before["content"])
        self.spool.mark_complete()
        self.assertEqual(self.read(), after)

    def test_utf8_chunk_boundary_and_malformed_input_remain_bounded(self):
        self.spool.update(("é" * 5).encode() + b"\xff\n", complete=True)
        first = self.read(maximum=5)
        self.assertEqual(first["content"], "éé")
        self.assertEqual(first["next_offset"], 4)
        content = first["content"]
        offset = first["next_offset"]
        while True:
            receipt = self.read(offset, 5)
            self.assertLessEqual(len(receipt["content"].encode()), 5)
            content += receipt["content"]
            offset = receipt["next_offset"]
            if receipt["complete"]:
                break
        self.assertEqual(content, "é" * 5 + "�\n")
        with self.assertRaises(ExecutorRefused):
            self.read(1)

    def test_canonical_limit_has_one_explicit_marker_and_never_grows(self):
        spool = CanonicalLogSpool(self.root, max_bytes=256)
        spool.update("x" * 1000)
        initial = spool.read(self.identity)
        self.assertTrue(initial["truncated"])
        self.assertIn("log output truncated", initial["content"])
        spool.update("x" * 1100, complete=True)
        receipt = spool.read(self.identity)
        self.assertEqual(receipt["content"], initial["content"])
        self.assertLessEqual(receipt["next_offset"], 256)
        self.assertTrue(receipt["complete"])

    def test_symlink_hardlink_and_nonprivate_roots_are_denied(self):
        self.spool.update("safe")
        path = self.root / "stdout.log"
        outside = Path(self.temporary.name) / "outside"
        path.rename(outside)
        path.symlink_to(outside)
        with self.assertRaises(OSError):
            self.read()
        path.unlink()
        os.link(outside, path)
        with self.assertRaises(ExecutorRefused):
            self.read()
        os.chmod(self.root, 0o755)
        with self.assertRaises(ExecutorRefused):
            CanonicalLogSpool(self.root)

    def test_interrupted_append_is_not_exposed_or_duplicated(self):
        self.spool.update("committed\n")
        with (self.root / "stdout.log").open("ab") as stream:
            stream.write(b"uncommitted\n")
        self.assertEqual(self.read()["content"], "committed\n")
        self.spool.update("committed\nnext\n", complete=True)
        self.assertEqual(self.read()["content"], "committed\nnext\n")

    def test_redaction_before_chunking_does_not_split_a_secret(self):
        from hf2l_jobs.collection import SafeCollector
        root = Path(self.temporary.name) / "source"
        root.mkdir(mode=0o700)
        (root / "stdout.log").write_text("a" * 65530 + "super-private-secret" + "b" * 100)
        with SafeCollector(root, secret_values=("super-private-secret",)) as collector:
            clean = collector.logs("stdout.log")
        self.spool.update(clean, complete=True)
        first = self.read()
        second = self.read(first["next_offset"])
        captured = first["content"] + second["content"]
        self.assertNotIn("super-private-secret", captured)
        self.assertNotIn("super-private", captured)
        self.assertEqual(captured, clean)


class DurableManagerLogsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.db = create_database("sqlite:///" + str(self.root / "manager.db"))
        self.now = datetime(2026, 10, 10, tzinfo=timezone.utc)
        self.identity = ExecutionIdentity("job", "attempt", "owner", 1)
        (self.root / "node").mkdir(mode=0o700)
        self.spool = CanonicalLogSpool(self.root / "node" / "logs")
        self.node = type("Node", (), {"read_logs": lambda _, identity, **options: self.spool.read(identity, **options)})()
        with self.db.transaction() as session:
            session.add(models.Project(id="project", name="Project", quotas_json={"retained_bytes": 1048576}))
            session.add(models.Pool(id="pool", name="Pool", node_id="node", healthy=True))
            session.flush()
            session.add(models.Job(id="job", project_id="project", creator_id="alice", name="Job",
                spec_json={}, spec_hash="a" * 64, state="RUNNING", epoch=1, current_attempt=1, target_round=1))
            session.flush()
            session.add(models.Attempt(id="attempt", job_id="job", number=1, epoch=1))
            session.flush()
            session.add(models.Allocation(id="allocation", job_id="job", attempt_id="attempt", component_id="owner",
                pool_id="pool", cpu_millicores=100, memory_bytes=100, disk_bytes=100, epoch=1,
                details_json={"node_id": "immutable-node"}))

    def tearDown(self):
        self.db.close()
        self.temporary.cleanup()

    def ingest(self, **options):
        return ingest_component_logs(self.db, self.node, "allocation", clock=lambda: self.now, **options)

    def stored(self):
        with self.db.transaction() as session:
            chunks = session.scalars(select(models.LogChunk).order_by(models.LogChunk.sequence)).all()
            row = session.get(models.Allocation, "allocation")
            return "".join(chunk.data for chunk in chunks), [chunk.charged_bytes for chunk in chunks], row.details_json, session.get(models.Project, "project").retained_bytes

    def test_running_incremental_ingress_restart_and_terminal_catchup(self):
        data = "LeNet training loss=1.0\n" + "x" * 140000
        self.spool.update(data)
        initial = self.ingest()
        self.assertEqual(initial.chunks, 1)
        self.assertEqual(initial.bytes, 65536)
        self.assertEqual(self.stored()[2]["node_id"], "immutable-node")
        self.db.close()
        self.db = create_database("sqlite:///" + str(self.root / "manager.db"))
        self.spool.update(data + "\ntraining complete\n", complete=True)
        with self.db.transaction() as session:
            job = session.get(models.Job, "job")
            job.state = "SUCCEEDED"; job.epoch = 2; job.terminated_at = self.now
            job.artifacts_expire_at = self.now + timedelta(days=90)
            row = session.get(models.Allocation, "allocation")
            row.state = "RELEASED"; row.released_at = self.now
        result = self.ingest(terminal=True, max_chunks=16)
        self.assertTrue(result.complete)
        stored, charges, cursor, budget = self.stored()
        self.assertEqual(stored, data + "\ntraining complete\n")
        self.assertEqual(budget, len(stored.encode()))
        self.assertEqual(budget, sum(charges))
        self.assertTrue(cursor["log_stream"]["complete"])
        self.assertEqual(self.ingest(terminal=True).chunks, 0)
        self.assertEqual(self.stored()[3], budget)

    def test_frozen_clock_terminal_batches_keep_public_ingestion_order(self):
        self.spool.update("first" + "x" * 140000 + "last", complete=True)
        self.assertTrue(self.ingest(terminal=True, max_chunks=16).complete)
        with self.db.transaction() as session:
            chunks = session.scalars(select(models.LogChunk).order_by(models.LogChunk.created_at, models.LogChunk.id)).all()
            self.assertEqual([chunk.sequence for chunk in chunks], [1, 2, 3])
            self.assertTrue(chunks[0].created_at < chunks[1].created_at < chunks[2].created_at)
            self.assertEqual("".join(chunk.data for chunk in chunks), "first" + "x" * 140000 + "last")

    def log_budget(self, amount=1048576, holder="allocation"):
        from hf2l_jobs.retention import RetentionService
        with self.db.transaction() as session:
            session.get(models.Project, "project").quotas_json = {"retained_bytes": amount}
            session.get(models.Pool, "pool").disk_bytes = 10 * 1048576
            session.add(models.ProvisioningResource(id="log-budget", job_id="job", attempt_id="attempt",
                component_id="owner", kind="log_budget", external_id="hf2l-log://job/1/owner",
                ownership_json={"job_id": "job", "component_id": "owner", "kind": "log_budget"},
                details_json={"pool_id": "pool", "attempt_number": 1, "component_id": "owner",
                              "reservation_max_bytes": amount}, state="planned"))
            row = session.get(models.Allocation, holder)
            row.details_json = {**row.details_json, "log_resource_id": "log-budget"}
        RetentionService(self.db).reserve_resource("log-budget", "job", amount)

    def test_full_canonical_stream_uses_prepaid_budget_without_free_project_quota(self):
        self.log_budget()
        content = "x" * (1048576 - 65536)
        self.spool.update(content, complete=True)
        result = self.ingest(terminal=True, max_chunks=16)
        self.assertTrue(result.complete)
        self.assertFalse(result.truncated)
        self.assertEqual(result.bytes, len(content))
        stored, charges, details, budget = self.stored()
        self.assertEqual(stored, content)
        self.assertTrue(all(charge == 0 for charge in charges))
        self.assertEqual(budget, 1048576)
        with self.db.transaction() as session:
            resource = session.get(models.ProvisioningResource, "log-budget")
            self.assertEqual(resource.details_json["log_consumed_bytes"], len(content))
        self.assertEqual(self.ingest(terminal=True).chunks, 0)
        self.assertEqual(self.stored()[3], budget)

    def test_exhausted_prepaid_budget_advances_source_and_marks_truncation(self):
        self.log_budget(128)
        self.spool.update("x" * 200, complete=True)
        result = self.ingest(terminal=True, max_chunks=16)
        self.assertEqual(result.status, "limit_reached")
        self.assertTrue(result.complete)
        self.assertTrue(result.truncated)
        stored, charges, details, budget = self.stored()
        self.assertEqual(len(stored.encode()), 128)
        self.assertEqual(result.bytes, 128)
        self.assertEqual(charges, [0])
        self.assertEqual(budget, 128)
        self.assertEqual(details["log_stream"]["offset"], 200)
        self.assertEqual(details["log_stream"]["dropped_bytes"], 72)
        self.assertTrue(details["log_stream"]["budget_exhausted"])
        self.assertIn("omitted", stored)
        self.assertTrue(self.ingest(terminal=True).complete)
        self.assertEqual(self.stored()[0], stored)

    def test_utf8_budget_truncation_remains_sticky_for_later_ascii_tail(self):
        self.log_budget(128)
        content = "é" * 100
        self.spool.update(content)
        initial = self.ingest()
        self.assertTrue(initial.truncated)
        self.assertFalse(initial.complete)
        first = self.stored()[0]
        self.spool.update(content + "z", complete=True)
        final = self.ingest(terminal=True, max_chunks=16)
        self.assertTrue(final.complete)
        self.assertTrue(final.truncated)
        self.assertEqual(self.stored()[0], first)
        self.assertEqual(self.stored()[2]["log_stream"]["offset"], 201)
        self.assertEqual(self.stored()[3], 128)

    def test_foreign_prepaid_budget_pointer_is_never_consumed(self):
        from hf2l_jobs.domain import Error
        self.log_budget()
        self.spool.update("training\n", complete=True)
        with self.db.transaction() as session:
            resource = session.get(models.ProvisioningResource, "log-budget")
            resource.component_id = "foreign"
        with self.assertRaises(Error) as error:
            self.ingest()
        self.assertEqual(error.exception.code, "retained_log_budget_ownership_mismatch")
        self.assertEqual(self.stored()[0], "")
        self.assertNotIn("log_stream", self.stored()[2])
        self.assertEqual(self.stored()[3], 1048576)

    def test_quota_failure_writes_neither_bytes_nor_cursor_then_retries(self):
        self.spool.update("sensitive already redacted\n", complete=True)
        with self.db.transaction() as session:
            session.get(models.Project, "project").quotas_json = {"retained_bytes": 1}
        result = self.ingest()
        self.assertEqual(result.status, "quota_exceeded")
        data, charges, details, budget = self.stored()
        self.assertEqual((data, charges, budget), ("", [], 0))
        self.assertNotIn("log_stream", details)
        with self.db.transaction() as session:
            session.get(models.Project, "project").quotas_json = {"retained_bytes": 100}
        self.assertTrue(self.ingest().complete)
        self.assertEqual(self.stored()[3], len("sensitive already redacted\n".encode()))

    def test_foreign_identity_oversized_and_nonmonotonic_receipts_rejected(self):
        receipt = {"identity": asdict(self.identity), "source_id": self.identity.key,
            "offset": 0, "next_offset": 4, "content": "safe", "complete": True, "truncated": False}
        for patch in ({"identity": {**asdict(self.identity), "job_id": "foreign"}},
                      {"source_id": "foreign"}, {"next_offset": 5},
                      {"content": "x" * 65537, "next_offset": 65537}):
            node = type("Node", (), {"read_logs": lambda _, *args, **kwargs: {**receipt, **patch}})()
            with self.assertRaises(ExecutorRefused):
                ingest_component_logs(self.db, node, "allocation", clock=lambda: self.now)
        self.assertEqual(self.stored()[0], "")
        self.assertEqual(self.stored()[3], 0)

    def test_concurrent_cursor_winner_is_not_duplicated(self):
        self.spool.update("one\n", complete=True)
        original = self.node.read_logs
        def interleaved(identity, **options):
            receipt = original(identity, **options)
            self.assertTrue(self.ingest().complete)
            return receipt
        node = type("Node", (), {"read_logs": lambda _, identity, **options: interleaved(identity, **options)})()
        result = ingest_component_logs(self.db, node, "allocation", clock=lambda: self.now)
        self.assertEqual(result.status, "concurrent_poll")
        self.assertEqual(self.stored()[0], "one\n")
        self.assertEqual(self.stored()[3], 4)

    def test_purge_or_expiry_does_not_recreate_raw_logs(self):
        self.spool.update("raw\n", complete=True)
        for status in ("purge_pending", "expiry_pending", "expired"):
            with self.db.transaction() as session:
                session.get(models.Job, "job").cleanup_status = status
            self.assertEqual(self.ingest().status, "expired")
        self.assertEqual(self.stored()[0], "")
        self.assertEqual(self.stored()[3], 0)

    def test_missing_optional_reader_is_unavailable(self):
        self.assertEqual(ingest_component_logs(self.db, object(), "allocation").status, "unavailable")

    def test_two_attempts_share_monotonic_component_sequence_not_cursor(self):
        self.spool.update("attempt one\n", complete=True)
        self.ingest()
        with self.db.transaction() as session:
            old = session.get(models.Allocation, "allocation")
            old.state = "RELEASED"; old.released_at = self.now
            session.add(models.Attempt(id="attempt2", job_id="job", number=2, epoch=2))
            session.flush()
            session.add(models.Allocation(id="allocation2", job_id="job", attempt_id="attempt2", component_id="owner",
                pool_id="pool", cpu_millicores=100, memory_bytes=100, disk_bytes=100, epoch=2))
        identity = ExecutionIdentity("job", "attempt2", "owner", 2)
        (self.root / "node2").mkdir(mode=0o700)
        spool = CanonicalLogSpool(self.root / "node2" / "logs")
        spool.update("attempt two\n", complete=True)
        node = type("Node", (), {"read_logs": lambda _, identity, **options: spool.read(identity, **options)})()
        self.assertTrue(ingest_component_logs(self.db, node, "allocation2", clock=lambda: self.now).complete)
        with self.db.transaction() as session:
            chunks = session.scalars(select(models.LogChunk).order_by(models.LogChunk.sequence)).all()
            self.assertEqual([(chunk.sequence, chunk.attempt_number) for chunk in chunks], [(1, 1), (2, 2)])
        self.assertEqual(self.stored()[0], "attempt one\nattempt two\n")


class ExternalLogsTests(unittest.TestCase):
    setUp = DurableManagerLogsTests.setUp
    tearDown = DurableManagerLogsTests.tearDown
    stored = DurableManagerLogsTests.stored
    def external(self):
        with self.db.transaction() as session:
            session.add(models.ProvisioningResource(id="external", job_id="job", attempt_id="attempt",
                component_id="owner", kind="external_execution", external_id=self.identity.key,
                ownership_json={"job_id": "job", "attempt_id": "attempt", "component_id": "owner"},
                details_json={"node_id": "external-node", "epoch": 1}, state="ready", retained=True))

    def append(self, receipt, node_id="external-node"):
        from hf2l_jobs.log_stream import append_external_logs
        return append_external_logs(self.db, self.identity, receipt, resource_id="external",
                                    node_id=node_id, clock=lambda: self.now)

    def test_external_repeated_ack_is_idempotent_and_foreign_node_is_denied(self):
        from hf2l_jobs.domain import Error
        self.external()
        self.spool.update("external actual training\n", complete=True)
        receipt = self.spool.read(self.identity)
        self.assertTrue(self.append(receipt)["complete"])
        first = self.stored()
        self.assertTrue(self.append(receipt)["complete"])
        self.assertEqual(self.stored(), first)
        with self.assertRaises(Error) as error:
            self.append(receipt, node_id="foreign-node")
        self.assertEqual(error.exception.status, 404)
        self.assertEqual(first[0], "external actual training\n")

    def test_external_prepaid_budget_and_duplicate_ack_never_charge_twice(self):
        self.external()
        DurableManagerLogsTests.log_budget(self)
        with self.db.transaction() as session:
            resource = session.get(models.ProvisioningResource, "external")
            resource.details_json = {**resource.details_json, "log_resource_id": "log-budget"}
        self.spool.update("external training complete\n", complete=True)
        receipt = self.spool.read(self.identity)
        self.assertTrue(self.append(receipt)["complete"])
        first = self.stored()
        self.assertEqual(first[1], [0])
        self.assertEqual(first[3], 1048576)
        self.assertTrue(self.append(receipt)["complete"])
        self.assertEqual(self.stored(), first)

    def test_external_quota_failure_preserves_source_cursor_and_bytes(self):
        from hf2l_jobs.domain import Error
        self.external()
        self.spool.update("training\n", complete=True)
        with self.db.transaction() as session:
            session.get(models.Project, "project").quotas_json = {"retained_bytes": 1}
        with self.assertRaises(Error):
            self.append(self.spool.read(self.identity))
        with self.db.transaction() as session:
            self.assertNotIn("log_stream", session.get(models.ProvisioningResource, "external").details_json)
        self.assertEqual(self.stored()[0], "")
        self.assertEqual(self.stored()[3], 0)
