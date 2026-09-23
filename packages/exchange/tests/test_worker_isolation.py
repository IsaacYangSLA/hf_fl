"""Pool selection stays fenced by the transfer state at lease acquisition."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from sqlalchemy import select

from hf2l_exchange.application import Service
from hf2l_exchange.config import DatabaseSettings, Settings, StorageSettings, WorkerSettings
from hf2l_exchange.domain import Principal
from hf2l_exchange.models import Base, Space, TransferAttempt
from hf2l_exchange.storage import StoredObject, UploadHandle, Verification
from hf2l_exchange.transfers import TransferService
from hf2l_exchange.worker import tick


class RecordingStorage:
    protocol = "s3-multipart-v1"

    def __init__(self):
        self.calls = []

    def record(self, operation):
        self.calls.append((operation, threading.current_thread().name))

    def start(self, key):
        self.record("start")
        return UploadHandle("upload-" + key.rsplit("/", 1)[-1], key)

    def complete(self, handle, size, part_size):
        self.record("complete")
        return StoredObject(handle.key, "version-1")

    def verify(self, stored, size, digest):
        self.record("verify")
        return Verification(size, digest)

    def cleanup(self, key):
        self.record("cleanup")


class WorkerIsolationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="exchange-worker-isolation-")
        self.addCleanup(directory.cleanup)
        settings = Settings(
            database=DatabaseSettings(url="sqlite:///" + str(Path(directory.name) / "test.db")),
            storage=StorageSettings(bucket="test"),
            worker=WorkerSettings(verify_concurrency=1, cleanup_concurrency=1),
        )
        self.service = Service(settings)
        self.addCleanup(self.service.engine.dispose)
        Base.metadata.create_all(self.service.engine)
        self.owner = Principal("owner", "owner", bootstrap_admin=True)
        self.space_id = self.service.create_space(
            self.owner, {"name": "worker-isolation", "quota_bytes": 3}, "space")["id"]
        revision = self.service.register_type(
            self.owner, self.space_id, "document", {"schema": {"type": "object"}}, "type")
        self.record = self.service.create_record(self.owner, self.space_id, {
            "kind": "document", "schema_revision_id": revision["id"], "metadata": {},
            "attachments": [{"path": "test.bin", "size": 3, "sha256": sha256(b"abc").hexdigest()}],
        }, "record")
        self.storage = RecordingStorage()
        self.transfers = TransferService(self.service, self.storage)
        args = self.space_id, self.record["id"], self.record["attachments"][0]["id"], self.owner
        self.attempt_id = self.transfers.initiate(*args)["attempt_id"]
        self.transfers.complete(*args)
        self.storage.calls.clear()

    def current(self):
        with self.service.sessions.begin() as session:
            return session.get(TransferAttempt, self.attempt_id)

    def cancel(self):
        result = self.service.withdraw_record(self.owner, self.space_id, self.record["id"])
        self.assertEqual(result["state"], "cancelled")

    def assert_calls(self, operation, pool):
        self.assertEqual(len(self.storage.calls), 1, self.storage.calls)
        self.assertEqual(self.storage.calls[0][0], operation)
        self.assertTrue(self.storage.calls[0][1].startswith(pool), self.storage.calls)

    def test_cancel_after_selection_waits_for_cleanup_pool_without_taking_lease(self):
        original_work = self.transfers.work

        def select_then_cancel(batch):
            selected = original_work(batch)
            self.assertEqual(selected, ([self.attempt_id], []))
            self.cancel()
            return selected

        with patch.object(self.transfers, "work", side_effect=select_then_cancel):
            counts = tick(self.transfers)
        self.assertEqual((counts["skipped"], counts["cleaned"]), (1, 0))
        self.assertEqual(self.storage.calls, [])
        attempt = self.current()
        self.assertEqual((attempt.state, attempt.token, attempt.lease_until), ("cleanup", None, None))

        self.assertEqual(tick(self.transfers)["cleaned"], 1)
        self.assert_calls("cleanup", "exchange-cleanup")
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(Space, self.space_id).reclaiming, 0)

    def test_cleanup_dispatch_skips_every_verification_phase_without_mutating_attempt(self):
        for state in ("initiating", "completing", "verifying"):
            with self.subTest(state=state):
                with self.service.sessions.begin() as session:
                    session.get(TransferAttempt, self.attempt_id).state = state
                self.assertEqual(self.transfers.process(self.attempt_id, cleanup=True), "skipped")
                attempt = self.current()
                self.assertEqual((attempt.state, attempt.token, attempt.lease_until), (state, None, None))
                self.assertEqual(attempt.mutation_tokens, [])
                self.assertEqual(self.storage.calls, [])
        self.assertEqual(tick(self.transfers)["verified"], 1)
        self.assert_calls("verify", "exchange-verification")

    def test_wrong_pool_leaves_expired_cleanup_lease_for_cleanup_worker(self):
        self.cancel()
        with self.service.sessions.begin() as session:
            attempt = session.get(TransferAttempt, self.attempt_id)
            attempt.token, attempt.lease_until = "expired-owner", 0
        self.assertEqual(self.transfers.process(self.attempt_id), "skipped")
        attempt = self.current()
        self.assertEqual((attempt.state, attempt.token, attempt.lease_until), ("cleanup", "expired-owner", 0))
        self.assertEqual(self.storage.calls, [])
        self.assertEqual(tick(self.transfers)["cleaned"], 1)
        self.assert_calls("cleanup", "exchange-cleanup")

    def test_cancellation_after_acquisition_cannot_change_provider_operation(self):
        original_acquire = self.transfers.acquire

        def acquire_then_cancel(*args, **kwargs):
            attempt = original_acquire(*args, **kwargs)
            self.assertIsNotNone(attempt)
            self.cancel()
            return attempt

        with patch.object(self.transfers, "acquire", side_effect=acquire_then_cancel):
            self.assertEqual(tick(self.transfers)["skipped"], 1)
        self.assert_calls("verify", "exchange-verification")
        self.assertEqual(self.current().state, "cleanup")
        self.storage.calls.clear()
        self.assertEqual(tick(self.transfers)["cleaned"], 1)
        self.assert_calls("cleanup", "exchange-cleanup")

    def test_competing_workers_take_only_one_phase_matched_lease(self):
        contender = TransferService(self.service, self.storage)
        gate = threading.Barrier(2)

        def acquire(transfers):
            gate.wait(timeout=5)
            return transfers.acquire(self.attempt_id, cleanup=False)

        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = [pool.submit(acquire, transfers) for transfers in (self.transfers, contender)]
            claimed = [result for future in pending if (result := future.result()) is not None]
        self.assertEqual(len(claimed), 1)
        self.assertEqual(self.current().token, claimed[0].token)
        self.assertEqual(contender.process(self.attempt_id), "skipped")
        self.assertEqual(self.storage.calls, [])
        self.transfers.release_lease(claimed[0])
        self.assertEqual(tick(contender)["verified"], 1)
        self.assert_calls("verify", "exchange-verification")

    def test_direct_acquire_remains_available_for_cleanup_callers(self):
        self.cancel()
        attempt = self.transfers.acquire(self.attempt_id)
        self.assertIsNotNone(attempt)
        self.assertEqual(attempt.state, "cleanup")
        self.assertEqual(self.current().token, attempt.token)
        self.transfers.release_lease(attempt)
        self.assertEqual(tick(self.transfers)["cleaned"], 1)

    def test_initiation_recovery_keeps_new_upload_in_verification_pool(self):
        with self.service.sessions.begin() as session:
            session.get(TransferAttempt, self.attempt_id).state = "initiating"
        self.assertEqual(tick(self.transfers)["recovered"], 1)
        self.assert_calls("start", "exchange-verification")
        self.assertEqual(self.current().state, "cleanup")
        with self.service.sessions.begin() as session:
            replacement = session.scalar(select(TransferAttempt).where(TransferAttempt.id != self.attempt_id))
            self.assertEqual(replacement.state, "uploading")
        self.storage.calls.clear()
        self.assertEqual(tick(self.transfers)["cleaned"], 1)
        self.assert_calls("cleanup", "exchange-cleanup")


if __name__ == "__main__":
    unittest.main()
