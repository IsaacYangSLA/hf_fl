"""Deterministic lifecycle races independently of a particular blob provider."""
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import tempfile
import time
import unittest

from sqlalchemy import select

from hf2l_exchange.application import Service
from hf2l_exchange.config import DatabaseSettings, Settings, StorageSettings, WorkerSettings
from hf2l_exchange.domain import ExchangeError, Principal
from hf2l_exchange.models import Base, Blob, Record, Space, TransferAttempt, database_time
from hf2l_exchange.storage import S3BlobStore, StorageFailure, StoredObject, TransferGrant, UploadHandle, UploadedPart, Verification
from hf2l_exchange.transfers import TransferService, repair_mutations, inspect_mutations
from hf2l_exchange.worker import tick


class FakeStore:
    protocol = "s3-multipart-v1"

    def __init__(self):
        self.started, self.cleaned = [], []
        self.parts_result = [UploadedPart(1, "opaque", 3)]
        self.failure = None
        self.on_start = self.on_complete = self.on_grant = None
        self.grant_expiry_offset = 0

    def start(self, key):
        self.started.append(key)
        if self.on_start:
            self.on_start(key)
        if self.failure:
            raise self.failure
        return UploadHandle("upload-" + key.rsplit("/", 1)[-1], key)

    def parts(self, handle):
        return self.parts_result

    def upload_grant(self, handle, number, size, expires_at, seconds):
        if self.on_grant:
            self.on_grant()
        return TransferGrant("https://storage.example.test/put", {"Content-Length": str(size)},
                             expires_at + self.grant_expiry_offset)

    def complete(self, handle, size, part_size):
        if self.on_complete:
            self.on_complete()
        if self.failure:
            raise self.failure
        return StoredObject(handle.key, "version-exact")

    def verify(self, stored, size, digest):
        if self.failure:
            raise self.failure
        return Verification(size, digest)

    def download_grant(self, stored, expires_at, seconds):
        return TransferGrant("https://storage.example.test/get", {}, expires_at)

    def cleanup(self, key):
        if self.failure:
            raise self.failure
        self.cleaned.append(key)


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="v2-transfer-test-")
        self.addCleanup(self.temp.cleanup)
        settings = Settings(database=DatabaseSettings(url="sqlite:///" + str(Path(self.temp.name) / "test.db")),
            storage=StorageSettings(bucket="test", grant_seconds=2), worker=WorkerSettings())
        self.service = Service(settings)
        Base.metadata.create_all(self.service.engine)
        self.addCleanup(self.service.engine.dispose)
        self.principal = Principal("owner", "owner", bootstrap_admin=True)
        self.space = self.service.create_space(self.principal, {"name": "documents", "quota_bytes": 3}, "space")["id"]
        revision = self.service.register_type(self.principal, self.space, "document", {"schema": {"type": "object"}}, "type")
        self.record = self.service.create_record(self.principal, self.space, {"kind": "document",
            "schema_revision_id": revision["id"], "metadata": {}, "attachments": [
                {"path": "document.bin", "size": 3, "sha256": sha256(b"abc").hexdigest()}]}, "record")
        self.blob = self.record["attachments"][0]["id"]
        self.args = self.space, self.record["id"], self.blob, self.principal
        self.storage = FakeStore()
        self.transfers = TransferService(self.service, self.storage)

    def current(self):
        with self.service.sessions.begin() as session:
            return session.scalar(select(TransferAttempt).where(TransferAttempt.blob_id == self.blob)
                                  .order_by(TransferAttempt.created_at.desc(), TransferAttempt.id.desc()))

    def upload(self):
        self.transfers.initiate(*self.args)
        self.transfers.complete(*self.args)

    def due(self, attempt_id):
        with self.service.sessions.begin() as session:
            attempt = session.get(TransferAttempt, attempt_id)
            attempt.next_attempt, attempt.lease_until, attempt.grant_expires_at = 0, None, 0

    def test_completion_and_verification_are_distinct_and_object_identity_private(self):
        response = self.transfers.initiate(*self.args)
        self.assertEqual(response["state"], "uploading")
        self.assertNotIn("object_key", response)
        self.transfers.complete(*self.args)
        with self.service.sessions.begin() as session:
            blob = session.get(Blob, self.blob)
            self.assertEqual(blob.state, "verifying")
            self.assertIsNone(blob.object_key)
            self.assertIsNone(blob.object_version)
        self.assertEqual(tick(self.transfers)["verified"], 1)
        self.service.publish_record(self.principal, self.space, self.record["id"], "publish")
        grant = self.transfers.download(*self.args)
        self.assertEqual(grant["sha256"], sha256(b"abc").hexdigest())
        with self.service.sessions.begin() as session:
            blob = session.get(Blob, self.blob)
            self.assertEqual(blob.object_version, "version-exact")
            self.assertGreaterEqual(blob.grant_expires_at, grant["expires_at"])

    def test_second_completion_request_does_not_start_competing_provider_call(self):
        self.transfers.initiate(*self.args)
        observations = []
        self.storage.on_complete = lambda: observations.append(self.transfers.complete(*self.args)["state"])
        self.transfers.complete(*self.args)
        self.assertEqual(observations, ["completing"])

    def test_stale_owner_cannot_commit_or_release_successor_lease(self):
        self.upload()
        original = self.transfers.acquire(self.current().id)
        with self.service.sessions.begin() as session:
            attempt = session.get(TransferAttempt, original.id)
            attempt.lease_until = 0
        successor = self.transfers.acquire(original.id)
        self.assertNotEqual(original.token, successor.token)
        self.assertFalse(self.transfers.commit(original, "verified", Verification(3, sha256(b"abc").hexdigest())))
        self.transfers.release_lease(original)
        self.assertEqual(self.current().token, successor.token)
        self.assertTrue(self.transfers.commit(successor, "verified", Verification(3, sha256(b"abc").hexdigest())))

    def test_missing_version_fails_record_and_retains_quota_until_cleanup(self):
        self.upload()
        self.storage.failure = StorageFailure("storage_missing")
        self.assertEqual(tick(self.transfers)["failed"], 1)
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(Record, self.record["id"]).state, "failed")
            space = session.get(Space, self.space)
            self.assertEqual((space.allocated, space.reclaiming), (0, 3))
        self.assertEqual(tick(self.transfers)["retry"], 1)
        attempt = self.current()
        self.assertEqual(attempt.retry_count, 1)
        self.assertEqual(attempt.last_error, "storage_missing")
        self.storage.failure = None
        self.due(attempt.id)
        self.assertEqual(tick(self.transfers)["cleaned"], 1)
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(Space, self.space).reclaiming, 0)

    def test_actual_grant_expiry_controls_cleanup_even_after_cancellation(self):
        self.transfers.initiate(*self.args)
        self.storage.grant_expiry_offset = 50
        grants = self.transfers.grants(*self.args, [1])["grants"]
        self.service.withdraw_record(self.principal, self.space, self.record["id"])
        attempt = self.current()
        self.assertGreaterEqual(attempt.grant_expires_at, grants[0]["expires_at"])
        self.assertEqual(tick(self.transfers)["cleaned"], 0)
        self.assertEqual(self.storage.cleaned, [])
        self.due(attempt.id)
        self.assertEqual(tick(self.transfers)["cleaned"], 1)

    def test_cancel_during_grant_signing_never_exposes_a_grant(self):
        self.transfers.initiate(*self.args)
        self.storage.on_grant = lambda: self.service.withdraw_record(self.principal, self.space, self.record["id"])
        with self.assertRaises(ExchangeError) as raised:
            self.transfers.grants(*self.args, [1])
        self.assertEqual(raised.exception.code, "upload_not_ready")

    def test_lost_initiation_response_gets_distinct_resource_and_retry_history(self):
        self.storage.failure = StorageFailure("storage_unavailable", True)
        self.transfers.initiate(*self.args)
        old = self.current()
        self.assertEqual(old.retry_count, 1)
        self.storage.failure = None
        self.due(old.id)
        self.assertEqual(tick(self.transfers)["recovered"], 1)
        self.assertEqual(len(set(self.storage.started)), 2)
        with self.service.sessions.begin() as session:
            old = session.get(TransferAttempt, old.id)
            self.assertEqual(old.state, "cleanup")
            self.assertNotEqual(old.object_key, self.storage.started[-1])
        self.assertEqual(tick(self.transfers)["cleaned"], 1)
        self.assertEqual(self.storage.cleaned, [self.storage.started[0]])
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(Blob, self.blob).state, "uploading")

    def test_invalid_parts_returns_to_upload_without_failing_record(self):
        self.transfers.initiate(*self.args)
        self.storage.failure = StorageFailure("invalid_parts")
        with self.assertRaises(ExchangeError) as raised:
            self.transfers.complete(*self.args)
        self.assertEqual(raised.exception.code, "invalid_parts")
        self.assertEqual(self.current().state, "uploading")
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(Record, self.record["id"]).state, "draft")

    def test_expiry_reclaims_reserved_blob_without_external_storage_work(self):
        with self.service.sessions.begin() as session:
            session.get(Record, self.record["id"]).expires_at = 0
        self.assertEqual(tick(self.transfers)["expired"], 1)
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(Blob, self.blob).state, "cleaned")
            space = session.get(Space, self.space)
            self.assertEqual((space.allocated, space.reclaiming), (0, 0))

    def test_late_initiation_reopens_own_cleanup_after_lease_loss(self):
        old_key = []
        def delayed_start(key):
            old_key.append(key)
            attempt = self.current()
            self.service.withdraw_record(self.principal, self.space, self.record["id"])
            self.due(attempt.id)
            self.assertEqual(tick(self.transfers)["cleaned"], 0)
            with self.service.sessions.begin() as session:
                self.assertEqual(session.get(Space, self.space).reclaiming, 3)
        self.storage.on_start = delayed_start
        self.transfers.initiate(*self.args)
        self.assertEqual(self.current().state, "cleanup")
        self.assertEqual(tick(self.transfers)["cleaned"], 1)
        self.assertEqual(self.storage.cleaned, old_key * 2)

    def test_late_completion_after_cleanup_reopens_reclamation_and_quota(self):
        self.transfers.initiate(*self.args)
        late_objects = set()
        original_cleanup = self.storage.cleanup
        def cleanup(key):
            original_cleanup(key)
            late_objects.discard(key)
        self.storage.cleanup = cleanup
        def late_completion():
            attempt = self.current()
            self.service.withdraw_record(self.principal, self.space, self.record["id"])
            self.due(attempt.id)
            self.assertEqual(tick(self.transfers)["cleaned"], 0)
            with self.service.sessions.begin() as session:
                self.assertEqual(session.get(Space, self.space).reclaiming, 3)
            late_objects.add(attempt.object_key)
        self.storage.on_complete = late_completion
        self.transfers.complete(*self.args)
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(Space, self.space).reclaiming, 3)
            self.assertTrue(session.get(Blob, self.blob).pending_deletion)
        self.assertEqual(tick(self.transfers)["cleaned"], 1)
        self.assertEqual(late_objects, set())
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(Space, self.space).reclaiming, 0)

    def test_uncertain_initiation_blocks_new_resources_until_explicit_repair(self):
        self.storage.failure = StorageFailure("storage_unavailable", True, uncertain=True)
        self.transfers.initiate(*self.args)
        old = self.current()
        self.assertEqual(len(old.mutation_tokens), 1)
        self.storage.failure = None
        self.due(old.id)
        tick(self.transfers)
        with self.assertRaises(ExchangeError) as blocked:
            self.transfers.initiate(*self.args)
        self.assertEqual(blocked.exception.code, "storage_mutation_uncertain")
        self.assertEqual(len(self.storage.started), 1)
        self.service.withdraw_record(self.principal, self.space, self.record["id"])
        tick(self.transfers)
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(Space, self.space).reclaiming, 3)
        with self.assertRaises(ExchangeError):
            self.service.purge_record(self.principal, self.space, self.record["id"])
        self.assertEqual(inspect_mutations(self.service, [old.id])["attempts"][0]["mutation_count"], 1)
        repair_mutations(self.service, [old.id])
        self.assertEqual(len(self.current().mutation_tokens), 1)
        with self.assertRaises(ExchangeError):
            repair_mutations(self.service, [old.id], execute=True, writers_stopped=True)
        repair_mutations(self.service, [old.id], execute=True, writers_stopped=True, provider_quiesced=True)
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(Space, self.space).reclaiming, 3)
        self.assertEqual(tick(self.transfers)["cleaned"], 1)
        self.service.purge_record(self.principal, self.space, self.record["id"])

    def test_settlement_fences_old_cleanup_before_releasing_its_marker(self):
        self.transfers.initiate(*self.args)
        cleanup_snapshot = []
        late_objects = set()
        original_cleanup = self.storage.cleanup
        def cleanup(key):
            original_cleanup(key)
            late_objects.discard(key)
        self.storage.cleanup = cleanup
        def complete_with_missing_version():
            attempt = self.current()
            self.service.withdraw_record(self.principal, self.space, self.record["id"])
            self.due(attempt.id)
            leased = self.transfers.acquire(attempt.id)
            cleanup(leased.object_key)  # this cleanup snapshot precedes the side effect
            cleanup_snapshot.append(leased)
            late_objects.add(leased.object_key)
            raise StorageFailure("storage_misconfigured", retryable=True)
        self.storage.on_complete = complete_with_missing_version
        original_settle = self.transfers._settle_mutation
        def settle_then_old_cleanup(attempt):
            original_settle(attempt)
            self.assertFalse(self.transfers.commit(cleanup_snapshot[0], "cleaned"))
            with self.assertRaises(ExchangeError):
                self.service.purge_record(self.principal, self.space, self.record["id"])
            with self.service.sessions.begin() as session:
                self.assertEqual(session.get(Space, self.space).reclaiming, 3)
        self.transfers._settle_mutation = settle_then_old_cleanup
        self.transfers.complete(*self.args)
        self.assertEqual(tick(self.transfers)["cleaned"], 1)
        self.assertEqual(late_objects, set())
        self.service.purge_record(self.principal, self.space, self.record["id"])

    def test_uncertain_completion_blocks_retries_until_same_handle_repair(self):
        self.transfers.initiate(*self.args)
        completed_calls = []
        self.storage.on_complete = lambda: completed_calls.append(True)
        self.storage.failure = StorageFailure("storage_unavailable", True, uncertain=True)
        self.transfers.complete(*self.args)
        attempt = self.current()
        self.assertEqual(len(attempt.mutation_tokens), 1)
        self.due(attempt.id)
        tick(self.transfers)
        self.assertEqual(len(completed_calls), 1)
        self.assertEqual(self.current().state, "completing")
        self.storage.failure = None
        report = repair_mutations(self.service, [attempt.id], execute=True,
                                  writers_stopped=True, provider_quiesced=True)
        self.assertEqual(report["attempts"][0]["action"], "recover_completion")
        self.assertEqual(tick(self.transfers)["recovered"], 1)
        self.assertEqual(tick(self.transfers)["verified"], 1)
        self.assertEqual(len(completed_calls), 2)
        self.assertEqual(self.current().mutation_tokens, [])

    def test_default_repair_inventory_filters_before_bounding(self):
        self.storage.failure = StorageFailure("storage_unavailable", True, uncertain=True)
        self.transfers.initiate(*self.args)
        attempt_id = self.current().id
        with self.service.sessions.begin() as session:
            uncertain = session.get(TransferAttempt, attempt_id)
            uncertain.id = "z_uncertain"
            for number in range(101):
                session.add(TransferAttempt(id=f"a{number:03}", blob_id=self.blob,
                    object_key=f"retired/{number}", operation="cleanup", state="cleaned", mutation_tokens=[]))
        report = inspect_mutations(self.service)
        self.assertEqual([row["attempt_id"] for row in report["attempts"]], ["z_uncertain"])
        self.assertFalse(report["truncated"])

    def test_heartbeat_keeps_active_lease_live(self):
        self.upload()
        self.transfers.settings = replace(self.transfers.settings,
                                         worker=replace(self.transfers.settings.worker, lease_seconds=.12))
        attempt = self.transfers.acquire(self.current().id)
        with self.transfers.heartbeat(attempt):
            time.sleep(.24)
            self.assertIsNone(self.transfers.acquire(attempt.id))
        self.transfers.release_lease(attempt)
        self.assertIsNotNone(self.transfers.acquire(attempt.id))


class StorageFailureTests(unittest.TestCase):
    def test_abort_requires_confirmed_multipart_absence(self):
        from botocore.exceptions import ClientError
        class Client:
            absent = False
            def abort_multipart_upload(self, **kwargs):
                return {}
            def list_parts(self, **kwargs):
                if self.absent:
                    raise ClientError({"Error": {"Code": "NoSuchUpload"}}, "ListParts")
                return {"Parts": [{"PartNumber": 1, "Size": 3}]}
        client = Client()
        storage = S3BlobStore(StorageSettings(bucket="test"), client=client)
        with self.assertRaises(StorageFailure) as raised:
            storage._abort_confirm("private-key", "private-handle")
        self.assertEqual(raised.exception.code, "cleanup_incomplete")
        self.assertTrue(raised.exception.retryable)
        client.absent = True
        storage._abort_confirm("private-key", "private-handle")

    def test_transport_failure_preserves_uncertainty(self):
        from botocore.exceptions import EndpointConnectionError
        class Client:
            def create_multipart_upload(self, **kwargs):
                raise EndpointConnectionError(endpoint_url="https://storage.example.test")
        storage = S3BlobStore(StorageSettings(bucket="test"), client=Client())
        with self.assertRaises(StorageFailure) as raised:
            storage.start("private-key")
        self.assertTrue(raised.exception.uncertain)
        self.assertTrue(raised.exception.retryable)


if __name__ == "__main__":
    unittest.main()
