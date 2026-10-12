"""Public adapter must not expose or even mint origin URLs for managed spaces."""
from contextlib import contextmanager
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hf2l_exchange.domain import ExchangeError
from hf2l_exchange.managed_transfers import ManagedTransferService


class Raw:
    def __init__(self, managed=True):
        self.managed = managed
        self.calls = []
        self.record = SimpleNamespace(state="draft", expires_at=100)
        self.blob = SimpleNamespace(state="uploading", size=8, part_size=4,
                                    verified_size=8, verified_sha256="a" * 64)
        self.attempt = SimpleNamespace(state="uploading")
        self.service = SimpleNamespace(is_managed_space=lambda _: self.managed,
                                       transaction=self.transaction)

    @contextmanager
    def transaction(self, space, principal, *, write=False):
        self.calls.append(("authorize", space, principal, write))
        if principal == "revoked":
            raise ExchangeError(403, "workload_grant_revoked")
        yield object(), object(), object()

    def _attachment(self, session, space, record, attachment, member, principal, write=False):
        self.calls.append(("attachment", space, record, attachment, principal, write))
        return self.record, self.blob

    def _active(self, session, blob):
        return self.attempt

    def initiate(self, *args):
        self.calls.append(("initiate", args))
        return {"protocol": "s3-multipart-v1", "state": "uploading", "part_size": 4}

    def complete(self, *args):
        return {"protocol": "s3-multipart-v1", "state": "verifying", "part_size": 4}

    def grants(self, *args):
        self.calls.append(("origin_grants", args))
        return {"grants": [{"url": "https://private-origin.test/signed-secret", "number": 1, "size": 4}]}

    def download(self, *args):
        self.calls.append(("origin_download", args))
        return {"url": "https://private-origin.test/signed-secret", "size": 8, "sha256": "a" * 64}

    def parts(self, *args):
        return {"parts": []}


class ManagedTransferServiceTests(unittest.TestCase):
    def setUp(self):
        self.raw = Raw()
        self.transfers = ManagedTransferService(self.raw)
        self.args = ("space", "record", "attachment", "owner")

    def test_managed_grants_are_structured_without_url_signing(self):
        with patch("hf2l_exchange.managed_transfers.database_time", return_value=1):
            grant = self.transfers.grants(*self.args, [1, 2])["grants"]
        self.assertEqual([item["size"] for item in grant], [4, 4])
        self.assertEqual(grant[0]["operation"], {"space_id": "space", "record_id": "record",
                         "attachment_id": "attachment", "method": "PUT", "part_number": 1})
        self.assertEqual(grant[0]["protocol"], "hf2l-managed-v1")
        self.assertNotIn("url", grant[0])
        self.assertFalse(any(call[0].startswith("origin") for call in self.raw.calls))
        self.assertEqual(self.raw.calls[0], ("authorize", "space", "owner", False))

    def test_download_requires_published_verified_object_without_origin_urls(self):
        self.raw.record.state, self.raw.blob.state = "published", "verified"
        result = self.transfers.download(*self.args)
        self.assertEqual(result["operation"]["method"], "GET")
        self.assertEqual((result["size"], result["sha256"]), (8, "a" * 64))
        self.assertNotIn("url", result)
        self.assertFalse(any(call[0].startswith("origin") for call in self.raw.calls))
        self.raw.blob.state = "verifying"
        with self.assertRaisesRegex(ExchangeError, "attachment_not_available"):
            self.transfers.download(*self.args)

    def test_unmanaged_signed_transfer_behavior_is_preserved(self):
        self.raw.managed = False
        self.assertIn("url", self.transfers.grants(*self.args, [1])["grants"][0])
        self.assertIn("url", self.transfers.download(*self.args))
        self.assertEqual(self.transfers.initiate(*self.args)["protocol"], "s3-multipart-v1")

    def test_managed_start_complete_preserve_state_and_protocol(self):
        self.assertEqual(self.transfers.initiate(*self.args), {
            "protocol": "hf2l-managed-v1", "state": "uploading", "part_size": 4})
        self.assertEqual(self.transfers.complete(*self.args)["protocol"], "hf2l-managed-v1")
        self.assertEqual(self.transfers.parts(*self.args), {"parts": []})

    def test_invalid_part_numbers_or_upload_state_never_sign(self):
        with patch("hf2l_exchange.managed_transfers.database_time", return_value=1):
            for numbers in ([], [1, 1], [True], [0], [3], ["1"]):
                with self.subTest(numbers=numbers), self.assertRaises(ExchangeError):
                    self.transfers.grants(*self.args, numbers)
            self.raw.attempt.state = "completing"
            with self.assertRaisesRegex(ExchangeError, "upload_not_ready"):
                self.transfers.grants(*self.args, [1])
        self.assertFalse(any(call[0].startswith("origin") for call in self.raw.calls))

    def test_revocation_is_checked_before_every_descriptor(self):
        args = (*self.args[:3], "revoked")
        with self.assertRaisesRegex(ExchangeError, "workload_grant_revoked"):
            self.transfers.download(*args)
        with self.assertRaisesRegex(ExchangeError, "workload_grant_revoked"):
            self.transfers.grants(*args, [1])
        self.assertFalse(any(call[0].startswith("origin") for call in self.raw.calls))


from test_transfers import FakeStore
from test_workload_grants import ManagedSpaceFixture
from hf2l_exchange.transfers import TransferService
from hf2l_exchange.worker import tick


class ManagedTransferIntegrationTests(ManagedSpaceFixture):
    def test_real_transfer_lifecycle_never_signs_public_managed_descriptors(self):
        import hashlib
        record = self.service.create_record(self.workload, self.space_id, {
            "kind": "document", "schema_revision_id": self.revision["id"], "metadata": {},
            "attachments": [{"path": "document.bin", "size": 3,
                             "sha256": hashlib.sha256(b"abc").hexdigest()}]}, "managed-transfer")
        attachment = record["attachments"][0]["id"]
        storage = FakeStore()
        raw = TransferService(self.service, storage)
        managed = ManagedTransferService(raw)
        args = self.space_id, record["id"], attachment, self.workload
        self.assertEqual(managed.initiate(*args)["protocol"], "hf2l-managed-v1")
        with patch.object(storage, "upload_grant", side_effect=AssertionError("Public signer invoked")):
            result = managed.grants(*args, [1])["grants"][0]
        self.assertEqual(result["size"], 3)
        self.assertNotIn("url", result)
        managed.complete(*args)
        self.assertEqual(tick(raw)["verified"], 1)
        self.service.publish_record(self.workload, self.space_id, record["id"], "managed-publish")
        with patch.object(storage, "download_grant", side_effect=AssertionError("Public signer invoked")):
            result = managed.download(*args)
        self.assertEqual((result["size"], result["sha256"]), (3, hashlib.sha256(b"abc").hexdigest()))
        self.assertNotIn("url", result)
        self.service.revoke_workload_grants(self.owner, self.space_id,
                                           {"attempt_id": "attempt-a"}, "managed-revoke")
        with self.assertRaisesRegex(ExchangeError, "workload_grant_invalid"):
            managed.download(*args)


if __name__ == "__main__":
    unittest.main()
