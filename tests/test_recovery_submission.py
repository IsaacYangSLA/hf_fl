"""Publication response loss must not create a second Exchange record."""
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock

from hf2l_exchange.client import ExchangeClient
from hf2l_exchange.client_types import AttachmentDescriptor, ExchangeError, RecordDescriptor


class SubmissionLookupTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        model = root / "model.bin"
        model.write_bytes(b"trained weights")
        self.arguments = {
            "kind": "training.update",
            "metadata": {"base_record_id": "round-zero"},
            "schema_revision_id": "schema",
            "files": {"model.bin": model},
            "state_path": root / "upload-state.json",
        }
        self.client = object.__new__(ExchangeClient)
        self.client.endpoint = "https://exchange.example"
        self.client.create_record = Mock(side_effect=self.create)
        self.client.get_record = Mock(side_effect=lambda *args, **kwargs: self.record)
        self.client.publish_record = Mock(side_effect=self.publish_then_lose_response)

    def create(self, space, *, kind, schema_revision_id, metadata, attachments, **kwargs):
        self.record = RecordDescriptor(
            id="submission", space_id=space, kind=kind, schema_revision_id=schema_revision_id,
            metadata=metadata, state="draft", version=1, shared=False, creator="alice",
            attachments=tuple(
                AttachmentDescriptor(id=str(index), state="verified", **entry)
                for index, entry in enumerate(attachments)
            ),
        )
        return self.record

    def publish_then_lose_response(self, *args, **kwargs):
        self.record = replace(self.record, state="published")
        raise TimeoutError("accepted result response lost")

    def lose_acknowledgment(self):
        with self.assertRaises(TimeoutError):
            self.client.put_record("study", **self.arguments)
        self.assertEqual(self.client.create_record.call_count, 1)
        self.assertEqual(self.client.publish_record.call_count, 1)

    def test_lookup_uses_original_record_after_lost_response(self):
        self.lose_acknowledgment()
        state_path = self.arguments["state_path"]
        saved = state_path.read_bytes()
        result = self.client.put_record("study", **self.arguments, reconcile_only=True)
        self.assertEqual(result, self.record)
        self.assertEqual(state_path.read_bytes(), saved)
        self.assertEqual(self.client.put_record("study", **self.arguments), self.record)
        self.client.create_record.assert_called_once()
        self.client.publish_record.assert_called_once()

    def test_unstarted_or_draft_result_is_not_reported_as_published(self):
        self.assertIsNone(self.client.put_record("study", **self.arguments, reconcile_only=True))
        self.assertFalse(self.arguments["state_path"].exists())
        self.client.create_record.assert_not_called()
        self.lose_acknowledgment()
        self.record = replace(self.record, state="draft")
        self.assertIsNone(self.client.put_record("study", **self.arguments, reconcile_only=True))
        self.client.publish_record.assert_called_once()

    def test_changed_payload_or_mismatched_remote_result_fails_closed(self):
        self.lose_acknowledgment()
        changed = dict(self.arguments, metadata={"base_record_id": "changed"})
        with self.assertRaises(ExchangeError):
            self.client.put_record("study", **changed, reconcile_only=True)
        altered = replace(self.record.attachments[0], sha256="0" * 64)
        self.record = replace(self.record, attachments=(altered,))
        with self.assertRaisesRegex(ExchangeError, "publication_result_mismatch"):
            self.client.put_record("study", **self.arguments, reconcile_only=True)
        self.client.create_record.assert_called_once()
        self.client.publish_record.assert_called_once()
