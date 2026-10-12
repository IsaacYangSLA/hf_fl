"""Client publication retries preserve the exact saved intent."""
from __future__ import annotations

from pathlib import Path
import unittest
from unittest.mock import patch

from hf2l.client_steps import download_client_round, upload_client_update
from hf2l.common.fs import read_json
from hf2l.core.protocol import SUBMISSION_FILE
from tests.test_client_listener import ListenerFixture


class SubmissionIntentTests(ListenerFixture, unittest.TestCase):
    def trained(self):
        work = self.root / "work"
        download_client_round(self.store, "repo", self.base, work)
        trained = work / "trained_model"
        self.train(work / "base_model", trained, {})
        return work, trained

    def test_accepted_submission_lost_ack_reuses_revision_manifest_and_timestamp(self):
        work, trained = self.trained()
        original = self.store.publish_submission
        accepted = []
        def lost(*args, **kwargs):
            accepted.append(original(*args, **kwargs))
            raise TimeoutError("accepted publication, lost acknowledgment")
        with patch.object(self.store, "new_submission_revision", wraps=self.store.new_submission_revision) as revision:
            with patch.object(self.store, "publish_submission", side_effect=lost):
                with self.assertRaises(TimeoutError):
                    upload_client_update(self.store, work, trained, "alice", 7, {"loss": 0.25})
            before = (trained / SUBMISSION_FILE).read_bytes()
            # This local adapter confirms the immutable reference already
            # exists; explicit listener reconciliation marks it submitted.
            with self.assertRaisesRegex(ValueError, "Submission reference already exists"):
                upload_client_update(self.store, work, trained, "alice", 7, {"loss": 0.25})
            manifest = read_json(trained / SUBMISSION_FILE)
            self.assertEqual(revision.call_count, 1)
        self.assertEqual(before, (trained / SUBMISSION_FILE).read_bytes())
        self.assertEqual(manifest["submission_revision"], accepted[0].revision)
        self.assertEqual(manifest, read_json(trained / SUBMISSION_FILE))

    def test_unknown_unaccepted_retry_uses_saved_intent_after_explicit_reconciliation(self):
        work, trained = self.trained()
        with patch.object(self.store, "publish_submission", side_effect=TimeoutError()):
            with self.assertRaises(TimeoutError):
                upload_client_update(self.store, work, trained, "alice", 7, {"loss": 0.25})
        before = (trained / SUBMISSION_FILE).read_bytes()
        with patch.object(self.store, "new_submission_revision", side_effect=AssertionError("must reuse")):
            upload_client_update(self.store, work, trained, "alice", 7, {"loss": 0.25})
        self.assertEqual(before, (trained / SUBMISSION_FILE).read_bytes())

    def test_changed_training_metadata_or_examples_rejects_saved_intent(self):
        work, trained = self.trained()
        with patch.object(self.store, "publish_submission", side_effect=TimeoutError()):
            with self.assertRaises(TimeoutError):
                upload_client_update(self.store, work, trained, "alice", 7, {"loss": 0.25})
        with patch.object(self.store, "publish_submission") as publish:
            for examples, metadata in ((8, {"loss": 0.25}), (7, {"loss": 0.5})):
                with self.assertRaisesRegex(ValueError, "Saved publication intent"):
                    upload_client_update(self.store, work, trained, "alice", examples, metadata)
            publish.assert_not_called()

    def test_changed_checkpoint_rejects_saved_intent(self):
        work, trained = self.trained()
        with patch.object(self.store, "publish_submission", side_effect=TimeoutError()):
            with self.assertRaises(TimeoutError):
                upload_client_update(self.store, work, trained, "alice", 7, {"loss": 0.25})
        import numpy as np
        from safetensors.numpy import load_file, save_file
        weights = load_file(trained / "model.safetensors")
        weights["weight"] += 1
        save_file(weights, trained / "model.safetensors")
        with self.assertRaisesRegex(ValueError, "Saved publication intent"):
            upload_client_update(self.store, work, trained, "alice", 7, {"loss": 0.25})


if __name__ == "__main__":
    unittest.main()
