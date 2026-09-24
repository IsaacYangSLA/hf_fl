"""Publication intent is recorded only after a real round is ready to publish."""

from __future__ import annotations

import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import numpy as np
from safetensors.numpy import load_file, save_file

from hf2l.backends.local import LocalStore
from hf2l.core.ports import ClaimHandle
from hf2l.core.protocol import ROUND_FILE, SUBMISSION_FILE, RoundRecord
from hf2l.fedavg_runner import FedAvgRunner, run_round
from hf2l.hub_helpers import artifact_hashes, read_json, validate_artifact_hashes, write_json
from hf2l.round.config import RoundConfig


class RunnerPublicationHookTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = LocalStore(self.root / "storage", "owner")
        self.addCleanup(self.store.close)
        initial = self._checkpoint("initial", [0.0])
        write_json(initial / ROUND_FILE, {
            "schema_version": 2, "backend": "local", "round": 0,
            "checkpoint_files_sha256": self._hashes(initial),
        })
        self.store.initialize_repository("repo", initial, private=False)
        self.base = self.store.resolve_reference("repo")
        self.config = RoundConfig("repo", self.root / "output", publish=True)

    def _checkpoint(self, name, weights):
        folder = self.root / name
        folder.mkdir()
        write_json(folder / "config.json", {"model_type": "hook-test"})
        save_file({"weight": np.asarray(weights, dtype=np.float32)}, folder / "model.safetensors")
        return folder

    def _hashes(self, folder):
        return artifact_hashes(folder, ["config.json", "model.safetensors"])

    def _submission(self, participant, weights, count):
        folder = self._checkpoint(participant, weights)
        revision = f"submission-{participant}"
        write_json(folder / SUBMISSION_FILE, {
            "schema_version": 2, "backend": "local", "repo_id": "repo",
            "base_revision": self.base.revision, "source_round": 0,
            "participant": participant, "num_examples": count,
            "submission_revision": revision,
            "checkpoint_files_sha256": self._hashes(folder),
        })
        client = LocalStore(self.root / "storage", participant)
        try:
            client.publish_submission(
                "repo", folder, ["config.json", "model.safetensors", SUBMISSION_FILE],
                participant=participant, source_round=0, base_revision=self.base.revision,
                submission_revision=revision,
            )
        finally:
            client.close()

    def _clients(self):
        self._submission("alice", [1.0], 1)
        self._submission("bob", [3.0], 3)

    def test_hook_observes_evaluated_validated_manifest_before_single_publication(self):
        self._clients()
        order = []

        def evaluate(folder, options):
            order.append("evaluate")
            return {"accuracy": 0.75}

        def before_publish(context, aggregate_dir):
            order.append("intent")
            self.assertEqual("repo", context.repo_id)
            self.assertEqual(self.base, context.reference)
            self.assertEqual(0, context.round_number)
            self.assertEqual(self.base, self.store.resolve_reference("repo"))
            document = read_json(aggregate_dir / ROUND_FILE)
            self.assertEqual(1, RoundRecord.from_dict(document).round)
            self.assertEqual({"accuracy": 0.75}, document["evaluation"])
            self.assertEqual(self.base.revision, document["base_revision"])
            self.assertEqual([0.25, 0.75], [item["coefficient"] for item in document["submissions"]])
            validate_artifact_hashes(aggregate_dir, document["checkpoint_files"],
                                     document["checkpoint_files_sha256"], "aggregate")
            np.testing.assert_array_equal(load_file(aggregate_dir / "model.safetensors")["weight"], [2.5])

        publish = self.store.publish_aggregate

        def observed_publish(*args, **kwargs):
            order.append("publish")
            return publish(*args, **kwargs)

        with patch("hf2l.fedavg_runner.load_plugin", return_value=SimpleNamespace(evaluate_model=evaluate)), \
                patch.object(self.store, "publish_aggregate", side_effect=observed_publish) as primary:
            result = run_round(self.store, replace(self.config, plugin="fixture"), before_publish=before_publish)
        self.assertEqual(["evaluate", "intent", "publish"], order)
        primary.assert_called_once()
        self.assertEqual("published", result.status)
        self.assertEqual(result.publication.revision, self.store.resolve_reference("repo").revision)

    def test_callback_failure_prevents_publication(self):
        self._clients()
        callback = Mock(side_effect=OSError("intent state cannot be persisted"))
        with patch.object(self.store, "publish_aggregate", wraps=self.store.publish_aggregate) as primary:
            with self.assertRaisesRegex(OSError, "intent state"):
                FedAvgRunner(self.store, before_publish=callback).run(self.config)
        callback.assert_called_once()
        primary.assert_not_called()
        self.assertEqual(self.base, self.store.resolve_reference("repo"))

    def test_readiness_and_unpublished_aggregation_never_invoke_hook(self):
        self._clients()
        callback = Mock()
        for name, options, status in (
            ("ready", {"check_only": True}, "ready"),
            ("waiting", {"check_only": True, "minimum_participants": 3}, "not_ready"),
            ("aggregate", {}, "aggregated"),
        ):
            with self.subTest(name=name):
                config = replace(self.config, publish=False, output_dir=self.root / name, **options)
                self.assertEqual(status, run_round(self.store, config, before_publish=callback).status)
        callback.assert_not_called()
        self.assertEqual(self.base, self.store.resolve_reference("repo"))

    def test_invalid_checkpoints_never_invoke_hook(self):
        self._submission("alice", [1.0, 2.0], 1)
        self._submission("bob", [3.0], 3)
        callback = Mock()
        with self.assertRaisesRegex(ValueError, "at least two valid client checkpoints"):
            run_round(self.store, self.config, before_publish=callback)
        callback.assert_not_called()
        self.assertEqual(self.base, self.store.resolve_reference("repo"))

    def test_evaluation_failure_never_invokes_hook(self):
        self._clients()
        evaluate = Mock(side_effect=RuntimeError("evaluation failed"))
        callback = Mock()
        with patch("hf2l.fedavg_runner.load_plugin", return_value=SimpleNamespace(evaluate_model=evaluate)):
            with self.assertRaisesRegex(RuntimeError, "evaluation failed"):
                run_round(self.store, replace(self.config, plugin="fixture"), before_publish=callback)
        callback.assert_not_called()
        self.assertEqual(self.base, self.store.resolve_reference("repo"))

    def test_callback_failure_preserves_existing_claim_abandonment(self):
        self._clients()
        capabilities = replace(self.store.capabilities, fenced_coordination=True,
                               requires_coordination_for_publication=True)
        candidates, _ = self.store.discover_submissions("repo")
        claim = ClaimHandle("claim", 1, self.base, tuple(item.revision for item in candidates),
                            time.time() + 3600, None)
        callback = Mock(side_effect=OSError("intent state cannot be persisted"))
        run_state = self.root / "claim-state.json"
        with patch.object(self.store, "capabilities", capabilities), \
                patch.object(self.store, "acquire_claim", return_value=claim), \
                patch.object(self.store, "abandon_claim") as abandon, \
                patch.object(self.store, "publish_aggregate", wraps=self.store.publish_aggregate) as primary:
            with self.assertRaisesRegex(OSError, "intent state"):
                run_round(self.store, replace(self.config, selection="claim", run_state=run_state),
                          before_publish=callback)
        callback.assert_called_once()
        abandon.assert_called_once_with("repo", claim)
        primary.assert_not_called()
        self.assertFalse(run_state.exists())
        self.assertEqual(self.base, self.store.resolve_reference("repo"))

    def test_report_failure_after_hook_and_publication_is_still_success(self):
        self._clients()
        callback = Mock()

        def fail_report(path, value):
            if Path(path).name == "result.json":
                raise OSError("report disk full")
            return write_json(path, value)

        with patch("hf2l.fedavg_runner.write_json", side_effect=fail_report):
            result = run_round(self.store, self.config, before_publish=callback)
        callback.assert_called_once()
        self.assertEqual("published", result.status)
        self.assertEqual(result.publication.revision, self.store.resolve_reference("repo").revision)
        self.assertTrue(any("report disk full" in warning for warning in result.warnings))


if __name__ == "__main__":
    unittest.main()
