"""Listener stages preserve round identity and validated resumable training output."""

from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from hf2l.common.fs import artifact_hashes, read_json, write_json
from hf2l.core.ports import PublishResult
from hf2l.core.protocol import CLIENT_CONTEXT_FILE, ROUND_FILE, SUBMISSION_FILE
from hf2l.listener.workflow import download_round, submit_round, train_round, validate_submission


ROOT = Path(__file__).resolve().parents[1]
CHECKPOINT = ROOT / "tests" / "goldens" / "single" / "clients" / "0"


class ListenerWorkflowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.work = self.root / "round"
        self.store = SimpleNamespace(
            name="local",
            resolve_revision=Mock(side_effect=lambda repo, revision: revision),
            download_snapshot=Mock(side_effect=self._snapshot),
            new_submission_revision=Mock(return_value="alice-round-3"),
            publish_submission=Mock(return_value=PublishResult(
                revision="submission-1", resolved_revision="immutable-submission",
                warnings=("test warning",),
            )),
        )

    def _snapshot(self, repo, revision, destination):
        shutil.copytree(CHECKPOINT, destination)
        write_json(destination / ROUND_FILE, {
            "schema_version": 2, "backend": self.store.name, "round": 3,
            "algorithm_spec": {"name": "fedavg", "version": 1, "params": {}},
            "checkpoint_files_sha256": artifact_hashes(
                destination, ["config.json", "model.safetensors"],
            ),
        })

    @staticmethod
    def _train(base_dir, trained_dir, options):
        shutil.copytree(base_dir, trained_dir)
        return {"num_examples": 7, "metrics": {"loss": 0.25}, "site": options["participant"]}

    def _download(self):
        return download_round(self.store, "owner/model", "immutable-base", self.work)

    def test_download_preserves_scheduled_base_and_validates_round(self):
        context = self._download()
        self.assertEqual("immutable-base", context["base_revision"])
        self.assertEqual(3, context["source_round"])
        self.assertEqual(context, read_json(self.work / CLIENT_CONTEXT_FILE))
        self.store.download_snapshot.assert_called_once_with(
            "owner/model", "immutable-base", self.work / "base_model",
        )

    def test_download_refuses_rebinding_even_when_snapshot_is_valid(self):
        self.store.resolve_revision = Mock(return_value="different-immutable-base")
        with self.assertRaisesRegex(ValueError, "rebound"):
            self._download()

    def test_training_copies_options_and_result_and_records_checkpoint_integrity(self):
        self._download()
        options = {"participant": "ignored", "nested": {"rate": 0.1}}
        saved_options = copy.deepcopy(options)
        result = {"num_examples": 9, "metrics": {"loss": 0.5}}

        def plugin(base_dir, trained_dir, supplied):
            self.assertEqual("alice", supplied["participant"])
            supplied["nested"]["rate"] = 1
            shutil.copytree(base_dir, trained_dir)
            return result

        metadata = train_round(plugin, options, "alice", self.work)
        self.assertEqual(saved_options, options)
        self.assertEqual(9, result["num_examples"])
        result["metrics"]["loss"] = 1
        self.assertEqual({"metrics": {"loss": 0.5}}, metadata["training"])
        self.assertEqual(9, metadata["num_examples"])
        self.assertEqual(
            artifact_hashes(self.work / "trained_model", ["config.json", "model.safetensors"]),
            metadata["checkpoint_files_sha256"],
        )

    def test_training_rejects_missing_or_nonpositive_or_noninteger_counts(self):
        self._download()
        for count in [None, True, False, 0, -1, 1.5, "2"]:
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, "positive integer"):
                train_round(lambda *args: {"num_examples": count}, {}, "alice", self.work)
        with self.assertRaisesRegex(ValueError, "positive integer"):
            train_round(lambda *args: {}, {}, "alice", self.work)

    def test_training_rejects_non_json_and_non_finite_metadata(self):
        self._download()
        invalid = [None, [], "metadata", {"num_examples": 1, "loss": float("nan")},
                   {"num_examples": 1, "loss": float("inf")},
                   {"num_examples": 1, "metrics": {1: "integer key"}},
                   {"num_examples": 1, "value": object()},
                   {"num_examples": 1, "value": (1, 2)}]
        for result in invalid:
            with self.subTest(result=result), self.assertRaises(ValueError):
                train_round(lambda *args: result, {}, "alice", self.work)

    def test_training_rejects_incompatible_checkpoint(self):
        self._download()

        def incompatible(base_dir, trained_dir, options):
            self._train(base_dir, trained_dir, options)
            config = read_json(trained_dir / "config.json")
            config["different_architecture"] = True
            write_json(trained_dir / "config.json", config)
            return {"num_examples": 1}

        with self.assertRaisesRegex(ValueError, "configuration changed"):
            train_round(incompatible, {}, "alice", self.work)
        self.store.publish_submission.assert_not_called()

    def test_training_checks_publication_protocol_limits_before_success(self):
        self._download()
        invalid = [
            {"num_examples": 2**63},
            {"num_examples": 1, "note": "x" * (64 * 1024)},
            {"num_examples": 1, "metric": 2**63},
        ]
        for result in invalid:
            with self.subTest(result_size=len(str(result))), self.assertRaises(ValueError):
                train_round(lambda *args: result, {}, "alice", self.work)

    def test_submission_uses_saved_training_metadata_and_immutable_round(self):
        self._download()
        metadata = train_round(self._train, {}, "alice", self.work)
        # Simulate the controller persisting and loading training metadata.
        saved = self.root / "training.json"
        write_json(saved, metadata)
        result = submit_round(self.store, self.work, "alice", read_json(saved))
        submission = read_json(self.work / "trained_model" / SUBMISSION_FILE)
        self.assertEqual(7, submission["num_examples"])
        self.assertEqual(metadata["training"], submission["training"])
        self.assertEqual("immutable-base", submission["base_revision"])
        self.assertEqual(3, submission["source_round"])
        self.assertEqual("submission-1", result["revision"])
        self.assertEqual("immutable-submission", result["resolved_revision"])
        self.assertEqual(["test warning"], json.loads(json.dumps(result))["warnings"])
        self.store.publish_submission.assert_called_once()

    def test_resume_refuses_modified_checkpoint_before_any_publication(self):
        self._download()
        metadata = train_round(self._train, {}, "alice", self.work)
        weights = self.work / "trained_model" / "model.safetensors"
        damaged = bytearray(weights.read_bytes())
        damaged[-1] ^= 1
        weights.write_bytes(damaged)
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            submit_round(self.store, self.work, "alice", metadata)
        self.store.new_submission_revision.assert_not_called()
        self.store.publish_submission.assert_not_called()

    def test_resume_requires_saved_hashes_and_valid_training_metadata(self):
        self._download()
        metadata = train_round(self._train, {}, "alice", self.work)
        for key, value in [("checkpoint_files_sha256", None), ("training", []), ("num_examples", True)]:
            changed = {**metadata, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                submit_round(self.store, self.work, "alice", changed)
        self.store.publish_submission.assert_not_called()

    def test_public_preflight_validates_without_publishing_or_creating_manifest(self):
        self._download()
        metadata = train_round(self._train, {}, "alice", self.work)
        validate_submission(self.work, "alice", metadata)
        self.assertFalse((self.work / "trained_model" / SUBMISSION_FILE).exists())
        self.store.new_submission_revision.assert_not_called()
        self.store.publish_submission.assert_not_called()
        self._damage_weights(self.work / "trained_model")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            validate_submission(self.work, "alice", metadata)

    def test_public_preflight_checks_compatibility_even_with_matching_saved_hashes(self):
        self._download()
        metadata = train_round(self._train, {}, "alice", self.work)
        trained_dir = self.work / "trained_model"
        config = read_json(trained_dir / "config.json")
        config["architecture_changed"] = True
        write_json(trained_dir / "config.json", config)
        metadata["checkpoint_files_sha256"] = artifact_hashes(
            trained_dir, ["config.json", "model.safetensors"],
        )
        with self.assertRaisesRegex(ValueError, "configuration changed"):
            validate_submission(self.work, "alice", metadata)

    @staticmethod
    def _damage_weights(directory):
        weights = directory / "model.safetensors"
        changed = bytearray(weights.read_bytes())
        changed[-1] ^= 1
        weights.write_bytes(changed)

    def test_training_revalidates_saved_base_after_restart(self):
        self._download()
        self._damage_weights(self.work / "base_model")
        plugin = Mock(side_effect=self._train)
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            train_round(plugin, {}, "alice", self.work)
        plugin.assert_not_called()

    def test_submission_revalidates_saved_base_after_restart(self):
        self._download()
        metadata = train_round(self._train, {}, "alice", self.work)
        self._damage_weights(self.work / "base_model")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            submit_round(self.store, self.work, "alice", metadata)
        self.store.new_submission_revision.assert_not_called()
        self.store.publish_submission.assert_not_called()

    def test_training_rejects_plugin_modification_of_base_payload(self):
        self._download()

        def mutating_plugin(base_dir, trained_dir, options):
            metadata = self._train(base_dir, trained_dir, options)
            self._damage_weights(base_dir)
            return metadata

        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            train_round(mutating_plugin, {}, "alice", self.work)
        self.store.publish_submission.assert_not_called()

    def test_training_rejects_plugin_modification_of_context(self):
        self._download()

        def mutating_plugin(base_dir, trained_dir, options):
            metadata = self._train(base_dir, trained_dir, options)
            context = read_json(self.work / CLIENT_CONTEXT_FILE)
            context["base_revision"] = "different-base"
            write_json(self.work / CLIENT_CONTEXT_FILE, context)
            return metadata

        with self.assertRaisesRegex(ValueError, "modified.*client context"):
            train_round(mutating_plugin, {}, "alice", self.work)

    def test_saved_context_and_base_round_must_agree(self):
        self._download()
        context_path = self.work / CLIENT_CONTEXT_FILE
        context = read_json(context_path)
        changes = [("source_round", 9), ("backend", "huggingface"),
                   ("algorithm_spec", {"name": "another-algorithm"}),
                   ("base_model_dir", "../elsewhere")]
        for key, value in changes:
            write_json(context_path, {**context, key: value})
            plugin = Mock(side_effect=self._train)
            with self.subTest(key=key), self.assertRaises(ValueError):
                train_round(plugin, {}, "alice", self.work)
            plugin.assert_not_called()

    def test_saved_round_document_integrity_is_checked(self):
        self._download()
        round_path = self.work / "base_model" / ROUND_FILE
        record = read_json(round_path)
        record["extension"] = "changed after download"
        write_json(round_path, record)
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            train_round(self._train, {}, "alice", self.work)

    def test_legacy_round_without_hashes_gets_a_local_integrity_baseline(self):
        def legacy_snapshot(repo, revision, destination):
            shutil.copytree(CHECKPOINT, destination)
            write_json(destination / ROUND_FILE, {"schema_version": 1, "round": 3})

        self.store.download_snapshot = Mock(side_effect=legacy_snapshot)
        context = self._download()
        self.assertIn("listener_base_files_sha256", context)
        metadata = train_round(self._train, {}, "alice", self.work)
        self._damage_weights(self.work / "base_model")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            submit_round(self.store, self.work, "alice", metadata)
        self.store.publish_submission.assert_not_called()

    def test_saved_base_directory_cannot_be_replaced_by_a_symlink(self):
        self._download()
        base = self.work / "base_model"
        moved = self.root / "moved-base"
        base.rename(moved)
        base.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "real directory"):
            train_round(self._train, {}, "alice", self.work)


if __name__ == "__main__":
    unittest.main()
