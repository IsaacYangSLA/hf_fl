"""Durable client-listener behavior against real adapters and checkpoint files."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
from safetensors.numpy import load_file, save_file

from hf2l.backends.local import LocalStore
from hf2l.core.protocol import CLIENT_CONTEXT_FILE, ROUND_FILE, SUBMISSION_FILE
from hf2l.hub_helpers import artifact_hashes, read_json, write_json
from hf2l.listener.client import ClientListener, ListenerStateError, UncertainSubmission
from tests.test_store_contract_v3 import FakeExchange, FakeHub


CHECKPOINT_FILES = ["config.json", "model.safetensors"]


class ListenerFixture:
    backend = "local"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state_dir = self.root / "listener"
        self.training_calls = []
        self.store = self.make_store()
        self.addCleanup(self.store.close)
        self.source = self.make_global("initial", 0)
        self.base = self.store.initialize_repository("repo", self.source, private=False).revision

    def make_store(self):
        if self.backend == "local":
            return LocalStore(self.root / "storage", "alice")
        if self.backend == "exchange":
            from hf2l.backends.exchange import ExchangeStore
            self.sdk = FakeExchange()
            return ExchangeStore(None, None, client=self.sdk)
        self.hub = FakeHub()
        if self.backend == "huggingface":
            from hf2l.backends.huggingface import HuggingFaceStore
            with patch("hf2l.backends.huggingface.HfApi", return_value=self.hub):
                return HuggingFaceStore(None)
        from hf2l.backends.jfrog import JFrogStore
        with patch("hf2l.backends.jfrog.HfApi", return_value=self.hub):
            store = JFrogStore(None, "https://example.test/artifactory/api/huggingfaceml/models")
        store._upload_folder = lambda repo, folder, revision: self.hub.put(folder, revision)
        return store

    def make_global(self, name, round_number):
        folder = self.root / name
        folder.mkdir()
        write_json(folder / "config.json", {"model_type": "listener-test"})
        save_file({"weight": np.array([1.0, 2.0], dtype=np.float32)}, folder / "model.safetensors")
        write_json(folder / ROUND_FILE, {
            "schema_version": 2,
            "backend": self.backend,
            "round": round_number,
            "checkpoint_files_sha256": artifact_hashes(folder, CHECKPOINT_FILES),
        })
        return folder

    def train(self, base_dir, output_dir, options):
        self.training_calls.append((base_dir, output_dir, dict(options)))
        output_dir.mkdir()
        tensors = load_file(base_dir / "model.safetensors")
        tensors["weight"] += 1
        save_file(tensors, output_dir / "model.safetensors")
        shutil.copyfile(base_dir / "config.json", output_dir / "config.json")
        return {"num_examples": 7, "loss": 0.25}

    def listener(self, **overrides):
        arguments = {
            "store": self.store,
            "repo_id": "repo",
            "participant": "alice",
            "state_dir": self.state_dir,
            "source_id": f"{self.backend}:test-endpoint",
            "training_id": "numpy-trainer-v1",
            "train_model": self.train,
            "options": {"learning_rate": 0.01},
        }
        arguments.update(overrides)
        return ClientListener(**arguments)

    def state(self):
        return read_json(self.state_dir / "state.json")

    def work(self, revision=None):
        digest = hashlib.sha256((revision or self.base).encode()).hexdigest()
        return self.state_dir / "jobs" / digest / "work"

    def submitted_manifests(self):
        if self.backend == "local":
            records, _ = self.store.discover_submissions("repo")
            result = []
            for index, record in enumerate(records):
                folder = self.root / f"inspection-{len(list(self.root.glob('inspection-*')))}-{index}"
                self.store.download_snapshot("repo", record.revision, folder)
                result.append(read_json(folder / SUBMISSION_FILE))
            return result
        if self.backend == "exchange":
            return [record.metadata["hf2l_files"][SUBMISSION_FILE]
                    for record in self.sdk.stored.values() if record.kind == "training.update"]
        return [json.loads(files[SUBMISSION_FILE]) for files in self.hub.files.values()
                if SUBMISSION_FILE in files]


class AdapterListenerContract(ListenerFixture):
    """Each provider exercises the same controller through its concrete adapter."""

    def test_pinned_round_is_submitted_once_and_survives_restart(self):
        with patch.object(self.store, "download_snapshot", wraps=self.store.download_snapshot) as download:
            with self.listener() as listener:
                self.assertEqual("submitted", listener.poll_once())
                self.assertEqual("idle", listener.poll_once())
            with self.listener() as restarted:
                self.assertEqual("idle", restarted.poll_once())
        self.assertEqual(1, len(self.training_calls))
        self.assertEqual(self.base, self.store.resolve_reference("repo").revision)
        self.assertTrue(download.call_args_list)
        self.assertTrue(all(call.args[1] == self.base for call in download.call_args_list))
        submissions = self.submitted_manifests()
        self.assertEqual(1, len(submissions))
        self.assertEqual(self.base, submissions[0]["base_revision"])
        self.assertEqual(0, submissions[0]["source_round"])
        self.assertEqual("alice", submissions[0]["participant"])
        self.assertEqual(7, submissions[0]["num_examples"])
        self.assertEqual({"loss": 0.25}, submissions[0]["training"])
        self.assertEqual("submitted", self.state()["jobs"][self.base]["status"])
        self.assertIsNone(self.state()["active"])
        self.assertEqual(0, self.state()["completed_round"])
        np.testing.assert_array_equal(
            load_file(self.work() / "trained_model" / "model.safetensors")["weight"],
            np.array([2.0, 3.0], dtype=np.float32),
        )


class HuggingFaceListenerTests(AdapterListenerContract, unittest.TestCase):
    backend = "huggingface"


class JFrogListenerTests(AdapterListenerContract, unittest.TestCase):
    backend = "jfrog"


class ExchangeListenerTests(AdapterListenerContract, unittest.TestCase):
    backend = "exchange"


class LocalListenerTests(AdapterListenerContract, unittest.TestCase):
    def advance(self, round_number, name="next"):
        folder = self.make_global(name, round_number)
        current = self.store.resolve_reference("repo")
        return self.store.publish_aggregate(
            "repo", folder, [*CHECKPOINT_FILES, ROUND_FILE], expected_base=current.revision,
            next_round=round_number, tag=None, reference=current,
        ).revision

    def test_next_round_trains_and_submits_with_its_own_immutable_base(self):
        with self.listener() as listener:
            self.assertEqual("submitted", listener.poll_once())
            next_base = self.advance(1)
            self.assertEqual("submitted", listener.poll_once())
        self.assertEqual(2, len(self.training_calls))
        submitted = {(item["source_round"], item["base_revision"]) for item in self.submitted_manifests()}
        self.assertEqual({(0, self.base), (1, next_base)}, submitted)
        self.assertEqual(1, self.state()["completed_round"])

    def test_main_advanced_during_training_skips_stale_submission(self):
        def train_then_advance(*args):
            result = self.train(*args)
            self.advance(1)
            return result
        with self.listener(train_model=train_then_advance) as listener:
            self.assertEqual("skipped", listener.poll_once())
        self.assertEqual([], self.submitted_manifests())
        self.assertEqual("skipped", self.state()["jobs"][self.base]["status"])
        with self.listener() as listener:
            self.assertEqual("submitted", listener.poll_once())
        self.assertEqual(1, self.submitted_manifests()[0]["source_round"])

    def test_main_advanced_during_download_never_runs_stale_training(self):
        original = self.store.download_snapshot
        def download_then_advance(*args, **kwargs):
            original(*args, **kwargs)
            if not kwargs.get("allow_patterns"):
                self.advance(1)
        with patch.object(self.store, "download_snapshot", side_effect=download_then_advance):
            with self.listener() as listener:
                self.assertEqual("skipped", listener.poll_once())
        self.assertEqual([], self.training_calls)
        self.assertEqual([], self.submitted_manifests())

    def test_metadata_only_commit_does_not_retrain_completed_round(self):
        with self.listener() as listener:
            listener.poll_once()
            metadata_revision = self.advance(0, "metadata-change")
            with patch.object(self.store, "download_snapshot", wraps=self.store.download_snapshot) as download:
                self.assertEqual("skipped", listener.poll_once())
                self.assertEqual("idle", listener.poll_once())
            self.assertTrue(all(call.kwargs.get("allow_patterns") for call in download.call_args_list))
        self.assertEqual(1, len(self.training_calls))
        self.assertEqual("skipped", self.state()["jobs"][metadata_revision]["status"])
        self.assertEqual(1, len(self.submitted_manifests()))

    def test_rollback_to_an_older_round_does_not_retrain(self):
        with self.listener() as listener:
            listener.poll_once()
            self.advance(3, "third")
            listener.poll_once()
            self.advance(1, "rollback")
            self.assertEqual("skipped", listener.poll_once())
        self.assertEqual(2, len(self.training_calls))
        self.assertEqual(3, self.state()["completed_round"])

    def test_partial_download_is_removed_before_retry_after_restart(self):
        original = self.store.download_snapshot
        def interrupted(repo, revision, destination, **kwargs):
            if kwargs.get("allow_patterns"):
                return original(repo, revision, destination, **kwargs)
            destination.mkdir(parents=True)
            (destination / "partial-transfer").write_text("incomplete")
            raise ConnectionError("download interrupted")
        with patch.object(self.store, "download_snapshot", side_effect=interrupted):
            with self.listener() as listener:
                with self.assertRaisesRegex(ConnectionError, "download interrupted"):
                    listener.poll_once()
        self.assertEqual([], self.training_calls)
        with self.listener() as restarted:
            self.assertEqual("submitted", restarted.poll_once())
        self.assertFalse((self.work() / "base_model" / "partial-transfer").exists())
        self.assertEqual(1, len(self.submitted_manifests()))

    def test_partial_training_output_is_removed_before_retry_after_restart(self):
        def interrupted(base_dir, output_dir, options):
            output_dir.mkdir()
            (output_dir / "partial-checkpoint").write_text("incomplete")
            raise RuntimeError("trainer interrupted")
        with self.listener(train_model=interrupted) as listener:
            with self.assertRaisesRegex(RuntimeError, "trainer interrupted"):
                listener.poll_once()
        with self.listener() as restarted:
            self.assertEqual("submitted", restarted.poll_once())
        self.assertFalse((self.work() / "trained_model" / "partial-checkpoint").exists())
        self.assertEqual(1, len(self.submitted_manifests()))

    def test_read_failure_after_training_preserves_output_for_restart(self):
        original = self.store.resolve_reference
        def fail_after_training(*args, **kwargs):
            if self.training_calls:
                raise ConnectionError("reference temporarily unavailable")
            return original(*args, **kwargs)
        with patch.object(self.store, "resolve_reference", side_effect=fail_after_training):
            with self.listener() as listener:
                with self.assertRaisesRegex(ConnectionError, "reference temporarily unavailable"):
                    listener.poll_once()
        self.assertEqual("ready", self.state()["jobs"][self.base]["status"])
        with self.listener() as restarted:
            self.assertEqual("submitted", restarted.poll_once())
        self.assertEqual(1, len(self.training_calls))
        self.assertEqual(1, len(self.submitted_manifests()))

    def test_resumed_training_rejects_context_for_another_job(self):
        def interrupted(*args):
            raise RuntimeError("trainer interrupted")
        with self.listener(train_model=interrupted) as listener:
            with self.assertRaisesRegex(RuntimeError, "trainer interrupted"):
                listener.poll_once()
        context_path = self.work() / CLIENT_CONTEXT_FILE
        original = read_json(context_path)
        changes = (
            {"source_round": 999}, {"repo_id": "other-repository"},
            {"base_revision": "f" * 32}, {"backend": "jfrog"},
            {"base_model_dir": "other-model"},
        )
        with patch.object(self.store, "publish_submission", wraps=self.store.publish_submission) as publish:
            for change in changes:
                write_json(context_path, {**original, **change})
                with self.subTest(change=change), self.listener() as restarted:
                    with self.assertRaisesRegex(ListenerStateError, "context"):
                        restarted.poll_once()
                self.assertEqual([], self.training_calls)
                publish.assert_not_called()
        write_json(context_path, original)
        with self.listener() as recovered:
            self.assertEqual("submitted", recovered.poll_once())
        self.assertEqual(1, len(self.training_calls))

    def test_damaged_ready_checkpoint_is_rejected_before_publication_intent(self):
        original = self.store.resolve_reference
        def fail_after_training(*args, **kwargs):
            if self.training_calls:
                raise ConnectionError("reference temporarily unavailable")
            return original(*args, **kwargs)
        with patch.object(self.store, "resolve_reference", side_effect=fail_after_training):
            with self.listener() as listener:
                with self.assertRaises(ConnectionError):
                    listener.poll_once()
        weights = self.work() / "trained_model" / "model.safetensors"
        tensors = load_file(weights)
        tensors["weight"] += 10
        save_file(tensors, weights)
        with patch.object(self.store, "publish_submission", wraps=self.store.publish_submission) as publish:
            with self.listener() as restarted:
                with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                    restarted.poll_once()
            publish.assert_not_called()
        self.assertEqual("ready", self.state()["jobs"][self.base]["status"])
        self.assertEqual(1, len(self.training_calls))

    def test_training_hash_validation_failure_never_invokes_plugin(self):
        snapshot = self.store._snapshot_path(self.store._repo("repo"), self.base) / "files"
        weights = snapshot / "model.safetensors"
        tensor = load_file(weights)
        tensor["weight"] += 10
        save_file(tensor, weights)
        with self.listener() as listener:
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                listener.poll_once()
        self.assertEqual([], self.training_calls)
        self.assertEqual([], self.submitted_manifests())

    def test_publish_intent_is_durable_before_submission_is_sent(self):
        original = self.store.publish_submission
        def checked_publish(*args, **kwargs):
            state = self.state()
            self.assertEqual(self.base, state["active"])
            self.assertEqual("publishing", state["jobs"][self.base]["status"])
            return original(*args, **kwargs)
        with patch.object(self.store, "publish_submission", side_effect=checked_publish):
            with self.listener() as listener:
                self.assertEqual("submitted", listener.poll_once())

    def test_accepted_upload_with_lost_response_blocks_restart_until_reconciled(self):
        original = self.store.publish_submission
        def accepted_but_disconnected(*args, **kwargs):
            original(*args, **kwargs)
            raise ConnectionError("response lost")
        with patch.object(self.store, "publish_submission", side_effect=accepted_but_disconnected):
            with self.listener() as listener:
                with self.assertRaises(UncertainSubmission):
                    listener.poll_once()
        self.assertEqual("uncertain", self.state()["jobs"][self.base]["status"])
        with self.listener() as restarted:
            with self.assertRaises(UncertainSubmission):
                restarted.poll_once()
            restarted.resolve_uncertain("submitted")
            self.assertEqual("idle", restarted.poll_once())
        self.assertEqual(1, len(self.training_calls))
        self.assertEqual(1, len(self.submitted_manifests()))

    def test_explicit_retry_reuses_trained_checkpoint_without_retraining(self):
        with patch.object(self.store, "publish_submission", side_effect=ConnectionError("not sent")):
            with self.listener() as listener:
                with self.assertRaises(UncertainSubmission):
                    listener.poll_once()
        with self.listener() as restarted:
            restarted.resolve_uncertain("retry")
            self.assertEqual("submitted", restarted.poll_once())
        self.assertEqual(1, len(self.training_calls))
        self.assertEqual(1, len(self.submitted_manifests()))

    def test_interrupted_publish_is_uncertain_on_restart(self):
        with patch.object(self.store, "publish_submission", side_effect=KeyboardInterrupt):
            with self.listener() as listener:
                with self.assertRaises(KeyboardInterrupt):
                    listener.poll_once()
        with self.listener() as restarted:
            with self.assertRaises(UncertainSubmission):
                restarted.poll_once()
        self.assertEqual([], self.submitted_manifests())
        self.assertEqual(1, len(self.training_calls))

    def test_new_global_round_does_not_bypass_uncertain_submission(self):
        with patch.object(self.store, "publish_submission", side_effect=ConnectionError("response lost")):
            with self.listener() as listener:
                with self.assertRaises(UncertainSubmission):
                    listener.poll_once()
        self.advance(1)
        with self.listener() as restarted:
            with self.assertRaises(UncertainSubmission):
                restarted.poll_once()
        self.assertEqual(1, len(self.training_calls))
        self.assertEqual(self.base, self.state()["active"])

    def test_uncertain_recovery_is_not_permitted_without_uncertain_job(self):
        with self.listener() as listener:
            for action in ("submitted", "retry", "arbitrary"):
                with self.subTest(action=action), self.assertRaises((ValueError, RuntimeError)):
                    listener.resolve_uncertain(action)

    def test_state_directory_has_one_active_listener(self):
        with self.listener():
            with self.assertRaises((ValueError, RuntimeError, BlockingIOError)):
                with self.listener():
                    self.fail("a second listener acquired the same state directory")
        with self.listener() as restarted:
            self.assertEqual("submitted", restarted.poll_once())

    def test_state_cannot_be_reused_by_different_identity(self):
        with self.listener():
            pass
        for changed in ({"participant": "bob"}, {"repo_id": "different"},
                        {"source_id": "different-endpoint"}, {"training_id": "different-trainer"},
                        {"reference": "other"}, {"options": {"learning_rate": 0.2}}):
            with self.subTest(change=changed), self.assertRaises((ValueError, RuntimeError)):
                with self.listener(**changed):
                    self.fail("incompatible listener identity accepted")

    def test_malformed_state_fails_without_training_or_backend_writes(self):
        with self.listener():
            pass
        original = self.state()
        invalid_states = (
            [], {**original, "jobs": []}, {**original, "completed_round": "0"},
            {**original, "schema_version": True}, {**original, "active": self.base},
            {**original, "jobs": {self.base: {
                "revision": self.base, "status": "training", "source_round": False,
            }}, "active": self.base},
        )
        with patch.object(self.store, "publish_submission", wraps=self.store.publish_submission) as publish:
            for invalid in invalid_states:
                (self.state_dir / "state.json").write_text(json.dumps(invalid))
                with self.subTest(state=invalid), self.assertRaises(ListenerStateError):
                    with self.listener():
                        self.fail("malformed durable state was accepted")
                self.assertEqual([], self.training_calls)
                publish.assert_not_called()
        write_json(self.state_dir / "state.json", original)
        with self.listener() as recovered:
            self.assertEqual("submitted", recovered.poll_once())

    def test_missing_state_with_existing_jobs_cannot_silently_resubmit(self):
        with self.listener() as listener:
            listener.poll_once()
        (self.state_dir / "state.json").unlink()
        with self.assertRaisesRegex(ValueError, "state"):
            with self.listener():
                self.fail("missing state allowed duplicate submission")
        self.assertEqual(1, len(self.submitted_manifests()))

    def test_symlinked_state_does_not_read_or_modify_external_file(self):
        with self.listener():
            pass
        external = self.root / "external-state.json"
        external.write_bytes((self.state_dir / "state.json").read_bytes())
        before = external.read_bytes()
        (self.state_dir / "state.json").unlink()
        (self.state_dir / "state.json").symlink_to(external)
        with self.assertRaisesRegex(ValueError, "symlink"):
            with self.listener():
                self.fail("symlinked state was accepted")
        self.assertEqual(before, external.read_bytes())

    def test_run_retries_read_failure_without_duplicate_training(self):
        original = self.store.resolve_reference
        attempts = 0
        def temporarily_unavailable(*args, **kwargs):
            nonlocal attempts
            attempts += 1
            if attempts <= 3:
                raise ConnectionError("temporarily unavailable")
            return original(*args, **kwargs)
        with patch.object(self.store, "resolve_reference", side_effect=temporarily_unavailable), \
                patch("hf2l.listener.client.time.sleep") as sleep:
            with self.listener() as listener:
                listener.run(poll_interval=1, max_backoff=2, max_rounds=1)
        self.assertEqual([1, 2, 2], [call.args[0] for call in sleep.call_args_list])
        self.assertEqual(1, len(self.training_calls))
        self.assertEqual(1, len(self.submitted_manifests()))

    def test_run_does_not_automatically_retry_uncertain_upload(self):
        with patch.object(self.store, "publish_submission", side_effect=ConnectionError("response lost")) as publish, \
                patch("hf2l.listener.client.time.sleep") as sleep:
            with self.listener() as listener:
                with self.assertRaises(UncertainSubmission):
                    listener.run(poll_interval=1, max_rounds=1)
        publish.assert_called_once()
        sleep.assert_not_called()

    def test_run_once_propagates_safe_failure_instead_of_waiting(self):
        with patch.object(self.store, "resolve_reference", side_effect=ConnectionError("offline")), \
                patch("hf2l.listener.client.time.sleep") as sleep:
            with self.listener() as listener:
                with self.assertRaisesRegex(ConnectionError, "offline"):
                    listener.run(once=True)
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
