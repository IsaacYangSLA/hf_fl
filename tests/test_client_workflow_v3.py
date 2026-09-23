"""Typed client boundaries, lazy CLI composition and a credential-free workflow."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from hf2l.client_steps import download_client_round, upload_client_update
from hf2l.core.protocol import ClientContext, RoundRecord, SubmissionManifest, document_schemas
from hf2l.hub_helpers import CLIENT_CONTEXT_FILE, ROUND_FILE, SUBMISSION_FILE, artifact_hashes, read_json, write_json


ROOT = Path(__file__).resolve().parents[1]
CHECKPOINT = ROOT / "tests" / "goldens" / "single" / "clients" / "0"


class ClientBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.work = self.root / "client"
        self.work.mkdir()
        shutil.copytree(CHECKPOINT, self.work / "base_model")
        self.trained = self.root / "trained"
        shutil.copytree(CHECKPOINT, self.trained)
        self.context = {
            "schema_version": 2, "backend": "local", "repo_id": "owner/model",
            "base_revision": "base-immutable", "source_round": 0,
            "base_model_dir": "base_model", "extension": {"future": 1},
        }
        self.store = SimpleNamespace(
            name="local", new_submission_revision=Mock(return_value="client-alice-0"),
            publish_submission=Mock(return_value=SimpleNamespace(revision="submission-1")),
        )
        write_json(self.work / CLIENT_CONTEXT_FILE, self.context)

    def test_submission_uses_typed_context_and_one_publish_boundary(self):
        result, submission = upload_client_update(
            self.store, self.work, self.trained, "alice", 7, {"extension": {"loss": 0.25}},
        )
        self.assertEqual("submission-1", result.revision)
        self.assertEqual("base-immutable", submission["base_revision"])
        self.assertEqual(7, SubmissionManifest.from_dict(submission).num_examples)
        self.assertEqual({"name": "fedavg", "version": 1, "params": {}}, submission["algorithm_spec"])
        self.assertEqual({"extension": {"loss": 0.25}}, submission["training"])
        self.assertEqual(submission, read_json(self.trained / SUBMISSION_FILE))
        self.assertEqual(self.context, ClientContext.from_dict(read_json(self.work / CLIENT_CONTEXT_FILE)).to_dict())
        self.store.publish_submission.assert_called_once()

    def test_legacy_context_base_commit_is_supported_without_rewriting_it(self):
        self.context["schema_version"] = 1
        self.context["base_commit"] = self.context.pop("base_revision")
        del self.context["base_model_dir"]
        write_json(self.work / CLIENT_CONTEXT_FILE, self.context)
        _, submission = upload_client_update(self.store, self.work, self.trained, "alice", 1)
        self.assertEqual("base-immutable", submission["base_revision"])
        self.assertEqual(self.context, read_json(self.work / CLIENT_CONTEXT_FILE))

    def test_invalid_example_count_or_context_round_fails_before_publish(self):
        for value in [True, False, 0, -1, 1.0, "1", None]:
            with self.subTest(num_examples=value), self.assertRaises(ValueError):
                upload_client_update(self.store, self.work, self.trained, "alice", value)
        for value in [True, -1, 1.0, "1", None]:
            self.context["source_round"] = value
            write_json(self.work / CLIENT_CONTEXT_FILE, self.context)
            with self.subTest(source_round=value), self.assertRaises(ValueError):
                upload_client_update(self.store, self.work, self.trained, "alice", 1)
        self.store.publish_submission.assert_not_called()

    def test_context_cannot_select_external_or_symlinked_base_directory(self):
        outside = self.root / "external"
        shutil.copytree(CHECKPOINT, outside)
        (self.work / "linked").symlink_to(outside, target_is_directory=True)
        (self.work / "internal-link").symlink_to(self.work / "base_model", target_is_directory=True)
        for value in ["../external", str(outside), "linked", "internal-link", "base_model/../base_model", 4, None]:
            self.context["base_model_dir"] = value
            write_json(self.work / CLIENT_CONTEXT_FILE, self.context)
            with self.subTest(base_model_dir=value), self.assertRaises(ValueError):
                upload_client_update(self.store, self.work, self.trained, "alice", 1)
        self.store.publish_submission.assert_not_called()

    def test_symlinked_context_is_rejected(self):
        saved = self.root / "context.json"
        write_json(saved, self.context)
        (self.work / CLIENT_CONTEXT_FILE).unlink()
        (self.work / CLIENT_CONTEXT_FILE).symlink_to(saved)
        with self.assertRaisesRegex(ValueError, "symlink"):
            upload_client_update(self.store, self.work, self.trained, "alice", 1)
        self.store.publish_submission.assert_not_called()

    def test_training_metadata_must_be_a_finite_json_object(self):
        for value in [[], "note", {"loss": float("nan")}, {"loss": float("inf")}, {"custom": object()}]:
            with self.subTest(metadata=value), self.assertRaises((ValueError, TypeError)):
                upload_client_update(self.store, self.work, self.trained, "alice", 1, value)
        self.store.publish_submission.assert_not_called()

    def test_download_rejects_a_coerced_round_number(self):
        def snapshot(repo, revision, destination):
            shutil.copytree(CHECKPOINT, destination)
            write_json(destination / ROUND_FILE, {"schema_version": 2, "round": "0", "algorithm": "initial model"})
        store = SimpleNamespace(name="local", resolve_revision=Mock(return_value="immutable"), download_snapshot=snapshot)
        with self.assertRaises(ValueError):
            download_client_round(store, "owner/model", "main", self.root / "download")
        self.assertFalse((self.root / "download" / CLIENT_CONTEXT_FILE).exists())

    def test_download_checks_payload_hashes_before_writing_context(self):
        def snapshot(repo, revision, destination):
            shutil.copytree(CHECKPOINT, destination)
            write_json(destination / ROUND_FILE, {
                "schema_version": 2, "backend": "local", "round": 0,
                "checkpoint_files_sha256": artifact_hashes(
                    destination, ["config.json", "model.safetensors"],
                ),
            })
            weights = destination / "model.safetensors"
            corrupted = bytearray(weights.read_bytes())
            corrupted[-1] ^= 1  # Preserve the tensor header and layout.
            weights.write_bytes(corrupted)
        store = SimpleNamespace(name="local", resolve_revision=Mock(return_value="immutable"), download_snapshot=snapshot)
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            download_client_round(store, "owner/model", "immutable", self.root / "tampered")
        self.assertFalse((self.root / "tampered" / CLIENT_CONTEXT_FILE).exists())

    def test_download_requires_schema2_hashes_and_matching_backend(self):
        for change in [{"checkpoint_files_sha256": None}, {"backend": "huggingface"}]:
            def snapshot(repo, revision, destination):
                shutil.copytree(CHECKPOINT, destination)
                record = {
                    "schema_version": 2, "backend": "local", "round": 0,
                    "checkpoint_files_sha256": artifact_hashes(
                        destination, ["config.json", "model.safetensors"],
                    ),
                }
                record.update(change)
                if record["checkpoint_files_sha256"] is None:
                    del record["checkpoint_files_sha256"]
                write_json(destination / ROUND_FILE, record)
            store = SimpleNamespace(name="local", resolve_revision=Mock(return_value="immutable"), download_snapshot=snapshot)
            work = self.root / next(iter(change))
            with self.subTest(change=change), self.assertRaises(ValueError):
                download_client_round(store, "owner/model", "immutable", work)
            self.assertFalse((work / CLIENT_CONTEXT_FILE).exists())

    def test_download_accepts_schema1_without_hashes(self):
        def snapshot(repo, revision, destination):
            shutil.copytree(CHECKPOINT, destination)
            write_json(destination / ROUND_FILE, {"schema_version": 1, "round": 0})
        store = SimpleNamespace(name="huggingface", resolve_revision=Mock(return_value="immutable"), download_snapshot=snapshot)
        work = self.root / "legacy-download"
        context = download_client_round(store, "owner/model", "immutable", work)
        self.assertEqual("immutable", context["base_revision"])
        self.assertEqual("fedavg", context["algorithm_spec"]["name"])
        self.assertTrue((work / CLIENT_CONTEXT_FILE).is_file())

    def test_algorithm_identity_flows_from_round_through_context_to_submission(self):
        declared = {"name": "custom-average", "version": 2, "params": {"weighting": "uniform"}, "extension": "kept"}
        def snapshot(repo, revision, destination):
            shutil.copytree(CHECKPOINT, destination)
            write_json(destination / ROUND_FILE, {"schema_version": 1, "round": 0, "algorithm_spec": declared})
        self.store.resolve_revision = Mock(return_value="immutable")
        self.store.download_snapshot = snapshot
        work = self.root / "algorithm-client"
        context = download_client_round(self.store, "owner/model", "immutable", work)
        self.assertEqual(declared, context["algorithm_spec"])
        _, submission = upload_client_update(self.store, work, self.trained, "alice", 1)
        self.assertEqual(declared, submission["algorithm_spec"])


class CliCompositionTests(unittest.TestCase):
    def test_dispatch_passes_arguments_without_modifying_sys_argv(self):
        from hf2l.cli import main
        original = list(sys.argv)
        target = SimpleNamespace(main=Mock(return_value=7))
        with patch("hf2l.cli.importlib.import_module", return_value=target) as load:
            self.assertEqual(7, main(["upload", "--participant", "alice"]))
        load.assert_called_once_with("hf2l.client_upload")
        target.main.assert_called_once_with(["--participant", "alice"])
        self.assertEqual(original, sys.argv)

    def test_all_help_paths_work_without_model_or_provider_imports(self):
        script = """
import importlib.abc
import sys
class RejectHeavy(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'torch', 'transformers', 'huggingface_hub', 'httpx'}:
            raise AssertionError('Unexpected heavy import: ' + fullname)
sys.meta_path.insert(0, RejectHeavy())
from hf2l.cli import main
for args in [[], ['--help']] + [[command, '--help'] for command in
        ('init', 'download', 'upload', 'train', 'round', 'allowlist', 'exchange', 'export-contract')]:
    assert main(args) == 0, args
"""
        result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_export_contract_matches_validators(self):
        from hf2l.cli import main
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            output = Path(directory) / "contract.json"
            self.assertEqual(0, main(["export-contract", "--output", str(output)]))
            self.assertEqual(document_schemas(), read_json(output))

    def test_failed_download_closes_store_and_returns_exit_code(self):
        from hf2l.client_download import main
        store = Mock()
        store.resolve_revision.side_effect = ValueError("cannot resolve base")
        with tempfile.TemporaryDirectory() as directory, patch("hf2l.client_download.make_store", return_value=store), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(1, main(["--repo-id", "owner/model", "--base-revision", "missing", "--work-dir", str(Path(directory) / "client")]))
        store.close.assert_called_once_with()


class LocalClientWorkflowTests(unittest.TestCase):
    def test_init_download_and_upload_with_distinct_local_principals(self):
        from hf2l.backends import make_store
        from hf2l.cli import main
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            root = Path(directory)
            endpoint = str(root / "store")
            common = ["--backend", "local", "--endpoint", endpoint]
            self.assertEqual(0, main(["init", "--repo-id", "owner/model", "--model-dir", str(CHECKPOINT), "--local-principal", "owner", *common]))
            with make_store("local", endpoint=endpoint, principal="owner") as owner:
                base = owner.resolve_revision("owner/model", "main")
            for participant, count in [("alice", 1), ("bob", 3)]:
                work = root / participant
                self.assertEqual(0, main(["download", "--repo-id", "owner/model", "--base-revision", base, "--work-dir", str(work), "--local-principal", participant, *common]))
                shutil.copytree(CHECKPOINT, work / "trained_model")
                self.assertEqual(0, main(["upload", "--work-dir", str(work), "--participant", participant, "--num-examples", str(count), "--local-principal", participant, *common]))
                self.assertEqual(base, SubmissionManifest.from_dict(read_json(work / "trained_model" / SUBMISSION_FILE)).base_revision)
                self.assertEqual(0, RoundRecord.from_dict(read_json(work / "base_model" / ROUND_FILE)).round)


if __name__ == "__main__":
    unittest.main()
