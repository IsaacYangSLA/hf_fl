"""Offline contracts for the CIFAR-10 owner listener example."""

from __future__ import annotations

from contextlib import redirect_stderr
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from examples.exchange_cifar10 import common


def load_owner_listener_example():
    path = Path(__file__).resolve().parents[1] / "examples/exchange_cifar10/listen_owner.py"
    spec = importlib.util.spec_from_file_location("cifar10_owner_listener_example", path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"common": common}):
        spec.loader.exec_module(module)
    return module


class Cifar10OwnerListenerExampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.example = load_owner_listener_example()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.eval_data = self.root / 'evaluation "split".npz'
        self.eval_data.write_bytes(b"Evaluation contents are validated by the plugin")
        self.token_file = self.root / "owner.token"
        self.token_file.write_text("private-owner-secret\n")
        self.round_file = self.root / "round.json"
        self.descriptor = {
            "schema_version": 1,
            "endpoint": "http://127.0.0.1:8765",
            "space_id": "cifar10-demo",
            "base_revision": "bootstrap-record-id",
            "round_number": 1,
            "allow_local_http": True,
        }
        self.round_file.write_text(json.dumps(self.descriptor))
        self.state_dir = self.root / "owner-listener"

    def arguments(self, *extra):
        return [
            "--round-file", str(self.round_file),
            "--token-file", str(self.token_file),
            "--eval-data", str(self.eval_data),
            "--state-dir", str(self.state_dir),
            *extra,
        ]

    def invoke(self, *extra):
        with patch.object(self.example, "run_hf2l") as run:
            self.assertEqual(0, self.example.main(self.arguments(*extra)))
        run.assert_called_once()
        return run.call_args

    @staticmethod
    def option(command, name):
        return command[command.index(name) + 1]

    @staticmethod
    def plugin_options(command):
        return {
            command[index + 1].split("=", 1)[0]: json.loads(command[index + 1].split("=", 1)[1])
            for index, value in enumerate(command) if value == "--plugin-arg"
        }

    def test_watches_main_and_aggregates_two_clients_with_private_credentials(self):
        call = self.invoke()
        module, command = call.args
        self.assertEqual("hf2l.cli.listen", module)
        for name, expected in {
            "--role": "owner", "--backend": "exchange", "--repo-id": "cifar10-demo",
            "--reference": "main", "--state-dir": str(self.state_dir),
            "--minimum-participants": "2", "--weighting": "examples",
            "--array-backend": "numpy", "--accumulator-dtype": "float32",
            "--plugin": "vgg-cifar10",
        }.items():
            self.assertEqual(expected, self.option(command, name))
        self.assertIn("--require-concurrent-publication", command)
        self.assertEqual({
            "eval_npz": str(self.eval_data), "batch_size": 128, "device": "cpu",
        }, self.plugin_options(command))
        self.assertEqual(2, float(self.option(command, "--poll-interval")))
        self.assertEqual(300, float(self.option(command, "--max-backoff")))
        for value in (
            "--base-revision", "bootstrap-record-id", "--output-dir", "--run-state",
            "--participant", "private-owner-secret",
        ):
            self.assertNotIn(value, command)
        self.assertNotIn("private-owner-secret", " ".join(command))
        self.assertEqual(self.token_file, call.kwargs["token_file"])
        self.assertEqual(self.descriptor["endpoint"], call.kwargs["endpoint"])
        self.assertTrue(call.kwargs["allow_local_http"])
        self.assertEqual(2, call.kwargs["threads"])
        self.assertTrue(call.kwargs["replace_process"])
        self.assertFalse(self.state_dir.exists())

    def test_restart_reuses_state_and_ignores_descriptor_base_revision(self):
        self.state_dir.mkdir()
        state = self.state_dir / "state.json"
        state.write_text('{"completed_round": 1}')
        initial = self.invoke()
        self.descriptor.update(base_revision="later-record-id", round_number=2)
        self.round_file.write_text(json.dumps(self.descriptor))
        self.assertEqual(initial, self.invoke())
        self.assertEqual('{"completed_round": 1}', state.read_text())

    def test_forwards_limits_recovery_and_evaluation_options(self):
        for resolution in ("published", "retry"):
            with self.subTest(resolution=resolution):
                call = self.invoke(
                    "--once", "--max-rounds", "2", "--resolve-uncertain", resolution,
                    "--poll-interval", "0.5", "--max-backoff", "7",
                    "--batch-size", "16", "--device", "cuda:0", "--threads", "4",
                )
                command = call.args[1]
                self.assertIn("--once", command)
                self.assertEqual("2", self.option(command, "--max-rounds"))
                self.assertEqual(resolution, self.option(command, "--resolve-uncertain"))
                self.assertEqual(0.5, float(self.option(command, "--poll-interval")))
                self.assertEqual(7, float(self.option(command, "--max-backoff")))
                self.assertEqual({
                    "eval_npz": str(self.eval_data), "batch_size": 16, "device": "cuda:0",
                }, self.plugin_options(command))
                self.assertEqual(4, call.kwargs["threads"])

    def assert_invalid(self, *extra):
        with patch.object(self.example, "run_hf2l") as run, redirect_stderr(io.StringIO()):
            try:
                status = self.example.main(self.arguments(*extra))
            except SystemExit as exc:
                status = exc.code
        self.assertNotEqual(0, status)
        run.assert_not_called()
        self.assertFalse(self.state_dir.exists())

    def test_invalid_options_do_not_start_listener_or_create_state(self):
        for option, value in (
            ("--batch-size", "0"), ("--threads", "0"),
            ("--poll-interval", "0"), ("--poll-interval", "-1"),
            ("--poll-interval", "nan"), ("--poll-interval", "inf"),
            ("--max-backoff", "0"), ("--max-backoff", "nan"),
            ("--max-backoff", "inf"), ("--max-backoff", "1"),
            ("--max-rounds", "0"), ("--max-rounds", "-1"),
            ("--resolve-uncertain", "submitted"),
        ):
            with self.subTest(option=option, value=value):
                self.assert_invalid(option, value)

    def test_invalid_evaluation_paths_and_descriptor_do_not_create_state(self):
        wrong_extension = self.root / "evaluation.data"
        wrong_extension.write_bytes(b"data")
        directory = self.root / "directory.npz"
        directory.mkdir()
        for path in (self.root / "missing.npz", wrong_extension, directory):
            with self.subTest(path=path):
                self.assert_invalid("--eval-data", str(path))
        self.round_file.write_text("{}")
        self.assert_invalid()

    def test_state_file_or_symlink_is_rejected_without_modifying_target(self):
        existing_file = self.root / "existing-file"
        existing_file.write_text("preserve this")
        real_directory = self.root / "real-state"
        real_directory.mkdir()
        symlink = self.root / "linked-state"
        symlink.symlink_to(real_directory, target_is_directory=True)
        dangling = self.root / "dangling-state"
        dangling.symlink_to(self.root / "missing-state", target_is_directory=True)
        for path in (existing_file, symlink, symlink / "nested", dangling):
            with self.subTest(path=path):
                self.assert_invalid("--state-dir", str(path))
        self.assertEqual("preserve this", existing_file.read_text())
        self.assertEqual([], list(real_directory.iterdir()))
        self.assertFalse((self.root / "missing-state").exists())


if __name__ == "__main__":
    unittest.main()
