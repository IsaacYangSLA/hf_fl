"""Offline contracts for the CIFAR-10 listener entry point and process handoff."""

from __future__ import annotations

from contextlib import redirect_stderr
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from examples.exchange_cifar10 import common


def load_listener_example():
    path = Path(__file__).resolve().parents[1] / "examples/exchange_cifar10/listen_client.py"
    spec = importlib.util.spec_from_file_location("cifar10_listener_example", path)
    module = importlib.util.module_from_spec(spec)
    # The source-checkout examples deliberately import their neighboring helper.
    with patch.dict(sys.modules, {"common": common}):
        spec.loader.exec_module(module)
    return module


class Cifar10ListenerExampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.example = load_listener_example()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dataset = self.root / 'client "one" dataset.npz'
        self.dataset.write_bytes(b"NPZ contents are validated by the training plugin")
        self.token_file = self.root / "client1.token"
        self.token_file.write_text("participant-secret\n")
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
        self.state_dir = self.root / "client1-listener"

    def arguments(self, *extra):
        return [
            "--round-file", str(self.round_file),
            "--participant", "client1",
            "--token-file", str(self.token_file),
            "--dataset", str(self.dataset),
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

    def test_watches_main_with_real_dataset_and_private_credentials(self):
        call = self.invoke()
        module, command = call.args
        self.assertEqual("hf2l.cli.listen", module)
        self.assertEqual("exchange", self.option(command, "--backend"))
        self.assertEqual("cifar10-demo", self.option(command, "--repo-id"))
        self.assertEqual("client1", self.option(command, "--participant"))
        self.assertEqual("main", self.option(command, "--reference"))
        self.assertEqual(str(self.state_dir), self.option(command, "--state-dir"))
        self.assertEqual("vgg-cifar10", self.option(command, "--plugin"))
        self.assertNotIn("--base-revision", command)
        self.assertNotIn("bootstrap-record-id", command)
        self.assertNotIn("participant-secret", " ".join(command))
        options = {}
        for index, value in enumerate(command):
            if value == "--plugin-arg":
                key, encoded = command[index + 1].split("=", 1)
                options[key] = json.loads(encoded)
        self.assertEqual({
            "dataset_npz": str(self.dataset), "epochs": 1, "batch_size": 64,
            "learning_rate": 0.01, "device": "cpu",
        }, options)
        self.assertEqual(2, float(self.option(command, "--poll-interval")))
        self.assertEqual(300, float(self.option(command, "--max-backoff")))
        self.assertEqual(self.token_file, call.kwargs["token_file"])
        self.assertEqual(self.descriptor["endpoint"], call.kwargs["endpoint"])
        self.assertTrue(call.kwargs["allow_local_http"])
        self.assertEqual(2, call.kwargs["threads"])
        self.assertTrue(call.kwargs["replace_process"])
        self.assertFalse(self.state_dir.exists())

    def test_reuses_state_and_does_not_pin_the_bootstrap_round(self):
        self.state_dir.mkdir()
        state = self.state_dir / "state.json"
        state.write_text('{"completed_round": 1}')
        initial = self.invoke()
        self.descriptor.update(base_revision="later-record-id", round_number=2)
        self.round_file.write_text(json.dumps(self.descriptor))
        later = self.invoke()
        self.assertEqual(initial, later)
        self.assertEqual('{"completed_round": 1}', state.read_text())

    def test_forwards_limits_recovery_and_training_options(self):
        for resolution in ("submitted", "retry"):
            with self.subTest(resolution=resolution):
                call = self.invoke(
                    "--participant", "client2", "--once", "--max-rounds", "2",
                    "--resolve-uncertain", resolution, "--poll-interval", "0.5",
                    "--max-backoff", "7", "--epochs", "3", "--batch-size", "16",
                    "--learning-rate", "0.05", "--device", "cuda:0", "--threads", "4",
                )
                command = call.args[1]
                self.assertEqual("client2", self.option(command, "--participant"))
                self.assertIn("--once", command)
                self.assertEqual("2", self.option(command, "--max-rounds"))
                self.assertEqual(resolution, self.option(command, "--resolve-uncertain"))
                self.assertEqual(0.5, float(self.option(command, "--poll-interval")))
                self.assertEqual(7, float(self.option(command, "--max-backoff")))
                options = dict(
                    command[index + 1].split("=", 1)
                    for index, value in enumerate(command) if value == "--plugin-arg"
                )
                self.assertEqual(3, json.loads(options["epochs"]))
                self.assertEqual(16, json.loads(options["batch_size"]))
                self.assertEqual(0.05, json.loads(options["learning_rate"]))
                self.assertEqual("cuda:0", json.loads(options["device"]))
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

    def test_invalid_numeric_options_do_not_start_listener_or_create_state(self):
        for option, value in (
            ("--epochs", "0"), ("--batch-size", "0"), ("--threads", "0"),
            ("--learning-rate", "0"), ("--learning-rate", "-1"),
            ("--learning-rate", "nan"), ("--learning-rate", "inf"),
            ("--poll-interval", "0"), ("--poll-interval", "nan"),
            ("--poll-interval", "inf"), ("--max-backoff", "0"),
            ("--max-backoff", "nan"), ("--max-backoff", "inf"),
            ("--max-backoff", "1"), ("--max-rounds", "0"),
        ):
            with self.subTest(option=option, value=value):
                self.assert_invalid(option, value)

    def test_invalid_datasets_and_descriptor_do_not_create_state(self):
        wrong_extension = self.root / "client.data"
        wrong_extension.write_bytes(b"data")
        directory = self.root / "directory.npz"
        directory.mkdir()
        for path in (self.root / "missing.npz", wrong_extension, directory):
            with self.subTest(path=path):
                self.assert_invalid("--dataset", str(path))
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


class ExampleProcessHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.token_file = Path(self.temporary.name) / "client.token"
        self.token_file.write_text("participant-secret\n")

    def invoke(self, **extra):
        return common.run_hf2l(
            "hf2l.cli.listen", ["--participant", "client1"], token_file=self.token_file,
            endpoint="http://127.0.0.1:8765", allow_local_http=True, threads=3, **extra,
        )

    def test_exec_preserves_process_exit_and_signal_handling_and_cleans_credentials(self):
        class ProcessReplaced(Exception):
            pass

        with patch.dict(os.environ, {"EXCHANGE_TOKEN": "inherited-secret", "KEEP_ME": "yes"}), \
                patch.object(common.os, "execvpe", side_effect=ProcessReplaced) as execute, \
                patch.object(common.subprocess, "run") as run:
            with self.assertRaises(ProcessReplaced):
                self.invoke(replace_process=True)
        run.assert_not_called()
        executable, command, environment = execute.call_args.args
        self.assertEqual(sys.executable, executable)
        self.assertEqual([sys.executable, "-m", "hf2l.cli.listen", "--participant", "client1"], command)
        self.assertNotIn("EXCHANGE_TOKEN", environment)
        self.assertEqual(str(self.token_file), environment["EXCHANGE_TOKEN_FILE"])
        self.assertEqual("http://127.0.0.1:8765", environment["EXCHANGE_ENDPOINT"])
        self.assertEqual("true", environment["EXCHANGE_ALLOW_LOCAL_HTTP"])
        self.assertEqual("3", environment["OMP_NUM_THREADS"])
        self.assertEqual("3", environment["MKL_NUM_THREADS"])
        self.assertEqual("yes", environment["KEEP_ME"])
        self.assertNotIn("participant-secret", command)
        self.assertNotIn("participant-secret", environment.values())

    def test_existing_commands_keep_checked_subprocess_behavior(self):
        with patch.object(common.os, "execvpe") as execute, patch.object(common.subprocess, "run") as run:
            self.invoke()
        execute.assert_not_called()
        run.assert_called_once()
        self.assertTrue(run.call_args.kwargs["check"])
        self.assertEqual(str(self.token_file), run.call_args.kwargs["env"]["EXCHANGE_TOKEN_FILE"])

    def test_empty_or_missing_token_is_rejected_before_process_handoff(self):
        self.token_file.write_text("  \n")
        with patch.object(common.os, "execvpe") as execute, patch.object(common.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                self.invoke(replace_process=True)
            self.token_file.unlink()
            with self.assertRaises(OSError):
                self.invoke(replace_process=True)
        execute.assert_not_called()
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
