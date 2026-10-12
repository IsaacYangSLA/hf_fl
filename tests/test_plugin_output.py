"""Plugin diagnostics leave listener events and owner JSON results parseable."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hf2l.backends.local import LocalStore
from hf2l.cli import listen
from hf2l.client_train import main as client_train_main
from hf2l.client_steps import download_client_round, upload_client_update
from hf2l.common.fs import artifact_hashes, write_json
from hf2l.common.output import plugin_stdout_to_stderr
from hf2l.core.protocol import ROUND_FILE
from hf2l.fedavg_runner import run_round
from hf2l.init_repo import main as initialize_main
from hf2l.listener.workflow import download_round, train_round
from hf2l.owner_fedavg import main as owner_main
from hf2l.plugin_loader import load_plugin
from hf2l.round.config import RoundConfig


CHECKPOINT = Path(__file__).resolve().parent / "goldens" / "single" / "clients" / "0"


class PluginOutputTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hf2l-plugin-output-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.store_dir = self.root / "store"
        initial = self.root / "initial"
        shutil.copytree(CHECKPOINT, initial)
        write_json(initial / ROUND_FILE, {
            "schema_version": 2, "backend": "local", "round": 0,
            "checkpoint_files_sha256": artifact_hashes(initial, ["config.json", "model.safetensors"]),
        })
        self.owner = LocalStore(self.store_dir, "owner")
        self.addCleanup(self.owner.close)
        self.base = self.owner.initialize_repository("repo", initial, private=True).revision

    def _plugin(self, name, source):
        path = self.root / name
        path.write_text(source, encoding="utf-8")
        return path

    def _client_arguments(self, plugin):
        return ["--backend", "local", "--endpoint", str(self.store_dir), "--local-principal", "alice",
                "--repo-id", "repo", "--participant", "alice", "--plugin", str(plugin),
                "--state-dir", str(self.root / "listener"), "--once"]

    def _submissions(self):
        for participant in ("alice", "bob"):
            client = LocalStore(self.store_dir, participant)
            try:
                work = self.root / participant
                download_client_round(client, "repo", self.base, work)
                trained = work / "trained_model"
                shutil.copytree(work / "base_model", trained)
                upload_client_update(client, work, trained, participant, 1)
            finally:
                client.close()

    def _evaluator(self, *, failure=False):
        action = "raise RuntimeError('evaluation failed')" if failure else "return {'accuracy': 0.5, 'nested': {'ok': True}}"
        return self._plugin("evaluate.py", "print('evaluation import diagnostic')\n"
                            "def evaluate_model(model_dir, options):\n"
                            "    print('evaluation call diagnostic')\n"
                            f"    {action}\n")

    def test_context_restores_stdout_after_exception_and_preserves_stderr(self):
        output, diagnostics = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(diagnostics):
            original = sys.stdout
            with self.assertRaisesRegex(RuntimeError, "plugin failed"):
                with plugin_stdout_to_stderr():
                    print("plugin stdout")
                    print("plugin stderr", file=sys.stderr)
                    raise RuntimeError("plugin failed")
            self.assertIs(sys.stdout, original)
            print("caller result")
        self.assertEqual(output.getvalue(), "caller result\n")
        self.assertEqual(diagnostics.getvalue(), "plugin stdout\nplugin stderr\n")

    def test_local_plugin_import_diagnostics_are_redirected_on_success_and_failure(self):
        for failure in (False, True):
            plugin = self._plugin(f"import-{failure}.py", "print('import diagnostic')\n" +
                                  ("raise RuntimeError('import failed')\n" if failure else "value = 7\n"))
            output, diagnostics = io.StringIO(), io.StringIO()
            with self.subTest(failure=failure), redirect_stdout(output), redirect_stderr(diagnostics):
                original = sys.stdout
                if failure:
                    with self.assertRaisesRegex(RuntimeError, "import failed"):
                        load_plugin(plugin)
                else:
                    self.assertEqual(load_plugin(plugin).value, 7)
                self.assertIs(sys.stdout, original)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(diagnostics.getvalue(), "import diagnostic\n")

    def test_builtin_plugin_import_diagnostics_are_redirected(self):
        def importing(name):
            print("builtin import diagnostic")
            return SimpleNamespace(name=name)

        output, diagnostics = io.StringIO(), io.StringIO()
        with patch("hf2l.plugin_loader.importlib.import_module", side_effect=importing), \
                redirect_stdout(output), redirect_stderr(diagnostics):
            plugin = load_plugin("lenet")
        self.assertEqual(plugin.name, "hf2l.plugins.lenet_poc")
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(diagnostics.getvalue(), "builtin import diagnostic\n")

    def test_library_training_redirects_diagnostics_without_changing_metadata(self):
        work = self.root / "work"
        download_round(self.owner, "repo", self.base, work)
        metadata = {"num_examples": 3, "metrics": {"loss": 0.25}}

        def trainer(base_dir, output_dir, options):
            print("training diagnostic")
            shutil.copytree(base_dir, output_dir)
            return metadata

        output, diagnostics = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(diagnostics):
            result = train_round(trainer, {}, "alice", work)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(diagnostics.getvalue(), "training diagnostic\n")
        self.assertEqual(result["num_examples"], 3)
        self.assertEqual(result["training"], {"metrics": {"loss": 0.25}})
        self.assertEqual(metadata, {"num_examples": 3, "metrics": {"loss": 0.25}})

    def test_library_training_restores_stdout_after_plugin_failure(self):
        work = self.root / "work"
        download_round(self.owner, "repo", self.base, work)

        def trainer(*args):
            print("failed training diagnostic")
            raise RuntimeError("training failed")

        output, diagnostics = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(diagnostics):
            original = sys.stdout
            with self.assertRaisesRegex(RuntimeError, "training failed"):
                train_round(trainer, {}, "alice", work)
            self.assertIs(sys.stdout, original)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(diagnostics.getvalue(), "failed training diagnostic\n")

    def test_listener_stdout_contains_only_json_events_with_noisy_plugin(self):
        plugin = self._plugin("train.py", "import shutil\nprint('training import diagnostic')\n"
                              "def train_model(base_dir, output_dir, options):\n"
                              "    print('training call diagnostic')\n"
                              "    shutil.copytree(base_dir, output_dir)\n"
                              "    return {'num_examples': 1, 'loss': 0.25}\n")
        output, diagnostics = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(diagnostics):
            status = listen.main(self._client_arguments(plugin))
        self.assertEqual(status, 0, diagnostics.getvalue())
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([event["event"] for event in events], ["training", "publishing", "submitted"])
        self.assertEqual(diagnostics.getvalue(), "training import diagnostic\ntraining call diagnostic\n")

    def test_listener_import_failure_does_not_pollute_event_stream(self):
        plugin = self._plugin("failed-import.py", "print('failed import diagnostic')\n"
                              "raise RuntimeError('import failed')\n")
        output, diagnostics = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(diagnostics):
            status = listen.main(self._client_arguments(plugin))
        self.assertEqual(status, 1)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("failed import diagnostic\n", diagnostics.getvalue())
        self.assertIn("error: listener failed (RuntimeError)", diagnostics.getvalue())

    def test_initializer_diagnostics_are_separate_from_command_results(self):
        for failure in (False, True):
            action = ("raise RuntimeError('initialization failed')" if failure else
                      "shutil.copytree(options['checkpoint'], output_dir, dirs_exist_ok=True)\n"
                      "    return {'model': 'copied checkpoint'}")
            plugin = self._plugin(f"initialize-{failure}.py", "import shutil\n"
                                  "print('initialization import diagnostic')\n"
                                  "def initialize_model(output_dir, options):\n"
                                  "    print('initialization call diagnostic')\n"
                                  f"    {action}\n")
            output, diagnostics = io.StringIO(), io.StringIO()
            with self.subTest(failure=failure), redirect_stdout(output), redirect_stderr(diagnostics):
                status = initialize_main([
                    "--backend", "local", "--endpoint", str(self.store_dir), "--local-principal", "owner",
                    "--repo-id", f"initialized-{failure}", "--plugin", str(plugin),
                    "--plugin-arg", f"checkpoint={json.dumps(str(CHECKPOINT))}",
                ])
            self.assertEqual(status, int(failure), diagnostics.getvalue())
            self.assertNotIn("diagnostic", output.getvalue())
            self.assertIn("initialization import diagnostic\ninitialization call diagnostic\n",
                          diagnostics.getvalue())
            if failure:
                self.assertEqual(output.getvalue(), "")
                self.assertIn("error: initialization failed", diagnostics.getvalue())
            else:
                self.assertIn("initial_main_revision=", output.getvalue())

    def test_manual_client_training_diagnostics_are_separate_from_command_results(self):
        for failure in (False, True):
            action = ("raise RuntimeError('training failed')" if failure else
                      "shutil.copytree(base_dir, output_dir)\n"
                      "    return {'num_examples': 1, 'loss': 0.25}")
            plugin = self._plugin(f"manual-train-{failure}.py", "import shutil\n"
                                  "print('training import diagnostic')\n"
                                  "def train_model(base_dir, output_dir, options):\n"
                                  "    print('training call diagnostic')\n"
                                  f"    {action}\n")
            output, diagnostics = io.StringIO(), io.StringIO()
            with self.subTest(failure=failure), redirect_stdout(output), redirect_stderr(diagnostics):
                status = client_train_main([
                    "--backend", "local", "--endpoint", str(self.store_dir), "--local-principal", "alice",
                    "--repo-id", "repo", "--participant", "alice", "--base-revision", self.base,
                    "--plugin", str(plugin), "--work-dir", str(self.root / f"manual-{failure}"),
                ])
            self.assertEqual(status, int(failure), diagnostics.getvalue())
            self.assertNotIn("diagnostic", output.getvalue())
            self.assertIn("training import diagnostic\ntraining call diagnostic\n", diagnostics.getvalue())
            if failure:
                self.assertEqual(output.getvalue(), "")
                self.assertIn("error: training failed", diagnostics.getvalue())
            else:
                self.assertIn("submission_revision=", output.getvalue())

    def test_library_evaluation_redirects_import_and_call_diagnostics(self):
        self._submissions()
        plugin = self._evaluator()
        output, diagnostics = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(diagnostics):
            result = run_round(self.owner, RoundConfig("repo", self.root / "round", plugin=str(plugin)))
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(diagnostics.getvalue(), "evaluation import diagnostic\nevaluation call diagnostic\n")
        self.assertEqual(result.evaluation, {"accuracy": 0.5, "nested": {"ok": True}})

    def test_library_evaluation_restores_stdout_after_plugin_failure(self):
        self._submissions()
        plugin = self._evaluator(failure=True)
        output, diagnostics = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(diagnostics):
            original = sys.stdout
            with self.assertRaisesRegex(RuntimeError, "evaluation failed"):
                run_round(self.owner, RoundConfig("repo", self.root / "round", plugin=str(plugin)))
            self.assertIs(sys.stdout, original)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(diagnostics.getvalue(), "evaluation import diagnostic\nevaluation call diagnostic\n")

    def test_owner_json_result_remains_parseable_with_noisy_evaluator(self):
        self._submissions()
        plugin = self._evaluator()
        output, diagnostics = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(diagnostics):
            status = owner_main(["--backend", "local", "--endpoint", str(self.store_dir),
                                 "--local-principal", "owner", "--repo-id", "repo", "--discover-submissions",
                                 "--output-dir", str(self.root / "round"), "--plugin", str(plugin), "--json"])
        self.assertEqual(status, 0, diagnostics.getvalue())
        result = json.loads(output.getvalue())
        self.assertEqual(result["evaluation"], {"accuracy": 0.5, "nested": {"ok": True}})
        self.assertEqual(diagnostics.getvalue(), "evaluation import diagnostic\nevaluation call diagnostic\n")

    @unittest.skipUnless(importlib.util.find_spec("torch"), "Built-in training requires Torch")
    def test_builtin_training_progress_uses_stderr(self):
        import torch
        from hf2l.training import train

        dataset = torch.utils.data.TensorDataset(torch.zeros(2, 2), torch.zeros(2, dtype=torch.long))
        output, diagnostics = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(diagnostics):
            metrics = train(torch.nn.Linear(2, 2), dataset, epochs=1, batch_size=2,
                            learning_rate=0.01, seed=1, device=torch.device("cpu"))
        self.assertEqual(output.getvalue(), "")
        self.assertIn("epoch=1/1 loss=", diagnostics.getvalue())
        self.assertTrue(0 <= metrics.accuracy <= 1)


if __name__ == "__main__":
    unittest.main()
