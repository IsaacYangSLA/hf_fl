"""Role-aware listener composition, recovery controls, and credential isolation."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

from hf2l.backends.factory import STORE_REGISTRY
from hf2l.cli import listen
from hf2l.listener.engine import ListenerStateError, UncertainOperation


class OwnerListenerCLI(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.argv = ["--role", "owner", "--repo-id", "team/model", "--state-dir", str(self.root / "owner")]

    def test_role_specific_arguments_and_defaults(self):
        for backend in STORE_REGISTRY:
            with self.subTest(backend=backend):
                args = listen.parse_args(self.argv + ["--backend", backend])
                self.assertEqual(args.role, "owner")
                self.assertIsNone(args.participant)
                self.assertIsNone(args.plugin)
                self.assertEqual(args.minimum_participants, 2)
                self.assertEqual(args.weighting, "examples")
                self.assertEqual(args.array_backend, "numpy")
                self.assertEqual(args.claim_lease_seconds, 3600)

    def test_invalid_role_combinations_are_rejected_before_effects(self):
        invalid = (
            self.argv + ["--participant", "client-1"],
            self.argv + ["--reference", "release"],
            self.argv + ["--resolve-uncertain", "submitted"],
            self.argv + ["--minimum-participants", "1"],
            self.argv + ["--claim-lease-seconds", "9"],
            self.argv + ["--claim-lease-seconds", "3601"],
            self.argv + ["--plugin-arg", "secret=hidden"],
            ["--repo-id", "team/model", "--state-dir", str(self.root / "client")],
            ["--repo-id", "team/model", "--participant", "client-1", "--plugin", "lenet",
             "--state-dir", str(self.root / "client"), "--resolve-uncertain", "published"],
        )
        for argv in invalid:
            with self.subTest(argv=argv), patch.object(listen, "make_store") as factory, \
                    redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    listen.main(argv)
                self.assertEqual(raised.exception.code, 2)
                factory.assert_not_called()

    def test_owner_help_does_not_import_listener_or_optional_providers(self):
        script = """
import importlib.abc
import sys
class NoProviders(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'torch', 'huggingface_hub', 'hf2l_exchange', 'boto3', 'sqlalchemy'}:
            raise AssertionError('help imported optional dependency: ' + fullname)
sys.meta_path.insert(0, NoProviders())
from hf2l.cli import main
assert main(['listen', '--role', 'owner', '--help']) == 0
assert 'hf2l.listener.owner' not in sys.modules
assert 'hf2l.listener.client' not in sys.modules
"""
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--minimum-participants", result.stdout)
        self.assertIn("--role {client,owner}", result.stdout)

    def _run(self, *, backend="exchange", failure=None, extra=()):
        events = []
        module = ModuleType("hf2l.listener.owner")

        class FakeListener:
            def __init__(self, **kwargs):
                events.append(("constructor", kwargs))

            def __enter__(self):
                events.append(("enter",))
                return self

            def __exit__(self, *args):
                events.append(("exit",))

            def resolve_uncertain(self, action):
                events.append(("resolve", action))

            def run(self, **kwargs):
                events.append(("run", kwargs))
                if failure == "uncertain":
                    raise UncertainOperation("Check the backend before retrying publication")
                if failure == "state":
                    raise ListenerStateError("State binding differs")
                if failure == "interrupt":
                    raise KeyboardInterrupt
                if failure == "sigterm":
                    signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
                if failure == "provider":
                    raise RuntimeError("signed-URL?token=secret")
                if failure == "provider_value":
                    raise ValueError("signed-URL?token=secret")
                return 1

        module.OwnerListener = FakeListener
        connection = SimpleNamespace(endpoint="https://user:password@EXAMPLE.test/api/?token=secret")
        store = SimpleNamespace(name=backend, api=connection, client=connection, root=self.root / "storage",
                                principal="owner", close=lambda: events.append(("close",)))
        output, error = io.StringIO(), io.StringIO()
        previous = signal.getsignal(signal.SIGTERM)
        with patch.dict(sys.modules, {module.__name__: module}), \
                patch.object(listen, "make_store", return_value=store), \
                redirect_stdout(output), redirect_stderr(error):
            status = listen.main(self.argv + ["--backend", backend, *extra])
        self.assertIs(signal.getsignal(signal.SIGTERM), previous)
        self.assertEqual(events[-1], ("close",))
        self.assertIn(("exit",), events)
        return status, events, output.getvalue(), error.getvalue()

    def test_owner_dispatch_uses_shared_run_controls_for_every_backend(self):
        for backend in STORE_REGISTRY:
            with self.subTest(backend=backend):
                status, events, _, error = self._run(
                    backend=backend, extra=["--once", "--max-rounds", "3", "--poll-interval", "2",
                                            "--max-backoff", "20", "--resolve-uncertain", "published"])
                self.assertEqual(status, 0, error)
                options = events[0][1]
                config = options["config"]
                config.validate()
                self.assertEqual(config.repo_id, "team/model")
                self.assertEqual(config.selection, "discover")  # Controller chooses claims from capabilities.
                self.assertTrue(config.publish)
                self.assertIsNone(config.expected_base_revision)
                self.assertIsNone(config.run_state)
                self.assertIsNone(config.tag)
                self.assertIsNone(config.claim_id)
                self.assertEqual(options["configuration_id"], "fedavg")
                self.assertNotIn("participant", options)
                self.assertNotIn("password", options["source_id"])
                self.assertNotIn("secret", options["source_id"])
                run_index = next(i for i, event in enumerate(events) if event[0] == "run")
                self.assertLess(events.index(("resolve", "published")), run_index)
                self.assertEqual(events[run_index][1],
                                 {"poll_interval": 2, "max_backoff": 20, "once": True, "max_rounds": 3})

    def test_owner_configuration_and_evaluation_identity_are_forwarded(self):
        plugin = self.root / "evaluate.py"
        plugin.write_text("def evaluate_model(model_dir, options):\n    return {}\n")
        allowlist = self.root / "allowlist.json"
        allowlist.write_text('{"identity-1": "client-1"}')
        extra = ["--minimum-participants", "4", "--weighting", "uniform", "--allowlist", str(allowlist),
                 "--array-backend", "torch", "--accumulator-dtype", "float64", "--claim-lease-seconds", "60",
                 "--require-concurrent-publication", "--plugin", str(plugin), "--plugin-arg", "secret=private"]
        status, events, _, error = self._run(extra=extra)
        self.assertEqual(status, 0, error)
        options = events[0][1]
        config = options["config"]
        self.assertEqual(config.minimum_participants, 4)
        self.assertEqual(config.weighting, "uniform")
        self.assertEqual(config.allowlist, allowlist)
        self.assertEqual(config.array_backend, "torch")
        self.assertEqual(config.accumulator_dtype, "float64")
        self.assertEqual(config.claim_lease_seconds, 60)
        self.assertTrue(config.require_concurrent_publication)
        self.assertEqual(config.plugin, str(plugin))
        self.assertEqual(config.plugin_arg, ("secret=private",))
        fingerprint = options["configuration_id"]
        self.assertEqual(len(fingerprint), 64)
        self.assertNotIn("private", fingerprint)
        plugin.write_text(plugin.read_text() + "# updated evaluator\n")
        status, events, _, _ = self._run(extra=extra)
        self.assertEqual(status, 0)
        self.assertNotEqual(fingerprint, events[0][1]["configuration_id"])

    def test_owner_requires_evaluation_contract_before_creating_store(self):
        plugin = self.root / "train_only.py"
        plugin.write_text("def train_model(base_dir, output_dir, options):\n    return {}\n")
        module = ModuleType("hf2l.listener.owner")
        module.OwnerListener = object
        with patch.dict(sys.modules, {module.__name__: module}), patch.object(listen, "make_store") as factory, \
                redirect_stderr(io.StringIO()) as error:
            status = listen.main(self.argv + ["--plugin", str(plugin)])
        self.assertEqual(status, 1)
        factory.assert_not_called()
        self.assertNotIn(str(plugin), error.getvalue())

    def test_owner_errors_close_store_and_restore_signal_handler(self):
        for failure, expected in (("uncertain", 2), ("state", 1), ("provider", 1), ("provider_value", 1),
                                  ("interrupt", 130), ("sigterm", 130)):
            with self.subTest(failure=failure):
                status, _, output, error = self._run(failure=failure)
                self.assertEqual(status, expected)
                self.assertNotIn("secret", error)
                if expected == 130:
                    self.assertEqual(json.loads(output), {"event": "stopped"})

    def test_readiness_event_reports_counts_without_provider_secrets(self):
        output = io.StringIO()
        with redirect_stdout(output):
            listen._print_event({"event": "not_ready", "eligible_count": 1, "minimum_participants": 2,
                                 "token": "secret", "error": "signed-URL?token=secret"})
        self.assertEqual(json.loads(output.getvalue()),
                         {"event": "not_ready", "eligible_count": 1, "minimum_participants": 2})


if __name__ == "__main__":
    unittest.main()
