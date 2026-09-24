"""Listener composition, credential-free identity, and optional-dependency isolation."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

from hf2l.backends.factory import STORE_REGISTRY, make_store
from hf2l.cli import listen


class ListenerCLI(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.plugin_path = self.root / "plugin.py"
        self.plugin_path.write_text("def train_model(base_dir, output_dir, options):\n    return {'num_examples': 1}\n")
        self.argv = ["--repo-id", "team/model", "--participant", "client-1", "--state-dir",
                     str(self.root / "state"), "--plugin", str(self.plugin_path)]

    def test_registry_choices_and_defaults(self):
        for backend in STORE_REGISTRY:
            with self.subTest(backend=backend):
                args = listen.parse_args(self.argv + ["--backend", backend])
                self.assertEqual(args.backend, backend)
                self.assertEqual(args.reference, "main")
                self.assertEqual(args.poll_interval, 30)
                self.assertEqual(args.max_backoff, 300)

    def test_invalid_polling_options(self):
        for arguments in (["--poll-interval", "0"], ["--poll-interval", "nan"],
                          ["--poll-interval", "-1"], ["--max-backoff", "inf"],
                          ["--max-backoff", "1"], ["--max-rounds", "0"],
                          ["--max-rounds", "1.5"], ["--resolve-uncertain", "discard"]):
            with self.subTest(arguments=arguments), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    listen.parse_args(self.argv + arguments)
                self.assertEqual(raised.exception.code, 2)

    def test_help_is_lazy_even_without_optional_dependencies(self):
        script = """
import importlib.abc
import sys
class NoProviders(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'torch', 'huggingface_hub', 'hf2l_exchange', 'boto3', 'sqlalchemy'}:
            raise AssertionError('help imported optional dependency: ' + fullname)
sys.meta_path.insert(0, NoProviders())
from hf2l.cli import main
assert main(['listen', '--help']) == 0
assert 'hf2l.listener.client' not in sys.modules
"""
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("{huggingface,jfrog,exchange,local}", result.stdout)
        self.assertIn("--resolve-uncertain", result.stdout)

    def test_module_and_console_entry_points(self):
        from hf2l.cli import _COMMANDS
        self.assertEqual(_COMMANDS["listen"][0], "hf2l.cli.listen")
        metadata = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
        self.assertIn('hf2l-client-listen = "hf2l.cli.listen:main"', metadata)

    def test_source_identity_uses_effective_provider_endpoints_without_credentials(self):
        for backend in ("huggingface", "jfrog", "exchange"):
            with self.subTest(backend=backend):
                client = SimpleNamespace(endpoint="https://user:password@EXAMPLE.test/api/repository/?token=secret#part")
                store = SimpleNamespace(name=backend, api=client, client=client, token="private-token")
                identity = json.loads(listen._source_id(store))
                self.assertEqual(identity, {"backend": backend, "endpoint": "https://example.test/api/repository"})

    def test_environment_configuration_changes_source_identity(self):
        for backend, environment_name in (("huggingface", "HF_ENDPOINT"), ("jfrog", "HF_ENDPOINT"),
                                           ("exchange", "EXCHANGE_ENDPOINT")):
            with self.subTest(backend=backend):
                module = ModuleType("hf2l.backends." + backend)
                def constructor(token, endpoint, **kwargs):
                    client = SimpleNamespace(endpoint=endpoint)
                    return SimpleNamespace(name=backend, api=client, client=client)
                setattr(module, {"huggingface": "HuggingFaceStore", "jfrog": "JFrogStore",
                                 "exchange": "ExchangeStore"}[backend], constructor)
                credentials = {"HF_TOKEN": "secret", "EXCHANGE_TOKEN": "secret", "JFROG_ACCESS_TOKEN": "secret"}
                with patch.dict(sys.modules, {module.__name__: module}), patch.dict(os.environ, credentials):
                    identities = []
                    for endpoint in ("https://first.test/api", "https://second.test/api"):
                        with patch.dict(os.environ, {environment_name: endpoint}):
                            identities.append(listen._source_id(make_store(backend)))
                    self.assertNotEqual(*identities)

    def test_local_source_identity_includes_effective_root_and_principal(self):
        with patch.dict(os.environ, {"HF2L_LOCAL_ROOT": str(self.root / "storage"),
                                     "HF2L_LOCAL_PRINCIPAL": "principal-1"}):
            first = make_store("local")
            second = make_store("local", principal="principal-2")
            try:
                identity = json.loads(listen._source_id(first))
                self.assertEqual(identity["root"], str((self.root / "storage").resolve()))
                self.assertEqual(identity["principal"], "principal-1")
                self.assertNotEqual(listen._source_id(first), listen._source_id(second))
            finally:
                first.close()
                second.close()

    def test_training_identity_binds_content_and_canonical_options(self):
        plugin = SimpleNamespace(__file__=str(self.plugin_path))
        first = listen._training_id(str(self.plugin_path), plugin, {"secret": "private", "epochs": 1})
        same = listen._training_id(str(self.plugin_path), plugin, {"epochs": 1, "secret": "private"})
        changed = listen._training_id(str(self.plugin_path), plugin, {"epochs": 2, "secret": "private"})
        self.assertEqual(first, same)
        self.assertNotEqual(first, changed)
        self.assertEqual(len(first), 64)
        self.assertNotIn("private", first)
        self.plugin_path.write_text(self.plugin_path.read_text() + "# changed implementation\n")
        self.assertNotEqual(first, listen._training_id(str(self.plugin_path), plugin,
                                                      {"secret": "private", "epochs": 1}))

    def _run(self, *, failure=None, extra=()):
        events = []
        module = ModuleType("hf2l.listener.client")
        class ListenerStateError(Exception):
            pass
        class UncertainSubmission(Exception):
            pass
        module.ListenerStateError = ListenerStateError
        module.UncertainSubmission = UncertainSubmission
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
                    raise UncertainSubmission("Check the pending upload before retrying")
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
        module.ClientListener = FakeListener
        store = SimpleNamespace(name="exchange", client=SimpleNamespace(endpoint="https://exchange.test"),
                                close=lambda: events.append(("close",)))
        out, err = io.StringIO(), io.StringIO()
        previous = signal.getsignal(signal.SIGTERM)
        with patch.dict(sys.modules, {module.__name__: module}), patch.object(listen, "make_store", return_value=store), \
                redirect_stdout(out), redirect_stderr(err):
            status = listen.main(self.argv + ["--backend", "exchange", *extra])
        self.assertIs(signal.getsignal(signal.SIGTERM), previous)
        self.assertEqual(events[-1], ("close",))
        self.assertIn(("exit",), events)
        return status, events, out.getvalue(), err.getvalue()

    def test_dispatch_and_operator_reconciliation(self):
        status, events, _, _ = self._run(extra=["--once", "--max-rounds", "2", "--resolve-uncertain", "retry",
                                               "--plugin-arg", "epochs=4"])
        self.assertEqual(status, 0)
        options = events[0][1]
        self.assertEqual(options["options"], {"participant": "client-1", "epochs": 4})
        self.assertEqual(options["repo_id"], "team/model")
        self.assertEqual(options["reference"], "main")
        self.assertTrue(callable(options["train_model"]))
        self.assertLess(events.index(("resolve", "retry")), next(i for i, event in enumerate(events) if event[0] == "run"))
        run = next(event[1] for event in events if event[0] == "run")
        self.assertEqual(run, {"poll_interval": 30, "max_backoff": 300, "once": True, "max_rounds": 2})

    def test_errors_and_signals_close_store_and_restore_handler(self):
        for failure, expected in (("uncertain", 2), ("state", 1), ("provider", 1), ("provider_value", 1),
                                  ("interrupt", 130), ("sigterm", 130)):
            with self.subTest(failure=failure):
                status, _, output, error = self._run(failure=failure)
                self.assertEqual(status, expected)
                self.assertNotIn("secret", error)
                if expected == 130:
                    self.assertEqual(json.loads(output), {"event": "stopped"})

    def test_event_output_omits_arbitrary_provider_data(self):
        output = io.StringIO()
        with redirect_stdout(output):
            listen._print_event({"event": "retry", "error_type": "TimeoutError", "retry_seconds": 30,
                                 "error": "token=secret", "options": {"password": "secret"}})
        self.assertEqual(json.loads(output.getvalue()),
                         {"event": "retry", "error_type": "TimeoutError", "retry_seconds": 30})


if __name__ == "__main__":
    unittest.main()
