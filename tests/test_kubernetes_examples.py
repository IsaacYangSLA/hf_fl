"""Rendered organization listeners must be accepted by the real command parser."""

from __future__ import annotations

import argparse
import importlib.util
import io
import json
import os
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from hf2l.cli import listen
from hf2l.backends.local import LocalStore
from hf2l.listener.client import ClientListener
from hf2l.plugin_loader import load_local_plugin


ROOT = Path(__file__).resolve().parents[1]


class _Parsed(BaseException):
    """Stop after real argument parsing, before connection or training side effects."""

    def __init__(self, namespace):
        self.namespace = namespace


class KubernetesExampleCommandsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        name = "hf2l_kubernetes_example_configure_tests"
        spec = importlib.util.spec_from_file_location(name, ROOT / "examples/kubernetes/configure.py")
        if spec is None or spec.loader is None:
            raise AssertionError("Kubernetes example renderer cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        cls.addClassCleanup(sys.modules.pop, name, None)
        spec.loader.exec_module(module)
        cls.configure = module

    def parse_rendered_listener(self, role):
        resources = self.configure.manifests(
            role, "example:test", "example-space", "https://exchange.example.test",
        )
        container = resources["listener.json"]["spec"]["template"]["spec"]["containers"][0]
        command = container.get("command", []) + container.get("args", [])
        self.assertEqual(command[:2], ["hf2l", "listen"])
        original_parse = argparse.ArgumentParser.parse_args

        def parse_and_stop(parser, args=None, namespace=None):
            parsed = original_parse(parser, args, namespace)
            raise _Parsed(parsed)

        with patch.object(argparse.ArgumentParser, "parse_args", parse_and_stop):
            with self.assertRaises(_Parsed) as captured:
                listen.main(command[2:])
        namespace = captured.exception.namespace
        self.assertEqual(namespace.backend, "exchange")
        self.assertEqual(namespace.repo_id, "example-space")
        return namespace

    def test_alice_listener_uses_supported_client_arguments(self):
        parsed = self.parse_rendered_listener("alice")
        self.assertEqual(parsed.role, "client")
        self.assertEqual(parsed.participant, "alice")

    def test_bob_listener_uses_supported_client_arguments(self):
        parsed = self.parse_rendered_listener("bob")
        self.assertEqual(parsed.role, "client")
        self.assertEqual(parsed.participant, "bob")

    def test_owner_listener_uses_supported_aggregation_arguments(self):
        parsed = self.parse_rendered_listener("owner")
        self.assertEqual(parsed.role, "owner")
        self.assertEqual(parsed.array_backend, "numpy")


class KubernetesInitializationWorkflowTests(unittest.TestCase):
    """Check protocol compatibility locally; cluster acceptance checks separate actors."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.initialization = self.root / "initialization"
        self.repository_root = self.root / "repositories"
        self.trainer = load_local_plugin(ROOT / "examples/kubernetes/trainer.py")
        with patch.dict(sys.modules, {"trainer": self.trainer}):
            self.initializer = load_local_plugin(ROOT / "examples/kubernetes/initialize.py")

    def test_real_initializer_publishes_a_round_the_real_client_can_train_and_submit(self):
        dataset = self.root / "private-data.npz"
        self.trainer._model.generate_data(dataset, examples=8, seed=7)
        token = self.root / "owner-token"
        token.write_text("local-protocol-fixture")
        publisher = LocalStore(self.repository_root, "alice")
        self.addCleanup(publisher.close)
        environment = {
            "EXCHANGE_TOKEN_FILE": str(token),
            "EXCHANGE_TOKEN": "",
            "EXCHANGE_ENDPOINT": "https://exchange.example.test",
            "HF2L_SPACE_ID": "example-space",
        }
        with patch.dict(os.environ, environment), \
                patch.object(self.initializer, "_STATE_DIR", self.initialization), \
                patch.object(self.initializer, "make_store", return_value=publisher), \
                redirect_stdout(io.StringIO()):
            self.initializer.main()
        client_store = LocalStore(self.repository_root, "alice")
        self.addCleanup(client_store.close)
        base = client_store.resolve_reference("example-space").revision
        receipt = json.loads((self.initialization / "published.json").read_text())
        self.assertEqual(receipt["revision"], base)
        trained = []

        def train(base_dir, output_dir, options):
            metadata = self.trainer.train_model(base_dir, output_dir, options)
            trained.append(metadata)
            return metadata

        with ClientListener(
            client_store,
            repo_id="example-space",
            participant="alice",
            state_dir=self.root / "listener-state",
            source_id="cpu-source",
            training_id="cpu-training",
            train_model=train,
            options={"dataset": str(dataset)},
        ) as listener:
            self.assertEqual(listener.poll_once(), "submitted")
            self.assertEqual(listener.poll_once(), "idle")
            self.assertEqual(client_store.resolve_reference("example-space").revision, base)
        self.assertEqual(len(trained), 1)
        self.assertEqual(trained[0]["num_examples"], 8)


if __name__ == "__main__":
    unittest.main()
