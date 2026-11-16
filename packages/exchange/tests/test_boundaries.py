"""Architectural boundaries that remain valid in the full development venv."""
from __future__ import annotations

import importlib.metadata
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("exchange_dependency_check", ROOT / "scripts/check_exchange_dependencies.py")
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class DependencyBoundaryTests(unittest.TestCase):
    def test_exchange_has_no_application_or_framework_domain_imports(self):
        self.assertEqual(checker.check_source(ROOT), [])

    def test_sdk_distribution_has_only_transport_dependency(self):
        self.assertEqual(checker._installed_requirements(), ["httpx"])

    def test_distribution_contains_clients_without_python_server_or_command(self):
        for name in ("api", "application", "auth", "cli", "config", "contracts",
                     "gateway_api", "managed_transfers", "migrations", "models",
                     "profiles", "schemas", "storage", "transfers", "worker"):
            with self.subTest(module=name):
                self.assertIsNone(importlib.util.find_spec("hf2l_exchange." + name))
        distribution = importlib.metadata.distribution("hf2l-exchange")
        self.assertNotIn("hf2l-exchange", [entry.name for entry in distribution.entry_points])
        self.assertNotIn("server", distribution.metadata.get_all("Provides-Extra", []))


if __name__ == "__main__":
    unittest.main()
