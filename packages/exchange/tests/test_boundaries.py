"""Architectural boundaries that remain valid in the full development venv."""
from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
