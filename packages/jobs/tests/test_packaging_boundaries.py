"""Architecture gates and installed-package resources for the manager."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("jobs_dependency_gate", ROOT / "scripts/check_jobs_dependencies.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class PackagingBoundaryTests(unittest.TestCase):
    def test_manager_sources_do_not_import_training_code(self):
        self.assertEqual([], GATE.check_source(ROOT))

    def test_manager_distribution_has_no_training_dependencies(self):
        self.assertEqual([], GATE.check_metadata())

    def test_manager_metadata_requires_the_current_python_minimum(self):
        distribution = SimpleNamespace(
            requires=[],
            entry_points=[SimpleNamespace(
                group="console_scripts", name="hf2l-jobs", value="hf2l_jobs.cli:main",
            )],
            metadata={"Requires-Python": ">=3.11"},
        )
        with patch.object(GATE.importlib.metadata, "distribution", return_value=distribution):
            self.assertEqual([], GATE.check_metadata())
            for value in ("", ">=3.10", ">=3.110", ">=3.11,>=3.10", "==3.11"):
                with self.subTest(python_requires=value):
                    distribution.metadata["Requires-Python"] = value
                    self.assertEqual(
                        [f"Expected Python >=3.11 metadata, got {value!r}"],
                        GATE.check_metadata(),
                    )
            distribution.metadata.clear()
            self.assertEqual(
                ["Expected Python >=3.11 metadata, got ''"], GATE.check_metadata(),
            )

    def test_dashboard_assets_are_packaged(self):
        self.assertEqual([], GATE.check_assets())

    def test_gate_rejects_training_imports_even_inside_manager_functions(self):
        for source in ("import torch\n", "def load():\n    from hf2l.plugin_loader import load_plugin\n",
                       "def load():\n    import numpy\n", "import importlib\nimportlib.import_module('hf2l.plugins')\n"):
            with self.subTest(source=source):
                self.assertTrue(GATE.source_problems(Path("application.py"), source))

    def test_runtime_training_imports_must_be_lazy(self):
        self.assertTrue(GATE.source_problems(Path("runtime.py"), "from hf2l.plugin_loader import load_plugin\n"))
        self.assertEqual([], GATE.source_problems(Path("runtime.py"), "def run():\n    import hf2l\n    import torch\n"))

    def test_runtime_helpers_do_not_expand_import_allowance(self):
        self.assertTrue(GATE.source_problems(Path("runtime_helper.py"), "def run():\n    import hf2l\n"))

    def test_manager_cannot_eagerly_import_the_runtime(self):
        self.assertTrue(GATE.source_problems(Path("application.py"), "from .runtime import run\n"))
        self.assertEqual([], GATE.source_problems(Path("cli.py"), "def run():\n    from .runtime import main\n"))

    def test_domain_cannot_import_http_database_or_exchange_server(self):
        for module in ("sqlalchemy", "fastapi", "uvicorn", "hf2l_exchange"):
            with self.subTest(module=module):
                self.assertTrue(GATE.source_problems(Path("domain.py"), f"import {module}\n"))

    def test_control_plane_cannot_load_a_user_selected_plugin(self):
        for source in ("import importlib\ndef load(name):\n    return importlib.import_module(name)",
                       "def load(name):\n    return __import__(name)",
                       "def load(source):\n    return exec(source)",
                       "def load(source):\n    return eval(source)"):
            with self.subTest(source=source):
                self.assertTrue(GATE.source_problems(Path("application.py"), source))

    def test_runtime_dynamic_plugin_loading_is_delayed_until_execution(self):
        self.assertTrue(GATE.source_problems(Path("runtime.py"), "import importlib\nimportlib.import_module(plugin)"))
        self.assertEqual([], GATE.source_problems(Path("runtime.py"), "import importlib\ndef run(plugin):\n    return importlib.import_module(plugin)"))

    def test_generic_exchange_cannot_depend_on_job_management(self):
        for text in ("import hf2l_jobs", "def handle():\n    from hf2l_jobs.application import Manager"):
            with self.subTest(source=text):
                self.assertTrue(GATE.generic_service_problems(Path("application.py"), text))
        self.assertEqual([], GATE.generic_service_problems(Path("api.py"), "from .application import Service"))

    def test_domain_cannot_import_its_own_infrastructure(self):
        self.assertTrue(GATE.source_problems(Path("domain.py"), "from .database import Database"))

    def test_import_aliases_cannot_hide_control_plane_plugin_loading(self):
        for source in ("from importlib import import_module as resolve\ndef load(plugin):\n    return resolve(plugin)",
                       "from builtins import __import__ as load\ndef resolve(plugin):\n    return load(plugin)"):
            with self.subTest(source=source):
                self.assertTrue(GATE.source_problems(Path("application.py"), source))

    def test_callable_assignments_cannot_hide_dynamic_code_loading(self):
        for source in (
            "import importlib\nload = importlib.import_module\ndef run(plugin):\n    return load(plugin)",
            "import importlib\nload = importlib.import_module\nresolve = load\ndef run(plugin):\n    return resolve(plugin)",
            "import importlib\nload: object = importlib.import_module\ndef run(plugin):\n    return load(plugin)",
            "import importlib\nload, other = importlib.import_module, None\ndef run(plugin):\n    return load(plugin)",
            "def run(plugin):\n    if (load := __import__):\n        return load(plugin)",
            "evaluate = eval\ndef run(source):\n    return evaluate(source)",
        ):
            with self.subTest(source=source):
                self.assertTrue(GATE.source_problems(Path("application.py"), source))
        self.assertEqual([], GATE.source_problems(
            Path("runtime.py"),
            "import importlib\nload = importlib.import_module\ndef run(plugin):\n    return load(plugin)",
        ))

    def test_absolute_from_import_cannot_eagerly_load_runtime(self):
        self.assertTrue(GATE.source_problems(Path("application.py"), "from hf2l_jobs import runtime"))
        self.assertEqual([], GATE.source_problems(Path("cli.py"), "def main():\n    from hf2l_jobs import runtime"))

    def test_function_annotations_cannot_hide_eager_training_imports(self):
        for source in ("import importlib\ndef run(value: importlib.import_module('torch')):\n    pass",
                       "def run() -> __import__('torch'):\n    pass",
                       "def run(*values: __import__('torch'), **options: __import__('torch')):\n    pass"):
            with self.subTest(source=source):
                self.assertTrue(GATE.source_problems(Path("runtime.py"), source))

    def test_function_defaults_cannot_hide_eager_training_imports(self):
        text = "import importlib\ndef run(module=importlib.import_module('torch')):\n    pass\n"
        self.assertTrue(GATE.source_problems(Path("runtime.py"), text))


if __name__ == "__main__":
    unittest.main()
