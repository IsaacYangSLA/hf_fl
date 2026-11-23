"""Python distribution contains execution adapters and no manager server."""
from __future__ import annotations

import ast
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "src" / "hf2l_jobs"
REMOVED = ("api", "application", "auth", "authorization", "broker", "cli", "collection",
           "composition", "config", "controller", "database", "execution_proxy", "executor",
           "gateway", "managed_nodes", "migrations", "models", "node_agent", "oidc",
           "participants", "provisioning", "remote_node", "resources", "retention", "scheduler")


class PackagingBoundaryTests(unittest.TestCase):
    def test_removed_server_modules_are_not_installable(self):
        for name in REMOVED:
            with self.subTest(module=name):
                self.assertIsNone(importlib.util.find_spec("hf2l_jobs." + name))
                self.assertFalse((SOURCE / (name + ".py")).exists())

    def test_python_console_command_is_adapter_only(self):
        distribution = importlib.metadata.distribution("hf2l-jobs")
        commands = {point.name: point.value for point in distribution.entry_points
                    if point.group == "console_scripts"}
        self.assertEqual(commands, {"hf2l-jobs-runtime": "hf2l_jobs.runtime:main"})
        self.assertEqual(sorted(distribution.metadata["Requires-Python"].split(",")), ["<3.16", ">=3.14"])

    def test_required_dependencies_do_not_install_server_or_training_frameworks(self):
        from packaging.requirements import Requirement
        distribution = importlib.metadata.distribution("hf2l-jobs")
        required = [Requirement(value) for value in distribution.requires or ()]
        names = {item.name.lower() for item in required if item.marker is None}
        self.assertEqual(names, {"pydantic"})

    def test_importing_adapters_does_not_load_training_or_server_packages(self):
        script = """
import json, sys
import hf2l_jobs.runtime, hf2l_jobs.build, hf2l_jobs.workflow
for name in ('hf2l', 'torch', 'numpy', 'fastapi', 'uvicorn', 'sqlalchemy', 'hf2l_exchange'):
    assert name not in sys.modules, name
print(json.dumps({'adapters_only': True}))
"""
        result = subprocess.run([sys.executable, "-c", script], check=True,
                                capture_output=True, text=True)
        self.assertEqual(json.loads(result.stdout), {"adapters_only": True})

    def test_contracts_and_build_adapter_have_no_control_plane_imports(self):
        for name in ("domain.py", "workflow.py", "build.py"):
            tree = ast.parse((SOURCE / name).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    modules = [item.name for item in node.names]
                elif isinstance(node, ast.ImportFrom):
                    modules = [node.module or ""]
                else:
                    continue
                for module in modules:
                    with self.subTest(file=name, module=module):
                        self.assertNotIn(module.split(".")[0], {"fastapi", "sqlalchemy", "uvicorn"})
                        if isinstance(node, ast.ImportFrom) and node.level:
                            self.assertNotIn(module.split(".")[0], REMOVED)


if __name__ == "__main__":
    unittest.main()
