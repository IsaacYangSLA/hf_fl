"""Regression checks for the guest namespace traversal qualification probe."""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import posixpath
import tempfile
from types import SimpleNamespace
import unittest

SCRIPT = Path(__file__).resolve().parents[3] / "deploy/jobs/runtime/qualify.py"
SPEC = importlib.util.spec_from_file_location("hf2l_runtime_traversal_qualification", SCRIPT)
QUALIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALIFY)


class SourceTraversalQualificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="runtime-traversal-")
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.guest = base / "guest"
        (self.guest / "root").mkdir(parents=True)
        (self.guest / "job" / "source").mkdir(parents=True)
        host = base / "operator-private" / "random-qualification"
        host.mkdir(parents=True)
        self.host_secret = host / "host-only-secret"
        self.host_secret.write_bytes(b"synthetic host-only canary")
        self.observed = []

    def _run_actual_probe_fragment(self, host_secret=None):
        tree = ast.parse(QUALIFY.PROBE)
        helper = next(node for node in tree.body
                      if isinstance(node, ast.FunctionDef)
                      and node.name == "source_traversal_path")
        loops = []
        for node in tree.body:
            if not isinstance(node, ast.For) or not isinstance(node.iter, ast.List):
                continue
            if any(isinstance(item, ast.Tuple) and item.elts
                   and isinstance(item.elts[0], ast.Constant)
                   and item.elts[0].value == "source_traversal"
                   for item in node.iter.elts):
                loops.append(node)
        self.assertEqual(len(loops), 1, "one actual guest traversal/proxy probe")
        fragment = ast.Module(body=[helper, loops[0]], type_ignores=[])
        rows = []

        def exists(path):
            self.observed.append(path)
            # The guest resolves '..' within its filesystem namespace.
            normalized = posixpath.normpath(path)
            return (self.guest / normalized.lstrip("/")).exists()

        scope = {
            "os": SimpleNamespace(path=SimpleNamespace(exists=exists)),
            "host_secret": str(self.host_secret) if host_secret is None else host_secret,
            "foreign_socket": "/unmounted/foreign-proxy.sock",
            "add": lambda name, passed, **detail: rows.append(
                dict(name=name, passed=bool(passed), **detail)),
        }
        exec(compile(fragment, "<actual-guest-traversal-probe>", "exec"), scope)
        return next(row for row in rows if row["name"] == "source_traversal")

    def test_benign_container_root_is_not_a_host_escape(self):
        self.assertTrue((self.guest / "root").exists())
        self.assertTrue(self.host_secret.exists())
        row = self._run_actual_probe_fragment()
        self.assertTrue(row["passed"], row)
        self.assertNotEqual(posixpath.normpath(row["path"]), "/root")

    def test_exposed_host_canary_fails_the_actual_guest_probe(self):
        exposed = self.guest / str(self.host_secret).lstrip("/")
        exposed.parent.mkdir(parents=True)
        exposed.write_bytes(self.host_secret.read_bytes())
        row = self._run_actual_probe_fragment()
        self.assertFalse(row["passed"], row)

    def test_traversal_targets_the_unique_host_only_path(self):
        row = self._run_actual_probe_fragment()
        self.assertEqual(posixpath.normpath(row["path"]), str(self.host_secret))
        self.assertTrue(row["path"].startswith("/job/source/../../"))
        self.assertIn(row["path"], self.observed)
        self.assertNotIn("/job/source/../../root", self.observed)

    def test_noncanonical_or_nonabsolute_canaries_are_rejected(self):
        for path in ("relative", "/", "//host/file", "/host/../file",
                     "/host/./file", "/host//file", "/host/secret\x00tail"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self._run_actual_probe_fragment(path)


if __name__ == "__main__":
    unittest.main()
