"""V3 evidence gates: preserved golden oracles and executable behavior inventory."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ArchitectureEvidenceTests(unittest.TestCase):
    def test_frozen_golden_files_match_committed_hashes(self):
        """Changing an oracle must not silently make a numeric regression pass."""
        fixtures = sorted((ROOT / "tests/goldens").glob("*/meta.json"))
        self.assertTrue(fixtures, "WP0 golden fixtures must be retained")
        for metadata_path in fixtures:
            metadata = json.loads(metadata_path.read_text())
            for relative, expected in metadata["file_sha256"].items():
                with self.subTest(fixture=metadata_path.parent.name, path=relative):
                    actual = hashlib.sha256((metadata_path.parent / relative).read_bytes()).hexdigest()
                    self.assertEqual(expected, actual)

    def test_inventory_has_explicit_evidence_for_every_frozen_behavior(self):
        inventory = (ROOT / "tests/support/scenarios.md").read_text()
        rows = [line for line in inventory.splitlines() if re.match(r"\| S-\d{3} \|", line)]
        self.assertEqual([f"S-{i:03d}" for i in range(1, 251)], [line.split("|")[1].strip() for line in rows])
        for row in rows:
            identifier = row.split("|")[1].strip()
            coverage = row.split("|")[-2].strip()
            with self.subTest(scenario=identifier):
                self.assertTrue(coverage, "unmapped behavior")
                self.assertIn("legacy:", coverage)
                self.assertRegex(coverage, r"`tests/[\w/]+\.py::\w+`")
        superseded = next(row for row in rows if "| S-050 |" in row)
        self.assertIn("superseded for automatic v2 selection", superseded)
        self.assertIn("test_full_fenced_round_verifies_files_and_publishes_weighted_result", superseded)

    def test_all_inventory_test_and_helper_references_exist(self):
        inventory = (ROOT / "tests/support/scenarios.md").read_text()
        references = set(re.findall(r"`((?:packages/exchange/)?tests/[\w/]+\.py)::(\w+)`", inventory))
        self.assertTrue(references)
        functions = {}
        for relative, method in sorted(references):
            with self.subTest(path=relative, function=method):
                path = ROOT / relative
                self.assertTrue(path.is_file(), f"Missing evidence file: {relative}")
                if relative not in functions:
                    tree = ast.parse(path.read_text(), filename=relative)
                    functions[relative] = {node.name for node in ast.walk(tree)
                                           if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
                self.assertIn(method, functions[relative], "Evidence points to a missing test/helper")


if __name__ == "__main__":
    unittest.main()
