"""Preserved numeric fixtures and source-checked current scenario references."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
CURRENT_INVENTORY = ROOT / "tests/support/scenarios.md"
HISTORICAL_INVENTORY = ROOT / "tests/support/history/scenarios-wp0.md"


class ArchitectureEvidenceTests(unittest.TestCase):
    def test_frozen_golden_files_match_committed_hashes(self):
        """Changing a numeric reference must not silently hide a regression."""
        fixtures = sorted((ROOT / "tests/goldens").glob("*/meta.json"))
        self.assertTrue(fixtures, "Frozen numerical fixtures must be retained")
        for metadata_path in fixtures:
            metadata = json.loads(metadata_path.read_text())
            for relative, expected in metadata["file_sha256"].items():
                with self.subTest(fixture=metadata_path.parent.name, path=relative):
                    actual = hashlib.sha256((metadata_path.parent / relative).read_bytes()).hexdigest()
                    self.assertEqual(expected, actual)

    def test_inventory_separates_current_checks_from_removed_server_history(self):
        inventory = CURRENT_INVENTORY.read_text()
        rows = [line for line in inventory.splitlines() if re.match(r"\| C-\d{3} \|", line)]
        self.assertGreaterEqual(len(rows), 22)
        self.assertEqual(
            [f"C-{i:03d}" for i in range(1, len(rows) + 1)],
            [line.split("|")[1].strip() for line in rows],
        )
        for row in rows:
            with self.subTest(scenario=row.split("|")[1].strip()):
                self.assertRegex(row.split("|")[-2], r"`[\w/.-]+\.(?:py|go)::\w+`")
        self.assertIn(".go::", inventory)
        self.assertIn(".py::", inventory)
        self.assertNotIn("legacy:", inventory)
        historical = HISTORICAL_INVENTORY.read_text()
        archived_rows = [line for line in historical.splitlines() if re.match(r"\| S-\d{3} \|", line)]
        self.assertEqual(
            [f"S-{i:03d}" for i in range(1, 251)],
            [line.split("|")[1].strip() for line in archived_rows],
        )
        self.assertIn("not current executable coverage", historical)

    def test_all_current_inventory_test_references_exist(self):
        references = set(re.findall(r"`([\w/.-]+\.(?:py|go))::(\w+)`", CURRENT_INVENTORY.read_text()))
        self.assertTrue(references)
        functions = {}
        for relative, method in sorted(references):
            with self.subTest(path=relative, function=method):
                path = ROOT / relative
                self.assertTrue(path.is_file(), f"Missing evidence file: {relative}")
                if relative not in functions:
                    source = path.read_text()
                    if path.suffix == ".py":
                        self.assertTrue(path.name.startswith("test_"))
                        tree = ast.parse(source, filename=relative)
                        functions[relative] = {node.name for node in ast.walk(tree)
                                               if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
                    else:
                        self.assertTrue(path.name.endswith("_test.go"))
                        functions[relative] = set(re.findall(r"^func (Test\w+)\(", source, re.MULTILINE))
                self.assertIn(method, functions[relative], "Evidence points to a missing test")


if __name__ == "__main__":
    unittest.main()
