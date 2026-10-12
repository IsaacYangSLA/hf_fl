"""Round eligibility rejects bad client payloads without losing a valid quorum."""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import numpy as np
from safetensors.numpy import load_file, save_file

from hf2l.core.protocol import AlgorithmSpec, ROUND_FILE, SUBMISSION_FILE
from hf2l.fedavg_runner import run_round
from hf2l.hub_helpers import read_json, write_json
from hf2l.round.aggregator import FedAvg
from hf2l.round.config import RoundConfig
from tests.test_round_v3 import FixtureStore


class RunnerHardeningTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def store(self, name="store"):
        directory = self.root / name
        directory.mkdir()
        return FixtureStore(directory)

    def config(self, store, **options):
        return RoundConfig("test/repo", store.root / "output", **options)

    def clients(self, store, **metadata):
        store.add("alice", 1, 1, **metadata)
        store.add("bob", 3, 3, **metadata)

    def update_record(self, path, **fields):
        record = read_json(path)
        record.update(fields)
        write_json(path, record)

    def test_automatic_nonfinite_clients_are_skipped_before_weighting(self):
        for selection in ("discover", "claim"):
            for index, value in enumerate((float("nan"), float("inf"), -float("inf"))):
                with self.subTest(selection=selection, value=value):
                    store = self.store(f"{selection}-{index}")
                    self.clients(store)
                    store.add("bad", value, 100)
                    if selection == "claim":
                        store.capabilities = replace(store.capabilities, fenced_coordination=True,
                                                     requires_coordination_for_publication=True)
                    result = run_round(store, self.config(store, selection=selection, publish=True))
                    self.assertEqual("published", result.status)
                    self.assertEqual(["bad"], [item.candidate for item in result.skipped])
                    self.assertIn("NaN or infinity", result.skipped[0].reason)
                    self.assertEqual(["alice", "bob"], [item["participant"] for item in result.eligible])
                    self.assertEqual([0.25, 0.75], [item["coefficient"] for item in result.eligible])
                    np.testing.assert_array_equal(load_file(result.aggregate_dir / "model.safetensors")["weight"], [2.5])
                    self.assertEqual(1, len(store.publications))

    def test_explicit_nonfinite_client_fails_without_publication(self):
        store = self.store()
        self.clients(store)
        store.add("bad", float("nan"), 100)
        with self.assertRaisesRegex(ValueError, "Input tensor contains NaN or infinity"):
            run_round(store, self.config(store, selection="explicit", submissions=("alice", "bob", "bad"),
                                         publish=True))
        self.assertEqual([], store.publications)

    def test_invalid_base_is_fatal_even_with_valid_clients(self):
        store = self.store()
        self.clients(store)
        save_file({"weight": np.asarray([float("nan")], dtype=np.float32)},
                  store.root / "base" / "model.safetensors")
        self.update_record(store.root / "base" / ROUND_FILE,
                           checkpoint_files_sha256=store._hashes("base"))
        with self.assertRaisesRegex(ValueError, "Input tensor contains NaN or infinity"):
            run_round(store, self.config(store, publish=True))
        self.assertEqual([], store.publications)

    def test_skipping_nonfinite_client_cannot_weaken_quorum(self):
        store = self.store()
        store.add("alice", 1, 1)
        store.add("bad", float("inf"), 1)
        with self.assertRaisesRegex(ValueError, "at least two valid client checkpoints; found 1"):
            run_round(store, self.config(store, publish=True))
        self.assertEqual([], store.publications)

    def test_float64_validation_keeps_implicit_accumulator_promotion(self):
        store = self.store()
        self.clients(store)
        for revision in ("base", "alice", "bob"):
            save_file({"weight": np.asarray([1e200], dtype=np.float64)},
                      store.root / revision / "model.safetensors")
            filename = ROUND_FILE if revision == "base" else SUBMISSION_FILE
            self.update_record(store.root / revision / filename,
                               checkpoint_files_sha256=store._hashes(revision))
        result = run_round(store, self.config(store, accumulator_dtype="float32"))
        self.assertEqual("aggregated", result.status)
        actual = load_file(result.aggregate_dir / "model.safetensors")["weight"]
        np.testing.assert_array_equal(actual, np.asarray([1e200], dtype=np.float64))

    def test_legacy_base_with_supplied_bad_hashes_fails(self):
        store = self.store()
        self.clients(store)
        self.update_record(store.root / "base" / ROUND_FILE, schema_version=1,
                           checkpoint_files_sha256={name: "0" * 64 for name in store._hashes("base")})
        with self.assertRaisesRegex(ValueError, "Checkpoint checksum mismatch in main"):
            run_round(store, self.config(store, publish=True))
        self.assertEqual([], store.publications)

    def test_legacy_bad_client_hashes_follow_selection_policy(self):
        for selection in ("discover", "explicit"):
            with self.subTest(selection=selection):
                store = self.store(selection)
                self.clients(store)
                store.add("bad", 100, 100, schema_version=1,
                          checkpoint_files_sha256={"config.json": "0" * 64, "model.safetensors": "0" * 64})
                config = self.config(store, selection=selection, publish=True,
                                     submissions=("alice", "bob", "bad") if selection == "explicit" else ())
                if selection == "explicit":
                    with self.assertRaisesRegex(ValueError, "Checkpoint checksum mismatch in bad"):
                        run_round(store, config)
                    self.assertEqual([], store.publications)
                else:
                    result = run_round(store, config)
                    self.assertEqual("published", result.status)
                    self.assertEqual(["bad"], [item.candidate for item in result.skipped])
                    self.assertEqual([0.25, 0.75], [item["coefficient"] for item in result.eligible])

    def test_legacy_hashless_and_correctly_hashed_checkpoints_stay_supported(self):
        for hashed in (False, True):
            with self.subTest(hashed=hashed):
                store = self.store(str(hashed))
                self.clients(store, schema_version=1)
                for revision in ("base", "alice", "bob"):
                    filename = ROUND_FILE if revision == "base" else SUBMISSION_FILE
                    path = store.root / revision / filename
                    record = read_json(path)
                    record["schema_version"] = 1
                    if not hashed:
                        record.pop("checkpoint_files_sha256")
                    write_json(path, record)
                result = run_round(store, self.config(store, publish=True))
                self.assertEqual("published", result.status)
                self.assertEqual((), result.skipped)

    def test_nested_boolean_algorithm_parameter_cannot_match_a_number(self):
        class Custom(FedAvg):
            @property
            def spec(self):
                return AlgorithmSpec("custom", params={"options": {"rates": [1]}})

        for selection in ("discover", "explicit"):
            with self.subTest(selection=selection):
                store = self.store(selection)
                store.add("alice", 1, 1, algorithm_spec=Custom().spec.to_dict())
                store.add("bad", 3, 3,
                          algorithm_spec={"name": "custom", "params": {"options": {"rates": [True]}}})
                config = self.config(store, selection=selection, check_only=True,
                                     submissions=("alice", "bad") if selection == "explicit" else ())
                if selection == "explicit":
                    with self.assertRaisesRegex(ValueError, "different algorithm parameters"):
                        run_round(store, config, aggregator=Custom())
                else:
                    result = run_round(store, config, aggregator=Custom())
                    self.assertEqual("not_ready", result.status)
                    self.assertEqual(["bad"], [item.candidate for item in result.skipped])

    def test_algorithm_numeric_equivalence_and_object_order_remain_compatible(self):
        class Custom(FedAvg):
            @property
            def spec(self):
                return AlgorithmSpec("custom", params={"options": {"rate": 1, "enabled": True}})

        store = self.store()
        store.add("alice", 1, 1, algorithm_spec=Custom().spec.to_dict())
        store.add("bob", 3, 3,
                  algorithm_spec={"name": "custom", "params": {"options": {"enabled": True, "rate": 1.0}}})
        result = run_round(store, self.config(store, check_only=True), aggregator=Custom())
        self.assertEqual("ready", result.status)
        self.assertEqual((), result.skipped)

    def test_cyclic_updates_are_excluded_even_when_the_base_matches(self):
        store = self.store()
        self.clients(store)
        store.add("cyclic", 100, 100, workflow="cyclic", source_kind="global",
                  lineage={"root_revision": "base", "root_round": 0, "parents": []})
        result = run_round(store, self.config(store, publish=True))
        self.assertEqual("published", result.status)
        self.assertEqual(["cyclic"], [item.candidate for item in result.skipped])
        self.assertIn("cannot participate in synchronous FedAvg", result.skipped[0].reason)

        with self.assertRaisesRegex(ValueError, "cannot participate in synchronous FedAvg"):
            run_round(store, replace(self.config(store), output_dir=store.root / "explicit",
                                     selection="explicit", submissions=("alice", "bob", "cyclic")))


if __name__ == "__main__":
    unittest.main()
