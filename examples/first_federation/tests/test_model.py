"""Behavioral checks for the first federation's real CPU training contract."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

import numpy as np
from safetensors.numpy import load_file, save_file

SCRIPT = Path(__file__).resolve().parents[1] / "model.py"
SPEC = importlib.util.spec_from_file_location("first_federation_model", SCRIPT)
model = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(model)


class FirstFederationModelTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base = self.root / "base"
        model.initialize(self.base)
        self.alice = self.root / "alice.npz"
        self.bob = self.root / "bob.npz"
        self.heldout = self.root / "owner.npz"
        for path, count, seed in ((self.alice, 64, 11), (self.bob, 96, 22), (self.heldout, 200, 33)):
            model.generate_data(path, count, seed)

    def snapshot(self, directory):
        return {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in directory.rglob("*") if path.is_file()}

    def test_model_is_compatible_with_generic_hf2l_checkpoint_reader(self):
        from hf2l.checkpoint_utils import discover_checkpoint
        layout = discover_checkpoint(self.base)
        self.assertEqual(set(layout.artifact_paths), {"config.json", "model.safetensors"})

    def test_training_uses_real_gradient_descent_and_improves_heldout_loss(self):
        output = self.root / "trained"
        before = model.evaluate(self.base, self.heldout)
        result = model.train(self.base, output, self.alice)
        after = model.evaluate(output, self.heldout)
        self.assertEqual(result["num_examples"], 64)
        self.assertGreater(after["accuracy"], 0.95)
        self.assertLess(after["cross_entropy"], before["cross_entropy"] / 2)
        self.assertNotEqual(model.checkpoint_digest(self.base), model.checkpoint_digest(output))

    def test_training_preserves_base_and_exact_config_bytes(self):
        # Formatting is part of the checkpoint contract, even when JSON agrees.
        custom_bytes = (json.dumps(model.CONFIG, separators=(",", ":")) + "\n").encode()
        (self.base / "config.json").write_bytes(custom_bytes)
        before = self.snapshot(self.base)
        output = self.root / "trained"
        model.train(self.base, output, self.alice)
        self.assertEqual(before, self.snapshot(self.base))
        self.assertEqual((output / "config.json").read_bytes(), custom_bytes)

    def test_training_is_deterministic(self):
        first, second = self.root / "first", self.root / "second"
        model.train(self.base, first, self.alice)
        model.train(self.base, second, self.alice)
        self.assertEqual(self.snapshot(first), self.snapshot(second))

    def test_data_is_local_balanced_deterministic_and_counts_are_actual(self):
        copy = self.root / "alice-copy.npz"
        model.generate_data(copy, 64, 11)
        x, y = model.load_data(self.alice)
        other_x, other_y = model.load_data(copy)
        self.assertTrue(np.array_equal(x, other_x))
        self.assertTrue(np.array_equal(y, other_y))
        self.assertEqual(np.bincount(y).tolist(), [32, 32])
        result = model.train(self.base, self.root / "bob-trained", self.bob, steps=2)
        self.assertEqual(result["num_examples"], 96)

    def test_two_round_hf2l_aggregation_matches_independent_weighted_reference(self):
        from hf2l.checkpoint_utils import aggregate_checkpoints, discover_checkpoint
        base = self.base
        initial_loss = model.evaluate(base, self.heldout)["cross_entropy"]
        for round_number in (1, 2):
            alice = self.root / f"alice-r{round_number}"
            bob = self.root / f"bob-r{round_number}"
            aggregate = self.root / f"aggregate-r{round_number}"
            model.train(base, alice, self.alice)
            model.train(base, bob, self.bob)
            aggregate_checkpoints(
                discover_checkpoint(base),
                [discover_checkpoint(alice), discover_checkpoint(bob)],
                [64 / 160, 96 / 160], aggregate, array_backend="numpy",
            )
            result = model.verify_aggregate(aggregate, alice, bob)
            self.assertEqual(result["weights"], [0.4, 0.6])
            self.assertLessEqual(result["max_abs_error"], 2 * np.finfo(np.float32).eps)
            base = aggregate
        self.assertLess(model.evaluate(base, self.heldout)["cross_entropy"], initial_loss / 2)

    def test_wrong_aggregate_is_rejected(self):
        alice, bob = self.root / "alice-trained", self.root / "bob-trained"
        model.train(self.base, alice, self.alice)
        model.train(self.base, bob, self.bob)
        with self.assertRaisesRegex(ValueError, "differs"):
            model.verify_aggregate(self.base, alice, bob)

    def test_output_cannot_overwrite_base_or_be_inside_it(self):
        before = self.snapshot(self.base)
        for output in (self.base, self.base / "trained"):
            with self.assertRaises(ValueError):
                model.train(self.base, output, self.alice)
        self.assertEqual(before, self.snapshot(self.base))

    def test_existing_model_or_dataset_is_not_overwritten(self):
        before = self.snapshot(self.base)
        with self.assertRaises(FileExistsError):
            model.initialize(self.base)
        with self.assertRaises(FileExistsError):
            model.generate_data(self.alice, 128, 44)
        self.assertEqual(before, self.snapshot(self.base))
        self.assertEqual(len(model.load_data(self.alice)[1]), 64)

    def test_rejects_symlinked_inputs_outputs_and_ancestors(self):
        link = self.root / "link"
        link.symlink_to(self.base, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "Symlinks"):
            model.load_model(link)
        with self.assertRaisesRegex(ValueError, "Symlinks"):
            model.initialize(link / "other")
        (self.base / "config.json").unlink()
        (self.base / "config.json").symlink_to(self.alice)
        with self.assertRaisesRegex(ValueError, "Symlinks"):
            model.load_model(self.base)

    def test_rejects_incompatible_config_before_creating_output(self):
        config = {**model.CONFIG, "num_labels": 3}
        (self.base / "config.json").write_text(json.dumps(config))
        output = self.root / "trained"
        with self.assertRaisesRegex(ValueError, "configuration"):
            model.train(self.base, output, self.alice)
        self.assertFalse(output.exists())

    def test_rejects_nonfinite_wrong_shape_or_wrong_dtype_tensors(self):
        for bad in (np.zeros((3, 2), dtype=np.float32),
                    np.zeros((2, 2), dtype=np.float64),
                    np.full((2, 2), np.nan, dtype=np.float32)):
            tensors = {"weight": bad, "bias": np.zeros(2, dtype=np.float32)}
            save_file(tensors, str(self.base / "model.safetensors"))
            with self.assertRaises(ValueError):
                model.load_model(self.base)

    def test_rejects_invalid_dataset_and_pickle_payload(self):
        invalid = self.root / "invalid.npz"
        for x, y in ((np.ones((2, 2), dtype=np.float32), np.array([0, 2], dtype=np.int64)),
                     (np.ones((2, 2), dtype=np.float32), np.array([0, 1], dtype=np.int32)),
                     (np.ones((2, 3), dtype=np.float32), np.array([0, 1], dtype=np.int64)),
                     (np.full((2, 2), np.nan, dtype=np.float32), np.array([0, 1], dtype=np.int64)),
                     (np.array([["secret"]], dtype=object), np.array([0], dtype=np.int64))):
            np.savez(invalid, features=x, labels=y)
            with self.assertRaises(ValueError):
                model.load_data(invalid)

    def test_invalid_training_parameters_fail_without_output(self):
        output = self.root / "trained"
        for kwargs in ({"steps": 0}, {"steps": 100001}, {"learning_rate": 0},
                       {"learning_rate": float("nan")}, {"learning_rate": float("inf")}):
            with self.assertRaises(ValueError):
                model.train(self.base, output, self.alice, **kwargs)
        self.assertFalse(output.exists())

    def test_owner_prepublication_plugin_evaluates_local_heldout_data(self):
        result = model.evaluate_model(self.base, {"dataset": str(self.heldout)})
        self.assertEqual(result["num_examples"], 200)
        self.assertEqual(result["accuracy"], 0.5)
        for options in ({}, {"dataset": str(self.heldout), "typo": True},
                        {"dataset": None}):
            with self.assertRaises(ValueError):
                model.evaluate_model(self.base, options)

    def test_cli_prints_machine_readable_actual_counts(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = model.main(["train", "--input", str(self.base), "--output",
                                 str(self.root / "cli-trained"), "--dataset", str(self.alice)])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(stdout.getvalue())["num_examples"], 64)

    def test_cli_corrupt_checkpoint_reports_error_without_traceback(self):
        (self.base / "model.safetensors").write_bytes(b"not a checkpoint")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = model.main(["evaluate", "--model", str(self.base),
                                 "--dataset", str(self.heldout)])
        self.assertEqual(result, 1)
        self.assertIn("error:", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_cli_failure_reports_error_and_nonzero_status(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = model.main(["data", "--output", str(self.root / "empty.npz"),
                                 "--examples", "0", "--seed", "11"])
        self.assertEqual(result, 1)
        self.assertIn("error:", stderr.getvalue())
        self.assertFalse((self.root / "empty.npz").exists())


if __name__ == "__main__":
    unittest.main()
