"""Exact continuation checks for the synchronous Kubernetes example trainer."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import numpy as np

from examples.kubernetes import configure, trainer


class PlannedPause(Exception):
    """A stand-in for the recovery interface's distinct paused outcome."""


class InterruptedTraining(BaseException):
    """Simulate abrupt termination on a completed update before the next save."""


class ExampleContext:
    """Exercise the trainer contract independently of the Kubernetes launcher."""

    def __init__(self, root, checkpoint=None, completed_steps=0):
        self.root = root
        self.checkpoint_dir = checkpoint
        self.completed_steps = completed_steps
        self.last_saved_step = completed_steps if checkpoint else None
        self.saved = {}
        self.stopping = False

    def save(self, step, writer):
        if self.last_saved_step is not None and step <= self.last_saved_step:
            raise AssertionError("Trainer attempted to replace a saved update")
        directory = self.root / str(step)
        directory.mkdir(parents=True)
        writer(directory)
        self.saved[step] = directory
        self.last_saved_step = step

    def pause_requested(self):
        return self.stopping

    def pause(self):
        if not self.stopping:
            raise AssertionError("Trainer paused without a stop request")
        raise PlannedPause()


class TestRecoverableExample(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.base = self.root / "base"
        self.dataset = self.root / "data.npz"
        trainer._model.initialize(self.base)
        trainer._model.generate_data(self.dataset, 23, 75)
        self.options = {
            "dataset": str(self.dataset),
            "steps": 100,
            "checkpoint_every": 10,
            "batch_size": 8,
            "seed": 2026,
            "noise_std": 0.07,
            "momentum": 0.8,
        }

    def assert_continuation(self, planned):
        uninterrupted = ExampleContext(self.root / "continuous-state")
        expected = trainer.train_recoverable(
            self.base, self.root / "continuous-model", self.options, uninterrupted,
        )
        first = ExampleContext(self.root / "first-state")
        first_output = self.root / "first-model"
        original_update = trainer._training_step

        def stop_after_update(state, features, labels, settings):
            original_update(state, features, labels, settings)
            if state.step == 37:
                if planned:
                    first.stopping = True
                else:
                    raise InterruptedTraining()

        error = PlannedPause if planned else InterruptedTraining
        with mock.patch.object(trainer, "_training_step", stop_after_update):
            with self.assertRaises(error):
                trainer.train_recoverable(self.base, first_output, self.options, first)
        self.assertFalse(first_output.exists())
        restored_step = 37 if planned else 30
        self.assertEqual(first.last_saved_step, restored_step)

        resumed = ExampleContext(self.root / "resumed-state", first.saved[restored_step], restored_step)
        updates = []

        def record_update(state, features, labels, settings):
            original_update(state, features, labels, settings)
            updates.append(state.step)

        with mock.patch.object(trainer, "_training_step", record_update):
            actual = trainer.train_recoverable(
                self.base, self.root / "resumed-model", self.options, resumed,
            )
        self.assertEqual(updates, list(range(restored_step + 1, 101)))
        self.assertEqual(actual, expected)
        self.assertEqual(actual["num_examples"], 23)
        self.assertEqual(
            (self.root / "continuous-model" / "model.safetensors").read_bytes(),
            (self.root / "resumed-model" / "model.safetensors").read_bytes(),
        )
        reference_state, recovered_state = uninterrupted.saved[100], resumed.saved[100]
        for name in trainer._SAVE_ARRAYS:
            with self.subTest(array=name):
                np.testing.assert_array_equal(
                    np.load(reference_state / f"{name}.npy", allow_pickle=False),
                    np.load(recovered_state / f"{name}.npy", allow_pickle=False),
                )
        self.assertEqual(
            json.loads((reference_state / "progress.json").read_text()),
            json.loads((recovered_state / "progress.json").read_text()),
        )

    def test_planned_pause_saves_current_update(self):
        self.assert_continuation(planned=True)

    def test_abrupt_stop_replays_only_unsaved_updates(self):
        self.assert_continuation(planned=False)

    def test_saved_step_must_match_worker_instruction(self):
        original = ExampleContext(self.root / "first-state")
        original.stopping = True
        with self.assertRaises(PlannedPause):
            trainer.train_recoverable(self.base, self.root / "initial-output", self.options, original)
        wrong = ExampleContext(self.root / "wrong-state", original.saved[0], completed_steps=1)
        with self.assertRaisesRegex(ValueError, "does not match the saved step"):
            trainer.train_recoverable(self.base, self.root / "incorrect-output", self.options, wrong)

    def test_recovery_manifest_mounts_only_participant_listener_settings(self):
        values = {
            "study_id": "example-1", "trainer_version": "image-1", "dataset_version": "data-1",
        }
        args = ("alice", "hf2l:example", "study-space", "https://exchange.example")
        legacy = configure.manifests(*args)
        recovery = configure.manifests(*args, recovery_config=values)
        self.assertNotIn("recovery-config.json", legacy)
        self.assertEqual(recovery["data-job.json"], legacy["data-job.json"])
        config = recovery["recovery-config.json"]
        self.assertTrue(config["immutable"])
        self.assertEqual(json.loads(config["data"]["config.json"]), values)
        spec = recovery["listener.json"]["spec"]["template"]["spec"]
        container = spec["containers"][0]
        self.assertIn("/work/recovery-listener", container["args"])
        self.assertIn("/work/recovery", container["args"])
        self.assertIn("/recovery-config/config.json", container["args"])
        self.assertIn(
            {"name": "recovery-config", "mountPath": "/recovery-config", "readOnly": True},
            container["volumeMounts"],
        )
        self.assertIn(
            {"name": "recovery-config", "configMap": {"name": config["metadata"]["name"]}},
            spec["volumes"],
        )
        with self.assertRaisesRegex(ValueError, "require an Alice or Bob role"):
            configure.manifests("owner", *args[1:], recovery_config=values)


if __name__ == "__main__":
    unittest.main()
