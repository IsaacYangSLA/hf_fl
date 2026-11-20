"""Failure-boundary tests for participant recovery storage."""

import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hf2l.recovery import RecoveryError, RecoveryStore, TrainingCancelled, TrainingContext, TrainingPaused


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.identity = {
            "study": "study-a", "participant": "alice", "round": 1,
            "base_revision": "immutable-base", "trainer_identity": "immutable-trainer",
        }
        self.store = RecoveryStore(self.root / "private", self.identity, max_bytes=100, max_files=5)

    def context(self, attempt, should_pause=lambda: False):
        return TrainingContext(
            attempt.checkpoint, attempt.completed_steps, self.proposals(attempt),
            work_id=self.store.work_id, generation=attempt.generation,
            max_bytes=100, max_files=5, should_pause=should_pause,
        )

    def proposals(self, attempt):
        return self.root / f"attempt-{attempt.generation}"

    @staticmethod
    def save(context, step, content=b"state"):
        return context.save(step, lambda target: (target / "state.txt").write_bytes(content))

    def new_attempt(self):
        return self.store.begin_attempt()

    def promote(self, attempt):
        self.store.confirm_stopped(attempt.generation)
        return self.store.accept_checkpoint(attempt.generation, self.proposals(attempt))

    def test_identity_and_generation_are_independent_of_file_times(self):
        first = self.new_attempt()
        context = self.context(first)
        self.assertEqual(context.start_mode, "fresh")
        self.save(context, 0, b"initial")
        self.save(context, 5, b"progress")
        self.promote(first)

        replacement = self.store.begin_attempt(previous_stopped=True)
        context = self.context(replacement)
        self.assertGreater(replacement.generation, first.generation)
        self.assertEqual(context.start_mode, "resume")
        self.assertEqual(context.completed_steps, 5)
        self.assertEqual((context.checkpoint_dir / "state.txt").read_bytes(), b"progress")
        for change in ({"round": 2}, {"base_revision": "changed"}, {"participant": "bob"}):
            with self.subTest(change=change):
                different = RecoveryStore(self.root / "private", self.identity | change)
                different_attempt = different.begin_attempt()
                self.assertIsNone(different_attempt.checkpoint)
                with self.assertRaisesRegex(RecoveryError, "incompatible"):
                    TrainingContext(
                        replacement.checkpoint, 5, self.root / "different",
                        work_id=different.work_id, generation=2,
                    )

    def test_partial_write_and_corruption_preserve_previous_save(self):
        attempt = self.new_attempt()
        context = self.context(attempt)
        self.save(context, 0, b"valid first")
        damaged = self.save(context, 2, b"damaged")
        (damaged / "payload" / "state.txt").write_bytes(b"changed")

        def disk_full(path):
            (path / "partial.bin").write_bytes(b"incomplete")
            raise OSError(errno.ENOSPC, "injected storage fault")

        with self.assertRaises(OSError):
            context.save(3, disk_full)
        self.assertEqual(context.last_saved_step, 2)
        self.assertEqual({p.name for p in self.proposals(attempt).iterdir()}, {"step-0", "step-2"})
        with self.assertWarnsRegex(RuntimeWarning, "invalid checkpoint"):
            accepted = self.promote(attempt)
        self.assertEqual(accepted.step, 0)
        replacement = self.store.begin_attempt(previous_stopped=True)
        self.assertEqual(self.context(replacement).start_mode, "resume")
        self.assertEqual(replacement.completed_steps, 0)

    def test_lost_journal_write_never_exposes_uncommitted_selection(self):
        attempt = self.new_attempt()
        context = self.context(attempt)
        self.save(context, 0)
        self.save(context, 2)
        self.store.confirm_stopped(attempt.generation)
        original_replace = os.replace

        def fail_journal(source, destination):
            if Path(destination).name == "state.json":
                raise OSError(errno.ENOSPC, "injected journal-write fault")
            return original_replace(source, destination)

        with patch("hf2l.recovery.os.replace", side_effect=fail_journal):
            with self.assertRaises(OSError):
                self.store.accept_checkpoint(attempt.generation, self.proposals(attempt))
        self.assertEqual(self.store.status()["checkpoints"], [])
        accepted = self.store.accept_checkpoint(attempt.generation, self.proposals(attempt))
        self.assertEqual(accepted.step, 2)
        self.assertEqual([x["step"] for x in self.store.status()["checkpoints"]], [2, 0])

    def test_storage_bounds_and_link_handling(self):
        attempt = self.new_attempt()
        context = self.context(attempt)
        with self.assertRaisesRegex(RecoveryError, "step zero"):
            self.save(context, 1)
        with self.assertRaisesRegex(RecoveryError, "byte limit"):
            self.save(context, 0, b"x" * 101)
        private_file = self.root / "private-other"
        private_file.write_bytes(b"external bytes")
        with self.assertRaises((RecoveryError, OSError)):
            context.save(0, lambda path: (path / "link").symlink_to(private_file))
        self.assertFalse(list(self.proposals(attempt).iterdir()))
        self.assertEqual(private_file.read_bytes(), b"external bytes")
        self.save(context, 0)
        self.save(context, 1)
        self.save(context, 2)
        self.assertEqual({p.name for p in self.proposals(attempt).iterdir()}, {"step-1", "step-2"})

    def test_supervisor_and_worker_stop_proof(self):
        reopened = RecoveryStore.open(self.root / "private", self.store.work_id)
        with self.store.supervise():
            with self.assertRaisesRegex(RecoveryError, "already owns"):
                with reopened.supervise():
                    self.fail("duplicate supervisor acquired the lock")
            attempt = self.store.begin_attempt()
            self.assertEqual(reopened.begin_attempt(), attempt)
            self.store.attach_pod(attempt.generation, name="worker-a")
            self.store.attach_pod(attempt.generation, name="worker-a", uid="original-id")
            with self.assertRaisesRegex(RecoveryError, "uid changed"):
                self.store.attach_pod(attempt.generation, name="worker-a", uid="replacement-id")
            for operation in (
                lambda: self.store.begin_attempt(previous_stopped=True),
                lambda: self.store.accept_checkpoint(attempt.generation, self.proposals(attempt)),
                lambda: self.store.record_failure(attempt.generation),
            ):
                with self.assertRaisesRegex(RecoveryError, "confirmed stopped"):
                    operation()
            self.store.confirm_stopped(attempt.generation)
            self.assertEqual(self.store.record_failure(attempt.generation), 1)
            self.assertEqual(self.store.record_failure(attempt.generation), 1)
            self.store.begin_attempt(previous_stopped=True)
            with self.assertRaisesRegex(RecoveryError, "no longer owns"):
                self.store.accept_checkpoint(attempt.generation, self.proposals(attempt))

    def test_activation_survives_reopen_and_cancellation(self):
        attempt = self.new_attempt()
        self.store.attach_pod(attempt.generation, name="worker")
        with self.assertRaisesRegex(RecoveryError, "requires an attached"):
            self.store.authorize_pod(attempt.generation)
        self.store.attach_pod(attempt.generation, name="worker", uid="worker-id")
        self.assertTrue(self.store.authorize_pod(attempt.generation))
        reopened = RecoveryStore.open(self.root / "private", self.store.work_id)
        self.assertTrue(reopened.status()["activated"])
        reopened.cancel()
        self.assertFalse(reopened.authorize_pod(attempt.generation))
        self.assertTrue(reopened.status()["activated"])

    def test_active_pause_prevents_worker_activation(self):
        attempt = self.new_attempt()
        self.store.attach_pod(attempt.generation, name="worker", uid="worker-id")
        self.store.request_pause()
        self.assertFalse(self.store.authorize_pod(attempt.generation))
        self.assertFalse(self.store.status()["activated"])
        self.store.confirm_stopped(attempt.generation)
        self.store.mark_paused(attempt.generation, graceful=False)
        self.store.resume()
        replacement = self.store.begin_attempt(previous_stopped=True)
        self.assertGreater(replacement.generation, attempt.generation)
        self.assertFalse(self.store.status()["activated"])

    def test_planned_pause_and_cancel_are_distinct(self):
        attempt = self.new_attempt()
        context = self.context(attempt, lambda: self.store.status()["desire"] == "pause")
        self.save(context, 0)
        with self.assertRaisesRegex(RecoveryError, "requires a request"):
            context.pause()
        self.store.request_pause()
        self.save(context, 3)
        with self.assertRaises(TrainingPaused) as paused:
            context.pause()
        self.assertEqual(paused.exception.completed_steps, 3)
        self.promote(attempt)
        with self.assertRaisesRegex(RecoveryError, "not confirmed"):
            self.store.mark_paused(attempt.generation, expected_step=4)
        self.store.mark_paused(attempt.generation, expected_step=3)
        with self.assertRaisesRegex(RecoveryError, "paused"):
            self.store.begin_attempt(previous_stopped=True)
        self.store.resume()
        self.assertEqual(self.store.status()["paused_generation"], attempt.generation)
        self.assertEqual(self.store.record_failure(attempt.generation), 0)
        replacement = self.store.begin_attempt(previous_stopped=True)
        self.assertIsNone(self.store.status()["paused_generation"])
        self.assertEqual(replacement.completed_steps, 3)
        self.store.cancel()
        with self.assertRaises(TrainingCancelled):
            self.store.begin_attempt(previous_stopped=True)
        with self.assertRaises(TrainingCancelled):
            self.store.accept_checkpoint(replacement.generation, self.proposals(replacement))

    def test_final_output_reuse_and_pause_fence(self):
        attempt = self.new_attempt()
        context = self.context(attempt)
        self.save(context, 0, b"private trainer state")
        self.promote(attempt)
        worker_result = self.root / "result"
        worker_result.mkdir()
        (worker_result / "model.bin").write_bytes(b"final public model")
        self.store.request_pause()
        with self.assertRaisesRegex(RecoveryError, "pause"):
            self.store.accept_result(attempt.generation, worker_result, {"num_examples": 4})
        self.store.mark_paused(attempt.generation, graceful=False)
        self.assertEqual(self.store.status()["phase"], "pause-interrupted")
        self.store.resume()
        ready = self.store.accept_result(attempt.generation, worker_result, {"num_examples": 4})
        self.assertEqual(ready, self.store.ready_result())
        self.assertEqual({p.name for p in ready.output_dir.iterdir()}, {"model.bin"})
        export = self.root / "export"
        copied = self.store.materialize_result(export)
        self.assertEqual(copied.output_dir, export)
        self.assertEqual(copied.fingerprint, ready.fingerprint)
        self.assertEqual(copied, self.store.materialize_result(export))
        self.assertEqual((export / "model.bin").read_bytes(), b"final public model")
        (export / "model.bin").write_bytes(b"wrong")
        with self.assertRaisesRegex(RecoveryError, "different result"):
            self.store.materialize_result(export)
        with self.assertRaisesRegex(RecoveryError, "already exists"):
            self.store.begin_attempt(previous_stopped=True)
        with self.assertRaisesRegex(RecoveryError, "cannot be cancelled"):
            self.store.cancel()
