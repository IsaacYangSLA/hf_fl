"""Recovery through the real listener, round metadata and local model store."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import signal
import time
import traceback
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from types import ModuleType
from unittest.mock import patch

import numpy as np
from safetensors.numpy import load_file, save_file

from hf2l import client_train
from hf2l.backends.local import LocalStore
from hf2l.core.protocol import CLIENT_CONTEXT_FILE, ROUND_FILE, SUBMISSION_FILE
from hf2l.hub_helpers import artifact_hashes, read_json, write_json
from hf2l.listener import client as listener_client
from hf2l.recovery import RecoveryError, RecoveryStore
from hf2l.recovery_client import RecoveryRunner
from tests.test_client_listener import CHECKPOINT_FILES, ListenerFixture


FINAL_STEP = 4
EXAMPLE_COUNT = 7


class ListenerRecoveryTests(ListenerFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.recovery_root = self.root / "private-recovery"
        self.trace = self.root / "training-events.jsonl"

    def _trainer(self, *, kill_after=None, pause_after=None):
        def train(base_dir, output_dir, options, context):
            base_model = base_dir / "model.safetensors"
            starting_from = context.completed_steps
            with self.trace.open("a", encoding="utf-8") as events:
                event = {
                    "base": hashlib.sha256(base_model.read_bytes()).hexdigest(),
                    "starting_from": starting_from,
                }
                events.write(json.dumps(event) + "\n")

            saved_model = (
                base_model if context.checkpoint_dir is None
                else context.checkpoint_dir / "parameters.safetensors"
            )
            parameters = load_file(saved_model)

            def save(directory):
                save_file(parameters, directory / "parameters.safetensors")

            if context.checkpoint_dir is None:
                context.save(0, save)
            for step in range(starting_from + 1, FINAL_STEP + 1):
                parameters = {
                    name: tensor * np.float32(2) + np.float32(step)
                    for name, tensor in parameters.items()
                }
                if step % 2 == 0 or step == pause_after:
                    context.save(step, save)
                if step == pause_after:
                    self._only_recovery_store().request_pause()
                    self.assertTrue(context.pause_requested())
                    context.pause()
                if step == kill_after:
                    os.kill(os.getpid(), signal.SIGKILL)
                if context.pause_requested():
                    context.pause()

            output_dir.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(base_dir / "config.json", output_dir / "config.json")
            save_file(parameters, output_dir / "model.safetensors")
            return {"num_examples": EXAMPLE_COUNT, "steps": FINAL_STEP}

        return train

    def _only_recovery_store(self):
        candidates = [
            path.name for path in self.recovery_root.iterdir()
            if path.is_dir() and len(path.name) == 64
        ]
        self.assertEqual(len(candidates), 1)
        return RecoveryStore.open(self.recovery_root, candidates[0])

    def _listener(self, trainer, *, reference=False):
        store = self.store
        state_dir = self.state_dir
        recovery_root = self.recovery_root
        source_id = "local-test-main"
        if reference:
            store = LocalStore(self.root / "reference-store", "alice")
            self.addCleanup(store.close)
            store.initialize_repository("repo", self.source, private=False)
            state_dir = self.root / "reference-listener"
            recovery_root = self.root / "reference-recovery"
            source_id = "local-test-reference"

        recovery = RecoveryRunner(
            recovery_root,
            {
                "study_id": "resume-study",
                "trainer_version": "affine-updates-v1",
                "dataset_version": "input-v1",
            },
            trainer,
            source_id=source_id,
            participant="alice",
        )

        def legacy(*args, **kwargs):
            self.fail("recovery invoked the legacy trainer")

        return listener_client.ClientListener(
            store,
            repo_id="repo",
            participant="alice",
            state_dir=state_dir,
            source_id=source_id,
            training_id="affine-updates-v1",
            train_model=legacy,
            recovery=recovery,
        )

    def _events(self):
        return [json.loads(line) for line in self.trace.read_text().splitlines()]

    def _abrupt_stop(self, invoke):
        """Kill a child without running the listener or store cleanup code."""
        error_file = self.root / "child-error"
        pid = os.fork()
        if pid == 0:
            try:
                invoke()
            except BaseException:
                error_file.write_text(traceback.format_exc())
                os._exit(1)
            os._exit(0)

        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            exited, status = os.waitpid(pid, os.WNOHANG)
            if exited:
                detail = error_file.read_text() if error_file.exists() else ""
                self.assertEqual(os.waitstatus_to_exitcode(status), -signal.SIGKILL, detail)
                return
            time.sleep(0.01)

        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        self.fail("listener child did not reach the expected failure boundary")

    @contextmanager
    def _submissions(self):
        """Record the update passed through actual validation and publication."""
        updates = []
        publish = listener_client.submit_round

        def record(store, work_dir, participant, metadata):
            result = publish(store, work_dir, participant, metadata)
            trained = work_dir / "trained_model"
            weights = load_file(trained / "model.safetensors")
            updates.append((participant, metadata["num_examples"], weights, sorted(
                path.name for path in trained.iterdir()
            )))
            return result

        with patch.object(listener_client, "submit_round", record):
            yield updates

    @unittest.skipUnless(hasattr(os, "fork"), "requires abrupt POSIX process termination")
    def test_abrupt_stop_resumes_last_save_and_matches_uninterrupted_result(self):
        with self._submissions() as reference, self._listener(
            self._trainer(), reference=True
        ) as listener:
            self.assertEqual(listener.poll_once(), "submitted")

        def interrupted():
            with self._listener(self._trainer(kill_after=3)) as listener:
                listener.poll_once()

        self._abrupt_stop(interrupted)
        with self._submissions() as resumed, self._listener(self._trainer()) as listener:
            self.assertEqual(listener.poll_once(), "submitted")

        self.assertEqual([event["starting_from"] for event in self._events()], [0, 0, 2])
        self.assertEqual(len({event["base"] for event in self._events()}), 1)
        self.assertEqual(len(reference), 1)
        self.assertEqual(len(resumed), 1)
        self.assertEqual(resumed[0][:2], ("alice", EXAMPLE_COUNT))
        self.assertEqual(resumed[0][3], ["config.json", SUBMISSION_FILE, "model.safetensors"])
        self.assertEqual(len(self.submitted_manifests()), 1)
        self.assertEqual(resumed[0][2].keys(), reference[0][2].keys())
        for name in resumed[0][2]:
            np.testing.assert_array_equal(resumed[0][2][name], reference[0][2][name])

    def test_pause_waits_for_explicit_resume(self):
        with self._listener(self._trainer(pause_after=1)) as listener:
            self.assertEqual(listener.poll_once(), "paused")
        with self._listener(self._trainer()) as listener:
            self.assertEqual(listener.poll_once(), "paused")
            self.assertEqual([event["starting_from"] for event in self._events()], [0])
            self._only_recovery_store().resume()
            self.assertEqual(listener.poll_once(), "submitted")
        self.assertEqual([event["starting_from"] for event in self._events()], [0, 1])

    def test_cancelled_round_does_not_resume_or_submit(self):
        with self._listener(self._trainer(pause_after=1)) as listener:
            self.assertEqual(listener.poll_once(), "paused")
        self._only_recovery_store().cancel()
        with self._submissions() as updates, self._listener(self._trainer()) as listener:
            self.assertEqual(listener.poll_once(), "skipped")
        self.assertEqual([event["starting_from"] for event in self._events()], [0])
        self.assertEqual(updates, [])

    @unittest.skipUnless(hasattr(os, "fork"), "requires abrupt POSIX process termination")
    def test_committed_final_output_survives_stop_before_listener_ready_transition(self):
        def interrupted():
            with self._listener(self._trainer()) as listener:
                original = listener._set_status

                def set_status(job, status, *args, **kwargs):
                    if status == "ready":
                        os.kill(os.getpid(), signal.SIGKILL)
                    return original(job, status, *args, **kwargs)

                with patch.object(listener, "_set_status", set_status):
                    listener.poll_once()

        self._abrupt_stop(interrupted)
        self.assertIsNotNone(self._only_recovery_store().ready_result())
        with self._submissions() as updates, self._listener(self._trainer()) as listener:
            self.assertEqual(listener.poll_once(), "submitted")
        self.assertEqual([event["starting_from"] for event in self._events()], [0])
        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0][1], EXAMPLE_COUNT)


    def test_verified_round_cannot_be_reopened_in_a_different_workspace(self):
        with self._listener(self._trainer(pause_after=1)) as listener:
            self.assertEqual(listener.poll_once(), "paused")
            runner = listener.recovery
            options = listener.options

        original = self.work()
        original_store = runner.store(original, options)
        self.assertEqual(original_store.work_id, self._only_recovery_store().work_id)
        self.assertTrue((original / ".hf2l-recovery-work").is_file())

        copied = original.with_name("copied-work")
        copied.mkdir()
        shutil.copytree(original / "base_model", copied / "base_model")
        shutil.copyfile(original / CLIENT_CONTEXT_FILE, copied / CLIENT_CONTEXT_FILE)

        with self.assertRaisesRegex(
            RecoveryError, "This participant round is bound to a different workspace"
        ):
            runner.store(copied, options)
        self.assertEqual(runner.store(original, options).work_id, original_store.work_id)

    def test_new_shared_model_supersedes_paused_work_for_older_round(self):
        with self._listener(self._trainer(pause_after=1)) as listener:
            self.assertEqual(listener.poll_once(), "paused")

        next_model = self.make_global("next-shared-model", 1)
        next_weights = {"weight": np.array([13.0, 17.0], dtype=np.float32)}
        save_file(next_weights, next_model / "model.safetensors")
        record = read_json(next_model / ROUND_FILE)
        record["checkpoint_files_sha256"] = artifact_hashes(next_model, CHECKPOINT_FILES)
        write_json(next_model / ROUND_FILE, record)
        current = self.store.resolve_reference("repo")
        published = self.store.publish_aggregate(
            "repo", next_model, [*CHECKPOINT_FILES, ROUND_FILE],
            expected_base=current.revision, next_round=1, tag=None, reference=current,
        )

        with self._listener(self._trainer()) as listener:
            outcome = listener.poll_once()
            if outcome == "skipped":
                outcome = listener.poll_once()
            self.assertEqual(outcome, "submitted")

        events = self._events()
        self.assertEqual([event["starting_from"] for event in events], [0, 0])
        self.assertNotEqual(events[0]["base"], events[1]["base"])
        self.assertEqual(
            events[1]["base"],
            hashlib.sha256((next_model / "model.safetensors").read_bytes()).hexdigest(),
        )
        manifests = self.submitted_manifests()
        self.assertEqual(len(manifests), 1)
        self.assertEqual(manifests[0]["base_revision"], published.revision)
        self.assertEqual(manifests[0]["source_round"], 1)
        self.assertEqual(manifests[0]["num_examples"], EXAMPLE_COUNT)

    def test_manual_entrypoint_keeps_legacy_callback_and_reuses_recovered_output(self):
        plugin_file = self.root / "trainer.py"
        plugin_file.write_text("# Trainer supplied by the command's plug-in loader in this test.\n")
        plugin = ModuleType("manual_test_trainer")
        plugin.__file__ = str(plugin_file)
        plugin.train_model = self.train
        plugin.train_recoverable = self._trainer()
        common = [
            "--repo-id", "repo",
            "--base-revision", self.base,
            "--participant", "alice",
            "--backend", "local",
            "--endpoint", str(self.root / "storage"),
            "--local-principal", "alice",
            "--plugin", str(plugin_file),
            "--plugin-arg", "learning_rate=0.01",
        ]
        legacy_work = self.root / "manual-legacy"
        recovery_work = self.root / "manual-recovered"
        settings = self.root / "recovery-config.json"
        settings.write_text(json.dumps({
            "study_id": "resume-study",
            "trainer_version": "affine-updates-v1",
            "dataset_version": "input-v1",
        }))
        recoverable = common + [
            "--work-dir", str(recovery_work),
            "--recovery-root", str(self.recovery_root),
            "--recovery-config", str(settings),
        ]

        with patch.object(client_train, "load_plugin", return_value=plugin):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    client_train.main(common + ["--work-dir", str(legacy_work)]), 0
                )
                self.assertEqual(client_train.main(recoverable), 0)
                self.assertEqual(client_train.main(recoverable), 0)

        self.assertEqual(len(self.training_calls), 1)
        self.assertEqual(self.training_calls[0][2]["learning_rate"], 0.01)
        self.assertEqual([event["starting_from"] for event in self._events()], [0])
        self.assertTrue((legacy_work / "trained_model" / "model.safetensors").is_file())
        self.assertTrue((recovery_work / "trained_model" / "model.safetensors").is_file())
        self.assertEqual(self._only_recovery_store().ready_result().metadata["num_examples"],
                         EXAMPLE_COUNT)

        weights_path = recovery_work / "trained_model" / "model.safetensors"
        tampered = {name: tensor + 1 for name, tensor in load_file(weights_path).items()}
        save_file(tampered, weights_path)
        with patch.object(client_train, "load_plugin", return_value=plugin):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(client_train.main(recoverable), 1)
        self.assertEqual([event["starting_from"] for event in self._events()], [0])


if __name__ == "__main__":
    unittest.main()
