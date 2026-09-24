"""Shared listener guarantees without model stores or training workflows."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

from hf2l.common.fs import read_json, write_json
from hf2l.listener.client import ClientListener, UncertainSubmission
from hf2l.listener.engine import DurableListener, ListenerStateError, UncertainOperation


class IndexListener(DurableListener):
    """An independent document-indexing task using the same persistence engine."""

    statuses = {"pending", "publishing", "uncertain", "indexed", "skipped"}
    terminal_statuses = {"indexed", "skipped"}
    success_status = "indexed"

    def __init__(self, root, *, versions=(), index=None, role="indexer", on_event=None):
        super().__init__(state_dir=root, identity={"role": role, "collection": "documents"},
                         on_event=on_event)
        self.versions = iter(versions)
        self.index = index or Mock()

    def poll_once(self):
        self._require_open()
        active = self.state["active"]
        job = self.state["jobs"].get(active)
        if job and job["status"] in self.uncertain_statuses:
            raise UncertainOperation("Reconcile the remote index before retrying")
        if job is None:
            version = next(self.versions, None)
            if version is None or version in self.state["jobs"]:
                return "idle"
            job = {"revision": version, "source_round": int(version[1:]), "status": "pending"}
            self.state["jobs"][version] = job
            self.state["active"] = version
            self._save()
        self._job_dir(job).joinpath("document.txt").write_text(job["revision"])
        self._set_status(job, "publishing")
        self.index(job["revision"])
        self._finish(job, "indexed", document_count=5)
        return "indexed"


class ListenerEngineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "listener"

    def test_other_workflow_counts_success_and_deduplicates_on_restart(self):
        index = Mock()
        events = []
        with patch("hf2l.listener.engine.time.sleep") as sleep:
            with IndexListener(self.root, versions=("v2", "v2", "v3"), index=index,
                               on_event=events.append) as listener:
                self.assertEqual(2, listener.run(poll_interval=1, max_rounds=2))
                self.assertEqual(3, listener.state["completed_round"])
                self.assertIsNone(listener.state["active"])
            with IndexListener(self.root, versions=("v3", "v4"), index=index) as listener:
                self.assertEqual(0, listener.run(once=True))
                self.assertEqual(1, listener.run(once=True))
        self.assertEqual([call("v2"), call("v3"), call("v4")], index.call_args_list)
        self.assertEqual([call(1), call(1)], sleep.call_args_list)
        self.assertEqual(["indexed", "indexed"], [event["event"] for event in events])
        self.assertEqual("v3", events[-1]["revision"])
        saved = read_json(self.root / "state.json")
        self.assertEqual(5, saved["jobs"]["v2"]["document_count"])

    def test_legacy_client_state_opens_without_migration_or_rewrite(self):
        digest = lambda value: hashlib.sha256(value.encode()).hexdigest()
        identity = {
            "backend": "local", "repo_id": "repo", "participant": "alice", "reference": "main",
            "source_hash": digest("local:endpoint"),
            "training_hash": digest(json.dumps({"trainer": "trainer-v1", "options": {"epochs": 1}},
                                                sort_keys=True, separators=(",", ":"))),
        }
        saved = {"schema_version": 1, "identity": identity, "completed_round": 7,
                 "active": None, "jobs": {"legacy-commit": {
                     "revision": "legacy-commit", "source_round": 7, "status": "submitted",
                     "result": {"revision": "uploaded-update"}, "retained_extension": "keep-me",
                 }}}
        write_json(self.root / "state.json", saved)
        original = (self.root / "state.json").read_bytes()
        with ClientListener(SimpleNamespace(name="local"), repo_id="repo", participant="alice",
                            state_dir=self.root, source_id="local:endpoint", training_id="trainer-v1",
                            train_model=lambda *_: None, options={"epochs": 1}) as listener:
            self.assertIsInstance(listener, DurableListener)
            self.assertEqual(saved, listener.state)
        self.assertEqual(original, (self.root / "state.json").read_bytes())
        self.assertTrue(issubclass(UncertainSubmission, UncertainOperation))

    def test_roles_cannot_reuse_state_even_after_the_lock_is_released(self):
        with IndexListener(self.root, role="client"):
            pass
        original = (self.root / "state.json").read_bytes()
        with self.assertRaisesRegex(ListenerStateError, "different role"):
            with IndexListener(self.root, role="fedavg"):
                self.fail("An unrelated role reused persisted jobs")
        self.assertEqual(original, (self.root / "state.json").read_bytes())

    def test_competing_listener_cannot_take_lock_and_failure_releases_its_handle(self):
        second = IndexListener(self.root)
        with IndexListener(self.root):
            with self.assertRaisesRegex(ListenerStateError, "Another listener"):
                second.__enter__()
            self.assertIsNone(second._lock)
        with second:
            self.assertEqual("idle", second.poll_once())

    def test_interrupted_remote_write_remains_uncertain_on_restart(self):
        index = Mock(side_effect=KeyboardInterrupt)
        with IndexListener(self.root, versions=("v1",), index=index) as listener:
            with self.assertRaises(KeyboardInterrupt):
                listener.run(once=True)
        with IndexListener(self.root, versions=("v2",), index=index) as listener:
            self.assertEqual("uncertain", listener.state["jobs"]["v1"]["status"])
            with patch("hf2l.listener.engine.time.sleep") as sleep:
                with self.assertRaises(UncertainOperation):
                    listener.run(poll_interval=1)
                sleep.assert_not_called()
        index.assert_called_once_with("v1")

    def test_safe_failures_back_off_and_successful_poll_resets_delay(self):
        poll = Mock(side_effect=[ConnectionError(), ConnectionError(), "idle",
                                ConnectionError(), "indexed"])
        events = []
        with IndexListener(self.root, on_event=events.append) as listener:
            with patch.object(listener, "poll_once", poll), patch("hf2l.listener.engine.time.sleep") as sleep:
                self.assertEqual(1, listener.run(poll_interval=2, max_backoff=3, max_rounds=1))
        self.assertEqual([call(2), call(3), call(2), call(2)], sleep.call_args_list)
        self.assertEqual([2, 3, 2], [event["retry_seconds"] for event in events])

    def test_persistence_failure_stops_before_remote_write_without_retry(self):
        index = Mock()
        with IndexListener(self.root, versions=("v1",), index=index) as listener:
            with patch("hf2l.listener.engine.write_json", side_effect=OSError("disk full")), \
                    patch("hf2l.listener.engine.time.sleep") as sleep:
                with self.assertRaisesRegex(ListenerStateError, "Cannot persist"):
                    listener.run(poll_interval=1)
                sleep.assert_not_called()
        index.assert_not_called()

    def test_invalid_completion_or_job_state_is_rejected_without_rewriting_it(self):
        with IndexListener(self.root, versions=("v2",)) as listener:
            listener.poll_once()
        original = read_json(self.root / "state.json")
        invalid = (
            {**original, "completed_round": 1},
            {**original, "active": "v2"},
            {**original, "jobs": {"v2": {"revision": "v2", "source_round": 2, "status": "submitted"}}},
            {**original, "jobs": {"v2": {"revision": "v2", "status": "indexed"}}},
        )
        for state in invalid:
            write_json(self.root / "state.json", state)
            before = (self.root / "state.json").read_bytes()
            with self.subTest(state=state), self.assertRaises(ListenerStateError):
                with IndexListener(self.root):
                    self.fail("Corrupt state was accepted")
            self.assertEqual(before, (self.root / "state.json").read_bytes())

    def test_missing_state_with_existing_artifacts_requires_recovery(self):
        with IndexListener(self.root, versions=("v1",)) as listener:
            listener.poll_once()
        (self.root / "state.json").unlink()
        with self.assertRaisesRegex(ListenerStateError, "artifacts exist"):
            with IndexListener(self.root):
                self.fail("Lost progress was silently discarded")

    def test_run_requires_an_open_listener_and_valid_polling_limits(self):
        listener = IndexListener(self.root)
        with self.assertRaisesRegex(ListenerStateError, "context manager"):
            listener.run(once=True)
        invalid = ({"poll_interval": 0}, {"poll_interval": float("nan")},
                   {"max_backoff": float("inf")}, {"poll_interval": 3, "max_backoff": 2},
                   {"max_rounds": False}, {"max_rounds": 0})
        with listener:
            for options in invalid:
                with self.subTest(options=options), self.assertRaises(ValueError):
                    listener.run(once=True, **options)


if __name__ == "__main__":
    unittest.main()
