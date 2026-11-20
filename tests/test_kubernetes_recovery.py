import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from hf2l import kubernetes_recovery as recovery


def _pod(name, state, *, uid="worker-uid", phase="Running"):
    return {
        "metadata": {
            "name": name["pod_name"], "namespace": "alice",
            "uid": uid, "labels": {recovery.OWNER_LABEL: name["attempt_id"]},
        },
        "spec": {"nodeName": "node", "restartPolicy": "Never"},
        "status": {"phase": phase, "containerStatuses": [{"name": "trainer", "state": state}]},
    }


def _terminated(reason="Error", *, exit_code=137):
    return {"terminated": {
        "reason": reason, "exitCode": exit_code, "containerID": "containerd://worker",
        "finishedAt": "2026-11-19T00:00:00Z",
    }}


class PodRecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.mount = Path(temporary.name)
        self.paths = recovery._Paths(self.mount / "a" / "attempt")
        for directory in (self.paths.inputs, self.paths.control, self.paths.worker):
            directory.mkdir(parents=True, exist_ok=True)
        self.config = {
            "namespace": "alice", "image": "example@sha256:" + "a" * 64,
            "dataset_claim": "alice-data", "resources": {},
            "readiness_timeout_seconds": 20, "training_timeout_seconds": 100,
            "cleanup_timeout_seconds": 10,
        }
        self.volume = recovery._Volume("alice-recovery", self.mount, None, 15, 2)
        self.name = recovery._attempt_name("a" * 64, 4)
        self.attempt = SimpleNamespace(generation=4, checkpoint=None)

    def test_worker_mounts_exclude_controller_and_other_attempts(self):
        checkpoint = self.mount / "a" / "selected"
        manifest = recovery._mount_spec(self.config, self.volume, self.name, self.paths, checkpoint)
        spec = manifest["spec"]
        self.assertEqual(manifest["metadata"]["finalizers"], [recovery._FINALIZER])
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertEqual(spec["restartPolicy"], "Never")
        mounts = {item["mountPath"]: item for item in spec["containers"][0]["volumeMounts"]}
        for path in ("/work/input", "/work/control", "/work/restore", "/data"):
            self.assertTrue(mounts[path]["readOnly"])
        self.assertEqual(mounts["/work/attempt"]["subPath"], "a/attempt/worker")
        self.assertFalse(mounts["/work/attempt"]["readOnly"])
        self.assertNotIn("kubeconfig", json.dumps(manifest))

    def test_worker_uses_the_staged_recovery_store_limits(self):
        base = self.mount / "base"
        base.mkdir()
        (base / "model.bin").write_bytes(b"starting model")
        config = self.config | {"plugin": "/trainer.py", "max_transfer_bytes": 16 * 1024}
        expected = recovery._manifest(base, config["max_transfer_bytes"])
        for index, (max_bytes, max_files) in enumerate(((32 * 1024, 4096), (2048, 2))):
            with self.subTest(max_bytes=max_bytes, max_files=max_files):
                paths = recovery._Paths(self.mount / f"staged-{index}")
                store = SimpleNamespace(
                    work_id="a" * 64,
                    status=lambda: {"limits": {"max_bytes": max_bytes, "max_files": max_files}},
                )
                attempt = SimpleNamespace(generation=1, checkpoint=None, completed_steps=0)
                recovery._stage(paths, config, store, attempt, base, {}, expected)
                request = recovery._read_message(paths.inputs / "request.json")
                self.assertEqual(request["checkpoint_limits"], {
                    "max_bytes": min(config["max_transfer_bytes"], max_bytes),
                    "max_files": max_files,
                })
                recovery._write_message(paths.permit, {"pod_uid": "worker-uid"})
                recovery._write_message(paths.control / "stop.json", {"requested": "pause"})
                work_dir = self.mount / f"worker-{index}"
                work_dir.mkdir()
                for name, source in {"input": paths.inputs, "control": paths.control, "attempt": paths.worker}.items():
                    (work_dir / name).symlink_to(source, target_is_directory=True)

                def trainer(base_dir, output_dir, options, context):
                    self.assertEqual((base_dir / "model.bin").read_bytes(), b"starting model")
                    self.assertTrue(context.pause_requested())
                    context.save(0, lambda payload: (payload / "progress").write_bytes(b"step zero"))
                    context.pause()

                plugin = SimpleNamespace(train_recoverable=trainer)
                with patch.dict(recovery.os.environ, {"HF2L_POD_UID": "worker-uid"}), \
                        patch.object(recovery.signal, "signal"), patch.object(recovery, "load_plugin", return_value=plugin):
                    recovery._worker(work_dir)
                self.assertEqual(recovery._read_message(paths.worker / "result.json"), {
                    "kind": "paused", "completed_steps": 0,
                })

    def test_claim_root_cannot_be_mounted_into_worker(self):
        with self.assertRaisesRegex(recovery.KubernetesError, "entire recovery claim"):
            recovery._subpath(self.mount, self.mount)
        with self.assertRaisesRegex(recovery.KubernetesError, "inside the configured claim"):
            recovery._subpath(self.mount.parent, self.mount)

    def test_actual_container_stop_is_required(self):
        self.assertTrue(recovery._confirmed_terminated(_pod(self.name, _terminated(), phase="Failed")))
        self.assertFalse(recovery._confirmed_terminated(
            _pod(self.name, _terminated("ContainerStatusUnknown"), phase="Failed"),
        ))
        fabricated = _pod(self.name, _terminated(), phase="Failed")
        fabricated["status"]["containerStatuses"][0]["state"]["terminated"]["finishedAt"] = "0001-01-01T00:00:00Z"
        self.assertFalse(recovery._confirmed_terminated(fabricated))

    def test_existing_pod_must_match_saved_permanent_identifier(self):
        with patch.object(recovery, "_get_pod", return_value=_pod(self.name, {}, uid="different")):
            with self.assertRaisesRegex(recovery.UncertainExecution, "no longer matches"):
                recovery._owned_pod(self.config, self.name, {"uid": "worker-uid"})

    def test_missing_permitted_pod_does_not_launch_replacement(self):
        recovery._write_message(self.paths.permit, {"pod_uid": "worker-uid"})
        store = Mock()
        store.status.return_value = {"pod": {"uid": "worker-uid"}, "desire": "run", "stopped": False, "activated": True}
        with patch.object(recovery, "_get_pod", return_value=None), patch.object(recovery, "_invoke") as invoke:
            with self.assertRaisesRegex(recovery.UncertainExecution, "disappeared without proof"):
                recovery._wait_attempt(self.config, self.volume, store, self.attempt, self.paths, self.name)
        invoke.assert_not_called()
        store.confirm_stopped.assert_not_called()

    def test_missing_permit_is_not_proof_an_authorized_pod_stopped(self):
        store = Mock()
        store.status.return_value = {
            "pod": {"uid": "worker-uid"}, "desire": "run", "stopped": False, "activated": True,
        }
        with patch.object(recovery, "_get_pod", return_value=None), patch.object(recovery, "_invoke") as invoke:
            with self.assertRaisesRegex(recovery.UncertainExecution, "disappeared without proof"):
                recovery._wait_attempt(self.config, self.volume, store, self.attempt, self.paths, self.name)
        invoke.assert_not_called()
        store.confirm_stopped.assert_not_called()

    def test_running_pod_reuses_identity_without_second_create(self):
        store = Mock()
        state = {"pod": {}, "desire": "run", "stopped": False, "activated": False}
        store.status.side_effect = lambda: state

        def record(_generation, *, name, uid, node_name):
            state["pod"].update(name=name, uid=uid, node_name=node_name)

        store.attach_pod.side_effect = record

        def authorize(_generation):
            state["activated"] = True
            return True

        store.authorize_pod.side_effect = authorize
        running = _pod(self.name, {"running": {"startedAt": "2026-11-19T00:00:00Z"}})
        stopped = _pod(self.name, _terminated(), phase="Failed")
        with patch.object(recovery, "_get_pod", side_effect=[running, stopped]), \
                patch.object(recovery, "_invoke") as invoke, patch.object(recovery.time, "sleep"):
            recovery._wait_attempt(self.config, self.volume, store, self.attempt, self.paths, self.name)
        self.assertEqual(recovery._read_message(self.paths.permit), {"pod_uid": "worker-uid"})
        invoke.assert_not_called()
        store.confirm_stopped.assert_called_once_with(4)

    def test_uid_record_precedes_activation(self):
        store = Mock()
        store.status.return_value = {"pod": {}, "desire": "run", "stopped": False, "activated": False}
        store.attach_pod.side_effect = OSError("simulated journal failure")
        running = _pod(self.name, {"running": {"startedAt": "2026-11-19T00:00:00Z"}})
        with patch.object(recovery, "_get_pod", return_value=running):
            with self.assertRaisesRegex(OSError, "journal failure"):
                recovery._wait_attempt(self.config, self.volume, store, self.attempt, self.paths, self.name)
        self.assertFalse(self.paths.permit.exists())

    def test_pause_uses_uid_conditioned_graceful_deletion(self):
        recovery._write_message(self.paths.permit, {"pod_uid": "worker-uid"})
        store = Mock()
        store.status.return_value = {"pod": {"uid": "worker-uid"}, "desire": "pause", "stopped": False, "activated": True}
        running = _pod(self.name, {"running": {"startedAt": "2026-11-19T00:00:00Z"}})
        stopped = _pod(self.name, _terminated(), phase="Failed")
        with patch.object(recovery, "_get_pod", side_effect=[running, stopped]), \
                patch.object(recovery, "_invoke") as invoke, patch.object(recovery.time, "sleep"):
            recovery._wait_attempt(self.config, self.volume, store, self.attempt, self.paths, self.name)
        self.assertEqual(recovery._read_message(self.paths.control / "stop.json"), {"requested": "pause"})
        body = json.loads(invoke.call_args.kwargs["input_data"])
        self.assertEqual(body["preconditions"], {"uid": "worker-uid"})
        self.assertEqual(body["gracePeriodSeconds"], 15)
        store.confirm_stopped.assert_called_once_with(4)

    def test_cleanup_removes_only_our_finalizer_with_uid_check(self):
        stopped = _pod(self.name, _terminated(), phase="Failed")
        stopped["metadata"]["finalizers"] = ["other.example/hold", recovery._FINALIZER]
        stopped["metadata"]["deletionTimestamp"] = "2026-11-19T00:00:00Z"
        with patch.object(recovery, "_get_pod", side_effect=[stopped, None, None]), \
                patch.object(recovery, "_invoke") as invoke:
            recovery._retire(self.config, self.name, {"uid": "worker-uid", "stopped": True})
        invoke.assert_called_once()
        changes = json.loads(invoke.call_args.args[1][-1])
        self.assertEqual(changes, [
            {"op": "test", "path": "/metadata/uid", "value": "worker-uid"},
            {"op": "test", "path": "/metadata/finalizers/1", "value": recovery._FINALIZER},
            {"op": "remove", "path": "/metadata/finalizers/1"},
        ])

    def test_resuming_planned_pause_does_not_count_as_a_worker_failure(self):
        store = Mock()
        store.status.return_value = {
            "pod": {"uid": "worker-uid"}, "desire": "run", "stopped": True, "paused_generation": 4,
        }
        recovery._write_message(self.paths.worker / "result.json", {
            "kind": "paused", "completed_steps": 12,
        })
        with patch.object(recovery, "_retire"):
            recovery._finish_attempt(self.config, store, self.attempt, self.paths, self.name,
                                     self.paths.inputs / "base")
        store.accept_checkpoint.assert_called_once()
        store.record_failure.assert_not_called()

    def test_result_persists_before_owned_pod_cleanup(self):
        store = Mock()
        store.status.return_value = {"pod": {"uid": "worker-uid"}, "desire": "run", "stopped": True}
        actions = []
        store.accept_checkpoint.side_effect = lambda *_: actions.append("checkpoint")
        store.accept_result.side_effect = lambda *_: actions.append("result")
        recovery._write_message(self.paths.worker / "result.json", {
            "kind": "complete", "metadata": {"num_examples": 2, "metrics": {}},
        })
        with patch.object(recovery, "_validate_outputs"), \
                patch.object(recovery, "_retire", side_effect=lambda *_: actions.append("delete")):
            recovery._finish_attempt(self.config | {"max_transfer_bytes": 1024}, store, self.attempt,
                                     self.paths, self.name, self.paths.inputs / "base")
        self.assertEqual(actions, ["checkpoint", "result", "delete"])


if __name__ == "__main__":
    unittest.main()
