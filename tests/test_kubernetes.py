"""Organization-local pod training preserves isolation and attempt lifecycle."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from hf2l import kubernetes as pods
from hf2l.plugin_loader import load_plugin, require_callable


CHECKPOINT = Path(__file__).parent / "goldens" / "single" / "clients" / "0"


class FakeCluster:
    """A cluster that enforces pod identity when accepting a deletion."""

    def __init__(self):
        self.pod = None
        self.calls = []
        self.configs = []
        self.events = []
        self.manifest = None
        self.delete_body = None
        self.failures = {}
        self.replace_at_delete = False

    def invoke(self, config, args, *, input_data=None, timeout=None):
        args = list(args)
        self.configs.append(config)
        self.calls.append((copy.deepcopy(args), input_data))
        verb = args[0]
        self.events.append(verb)
        failure = self.failures.get(verb)
        if failure is not None:
            raise failure
        if verb == "create":
            manifest = json.loads(input_data)
            self.manifest = copy.deepcopy(manifest)
            self.pod = copy.deepcopy(manifest)
            self.pod["metadata"].setdefault("name", "hf2l-test-attempt")
            self.pod["metadata"]["uid"] = "original-pod-identity"
            self.pod["status"] = {"phase": "Running"}
            return json.dumps(self.pod).encode()
        if verb == "get":
            return b"" if self.pod is None else json.dumps(self.pod).encode()
        if verb == "wait":
            return b"pod ready\n"
        if verb == "exec":
            return b""
        if verb == "delete":
            if not any(x == "--raw" or x.startswith("--raw=") for x in args):
                raise AssertionError("Deletion must use the API identity precondition")
            self.delete_body = json.loads(input_data)
            if self.replace_at_delete and self.pod is not None:
                self.pod["metadata"]["uid"] = "raced-replacement-identity"
            expected = self.delete_body.get("preconditions", {}).get("uid")
            if self.pod is not None and expected != self.pod["metadata"]["uid"]:
                raise pods.KubernetesError("Conflict: pod identity changed")
            self.pod = None
            return b"{}"
        raise AssertionError("Unexpected cluster command: " + repr(args))


class KubernetesLifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.work = self.root / "attempt"
        self.work.mkdir()
        self.base = self.work / "base_model"
        shutil.copytree(CHECKPOINT, self.base)
        self.output = self.work / "trained_model"
        self.kubeconfig = self.root / "private-cluster.json"
        self.kubeconfig.write_text(json.dumps({"apiVersion": "v1", "kind": "Config"}))
        self.config = {
            "kubeconfig": str(self.kubeconfig),
            "context": "org-a-cluster",
            "namespace": "org-a-study",
            "image": "example.invalid/hf2l-training@sha256:" + "a" * 64,
            "plugin": "/opt/hf2l/examples/kubernetes/trainer.py",
            "dataset_claim": "org-a-private-data",
        }
        self.config_file = self.root / "private-pod-config.json"
        self.write_config()
        self.options = {"pod_config": str(self.config_file), "dataset": "/data/private-data.npz"}
        self.cluster = FakeCluster()
        self.staged_options = None
        self.collect_calls = 0
        self.stage_failure = None
        self.collect_failure = None
        self.metadata = {"num_examples": 8, "metrics": {"accuracy": 0.75}}
        self.real_invoke = pods._invoke
        self.addCleanup(patch.stopall)
        patch.object(pods, "_invoke", side_effect=self.cluster.invoke).start()
        patch.object(pods, "_stream_to_pod", side_effect=self.stage).start()
        patch.object(pods, "_collect", side_effect=self.collect).start()

    def write_config(self):
        self.config_file.write_text(json.dumps(self.config))

    def stage(self, config, state, base_dir, training_options):
        self.cluster.events.append("stage")
        self.staged_options = copy.deepcopy(training_options)
        if self.stage_failure is not None:
            raise self.stage_failure

    def collect(self, config, state, destination):
        self.cluster.events.append("collect")
        self.collect_calls += 1
        if self.collect_failure is not None:
            raise self.collect_failure
        shutil.copytree(CHECKPOINT, destination, dirs_exist_ok=True)
        return copy.deepcopy(self.metadata)

    def state(self):
        return json.loads((self.work / ".hf2l-kubernetes-attempt.json").read_text())

    def test_registered_plugin_exposes_existing_training_callback(self):
        plugin = load_plugin("kubernetes")
        self.assertTrue(callable(require_callable(plugin, "train_model")))

    def test_callback_collects_before_cleanup_and_returns_only_after_cleanup(self):
        metadata = require_callable(load_plugin("kubernetes"), "train_model")(self.base, self.output, self.options)
        self.assertEqual(metadata, self.metadata)
        self.assertTrue(self.output.is_dir())
        self.assertIsNone(self.cluster.pod)
        self.assertEqual(self.collect_calls, 1)
        events = self.cluster.events
        self.assertLess(events.index("stage"), events.index("exec"))
        self.assertLess(events.index("exec"), events.index("collect"))
        self.assertLess(events.index("collect"), events.index("delete"))
        self.assertEqual(self.state()["phase"], "succeeded")

    def test_manual_phases_do_not_train_during_preparation(self):
        pods.prepare(self.base, self.output, self.options)
        self.assertIsNotNone(self.cluster.pod)
        self.assertNotIn("exec", self.cluster.events)
        self.assertEqual(self.collect_calls, 0)
        pods.train(self.base)
        self.assertEqual(self.cluster.events.count("exec"), 1)
        self.assertEqual(self.collect_calls, 0)
        metadata = pods.post(self.base)
        self.assertEqual(metadata, self.metadata)
        self.assertIsNone(self.cluster.pod)

    def test_control_configuration_is_not_sent_as_training_options(self):
        pods.prepare(self.base, self.output, self.options)
        self.assertEqual(self.staged_options, {"dataset": "/data/private-data.npz"})
        self.assertNotIn(str(self.kubeconfig), json.dumps(self.cluster.manifest))
        self.assertNotIn(str(self.config_file), json.dumps(self.cluster.manifest))
        pods.cleanup(self.base)

    def test_pod_has_no_cluster_credentials_or_host_privileges(self):
        pods.prepare(self.base, self.output, self.options)
        spec = self.cluster.manifest["spec"]
        self.assertIs(spec["automountServiceAccountToken"], False)
        self.assertFalse(spec.get("hostNetwork", False))
        self.assertFalse(spec.get("hostPID", False))
        self.assertFalse(spec.get("hostIPC", False))
        volumes = spec.get("volumes", [])
        self.assertTrue(all("hostPath" not in volume for volume in volumes))
        dataset_volumes = [v for v in volumes if "persistentVolumeClaim" in v]
        self.assertEqual(len(dataset_volumes), 1)
        self.assertEqual(dataset_volumes[0]["persistentVolumeClaim"]["claimName"], "org-a-private-data")
        container = spec["containers"][0]
        security = dict(spec.get("securityContext", {}))
        security.update(container.get("securityContext", {}))
        self.assertTrue(security.get("runAsNonRoot"))
        self.assertIs(security.get("allowPrivilegeEscalation"), False)
        self.assertFalse(security.get("privileged", False))
        self.assertIn("ALL", security.get("capabilities", {}).get("drop", []))
        self.assertTrue(container["resources"]["limits"])
        mounts = [m for m in container.get("volumeMounts", []) if m["mountPath"] == "/data"]
        self.assertEqual(len(mounts), 1)
        self.assertIs(mounts[0]["readOnly"], True)
        pods.cleanup(self.base)

    def test_state_is_private_and_cleanup_uses_server_identity_precondition(self):
        pods.prepare(self.base, self.output, self.options)
        state_file = self.work / ".hf2l-kubernetes-attempt.json"
        self.assertEqual(stat.S_IMODE(state_file.stat().st_mode), 0o600)
        pods.cleanup(self.base)
        self.assertEqual(self.cluster.delete_body["preconditions"]["uid"], "original-pod-identity")
        self.assertIsNone(self.cluster.pod)
        deletes = self.cluster.events.count("delete")
        pods.cleanup(self.base)
        self.assertEqual(self.cluster.events.count("delete"), deletes)

    def test_missing_required_configuration_fails_before_cluster_access(self):
        for key in ("kubeconfig", "context", "namespace", "image", "plugin"):
            with self.subTest(key=key):
                config = dict(self.config)
                del config[key]
                self.config_file.write_text(json.dumps(config))
                with self.assertRaises((pods.KubernetesError, ValueError)):
                    pods.prepare(self.base, self.output, self.options)
                self.assertEqual(self.cluster.calls, [])
        self.write_config()

    def test_nonexistent_cluster_configuration_fails_before_cluster_access(self):
        self.config["kubeconfig"] = str(self.root / "missing-config")
        self.write_config()
        with self.assertRaises((pods.KubernetesError, ValueError)):
            pods.prepare(self.base, self.output, self.options)
        self.assertEqual(self.cluster.calls, [])

    def test_existing_nonempty_output_is_not_overwritten(self):
        self.output.mkdir()
        sentinel = self.output / "previous-result"
        sentinel.write_text("retain")
        with self.assertRaises((pods.KubernetesError, ValueError)):
            pods.train_model(self.base, self.output, self.options)
        self.assertEqual(sentinel.read_text(), "retain")
        self.assertEqual(self.cluster.calls, [])

    def test_prepare_wait_failure_cleans_created_pod(self):
        self.cluster.failures["wait"] = pods.KubernetesError("pod was not ready")
        with self.assertRaisesRegex(pods.KubernetesError, "ready"):
            pods.train_model(self.base, self.output, self.options)
        self.assertIsNone(self.cluster.pod)
        self.assertNotIn("exec", self.cluster.events)
        self.assertEqual(self.collect_calls, 0)
        self.assertFalse(self.output.exists())

    def test_input_staging_failure_cleans_created_pod(self):
        self.stage_failure = pods.KubernetesError("input transfer failed")
        with self.assertRaisesRegex(pods.KubernetesError, "input transfer failed"):
            pods.train_model(self.base, self.output, self.options)
        self.assertIsNone(self.cluster.pod)
        self.assertNotIn("exec", self.cluster.events)
        self.assertEqual(self.collect_calls, 0)

    def test_training_failure_cleans_without_collecting_or_publishing(self):
        self.cluster.failures["exec"] = pods.KubernetesError("training command failed")
        with self.assertRaises(pods.KubernetesError):
            pods.train_model(self.base, self.output, self.options)
        self.assertIsNone(self.cluster.pod)
        self.assertEqual(self.collect_calls, 0)
        self.assertFalse(self.output.exists())

    def test_interrupted_training_cleans_without_collecting(self):
        self.cluster.failures["exec"] = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            pods.train_model(self.base, self.output, self.options)
        self.assertIsNone(self.cluster.pod)
        self.assertEqual(self.collect_calls, 0)
        self.assertFalse(self.output.exists())

    def test_collection_failure_cleans_without_installing_partial_result(self):
        self.collect_failure = pods.KubernetesError("result transfer failed")
        with self.assertRaisesRegex(pods.KubernetesError, "result transfer failed"):
            pods.train_model(self.base, self.output, self.options)
        self.assertIsNone(self.cluster.pod)
        self.assertFalse(self.output.exists())

    def test_cleanup_failure_never_returns_a_successful_result(self):
        self.cluster.failures["delete"] = pods.KubernetesError("delete permission denied")
        with self.assertRaises(pods.KubernetesError):
            pods.train_model(self.base, self.output, self.options)
        self.assertIsNotNone(self.cluster.pod)
        self.assertFalse(self.output.exists())
        self.assertNotEqual(self.state()["phase"], "succeeded")

    def test_replaced_pod_is_neither_collected_nor_deleted(self):
        pods.prepare(self.base, self.output, self.options)
        self.cluster.pod["metadata"]["uid"] = "replacement-pod-identity"
        with self.assertRaises(pods.KubernetesError):
            pods.train(self.base)
        with self.assertRaises(pods.KubernetesError):
            pods.cleanup(self.base)
        self.assertEqual(self.cluster.pod["metadata"]["uid"], "replacement-pod-identity")
        self.assertNotIn("exec", self.cluster.events)
        self.assertNotIn("delete", self.cluster.events)
        self.assertEqual(self.collect_calls, 0)

    def test_foreign_owner_label_prevents_execution_and_deletion(self):
        pods.prepare(self.base, self.output, self.options)
        self.cluster.pod["metadata"]["labels"]["hf2l.org/attempt"] = "foreign-attempt"
        with self.assertRaises(pods.KubernetesError):
            pods.train(self.base)
        with self.assertRaises(pods.KubernetesError):
            pods.cleanup(self.base)
        self.assertNotIn("exec", self.cluster.events)
        self.assertNotIn("delete", self.cluster.events)

    def test_uncertain_attempt_is_not_executed_again(self):
        self.cluster.failures["exec"] = subprocess.TimeoutExpired("kubectl exec", 1)
        with self.assertRaises((pods.KubernetesError, subprocess.TimeoutExpired)):
            pods.train_model(self.base, self.output, self.options)
        executions = self.cluster.events.count("exec")
        creations = self.cluster.events.count("create")
        self.cluster.failures.clear()
        with self.assertRaises(pods.KubernetesError):
            pods.train_model(self.base, self.output, self.options)
        self.assertEqual(self.cluster.events.count("exec"), executions)
        self.assertEqual(self.cluster.events.count("create"), creations)
        self.assertEqual(self.collect_calls, 0)

    def test_prepared_attempt_cannot_be_silently_replaced(self):
        pods.prepare(self.base, self.output, self.options)
        original = copy.deepcopy(self.cluster.pod)
        try:
            pods.prepare(self.base, self.output, self.options)
        except pods.KubernetesError:
            pass
        self.assertEqual(self.cluster.pod, original)
        self.assertEqual(self.cluster.events.count("create"), 1)
        pods.cleanup(self.base)

    def test_post_cannot_publish_without_successful_training(self):
        pods.prepare(self.base, self.output, self.options)
        with self.assertRaises(pods.KubernetesError):
            pods.post(self.base)
        self.assertEqual(self.collect_calls, 0)
        self.assertFalse(self.output.exists())
        pods.cleanup(self.base)


    def test_real_invoker_passes_explicit_cluster_selection_to_executable(self):
        pods.prepare(self.base, self.output, self.options)
        binary_dir = self.root / "bin"
        binary_dir.mkdir()
        executable = binary_dir / "kubectl"
        executable.write_text("\n".join([
            "#!/usr/bin/env python3", "import json, sys", "print(json.dumps(sys.argv[1:]))", "",
        ]))
        executable.chmod(0o755)
        with patch.dict(os.environ, {"PATH": str(binary_dir) + os.pathsep + os.environ["PATH"]}):
            command = json.loads(self.real_invoke(self.cluster.configs[0], ["get", "pods"]))
        for flag, expected in (("--kubeconfig", str(self.kubeconfig)),
                               ("--context", "org-a-cluster"),
                               ("--namespace", "org-a-study")):
            if flag in command:
                self.assertEqual(command[command.index(flag) + 1], expected)
            else:
                self.assertIn(flag + "=" + expected, command)
        self.assertEqual(command[-2:], ["get", "pods"])
        pods.cleanup(self.base)

    def test_cleanup_failure_preserves_original_training_failure(self):
        self.cluster.failures["exec"] = pods.KubernetesError("original training failure")
        self.cluster.failures["delete"] = pods.KubernetesError("secondary cleanup failure")
        with self.assertRaises(pods.KubernetesError) as caught:
            pods.train_model(self.base, self.output, self.options)
        self.assertNotIn("secondary cleanup failure", str(caught.exception))
        messages = []
        error = caught.exception
        while error is not None and len(messages) < 10:
            messages.append(str(error))
            error = error.__cause__ or error.__context__
        self.assertIn("original training failure", " ".join(messages))
        self.assertFalse(self.output.exists())
        self.assertEqual(self.collect_calls, 0)


    def test_server_identity_precondition_protects_replacement_after_final_read(self):
        pods.prepare(self.base, self.output, self.options)
        self.cluster.replace_at_delete = True
        with self.assertRaises(pods.KubernetesError):
            pods.cleanup(self.base)
        self.assertEqual(self.cluster.delete_body["preconditions"]["uid"], "original-pod-identity")
        self.assertEqual(self.cluster.pod["metadata"]["uid"], "raced-replacement-identity")
        self.assertEqual(self.collect_calls, 0)


    def test_concurrent_prepare_cannot_create_two_pods_for_one_attempt(self):
        entered = threading.Event()
        release = threading.Event()
        errors = []

        def blocked_stage(config, state, base_dir, training_options):
            self.stage(config, state, base_dir, training_options)
            entered.set()
            if not release.wait(5):
                raise AssertionError("test did not release staging")

        def prepare():
            try:
                pods.prepare(self.base, self.output, self.options)
            except BaseException as error:
                errors.append(error)

        with patch.object(pods, "_stream_to_pod", side_effect=blocked_stage):
            first = threading.Thread(target=prepare, daemon=True)
            second = threading.Thread(target=prepare, daemon=True)
            first.start()
            try:
                self.assertTrue(entered.wait(3), "first preparation did not stage inputs")
                second.start()
                second.join(0.2)
            finally:
                release.set()
                first.join(3)
                if second.ident is not None:
                    second.join(3)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertTrue(all(isinstance(error, pods.KubernetesError) for error in errors), errors)
        self.assertEqual(self.cluster.events.count("create"), 1)
        self.assertEqual(self.cluster.events.count("stage"), 1)
        self.assertNotIn("exec", self.cluster.events)
        pods.cleanup(self.base)

    def test_lost_create_acknowledgement_reconciles_the_owned_pod(self):
        original = self.cluster.invoke

        def invoke(config, args, **kwargs):
            result = original(config, args, **kwargs)
            if args[0] == "create":
                raise pods.KubernetesError("create acknowledgement lost")
            return result

        with patch.object(pods, "_invoke", side_effect=invoke):
            with self.assertRaises(pods.KubernetesError):
                pods.train_model(self.base, self.output, self.options)
        self.assertIsNone(self.cluster.pod)
        self.assertNotIn("exec", self.cluster.events)
        self.assertEqual(self.collect_calls, 0)
        self.assertEqual(self.cluster.delete_body["preconditions"]["uid"], "original-pod-identity")

    def test_lost_create_with_no_observed_pod_is_not_treated_as_success(self):
        self.cluster.failures["create"] = pods.KubernetesError("create connection lost")
        with self.assertRaises(pods.KubernetesError):
            pods.train_model(self.base, self.output, self.options)
        creations = self.cluster.events.count("create")
        self.cluster.failures.clear()
        with self.assertRaises(pods.KubernetesError):
            pods.train_model(self.base, self.output, self.options)
        self.assertEqual(self.cluster.events.count("create"), creations)
        self.assertEqual(self.collect_calls, 0)
        self.assertFalse(self.output.exists())


    def test_training_exec_has_unlimited_api_request_duration_but_finite_parent_deadline(self):
        pods.prepare(self.base, self.output, self.options)
        binary_dir = self.root / "bin"
        binary_dir.mkdir()
        executable = binary_dir / "kubectl"
        executable.write_text("\n".join([
            "#!/usr/bin/env python3", "import json, sys", "print(json.dumps(sys.argv[1:]))", "",
        ]))
        executable.chmod(0o755)
        with patch.dict(os.environ, {"PATH": str(binary_dir) + os.pathsep + os.environ["PATH"]}):
            config = self.cluster.configs[0]
            ordinary = json.loads(self.real_invoke(config, ["get", "pods"], timeout=2))
            streaming = json.loads(self.real_invoke(config, ["exec", "owned-pod", "--", "python", "train.py"], timeout=2))
        self.assertIn("--request-timeout=30s", ordinary)
        self.assertIn("--request-timeout=0", streaming)
        self.assertNotIn("--request-timeout=30s", streaming)
        pods.cleanup(self.base)

    def test_streaming_parent_deadline_terminates_a_stalled_kubectl_process(self):
        pods.prepare(self.base, self.output, self.options)
        binary_dir = self.root / "bin"
        binary_dir.mkdir()
        executable = binary_dir / "kubectl"
        executable.write_text("\n".join([
            "#!/usr/bin/env python3", "import time", "time.sleep(0.4)", "",
        ]))
        executable.chmod(0o755)
        with patch.dict(os.environ, {"PATH": str(binary_dir) + os.pathsep + os.environ["PATH"]}):
            with self.assertRaises((pods.KubernetesError, subprocess.TimeoutExpired)):
                self.real_invoke(self.cluster.configs[0], ["exec", "owned-pod", "--", "python", "train.py"], timeout=0.05)
        pods.cleanup(self.base)


    def test_rejected_second_callback_does_not_cancel_the_first_prepared_attempt(self):
        pods.prepare(self.base, self.output, self.options)
        original = copy.deepcopy(self.cluster.pod)
        with self.assertRaises(pods.KubernetesError):
            pods.train_model(self.base, self.output, self.options)
        self.assertEqual(self.cluster.pod, original)
        self.assertNotIn("delete", self.cluster.events)
        self.assertNotIn("exec", self.cluster.events)
        pods.train(self.base)
        self.assertEqual(pods.post(self.base), self.metadata)
        self.assertEqual(self.cluster.events.count("exec"), 1)


    def test_state_persistence_failure_prevents_any_pod_creation(self):
        with patch.object(pods, "_save", side_effect=OSError("attempt storage unavailable")):
            with self.assertRaises((pods.KubernetesError, OSError)):
                pods.train_model(self.base, self.output, self.options)
        self.assertNotIn("create", self.cluster.events)
        self.assertNotIn("exec", self.cluster.events)
        self.assertIsNone(self.cluster.pod)
        self.assertEqual(self.collect_calls, 0)
        self.assertFalse(self.output.exists())

    def test_failure_recording_error_does_not_skip_fencing_or_replace_training_error(self):
        original_save = pods._save
        self.cluster.failures["exec"] = pods.KubernetesError("original training failure")

        def save(*args, **kwargs):
            if "exec" in self.cluster.events:
                raise OSError("failure record could not be persisted")
            return original_save(*args, **kwargs)

        with patch.object(pods, "_save", side_effect=save):
            with self.assertRaises(pods.KubernetesError) as caught:
                pods.train_model(self.base, self.output, self.options)
        messages = []
        error = caught.exception
        while error is not None and len(messages) < 10:
            messages.append(str(error))
            error = error.__cause__ or error.__context__
        self.assertIn("original training failure", " ".join(messages))
        self.assertIsNone(self.cluster.pod)
        self.assertIn("delete", self.cluster.events)
        self.assertEqual(self.cluster.delete_body["preconditions"]["uid"], "original-pod-identity")
        self.assertEqual(self.collect_calls, 0)
        self.assertFalse(self.output.exists())


class KubernetesTransferValidationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.destination = self.root / "destination"
        self.destination.mkdir()

    def archive(self, members):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for name, content, member_type in members:
                info = tarfile.TarInfo(name)
                info.type = member_type
                if member_type == tarfile.REGTYPE:
                    info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))
                elif member_type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    info.linkname = "../outside"
                    archive.addfile(info)
                else:
                    archive.addfile(info)
        stream.seek(0)
        return stream

    def test_safe_regular_files_are_extracted_with_their_contents(self):
        stream = self.archive([("nested", b"", tarfile.DIRTYPE),
                               ("nested/model.safetensors", b"model-bytes", tarfile.REGTYPE)])
        pods._safe_extract(stream, self.destination, 128)
        self.assertEqual((self.destination / "nested/model.safetensors").read_bytes(), b"model-bytes")

    def test_absolute_and_parent_paths_cannot_escape_destination(self):
        for name in ("../outside", "nested/../../outside", "/outside"):
            with self.subTest(name=name):
                stream = self.archive([(name, b"unexpected", tarfile.REGTYPE)])
                with self.assertRaises((pods.KubernetesError, ValueError)):
                    pods._safe_extract(stream, self.destination, 128)
                self.assertFalse((self.root / "outside").exists())

    def test_links_and_special_files_are_rejected(self):
        for member_type in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            with self.subTest(member_type=member_type):
                stream = self.archive([("unsafe", b"", member_type)])
                with self.assertRaises((pods.KubernetesError, ValueError)):
                    pods._safe_extract(stream, self.destination, 128)
                self.assertFalse((self.destination / "unsafe").exists())

    def test_existing_symbolic_link_parent_cannot_redirect_extraction(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.destination / "redirect").symlink_to(outside, target_is_directory=True)
        stream = self.archive([("redirect/escaped", b"unexpected", tarfile.REGTYPE)])
        with self.assertRaises((pods.KubernetesError, ValueError)):
            pods._safe_extract(stream, self.destination, 128)
        self.assertFalse((outside / "escaped").exists())

    def test_transfer_byte_limit_applies_to_total_unpacked_contents(self):
        stream = self.archive([("first", b"1234", tarfile.REGTYPE),
                               ("second", b"5678", tarfile.REGTYPE)])
        with self.assertRaises((pods.KubernetesError, ValueError)):
            pods._safe_extract(stream, self.destination, 6)
        total = sum(path.stat().st_size for path in self.destination.rglob("*") if path.is_file())
        self.assertLessEqual(total, 6)

    def test_metadata_requires_positive_integer_example_count(self):
        for value in (None, {}, [], True, False, 0, -1, 1.5, "8"):
            with self.subTest(value=value):
                metadata = value if isinstance(value, (dict, list)) or value is None else {"num_examples": value}
                with self.assertRaises((pods.KubernetesError, ValueError)):
                    pods._validate_metadata(metadata)
        self.assertEqual(pods._validate_metadata({"num_examples": 8, "metrics": {"loss": 0.25}})["num_examples"], 8)

    def test_metadata_rejects_nonfinite_values_instead_of_emitting_invalid_json(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=repr(value)):
                with self.assertRaises((pods.KubernetesError, ValueError)):
                    pods._validate_metadata({"num_examples": 8, "metrics": {"loss": value}})

    def test_empty_output_is_not_a_checkpoint(self):
        with self.assertRaises((pods.KubernetesError, ValueError)):
            pods._validate_outputs(CHECKPOINT, self.destination, 1024 * 1024)


    def test_huge_extended_header_is_rejected_before_its_payload_is_read(self):
        header = tarfile.TarInfo("././@PaxHeader")
        header.type = tarfile.XHDTYPE
        header.size = 16 * 1024 * 1024

        class ReadGuard(io.BytesIO):
            consumed = 0

            def read(self, size=-1):
                data = super().read(size)
                self.consumed += len(data)
                if self.consumed > 64 * 1024:
                    raise AssertionError("extended-header payload was consumed without a bound")
                return data

        stream = ReadGuard(header.tobuf() + b"0" * (128 * 1024))
        with self.assertRaises((pods.KubernetesError, ValueError)):
            pods._safe_extract(stream, self.destination, 128)
        self.assertLessEqual(stream.consumed, 64 * 1024)


    def test_metadata_size_is_bounded_before_a_publishable_receipt_is_written(self):
        with self.assertRaises((pods.KubernetesError, ValueError)):
            pods._validate_metadata({"num_examples": 8, "note": "x" * (1024 * 1024 + 1)})


class KubernetesWorkerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.base = self.root / "base"
        shutil.copytree(CHECKPOINT, self.base)
        self.output = self.root / "output"
        self.options_file = self.root / "options.json"
        self.options_file.write_text(json.dumps({"num_examples": 8}))
        self.plugin = self.root / "trusted_training.py"
        self.metadata_file = self.root / "metadata.json"
        self.integrity_file = self.root / "integrity.json"

    def write_plugin(self, *, checkpoint=True, count=8):
        lines = ["import shutil", "", "def train_model(base_dir, output_dir, options):"]
        if checkpoint:
            lines.append("    shutil.copytree(base_dir, output_dir, dirs_exist_ok=True)")
        lines.append("    return " + repr({"num_examples": count, "metrics": {"loss": 0.25}}))
        self.plugin.write_text("\n".join(lines) + "\n")

    def run_worker(self):
        pods._worker(self.base, self.output, self.options_file, str(self.plugin), self.metadata_file)

    def test_worker_loads_training_code_and_records_independent_integrity_hashes(self):
        self.write_plugin()
        self.run_worker()
        metadata = json.loads(self.metadata_file.read_text())
        self.assertEqual(metadata, {"num_examples": 8, "metrics": {"loss": 0.25}})
        integrity = json.loads(self.integrity_file.read_text())
        self.assertEqual(integrity["metadata_sha256"], hashlib.sha256(self.metadata_file.read_bytes()).hexdigest())
        expected = {
            path.relative_to(self.output).as_posix(): {
                "size": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for path in self.output.rglob("*") if path.is_file()
        }
        self.assertTrue(expected)
        self.assertEqual(integrity["output_manifest"], expected)

    def test_worker_invalid_metadata_does_not_produce_publishable_result(self):
        self.write_plugin(count=0)
        with self.assertRaises((pods.KubernetesError, ValueError)):
            self.run_worker()
        self.assertFalse(self.metadata_file.exists())
        self.assertFalse(self.integrity_file.exists())

    def test_worker_without_checkpoint_does_not_produce_publishable_result(self):
        self.write_plugin(checkpoint=False)
        with self.assertRaises((pods.KubernetesError, ValueError)):
            self.run_worker()
        self.assertFalse(self.metadata_file.exists())
        self.assertFalse(self.integrity_file.exists())


    def base_manifest(self):
        return {
            path.relative_to(self.base).as_posix(): {
                "size": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for path in self.base.rglob("*") if path.is_file()
        }

    def test_worker_accepts_the_exact_staged_input_manifest(self):
        self.write_plugin()
        manifest_file = self.root / "base-manifest.json"
        manifest_file.write_text(json.dumps(self.base_manifest()))
        pods._worker(self.base, self.output, self.options_file, str(self.plugin), self.metadata_file, manifest_file)
        self.assertEqual(json.loads(self.metadata_file.read_text())["num_examples"], 8)
        self.assertTrue(self.integrity_file.exists())

    def test_worker_refuses_modified_staged_input_before_running_training_code(self):
        note = self.base / "training-note.txt"
        note.write_text("verified input")
        manifest_file = self.root / "base-manifest.json"
        manifest_file.write_text(json.dumps(self.base_manifest()))
        note.write_text("changed input")
        self.write_plugin()
        marker = self.root / "training-started"
        code = self.plugin.read_text()
        code = "from pathlib import Path\n" + code.replace(
            "    shutil.copytree", "    Path(" + repr(str(marker)) + ").write_text('started')\n    shutil.copytree", 1,
        )
        self.plugin.write_text(code)
        with self.assertRaises((pods.KubernetesError, ValueError)):
            pods._worker(self.base, self.output, self.options_file, str(self.plugin), self.metadata_file, manifest_file)
        self.assertFalse(marker.exists())
        self.assertFalse(self.metadata_file.exists())
        self.assertFalse(self.integrity_file.exists())


class KubernetesCollectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.destination = self.root / "collected"
        self.destination.mkdir()
        self.config = {
            "kubeconfig": "/not-used-by-fake-process",
            "context": "org-a-cluster",
            "namespace": "org-a-study",
            "request_timeout_seconds": 30,
            "readiness_timeout_seconds": 5,
            "max_transfer_bytes": 1024 * 1024,
        }
        self.state = {"pod_name": "owned-pod"}
        self.metadata = {"num_examples": 8, "metrics": {"loss": 0.25}}

    def archive(self, corruption=None):
        files = {path.relative_to(CHECKPOINT).as_posix(): path.read_bytes()
                 for path in CHECKPOINT.rglob("*") if path.is_file()}
        files["trainer-note.txt"] = b"verified training output"
        metadata = (json.dumps(self.metadata, sort_keys=True) + "\n").encode()
        integrity = {
            "metadata_sha256": hashlib.sha256(metadata).hexdigest(),
            "output_manifest": {
                name: {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                for name, content in files.items()
            },
        }
        if corruption == "metadata":
            metadata = (json.dumps({"num_examples": 999}) + "\n").encode()
        if corruption == "output":
            files["trainer-note.txt"] = b"modified training output"
        archive_stream = io.BytesIO()
        with tarfile.open(fileobj=archive_stream, mode="w") as archive:
            entries = {"metadata.json": metadata}
            if corruption != "missing-integrity":
                entries["integrity.json"] = json.dumps(integrity).encode()
            entries.update({"output/" + name: content for name, content in files.items()})
            for name, content in entries.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        return archive_stream.getvalue(), files

    def collect(self, corruption=None):
        data, files = self.archive(corruption)

        class Process:
            returncode = 0

            def __init__(self):
                self.stdout = io.BytesIO(data)

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                return self.returncode

            def kill(self):
                self.returncode = -9

        process = Process()
        with patch.object(pods.subprocess, "Popen", return_value=process) as popen:
            result = pods._collect(self.config, self.state, self.destination)
        command = popen.call_args.args[0]
        self.assertIn("--request-timeout=0", command)
        return result, files

    def test_verified_output_and_metadata_are_collected_without_control_files(self):
        result, expected = self.collect()
        self.assertEqual(result, self.metadata)
        actual = {path.relative_to(self.destination).as_posix(): path.read_bytes()
                  for path in self.destination.rglob("*") if path.is_file()}
        self.assertEqual(actual, expected)
        self.assertNotIn("metadata.json", actual)
        self.assertNotIn("integrity.json", actual)

    def test_changed_metadata_is_rejected(self):
        with self.assertRaises((pods.KubernetesError, ValueError, OSError)):
            self.collect("metadata")

    def test_changed_checkpoint_tree_is_rejected(self):
        with self.assertRaises((pods.KubernetesError, ValueError, OSError)):
            self.collect("output")

    def test_missing_integrity_manifest_is_rejected(self):
        with self.assertRaises((pods.KubernetesError, ValueError, OSError)):
            self.collect("missing-integrity")


if __name__ == "__main__":
    unittest.main()
