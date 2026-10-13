"""Managed runtime safety and real CPU FedAvg integration tests.

The injected LocalStore is a deterministic test transport, never a production
fallback. Plugin/training/aggregation here execute the real LeNet implementation.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from hf2l_jobs.domain import JobSpec
from hf2l_jobs.workflow import RuntimeConfig
from hf2l_jobs.runtime import (
    InitializationUncertain, RuntimeSafetyError, TargetRoundReached,
    _load_plugin, _main_document, _verify_source,
    initialize_once, make_listener, run_worker,
)
try:
    import torch
    import safetensors
    from hf2l.backends.local import LocalStore
except ImportError as exc:
    if os.environ.get("JOBS_REQUIRE_RUNTIME_TESTS") == "1":
        raise
    raise unittest.SkipTest("Runtime integration requires sandbox HF2L CPU training extras") from exc
from hf2l.common.fs import read_json
from hf2l.core.protocol import ROUND_FILE
from hf2l.listener.engine import UncertainOperation

SOURCE = Path(__file__).resolve().parents[3]


class ManagedRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.storage = self.root / "storage"
        self.stores = []

    def store(self, principal="owner"):
        store = LocalStore(self.storage, principal)
        self.stores.append(store)
        self.addCleanup(store.close)
        return store

    def config(self, job="job-a", role="owner", participant=None, target=1, seed=7, epoch=1):
        spec = JobSpec.model_validate({
            "project_id": "test", "name": job, "source_id": "approved-source",
            "source_commit": "a" * 40, "runtime_image": "approved-cpu",
            "plugin": "lenet", "options": {
                "seed": seed, "epochs": 1, "synthetic_examples": 8,
                "batch_size": 4, "learning_rate": 0.02, "device": "cpu",
                "minimum_participants": 2,
            },
            "participants": [
                {"participant_id": "alice", "dataset_binding": "synthetic"},
                {"participant_id": "bob", "dataset_binding": "synthetic"},
            ],
            "components": [{"component_id": "owner", "role": "owner", "resources": {
                "pool_id": "cpu", "cpu_millicores": 1000,
                "memory_bytes": 1 << 30, "disk_bytes": 1 << 30}}],
            "target_round": target, "max_duration_seconds": 60,
        })
        return RuntimeConfig.model_validate({
            "role": role, "job_id": job, "attempt_id": "attempt-" + str(epoch),
            "component_id": "owner" if participant is None else "client-" + participant,
            "participant_id": participant, "space_id": job, "epoch": epoch,
            "spec": spec.to_dict(), "spec_digest": spec.digest,
            "source_dir": str(SOURCE), "state_dir": str(self.root / job / (participant or "owner")),
            "participant_principals": {"alice": "alice", "bob": "bob"},
            "dataset_bindings": {"synthetic": {"kind": "synthetic"}},
        })

    def step(self, config, store):
        with redirect_stdout(StringIO()):
            return run_worker(config, store=store, once=True)

    def test_large_source_manifest_has_bounded_stable_complete_listener_identity(self):
        from types import SimpleNamespace
        from hf2l_jobs.domain import canonical_json
        manifest = {f"package/module_{index:04d}.py": hashlib.sha256(str(index).encode()).hexdigest()
                    for index in range(395)}
        plugin = SimpleNamespace(train_model=lambda *args, **kwargs: None)
        for role, participant in (("owner", None), ("client", "alice")):
            with self.subTest(role=role):
                payload = self.config(role=role, participant=participant).to_dict()
                payload["source_manifest"] = manifest
                config = RuntimeConfig.model_validate(payload)
                self.assertGreater(len(canonical_json(config.durable_binding)), 4096)
                self.assertEqual(dict(config.source_manifest), manifest)
                self.assertEqual(config.durable_binding["source_manifest"], manifest)
                self.assertLess(len(config.source_identity), 4096)
                payload["source_manifest"] = dict(reversed(list(manifest.items())))
                reordered = RuntimeConfig.model_validate(payload)
                self.assertEqual(config.source_identity, reordered.source_identity)
                changed = dict(manifest)
                changed["package/module_0000.py"] = "e" * 64
                payload["source_manifest"] = changed
                self.assertNotEqual(config.source_identity, RuntimeConfig.model_validate(payload).source_identity)
                store = self.store(participant or "owner")
                with make_listener(store, config, plugin=plugin) as listener:
                    self.assertEqual(listener.state["identity"], listener.identity)
                with make_listener(store, reordered, plugin=plugin):
                    pass

    def test_legacy_raw_json_listener_identity_refused_without_mutating_state(self):
        from types import SimpleNamespace
        from hf2l.common.fs import write_json
        from hf2l.listener.engine import ListenerStateError
        from hf2l_jobs.domain import canonical_json
        plugin = SimpleNamespace(train_model=lambda *args, **kwargs: None)
        for role, participant in (("owner", None), ("client", "alice")):
            with self.subTest(role=role):
                config = self.config(role=role, participant=participant)
                store = self.store(participant or "owner")
                with make_listener(store, config, plugin=plugin):
                    pass
                path = Path(config.state_dir) / "listener/state.json"
                legacy = read_json(path)
                legacy["identity"]["source_hash"] = hashlib.sha256(
                    canonical_json(config.durable_binding).encode("utf-8")).hexdigest()
                write_json(path, legacy)
                before = path.read_bytes()
                with self.assertRaisesRegex(ListenerStateError, "different role, source"):
                    with make_listener(store, config, plugin=plugin):
                        self.fail("legacy listener identity must require explicit recovery")
                self.assertEqual(path.read_bytes(), before)

    def test_two_real_jobs_do_not_share_models_state_or_completion(self):
        owners = {job: self.config(job, target=2, seed=seed) for job, seed in (("job-a", 7), ("job-b", 9))}
        owner_store = self.store()
        for config in owners.values():
            self.assertEqual(self.step(config, owner_store), 0)
            self.assertEqual(_main_document(owner_store, config)[1]["round"], 0)
        initial_hashes = {job: _main_document(owner_store, config)[1]["checkpoint_files_sha256"]
                          for job, config in owners.items()}
        self.assertNotEqual(initial_hashes["job-a"], initial_hashes["job-b"])
        for round_number in (1, 2):
            for job, config in owners.items():
                for participant in ("alice", "bob"):
                    self.assertEqual(self.step(self.config(job, "client", participant, target=2,
                                                          seed=7 if job == "job-a" else 9),
                                               self.store(participant)), 0)
                self.assertEqual(self.step(config, owner_store), 0)
                document = _main_document(owner_store, config)[1]
                self.assertEqual(document["round"], round_number)
                self.assertEqual({s["participant"] for s in document["submissions"]}, {"alice", "bob"})
                self.assertEqual(sum(s["num_examples"] for s in document["submissions"]), 16)
        for job, config in owners.items():
            completed = _main_document(owner_store, config)
            # Infrastructure retry rotates attempt/epoch while preserving identity.
            resumed = self.config(job, target=2, seed=7 if job == "job-a" else 9, epoch=2)
            self.assertEqual(self.step(resumed, owner_store), 0)
            self.assertEqual(_main_document(owner_store, config), completed)
            for participant in ("alice", "bob"):
                client = self.config(job, "client", participant, target=2,
                                     seed=7 if job == "job-a" else 9, epoch=2)
                self.assertEqual(self.step(client, self.store(participant)), 0)
                status = read_json(Path(client.state_dir) / "runtime-status.json")
                self.assertEqual(set(status["metrics"]), {"local_loss", "local_accuracy"})
                self.assertEqual(status["readiness"], "finished")
                self.assertEqual(_main_document(owner_store, config), completed)
            self.assertEqual(read_json(Path(config.state_dir) / "progress.json")["phase"], "completed")
            self.assertNotEqual(completed[1]["checkpoint_files_sha256"], initial_hashes[job])

    def test_initial_accepted_publication_lost_ack_is_reconciled_without_reinitializing(self):
        config, store = self.config(), self.store()
        original = store.initialize_repository
        calls = []
        def accepted(*args, **kwargs):
            calls.append(1)
            original(*args, **kwargs)
            raise TimeoutError("accepted but acknowledgment lost")
        with patch.object(store, "initialize_repository", side_effect=accepted):
            with self.assertRaises(InitializationUncertain):
                initialize_once(store, config)
        before = _main_document(store, config)
        revision = initialize_once(store, config)
        self.assertEqual(revision, before[0])
        self.assertEqual(len(calls), 1)
        self.assertEqual(_main_document(store, config), before)
        self.assertTrue(read_json(Path(config.state_dir) / "initialization.json")["reconciled"])

    def test_unknown_initial_publication_does_not_blindly_retry(self):
        config, store = self.config(), self.store()
        with patch.object(store, "initialize_repository", side_effect=TimeoutError("unknown")) as publish:
            with self.assertRaises(InitializationUncertain):
                initialize_once(store, config)
            with self.assertRaises(InitializationUncertain):
                initialize_once(store, config)
            self.assertEqual(publish.call_count, 1)

    def test_attempt_rotation_does_not_allow_changed_specification(self):
        config, store = self.config(), self.store()
        initialize_once(store, config)
        with self.assertRaises(RuntimeSafetyError):
            initialize_once(store, self.config(seed=99, epoch=2))

    def test_initial_intent_detects_modified_checkpoint(self):
        config, store = self.config(), self.store()
        with patch.object(store, "initialize_repository", side_effect=TimeoutError()):
            with self.assertRaises(InitializationUncertain):
                initialize_once(store, config)
        weight = Path(config.state_dir) / "initial-model/model.safetensors"
        weight.write_bytes(weight.read_bytes() + b"changed")
        with self.assertRaises(InitializationUncertain):
            initialize_once(store, config)

    def test_source_manifest_and_job_state_are_checked_before_plugin_import(self):
        config = self.config()
        bad = config.model_copy(update={"source_manifest": {"README.md": "0" * 64}})
        with self.assertRaises(RuntimeSafetyError):
            _verify_source(bad)
        with self.assertRaises(RuntimeSafetyError):
            _load_plugin(bad)

    def test_runtime_contract_rejects_foreign_dataset_component_and_spec(self):
        config = self.config()
        payload = config.to_dict()
        payload["spec_digest"] = "0" * 64
        with self.assertRaises(ValueError):
            RuntimeConfig.model_validate(payload)
        payload = self.config(role="client", participant="alice").to_dict()
        payload["dataset_bindings"] = {}
        with self.assertRaises(ValueError):
            RuntimeConfig.model_validate(payload)
        payload = config.to_dict()
        payload["component_id"] = "client-alice"
        with self.assertRaises(ValueError):
            RuntimeConfig.model_validate(payload)

    def test_relative_source_and_proxy_paths_are_rejected(self):
        payload = self.config().to_dict()
        payload["source_dir"] = "../other-job"
        with self.assertRaises(ValueError):
            RuntimeConfig.model_validate(payload)
        payload = self.config().to_dict()
        payload["proxy_socket"] = "socket"
        with self.assertRaises(ValueError):
            RuntimeConfig.model_validate(payload)

    def test_unapproved_dataset_option_is_rejected(self):
        config = self.config(role="client", participant="alice")
        payload = config.to_dict()
        payload["spec"]["options"]["dataset_npz"] = "/other-job/data.npz"
        payload["spec_digest"] = JobSpec.model_validate(payload["spec"]).digest
        changed = RuntimeConfig.model_validate(payload)
        from hf2l_jobs.runtime import _training_options
        with self.assertRaises(RuntimeSafetyError):
            _training_options(changed)

    def proof(self, config, role, document, action, record=None):
        from hf2l_jobs.workflow import publication_intent_fingerprint
        return {
            "role": role, "action": action,
            "intent_sha256": publication_intent_fingerprint(role, document),
            "old_attempt_id": config.attempt_id, "old_epoch": config.epoch,
            "revocation_operation_id": "revoke-confirmed", "termination_operation_id": "stopped-confirmed",
            "grants_revoked": True, "termination_confirmed": True, "record_id": record,
        }

    def recovered(self, config, proof):
        payload = config.to_dict()
        payload.update(attempt_id="attempt-2", epoch=2, reconciliation=[proof])
        return RuntimeConfig.model_validate(payload)

    def pending_client(self, accepted=False):
        owner = self.config()
        self.step(owner, self.store())
        config, store = self.config(role="client", participant="alice"), self.store("alice")
        original = store.publish_submission
        results = []
        def unknown(*args, **kwargs):
            if accepted:
                results.append(original(*args, **kwargs))
            raise TimeoutError("unknown acknowledgment")
        with patch.object(store, "publish_submission", side_effect=unknown):
            self.assertEqual(self.step(config, store), 4)
        state = read_json(Path(config.state_dir) / "listener/state.json")
        job = state["jobs"][state["active"]]
        work = Path(config.state_dir) / "listener/jobs" / hashlib.sha256(job["revision"].encode()).hexdigest() / "work"
        return config, store, state, work, results

    def test_confirmed_client_reconciliation_preserves_submission_and_final_metrics(self):
        config, store, state, work, results = self.pending_client(accepted=True)
        intent = read_json(work / "client-publication-intent.json")
        recovered = self.recovered(config, self.proof(config, "client", intent, "confirmed", (results[0].resolved_revision or results[0].revision)))
        with patch.object(store, "publish_submission", side_effect=AssertionError("must not repeat publication")):
            self.assertEqual(self.step(recovered, store), 0)
        latest = read_json(Path(config.state_dir) / "listener/state.json")
        self.assertEqual(latest["jobs"][state["active"]]["status"], "submitted")

    def test_absent_client_reconciliation_reuses_exact_retained_manifest(self):
        config, store, state, work, _ = self.pending_client()
        intent = read_json(work / "client-publication-intent.json")
        before = (work / "trained_model/fedavg_submission.json").read_bytes()
        recovered = self.recovered(config, self.proof(config, "client", intent, "absent"))
        with patch.object(store, "new_submission_revision", side_effect=AssertionError("must reuse")):
            self.assertEqual(self.step(recovered, store), 0)
        self.assertEqual((work / "trained_model/fedavg_submission.json").read_bytes(), before)

    def test_wrong_client_intent_or_record_cannot_clear_unknown_submission(self):
        config, store, state, work, results = self.pending_client(accepted=True)
        intent = read_json(work / "client-publication-intent.json")
        proof = self.proof(config, "client", intent, "confirmed", (results[0].resolved_revision or results[0].revision))
        proof["intent_sha256"] = "0" * 64
        with self.assertRaises(RuntimeSafetyError):
            self.step(self.recovered(config, proof), store)
        latest = read_json(Path(config.state_dir) / "listener/state.json")
        self.assertEqual(latest["jobs"][state["active"]]["status"], "uncertain")

    def pending_owner(self, accepted=False):
        config, store = self.config(), self.store()
        self.step(config, store)
        for participant in ("alice", "bob"):
            self.step(self.config(role="client", participant=participant), self.store(participant))
        original = store.publish_aggregate
        results = []
        def unknown(*args, **kwargs):
            if accepted:
                results.append(original(*args, **kwargs))
            raise TimeoutError("unknown aggregate acknowledgment")
        with patch.object(store, "publish_aggregate", side_effect=unknown):
            self.assertEqual(self.step(config, store), 4)
        state = read_json(Path(config.state_dir) / "listener/state.json")
        job = state["jobs"][state["active"]]
        return config, store, job, results

    def test_absent_owner_reconciliation_publishes_identical_aggregate_without_rerun(self):
        config, store, job, _ = self.pending_owner()
        manifest = Path(job["publication_intent"]["aggregate_dir"]) / ROUND_FILE
        before = manifest.read_bytes()
        recovered = self.recovered(config, self.proof(config, "owner", job, "absent"))
        with patch("hf2l.listener.owner.run_round", side_effect=AssertionError("must not reaggregate")):
            self.assertEqual(self.step(recovered, store), 0)
        self.assertEqual(manifest.read_bytes(), before)
        self.assertEqual(_main_document(store, config)[1], read_json(manifest))

    def test_confirmed_owner_reconciliation_clears_fence_only_for_exact_main_record(self):
        config, store, job, results = self.pending_owner(accepted=True)
        recovered = self.recovered(config, self.proof(config, "owner", job, "confirmed", (results[0].resolved_revision or results[0].revision)))
        with patch.object(store, "publish_aggregate", side_effect=AssertionError("must not republish")):
            self.assertEqual(self.step(recovered, store), 0)
        self.assertEqual(_main_document(store, config)[1]["round"], 1)

    def test_absent_initial_reconciliation_preserves_initial_manifest(self):
        config, store = self.config(), self.store()
        with patch.object(store, "initialize_repository", side_effect=TimeoutError()):
            with self.assertRaises(InitializationUncertain):
                initialize_once(store, config)
        before = (Path(config.state_dir) / "initial-model" / ROUND_FILE).read_bytes()
        document = read_json(Path(config.state_dir) / "initialization.json")
        recovered = self.recovered(config, self.proof(config, "init", document, "absent"))
        initialize_once(store, recovered)
        self.assertEqual((Path(config.state_dir) / "initial-model" / ROUND_FILE).read_bytes(), before)

    def test_reconciliation_requires_old_attempt_and_explicit_fencing(self):
        config = self.config()
        from hf2l_jobs.workflow import PublicationResolution
        valid = self.proof(config, "init", {"binding": {}, "manifest_sha256": "a",
                                          "checkpoint_files_sha256": {}}, "absent")
        for field in ("grants_revoked", "termination_confirmed"):
            bad = {**valid, field: 1}
            with self.assertRaises(ValueError):
                PublicationResolution.model_validate(bad)
        payload = config.to_dict()
        payload["reconciliation"] = [valid]
        with self.assertRaises(ValueError):
            RuntimeConfig.model_validate(payload)


    def secret_config(self):
        payload = self.config().to_dict()
        payload["spec"]["secret_refs"] = {"private_opt": "approved-secret"}
        payload["spec_digest"] = JobSpec.model_validate(payload["spec"]).digest
        payload["secret_options_file"] = "/run/hf2l/secrets.json"
        payload["secret_option_names"] = ["private_opt"]
        return RuntimeConfig.model_validate(payload)

    def secret_manifest(self, config):
        return {"schema_version": 1, "job_id": config.job_id, "attempt_id": config.attempt_id,
                "component_id": config.component_id, "epoch": config.epoch, "role": "owner",
                "options": {"private_opt": "synthetic-private-test-value"},
                "references": {"private_opt": "approved-secret"}}

    def test_secret_options_are_job_bound_and_not_persisted_in_identity(self):
        from hf2l_jobs.runtime import _training_options
        from hf2l.common.fs import write_json
        config = self.secret_config()
        path = self.root / "private-options.json"
        write_json(path, self.secret_manifest(config))
        path.chmod(0o400)
        with patch("hf2l_jobs.runtime._safe", return_value=path):
            options = _training_options(config)
        self.assertEqual(options["private_opt"], "synthetic-private-test-value")
        import json
        self.assertNotIn("synthetic-private-test-value", json.dumps(config.durable_binding))
        self.assertNotIn("synthetic-private-test-value", json.dumps(config.to_dict()))

    def test_other_attempt_secret_manifest_cannot_be_used(self):
        from hf2l_jobs.runtime import _training_options
        from hf2l.common.fs import write_json
        config = self.secret_config()
        document = self.secret_manifest(config)
        document["attempt_id"] = "foreign-attempt"
        path = self.root / "private-options.json"
        write_json(path, document)
        with patch("hf2l_jobs.runtime._safe", return_value=path):
            with self.assertRaises(RuntimeSafetyError):
                _training_options(config)

    def test_secret_config_cannot_override_dataset_binding(self):
        payload = self.secret_config().to_dict()
        payload["spec"]["secret_refs"] = {"dataset_npz": "approved-secret"}
        payload["spec_digest"] = JobSpec.model_validate(payload["spec"]).digest
        payload["secret_option_names"] = ["dataset_npz"]
        config = RuntimeConfig.model_validate(payload)
        document = self.secret_manifest(config)
        document["options"] = {"dataset_npz": "/foreign-job/data.npz"}
        document["references"] = {"dataset_npz": "approved-secret"}
        from hf2l_jobs.runtime import _training_options
        from hf2l.common.fs import write_json
        path = self.root / "private-options.json"
        write_json(path, document)
        with patch("hf2l_jobs.runtime._safe", return_value=path):
            with self.assertRaises(RuntimeSafetyError):
                _training_options(config)



if __name__ == "__main__":
    unittest.main()
