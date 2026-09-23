"""FedAvg application contracts and a real v2 service round with verified transfers."""
from __future__ import annotations

import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import torch
from safetensors.torch import load_file, save_file

from hf2l.backends.base import (BackendCapabilities, ClaimHandle, PublicationConsistency,
                                PublicationUncertain, ResolvedReference, RoundContext)
from hf2l.backends.huggingface import HuggingFaceStore
from hf2l.backends.jfrog import JFrogStore
from hf2l.fedavg_runner import ClaimRenewal, FedAvgRunner, RunState
from hf2l.hub_helpers import ROUND_FILE, SUBMISSION_FILE, artifact_hashes, regular_file_paths, write_json


class BackendContractTests(unittest.TestCase):
    def test_huggingface_primary_commit_survives_tag_failure_and_concurrent_advance(self):
        store = HuggingFaceStore(None)
        store.api = Mock()
        store.api.create_commit.return_value = SimpleNamespace(oid="published", commit_url="url")
        store.api.create_tag.side_effect = RuntimeError("tag exists")
        result = store.publish_aggregate("repo", Path("."), [], expected_base="base", next_round=1, tag="round1")
        self.assertEqual(result.revision, "published")
        self.assertFalse(result.tag_created)
        self.assertIn("tag", result.warnings[0])
        store.api.model_info.assert_not_called()
        self.assertEqual(store.api.create_commit.call_args.kwargs["parent_commit"], "base")

    def test_huggingface_lost_primary_response_is_uncertain(self):
        store = HuggingFaceStore(None)
        store.api = Mock()
        store.api.create_commit.side_effect = ConnectionError("lost reply")
        with self.assertRaises(PublicationUncertain):
            store.publish_aggregate("repo", Path("."), [], expected_base="base", next_round=1, tag=None)

    def test_jfrog_primary_success_and_tag_failure_are_separate(self):
        store = object.__new__(JFrogStore)
        store.resolve_revision = Mock(side_effect=["base", "published"])
        store._upload_folder = Mock(side_effect=[None, RuntimeError("tag failed")])
        with tempfile.TemporaryDirectory() as folder:
            result = store.publish_aggregate("repo", Path(folder), [], expected_base="base", next_round=1, tag="round1")
        self.assertEqual(result.revision, "published")
        self.assertFalse(result.tag_created)
        self.assertEqual(store.capabilities.publication, PublicationConsistency.PREFLIGHT)

    def test_jfrog_uncertain_primary_is_not_reported_as_failed(self):
        store = object.__new__(JFrogStore)
        store.resolve_revision = Mock(return_value="base")
        store._upload_folder = Mock(side_effect=TimeoutError())
        with tempfile.TemporaryDirectory() as folder, self.assertRaises(PublicationUncertain):
            store.publish_aggregate("repo", Path(folder), [], expected_base="base", next_round=1, tag=None)

    def test_legacy_publishers_reject_claims_instead_of_ignoring_them(self):
        for store in (HuggingFaceStore(None), object.__new__(JFrogStore)):
            with self.subTest(backend=store.name), self.assertRaisesRegex(ValueError, "fenced coordination"):
                store.publish_aggregate("repo", Path("."), [], expected_base="base", next_round=1,
                                        tag=None, claim=object())

    def test_claim_reference_name_is_part_of_ownership(self):
        from hf2l.backends.exchange import ExchangeStore
        from hf2l_exchange.client_types import CoordinationHandle
        value = CoordinationHandle("attempt", "other", "7", "owner", 1, "active", time.time() + 10)
        with self.assertRaisesRegex(ValueError, "different reference"):
            ExchangeStore._claim(value, ResolvedReference("base", token="7"))

    def test_runner_cannot_reuse_completed_ownership_for_another_round(self):
        runner = FedAvgRunner(Mock())
        runner._execute = Mock()
        runner.run(SimpleNamespace())
        with self.assertRaisesRegex(RuntimeError, "new FedAvgRunner"):
            runner.run(SimpleNamespace())
        runner._execute.assert_called_once()

    def test_postpublication_state_cleanup_failure_preserves_success(self):
        store = Mock()
        runner = FedAvgRunner(store)
        runner.run_state = Mock()
        runner.run_state.clear.side_effect = OSError("disk unavailable")
        runner.renewal = Mock()
        with contextlib.redirect_stderr(io.StringIO()) as messages:
            runner._publication_succeeded()
        self.assertTrue(runner.published)
        self.assertEqual(messages.getvalue(), "")
        self.assertTrue(any("publication succeeded" in warning for warning in runner.warnings))
        store.abandon_claim.assert_not_called()
        runner.renewal.close.assert_called_once()

    def test_required_concurrent_guarantee_rejected_before_output_or_download(self):
        store = Mock(name="jfrog")
        store.name = "jfrog"
        store.capabilities = BackendCapabilities(PublicationConsistency.PREFLIGHT)
        options = SimpleNamespace(publish=True, claim_submissions=False, claim_id=None, tag=None,
                                  check_only=False, require_concurrent_publication=True)
        with self.assertRaisesRegex(ValueError, "preflight-only"):
            FedAvgRunner(store).run(options)
        store.resolve_reference.assert_not_called()
        store.download_snapshot.assert_not_called()

    def test_run_state_recovers_acquisition_identity_and_rejects_another_round(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            context = RoundContext("space", ResolvedReference("base", token="7"), 0)
            first = RunState(path)
            saved = first.acquire(context, lease_seconds=10)
            competing = RunState(path)
            with self.assertRaisesRegex(ValueError, "Another coordinator"):
                competing.acquire(context)
            first.close()
            restarted = RunState(path)
            try:
                recovered = restarted.acquire(context, lease_seconds=3600)
                self.assertEqual(recovered["acquisition_key"], saved["acquisition_key"])
                self.assertEqual(recovered["lease_seconds"], 10)
            finally:
                restarted.close()
            different = RunState(path)
            try:
                with self.assertRaisesRegex(ValueError, "different round"):
                    different.acquire(RoundContext("space", ResolvedReference("new", token="8"), 1))
            finally:
                different.close()

    def test_lease_renewal_failure_stops_runner_publication(self):
        store, state = Mock(), Mock()
        claim = ClaimHandle("attempt", 3, ResolvedReference("base", token="7"), ("one", "two"), time.time() + 10, None)
        attempted = threading.Event()
        def lost(*_):
            attempted.set()
            raise ValueError("fence lost")
        store.renew_claim.side_effect = lost
        renewal = ClaimRenewal(store, "space", claim, 10, state, interval=.01)
        renewal.start()
        self.assertTrue(attempted.wait(2))
        renewal.close()
        runner = FedAvgRunner(store)
        runner.renewal = renewal
        with self.assertRaisesRegex(RuntimeError, "publication is stopped"):
            runner._check_lease()
        store.publish_aggregate.assert_not_called()

    def test_changed_fence_is_not_accepted_as_renewal(self):
        store, state = Mock(), Mock()
        reference = ResolvedReference("base", token="7")
        claim = ClaimHandle("attempt", 3, reference, (), time.time() + 10, None)
        store.renew_claim.return_value = ClaimHandle("attempt", 4, reference, (), time.time() + 10, None)
        renewal = ClaimRenewal(store, "space", claim, 10, state, interval=.01)
        renewal.start()
        self.assertTrue(renewal.stopped.wait(2))
        renewal.close()
        with self.assertRaises(RuntimeError):
            renewal.check()
        state.remember.assert_not_called()


# Load the shared isolated-resource fixture without coupling application production
# code to the independently packaged service's test modules.
_fixture = Path(__file__).resolve().parents[1] / "packages/exchange/tests/support.py"
_spec = importlib.util.spec_from_file_location("fedavg_exchange_test_support", _fixture)
_support = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_support)


class FedAvgServiceTests(_support.ExchangeTestCase):
    def sdk(self, subject):
        from hf2l_exchange.client import ExchangeClient
        from hf2l_exchange.worker import tick
        client = ExchangeClient("http://127.0.0.1", self.auth(subject)["Authorization"].split(" ", 1)[1],
                                http=self.client, allow_local_http=True, sleep=lambda _: tick(self.transfers))
        self.addCleanup(client.close)
        return client

    def test_full_fenced_round_verifies_files_and_publishes_weighted_result(self):
        from hf2l.backends.exchange import ExchangeStore
        from hf2l.owner_fedavg import main
        from hf2l_exchange.client import ExchangeError

        space = self.new_space("fedavg", profile="fedavg.v1")
        sid = space["id"]
        self.member("alice", ["reader", "contributor"], {"participant": "alice"}, space=sid)
        self.member("bob", ["reader", "contributor"], {"participant": "bob"}, space=sid)
        self.member("carol", ["reader", "contributor"], {"participant": "carol"}, space=sid)
        self.member("dave", ["reader", "contributor"], {"participant": "dave"}, space=sid)
        self.register_type("model.global", publish_roles=["publisher"], space=sid)
        self.register_type("training.update", visibility="private", publish_roles=["contributor"], space=sid)
        owner = ExchangeStore(None, None, client=self.sdk("owner"), wait_seconds=15)
        initial = self.directory / "initial"
        initial.mkdir()
        save_file({"weight": torch.tensor([0.0])}, initial / "model.safetensors")
        write_json(initial / "config.json", {"model_type": "test"})
        write_json(initial / ROUND_FILE, {"schema_version": 2, "backend": "exchange", "round": 0,
            "checkpoint_files_sha256": artifact_hashes(initial, ["config.json", "model.safetensors"])})
        base = owner.initialize_repository(sid, initial, private=True).revision
        submitted, rejected = [], []
        for name, count in (("alice", 1), ("bob", 3), ("dave", 9)):
            folder = self.directory / name
            folder.mkdir()
            save_file({"weight": torch.tensor([float(count)] * (2 if name == "dave" else 1))}, folder / "model.safetensors")
            write_json(folder / "config.json", {"model_type": "test"})
            write_json(folder / SUBMISSION_FILE, {
                "schema_version": 2, "backend": "exchange", "repo_id": sid, "base_revision": base,
                "source_round": 0, "participant": name, "num_examples": count,
                "checkpoint_files_sha256": artifact_hashes(folder, ["config.json", "model.safetensors"]),
            })
            client = ExchangeStore(None, None, client=self.sdk(name), wait_seconds=15)
            (rejected if name == "dave" else submitted).append(client.publish_submission(sid, folder, regular_file_paths(folder), participant=name,
                source_round=0, base_revision=base, submission_revision=None).revision)
        # A published update with an unusable manifest must not permanently wedge
        # the round. Its server metadata is valid, but it cannot be aggregated.
        revision = next(item for item in owner.client.types(sid) if item.kind == "training.update")
        malformed = self.sdk("carol").put_record(sid, kind="training.update", schema_revision_id=revision.id,
            metadata={"base_record_id": base, "sample_count": 5, "hf2l_files": {}})
        context = RoundContext(sid, owner.resolve_reference(sid), 0)
        # Discovery works on a fresh adapter without a preceding resolve call on that instance.
        observer = ExchangeStore(None, None, client=self.sdk("owner"))
        found, _ = observer.discover_submissions(sid, context=context)
        self.assertEqual({item.revision for item in found}, set(submitted + rejected) | {malformed.id})
        argv = ["owner_fedavg", "--backend", "exchange", "--repo-id", sid, "--claim-submissions",
                "--claim-lease-seconds", "10", "--output-dir", str(self.directory / "output"), "--publish", "--tag", "round1"]
        with patch("sys.argv", argv), patch("hf2l.owner_fedavg.make_store", return_value=owner):
            with contextlib.redirect_stdout(io.StringIO()):
                main()
        reference = owner.client.resolve(sid, "main")
        self.assertNotEqual(reference.record_id, base)
        result = owner.client.get_record(sid, reference.record_id)
        self.assertEqual(set(result.metadata["inputs"]), set(submitted))
        downloaded = self.directory / "result"
        observer.download_snapshot(sid, result.id, downloaded)
        torch.testing.assert_close(load_file(downloaded / "model.safetensors")["weight"], torch.tensor([2.5]))
        self.assertEqual(owner.client.resolve(sid, "round1").record_id, result.id)
        self.assertFalse((self.directory / "output.run-state.json").exists())
        with self.assertRaises(ExchangeError) as caught:
            owner.client.set_ref(sid, "main", result.id, reference=reference)
        self.assertEqual(caught.exception.code, "coordination_required")


if __name__ == "__main__":
    unittest.main()
