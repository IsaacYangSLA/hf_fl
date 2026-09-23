"""Complete v3 rounds across the application, stores, SDK, and tensor boundary."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hf2l.backends.local import LocalStore
from hf2l.client_steps import download_client_round, upload_client_update
from hf2l.core.protocol import AlgorithmSpec
from hf2l.fedavg_runner import run_round
from hf2l.hub_helpers import CLIENT_CONTEXT_FILE, ROUND_FILE, regular_file_paths
from hf2l.round.aggregator import AGGREGATORS, FedAvg
from hf2l.round.config import RoundConfig
from tests.support.v3_helpers import checkpoint_value, initialize_model, write_checkpoint


class LocalV3EndToEndTests(unittest.TestCase):
    """No credentials, services, mocks of persistence, or training framework."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hf2l-v3-integration-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / "store"
        self.repo = "federated-model"
        self.owner = LocalStore(self.root, "owner")
        initial = initialize_model(self.directory / "initial", "local")
        self.base = self.owner.initialize_repository(self.repo, initial, private=True).revision

    def submit(self, participant: str, value: float, examples: int):
        store = LocalStore(self.root, participant)
        work = self.directory / participant
        context = download_client_round(store, self.repo, self.base, work)
        trained = write_checkpoint(work / "trained_model", value)
        publication, manifest = upload_client_update(store, work, trained, participant, examples)
        return publication, manifest, context

    def test_local_round_preserves_immutable_inputs_and_advances_main_once(self):
        reference = self.owner.resolve_reference(self.repo)
        alice, alice_manifest, alice_context = self.submit("alice", 1.0, 1)
        bob, bob_manifest, bob_context = self.submit("bob", 3.0, 3)
        self.assertEqual(self.owner.resolve_reference(self.repo), reference)
        self.assertNotEqual(alice.revision, bob.revision)
        for context, manifest in ((alice_context, alice_manifest), (bob_context, bob_manifest)):
            self.assertEqual(context["base_revision"], self.base)
            self.assertEqual(manifest["base_revision"], self.base)
            self.assertEqual(manifest["source_round"], 0)

        output = self.directory / "round-one"
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            result = run_round(self.owner, RoundConfig(
                repo_id=self.repo, output_dir=output, publish=True, tag="round1",
                expected_base_revision=self.base, require_concurrent_publication=True,
                array_backend="numpy"))
        self.assertEqual(stdout.getvalue(), "", "Library execution must return results without printing")
        self.assertEqual(result.status, "published")
        self.assertEqual(result.base.revision, self.base)
        self.assertEqual(result.round_number, 1)
        self.assertEqual(checkpoint_value(result.aggregate_dir), 2.5)
        self.assertEqual({entry["participant"] for entry in result.eligible}, {"alice", "bob"})
        self.assertEqual(self.owner.resolve_revision(self.repo, "main"), result.publication.revision)
        self.assertEqual(self.owner.resolve_revision(self.repo, "round1"), result.publication.revision)

        for revision, expected in ((self.base, 0.0), (alice.revision, 1.0), (bob.revision, 3.0)):
            destination = self.directory / ("immutable-" + revision)
            self.owner.download_snapshot(self.repo, revision, destination)
            self.assertEqual(checkpoint_value(destination), expected)

        with self.assertRaises(ValueError):
            self.owner.publish_aggregate(
                self.repo, result.aggregate_dir, regular_file_paths(result.aggregate_dir),
                expected_base=self.base, reference=reference, next_round=1, tag=None)
        self.assertEqual(self.owner.resolve_revision(self.repo, "main"), result.publication.revision)

        next_work = self.directory / "next-round-client"
        next_context = download_client_round(LocalStore(self.root, "alice"), self.repo, "main", next_work)
        self.assertEqual(next_context["source_round"], 1)
        self.assertEqual(next_context["base_revision"], result.publication.revision)
        self.assertEqual(checkpoint_value(next_work / "base_model"), 2.5)
        self.assertEqual(checkpoint_value(self.directory / "alice" / "base_model"), 0.0)
        readiness = run_round(self.owner, RoundConfig(
            repo_id=self.repo, output_dir=self.directory / "next-readiness", check_only=True))
        self.assertEqual(readiness.status, "not_ready")
        self.assertEqual(readiness.readiness()["eligible_count"], 0)

    def test_registered_algorithm_changes_weights_without_changing_round_workflow(self):
        spec = AlgorithmSpec("integration_uniform")
        self.repo = "custom-algorithm-model"
        initial = initialize_model(self.directory / "custom-initial", "local", algorithm_spec=spec.to_dict())
        self.base = self.owner.initialize_repository(self.repo, initial, private=True).revision
        for participant, value, examples in (("alice", 1.0, 1), ("bob", 3.0, 3)):
            _, manifest, context = self.submit(participant, value, examples)
            self.assertEqual(context["algorithm_spec"], spec.to_dict())
            self.assertEqual(manifest["algorithm_spec"], spec.to_dict())

        class UniformStrategy(FedAvg):
            @property
            def spec(self):
                return AlgorithmSpec("integration_uniform")

        with patch.dict(AGGREGATORS, {"integration_uniform": lambda spec, weighting: UniformStrategy("uniform")}):
            result = run_round(self.owner, RoundConfig(
                repo_id=self.repo, output_dir=self.directory / "uniform",
                algorithm=spec, array_backend="numpy"))
        self.assertEqual(result.status, "aggregated")
        self.assertEqual(checkpoint_value(result.aggregate_dir), 2.0)
        self.assertEqual([entry["coefficient"] for entry in result.eligible], [0.5, 0.5])
        self.assertEqual(self.owner.resolve_revision(self.repo, "main"), self.base)
        round_record = json.loads((result.aggregate_dir / ROUND_FILE).read_text(encoding="utf-8"))
        self.assertEqual(round_record["algorithm_spec"], spec.to_dict())

    def test_participant_floor_blocks_publication_after_discovery(self):
        self.submit("alice", 1.0, 1)
        self.submit("bob", 3.0, 3)
        with self.assertRaisesRegex(ValueError, "at least 3.*found 2"):
            run_round(self.owner, RoundConfig(
                repo_id=self.repo, output_dir=self.directory / "too-few",
                minimum_participants=3, publish=True))
        self.assertEqual(self.owner.resolve_revision(self.repo, "main"), self.base)

    def test_typed_client_metadata_rejects_boolean_counts_and_coerced_rounds(self):
        store = LocalStore(self.root, "alice")
        work = self.directory / "invalid-client"
        download_client_round(store, self.repo, self.base, work)
        trained = write_checkpoint(work / "trained_model", 1.0)
        with self.assertRaisesRegex(ValueError, "num_examples"):
            upload_client_update(store, work, trained, "alice", True)
        context_file = work / CLIENT_CONTEXT_FILE
        malformed = json.loads(context_file.read_text(encoding="utf-8"))
        malformed["source_round"] = "0"
        context_file.write_text(json.dumps(malformed), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source_round"):
            upload_client_update(store, work, trained, "alice", 1)
        self.assertEqual(self.owner.resolve_revision(self.repo, "main"), self.base)
        self.assertFalse((trained / "fedavg_submission.json").exists())


_fixture = Path(__file__).resolve().parents[1] / "packages/exchange/tests/support.py"
_exchange_available = all(importlib.util.find_spec(name) is not None for name in (
    "boto3", "moto", "sqlalchemy", "jwt", "fastapi", "hf2l_exchange"))
if not _exchange_available and os.environ.get("EXCHANGE_REQUIRE_TESTS") == "1":
    raise ImportError("The v3 Exchange integration requires the exchange service/test dependencies")
if _exchange_available:
    _spec = importlib.util.spec_from_file_location("v3_exchange_test_support", _fixture)
    _support = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_support)
    _ExchangeTestCase = _support.ExchangeTestCase
else:
    _ExchangeTestCase = unittest.TestCase


@unittest.skipUnless(_exchange_available, "Exchange integration dependencies are optional")
class ExchangeV3EndToEndTests(_ExchangeTestCase):
    """The same typed NumPy application through authenticated, verified transfers."""

    def sdk(self, subject):
        from hf2l_exchange.client import ExchangeClient
        from hf2l_exchange.worker import tick
        client = ExchangeClient(
            "http://127.0.0.1", self.auth(subject)["Authorization"].split(" ", 1)[1],
            http=self.client, allow_local_http=True, sleep=lambda _: tick(self.transfers))
        self.addCleanup(client.close)
        return client

    def test_numpy_round_uses_exchange_fencing_and_preserves_detached_client_uploads(self):
        from hf2l.backends.exchange import ExchangeStore

        space = self.new_space("v3-federated-model", profile="fedavg.v1")
        sid = space["id"]
        for participant in ("alice", "bob"):
            self.member(participant, ["reader", "contributor"], {"participant": participant}, space=sid)
        self.register_type("model.global", publish_roles=["publisher"], space=sid)
        self.register_type("training.update", visibility="private", publish_roles=["contributor"], space=sid)
        owner = ExchangeStore(None, None, client=self.sdk("owner"), wait_seconds=15)
        initial = initialize_model(self.directory / "initial-numpy", "exchange")
        base = owner.initialize_repository(sid, initial, private=True).revision
        inputs = []
        for participant, value, examples in (("alice", 1.0, 1), ("bob", 3.0, 3)):
            client = ExchangeStore(None, None, client=self.sdk(participant), wait_seconds=15)
            work = self.directory / ("numpy-" + participant)
            download_client_round(client, sid, base, work)
            trained = write_checkpoint(work / "trained_model", value)
            publication, _ = upload_client_update(client, work, trained, participant, examples)
            inputs.append(publication.revision)
        self.assertEqual(owner.resolve_revision(sid, "main"), base)

        output = self.directory / "numpy-exchange-result"
        result = run_round(owner, RoundConfig(
            repo_id=sid, output_dir=output, selection="claim", publish=True,
            tag="numpy-round1", claim_lease_seconds=10, array_backend="numpy"))
        self.assertEqual(result.status, "published")
        self.assertEqual(checkpoint_value(result.aggregate_dir), 2.5)
        record = owner.client.get_record(sid, result.publication.revision)
        self.assertEqual(set(record.metadata["inputs"]), set(inputs))
        self.assertEqual(owner.resolve_revision(sid, "main"), result.publication.revision)
        self.assertEqual(owner.resolve_revision(sid, "numpy-round1"), result.publication.revision)
        downloaded = self.directory / "numpy-exchange-download"
        owner.download_snapshot(sid, result.publication.revision, downloaded)
        self.assertEqual(checkpoint_value(downloaded), 2.5)
        self.assertEqual(json.loads((downloaded / ROUND_FILE).read_text())["round"], 1)
        self.assertFalse(output.with_name(output.name + ".run-state.json").exists())


if __name__ == "__main__":
    unittest.main()
