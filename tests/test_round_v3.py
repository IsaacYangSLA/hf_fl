"""Application-level round contracts using immutable local checkpoint fixtures."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

import numpy as np
from safetensors.numpy import load_file, save_file

from hf2l.core.ports import (BackendCapabilities, ClaimHandle, PublicationConsistency,
                             PublicationUncertain, PublishResult, ResolvedReference, SubmissionCandidate)
from hf2l.core.protocol import ROUND_FILE, SUBMISSION_FILE, AlgorithmSpec
from hf2l.fedavg_runner import FedAvgRunner, run_round
from hf2l.hub_helpers import artifact_hashes, read_json, write_json
from hf2l.owner_fedavg import main, render_result
from hf2l.round.aggregator import FedAvg
from hf2l.round.config import RoundConfig


class FixtureStore:
    """An immutable in-process transport with deliberately unfamiliar backend name."""

    name = "test-artifacts"
    capabilities = BackendCapabilities(PublicationConsistency.ATOMIC, binds_participants=True)

    def __init__(self, root: Path):
        self.root = root
        self.candidates = []
        self.downloads = []
        self.publications = []
        self.abandoned = []
        self.closed = False
        self.publication_error = None
        self.reference = ResolvedReference("base", generation=1)
        self._checkpoint("base", 0)
        write_json(root / "base" / ROUND_FILE, {"schema_version": 2, "backend": self.name, "round": 0,
                   "checkpoint_files_sha256": self._hashes("base")})

    def _checkpoint(self, revision, value):
        folder = self.root / revision
        folder.mkdir()
        write_json(folder / "config.json", {"model_type": "fixture"})
        save_file({"weight": np.asarray([value], dtype=np.float32)}, folder / "model.safetensors")
        return folder

    def _hashes(self, revision):
        return artifact_hashes(self.root / revision, ["config.json", "model.safetensors"])

    def add(self, name, value, count, **metadata):
        folder = self._checkpoint(name, value)
        write_json(folder / SUBMISSION_FILE, {"schema_version": 2, "backend": self.name,
                   "repo_id": "test/repo", "base_revision": "base", "source_round": 0,
                   "participant": name, "num_examples": count,
                   "checkpoint_files_sha256": self._hashes(name), **metadata})
        self.candidates.append(SubmissionCandidate(name, name, name, name))

    def resolve_reference(self, repo_id, name="main"):
        return self.reference

    def resolve_revision(self, repo_id, revision):
        return revision

    def download_snapshot(self, repo_id, revision, local_dir, *, allow_patterns=None):
        self.downloads.append((revision, allow_patterns))
        local_dir.mkdir(parents=True, exist_ok=True)
        for source in (self.root / revision).iterdir():
            if allow_patterns is None or source.name == allow_patterns:
                shutil.copyfile(source, local_dir / source.name)

    def discover_submissions(self, repo_id, *, context=None):
        return self.candidates, []

    def explicit_submissions(self, repo_id, values):
        return [item for item in self.candidates if item.identifier in values]

    def publish_aggregate(self, repo_id, folder, paths, **kwargs):
        self.publications.append(kwargs)
        if self.publication_error:
            raise self.publication_error
        return PublishResult("new", warnings=("secondary operation warning",), tag_created=False)

    def claim_submissions(self, repo_id, *, context, acquisition_key, claim_id=None, lease_seconds=3600):
        self.acquisition_key = acquisition_key
        return ClaimHandle("claim", 1, context.reference, tuple(c.revision for c in self.candidates),
                           time.time() + lease_seconds, None), self.candidates

    def renew_claim(self, repo_id, claim, lease_seconds):
        return replace(claim, lease_until=time.time() + lease_seconds)

    def abandon_claim(self, repo_id, claim):
        self.abandoned.append(claim)

    def close(self):
        self.closed = True


class RoundTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = FixtureStore(self.root)
        self.config = RoundConfig("test/repo", self.root / "output")

    def _clients(self):
        self.store.add("alice", 1, 1)
        self.store.add("bob", 3, 3)

    def test_library_returns_structured_published_result_without_output(self):
        self._clients()
        logs = io.StringIO()
        with contextlib.redirect_stdout(logs), contextlib.redirect_stderr(logs):
            result = run_round(self.store, replace(self.config, publish=True))
        self.assertEqual("", logs.getvalue())
        self.assertEqual("published", result.status)
        self.assertEqual("new", result.publication.revision)
        self.assertEqual("secondary operation warning", result.warnings[0])
        self.assertEqual([.25, .75], [item["coefficient"] for item in result.eligible])
        self.assertEqual([2.5], load_file(result.aggregate_dir / "model.safetensors")["weight"].tolist())
        persisted = read_json(self.config.output_dir / "result.json")
        self.assertEqual(result.to_dict()["publication"], persisted["publication"])
        self.assertFalse(self.store.closed, "The library caller owns its transport")

    def test_typed_readiness_is_metadata_only_and_honors_higher_quorum(self):
        self._clients()
        result = run_round(self.store, replace(self.config, check_only=True, minimum_participants=3))
        self.assertEqual("not_ready", result.status)
        self.assertEqual(2, result.readiness()["eligible_count"])
        self.assertTrue(all(pattern in {ROUND_FILE, SUBMISSION_FILE} for _, pattern in self.store.downloads))
        self.assertEqual([], self.store.publications)

    def test_minimum_cannot_weaken_two_client_floor(self):
        for minimum in (1, True, 2.5):
            with self.subTest(minimum=minimum), self.assertRaisesRegex(ValueError, "at least two"):
                run_round(self.store, replace(self.config, minimum_participants=minimum))
        self.assertEqual([], self.store.downloads)

    def test_automatic_invalid_manifest_is_a_structured_skip(self):
        self._clients()
        self.store.add("mallory", 9, True)
        result = run_round(self.store, self.config)
        self.assertEqual("aggregated", result.status)
        self.assertEqual(1, len(result.skipped))
        self.assertEqual("mallory", result.skipped[0].candidate)
        self.assertIn("num_examples", result.skipped[0].reason)

    def test_explicit_invalid_manifest_is_not_silently_skipped(self):
        self._clients()
        self.store.add("mallory", 9, True)
        with self.assertRaisesRegex(ValueError, "num_examples"):
            run_round(self.store, replace(self.config, selection="explicit", submissions=("alice", "bob", "mallory")))
        self.assertEqual([], self.store.publications)

    def test_automatic_deleted_candidate_is_skipped_during_resolution(self):
        self._clients()
        self.store.candidates.append(SubmissionCandidate("deleted", "deleted", "deleted", "deleted"))
        original = self.store.resolve_revision
        def resolve(repo, revision):
            if revision == "deleted":
                raise ValueError("revision no longer exists")
            return original(repo, revision)
        self.store.resolve_revision = resolve
        result = run_round(self.store, self.config)
        self.assertEqual("aggregated", result.status)
        self.assertEqual("deleted", result.skipped[0].candidate)

    def test_transport_outage_is_never_reported_as_invalid_submission(self):
        self._clients()
        for stage in ("resolve_revision", "download_snapshot"):
            with self.subTest(stage=stage):
                config = replace(self.config, output_dir=self.root / stage)
                original = getattr(self.store, stage)
                def failed(repo, revision, *args, **kwargs):
                    if revision == "bob":
                        raise ConnectionError("backend unavailable")
                    return original(repo, revision, *args, **kwargs)
                with patch.object(self.store, stage, side_effect=failed):
                    with self.assertRaisesRegex(ConnectionError, "backend unavailable"):
                        run_round(self.store, config)
                self.assertFalse((config.output_dir / "aggregated_model").exists())

    def test_algorithm_training_parameters_must_match(self):
        class Custom(FedAvg):
            @property
            def spec(self):
                return AlgorithmSpec("custom", params={"rate": .1})
        self.store.add("alice", 1, 1, algorithm_spec={"name": "custom", "params": {"rate": .1}})
        self.store.add("bob", 3, 3, algorithm_spec={"name": "custom", "params": {"rate": .2}})
        result = run_round(self.store, replace(self.config, check_only=True), aggregator=Custom())
        self.assertEqual("not_ready", result.status)
        self.assertEqual(1, len(result.eligible))
        self.assertIn("different algorithm parameters", result.skipped[0].reason)

    def test_fedavg_server_weighting_can_change_without_retraining_clients(self):
        for name, value in (("alice", 1), ("bob", 3)):
            self.store.add(name, value, value, algorithm_spec={"name": "fedavg", "params": {"weighting": "examples"}})
        result = run_round(self.store, replace(self.config, weighting="uniform"))
        self.assertEqual([2.0], load_file(result.aggregate_dir / "model.safetensors")["weight"].tolist())

    def test_injected_strategy_owns_weighting_and_reducer(self):
        self._clients()
        strategy = Mock(wraps=FedAvg("uniform"))
        strategy.spec = AlgorithmSpec("fedavg", params={"weighting": "uniform"})
        strategy.minimum_participants = 2
        result = run_round(self.store, self.config, aggregator=strategy)
        strategy.coefficients.assert_called_once()
        strategy.reduce.assert_called_once()
        self.assertEqual([2.0], load_file(result.aggregate_dir / "model.safetensors")["weight"].tolist())
        self.assertEqual("uniform", read_json(result.aggregate_dir / ROUND_FILE)["algorithm_spec"]["params"]["weighting"])

    def test_uncertain_publication_preserves_claim_state_for_reconciliation(self):
        self._clients()
        self.store.capabilities = replace(self.store.capabilities, fenced_coordination=True,
                                          requires_coordination_for_publication=True)
        self.store.publication_error = PublicationUncertain("lost primary response")
        with self.assertRaises(PublicationUncertain):
            run_round(self.store, replace(self.config, selection="claim", publish=True))
        self.assertEqual([], self.store.abandoned)
        saved = read_json(self.root / "output.run-state.json")
        self.assertEqual(self.store.acquisition_key, saved["acquisition_key"])
        self.assertEqual("claim", saved["claim_id"])

    def test_known_prepublication_failure_abandons_claim_and_clears_state(self):
        self.store.add("alice", 1, 1)
        self.store.capabilities = replace(self.store.capabilities, fenced_coordination=True,
                                          requires_coordination_for_publication=True)
        with self.assertRaisesRegex(ValueError, "at least two"):
            run_round(self.store, replace(self.config, selection="claim", publish=True))
        self.assertEqual(1, len(self.store.abandoned))
        self.assertFalse((self.root / "output.run-state.json").exists())

    def test_publication_requirement_is_capability_driven_for_an_unfamiliar_backend(self):
        self.store.capabilities = replace(self.store.capabilities, requires_coordination_for_publication=True)
        with self.assertRaisesRegex(ValueError, "claim-submissions"):
            run_round(self.store, replace(self.config, publish=True))
        self.assertEqual([], self.store.downloads)

    def test_cli_renders_one_json_object_and_closes_store(self):
        self._clients()
        with patch("hf2l.owner_fedavg.make_store", return_value=self.store):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["--repo-id", "test/repo", "--discover-submissions", "--output-dir",
                             str(self.config.output_dir), "--json", "--publish"])
        self.assertEqual(0, code)
        self.assertEqual("published", json.loads(output.getvalue())["status"])
        self.assertTrue(self.store.closed)

    def test_cli_closes_store_after_validation_failure(self):
        with patch("hf2l.owner_fedavg.make_store", return_value=self.store), contextlib.redirect_stderr(io.StringIO()):
            code = main(["--repo-id", "test/repo", "--discover-submissions", "--output-dir",
                         str(self.config.output_dir), "--minimum-participants", "1"])
        self.assertEqual(1, code)
        self.assertTrue(self.store.closed)


if __name__ == "__main__":
    unittest.main()
