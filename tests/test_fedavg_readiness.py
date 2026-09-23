from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import torch
from safetensors.torch import load_file, save_file

from hf2l.backends.base import BackendCapabilities, PublicationConsistency, PublishResult, SubmissionCandidate
from hf2l.hub_helpers import ROUND_FILE, SUBMISSION_FILE, artifact_hashes, write_json
from hf2l.owner_fedavg import main


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.allowlist = self.root / "allowlist.json"
        write_json(self.allowlist, {"alice-hf": "alice", "bob-hf": "bob", "carol-hf": "carol"})
        self.manifests = {}
        from hf2l.backends.base import ResolvedReference
        self.store = Mock(name="store")
        self.store.resolve_reference.side_effect = lambda repo, name="main": ResolvedReference(self.store.resolve_revision(repo, name))
        self.store.name = "huggingface"
        self.store.capabilities = BackendCapabilities(PublicationConsistency.ATOMIC, ancestry=True, pull_requests=True)
        self.store.supports_ancestry = True
        self.store.resolve_revision.side_effect = lambda repo, revision: (
            "base-sha" if revision == "main" else revision + "-sha"
        )
        self.store.is_descendant.return_value = True
        self.store.download_snapshot.side_effect = self.download
        self.store.publish_aggregate.return_value = PublishResult("next-sha")
        self.candidates = []
        self.store.discover_submissions.return_value = (self.candidates, [])

    def add_submission(self, participant, **changes):
        revision = f"refs/pr/{len(self.candidates) + 1}"
        self.candidates.append(SubmissionCandidate(revision, revision, participant + "-hf"))
        self.manifests[revision + "-sha"] = {
            "schema_version": 2,
            "backend": "huggingface",
            "repo_id": "owner/model",
            "base_revision": "base-sha",
            "source_round": 0,
            "participant": participant,
            "num_examples": 1,
            **changes,
        }

    def download(self, repo, revision, local_dir, *, allow_patterns=None):
        local_dir.mkdir(parents=True, exist_ok=True)
        if revision == "base-sha":
            record = {"schema_version": 2, "backend": "huggingface", "round": 0}
            filename = ROUND_FILE
        else:
            record = self.manifests[revision]
            filename = SUBMISSION_FILE
            if record is None:
                return
        source = local_dir if allow_patterns is None else self.root / revision.replace("/", "_")
        source.mkdir(exist_ok=True)
        value = 0.0 if revision == "base-sha" else float(record["num_examples"])
        save_file({"weight": torch.tensor([value])}, source / "model.safetensors")
        write_json(source / "config.json", {"model_type": "test"})
        record["checkpoint_files_sha256"] = artifact_hashes(
            source, ["config.json", "model.safetensors"]
        )
        write_json(local_dir / filename, record)

    def run_owner(self, *options):
        argv = [
            "owner_fedavg", "--repo-id", "owner/model", "--discover-prs",
            "--allowlist", str(self.allowlist), "--output-dir", str(self.root / "output"),
            *options,
        ]
        self.logs = io.StringIO()
        with patch("sys.argv", argv), patch("hf2l.owner_fedavg.make_store", return_value=self.store):
            with contextlib.redirect_stdout(self.logs), contextlib.redirect_stderr(self.logs):
                return main()

    def test_threshold_and_metadata_only_downloads(self):
        for count in (0, 1, 2, 3):
            with self.subTest(count=count):
                if count:
                    self.add_submission(("alice", "bob", "carol")[count - 1])
                self.run_owner("--check-only")
                output = self.root / "output"
                report = json.loads((output / "readiness.json").read_text())
                self.assertEqual(report, {
                    "ready": count >= 2, "eligible_count": count, "base_revision": "base-sha",
                })
                for call in self.store.download_snapshot.call_args_list:
                    self.assertIn(call.kwargs["allow_patterns"], (ROUND_FILE, SUBMISSION_FILE))
                self.store.publish_aggregate.assert_not_called()
                output.rename(self.root / f"check-{count}")

    def test_stale_unauthorized_invalid_and_missing_manifests_do_not_count(self):
        self.add_submission("alice")
        self.add_submission("bob", base_revision="old-sha")
        self.add_submission("mallory")
        self.add_submission("carol", source_round=9)
        self.add_submission("carol", num_examples=0)
        self.add_submission("carol")
        self.manifests["refs/pr/6-sha"] = None
        self.run_owner("--check-only")
        report = json.loads((self.root / "output/readiness.json").read_text())
        self.assertEqual(report["eligible_count"], 1)
        self.assertFalse(report["ready"])

    def test_ancestry_is_required_even_with_matching_manifest(self):
        self.add_submission("alice")
        self.add_submission("bob")
        self.store.is_descendant.side_effect = [True, False]
        self.run_owner("--check-only")
        report = json.loads((self.root / "output/readiness.json").read_text())
        self.assertFalse(report["ready"])

    def test_duplicate_participant_fails(self):
        self.add_submission("alice")
        self.add_submission("alice")
        self.assertEqual(1, self.run_owner("--check-only"))
        self.assertIn("Duplicate participant", self.logs.getvalue())

    def test_changed_main_fails_before_download_or_publish(self):
        self.assertEqual(1, self.run_owner("--expected-base-revision", "old-sha", "--publish"))
        self.assertIn("Main changed since readiness check", self.logs.getvalue())
        self.store.download_snapshot.assert_not_called()
        self.store.publish_aggregate.assert_not_called()

    def test_check_only_cannot_publish(self):
        self.assertEqual(1, self.run_owner("--check-only", "--publish"))
        self.store.publish_aggregate.assert_not_called()

    def test_normal_aggregation_still_requires_two_submissions(self):
        self.add_submission("alice")
        self.assertEqual(1, self.run_owner())
        self.assertIn("requires at least two", self.logs.getvalue())

    def test_aggregate_and_publish_uses_checked_base(self):
        self.add_submission("alice", num_examples=1)
        self.add_submission("bob", num_examples=3)
        self.run_owner("--expected-base-revision", "base-sha", "--publish")
        aggregate = self.root / "output/aggregated_model"
        torch.testing.assert_close(load_file(aggregate / "model.safetensors")["weight"], torch.tensor([2.5]))
        self.assertEqual(self.store.publish_aggregate.call_args.kwargs["expected_base"], "base-sha")
        self.assertEqual(json.loads((aggregate / ROUND_FILE).read_text())["round"], 1)


if __name__ == "__main__":
    unittest.main()
