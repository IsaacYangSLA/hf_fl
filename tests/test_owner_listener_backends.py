"""Owner/client cycles through real HF and JFrog adapters with SDK doubles."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hf2l.common.fs import read_json
from hf2l.core.ports import PublicationConsistency
from hf2l.core.protocol import ROUND_FILE, SUBMISSION_FILE
from hf2l.listener.client import ClientListener
from hf2l.listener.owner import OwnerListener, UncertainAggregation
from hf2l.round.config import RoundConfig
from tests import test_store_contract_v3 as store_fixtures
from tests.support.v3_helpers import checkpoint_value, initialize_model, write_checkpoint


class AuthoredHub(store_fixtures.FakeHub):
    """Keep provider authors separate from the uploaded participant claims."""

    def __init__(self):
        super().__init__()
        self.principal = "owner"
        self.authors = {}
        self.commit_requests = []
        self.upload_requests = []
        self.aql_queries = []

    def create_commit(self, **kwargs):
        self.commit_requests.append({key: value for key, value in kwargs.items() if key != "operations"})
        result = super().create_commit(**kwargs)
        self.authors[result.oid] = self.principal
        if result.pr_revision:
            self.submissions[result.pr_revision].author = self.principal
        return result

    def upload_folder(self, **kwargs):
        result = super().upload_folder(**kwargs)
        self.authors[result.oid] = self.principal
        self.upload_requests.append({"revision": kwargs.get("revision", "main"), "oid": result.oid})
        return result

    def artifact_request(self, url, *, data=None, content_type=None):
        """Serve the actual adapter's AQL query and manifest HTTP reads."""
        if url.endswith("/api/search/aql"):
            self.aql_queries.append((data.decode("utf-8"), content_type))
            results = [
                {"repo": "models", "path": f"repo/{name}", "name": SUBMISSION_FILE,
                 "created_by": self.authors[revision]}
                for name, revision in self.refs.items() if SUBMISSION_FILE in self.files[revision]
            ]
            return json.dumps({"results": results}).encode("utf-8")
        for name, revision in self.refs.items():
            if url.endswith(f"/models/repo/{name}/{SUBMISSION_FILE}"):
                return self.files[revision][SUBMISSION_FILE]
        raise AssertionError(f"Unexpected artifact request: {url}")


class OwnerBackendContract:
    backend = ""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hf2l-owner-adapter-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.hub = AuthoredHub()
        self.store = self.make_store()
        self.addCleanup(self.store.close)
        initial = initialize_model(self.root / "initial", self.backend)
        self.base = self.store.initialize_repository("repo", initial, private=False).revision
        self.allowlist = self.root / "allowlist.json"
        self.allowlist.write_text(json.dumps({"alice": "alice", "bob": "bob"}))
        self.config = RoundConfig("repo", self.root / "unused", allowlist=self.allowlist)
        self.state_dir = self.root / "owner-state"

    def make_store(self):
        if self.backend == "huggingface":
            from hf2l.backends.huggingface import HuggingFaceStore
            with patch("hf2l.backends.huggingface.HfApi", return_value=self.hub):
                return HuggingFaceStore(None)
        from hf2l.backends.jfrog import JFrogStore
        with patch("hf2l.backends.jfrog.HfApi", return_value=self.hub):
            store = JFrogStore(None, "https://example.test/artifactory/api/huggingfaceml/models")
        # Keep the real AQL/discovery code; replace only its HTTP boundary.
        store._request = self.hub.artifact_request
        return store

    def listener(self, **overrides):
        kwargs = {
            "store": self.store, "config": self.config, "state_dir": self.state_dir,
            "source_id": f"{self.backend}:owner-adapter-test", "configuration_id": "fedavg-test-v1",
        }
        kwargs.update(overrides)
        return OwnerListener(**kwargs)

    def submit(self, participant):
        count = {"alice": 1, "bob": 3}[participant]

        def train(base_dir, output_dir, options):
            write_checkpoint(output_dir, checkpoint_value(base_dir) + count)
            return {"num_examples": count}

        self.hub.principal = participant
        try:
            with ClientListener(
                self.store, repo_id="repo", participant=participant,
                state_dir=self.root / f"client-{participant}",
                source_id=f"{self.backend}:owner-adapter-test", training_id="increment-test-v1",
                train_model=train,
            ) as client:
                self.assertEqual("submitted", client.poll_once())
                self.assertEqual("idle", client.poll_once())
        finally:
            self.hub.principal = "owner"

    def test_two_rounds_require_two_current_base_clients_and_publish_weighted_models(self):
        base = self.base
        with self.listener() as owner:
            for number in (1, 2):
                # Old PRs/named revisions remain discoverable in the second
                # round, but their immutable base makes them ineligible.
                self.assertEqual("not_ready", owner.poll_once())
                self.submit("alice")
                self.assertEqual("not_ready", owner.poll_once())
                self.assertEqual(base, self.store.resolve_reference("repo").revision)
                self.submit("bob")
                self.assertEqual(base, self.store.resolve_reference("repo").revision)
                self.assertEqual("published", owner.poll_once())

                revision = self.store.resolve_reference("repo").revision
                output = self.root / f"inspect-round-{number}"
                self.store.download_snapshot("repo", revision, output)
                record = read_json(output / ROUND_FILE)
                self.assertEqual(base, record["base_revision"])
                self.assertEqual(number, record["round"])
                self.assertEqual(2.5 * number, checkpoint_value(output))
                self.assertEqual({"alice": 0.25, "bob": 0.75},
                                 {item["participant"]: item["coefficient"] for item in record["submissions"]})
                for submission in record["submissions"]:
                    manifest = json.loads(self.hub.files[submission["resolved_revision"]][SUBMISSION_FILE])
                    self.assertEqual(base, manifest["base_revision"])
                    self.assertEqual(number - 1, manifest["source_round"])
                    self.assertEqual(submission["participant"], submission["author"])
                self.assertEqual(revision, owner.state["jobs"][base]["result"]["publication"]["revision"])
                base = revision

        with self.listener() as restarted:
            self.assertEqual("not_ready", restarted.poll_once())
        self.assertEqual(base, self.store.resolve_reference("repo").revision)
        self.assertEqual(1, read_json(self.state_dir / "state.json")["completed_round"])
        self.assert_provider_publication_contract()

    def assert_provider_publication_contract(self):
        raise NotImplementedError


class HuggingFaceOwnerListenerTests(OwnerBackendContract, unittest.TestCase):
    backend = "huggingface"

    def assert_provider_publication_contract(self):
        self.assertEqual(PublicationConsistency.ATOMIC, self.store.capabilities.publication)
        commits = self.hub.commit_requests
        self.assertEqual(6, len(commits))
        expected_base = self.base
        for offset in (0, 3):
            alice, bob, aggregate = commits[offset:offset + 3]
            self.assertTrue(alice["create_pr"])
            self.assertTrue(bob["create_pr"])
            self.assertFalse(aggregate.get("create_pr", False))
            self.assertEqual("main", aggregate["revision"])
            self.assertTrue(all(item["parent_commit"] == expected_base for item in (alice, bob, aggregate)))
            next_base = [revision for revision, files in self.hub.files.items()
                         if ROUND_FILE in files and json.loads(files[ROUND_FILE]).get("base_revision") == expected_base]
            self.assertEqual(1, len(next_base))
            expected_base = next_base[0]

    def test_conditional_publication_keeps_concurrently_advanced_main(self):
        self.submit("alice")
        self.submit("bob")
        original = self.hub.create_commit
        concurrent = initialize_model(self.root / "concurrent-owner", self.backend, value=99)
        advanced = []

        def race_publication(**kwargs):
            if not kwargs.get("create_pr", False):
                advanced.append(self.hub.put(concurrent, "main", parent=self.base))
            return original(**kwargs)

        with patch.object(self.hub, "create_commit", side_effect=race_publication):
            with self.listener() as owner:
                with self.assertRaises(UncertainAggregation):
                    owner.poll_once()
        self.assertEqual(1, len(advanced))
        self.assertEqual(advanced[0], self.store.resolve_reference("repo").revision)


class JFrogOwnerListenerTests(OwnerBackendContract, unittest.TestCase):
    backend = "jfrog"

    def assert_provider_publication_contract(self):
        self.assertEqual(PublicationConsistency.PREFLIGHT, self.store.capabilities.publication)
        uploads = self.hub.upload_requests
        self.assertEqual(3, sum(item["revision"] == "main" for item in uploads))
        submissions = [item["revision"] for item in uploads if item["revision"] != "main"]
        self.assertEqual(4, len(submissions))
        self.assertEqual(4, len(set(submissions)))
        self.assertTrue(self.hub.aql_queries)
        self.assertTrue(all("created_by" in query and mime == "text/plain" for query, mime in self.hub.aql_queries))
        state = read_json(self.state_dir / "state.json")
        for job in state["jobs"].values():
            if job["status"] == "published":
                self.assertIn("This backend requires a single publishing coordinator", job["result"]["warnings"])

    def test_required_atomic_publication_is_rejected_without_upload(self):
        before = list(self.hub.upload_requests)
        config = replace(self.config, require_concurrent_publication=True)
        with self.assertRaisesRegex(ValueError, "preflight|atomic|concurrent"):
            self.listener(config=config)
        self.assertFalse(self.state_dir.exists())
        self.assertEqual(before, self.hub.upload_requests)
        self.assertEqual(self.base, self.store.resolve_reference("repo").revision)

    def test_preflight_rejects_main_advanced_before_upload(self):
        self.submit("alice")
        self.submit("bob")
        original = self.store.publish_aggregate
        concurrent = initialize_model(self.root / "concurrent-owner", self.backend, value=99)
        advanced = []
        before = list(self.hub.upload_requests)

        def race_publication(*args, **kwargs):
            advanced.append(self.hub.put(concurrent, "main"))
            return original(*args, **kwargs)

        with patch.object(self.store, "publish_aggregate", side_effect=race_publication):
            with self.listener() as owner:
                with self.assertRaises(UncertainAggregation):
                    owner.poll_once()
        self.assertEqual(1, len(advanced))
        self.assertEqual(advanced[0], self.store.resolve_reference("repo").revision)
        self.assertEqual(before, self.hub.upload_requests)


if __name__ == "__main__":
    unittest.main()
