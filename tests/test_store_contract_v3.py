"""Reusable model-store behavioral contracts; remote adapters use deterministic SDK doubles."""
from __future__ import annotations

import argparse
import fnmatch
import json
import multiprocessing
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

from hf2l.backends.factory import STORE_REGISTRY, add_store_arguments, make_store
from hf2l.backends.local import LocalStore
from hf2l.core.ports import ClaimHandle, PublicationConsistency, ResolvedReference, RoundContext


class FakeHub:
    def __init__(self):
        self.refs, self.files, self.parents, self.submissions = {}, {}, {}, {}

    def put(self, folder, name, parent=None):
        revision = uuid.uuid4().hex
        self.files[revision] = {p.relative_to(folder).as_posix(): p.read_bytes()
                                for p in Path(folder).rglob("*") if p.is_file()}
        self.refs[name] = revision
        self.parents[revision] = parent
        return revision

    def create_repo(self, **kwargs):
        return "https://example.test/repo"

    def upload_folder(self, *, folder_path, revision="main", **kwargs):
        return SimpleNamespace(oid=self.put(folder_path, revision))

    def model_info(self, repo_id, revision):
        return SimpleNamespace(sha=self.refs.get(revision, revision))

    def snapshot_download(self, *, revision, local_dir, allow_patterns=None, **kwargs):
        patterns = [allow_patterns] if isinstance(allow_patterns, str) else allow_patterns
        for name, content in self.files[self.refs.get(revision, revision)].items():
            if patterns is None or any(fnmatch.fnmatch(name, pattern) for pattern in patterns):
                path = Path(local_dir) / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)

    def create_commit(self, *, operations, parent_commit, create_pr=False, **kwargs):
        if not create_pr and self.refs.get("main") != parent_commit:
            error = RuntimeError("stale main")
            error.response = SimpleNamespace(status_code=409)
            raise error
        revision = uuid.uuid4().hex
        self.files[revision] = {operation.path_in_repo: Path(operation.path_or_fileobj).read_bytes()
                                for operation in operations}
        self.parents[revision] = parent_commit
        name = f"refs/pr/{len(self.submissions) + 1}" if create_pr else "main"
        self.refs[name] = revision
        if create_pr:
            self.submissions[name] = SimpleNamespace(is_pull_request=True, num=len(self.submissions) + 1,
                                                      author="alice")
        return SimpleNamespace(oid=revision, pr_revision=name if create_pr else None,
                               pr_url="https://example.test/pr", commit_url="https://example.test/commit")

    def create_tag(self, repo_id, *, tag, revision, **kwargs):
        if tag in self.refs:
            raise ValueError("tag exists")
        self.refs[tag] = revision

    def get_repo_discussions(self, **kwargs):
        return list(self.submissions.values())

    def get_discussion_details(self, *, discussion_num, **kwargs):
        return self.submissions[f"refs/pr/{discussion_num}"]

    def list_repo_commits(self, repo_id, revision):
        current, result = self.refs.get(revision, revision), []
        while current:
            result.append(SimpleNamespace(commit_id=current))
            current = self.parents.get(current)
        return result


class FakeRecord(SimpleNamespace):
    def to_dict(self):
        return {**vars(self), "attachments": [vars(item) for item in self.attachments]}


class FakeExchange:
    def __init__(self):
        self.refs, self.stored, self.contents = {}, {}, {}

    @staticmethod
    def safe_destination(root, name):
        from hf2l_exchange.client import ExchangeClient
        return ExchangeClient.safe_destination(root, name)

    def get_space(self, space):
        return SimpleNamespace(profile="fedavg.v1")

    def get_membership(self, space):
        return SimpleNamespace(bindings={"participant": "alice"})

    def types(self, space):
        return [SimpleNamespace(kind=kind, revision=1, id=kind)
                for kind in ("model.global", "training.update")]

    def put_record(self, space, *, kind, metadata, files, **kwargs):
        revision = uuid.uuid4().hex
        self.contents[revision] = {name: path.read_bytes() for name, path in files.items()}
        value = FakeRecord(id=revision, kind=kind, state="published", creator="alice",
                           creator_bindings={"participant": "alice"}, metadata=metadata,
                           attachments=[SimpleNamespace(path=name) for name in files], published_at=len(self.stored))
        self.stored[revision] = value
        return value

    def get_record(self, space, revision):
        return self.stored[revision]

    def records(self, space, *, kind, state):
        return [value for value in self.stored.values() if value.kind == kind and value.state == state]

    def set_ref(self, space, name, revision, **kwargs):
        if name in self.refs:
            raise ValueError("reference exists")
        self.refs[name] = SimpleNamespace(record_id=revision, token="1")

    def resolve(self, space, name):
        return self.refs[name]

    def complete(self, space, handle, revision, **kwargs):
        if self.refs["main"].token != handle.expected_token:
            from hf2l_exchange.client import ExchangeError
            raise ExchangeError(409, "reference_changed")
        self.refs["main"] = SimpleNamespace(record_id=revision, token=str(int(handle.expected_token) + 1))

    def download_attachment(self, space, revision, attachment, destination):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.contents[revision][attachment.path])


def _cas_process(root, folder, base, start, results):
    store = LocalStore(root, "owner")
    start.wait(5)
    try:
        result = store.publish_aggregate("repo", Path(folder), ["model.bin"], expected_base=base,
                                         next_round=1, tag=None)
        results.put(("published", result.revision))
    except ValueError:
        results.put(("conflict", None))


class ModelStoreContract:
    """A fixture supplies each concrete adapter; these are the same external assertions."""
    backend = ""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "input"
        self.source.mkdir()
        self.files = {"model.bin": b"original", "config.json": b'{"model_type":"test"}'}
        for name, value in self.files.items():
            (self.source / name).write_bytes(value)
        self.store = self.make_adapter()
        self.addCleanup(self.store.close)
        self.base = self.store.initialize_repository("repo", self.source, private=False).revision

    def make_adapter(self):
        if self.backend == "local":
            return LocalStore(self.root / "storage", "alice")
        if self.backend == "exchange":
            from hf2l.backends.exchange import ExchangeStore
            self.sdk = FakeExchange()
            return ExchangeStore(None, None, client=self.sdk)
        self.hub = FakeHub()
        if self.backend == "huggingface":
            from hf2l.backends.huggingface import HuggingFaceStore
            with patch("hf2l.backends.huggingface.HfApi", return_value=self.hub):
                return HuggingFaceStore(None)
        from hf2l.backends.jfrog import JFrogStore
        with patch("hf2l.backends.jfrog.HfApi", return_value=self.hub):
            store = JFrogStore(None, "https://example.test/artifactory/api/huggingfaceml/models")
        store._upload_folder = lambda repo, folder, revision: self.hub.put(folder, revision)
        def manifests(repo):
            records = []
            for name, revision in self.hub.refs.items():
                if "fedavg_submission.json" in self.hub.files[revision]:
                    records.append({"item": {"created_by": "alice"},
                                    "manifest": json.loads(self.hub.files[revision]["fedavg_submission.json"])})
            return records, []
        store._manifest_items = manifests
        return store

    def publish(self, expected=None, tag=None):
        expected = expected or self.base
        reference = self.store.resolve_reference("repo")
        if expected != reference.revision:
            reference = ResolvedReference(expected, generation=1, token="1")
        kwargs = {"reference": reference}
        if self.backend == "exchange":
            inputs = ("input-one", "input-two")
            (self.source / "fedavg_round.json").write_text(json.dumps({"round": 1, "submissions": [
                {"resolved_revision": item} for item in inputs]}))
            kwargs["claim"] = ClaimHandle("claim", 1, reference, inputs, 1e12,
                                             SimpleNamespace(reference="main", expected_token=reference.token))
        return self.store.publish_aggregate("repo", self.source,
            sorted(p.name for p in self.source.iterdir()), expected_base=expected, next_round=1, tag=tag, **kwargs)

    def test_snapshot_is_immutable_and_pattern_download_is_exact(self):
        (self.source / "model.bin").write_bytes(b"changed")
        output = self.root / "download"
        self.store.download_snapshot("repo", self.base, output, allow_patterns="*.bin")
        self.assertEqual((output / "model.bin").read_bytes(), b"original")
        self.assertFalse((output / "config.json").exists())

    def test_submission_is_detached_and_discoverable(self):
        name = self.store.new_submission_revision("alice", 0)
        manifest = {"repo_id": "repo", "participant": "alice", "num_examples": 1,
                    "base_revision": self.base, "submission_revision": name}
        (self.source / "fedavg_submission.json").write_text(json.dumps(manifest))
        before = {p.name: p.read_bytes() for p in self.source.iterdir()}
        result = self.store.publish_submission("repo", self.source, list(before), participant="alice",
                       source_round=0, base_revision=self.base, submission_revision=name)
        self.assertEqual(self.store.resolve_revision("repo", "main"), self.base)
        self.assertEqual(self.store.resolve_revision("repo", result.revision), result.resolved_revision)
        candidates, _ = self.store.discover_submissions("repo", context=RoundContext("repo", self.store.resolve_reference("repo"), 0))
        self.assertEqual(len(candidates), 1)
        self.assertEqual(self.store.resolve_revision("repo", candidates[0].revision), result.resolved_revision)
        self.assertEqual({p.name: p.read_bytes() for p in self.source.iterdir()}, before)
        self.assertEqual(len(self.store.explicit_submissions("repo", [candidates[0].identifier])), 1)

    def test_stale_publication_cannot_replace_main(self):
        first = self.publish()
        self.assertNotEqual(first.revision, self.base)
        with self.assertRaises(Exception):
            self.publish(expected=self.base)
        self.assertEqual(self.store.resolve_revision("repo", "main"), first.revision)
        expected = PublicationConsistency.PREFLIGHT if self.backend == "jfrog" else PublicationConsistency.ATOMIC
        self.assertEqual(self.store.capabilities.publication, expected)

    def test_primary_success_survives_secondary_tag_failure(self):
        if self.backend == "local":
            target = patch.object(self.store, "_set_tag", side_effect=OSError("tag storage unavailable"))
        elif self.backend == "exchange":
            target = patch.object(self.sdk, "set_ref", side_effect=ValueError("tag exists"))
        elif self.backend == "huggingface":
            target = patch.object(self.hub, "create_tag", side_effect=ValueError("tag exists"))
        else:
            original = self.store._upload_folder
            def upload(repo, folder, name):
                if name != "main":
                    raise OSError("tag storage unavailable")
                return original(repo, folder, name)
            target = patch.object(self.store, "_upload_folder", side_effect=upload)
        with target:
            result = self.publish(tag="round1")
        self.assertFalse(result.tag_created)
        self.assertTrue(result.warnings)
        self.assertEqual(self.store.resolve_revision("repo", "main"), result.revision)
        output = self.root / "previous"
        self.store.download_snapshot("repo", self.base, output)
        self.assertEqual((output / "model.bin").read_bytes(), self.files["model.bin"])

    def test_upload_rejects_path_escape_and_symlinks(self):
        (self.source / "link.bin").symlink_to(self.source / "model.bin")
        for name in ("../input/model.bin", "/absolute.bin", "link.bin"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.store.publish_submission("repo", self.source, [name], participant="alice", source_round=0,
                    base_revision=self.base, submission_revision=self.store.new_submission_revision("alice", 0))
        self.assertEqual(self.store.resolve_revision("repo", "main"), self.base)

    def test_missing_revision_is_distinct_from_permission_failure_or_outage(self):
        from hf2l.core.ports import RevisionNotFound
        if self.backend == "local":
            with self.assertRaises(RevisionNotFound):
                self.store.resolve_revision("repo", "0" * 32)
            return
        provider = self.sdk if self.backend == "exchange" else self.hub
        for operation, provider_method in (("resolve", "get_record" if self.backend == "exchange" else "model_info"),
                                           ("download", "get_record" if self.backend == "exchange" else "snapshot_download")):
            for status in (404, 403, 500):
                error = RuntimeError(f"provider HTTP {status}")
                error.response = SimpleNamespace(status_code=status)
                with self.subTest(operation=operation, status=status), patch.object(provider, provider_method, side_effect=error):
                    expected = RevisionNotFound if status == 404 else RuntimeError
                    with self.assertRaises(expected) as caught:
                        if operation == "resolve":
                            self.store.resolve_revision("repo", self.base)
                        else:
                            self.store.download_snapshot("repo", self.base, self.root / "absent")
                    if status != 404:
                        self.assertIs(caught.exception, error)

    def test_close_is_idempotent(self):
        self.store.close()
        self.store.close()


class LocalContractTests(ModelStoreContract, unittest.TestCase):
    backend = "local"

    def test_processes_have_one_cas_winner(self):
        context = multiprocessing.get_context("spawn")
        start, results = context.Event(), context.Queue()
        workers = [context.Process(target=_cas_process, args=(str(self.root / "storage"),
                   str(self.source), self.base, start, results)) for _ in range(2)]
        for worker in workers:
            worker.start()
        start.set()
        answers = [results.get(timeout=15) for _ in workers]
        for worker in workers:
            worker.join(15)
            if worker.is_alive():
                worker.terminate()
                worker.join()
            self.assertEqual(worker.exitcode, 0)
        results.close()
        self.assertEqual(sorted(item[0] for item in answers), ["conflict", "published"])

    def test_immutable_revision_cannot_be_shadowed_by_submission_or_tag(self):
        with self.assertRaises(ValueError):
            self.store.publish_submission("repo", self.source, ["model.bin"], participant="alice", source_round=0,
                base_revision=self.base, submission_revision=self.base)
        result = self.publish(tag=self.base)
        self.assertFalse(result.tag_created)
        self.assertEqual(self.store.resolve_revision("repo", self.base), self.base)
        old = self.root / "old"
        self.store.download_snapshot("repo", self.base, old)
        self.assertEqual((old / "model.bin").read_bytes(), b"original")

    def test_failure_after_reference_replace_has_uncertain_outcome(self):
        from hf2l.core.ports import PublicationUncertain
        original = self.store._write
        def interrupted(path, value):
            original(path, value)
            if path.name == "refs.json":
                raise OSError("directory synchronization failed")
        with patch.object(self.store, "_write", side_effect=interrupted):
            with self.assertRaises(PublicationUncertain):
                self.publish()
        self.assertNotEqual(self.store.resolve_revision("repo", "main"), self.base)

    def test_download_cannot_overwrite_store_or_modify_hardlinked_snapshot(self):
        import os
        snapshot = self.store._snapshot_path(self.store._repo("repo"), self.base) / "files"
        with self.assertRaises(ValueError):
            self.store.download_snapshot("repo", self.base, snapshot)
        destination = self.root / "hardlink-target"
        destination.mkdir()
        os.link(snapshot / "config.json", destination / "model.bin")
        self.store.download_snapshot("repo", self.base, destination, allow_patterns="model.bin")
        self.assertEqual((snapshot / "config.json").read_bytes(), self.files["config.json"])
        self.assertEqual((destination / "model.bin").read_bytes(), b"original")

    def test_generation_prevents_stale_reference(self):
        with self.assertRaises(ValueError):
            self.store.publish_aggregate("repo", self.source, ["model.bin"], expected_base=self.base,
                reference=ResolvedReference(self.base, generation=0), next_round=1, tag=None)

    def test_identity_paths_and_symlinks_are_checked(self):
        for path in ("../model.bin", "/tmp/model.bin", "x/../model.bin", "model.bin/", "config.json/../model.bin"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.store.publish_submission("repo", self.source, [path], participant="alice", source_round=0,
                    base_revision=self.base, submission_revision=None)
        (self.source / "link.bin").symlink_to(self.source / "model.bin")
        with self.assertRaises(ValueError):
            self.store.publish_submission("repo", self.source, ["link.bin"], participant="alice", source_round=0,
                base_revision=self.base, submission_revision=None)
        with self.assertRaises(ValueError):
            self.store.publish_submission("repo", self.source, ["model.bin"], participant="bob", source_round=0,
                base_revision=self.base, submission_revision=None)
        outside = self.root / "outside"
        outside.mkdir()
        destination = self.root / "destination"
        destination.mkdir()
        (destination / "model.bin").symlink_to(outside / "written")
        with self.assertRaises(ValueError):
            self.store.download_snapshot("repo", self.base, destination)
        self.assertFalse((outside / "written").exists())


class HuggingFaceContractTests(ModelStoreContract, unittest.TestCase):
    backend = "huggingface"


class JFrogContractTests(ModelStoreContract, unittest.TestCase):
    backend = "jfrog"


class JFrogDiscoveryFailureTests(unittest.TestCase):
    def setUp(self):
        from hf2l.backends.jfrog import JFrogStore
        self.store = object.__new__(JFrogStore)
        self.store.repo_key = "models"
        self.store.artifactory_url = "https://example.test/artifactory"
        self.store.token = None
        self.query = json.dumps({"results": [{"path": "org/model/revision", "name": "fedavg_submission.json"}]}).encode()

    @staticmethod
    def http_error(status):
        import io
        import urllib.error
        return urllib.error.HTTPError("https://example.test/artifact", status, "provider failure", {}, io.BytesIO(b"details"))

    def test_artifact_http_failures_preserve_status_and_propagate(self):
        import io
        from hf2l.backends.jfrog import JFrogRequestError
        for status in (401, 403, 429, 500, 503):
            with self.subTest(status=status), patch("urllib.request.urlopen", side_effect=[
                    io.BytesIO(self.query), self.http_error(status)]):
                with self.assertRaises(JFrogRequestError) as caught:
                    self.store._manifest_items("org/model")
                self.assertEqual(caught.exception.status, status)

    def test_only_disappeared_or_malformed_artifacts_are_skipped(self):
        import io
        for response in (self.http_error(404), b"invalid JSON", b"\xff"):
            response = io.BytesIO(response) if isinstance(response, bytes) else response
            with self.subTest(response=response), patch("urllib.request.urlopen", side_effect=[
                    io.BytesIO(self.query), response]):
                records, skipped = self.store._manifest_items("org/model")
                self.assertEqual(records, [])
                self.assertEqual(len(skipped), 1)

    def test_query_failure_is_never_interpreted_as_a_missing_candidate(self):
        from hf2l.backends.jfrog import JFrogRequestError
        with patch("urllib.request.urlopen", side_effect=self.http_error(404)):
            with self.assertRaises(JFrogRequestError):
                self.store._manifest_items("org/model")

    def test_unclassified_transport_failure_propagates(self):
        for error in (RuntimeError("transport outage"), TimeoutError("timed out")):
            with self.subTest(error=error), patch.object(self.store, "_request", side_effect=[self.query, error]):
                with self.assertRaises(type(error)) as caught:
                    self.store._manifest_items("org/model")
                self.assertIs(caught.exception, error)


class ExchangeContractTests(ModelStoreContract, unittest.TestCase):
    backend = "exchange"

    def test_overflow_manifest_does_not_mutate_input_folder(self):
        manifest = {"round": 1, "submissions": [{"participant": f"client-{index}", "resolved_revision": "a" * 32,
                     "num_examples": 1, "coefficient": .001, "training": {"details": "x" * 1000}}
                     for index in range(1000)]}
        (self.source / "fedavg_round.json").write_text(json.dumps(manifest))
        before = {path.name: path.read_bytes() for path in self.source.iterdir()}
        revision = self.store._publish("repo", self.source, list(before), "model.global")
        self.assertEqual({path.name: path.read_bytes() for path in self.source.iterdir()}, before)
        self.assertEqual(json.loads(self.sdk.contents[revision]["fedavg_round-full.json"]), manifest)


class RegistryTests(unittest.TestCase):
    def test_cli_and_factory_share_registry(self):
        parser = argparse.ArgumentParser()
        add_store_arguments(parser)
        choices = next(action.choices for action in parser._actions if action.dest == "backend")
        self.assertEqual(tuple(choices), tuple(STORE_REGISTRY))
        with tempfile.TemporaryDirectory() as root:
            with make_store("local", endpoint=root, principal="owner") as store:
                self.assertEqual(store.name, "local")
        with self.assertRaises(ValueError):
            make_store("custom.module.Store")

    def test_local_requires_explicit_identity_without_credentials(self):
        with tempfile.TemporaryDirectory() as root, patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(ValueError):
                make_store("local", endpoint=root)
            with make_store("local", endpoint=root, principal="owner") as store:
                self.assertEqual(store.principal, "owner")


if __name__ == "__main__":
    unittest.main()
