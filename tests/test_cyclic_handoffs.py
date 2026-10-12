"""Manual cyclic handoffs preserve detached snapshots and verify their lineage."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import numpy as np
from safetensors.numpy import load_file, save_file

from hf2l.backends.local import LocalStore
from hf2l.client_steps import download_client_round, upload_client_update
from hf2l.hub_helpers import (
    CLIENT_CONTEXT_FILE, ROUND_FILE, SUBMISSION_FILE, artifact_hashes, read_json, write_json,
)


REPO = "owner/model"
ARTIFACTS = ["config.json", "model.safetensors"]


def checkpoint(folder: Path, value: float = 0.0) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    write_json(folder / "config.json", {"model_type": "test", "width": 1})
    save_file({"weight": np.array([value], dtype=np.float32)}, folder / "model.safetensors")


class LocalCyclicHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.storage = self.root / "store"
        self.owner = LocalStore(self.storage, "owner")
        self.addCleanup(self.owner.close)
        initial = self.root / "initial"
        checkpoint(initial)
        write_json(initial / ROUND_FILE, {
            "schema_version": 2, "backend": "local", "round": 0,
            "algorithm_spec": {"name": "fedavg", "version": 1, "params": {}},
            "checkpoint_files_sha256": artifact_hashes(initial, ARTIFACTS),
        })
        self.base = self.owner.initialize_repository(REPO, initial, private=False).resolved_revision
        self.sequence = 0

    def client(self, participant):
        store = LocalStore(self.storage, participant)
        self.addCleanup(store.close)
        return store

    def train_and_upload(self, store, work, participant, increment=1.0):
        self.sequence += 1
        trained = self.root / f"trained-{self.sequence}"
        shutil.copytree(work / "base_model", trained)
        tensors = load_file(trained / "model.safetensors")
        tensors["weight"] += increment
        save_file(tensors, trained / "model.safetensors")
        result, manifest = upload_client_update(store, work, trained, participant, 3)
        return result, manifest, trained

    def first_submission(self, *, cyclic=True):
        alice = self.client("alice")
        work = self.root / "alice-first"
        kwargs = {"workflow": "cyclic"} if cyclic else {}
        download_client_round(alice, REPO, "main", work, **kwargs)
        result, manifest, trained = self.train_and_upload(alice, work, "alice")
        return alice, result, manifest, trained

    def test_alice_bob_alice_chain_uses_immutable_detached_snapshots(self):
        alice, first, first_manifest, first_trained = self.first_submission()
        self.assertEqual("cyclic", first_manifest["workflow"])
        self.assertEqual({"root_revision": self.base, "root_round": 0, "parents": []},
                         first_manifest["lineage"])
        bob = self.client("bob")
        bob_work = self.root / "bob"
        bob_context = download_client_round(
            bob, REPO, first.revision, bob_work, workflow="cyclic",
            source_kind="submission", source_participant="alice",
        )
        first_parent = {"revision": first.resolved_revision, "participant": "alice"}
        self.assertEqual(first.resolved_revision, bob_context["base_revision"])
        self.assertEqual("submission", bob_context["source_kind"])
        self.assertEqual({"root_revision": self.base, "root_round": 0, "parents": [first_parent]},
                         bob_context["lineage"])
        self.assertFalse((bob_work / "base_model" / ROUND_FILE).exists())
        np.testing.assert_array_equal(load_file(bob_work / "base_model" / "model.safetensors")["weight"], [1.0])

        # Altering a prior client's training folder cannot change its published snapshot.
        save_file({"weight": np.array([99.0], np.float32)}, first_trained / "model.safetensors")
        second, second_manifest, _ = self.train_and_upload(bob, bob_work, "bob")
        self.assertEqual(bob_context["lineage"], second_manifest["lineage"])
        self.assertEqual(first.resolved_revision, second_manifest["base_revision"])

        alice_work = self.root / "alice-again"
        alice_context = download_client_round(
            alice, REPO, second.resolved_revision, alice_work, workflow="cyclic",
            source_kind="submission", source_participant="bob",
        )
        self.assertEqual([first_parent, {"revision": second.resolved_revision, "participant": "bob"}],
                         alice_context["lineage"]["parents"])
        np.testing.assert_array_equal(load_file(alice_work / "base_model" / "model.safetensors")["weight"], [2.0])
        third, third_manifest, _ = self.train_and_upload(alice, alice_work, "alice")
        self.assertEqual(alice_context["lineage"], third_manifest["lineage"])
        self.assertEqual(0, third_manifest["source_round"])
        self.assertEqual(self.base, self.owner.resolve_revision(REPO, "main"))
        final = self.root / "final"
        self.owner.download_snapshot(REPO, third.resolved_revision, final)
        np.testing.assert_array_equal(load_file(final / "model.safetensors")["weight"], [3.0])
        self.assertFalse((final / ROUND_FILE).exists())

    def test_ordinary_fedavg_submission_can_start_a_cyclic_chain(self):
        _, first, _, _ = self.first_submission(cyclic=False)
        context = download_client_round(
            self.client("bob"), REPO, first.revision, self.root / "bob",
            workflow="cyclic", source_kind="submission", source_participant="alice",
        )
        self.assertEqual({"root_revision": self.base, "root_round": 0,
                          "parents": [{"revision": first.resolved_revision, "participant": "alice"}]},
                         context["lineage"])
        self.assertEqual("fedavg", context["algorithm_spec"]["name"])

    def test_default_fedavg_remains_a_global_round_workflow(self):
        alice = self.client("alice")
        work = self.root / "fedavg"
        context = download_client_round(alice, REPO, "main", work)
        self.assertEqual(self.base, context["base_revision"])
        self.assertEqual("fedavg", context["algorithm_spec"]["name"])
        first, manifest, _ = self.train_and_upload(alice, work, "alice")
        self.assertEqual(self.base, manifest["base_revision"])
        self.assertEqual(self.base, self.owner.resolve_revision(REPO, "main"))
        with self.assertRaises((ValueError, FileNotFoundError)):
            download_client_round(alice, REPO, first.revision, self.root / "ordinary-submission")

    def test_cyclic_upload_revalidates_local_base_hashes(self):
        alice = self.client("alice")
        work = self.root / "alice"
        download_client_round(alice, REPO, "main", work, workflow="cyclic")
        trained = self.root / "trained"
        checkpoint(trained, 1.0)
        save_file({"weight": np.array([17.0], np.float32)}, work / "base_model" / "model.safetensors")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            upload_client_update(alice, work, trained, "alice", 1)
        self.assertEqual([], self.owner.discover_submissions(REPO)[0])

    def test_cyclic_upload_requires_the_local_source_manifest(self):
        _, first, _, _ = self.first_submission()
        bob = self.client("bob")
        work = self.root / "bob"
        download_client_round(bob, REPO, first.revision, work, workflow="cyclic",
                              source_kind="submission", source_participant="alice")
        (work / "base_model" / SUBMISSION_FILE).unlink()
        trained = self.root / "bob-trained"
        checkpoint(trained, 2.0)
        with self.assertRaises((ValueError, FileNotFoundError)):
            upload_client_update(bob, work, trained, "bob", 1)
        self.assertEqual(1, len(self.owner.discover_submissions(REPO)[0]))

    def test_cyclic_upload_rejects_context_lineage_changes(self):
        _, first, _, _ = self.first_submission()
        bob = self.client("bob")
        work = self.root / "bob"
        download_client_round(bob, REPO, first.revision, work, workflow="cyclic",
                              source_kind="submission", source_participant="alice")
        context = read_json(work / CLIENT_CONTEXT_FILE)
        context["lineage"]["parents"][-1]["participant"] = "mallory"
        write_json(work / CLIENT_CONTEXT_FILE, context)
        trained = self.root / "bob-trained"
        checkpoint(trained, 2.0)
        with self.assertRaises(ValueError):
            upload_client_update(bob, work, trained, "bob", 1)
        self.assertEqual(1, len(self.owner.discover_submissions(REPO)[0]))

    def test_removing_workflow_markers_cannot_downgrade_a_submission_source(self):
        _, first, _, _ = self.first_submission()
        bob = self.client("bob")
        work = self.root / "bob"
        download_client_round(bob, REPO, first.revision, work, workflow="cyclic",
                              source_kind="submission", source_participant="alice")
        context = read_json(work / CLIENT_CONTEXT_FILE)
        for field in ("workflow", "lineage", "source_kind", "source_participant"):
            context.pop(field)
        write_json(work / CLIENT_CONTEXT_FILE, context)
        trained = self.root / "bob-trained"
        checkpoint(trained, 2.0)
        with patch.object(bob, "publish_submission", wraps=bob.publish_submission) as publish:
            with self.assertRaises(ValueError):
                upload_client_update(bob, work, trained, "bob", 1)
            publish.assert_not_called()


class CyclicSnapshotValidationTests(unittest.TestCase):
    """Snapshots mimic HF commits retaining an inherited global round file."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.snapshots = {}
        self.aliases = {"main": "global-sha", "alice-pr": "alice-sha"}
        self.store = SimpleNamespace(
            name="huggingface", resolve_revision=self.resolve_revision,
            download_snapshot=self.download_snapshot,
        )
        self.counter = 0
        global_dir = self.add_snapshot("global-sha", value=0.0)
        write_json(global_dir / ROUND_FILE, {
            "schema_version": 2, "backend": "huggingface", "round": 0,
            "algorithm_spec": {"name": "fedavg", "version": 1, "params": {}},
            "checkpoint_files_sha256": artifact_hashes(global_dir, ARTIFACTS),
        })
        self.add_submission("alice-sha", participant="alice", base_revision="global-sha", value=1.0)
        # A Hugging Face PR can inherit this file while its weights have changed.
        shutil.copyfile(global_dir / ROUND_FILE, self.snapshots["alice-sha"] / ROUND_FILE)

    def add_snapshot(self, revision, *, value):
        folder = self.root / "snapshots" / revision
        checkpoint(folder, value)
        self.snapshots[revision] = folder
        return folder

    def add_submission(self, revision, *, participant, base_revision, value, lineage=None):
        folder = self.add_snapshot(revision, value=value)
        document = {
            "schema_version": 2, "backend": "huggingface", "repo_id": REPO,
            "participant": participant, "base_revision": base_revision, "source_round": 0,
            "num_examples": 1, "submission_revision": f"refs/pr/{len(self.snapshots)}",
            "algorithm_spec": {"name": "fedavg", "version": 1, "params": {}},
            "checkpoint_files_sha256": artifact_hashes(folder, ARTIFACTS),
        }
        self.aliases[document["submission_revision"]] = revision
        if lineage is not None:
            document.update(workflow="cyclic", source_kind="submission" if lineage["parents"] else "global",
                            lineage=lineage)
            if lineage["parents"]:
                document["source_participant"] = lineage["parents"][-1]["participant"]
        write_json(folder / SUBMISSION_FILE, document)
        return document

    def resolve_revision(self, repo, revision):
        self.assertEqual(REPO, repo)
        return self.aliases.get(revision, revision)

    def download_snapshot(self, repo, revision, destination, *, allow_patterns=None):
        self.assertEqual(REPO, repo)
        shutil.copytree(self.snapshots[self.resolve_revision(repo, revision)], destination, dirs_exist_ok=True)

    def download(self, revision="alice-pr", participant="alice", **kwargs):
        self.counter += 1
        work = self.root / f"download-{self.counter}"
        return download_client_round(self.store, REPO, revision, work, workflow="cyclic",
                                     source_kind="submission", source_participant=participant, **kwargs)

    def change_manifest(self, revision="alice-sha", **changes):
        path = self.snapshots[revision] / SUBMISSION_FILE
        manifest = read_json(path)
        manifest.update(changes)
        write_json(path, manifest)

    def add_bob(self):
        lineage = {"root_revision": "global-sha", "root_round": 0,
                   "parents": [{"revision": "alice-sha", "participant": "alice"}]}
        return self.add_submission("bob-sha", participant="bob", base_revision="alice-sha",
                                   value=2.0, lineage=lineage)

    def test_submission_source_ignores_inherited_stale_global_record(self):
        context = self.download()
        self.assertEqual("alice-sha", context["base_revision"])
        self.assertEqual(0, context["source_round"])
        self.assertEqual({"root_revision": "global-sha", "root_round": 0,
                          "parents": [{"revision": "alice-sha", "participant": "alice"}]},
                         context["lineage"])

    def test_inherited_round_file_cannot_make_a_submission_a_global_source(self):
        folder = self.snapshots["alice-sha"]
        # Even unchanged weights satisfy the inherited root hash, so document
        # identity must distinguish the submission from a global round.
        checkpoint(folder, 0.0)
        self.change_manifest(checkpoint_files_sha256=artifact_hashes(folder, ARTIFACTS))
        for index, options in enumerate([{}, {"workflow": "cyclic"}]):
            with self.subTest(options=options), self.assertRaises(ValueError):
                download_client_round(self.store, REPO, "alice-pr", self.root / f"global-source-{index}",
                                      **options)

    def test_selected_submission_requires_matching_repository_backend_and_participant(self):
        original = read_json(self.snapshots["alice-sha"] / SUBMISSION_FILE)
        for change in [{"repo_id": "another/model"}, {"backend": "local"}, {"participant": "mallory"}]:
            write_json(self.snapshots["alice-sha"] / SUBMISSION_FILE, {**original, **change})
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.download()

    def test_authenticated_storage_participant_must_match_manifest(self):
        self.store.capabilities = SimpleNamespace(binds_participants=True)
        self.store.explicit_submissions = lambda repo, values: [
            SimpleNamespace(participant="mallory", revision="alice-sha"),
        ]
        with self.assertRaisesRegex(ValueError, "authenticated storage identity"):
            self.download()

    def test_predecessor_must_have_the_declared_parent_in_backends_with_ancestry(self):
        self.store.supports_ancestry = True
        self.store.is_descendant = lambda repo, revision, parent: False
        with self.assertRaisesRegex(ValueError, "does not descend"):
            self.download()

    def test_submission_source_requires_hashes_including_legacy_manifests(self):
        manifest = read_json(self.snapshots["alice-sha"] / SUBMISSION_FILE)
        manifest["schema_version"] = 1
        del manifest["checkpoint_files_sha256"]
        write_json(self.snapshots["alice-sha"] / SUBMISSION_FILE, manifest)
        with self.assertRaises(ValueError):
            self.download()

    def test_selected_predecessor_hash_tampering_is_rejected(self):
        save_file({"weight": np.array([100.0], np.float32)}, self.snapshots["alice-sha"] / "model.safetensors")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            self.download()

    def test_recursive_ancestor_and_root_hashes_are_verified(self):
        self.add_bob()
        for revision in ["alice-sha", "global-sha"]:
            path = self.snapshots[revision] / "model.safetensors"
            original = path.read_bytes()
            save_file({"weight": np.array([100.0], np.float32)}, path)
            with self.subTest(revision=revision), self.assertRaisesRegex(ValueError, "checksum mismatch"):
                self.download("bob-sha", "bob")
            path.write_bytes(original)

    def test_recursive_lineage_cannot_forge_parent_participants_or_root_round(self):
        original = self.add_bob()
        malformed = [
            {"root_revision": "global-sha", "root_round": 0,
             "parents": [{"revision": "alice-sha", "participant": "mallory"}]},
            {"root_revision": "global-sha", "root_round": 1,
             "parents": [{"revision": "alice-sha", "participant": "alice"}]},
        ]
        for lineage in malformed:
            self.change_manifest("bob-sha", lineage=lineage, source_round=lineage["root_round"],
                                 source_participant=lineage["parents"][-1]["participant"])
            with self.subTest(lineage=lineage), self.assertRaises(ValueError):
                self.download("bob-sha", "bob")
        write_json(self.snapshots["bob-sha"] / SUBMISSION_FILE, original)
        self.change_manifest("alice-sha", source_round=1)
        with self.assertRaises(ValueError):
            self.download("bob-sha", "bob")

    def test_lineage_must_end_at_the_declared_base(self):
        self.add_bob()
        self.change_manifest("bob-sha", base_revision="global-sha")
        with self.assertRaises(ValueError):
            self.download("bob-sha", "bob")

    def test_duplicate_lineage_revisions_and_cycles_are_rejected(self):
        self.add_bob()
        malformed = [
            {"root_revision": "global-sha", "root_round": 0,
             "parents": [{"revision": "alice-sha", "participant": "alice"},
                         {"revision": "alice-sha", "participant": "alice"}]},
            {"root_revision": "global-sha", "root_round": 0,
             "parents": [{"revision": "bob-sha", "participant": "bob"},
                         {"revision": "alice-sha", "participant": "alice"}]},
            {"root_revision": "global-sha", "root_round": 0,
             "parents": [{"revision": "global-sha", "participant": "owner"},
                         {"revision": "alice-sha", "participant": "alice"}]},
        ]
        for lineage in malformed:
            self.change_manifest("bob-sha", lineage=lineage)
            with self.subTest(lineage=lineage), self.assertRaises(ValueError):
                self.download("bob-sha", "bob")

    def test_lineage_is_bounded_before_resolving_untrusted_ancestors(self):
        self.add_bob()
        oversized = {"root_revision": "global-sha", "root_round": 0,
                     "parents": [{"revision": f"parent-{index}", "participant": "alice"}
                                 for index in range(65)]}
        self.change_manifest("bob-sha", base_revision="parent-64", lineage=oversized)
        with self.assertRaises(ValueError):
            self.download("bob-sha", "bob")

    def test_sixty_four_handoffs_are_valid_and_the_next_is_rejected(self):
        parents = []
        previous = "global-sha"
        for index in range(65):
            revision = f"handoff-{index}"
            self.add_submission(revision, participant="alice", base_revision=previous, value=float(index),
                                lineage={"root_revision": "global-sha", "root_round": 0,
                                         "parents": list(parents)})
            parents.append({"revision": revision, "participant": "alice"})
            previous = revision
        context = self.download("handoff-63", "alice")
        self.assertEqual(64, len(context["lineage"]["parents"]))
        with self.assertRaises(ValueError):
            self.download("handoff-64", "alice")

    def test_source_selection_requires_explicit_cyclic_submission_options(self):
        invalid = [
            {"workflow": "fedavg", "source_kind": "submission", "source_participant": "alice"},
            {"workflow": "cyclic", "source_kind": "submission"},
            {"workflow": "cyclic", "source_kind": "global", "source_participant": "alice"},
            {"workflow": "other"},
            {"workflow": "cyclic", "source_kind": "other"},
        ]
        for index, options in enumerate(invalid):
            with self.subTest(options=options), self.assertRaises(ValueError):
                download_client_round(self.store, REPO, "alice-pr", self.root / f"invalid-{index}", **options)


class HuggingFaceCyclicPublicationTests(unittest.TestCase):
    def test_sdk_compares_uploads_to_the_cyclic_parent_before_filtering_unchanged_files(self):
        from huggingface_hub import CommitOperationAdd, HfApi
        from huggingface_hub import _commit_api, hf_api
        from hf2l.backends.huggingface import HuggingFaceStore

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trained, parent, main = root / "trained", root / "parent", root / "main"
            checkpoint(trained, 1.0)  # Current main has these same weights.
            checkpoint(main, 1.0)
            checkpoint(parent, 2.0)   # The selected cyclic predecessor differs.
            write_json(trained / SUBMISSION_FILE, {
                "workflow": "cyclic", "participant": "bob",
                "checkpoint_files_sha256": artifact_hashes(trained, ARTIFACTS),
            })
            parent_revision = "a" * 40
            api = HfApi(token=False)
            with patch("hf2l.backends.huggingface.HfApi", return_value=api):
                store = HuggingFaceStore(None)

            def fetch_modes(*, additions, revision, **kwargs):
                for operation in additions:
                    operation._upload_mode = "regular"
                    reference = parent if revision == parent_revision else main
                    remote_file = reference / operation.path_in_repo
                    if remote_file.exists():
                        remote = CommitOperationAdd(path_in_repo=operation.path_in_repo, path_or_fileobj=remote_file)
                        remote._upload_mode = "regular"
                        operation._remote_oid = remote._local_oid
                    else:
                        operation._remote_oid = None

            commit = SimpleNamespace(pr_revision="refs/pr/7", pr_url="https://example.test/pr/7", oid="b" * 40)
            published = root / "published"

            def publish_snapshot(*, operations, **kwargs):
                shutil.copytree(parent, published)
                for operation in operations:
                    destination = published / operation.path_in_repo
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with operation.as_file() as source:
                        destination.write_bytes(source.read())
                return commit

            with ExitStack() as stack:
                # Older supported SDKs import transport functions at module
                # scope; recent SDKs import them inside the public methods.
                hooks = hf_api if hasattr(hf_api, "_fetch_upload_modes") else _commit_api
                fetch = stack.enter_context(patch.object(hooks, "_fetch_upload_modes", side_effect=fetch_modes))
                stack.enter_context(patch.object(hooks, "_fetch_files_to_copy", return_value={}))
                stack.enter_context(patch.object(api, "repo_info", return_value=SimpleNamespace(xet_enabled=False)))
                if hasattr(api, "_duplicate_lfs_files"):
                    stack.enter_context(patch.object(api, "_duplicate_lfs_files"))
                if hasattr(hf_api, "_upload_lfs_files"):
                    stack.enter_context(patch.object(hf_api, "_upload_lfs_files"))
                preupload = stack.enter_context(patch.object(api, "preupload_lfs_files", wraps=api.preupload_lfs_files))
                commit_call = stack.enter_context(patch.object(api, "create_commit", wraps=api.create_commit))
                modern_transport = hasattr(_commit_api, "_send_commit")
                if modern_transport:
                    send = stack.enter_context(patch.object(_commit_api, "_send_commit", side_effect=publish_snapshot))
                else:
                    prepare = hf_api._prepare_commit_payload

                    def prepare_and_publish(**kwargs):
                        publish_snapshot(**kwargs)
                        return prepare(**kwargs)

                    send = stack.enter_context(patch.object(hf_api, "_prepare_commit_payload", side_effect=prepare_and_publish))
                    response = SimpleNamespace(json=lambda: {
                        "commitUrl": f"https://huggingface.co/{REPO}/commit/{commit.oid}",
                        "commitOid": commit.oid,
                        "pullRequestUrl": f"https://huggingface.co/{REPO}/discussions/7",
                    })
                    post = Mock(return_value=response)
                    stack.enter_context(patch.object(hf_api, "get_session", return_value=SimpleNamespace(post=post)))
                    stack.enter_context(patch.object(hf_api, "hf_raise_for_status"))
                result = store.publish_submission(
                    REPO, trained, [*ARTIFACTS, SUBMISSION_FILE], participant="bob", source_round=0,
                    base_revision=parent_revision, submission_revision=None,
                )

            fetch.assert_called_once()
            self.assertEqual(parent_revision, fetch.call_args.kwargs["revision"])
            first_preupload = preupload.call_args_list[0].kwargs
            self.assertEqual(parent_revision, first_preupload["revision"])
            self.assertTrue(first_preupload["create_pr"])
            self.assertFalse(first_preupload["free_memory"])
            send.assert_called_once()
            sent = send.call_args.kwargs
            self.assertEqual(parent_revision, sent["parent_commit"])
            self.assertTrue(commit_call.call_args.kwargs["create_pr"])
            self.assertEqual(parent_revision, commit_call.call_args.kwargs["parent_commit"])
            if modern_transport:
                self.assertTrue(sent["create_pr"])
                self.assertEqual("main", sent["revision"])
            else:
                self.assertTrue(post.call_args.kwargs["url"].endswith("/commit/main"))
                self.assertEqual({"create_pr": "1"}, post.call_args.kwargs["params"])
            self.assertIn("model.safetensors", [operation.path_in_repo for operation in sent["operations"]])
            self.assertEqual((trained / "model.safetensors").read_bytes(),
                             (published / "model.safetensors").read_bytes())
            self.assertNotEqual((parent / "model.safetensors").read_bytes(),
                                (published / "model.safetensors").read_bytes())
            self.assertEqual(read_json(published / SUBMISSION_FILE)["checkpoint_files_sha256"],
                             artifact_hashes(published, ARTIFACTS))
            self.assertEqual("refs/pr/7", result.revision)

    def test_default_publication_accepts_an_api_with_only_the_existing_commit_boundary(self):
        from hf2l.backends.huggingface import HuggingFaceStore

        with tempfile.TemporaryDirectory() as directory:
            trained = Path(directory)
            checkpoint(trained, 1.0)
            write_json(trained / SUBMISSION_FILE, {"participant": "alice"})
            commit = SimpleNamespace(pr_revision="refs/pr/3", pr_url=None, oid="b" * 40)
            api = SimpleNamespace(create_commit=Mock(return_value=commit))
            with patch("hf2l.backends.huggingface.HfApi", return_value=api):
                store = HuggingFaceStore(None)
            result = store.publish_submission(
                REPO, trained, [*ARTIFACTS, SUBMISSION_FILE], participant="alice", source_round=0,
                base_revision="a" * 40, submission_revision=None,
            )
            api.create_commit.assert_called_once()
            self.assertEqual("a" * 40, api.create_commit.call_args.kwargs["parent_commit"])
            self.assertEqual("refs/pr/3", result.revision)


if __name__ == "__main__":
    unittest.main()
