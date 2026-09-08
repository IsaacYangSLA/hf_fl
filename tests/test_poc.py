from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import torch
from safetensors.torch import load_file, save_file


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from hf2l.checkpoint_utils import aggregate_checkpoints, discover_checkpoint  # noqa: E402
from hf2l.backends.base import PublishResult  # noqa: E402
from hf2l.backends.huggingface import HuggingFaceStore  # noqa: E402
from hf2l.backends.jfrog import JFrogStore  # noqa: E402
from examples.cifar10_data import (  # noqa: E402
    load_npz_dataset as load_cifar10_npz_dataset,
    synthetic_dataset as synthetic_cifar10_dataset,
)
from hf2l.client_steps import upload_client_update  # noqa: E402
from examples.lenet_model import LeNet  # noqa: E402
from examples.mnist_data import load_npz_dataset, synthetic_dataset  # noqa: E402
from examples.vgg_model import VGG  # noqa: E402
from hf2l.create_allowlist import create_allowlist  # noqa: E402
from hf2l.hub_helpers import (  # noqa: E402
    CLIENT_CONTEXT_FILE,
    SCHEMA_VERSION,
    artifact_hashes,
    base_revision_from,
    validate_artifact_hashes,
    write_json,
)
from hf2l.owner_fedavg import (  # noqa: E402
    fedavg_states,
    load_allowlist,
    validate_submission_manifest,
)
from hf2l.plugin_loader import load_plugin, parse_plugin_args  # noqa: E402


class PocTests(unittest.TestCase):
    def test_lenet_shape_and_hf_round_trip(self) -> None:
        model = LeNet()
        output = model(torch.zeros(3, 1, 28, 28))
        self.assertEqual(output.shape, (3, 10))
        with tempfile.TemporaryDirectory() as temporary:
            model.save_pretrained(temporary)
            loaded = LeNet.from_pretrained(temporary)
            for expected, actual in zip(model.parameters(), loaded.parameters(), strict=True):
                torch.testing.assert_close(expected, actual)

    def test_vgg_shape_and_hf_round_trip(self) -> None:
        model = VGG(width_multiplier=0.03125, dropout=0.0)
        output = model(torch.zeros(2, 3, 32, 32))
        self.assertEqual(output.shape, (2, 10))
        with tempfile.TemporaryDirectory() as temporary:
            model.save_pretrained(temporary)
            loaded = VGG.from_pretrained(temporary)
            self.assertEqual(loaded.width_multiplier, 0.03125)
            self.assertEqual(loaded.dropout, 0.0)
            for expected, actual in zip(model.parameters(), loaded.parameters(), strict=True):
                torch.testing.assert_close(expected, actual)

    def test_synthetic_data_is_reproducible_and_client_specific(self) -> None:
        alice_1 = synthetic_dataset("alice", 20, 7)
        alice_2 = synthetic_dataset("alice", 20, 7)
        bob = synthetic_dataset("bob", 20, 7)
        torch.testing.assert_close(alice_1.tensors[0], alice_2.tensors[0])
        torch.testing.assert_close(alice_1.tensors[1], alice_2.tensors[1])
        self.assertFalse(torch.equal(alice_1.tensors[0], bob.tensors[0]))

    def test_npz_dataset_loading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "data.npz"
            np.savez(
                path,
                x=np.zeros((4, 28, 28), dtype=np.uint8),
                y=np.array([0, 1, 2, 3], dtype=np.int64),
            )
            dataset = load_npz_dataset(path)
            self.assertEqual(dataset.tensors[0].shape, (4, 1, 28, 28))
            self.assertEqual(dataset.tensors[0].dtype, torch.float32)

    def test_cifar10_data_shapes_and_reproducibility(self) -> None:
        alice_1 = synthetic_cifar10_dataset("alice", 12, 7)
        alice_2 = synthetic_cifar10_dataset("alice", 12, 7)
        self.assertEqual(alice_1.tensors[0].shape, (12, 3, 32, 32))
        torch.testing.assert_close(alice_1.tensors[0], alice_2.tensors[0])
        torch.testing.assert_close(alice_1.tensors[1], alice_2.tensors[1])

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "cifar10.npz"
            np.savez(
                path,
                x=np.zeros((4, 32, 32, 3), dtype=np.uint8),
                y=np.array([0, 1, 2, 3], dtype=np.int64),
            )
            dataset = load_cifar10_npz_dataset(path)
            self.assertEqual(dataset.tensors[0].shape, (4, 3, 32, 32))
            self.assertEqual(dataset.tensors[0].dtype, torch.float32)

    def test_fedavg_uses_supplied_coefficients(self) -> None:
        reference = {
            "weight": torch.tensor([0.0, 0.0], dtype=torch.float32),
            "bias": torch.tensor([0.0], dtype=torch.float32),
        }
        first = {
            "weight": torch.tensor([2.0, 4.0], dtype=torch.float32),
            "bias": torch.tensor([1.0], dtype=torch.float32),
        }
        second = {
            "weight": torch.tensor([6.0, 8.0], dtype=torch.float32),
            "bias": torch.tensor([3.0], dtype=torch.float32),
        }
        result = fedavg_states(reference, [first, second], [0.25, 0.75])
        torch.testing.assert_close(result["weight"], torch.tensor([5.0, 7.0]))
        torch.testing.assert_close(result["bias"], torch.tensor([2.5]))

    def test_generic_checkpoint_aggregation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            layouts = []
            for name, weight in (("base", 0.0), ("alice", 2.0), ("bob", 6.0)):
                model_dir = root / name
                model_dir.mkdir()
                write_json(model_dir / "config.json", {"architecture": "anything"})
                save_file(
                    {
                        "weight": torch.full((2,), weight, dtype=torch.float32),
                        "constant": torch.tensor([7], dtype=torch.int64),
                    },
                    model_dir / "model.safetensors",
                )
                layouts.append(discover_checkpoint(model_dir))

            output = root / "aggregate"
            aggregate_checkpoints(layouts[0], layouts[1:], [0.25, 0.75], output)
            result = load_file(output / "model.safetensors")
            torch.testing.assert_close(result["weight"], torch.tensor([5.0, 5.0]))
            torch.testing.assert_close(result["constant"], torch.tensor([7]))

    def test_vgg_uses_the_generic_checkpoint_aggregator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            layouts = []
            for name, value in (("base", 0.0), ("alice", 2.0), ("bob", 6.0)):
                model_dir = root / name
                model = VGG(width_multiplier=0.03125, dropout=0.0)
                with torch.no_grad():
                    for parameter in model.parameters():
                        parameter.fill_(value)
                model.save_pretrained(model_dir)
                layouts.append(discover_checkpoint(model_dir))

            output = root / "aggregate"
            aggregate_checkpoints(layouts[0], layouts[1:], [0.25, 0.75], output)
            aggregate = VGG.from_pretrained(output)
            for parameter in aggregate.parameters():
                torch.testing.assert_close(parameter, torch.full_like(parameter, 5.0))

    def test_sharded_checkpoint_index_is_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            layouts = []
            for name, value in (("base", 0.0), ("alice", 2.0), ("bob", 6.0)):
                model_dir = root / name
                model_dir.mkdir()
                write_json(model_dir / "config.json", {"model_type": "test"})
                save_file(
                    {"a": torch.full((2,), value)},
                    model_dir / "model-00001-of-00002.safetensors",
                )
                save_file(
                    {"b": torch.full((3,), value)},
                    model_dir / "model-00002-of-00002.safetensors",
                )
                write_json(
                    model_dir / "model.safetensors.index.json",
                    {
                        "metadata": {"total_size": 20},
                        "weight_map": {
                            "a": "model-00001-of-00002.safetensors",
                            "b": "model-00002-of-00002.safetensors",
                        },
                    },
                )
                layouts.append(discover_checkpoint(model_dir))
            self.assertEqual(len(layouts[0].weight_files), 2)
            self.assertEqual(layouts[0].tensors["b"].shape, (3,))

            output = root / "aggregate"
            aggregate_checkpoints(layouts[0], layouts[1:], [0.25, 0.75], output)
            first_shard = load_file(output / "model-00001-of-00002.safetensors")
            second_shard = load_file(output / "model-00002-of-00002.safetensors")
            torch.testing.assert_close(first_shard["a"], torch.full((2,), 5.0))
            torch.testing.assert_close(second_shard["b"], torch.full((3,), 5.0))

    def test_external_training_output_can_be_submitted(self) -> None:
        class FakeStore:
            name = "huggingface"

            def __init__(self) -> None:
                self.paths = []

            def new_submission_revision(self, participant, source_round):
                return None

            def publish_submission(self, repo_id, folder, paths, **kwargs):
                self.paths = paths
                self.base_revision = kwargs["base_revision"]
                return PublishResult("refs/pr/9", "https://example/pr/9")

        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary) / "work"
            base = work / "base_model"
            trained = work / "trainer-output"
            base.mkdir(parents=True)
            trained.mkdir()
            for directory, value in ((base, 0.0), (trained, 1.0)):
                write_json(directory / "config.json", {"model": "custom"})
                save_file(
                    {"weight": torch.tensor([value], dtype=torch.float32)},
                    directory / "model.safetensors",
                )
            write_json(
                work / CLIENT_CONTEXT_FILE,
                {
                    "schema_version": SCHEMA_VERSION,
                    "backend": "huggingface",
                    "repo_id": "owner/model",
                    "base_revision": "abc123",
                    "source_round": 4,
                    "base_model_dir": "base_model",
                },
            )
            store = FakeStore()
            result, manifest = upload_client_update(
                store, work, trained, "alice", 12, {"trainer": "private"}
            )
            self.assertEqual(result.revision, "refs/pr/9")
            self.assertEqual(store.base_revision, "abc123")
            self.assertEqual(manifest["training"]["trainer"], "private")
            self.assertEqual(
                set(store.paths),
                {"config.json", "model.safetensors", "fedavg_submission.json"},
            )
            self.assertEqual(
                manifest["checkpoint_files_sha256"],
                artifact_hashes(trained, ["config.json", "model.safetensors"]),
            )

    def test_plugin_arguments_decode_json_values(self) -> None:
        values = parse_plugin_args(["epochs=3", "enabled=true", "name=alice"])
        self.assertEqual(values, {"epochs": 3, "enabled": True, "name": "alice"})

    def test_builtin_and_local_plugins_can_be_loaded(self) -> None:
        self.assertEqual(load_plugin("lenet").__name__, "hf2l.plugins.lenet_poc")
        self.assertEqual(
            load_plugin("vgg-cifar10").__name__,
            "hf2l.plugins.vgg_cifar10_poc",
        )
        with tempfile.TemporaryDirectory() as temporary:
            plugin_path = Path(temporary) / "custom_plugin.py"
            plugin_path.write_text(
                "def train_model(base_dir, output_dir, options):\n"
                "    return {'num_examples': 1}\n",
                encoding="utf-8",
            )
            self.assertTrue(callable(load_plugin(plugin_path).train_model))

    def test_create_allowlist_writes_valid_normalized_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "allowlist.json"
            created = create_allowlist(
                ["Alice-HF=alice", "bob-hf=bob"],
                path,
            )
            self.assertEqual(created, {"alice-hf": "alice", "bob-hf": "bob"})
            self.assertEqual(load_allowlist(path), created)
            with self.assertRaisesRegex(ValueError, "already exists"):
                create_allowlist(["carol-hf=carol"], path)

    def test_create_allowlist_rejects_ambiguous_mappings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "Duplicate repository identity"):
                create_allowlist(
                    ["Alice-HF=alice", "alice-hf=alice-duplicate"],
                    root / "duplicate-author.json",
                )
            with self.assertRaisesRegex(ValueError, "mapped to both"):
                create_allowlist(
                    ["alice-hf=participant", "bob-hf=participant"],
                    root / "duplicate-participant.json",
                )

    def test_allowlist_binds_hf_author_to_participant(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "allowlist.json"
            write_json(path, {"Alice-HF": "alice", "bob-hf": "bob"})
            allowlist = load_allowlist(path)
            self.assertEqual(allowlist, {"alice-hf": "alice", "bob-hf": "bob"})

            manifest = {
                "schema_version": SCHEMA_VERSION,
                "backend": "huggingface",
                "repo_id": "owner/model",
                "base_revision": "abc123",
                "source_round": 4,
                "participant": "alice",
                "num_examples": 12,
            }
            participant, count = validate_submission_manifest(
                manifest,
                repo_id="owner/model",
                base_revision="abc123",
                current_round=4,
                revision="refs/pr/1",
                expected_participant=allowlist["alice-hf"],
            )
            self.assertEqual((participant, count), ("alice", 12))
            with self.assertRaisesRegex(ValueError, "approved only as participant"):
                validate_submission_manifest(
                    {**manifest, "participant": "mallory"},
                    repo_id="owner/model",
                    base_revision="abc123",
                    current_round=4,
                    revision="refs/pr/1",
                    expected_participant=allowlist["alice-hf"],
                )

    def test_pr_discovery_keeps_only_allowlisted_authors(self) -> None:
        class FakeApi:
            def get_repo_discussions(self, **kwargs):
                self.arguments = kwargs
                return iter(
                    [
                        SimpleNamespace(
                            num=8, author="mallory-hf", is_pull_request=True
                        ),
                        SimpleNamespace(num=5, author="Bob-HF", is_pull_request=True),
                        SimpleNamespace(num=3, author="alice-hf", is_pull_request=True),
                    ]
                )

        store = object.__new__(HuggingFaceStore)
        store.api = FakeApi()
        candidates, skipped = store.discover_submissions("owner/model")
        self.assertEqual(
            [candidate.identifier for candidate in candidates],
            ["refs/pr/3", "refs/pr/5", "refs/pr/8"],
        )
        self.assertEqual(candidates[1].author, "Bob-HF")
        self.assertEqual(skipped, [])
        self.assertEqual(store.api.arguments["discussion_type"], "pull_request")
        self.assertEqual(store.api.arguments["discussion_status"], "open")

    def test_explicit_pr_selection_also_enforces_allowlist(self) -> None:
        class FakeApi:
            def get_discussion_details(self, **kwargs):
                authors = {3: "alice-hf", 5: "mallory-hf"}
                return SimpleNamespace(
                    author=authors[kwargs["discussion_num"]], is_pull_request=True
                )

        store = object.__new__(HuggingFaceStore)
        store.api = FakeApi()
        candidates = store.explicit_submissions("owner/model", ["3"])
        self.assertEqual(candidates[0].revision, "refs/pr/3")
        self.assertEqual(candidates[0].author, "alice-hf")

    def test_jfrog_submission_revision_is_valid_and_unique(self) -> None:
        store = object.__new__(JFrogStore)
        first = store.new_submission_revision("Alice Example", 3)
        second = store.new_submission_revision("Alice Example", 3)
        self.assertRegex(first, r"^r0003-Alice-Example-[a-f0-9]{12}$")
        self.assertNotEqual(first, second)

    def test_jfrog_upload_repairs_placeholder_commit_url(self) -> None:
        class FakeApi:
            def upload_folder(self, **kwargs):
                from huggingface_hub import hf_api

                self.result = hf_api.CommitInfo(
                    commit_url="commitUrl",
                    commit_message="upload",
                    commit_description="",
                    oid="0123456789abcdef",
                    _endpoint="https://company.jfrog.io/api/huggingfaceml/hf-local",
                )

        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "config.json").write_text("{}", encoding="utf-8")
            store = object.__new__(JFrogStore)
            store.endpoint = "https://company.jfrog.io/api/huggingfaceml/hf-local"
            store.api = FakeApi()
            store._upload_folder("owner/model", folder, "main")
            self.assertEqual(store.api.result.repo_url.repo_id, "owner/model")
            self.assertEqual(store.api.result.oid, "0123456789abcdef")

    def test_jfrog_rejects_invalid_explicit_revision(self) -> None:
        store = object.__new__(JFrogStore)
        store.discover_submissions = lambda repo_id: ([], [])  # type: ignore[method-assign]
        with self.assertRaisesRegex(ValueError, "only letters"):
            store.explicit_submissions("owner/model", ["refs/pr/1"])

    def test_jfrog_discovery_uses_manifest_revision_and_uploader(self) -> None:
        store = object.__new__(JFrogStore)
        store._manifest_items = lambda repo_id: (  # type: ignore[method-assign]
            [
                {
                    "item": {"created_by": "alice-jfrog", "path": "some/path"},
                    "manifest": {
                        "repo_id": repo_id,
                        "submission_revision": "r0003-alice-abc123",
                    },
                }
            ],
            [],
        )
        candidates, skipped = store.discover_submissions("owner/model")
        self.assertEqual(skipped, [])
        self.assertEqual(candidates[0].revision, "r0003-alice-abc123")
        self.assertEqual(candidates[0].author, "alice-jfrog")

    def test_jfrog_endpoint_and_aql_manifest_discovery(self) -> None:
        store = JFrogStore(
            "secret-token",
            "https://company.jfrog.io/artifactory/api/huggingfaceml/hf-local",
        )
        requests = []

        def fake_request(url, *, data=None, content_type=None):
            requests.append((url, data, content_type))
            if url.endswith("/api/search/aql"):
                return (
                    b'{"results":[{"repo":"hf-local",'
                    b'"path":"models/org/model/rev",'
                    b'"name":"fedavg_submission.json","created_by":"alice"}]}'
                )
            return b'{"repo_id":"org/model","submission_revision":"r0001-alice-abc"}'

        store._request = fake_request  # type: ignore[method-assign]
        records, skipped = store._manifest_items("org/model")
        self.assertEqual(skipped, [])
        self.assertEqual(records[0]["item"]["created_by"], "alice")
        self.assertIn(b'"repo":{"$eq":"hf-local"}', requests[0][1])
        self.assertEqual(requests[0][2], "text/plain")
        self.assertEqual(
            requests[1][0],
            "https://company.jfrog.io/artifactory/hf-local/"
            "models/org/model/rev/fedavg_submission.json",
        )

    def test_schema_v1_base_commit_remains_readable(self) -> None:
        self.assertEqual(base_revision_from({"base_commit": "legacy-sha"}), "legacy-sha")

    def test_checkpoint_hash_validation_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "config.json"
            path.write_text("original", encoding="utf-8")
            expected = artifact_hashes(root, ["config.json"])
            validate_artifact_hashes(root, ["config.json"], expected, "submission")
            path.write_text("tampered", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                validate_artifact_hashes(
                    root, ["config.json"], expected, "submission"
                )


if __name__ == "__main__":
    unittest.main()
