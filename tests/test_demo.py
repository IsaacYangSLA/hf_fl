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

from checkpoint_utils import aggregate_checkpoints, discover_checkpoint  # noqa: E402
from client_steps import upload_client_update  # noqa: E402
from demo_data import load_npz_dataset, synthetic_dataset  # noqa: E402
from hub_helpers import CLIENT_CONTEXT_FILE, SCHEMA_VERSION, write_json  # noqa: E402
from lenet_model import LeNet  # noqa: E402
from owner_fedavg import (  # noqa: E402
    discover_open_pull_requests,
    explicit_pull_requests,
    fedavg_states,
    load_allowlist,
    validate_submission_manifest,
)
from plugin_loader import parse_plugin_args  # noqa: E402


class DemoTests(unittest.TestCase):
    def test_lenet_shape_and_hf_round_trip(self) -> None:
        model = LeNet()
        output = model(torch.zeros(3, 1, 28, 28))
        self.assertEqual(output.shape, (3, 10))
        with tempfile.TemporaryDirectory() as temporary:
            model.save_pretrained(temporary)
            loaded = LeNet.from_pretrained(temporary)
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
        class FakeApi:
            def __init__(self) -> None:
                self.operations = []

            def create_commit(self, **kwargs):
                self.operations = kwargs["operations"]
                self.parent_commit = kwargs["parent_commit"]
                return SimpleNamespace(pr_revision="refs/pr/9", pr_url="https://example/pr/9")

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
                    "repo_id": "owner/model",
                    "base_commit": "abc123",
                    "source_round": 4,
                    "base_model_dir": "base_model",
                },
            )
            api = FakeApi()
            result, manifest = upload_client_update(
                api, work, trained, "alice", 12, {"trainer": "private"}
            )
            self.assertEqual(result.pr_revision, "refs/pr/9")
            self.assertEqual(api.parent_commit, "abc123")
            self.assertEqual(manifest["training"]["trainer"], "private")
            self.assertEqual(
                {operation.path_in_repo for operation in api.operations},
                {"config.json", "model.safetensors", "fedavg_submission.json"},
            )

    def test_plugin_arguments_decode_json_values(self) -> None:
        values = parse_plugin_args(["epochs=3", "enabled=true", "name=alice"])
        self.assertEqual(values, {"epochs": 3, "enabled": True, "name": "alice"})

    def test_allowlist_binds_hf_author_to_participant(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "allowlist.json"
            write_json(path, {"Alice-HF": "alice", "bob-hf": "bob"})
            allowlist = load_allowlist(path)
            self.assertEqual(allowlist, {"alice-hf": "alice", "bob-hf": "bob"})

            manifest = {
                "schema_version": SCHEMA_VERSION,
                "repo_id": "owner/model",
                "base_commit": "abc123",
                "source_round": 4,
                "participant": "alice",
                "num_examples": 12,
            }
            participant, count = validate_submission_manifest(
                manifest,
                repo_id="owner/model",
                base_commit="abc123",
                current_round=4,
                revision="refs/pr/1",
                expected_participant=allowlist["alice-hf"],
            )
            self.assertEqual((participant, count), ("alice", 12))
            with self.assertRaisesRegex(ValueError, "approved only as participant"):
                validate_submission_manifest(
                    {**manifest, "participant": "mallory"},
                    repo_id="owner/model",
                    base_commit="abc123",
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

        api = FakeApi()
        candidates, skipped = discover_open_pull_requests(
            api, "owner/model", {"alice-hf": "alice", "bob-hf": "bob"}
        )
        self.assertEqual([candidate.number for candidate in candidates], [3, 5])
        self.assertEqual(candidates[1].author, "Bob-HF")
        self.assertEqual(len(skipped), 1)
        self.assertEqual(api.arguments["discussion_type"], "pull_request")
        self.assertEqual(api.arguments["discussion_status"], "open")

    def test_explicit_pr_selection_also_enforces_allowlist(self) -> None:
        class FakeApi:
            def get_discussion_details(self, **kwargs):
                authors = {3: "alice-hf", 5: "mallory-hf"}
                return SimpleNamespace(
                    author=authors[kwargs["discussion_num"]], is_pull_request=True
                )

        api = FakeApi()
        candidates = explicit_pull_requests(
            api, "owner/model", ["3"], {"alice-hf": "alice"}
        )
        self.assertEqual(candidates[0].revision, "refs/pr/3")
        with self.assertRaisesRegex(ValueError, "not in the allowlist"):
            explicit_pull_requests(
                api, "owner/model", ["5"], {"alice-hf": "alice"}
            )


if __name__ == "__main__":
    unittest.main()
