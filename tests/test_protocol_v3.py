"""Wire-compatible FL contracts and workflow-independent file helpers."""

from __future__ import annotations

import json
import math
import tempfile
import unittest
from pathlib import Path

from hf2l.common.fs import checked_file_paths, read_json, safe_relative_path, write_json
from hf2l.core.errors import ProtocolError
from hf2l.core.protocol import (
    AlgorithmSpec, ClientContext, RoundRecord, SubmissionManifest,
    MAX_METADATA_BYTES, base_revision_from, document_schemas, json_schema,
)


def submission(**overrides):
    return {"schema_version": 2, "backend": "huggingface", "repo_id": "owner/model",
            "base_revision": "abc123", "source_round": 0, "participant": "alice",
            "num_examples": 10, **overrides}


class ProtocolTests(unittest.TestCase):
    def test_submission_round_trip_preserves_extensions(self):
        source = submission(training={"loss": 1.2}, extension={"nested": [1, True, None]})
        parsed = SubmissionManifest.from_dict(source)
        self.assertEqual(parsed.to_dict(), source)
        self.assertEqual((parsed.participant, parsed.num_examples), ("alice", 10))
        source["extension"]["nested"].append(7)
        exported = parsed.to_dict()
        exported["training"]["loss"] = 9
        self.assertEqual(parsed.training, {"loss": 1.2})
        self.assertEqual(parsed.to_dict()["extension"]["nested"], [1, True, None])

    def test_v1_base_commit_alias_and_missing_optional_fields(self):
        legacy = submission(schema_version=1)
        legacy.pop("backend")
        legacy["base_commit"] = legacy.pop("base_revision")
        parsed = SubmissionManifest.from_dict(legacy)
        self.assertEqual(parsed.backend, "huggingface")
        self.assertEqual(parsed.base_revision, "abc123")
        self.assertEqual(parsed.to_dict(), legacy)
        self.assertEqual(parsed.checkpoint_files_sha256, {})

    def test_alias_conflict_is_rejected(self):
        with self.assertRaisesRegex(ProtocolError, "disagree"):
            SubmissionManifest.from_dict(submission(base_commit="other"))
        self.assertEqual(base_revision_from({"base_commit": "legacy-sha"}), "legacy-sha")
        self.assertEqual(base_revision_from({}), "")

    def test_boolean_float_string_and_unknown_schema_are_rejected(self):
        for field, values in {"schema_version": [True, 2.0, "2", 3, None],
                              "source_round": [False, 0.0, "0", -1],
                              "num_examples": [True, 1.0, "1", 0, -1, 2**63]}.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ProtocolError):
                    SubmissionManifest.from_dict(submission(**{field: value}))

    def test_round_zero_is_valid_but_coerced_or_negative_round_is_not(self):
        self.assertEqual(RoundRecord.from_dict({"schema_version": 1, "round": 0}).round, 0)
        for value in [True, 1.0, "1", -1]:
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                RoundRecord.from_dict({"schema_version": 2, "round": value})

    def test_mutable_base_names_are_rejected_with_opaque_immutable_ids_allowed(self):
        for value in ["main", "master", "latest", "HEAD", "refs/heads/work", "refs/tags/v1"]:
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                SubmissionManifest.from_dict(submission(base_revision=value))
        for value in ["rec_123", "rounds/0001-uuid", "f" * 40]:
            self.assertEqual(SubmissionManifest.from_dict(submission(base_revision=value)).base_revision, value)

    def test_required_identity_fields_are_strict_strings(self):
        for field in ["repo_id", "participant", "backend"]:
            for value in ["", " alice ", "bad\nname", 9, None]:
                with self.subTest(field=field, value=value), self.assertRaises(ProtocolError):
                    SubmissionManifest.from_dict(submission(**{field: value}))

    def test_client_context_preserves_wire_names_and_optional_defaults(self):
        source = {"schema_version": 1, "repo_id": "owner/model", "base_commit": "sha",
                  "source_round": 3, "requested_revision": "main", "extension": "kept"}
        parsed = ClientContext.from_dict(source)
        self.assertEqual(parsed.source_round, 3)
        self.assertEqual(parsed.base_model_dir, "base_model")
        self.assertEqual(parsed.to_dict(), source)
        for value in ["../outside", "/tmp/model", "base//model", "C:/model", "a\\b"]:
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                ClientContext.from_dict({**source, "base_model_dir": value})

    def test_checkpoint_paths_and_hashes_validate_together(self):
        value = submission(checkpoint_files=["config.json", "model.safetensors"],
                           checkpoint_files_sha256={"config.json": "a" * 64, "model.safetensors": "b" * 64})
        self.assertEqual(SubmissionManifest.from_dict(value).to_dict(), value)
        for hashes in [{}, {"../escape": "a" * 64}, {"model": "A" * 64}, {"model": "short"}]:
            with self.subTest(hashes=hashes), self.assertRaises(ProtocolError):
                SubmissionManifest.from_dict(submission(checkpoint_files_sha256=hashes))
        with self.assertRaises(ProtocolError):
            SubmissionManifest.from_dict(submission(checkpoint_files=["model", "model"]))

    def test_non_json_or_unbounded_metadata_fails(self):
        for value in [float("nan"), float("inf"), {1: "key"}, (1, 2), Path("file"), "\ud800"]:
            with self.subTest(value=repr(value)), self.assertRaises(ProtocolError):
                SubmissionManifest.from_dict(submission(training={"value": value}))
        with self.assertRaises(ProtocolError):
            SubmissionManifest.from_dict(submission(training={"data": "x" * MAX_METADATA_BYTES}))
        nested = {}
        for _ in range(20):
            nested = {"child": nested}
        with self.assertRaises(ProtocolError):
            SubmissionManifest.from_dict(submission(extension=nested))

    def test_algorithm_typed_and_legacy_wire_forms(self):
        algorithm = AlgorithmSpec("fedavg", params={"weighting": "examples"})
        self.assertEqual(AlgorithmSpec.from_dict(algorithm.to_dict()), algorithm)
        for value in ["initial model", "FedAvg with examples weighting", algorithm.to_dict()]:
            source = {"schema_version": 2, "round": 0, "algorithm": value}
            parsed = RoundRecord.from_dict(source)
            self.assertIsInstance(parsed.algorithm, AlgorithmSpec)
            self.assertEqual(parsed.to_dict(), source)
        extended = {"name": "fedavg", "version": 1, "params": {}, "vendor": {"policy": "a"}}
        self.assertEqual(AlgorithmSpec.from_dict(extended).to_dict(), extended)
        for value in [{"name": "fedavg", "version": True}, {"name": "fedavg", "params": []}, {}]:
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                AlgorithmSpec.from_dict(value)

    def test_algorithm_spec_is_an_optional_canonical_mapping(self):
        value = {"schema_version": 2, "round": 0, "algorithm": "initial model",
                 "algorithm_spec": AlgorithmSpec("fedavg", params={"weighting": "examples"}).to_dict()}
        parsed = RoundRecord.from_dict(value)
        self.assertEqual(parsed.algorithm_spec.name, "fedavg")
        self.assertEqual(parsed.algorithm.name, "initial model")
        self.assertEqual(parsed.to_dict(), value)
        for invalid in ["fedavg", {"name": "fedavg", "version": True}, None]:
            with self.subTest(invalid=invalid), self.assertRaises(ProtocolError):
                SubmissionManifest.from_dict(submission(algorithm_spec=invalid))

    def test_summary_counts_and_coefficients_are_validated(self):
        for summary in [{"num_examples": True}, {"coefficient": True}, {"coefficient": 1.1}]:
            with self.subTest(summary=summary), self.assertRaises(ProtocolError):
                RoundRecord.from_dict({"schema_version": 2, "round": 1, "submissions": [summary]})

    def test_checked_schema_artifact_matches_runtime_export(self):
        path = Path(__file__).resolve().parents[1] / "docs/generated/fl-documents.json"
        self.assertEqual(json.loads(path.read_text()), document_schemas())
        self.assertEqual(json_schema(SubmissionManifest)["$ref"], "#/$defs/SubmissionManifest")
        with self.assertRaises(TypeError):
            json_schema(dict)

    def test_generated_json_schema_accepts_wire_examples_and_rejects_wrong_types(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("optional JSON Schema validator is not installed")
        for cls, value in [(SubmissionManifest, submission()),
                           (RoundRecord, {"schema_version": 2, "round": 0, "algorithm": "initial model"}),
                           (ClientContext, {"schema_version": 1, "repo_id": "owner/model", "base_commit": "sha",
                                            "source_round": 0}),
                           (AlgorithmSpec, {"name": "fedavg", "version": 1, "params": {}})]:
            with self.subTest(cls=cls.__name__):
                jsonschema.Draft202012Validator.check_schema(json_schema(cls))
                jsonschema.validate(value, json_schema(cls))
        for value in [submission(num_examples=True), submission(base_revision="main"), submission(schema_version=3),
                      submission(checkpoint_files_sha256={"../escape": "a" * 64})]:
            with self.subTest(value=value), self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(value, json_schema(SubmissionManifest))


class CommonFileTests(unittest.TestCase):
    def test_json_parser_rejects_duplicates_nonfinite_and_nonobject(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.json"
            for text in ['{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', '{"a":1e9999}', '[]']:
                path.write_text(text)
                with self.subTest(text=text), self.assertRaises(ValueError):
                    read_json(path)

    def test_json_writer_is_atomic_and_rejects_nonfinite_before_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "document.json"
            write_json(path, {"value": 1})
            with self.assertRaises(ValueError):
                write_json(path, {"value": math.nan})
            self.assertEqual(read_json(path), {"value": 1})
            self.assertEqual(sorted(p.name for p in path.parent.iterdir()), ["document.json"])

    def test_safe_relative_path_rejects_traversal_and_windows_aliases(self):
        self.assertEqual(safe_relative_path("folder/model.bin"), "folder/model.bin")
        for path in ["", ".", "..", "../a", "a/../b", "a/./b", "a//b", "/a", "a/", "a\\b", "C:foo", "a\0b"]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                safe_relative_path(path)

    def test_checked_selection_rejects_symlinks_missing_and_case_collisions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "model").write_text("a")
            (root / "MODEL").write_text("b")
            (root / "Folder").mkdir()
            (root / "Folder/child").write_text("c")
            (root / "folder").write_text("d")
            (root / "link").symlink_to(root / "model")
            self.assertEqual(checked_file_paths(root, ["model"]), ["model"])
            for paths in [["../model"], ["missing"], ["link"], ["model", "MODEL"], ["model", "model"], ["folder", "Folder/child"]]:
                with self.subTest(paths=paths), self.assertRaises(ValueError):
                    checked_file_paths(root, paths)
            (root / "directory_link").symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                checked_file_paths(root, ["directory_link/model"])
            with self.assertRaises(ValueError):
                checked_file_paths(root)


if __name__ == "__main__":
    unittest.main()
