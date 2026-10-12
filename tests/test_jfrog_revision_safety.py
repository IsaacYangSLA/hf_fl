"""JFrog submissions and optional tags must preserve mutable global references."""

from __future__ import annotations

from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from hf2l.backends.jfrog import JFrogStore


class RecordingApi:
    """A local provider double that records every read and upload."""

    def __init__(self):
        self.refs = {
            "main": "base",
            "master": "legacy-base",
            "HEAD": "base",
            "latest": "base",
            "default": "base",
        }
        self.snapshots = {
            "base": {"model.bin": b"original"},
            "legacy-base": {"model.bin": b"legacy"},
        }
        self.uploads: list[str] = []
        self.reads: list[str] = []

    def upload_folder(self, *, folder_path, revision, **kwargs):
        self.uploads.append(revision)
        resolved = f"commit-{len(self.uploads)}"
        folder = Path(folder_path)
        self.snapshots[resolved] = {
            path.relative_to(folder).as_posix(): path.read_bytes()
            for path in folder.rglob("*")
            if path.is_file()
        }
        self.refs[revision] = resolved
        return SimpleNamespace(oid=resolved)

    def model_info(self, repo_id, *, revision):
        self.reads.append(revision)
        return SimpleNamespace(sha=self.refs.get(revision, revision))


class JFrogRevisionSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name)
        (self.source / "model.bin").write_bytes(b"updated")
        self.api = RecordingApi()
        self.store = object.__new__(JFrogStore)
        self.store.endpoint = "https://example.test/artifactory/api/huggingfaceml/models"
        self.store.api = self.api

    def assert_provider_untouched(self, refs):
        self.assertEqual(self.api.uploads, [])
        self.assertEqual(self.api.reads, [])
        self.assertEqual(self.api.refs, refs)
        self.assertEqual(self.api.snapshots["base"]["model.bin"], b"original")

    def test_reserved_submission_names_are_rejected_before_provider_calls(self):
        before = dict(self.api.refs)
        for revision in ("main", "master", "HEAD", "latest", "default", "MaIn", " head "):
            with self.subTest(revision=revision):
                with self.assertRaisesRegex(ValueError, "reserved mutable revision"):
                    self.store.publish_submission(
                        "repo", self.source, ["model.bin"], participant="alice",
                        source_round=0, base_revision="base", submission_revision=revision,
                    )
                self.assert_provider_untouched(before)

    def test_reserved_tag_names_are_rejected_before_main_publication(self):
        before = dict(self.api.refs)
        for tag in ("main", "master", "HEAD", "latest", "default", "MAIN", " Master "):
            with self.subTest(tag=tag):
                with self.assertRaisesRegex(ValueError, "reserved mutable revision"):
                    self.store.publish_aggregate(
                        "repo", self.source, ["model.bin"], expected_base="base",
                        next_round=1, tag=tag,
                    )
                self.assert_provider_untouched(before)

    def test_invalid_named_revisions_fail_before_provider_calls(self):
        before = dict(self.api.refs)
        for revision in ("refs/heads/main", "refs/pr/1", "round_1", " "):
            with self.subTest(revision=revision):
                with self.assertRaisesRegex(ValueError, "only letters"):
                    self.store.publish_submission(
                        "repo", self.source, ["model.bin"], participant="alice",
                        source_round=0, base_revision="base", submission_revision=revision,
                    )
                with self.assertRaisesRegex(ValueError, "only letters"):
                    self.store.publish_aggregate(
                        "repo", self.source, ["model.bin"], expected_base="base",
                        next_round=1, tag=revision,
                    )
                self.assert_provider_untouched(before)

    def test_generated_submission_remains_detached(self):
        revision = self.store.new_submission_revision("Alice Example", 3)
        result = self.store.publish_submission(
            "repo", self.source, ["model.bin"], participant="Alice Example",
            source_round=3, base_revision="base", submission_revision=revision,
        )
        self.assertRegex(revision, r"^r0003-Alice-Example-[a-f0-9]{12}$")
        self.assertEqual(result.revision, revision)
        self.assertEqual(result.resolved_revision, self.api.refs[revision])
        self.assertEqual(self.api.uploads, [revision])
        self.assertEqual(self.api.refs["main"], "base")
        self.assertEqual(self.api.snapshots["base"]["model.bin"], b"original")
        self.assertEqual(self.api.snapshots[result.resolved_revision]["model.bin"], b"updated")

    def test_valid_named_submission_and_round_tag_remain_supported(self):
        submission = self.store.publish_submission(
            "repo", self.source, ["model.bin"], participant="alice",
            source_round=0, base_revision="base", submission_revision="experiment-1.2",
        )
        self.assertEqual(submission.revision, "experiment-1.2")
        self.assertEqual(self.api.refs["main"], "base")
        result = self.store.publish_aggregate(
            "repo", self.source, ["model.bin"], expected_base="base",
            next_round=1, tag="round-1.2",
        )
        self.assertTrue(result.tag_created)
        self.assertEqual(result.revision, self.api.refs["main"])
        self.assertNotEqual(result.revision, "base")
        self.assertEqual(self.api.uploads, ["experiment-1.2", "main", "round-1.2"])
        self.assertEqual(
            self.api.snapshots[self.api.refs["round-1.2"]],
            self.api.snapshots[result.revision],
        )

    def test_reserved_names_still_resolve_for_reads(self):
        for revision in ("main", "master", "HEAD", "latest", "default"):
            with self.subTest(revision=revision):
                self.assertEqual(
                    self.store.resolve_revision("repo", revision), self.api.refs[revision],
                )
        self.assertEqual(self.api.uploads, [])


if __name__ == "__main__":
    unittest.main()
