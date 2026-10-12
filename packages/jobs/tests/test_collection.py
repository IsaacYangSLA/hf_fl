"""Adversarial collection checks run without loading workload outputs."""
from __future__ import annotations

import hashlib
import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from hf2l_jobs.collection import CollectionError, FileMetadata, SafeCollector


class SafeCollectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hf2l-collector-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "component"
        self.root.mkdir()

    def collector(self, **kwargs):
        collector = SafeCollector(self.root, **kwargs)
        self.addCleanup(collector.close)
        return collector

    def write(self, path, content):
        output = self.root / path
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(content)
        return output

    def test_opaque_file_read_and_sorted_hashed_manifest(self):
        self.write("z/checkpoint.pkl", b"cos\nsystem\n(S'not executed'\ntR.")
        self.write("a.bin", b"\x00\xffdata")
        collector = self.collector()
        self.assertEqual(collector.read("a.bin"), b"\x00\xffdata")
        manifest = collector.collect()
        self.assertEqual([item.path for item in manifest], ["a.bin", "z/checkpoint.pkl"])
        self.assertEqual(
            manifest[0].as_dict(),
            {"path": "a.bin", "size_bytes": 6, "sha256": hashlib.sha256(b"\x00\xffdata").hexdigest()},
        )
        self.assertIsInstance(manifest[0], FileMetadata)

    def test_absolute_traversal_and_ambiguous_paths_are_rejected(self):
        collector = self.collector()
        for relative in ("", ".", "..", "../outside", "/etc/passwd", "x/../a",
                         "./a", "x//a", "x/", r"x\a", "a\x00b"):
            with self.subTest(relative=relative), self.assertRaises(CollectionError):
                collector.read(relative)

    def test_symlink_root_and_ancestor_are_rejected(self):
        link = self.base / "link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(CollectionError):
            SafeCollector(link)
        nested = self.root / "nested"
        nested.mkdir()
        with self.assertRaises(CollectionError):
            SafeCollector(link / "nested")

    def test_root_must_be_existing_directory(self):
        self.write("regular", b"file")
        for root in (self.root / "missing", self.root / "regular"):
            with self.subTest(root=root), self.assertRaises(CollectionError):
                SafeCollector(root)

    def test_final_file_symlink_is_rejected(self):
        outside = self.base / "other-job-secret"
        outside.write_bytes(b"other job")
        (self.root / "leak").symlink_to(outside)
        collector = self.collector()
        with self.assertRaises(CollectionError):
            collector.read("leak")
        with self.assertRaises(CollectionError):
            collector.collect()

    def test_intermediate_directory_symlink_is_rejected(self):
        outside = self.base / "other-job"
        outside.mkdir()
        (outside / "secret").write_bytes(b"other job")
        (self.root / "nested").symlink_to(outside, target_is_directory=True)
        collector = self.collector()
        with self.assertRaises(CollectionError):
            collector.read("nested/secret")
        with self.assertRaises(CollectionError):
            collector.list_files()

    def test_hardlinks_are_rejected_even_when_source_is_inside_root(self):
        original = self.write("original", b"private")
        os.link(original, self.root / "alias")
        collector = self.collector()
        for relative in ("original", "alias"):
            with self.subTest(relative=relative), self.assertRaises(CollectionError):
                collector.read(relative)
        with self.assertRaises(CollectionError):
            collector.collect()

    def test_external_hardlink_escape_is_rejected(self):
        outside = self.base / "other-job-checkpoint"
        outside.write_bytes(b"private")
        os.link(outside, self.root / "checkpoint")
        collector = self.collector()
        with self.assertRaises(CollectionError):
            collector.read("checkpoint")
        with self.assertRaises(CollectionError):
            collector.collect()

    def test_fifo_is_rejected_without_blocking(self):
        os.mkfifo(self.root / "pipe")
        collector = self.collector()
        with self.assertRaises(CollectionError):
            collector.read("pipe")
        with self.assertRaises(CollectionError):
            collector.collect()

    def test_socket_and_directory_reads_are_rejected(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(self.root / "socket"))
            collector = self.collector()
            with self.assertRaises(CollectionError):
                collector.read("socket")
            with self.assertRaises(CollectionError):
                collector.collect()
        (self.root / "nested").mkdir()
        with self.assertRaises(CollectionError):
            collector.read("nested")

    def test_file_read_limit_cannot_override_configured_limit(self):
        self.write("large", b"12345")
        collector = self.collector(max_file_bytes=4)
        for limit in (None, 2, 100):
            with self.subTest(limit=limit), self.assertRaises(CollectionError):
                collector.read("large", max_bytes=limit)
        with self.assertRaises(CollectionError):
            collector.collect()

    def test_zero_read_limit_allows_empty_files_only(self):
        self.write("empty", b"")
        self.write("one", b"x")
        collector = self.collector()
        self.assertEqual(collector.read("empty", max_bytes=0), b"")
        with self.assertRaises(CollectionError):
            collector.read("one", max_bytes=0)

    def test_total_byte_limit_and_file_limit_are_enforced(self):
        self.write("one", b"123")
        self.write("two", b"456")
        with self.assertRaises(CollectionError):
            self.collector(max_total_bytes=5).collect()
        with self.assertRaises(CollectionError):
            self.collector(max_files=1).collect()
        self.assertEqual(len(self.collector(max_total_bytes=6, max_files=2).collect()), 2)

    def test_read_respects_total_byte_limit(self):
        self.write("large", b"12345")
        with self.assertRaises(CollectionError):
            self.collector(max_file_bytes=100, max_total_bytes=4).read("large")

    def test_directory_entry_and_depth_limits_are_enforced(self):
        self.write("one/a", b"a")
        self.write("two/b", b"b")
        with self.assertRaises(CollectionError):
            self.collector(max_entries=3).collect()
        with self.assertRaises(CollectionError):
            self.collector(max_depth=1).collect()
        with self.assertRaises(CollectionError):
            self.collector(max_depth=1).read("one/a")
        self.assertEqual(len(self.collector(max_entries=4, max_depth=2).collect()), 2)

    def test_empty_directories_count_against_entry_bound(self):
        for index in range(3):
            (self.root / str(index)).mkdir()
        with self.assertRaises(CollectionError):
            self.collector(max_entries=2).collect()

    def test_root_descriptor_is_pinned_against_path_replacement(self):
        self.write("value", b"original")
        collector = self.collector()
        old_root = self.base / "original"
        self.root.rename(old_root)
        self.root.mkdir()
        self.write("value", b"replacement")
        self.assertEqual(collector.read("value"), b"original")
        self.assertEqual(collector.collect()[0].sha256, hashlib.sha256(b"original").hexdigest())

    def test_symlink_swap_between_stat_and_open_is_rejected(self):
        self.write("victim", b"safe")
        outside = self.base / "secret"
        outside.write_bytes(b"unsafe")
        collector = self.collector()
        actual_open = os.open
        swapped = False

        def swap(name, flags, *args, **kwargs):
            nonlocal swapped
            if name == "victim" and not swapped:
                swapped = True
                (self.root / "victim").unlink()
                (self.root / "victim").symlink_to(outside)
            return actual_open(name, flags, *args, **kwargs)

        with patch("hf2l_jobs.collection.os.open", side_effect=swap):
            with self.assertRaises(CollectionError):
                collector.collect()
        self.assertTrue(swapped)

    def test_changes_during_read_are_rejected(self):
        output = self.write("changing", b"safe")
        collector = self.collector()
        actual_read = os.read
        changed = False

        def mutate(descriptor, count):
            nonlocal changed
            result = actual_read(descriptor, count)
            if not changed:
                changed = True
                output.write_bytes(b"changed")
            return result

        with patch("hf2l_jobs.collection.os.read", side_effect=mutate):
            with self.assertRaises(CollectionError):
                collector.read("changing")
        self.assertTrue(changed)

    def test_filesystem_crossing_is_rejected(self):
        self.write("value", b"safe")
        collector = self.collector()
        actual_fstat = os.fstat

        def crossed(descriptor):
            information = actual_fstat(descriptor)
            return SimpleNamespace(
                st_dev=information.st_dev + 1, st_mode=information.st_mode, st_nlink=1
            )

        with patch("hf2l_jobs.collection.os.fstat", side_effect=crossed):
            with self.assertRaises(CollectionError):
                collector.read("value")

    def test_invalid_utf8_names_are_rejected(self):
        path = os.fsencode(self.root) + b"/\xff"
        descriptor = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(descriptor)
        with self.assertRaises(CollectionError):
            self.collector().collect()

    def test_closed_collector_cannot_reopen_by_path(self):
        self.write("value", b"value")
        with SafeCollector(self.root) as collector:
            self.assertEqual(collector.read("value"), b"value")
        collector.close()
        for operation in (lambda: collector.read("value"), collector.collect):
            with self.assertRaises(CollectionError):
                operation()

    def test_constructor_bounds_reject_bool_nonintegers_and_zero(self):
        for key in ("max_files", "max_file_bytes", "max_total_bytes", "max_log_events",
                    "max_event_bytes", "max_entries", "max_depth"):
            for value in (True, 0, -1, 1.5):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    SafeCollector(self.root, **{key: value})
        for secrets in ([""], [None], ["x" * 8193], ["x"] * 129):
            with self.subTest(secrets=secrets), self.assertRaises(ValueError):
                SafeCollector(self.root, secret_values=secrets)

    def test_event_secret_fields_are_omitted_and_values_redacted(self):
        value = {
            "event": "round", "password": "not exposed", "API-Key": "not exposed",
            "nested": {"access_token": "hidden", "message": "used credential-123"},
            "metrics": [1, {"loss": 0.5, "private_key": "hidden"}],
        }
        self.write("events.jsonl", (json.dumps(value) + "\r\n").encode())
        events = self.collector(secret_values=["credential-123"]).events("events.jsonl")
        self.assertEqual(
            events,
            ({
                "event": "round", "nested": {"message": "used [REDACTED]"},
                "metrics": [1, {"loss": 0.5}],
            },),
        )

    def test_events_require_utf8_objects_and_finite_unambiguous_json(self):
        collector = self.collector()
        for content in (b"[]", b'"text"', b'{"bad":NaN}', b'{"bad":Infinity}',
                        b'{"bad":1e999}', b'{"x":1,"x":2}', b'{invalid}', b'\xff',
                        '{"event":"x"}'.encode("utf-16")):
            self.write("events", content)
            with self.subTest(content=content), self.assertRaises(CollectionError):
                collector.events("events")

    def test_event_lines_bytes_depth_and_sanitized_bytes_are_bounded(self):
        self.write("many", b'{"a":1}\n{"b":2}\n')
        with self.assertRaises(CollectionError):
            self.collector(max_log_events=1).events("many")
        self.write("blank", b"\n\n\n")
        with self.assertRaises(CollectionError):
            self.collector(max_log_events=2).events("blank")
        self.write("large", b'{"event":"abc"}')
        with self.assertRaises(CollectionError):
            self.collector(max_event_bytes=8).events("large")
        value = {}
        for _ in range(18):
            value = {"nested": value}
        self.write("deep", json.dumps(value).encode())
        with self.assertRaises(CollectionError):
            self.collector().events("deep")
        self.write("expanded", b'{"event":"x"}')
        with self.assertRaises(CollectionError):
            self.collector(max_event_bytes=15, secret_values=["x"]).events("expanded")

    def test_log_redaction_utf8_and_expansion_limit(self):
        self.write("log", b"safe: secret-value")
        collector = self.collector(secret_values=["secret-value"])
        self.assertEqual(collector.logs("log"), "safe: [REDACTED]")
        self.write("invalid", b"\xff")
        with self.assertRaises(CollectionError):
            collector.logs("invalid")
        self.write("expanded", b"xxxx")
        with self.assertRaises(CollectionError):
            self.collector(max_file_bytes=8, secret_values=["x"]).logs("expanded")

    def test_redacted_key_collisions_are_rejected(self):
        self.write("events", b'{"opaque-one":1,"opaque-two":2}')
        with self.assertRaises(CollectionError):
            self.collector(secret_values=["opaque-one", "opaque-two"]).events("events")

    def test_retention_preserves_opaque_bytes_after_source_volume_is_removed(self):
        import shutil
        self.write("artifacts/checkpoint.pkl", b"opaque\x00model")
        self.write("logs/stdout.log", b"training output")
        collector = self.collector()
        destination = self.base / "retained" / "component"
        result = collector.retain(destination)
        self.assertEqual([item.path for item in result], ["artifacts/checkpoint.pkl", "logs/stdout.log"])
        self.assertEqual(result[0].as_dict(), {
            "path": "artifacts/checkpoint.pkl",
            "locator": str(destination / "artifacts/checkpoint.pkl"),
            "size_bytes": 12,
            "sha256": hashlib.sha256(b"opaque\x00model").hexdigest(),
        })
        shutil.rmtree(self.root)
        self.assertEqual(Path(result[0].locator).read_bytes(), b"opaque\x00model")
        for item in result:
            information = Path(item.locator).stat()
            self.assertEqual(information.st_nlink, 1)
            self.assertEqual(information.st_mode & 0o777, 0o600)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
        self.assertEqual((destination / "artifacts").stat().st_mode & 0o777, 0o700)

    def test_identical_retention_retry_preserves_existing_inode(self):
        self.write("value", b"data")
        collector = self.collector()
        destination = self.base / "retained"
        first = collector.retain(destination)
        inode = Path(first[0].locator).stat().st_ino
        second = collector.retain(destination)
        self.assertEqual(first, second)
        self.assertEqual(Path(second[0].locator).stat().st_ino, inode)
        self.assertEqual(list(destination.iterdir()), [destination / "value"])

    def test_different_retained_content_conflicts_without_overwriting(self):
        output = self.write("value", b"original")
        collector = self.collector()
        destination = self.base / "retained"
        collector.retain(destination)
        output.write_bytes(b"changed")
        with self.assertRaises(CollectionError):
            collector.retain(destination)
        self.assertEqual((destination / "value").read_bytes(), b"original")

    def test_retention_root_or_ancestor_symlink_is_rejected(self):
        self.write("value", b"data")
        collector = self.collector()
        outside = self.base / "outside"
        outside.mkdir(mode=0o700)
        link = self.base / "symlink"
        link.symlink_to(outside, target_is_directory=True)
        for destination in (link, link / "child"):
            with self.subTest(destination=destination), self.assertRaises(CollectionError):
                collector.retain(destination)
        self.assertEqual(list(outside.iterdir()), [])

    def test_retention_inside_source_and_same_source_is_rejected(self):
        self.write("value", b"data")
        collector = self.collector()
        for destination in (self.root, self.root / "retained"):
            with self.subTest(destination=destination), self.assertRaises(CollectionError):
                collector.retain(destination)
        self.assertFalse((self.root / "retained").exists())

    def test_retention_requires_trusted_absolute_private_directory(self):
        self.write("value", b"data")
        collector = self.collector()
        public = self.base / "public"
        public.mkdir(mode=0o755)
        public.chmod(0o755)
        for destination in ("relative", str(self.base) + "/../escape", public):
            with self.subTest(destination=destination), self.assertRaises(CollectionError):
                collector.retain(destination)
        self.assertEqual(list(public.iterdir()), [])

    def test_retention_destination_file_symlink_and_hardlink_are_rejected(self):
        self.write("value", b"data")
        collector = self.collector()
        outside = self.base / "other-job"
        outside.write_bytes(b"data")
        for kind in ("symlink", "hardlink"):
            destination = self.base / kind
            destination.mkdir(mode=0o700)
            if kind == "symlink":
                (destination / "value").symlink_to(outside)
            else:
                os.link(outside, destination / "value")
            with self.subTest(kind=kind), self.assertRaises(CollectionError):
                collector.retain(destination)
        self.assertEqual(outside.read_bytes(), b"data")

    def test_retention_destination_subdirectory_symlink_is_rejected(self):
        self.write("nested/value", b"data")
        collector = self.collector()
        destination = self.base / "retained"
        destination.mkdir(mode=0o700)
        outside = self.base / "other-job"
        outside.mkdir(mode=0o700)
        (destination / "nested").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(CollectionError):
            collector.retain(destination)
        self.assertEqual(list(outside.iterdir()), [])

    def test_retention_destination_fifo_is_rejected_without_blocking(self):
        self.write("value", b"data")
        collector = self.collector()
        destination = self.base / "retained"
        destination.mkdir(mode=0o700)
        os.mkfifo(destination / "value")
        with self.assertRaises(CollectionError):
            collector.retain(destination)

    def test_retention_rejects_untrusted_subdirectory_permissions(self):
        self.write("nested/value", b"data")
        destination = self.base / "retained"
        destination.mkdir(mode=0o700)
        (destination / "nested").mkdir(mode=0o755)
        (destination / "nested").chmod(0o755)
        with self.assertRaises(CollectionError):
            self.collector().retain(destination)

    def test_retention_rechecks_source_manifest_before_copy(self):
        output = self.write("value", b"data")
        collector = self.collector()
        manifest = collector.collect()
        destination = self.base / "retained"
        output.write_bytes(b"changed")
        with patch.object(collector, "collect", return_value=manifest):
            with self.assertRaises(CollectionError):
                collector.retain(destination)
        self.assertFalse((destination / "value").exists())

    def test_retention_partial_writes_are_completed_before_publication(self):
        self.write("value", b"longer data")
        actual_write = os.write

        def partial(descriptor, content):
            return actual_write(descriptor, content[:2])

        with patch("hf2l_jobs.collection.os.write", side_effect=partial):
            retained = self.collector().retain(self.base / "retained")
        self.assertEqual(Path(retained[0].locator).read_bytes(), b"longer data")

    def test_retention_failed_write_cleans_staging_and_does_not_publish(self):
        self.write("value", b"data")
        destination = self.base / "retained"
        with patch("hf2l_jobs.collection.os.write", return_value=0):
            with self.assertRaises(CollectionError):
                self.collector().retain(destination)
        self.assertEqual(list(destination.iterdir()), [])

    def test_retention_raced_conflicting_target_is_never_overwritten(self):
        self.write("value", b"data")
        collector = self.collector()
        destination = self.base / "retained"
        from hf2l_jobs.collection import _rename_no_replace

        def conflict(temporary, target, descriptor):
            output = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=descriptor)
            os.write(output, b"raced content")
            os.close(output)
            return _rename_no_replace(temporary, target, descriptor)

        with patch("hf2l_jobs.collection._rename_no_replace", side_effect=conflict):
            with self.assertRaises(CollectionError):
                collector.retain(destination)
        self.assertEqual((destination / "value").read_bytes(), b"raced content")
        self.assertEqual(list(destination.iterdir()), [destination / "value"])

    def test_retention_raced_identical_target_is_reused(self):
        self.write("value", b"data")
        collector = self.collector()
        destination = self.base / "retained"
        from hf2l_jobs.collection import _rename_no_replace

        def identical(temporary, target, descriptor):
            output = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=descriptor)
            os.write(output, b"data")
            os.close(output)
            return _rename_no_replace(temporary, target, descriptor)

        with patch("hf2l_jobs.collection._rename_no_replace", side_effect=identical):
            result = collector.retain(destination)
        self.assertEqual(Path(result[0].locator).read_bytes(), b"data")
        self.assertEqual(list(destination.iterdir()), [destination / "value"])

    def test_retention_failure_after_atomic_publish_is_retriable(self):
        self.write("value", b"data")
        collector = self.collector()
        destination = self.base / "retained"
        from hf2l_jobs.collection import _rename_no_replace
        actual_fsync = os.fsync
        published = False
        failed = False

        def publish(temporary, target, descriptor):
            nonlocal published
            result = _rename_no_replace(temporary, target, descriptor)
            published = True
            return result

        def fail_after_publish(descriptor):
            nonlocal failed
            if published and not failed:
                failed = True
                raise OSError("simulated lost acknowledgement")
            return actual_fsync(descriptor)

        with patch("hf2l_jobs.collection._rename_no_replace", side_effect=publish):
            with patch("hf2l_jobs.collection.os.fsync", side_effect=fail_after_publish):
                with self.assertRaises(CollectionError):
                    collector.retain(destination)
        inode = (destination / "value").stat().st_ino
        result = collector.retain(destination)
        self.assertEqual(Path(result[0].locator).read_bytes(), b"data")
        self.assertEqual(Path(result[0].locator).stat().st_ino, inode)

    def test_retention_never_creates_destination_for_unsafe_source(self):
        outside = self.base / "other-job"
        outside.write_bytes(b"private")
        (self.root / "leak").symlink_to(outside)
        destination = self.base / "retained"
        with self.assertRaises(CollectionError):
            self.collector().retain(destination)
        self.assertFalse(destination.exists())

    def test_retention_respects_source_file_and_total_byte_limits(self):
        self.write("value", b"data")
        destination = self.base / "retained"
        with self.assertRaises(CollectionError):
            self.collector(max_file_bytes=3).retain(destination)
        self.assertFalse(destination.exists())

    def test_retained_purge_deletes_known_files_and_is_idempotent(self):
        from hf2l_jobs.collection import delete_retained
        self.write("artifacts/value", b"retained")
        self.write("logs/stdout.log", b"logs")
        destination = self.base / "retained"
        manifest = self.collector().retain(destination)
        self.assertTrue(delete_retained(destination, [item.as_dict() for item in manifest]))
        self.assertFalse(destination.exists())
        self.assertTrue(delete_retained(destination, manifest))
        self.assertTrue((self.root / "artifacts/value").exists())

    def test_retained_purge_symlink_root_ancestor_and_target_are_rejected(self):
        from hf2l_jobs.collection import delete_retained
        self.write("value", b"retained")
        destination = self.base / "retained"
        manifest = self.collector().retain(destination)
        outside = self.base / "other-job"
        outside.write_bytes(b"private")
        (destination / "value").unlink()
        (destination / "value").symlink_to(outside)
        with self.assertRaises(CollectionError):
            delete_retained(destination, manifest)
        link = self.base / "linked-root"
        link.symlink_to(destination, target_is_directory=True)
        with self.assertRaises(CollectionError):
            delete_retained(link, [])
        with self.assertRaises(CollectionError):
            delete_retained(link / "nested", [])
        self.assertEqual(outside.read_bytes(), b"private")

    def test_retained_purge_hardlink_is_rejected_without_affecting_source(self):
        from hf2l_jobs.collection import delete_retained
        self.write("value", b"retained")
        destination = self.base / "retained"
        manifest = self.collector().retain(destination)
        outside = self.base / "other-job"
        os.link(destination / "value", outside)
        with self.assertRaises(CollectionError):
            delete_retained(destination, manifest)
        self.assertTrue((destination / "value").exists())
        self.assertEqual(outside.read_bytes(), b"retained")

    def test_retained_purge_rejects_forged_locator_and_traversal(self):
        from hf2l_jobs.collection import delete_retained
        self.write("value", b"retained")
        destination = self.base / "retained"
        manifest = self.collector().retain(destination)
        forged = manifest[0].as_dict()
        forged["locator"] = str(self.base / "other-job")
        with self.assertRaises(CollectionError):
            delete_retained(destination, [forged])
        forged["path"] = "../other-job"
        forged["locator"] = str(self.base / "other-job")
        with self.assertRaises(CollectionError):
            delete_retained(destination, [forged])
        self.assertTrue((destination / "value").exists())

    def test_retained_purge_rejects_changed_unowned_files_before_any_deletion(self):
        from hf2l_jobs.collection import delete_retained
        self.write("a", b"original-a")
        self.write("b", b"original-b")
        destination = self.base / "retained"
        manifest = self.collector().retain(destination)
        (destination / "b").write_bytes(b"changed-b")
        with self.assertRaises(CollectionError):
            delete_retained(destination, manifest)
        self.assertEqual((destination / "a").read_bytes(), b"original-a")
        (destination / "b").write_bytes(b"original-b")
        (destination / "unowned").write_bytes(b"unexpected")
        with self.assertRaises(CollectionError):
            delete_retained(destination, manifest)
        self.assertTrue((destination / "a").exists())
        self.assertTrue((destination / "unowned").exists())

    def test_retained_purge_rejects_unowned_directory_and_fifo(self):
        from hf2l_jobs.collection import delete_retained
        self.write("value", b"retained")
        destination = self.base / "retained"
        manifest = self.collector().retain(destination)
        (destination / "unowned").mkdir(mode=0o700)
        with self.assertRaises(CollectionError):
            delete_retained(destination, manifest)
        (destination / "unowned").rmdir()
        os.mkfifo(destination / "pipe")
        with self.assertRaises(CollectionError):
            delete_retained(destination, manifest)
        self.assertTrue((destination / "value").exists())

    def test_retained_purge_retry_accepts_already_deleted_manifest_files(self):
        from hf2l_jobs.collection import delete_retained
        self.write("a", b"first")
        self.write("nested/b", b"second")
        destination = self.base / "retained"
        manifest = self.collector().retain(destination)
        (destination / "a").unlink()
        self.assertTrue(delete_retained(destination, manifest))
        self.assertFalse(destination.exists())

    def test_retained_purge_bounds_and_empty_root(self):
        from hf2l_jobs.collection import delete_retained
        self.write("value", b"retained")
        destination = self.base / "retained"
        manifest = self.collector().retain(destination)
        with self.assertRaises(CollectionError):
            delete_retained(destination, manifest, max_file_bytes=4)
        self.assertTrue((destination / "value").exists())
        empty = self.base / "empty"
        empty.mkdir(mode=0o700)
        self.assertTrue(delete_retained(empty, []))
        self.assertFalse(empty.exists())
        with self.assertRaises(CollectionError):
            delete_retained("/", [])


if __name__ == "__main__":
    unittest.main()
