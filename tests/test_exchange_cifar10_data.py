"""Offline tests for real CIFAR-10 preparation, parsing, and provenance."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

from examples.exchange_cifar10 import prepare_data as data


class Cifar10PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    @staticmethod
    def batch(count=2):
        values = np.empty((count, data.RECORD_BYTES), dtype=np.uint8)
        values[:, 0] = np.arange(count) % 10
        values[:, 1:1025] = 17
        values[:, 1025:2049] = 42
        values[:, 2049:] = 91
        return values.tobytes()

    def archive(self, *, missing=None, duplicate=None, symlink=None):
        path = self.root / "fixture.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            names = [*data.TRAIN_MEMBERS, data.TEST_MEMBER]
            if duplicate:
                names.append(duplicate)
            for name in names:
                if name == missing:
                    continue
                entry = tarfile.TarInfo(name)
                if name == symlink:
                    entry.type = tarfile.SYMTYPE
                    entry.linkname = "../../outside"
                    archive.addfile(entry)
                else:
                    content = self.batch()
                    entry.size = len(content)
                    archive.addfile(entry, io.BytesIO(content))
            # Paths outside the expected binary members are never extracted.
            entry = tarfile.TarInfo("../../outside")
            entry.size = 4
            archive.addfile(entry, io.BytesIO(b"data"))
        return path

    def test_binary_parser_preserves_cifar_channel_order_and_labels(self):
        images, labels = data.parse_batch(self.batch(), 2)
        self.assertEqual(images.shape, (2, 3, 32, 32))
        self.assertEqual(images.dtype, np.uint8)
        np.testing.assert_array_equal(labels, [0, 1])
        np.testing.assert_array_equal(images[:, :, 5, 7], [[17, 42, 91], [17, 42, 91]])
        with self.assertRaisesRegex(ValueError, "length"):
            data.parse_batch(self.batch()[:-1], 2)
        invalid = bytearray(self.batch())
        invalid[0] = 10
        with self.assertRaisesRegex(ValueError, "labels"):
            data.parse_batch(bytes(invalid), 2)

    def test_archive_members_are_read_without_extraction(self):
        values = data.read_batches(self.archive(), examples_per_batch=2)
        self.assertEqual(values[0].shape, (10, 3, 32, 32))
        self.assertEqual(values[2].shape, (2, 3, 32, 32))
        self.assertFalse((self.root / "cifar-10-batches-bin").exists())
        self.assertFalse((self.root.parent / "outside").exists())

    def test_missing_duplicate_symlink_and_oversized_members_are_rejected(self):
        for options in ({"missing": data.TEST_MEMBER}, {"duplicate": data.TEST_MEMBER},
                        {"symlink": data.TEST_MEMBER}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                data.read_batches(self.archive(**options), examples_per_batch=2)
        path = self.archive()
        with self.assertRaisesRegex(ValueError, "length"):
            data.read_batches(path, examples_per_batch=1)
        with patch.object(data, "MAX_EXPANDED_BYTES", 100), self.assertRaises(ValueError):
            data.read_batches(path, examples_per_batch=2)

    def test_truncated_and_overexpanded_archives_are_rejected(self):
        path = self.archive()
        path.write_bytes(path.read_bytes()[:20])
        with self.assertRaises((EOFError, tarfile.TarError)):
            data.read_batches(path, examples_per_batch=2)
        with gzip.open(self.root / "expanded.gz", "wb") as stream:
            stream.write(b"x" * 1024)
        with gzip.open(self.root / "expanded.gz", "rb") as stream:
            with patch.object(data, "MAX_EXPANDED_BYTES", 100), self.assertRaises(ValueError):
                data.LimitedReader(stream).read(1024)

    def test_partition_is_reproducible_disjoint_and_size_weighted(self):
        first = data.partition_indices(50_000, 10_000, 256, 384, 1000, 20260923)
        second = data.partition_indices(50_000, 10_000, 256, 384, 1000, 20260923)
        for actual, expected in zip(first, second):
            np.testing.assert_array_equal(actual, expected)
        self.assertEqual([len(index) for index in first], [256, 384, 1000])
        self.assertEqual(len(np.intersect1d(first[0], first[1])), 0)
        self.assertEqual(len(np.unique(first[2])), 1000)
        self.assertLess(int(first[2].max()), 10_000)
        different = data.partition_indices(50_000, 10_000, 256, 384, 1000, 9)
        self.assertFalse(np.array_equal(first[0], different[0]))
        self.assertEqual(len(first[0]) / (len(first[0]) + len(first[1])), 0.4)
        full = data.partition_indices(50_000, 10_000, 25_000, 25_000, 10_000, 9)
        self.assertEqual(len(np.union1d(full[0], full[1])), 50_000)

    def test_invalid_counts_and_seed_are_rejected(self):
        for values in [(0, 1, 1, 1), (-1, 1, 1, 1), (1, 1, 0, 1),
                       (30_000, 25_000, 1, 1), (1, 1, 10_001, 1), (1, 1, 1, -1)]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                data.partition_indices(50_000, 10_000, *values)

    def test_archive_checksum_and_cache_reuse(self):
        path = self.archive()
        with self.assertRaisesRegex(ValueError, "checksum"):
            data.archive_hashes(path)
        expected = hashlib.md5(path.read_bytes(), usedforsecurity=False).hexdigest()
        cached = self.root / data.ARCHIVE_NAME
        path.rename(cached)
        with patch.object(data, "ARCHIVE_MD5", expected), patch.object(data.urllib.request, "build_opener") as opener:
            actual, hashes = data.obtain_archive(self.root, None)
            self.assertEqual(actual, cached)
            self.assertEqual(hashes["sha256"], hashlib.sha256(cached.read_bytes()).hexdigest())
            opener.assert_not_called()
        with patch.object(data, "MAX_ARCHIVE_BYTES", 1), self.assertRaisesRegex(ValueError, "size limit"):
            data.archive_hashes(cached)

    def test_download_checksum_failure_removes_temporary_file(self):
        response = io.BytesIO(b"corrupt download")
        response.headers = {}
        with patch.object(data.urllib.request, "build_opener") as build:
            build.return_value.open.return_value = response
            with self.assertRaisesRegex(ValueError, "checksum"):
                data.obtain_archive(self.root, None)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_download_length_and_https_redirect_are_enforced(self):
        response = io.BytesIO(b"small")
        response.headers = {"Content-Length": str(data.MAX_ARCHIVE_BYTES + 1)}
        with patch.object(data.urllib.request, "build_opener") as build:
            build.return_value.open.return_value = response
            with self.assertRaisesRegex(ValueError, "size limit"):
                data.obtain_archive(self.root, None)
        self.assertEqual(list(self.root.iterdir()), [])
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            data.HTTPSRedirectHandler().redirect_request(None, None, 302, "", {}, "http://example.com/archive")

    def test_prepare_writes_real_shards_provenance_and_refuses_overwrite(self):
        args = argparse.Namespace(output_dir=self.root / "data", cache_dir=self.root / "cache", archive=None,
                                  client1_examples=7, client2_examples=11, eval_examples=3, seed=4)
        # Parsing is covered above. Tiny pixels isolate partition/provenance behavior.
        train_x = (np.arange(50_000) % 256).astype(np.uint8).reshape(-1, 1, 1, 1)
        test_x = (np.arange(10_000) % 256).astype(np.uint8).reshape(-1, 1, 1, 1)
        arrays = (train_x, np.arange(50_000) % 10, test_x, np.arange(10_000) % 10)
        hashes = {"md5": data.ARCHIVE_MD5, "sha256": "a" * 64}
        with patch.object(data, "obtain_archive", return_value=(self.root / "archive", hashes)), \
             patch.object(data, "read_batches", return_value=arrays):
            manifest = data.prepare(args)
        self.assertTrue(manifest["train_shards_disjoint"])
        self.assertEqual(manifest, json.loads((args.output_dir / "data.json").read_text()))
        indexes = []
        for name in ["client1", "client2", "evaluation"]:
            info = manifest["shards"][name]
            path = args.output_dir / info["file"]
            self.assertEqual(info["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            with np.load(path, allow_pickle=False) as archive:
                original = arrays[2] if name == "evaluation" else arrays[0]
                np.testing.assert_array_equal(archive["x"], original[archive["indices"]])
                indexes.append(archive["indices"])
        self.assertEqual(len(np.intersect1d(indexes[0], indexes[1])), 0)
        with patch.object(data, "obtain_archive") as obtain, self.assertRaisesRegex(ValueError, "overwrite"):
            data.prepare(args)
        obtain.assert_not_called()


if __name__ == "__main__":
    unittest.main()
