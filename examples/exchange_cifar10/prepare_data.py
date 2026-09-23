#!/usr/bin/env python3
"""Prepare two disjoint real CIFAR-10 training shards and held-out evaluation data."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request

import numpy as np


ARCHIVE_URL = "https://cave.cs.toronto.edu/kriz/cifar-10-binary.tar.gz"
ARCHIVE_MD5 = "c32a1d4ab5d03f1284b67883e8d87530"
ARCHIVE_NAME = "cifar-10-binary.tar.gz"
MAX_ARCHIVE_BYTES = 200 * 1024 * 1024
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
EXAMPLES_PER_BATCH = 10_000
RECORD_BYTES = 1 + 3 * 32 * 32
TRAIN_MEMBERS = tuple(f"cifar-10-batches-bin/data_batch_{i}.bin" for i in range(1, 6))
TEST_MEMBER = "cifar-10-batches-bin/test_batch.bin"


class HTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        if urllib.parse.urlsplit(new_url).scheme != "https":
            raise ValueError("CIFAR-10 download redirects must use HTTPS")
        return super().redirect_request(request, fp, code, message, headers, new_url)


def archive_hashes(path: Path) -> dict[str, str]:
    """Verify the publisher's MD5 and record SHA-256 for reproducible provenance."""
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("CIFAR-10 archive exceeds the 200 MiB size limit")
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            md5.update(chunk)
            sha256.update(chunk)
    if md5.hexdigest() != ARCHIVE_MD5:
        raise ValueError(f"CIFAR-10 publisher checksum mismatch: {path}")
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def obtain_archive(cache_dir: Path, supplied: Path | None) -> tuple[Path, dict[str, str]]:
    if supplied is not None:
        return supplied, archive_hashes(supplied)
    cache_dir.mkdir(parents=True, exist_ok=True)
    destination = cache_dir / ARCHIVE_NAME
    if destination.exists():
        return destination, archive_hashes(destination)
    opener = urllib.request.build_opener(HTTPSRedirectHandler())
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=cache_dir, prefix=".cifar10-", suffix=".part", delete=False) as output:
            temporary = Path(output.name)
            request = urllib.request.Request(ARCHIVE_URL, headers={"User-Agent": "hf2l-cifar10-demo"})
            with opener.open(request, timeout=30) as response:
                length = response.headers.get("Content-Length")
                if length is not None and int(length) > MAX_ARCHIVE_BYTES:
                    raise ValueError("CIFAR-10 download exceeds the 200 MiB size limit")
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_ARCHIVE_BYTES:
                        raise ValueError("CIFAR-10 download exceeds the 200 MiB size limit")
                    output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        hashes = archive_hashes(temporary)
        os.replace(temporary, destination)
        return destination, hashes
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class LimitedReader:
    def __init__(self, stream):
        self.stream = stream
        self.total = 0

    def read(self, size):
        chunk = self.stream.read(min(size, MAX_EXPANDED_BYTES - self.total + 1))
        self.total += len(chunk)
        if self.total > MAX_EXPANDED_BYTES:
            raise ValueError("CIFAR-10 archive exceeds the expanded size limit")
        return chunk


def parse_batch(content: bytes, expected_examples: int) -> tuple[np.ndarray, np.ndarray]:
    if len(content) != expected_examples * RECORD_BYTES:
        raise ValueError("CIFAR-10 binary batch has an unexpected length")
    records = np.frombuffer(content, dtype=np.uint8).reshape(expected_examples, RECORD_BYTES)
    labels = records[:, 0].astype(np.int64)
    if np.any(labels > 9):
        raise ValueError("CIFAR-10 labels must be between 0 and 9")
    return records[:, 1:].copy().reshape(-1, 3, 32, 32), labels


def read_batches(path: Path, *, examples_per_batch: int = EXAMPLES_PER_BATCH):
    """Read only named regular members; never extract archive paths or unpickle data."""
    expected = {*TRAIN_MEMBERS, TEST_MEMBER}
    batches = {}
    with gzip.open(path, "rb") as compressed:
        with tarfile.open(fileobj=LimitedReader(compressed), mode="r|") as archive:
            for member in archive:
                if member.size < 0 or member.size > MAX_EXPANDED_BYTES:
                    raise ValueError("CIFAR-10 archive member exceeds the size limit")
                if member.name not in expected:
                    continue
                if member.name in batches or not member.isfile():
                    raise ValueError("CIFAR-10 archive has duplicate or nonregular data members")
                if member.size != examples_per_batch * RECORD_BYTES:
                    raise ValueError("CIFAR-10 binary batch has an unexpected length")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("Cannot read CIFAR-10 binary batch")
                with stream:
                    batches[member.name] = parse_batch(stream.read(), examples_per_batch)
    if set(batches) != expected:
        raise ValueError("CIFAR-10 archive is missing expected binary batches")
    train_x = np.concatenate([batches[name][0] for name in TRAIN_MEMBERS])
    train_y = np.concatenate([batches[name][1] for name in TRAIN_MEMBERS])
    return train_x, train_y, *batches[TEST_MEMBER]


def partition_indices(train_count: int, test_count: int, client1: int, client2: int, evaluation: int, seed: int):
    if min(client1, client2, evaluation) <= 0:
        raise ValueError("Client and evaluation example counts must be positive")
    if client1 + client2 > train_count or evaluation > test_count:
        raise ValueError("Requested examples exceed the available CIFAR-10 split")
    if seed < 0:
        raise ValueError("The partition seed must be nonnegative")
    generator = np.random.default_rng(seed)
    train = generator.permutation(train_count)
    test = generator.permutation(test_count)
    return train[:client1], train[client1:client1 + client2], test[:evaluation]


def prepare(args) -> dict:
    output = args.output_dir.expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise ValueError(f"Refusing to overwrite existing output: {output}")
    indexes = partition_indices(50_000, 10_000, args.client1_examples, args.client2_examples,
                                args.eval_examples, args.seed)
    archive, hashes = obtain_archive(args.cache_dir.expanduser(), args.archive.expanduser() if args.archive else None)
    train_x, train_y, test_x, test_y = read_batches(archive)
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}-", dir=output.parent))
    try:
        shards = {}
        for name, source, images, labels, index in (
            ("client1", "train", train_x, train_y, indexes[0]),
            ("client2", "train", train_x, train_y, indexes[1]),
            ("evaluation", "test", test_x, test_y, indexes[2]),
        ):
            path = staging / f"{name}.npz"
            np.savez_compressed(path, x=images[index], y=labels[index], indices=index)
            shards[name] = {"file": path.name, "split": source, "num_examples": len(index),
                            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                            "index_sha256": hashlib.sha256(index.astype("<i8").tobytes()).hexdigest()}
        manifest = {"dataset": "CIFAR-10", "source_url": ARCHIVE_URL,
                    "archive": {"file": ARCHIVE_NAME, **hashes}, "seed": args.seed,
                    "partition": "seeded shuffled original indexes; first client1, then client2",
                    "train_shards_disjoint": bool(not np.intersect1d(indexes[0], indexes[1]).size),
                    "evaluation_source": "held-out original test split",
                    "source_counts": {"train": len(train_y), "test": len(test_y)}, "shards": shards}
        (staging / "data.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if output.exists() or output.is_symlink():
            raise ValueError(f"Refusing to overwrite existing output: {output}")
        staging.rename(output)
        return manifest
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--cache-dir", type=Path, default=Path("work/cifar10-cache"))
    parser.add_argument("--archive", type=Path, help="Use an already downloaded official binary archive")
    parser.add_argument("--client1-examples", type=int, default=25_000)
    parser.add_argument("--client2-examples", type=int, default=25_000)
    parser.add_argument("--eval-examples", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=20260923)
    args = parser.parse_args(argv)
    try:
        manifest = prepare(args)
    except (OSError, ValueError, tarfile.TarError, EOFError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"data_dir": str(args.output_dir.resolve()),
                      "examples": {name: info["num_examples"] for name, info in manifest["shards"].items()}}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
