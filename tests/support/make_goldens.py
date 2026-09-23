"""Generate the WP0 aggregation goldens under tests/goldens/ with the legacy hf2l.checkpoint_utils implementation.

Frozen generator: the goldens are pinned to the pre-cutover implementation on purpose, so this script imports
``hf2l.checkpoint_utils`` and torch and is NOT runnable after WP1 deletes that module. Do not repoint it at the new
checkpoint layer; regenerating the goldens would silently move the oracle. Nothing imports it (discovery pattern is
``test_*.py``); it is kept beside the fixtures it produced so the recipe (seed, shapes, coefficients) stays readable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import platform
import shutil
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import safetensors
import torch
from safetensors.numpy import save_file

from hf2l.checkpoint_utils import CONFIG_FILE, MODEL_FILE, MODEL_INDEX_FILE, aggregate_checkpoints, discover_checkpoint

LOG = logging.getLogger(__name__)

GOLDENS_DIR = Path(__file__).resolve().parents[1] / "goldens"
META_FILE = "meta.json"
CLIENTS_DIR = "clients"
EXPECTED_DIR = "expected"
SEED = 20260922
COEFFICIENTS = (0.2, 0.3, 0.5)
CLIENTS = len(COEFFICIENTS)
ACCUMULATOR_DTYPE = torch.float32
SHARD_METADATA = {"format": "pt"}
HASHED_KEYS = ("tensor_sha256", "file_sha256")

ClientArrays = list[np.ndarray]
TensorFamily = Callable[[np.random.Generator], dict[str, ClientArrays]]


class GoldenMismatch(RuntimeError):
    """Two generations of the same fixture produced different bytes."""


@dataclass(frozen=True)
class FixtureSpec:
    """One golden: its tensor families and how the tensors are split over weight files."""

    name: str
    tensors: TensorFamily
    shards: Mapping[str, tuple[str, ...]] | None = None  # None -> everything in MODEL_FILE, no index

    def weight_map(self, names: Sequence[str]) -> dict[str, str]:
        if self.shards is None:
            return {name: MODEL_FILE for name in names}
        return {name: filename for filename, members in self.shards.items() for name in members}


def _independent(rng: np.random.Generator, shape: tuple[int, ...], dtype: type, scale: float) -> ClientArrays:
    """One independent uniform draw of magnitude ``scale`` per client."""
    return [rng.uniform(-scale, scale, shape).astype(dtype) for _ in range(CLIENTS)]


def _cancelling(rng: np.random.Generator, shape: tuple[int, ...], dtype: type, scale: float) -> ClientArrays:
    """Clients whose weighted sum cancels to about zero, so the output magnitude is far below the operands'."""
    others = [rng.uniform(-scale, scale, shape).astype(dtype) for _ in COEFFICIENTS[:-1]]
    partial = sum(c * x.astype(np.float64) for c, x in zip(COEFFICIENTS[:-1], others, strict=True))
    last = (-partial / COEFFICIENTS[-1]).astype(dtype)
    return [*others, last]


def _shared(values: np.ndarray) -> ClientArrays:
    """The same values on every client, as the non-floating equality rule requires."""
    return [values.copy() for _ in range(CLIENTS)]


def _single_tensors(rng: np.random.Generator) -> dict[str, ClientArrays]:
    return {
        "encoder.weight": _independent(rng, (8, 16), np.float32, 1.0),
        "encoder.bias": _independent(rng, (16,), np.float32, 0.01),
        "head.weight": _cancelling(rng, (4, 4, 4), np.float16, 100.0),
    }


def _sharded_tensors(rng: np.random.Generator) -> dict[str, ClientArrays]:
    return {
        "layers.0.weight": _independent(rng, (8, 16), np.float32, 1.0),
        "layers.0.bias": _independent(rng, (16,), np.float32, 0.01),
        "layers.1.weight": _independent(rng, (4, 4, 4), np.float16, 100.0),
        "layers.1.bias": _cancelling(rng, (16,), np.float16, 100.0),
    }


def _mixed_tensors(rng: np.random.Generator) -> dict[str, ClientArrays]:
    return {
        "embed.weight": _independent(rng, (8, 16), np.float32, 1.0),
        "embed.scale": _cancelling(rng, (16,), np.float16, 100.0),
        "norm.weight": _independent(rng, (4, 4, 4), np.float64, 1.0),
        "stats.count": _shared(rng.integers(-(2**40), 2**40, (4, 4), dtype=np.int64)),
        "stats.mask": _shared(rng.integers(0, 2, (16,)).astype(np.bool_)),
    }


FIXTURES: tuple[FixtureSpec, ...] = (
    FixtureSpec("single", _single_tensors),
    FixtureSpec(
        "sharded",
        _sharded_tensors,
        shards={
            "model-00001-of-00002.safetensors": ("layers.0.weight", "layers.0.bias"),
            "model-00002-of-00002.safetensors": ("layers.1.weight", "layers.1.bias"),
        },
    ),
    FixtureSpec("mixed", _mixed_tensors),
)


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_client(root: Path, spec: FixtureSpec, tensors: dict[str, np.ndarray]) -> None:
    """Write config.json plus either model.safetensors or the index and its shards."""
    root.mkdir(parents=True)
    config = {"architectures": ["Hf2lGolden"], "fixture": spec.name, "model_type": "hf2l-golden"}
    _write_json(root / CONFIG_FILE, config)
    weight_map = spec.weight_map(list(tensors))
    for filename in sorted(set(weight_map.values())):
        members = {name: tensors[name] for name, target in weight_map.items() if target == filename}
        save_file(members, root / filename, metadata=SHARD_METADATA)
    if spec.shards is not None:
        total_size = sum(array.nbytes for array in tensors.values())
        _write_json(root / MODEL_INDEX_FILE, {"metadata": {"total_size": total_size}, "weight_map": weight_map})


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_hashes(root: Path) -> dict[str, str]:
    """sha256 of every generated file, keyed by path relative to the fixture root (meta.json excluded)."""
    files = (path for path in sorted(root.rglob("*")) if path.is_file() and path.name != META_FILE)
    return {path.relative_to(root).as_posix(): _sha256(path.read_bytes()) for path in files}


def _tensor_hashes(path: Path) -> dict[str, str]:
    """sha256 of each tensor's raw bytes as stored in one safetensors file, read from the header offsets."""
    data = path.read_bytes()
    header_length = int.from_bytes(data[:8], "little")
    header = json.loads(data[8 : 8 + header_length])
    base = 8 + header_length
    hashes: dict[str, str] = {}
    for name, entry in header.items():
        if name == "__metadata__":
            continue
        start, end = entry["data_offsets"]
        hashes[name] = _sha256(data[base + start : base + end])
    return hashes


def build_fixture(spec: FixtureSpec, root: Path) -> dict[str, Any]:
    """Write the clients and the legacy aggregate under ``root`` and return the meta.json content."""
    rng = np.random.default_rng([SEED, FIXTURES.index(spec)])
    families = spec.tensors(rng)
    for index in range(CLIENTS):
        _write_client(root / CLIENTS_DIR / str(index), spec, {name: arrays[index] for name, arrays in families.items()})
    layouts = [discover_checkpoint(root / CLIENTS_DIR / str(index)) for index in range(CLIENTS)]
    expected = aggregate_checkpoints(
        layouts[0], layouts, list(COEFFICIENTS), root / EXPECTED_DIR, accumulator_dtype=ACCUMULATOR_DTYPE
    )
    tensor_sha256: dict[str, str] = {}
    for filename in expected.weight_files:
        tensor_sha256.update(_tensor_hashes(expected.root / filename))
    meta = {
        "torch_version": torch.__version__,
        "numpy_version": np.__version__,
        "safetensors_version": safetensors.__version__,
        "platform_machine": platform.machine(),
        "cpu_capability": torch.backends.cpu.get_cpu_capability(),
        "coefficients": list(COEFFICIENTS),
        "accumulator_dtype": str(ACCUMULATOR_DTYPE).removeprefix("torch."),
        "tensor_sha256": dict(sorted(tensor_sha256.items())),
        "file_sha256": _file_hashes(root),
    }
    _write_json(root / META_FILE, meta)
    return meta


def _differences(first: Mapping[str, Any], second: Mapping[str, Any]) -> list[str]:
    """Names of hashed entries that differ between two meta.json contents."""
    return [
        f"{key}[{name}]"
        for key in HASHED_KEYS
        for name in sorted(set(first[key]) | set(second[key]))
        if first[key].get(name) != second[key].get(name)
    ]


def generate(spec: FixtureSpec, scratch: Path) -> Path:
    """Build ``spec`` twice into ``scratch`` and return the first build after proving both are byte-identical."""
    builds = [build_fixture(spec, scratch / attempt / spec.name) for attempt in ("first", "second")]
    if differences := _differences(*builds):
        raise GoldenMismatch(f"{spec.name}: re-running produced different bytes for {', '.join(differences)}")
    return scratch / "first" / spec.name


def _check(fresh: Path, committed: Path) -> list[str]:
    """Hashed entries where a fresh build disagrees with the committed fixture."""
    meta_path = committed / META_FILE
    if not meta_path.is_file():
        return [f"{META_FILE} missing"]
    committed_meta = json.loads(meta_path.read_text(encoding="utf-8"))
    return _differences(json.loads((fresh / META_FILE).read_text(encoding="utf-8")), committed_meta)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=GOLDENS_DIR, help="goldens directory (default: tests/goldens)")
    parser.add_argument(
        "--check", action="store_true", help="compare a fresh generation against --output; write nothing"
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="hf2l-goldens-") as scratch:
        for spec in FIXTURES:
            fresh = generate(spec, Path(scratch))
            meta = json.loads((fresh / META_FILE).read_text(encoding="utf-8"))
            destination = args.output / spec.name
            if args.check:
                mismatches = _check(fresh, destination)
                failures.extend(f"{spec.name}: {item}" for item in mismatches)
                LOG.info("%s: %s", spec.name, "matches" if not mismatches else f"{len(mismatches)} mismatch(es)")
                continue
            if destination.exists():
                shutil.rmtree(destination)
            shutil.copytree(fresh, destination)
            LOG.info(
                "%s: %d tensors, %d files written to %s (cpu_capability=%s)",
                spec.name,
                len(meta["tensor_sha256"]),
                len(meta["file_sha256"]),
                destination,
                meta["cpu_capability"],
            )
    for failure in failures:
        LOG.error(failure)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
