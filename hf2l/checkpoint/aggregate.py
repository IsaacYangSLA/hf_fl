"""One averaging policy, parameterized by primitive array operations."""
from __future__ import annotations

import math
import shutil
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Iterable

from hf2l.checkpoint.format import ArrayOps, accumulator_name, discover, get_ops
from hf2l.checkpoint.layout import CONFIG_FILE, CheckpointLayout, CompatibilityPolicy


def validate_coefficients(coefficients: list[float], client_count: int) -> None:
    if client_count == 0:
        raise ValueError("At least one client checkpoint is required")
    if len(coefficients) != client_count:
        raise ValueError("Client and coefficient counts differ")
    if any(not math.isfinite(value) or value < 0 for value in coefficients):
        raise ValueError("Aggregation coefficients must be finite and non-negative")
    if not math.isclose(sum(coefficients), 1.0, rel_tol=1e-9, abs_tol=1e-9):
        raise ValueError("Aggregation coefficients must sum to one")


def average(reference: Any, candidates: list[Any], coefficients: list[float], *,
            accumulator_dtype: str = "float32", name: str, ops: ArrayOps,
            cast_back: bool = True) -> Any:
    """Require matching non-floats; reject non-finite inputs and intermediates.

    ``cast_back=False`` exposes the same accumulator for numeric conformance
    checks. Production always casts the validated accumulator to the input dtype.
    """
    validate_coefficients(coefficients, len(candidates))
    accumulator_dtype = accumulator_name(accumulator_dtype)
    if any(tuple(candidate.shape) != tuple(reference.shape) or ops.dtype_name(candidate) != ops.dtype_name(reference)
           for candidate in candidates):
        raise ValueError(f"Checkpoint tensor schema changed for {name!r}")
    if not ops.is_floating(reference):
        if not all(ops.equal(reference, candidate) for candidate in candidates):
            raise ValueError(f"Non-floating tensor {name!r} differs between clients; it cannot be averaged safely")
        return ops.clone(reference)
    if not ops.all_finite(reference) or any(not ops.all_finite(candidate) for candidate in candidates):
        raise ValueError(f"Input tensor contains NaN or infinity: {name}")
    dtype = "float64" if ops.dtype_name(reference) == "F64" else accumulator_dtype
    accumulator = ops.zeros(tuple(reference.shape), dtype)
    for coefficient, candidate in zip(coefficients, candidates, strict=True):
        converted = ops.astype(candidate, dtype)
        if not ops.all_finite(converted):
            raise ValueError(f"Input tensor overflows accumulator dtype: {name}")
        ops.add_scaled(accumulator, converted, coefficient)
        if not ops.all_finite(accumulator):
            raise ValueError(f"Aggregated tensor contains NaN or infinity: {name}")
    if not cast_back:
        return accumulator
    result = ops.astype(accumulator, ops.dtype_name(reference))
    if not ops.all_finite(result):
        raise ValueError(f"Aggregated tensor overflows output dtype: {name}")
    return result


def _copy_non_checkpoint_files(reference: CheckpointLayout, output_dir: Path, exclude: Iterable[str]) -> None:
    excluded = {Path(value).as_posix().rstrip("/") for value in (*reference.artifact_paths, *exclude)}
    for source in reference.root.rglob("*"):
        relative = source.relative_to(reference.root)
        if any(part in {".git", ".cache", "__pycache__"} for part in relative.parts):
            continue
        if any(relative.as_posix() == value or relative.as_posix().startswith(value + "/") for value in excluded):
            continue
        if source.is_symlink():
            raise ValueError(f"Refusing to copy symlink from checkpoint: {source}")
        if source.is_dir():
            continue
        target = output_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def aggregate_shards(reference: CheckpointLayout, clients: list[CheckpointLayout], coefficients: list[float],
                     output_dir: Path, *, ops: ArrayOps | None = None, accumulator_dtype: Any = "float32",
                     exclude: Iterable[str] = (), compatibility: CompatibilityPolicy | None = None) -> CheckpointLayout:
    """Open only one shard per input at a time, then write and release its output."""
    validate_coefficients(coefficients, len(clients))
    dtype = accumulator_name(accumulator_dtype)
    ops = get_ops(reference) if ops is None else ops
    policy = compatibility or CompatibilityPolicy()
    for client in clients:
        policy.check(reference, client)
    output_dir = Path(output_dir)
    resolved_output = output_dir.resolve()
    for layout in (reference, *clients):
        if resolved_output == layout.root.resolve() or layout.root.resolve() in resolved_output.parents:
            raise ValueError("Aggregation output must be outside every input checkpoint")
    output_dir.mkdir(parents=True, exist_ok=False)
    _copy_non_checkpoint_files(reference, output_dir, exclude)
    shutil.copy2(reference.root / CONFIG_FILE, output_dir / CONFIG_FILE)
    if reference.index_file:
        shutil.copy2(reference.root / reference.index_file, output_dir / reference.index_file)
    for filename in reference.weight_files:
        keys = sorted(key for key, spec in reference.tensors.items() if spec.filename == filename)
        with ExitStack() as stack:
            base = stack.enter_context(ops.open_shard(reference.root / filename))
            handles = [stack.enter_context(ops.open_shard(client.root / filename)) for client in clients]
            averaged: dict[str, Any] = {}
            for key in keys:
                averaged[key] = average(base.get_tensor(key), [handle.get_tensor(key) for handle in handles],
                                        coefficients, accumulator_dtype=dtype, name=key, ops=ops)
            ops.write_shard(output_dir / filename, averaged, base.metadata())
            del averaged
    return discover(output_dir, format_name=reference.format)


def copy_model_directory(source: Path, destination: Path) -> None:
    """Copy a model export excluding local caches and refusing symlinks."""
    source = Path(source).resolve()
    if not source.is_dir():
        raise ValueError(f"Model directory does not exist: {source}")
    destination = Path(destination)
    resolved = destination.resolve()
    if resolved == source or source in resolved.parents:
        raise ValueError("Model destination must be outside its source directory")
    destination.mkdir(parents=True, exist_ok=False)
    for item in source.rglob("*"):
        relative = item.relative_to(source)
        if any(part in {".git", ".cache", "__pycache__"} for part in relative.parts):
            continue
        if item.is_symlink():
            raise ValueError(f"Refusing to copy symlink from model directory: {item}")
        if item.is_dir():
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, target)
