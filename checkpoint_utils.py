#!/usr/bin/env python3
"""Validate and aggregate generic SafeTensors model checkpoints."""

from __future__ import annotations

import math
import shutil
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import torch
from safetensors.torch import safe_open, save_file

from hub_helpers import ROUND_FILE, SUBMISSION_FILE, read_json


CONFIG_FILE = "config.json"
MODEL_FILE = "model.safetensors"
MODEL_INDEX_FILE = "model.safetensors.index.json"


@dataclass(frozen=True)
class TensorSpec:
    filename: str
    shape: tuple[int, ...]
    dtype: str


@dataclass(frozen=True)
class CheckpointLayout:
    root: Path
    config: dict[str, Any]
    weight_files: tuple[str, ...]
    index_file: str | None
    tensors: dict[str, TensorSpec]

    @property
    def artifact_paths(self) -> tuple[str, ...]:
        paths = [CONFIG_FILE, *self.weight_files]
        if self.index_file:
            paths.append(self.index_file)
        return tuple(paths)


def _safe_relative_filename(value: object, source: Path) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"Invalid shard filename in {source}: {value!r}")
    path = Path(value)
    if path.is_absolute() or len(path.parts) != 1 or path.name != value:
        raise ValueError(f"Shard filename must be a plain filename in {source}: {value!r}")
    if path.suffix != ".safetensors":
        raise ValueError(f"Checkpoint shard is not a SafeTensors file: {value}")
    return value


def discover_checkpoint(root: Path) -> CheckpointLayout:
    """Read the layout and tensor schema without materializing model tensors."""
    root = root.resolve()
    config = read_json(root / CONFIG_FILE)
    single = root / MODEL_FILE
    index_path = root / MODEL_INDEX_FILE

    expected_map: dict[str, str] | None = None
    if index_path.is_file():
        index = read_json(index_path)
        raw_map = index.get("weight_map")
        if not isinstance(raw_map, dict) or not raw_map:
            raise ValueError(f"Missing or empty weight_map in {index_path}")
        expected_map = {}
        for tensor_name, filename in raw_map.items():
            if not isinstance(tensor_name, str) or not tensor_name:
                raise ValueError(f"Invalid tensor name in {index_path}: {tensor_name!r}")
            expected_map[tensor_name] = _safe_relative_filename(filename, index_path)
        weight_files = tuple(sorted(set(expected_map.values())))
        if single.exists() and MODEL_FILE not in weight_files:
            raise ValueError(f"Both unsharded and indexed checkpoints exist in {root}")
        index_file: str | None = MODEL_INDEX_FILE
    elif single.is_file():
        weight_files = (MODEL_FILE,)
        index_file = None
    else:
        raise ValueError(
            f"No supported checkpoint in {root}; expected {MODEL_FILE} or {MODEL_INDEX_FILE}"
        )

    tensors: dict[str, TensorSpec] = {}
    for filename in weight_files:
        path = root / filename
        if not path.is_file():
            raise ValueError(f"Checkpoint shard listed but missing: {path}")
        with safe_open(path, framework="pt", device="cpu") as handle:
            for key in handle.keys():
                if key in tensors:
                    raise ValueError(f"Tensor {key!r} occurs in more than one checkpoint shard")
                tensor_slice = handle.get_slice(key)
                tensors[key] = TensorSpec(
                    filename=filename,
                    shape=tuple(tensor_slice.get_shape()),
                    dtype=str(tensor_slice.get_dtype()),
                )

    if not tensors:
        raise ValueError(f"Checkpoint contains no tensors: {root}")
    if expected_map is not None:
        if set(expected_map) != set(tensors):
            missing = sorted(set(tensors) - set(expected_map))
            extra = sorted(set(expected_map) - set(tensors))
            raise ValueError(
                f"Index/tensor keys differ in {root}: missing_from_index={missing[:5]}, "
                f"missing_from_shards={extra[:5]}"
            )
        for key, filename in expected_map.items():
            if tensors[key].filename != filename:
                raise ValueError(
                    f"Index maps {key!r} to {filename}, but it is stored in "
                    f"{tensors[key].filename}"
                )

    return CheckpointLayout(root, config, weight_files, index_file, tensors)


def validate_compatible(reference: CheckpointLayout, candidate: CheckpointLayout) -> None:
    """Require an identical config, tensor schema, and shard layout."""
    if candidate.config != reference.config:
        raise ValueError(f"Model configuration changed in {candidate.root}")
    if candidate.index_file != reference.index_file:
        raise ValueError(f"Checkpoint index layout changed in {candidate.root}")
    if candidate.weight_files != reference.weight_files:
        raise ValueError(f"Checkpoint shard filenames changed in {candidate.root}")
    if candidate.tensors != reference.tensors:
        reference_keys = set(reference.tensors)
        candidate_keys = set(candidate.tensors)
        missing = sorted(reference_keys - candidate_keys)
        extra = sorted(candidate_keys - reference_keys)
        if missing or extra:
            raise ValueError(
                f"Checkpoint tensor keys changed in {candidate.root}: "
                f"missing={missing[:5]}, extra={extra[:5]}"
            )
        for key in sorted(reference_keys):
            if reference.tensors[key] != candidate.tensors[key]:
                raise ValueError(
                    f"Checkpoint tensor schema changed for {key!r}: "
                    f"{reference.tensors[key]} != {candidate.tensors[key]}"
                )
        raise ValueError(f"Checkpoint layout changed in {candidate.root}")


def validate_coefficients(coefficients: list[float], client_count: int) -> None:
    if client_count == 0:
        raise ValueError("At least one client checkpoint is required")
    if len(coefficients) != client_count:
        raise ValueError("Client and coefficient counts differ")
    if any(not math.isfinite(value) or value < 0 for value in coefficients):
        raise ValueError("Aggregation coefficients must be finite and non-negative")
    if not math.isclose(sum(coefficients), 1.0, rel_tol=1e-9, abs_tol=1e-9):
        raise ValueError("Aggregation coefficients must sum to one")


def average_tensor(
    reference: torch.Tensor,
    candidates: list[torch.Tensor],
    coefficients: list[float],
    accumulator_dtype: torch.dtype,
    name: str,
) -> torch.Tensor:
    if not reference.is_floating_point():
        if not all(torch.equal(reference, candidate) for candidate in candidates):
            raise ValueError(
                f"Non-floating tensor {name!r} differs between clients; "
                "it cannot be averaged safely"
            )
        return reference.clone()

    effective_dtype = torch.float64 if reference.dtype == torch.float64 else accumulator_dtype
    accumulator = torch.zeros(reference.shape, dtype=effective_dtype)
    for coefficient, tensor in zip(coefficients, candidates, strict=True):
        accumulator.add_(tensor.to(effective_dtype), alpha=coefficient)
    if not bool(torch.isfinite(accumulator).all()):
        raise ValueError(f"Aggregated tensor contains NaN or infinity: {name}")
    return accumulator.to(reference.dtype)


def _copy_non_checkpoint_files(reference: CheckpointLayout, output_dir: Path) -> None:
    excluded = set(reference.weight_files) | {
        CONFIG_FILE,
        MODEL_INDEX_FILE,
        ROUND_FILE,
        SUBMISSION_FILE,
    }
    for source in reference.root.rglob("*"):
        relative = source.relative_to(reference.root)
        if any(part in {".git", ".cache"} for part in relative.parts):
            continue
        if len(relative.parts) == 1 and relative.as_posix() in excluded:
            continue
        if source.is_symlink():
            raise ValueError(f"Refusing to copy symlink from checkpoint: {source}")
        if source.is_dir():
            continue
        target = output_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def aggregate_checkpoints(
    reference: CheckpointLayout,
    clients: list[CheckpointLayout],
    coefficients: list[float],
    output_dir: Path,
    *,
    accumulator_dtype: torch.dtype = torch.float32,
) -> CheckpointLayout:
    """Average one shard at a time and return the validated output layout."""
    validate_coefficients(coefficients, len(clients))
    for client in clients:
        validate_compatible(reference, client)
    output_dir.mkdir(parents=True, exist_ok=False)
    _copy_non_checkpoint_files(reference, output_dir)
    shutil.copy2(reference.root / CONFIG_FILE, output_dir / CONFIG_FILE)
    if reference.index_file:
        shutil.copy2(reference.root / reference.index_file, output_dir / reference.index_file)

    for filename in reference.weight_files:
        keys = sorted(key for key, spec in reference.tensors.items() if spec.filename == filename)
        with ExitStack() as stack:
            reference_handle = stack.enter_context(
                safe_open(reference.root / filename, framework="pt", device="cpu")
            )
            client_handles = [
                stack.enter_context(safe_open(client.root / filename, framework="pt", device="cpu"))
                for client in clients
            ]
            metadata = reference_handle.metadata()
            averaged: dict[str, torch.Tensor] = {}
            for key in keys:
                reference_tensor = reference_handle.get_tensor(key)
                candidate_tensors = [handle.get_tensor(key) for handle in client_handles]
                averaged[key] = average_tensor(
                    reference_tensor,
                    candidate_tensors,
                    coefficients,
                    accumulator_dtype,
                    key,
                )
            save_file(averaged, output_dir / filename, metadata=metadata)
            del averaged

    return discover_checkpoint(output_dir)


def copy_model_directory(source: Path, destination: Path) -> None:
    """Copy an intentional model export while excluding local Hub/Git caches."""
    source = source.resolve()
    if not source.is_dir():
        raise ValueError(f"Model directory does not exist: {source}")
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
