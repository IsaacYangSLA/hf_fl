"""Compatibility façade for the framework-neutral :mod:`hf2l.checkpoint` layer.

Existing callers retain Torch arithmetic unless they explicitly select NumPy.
Imports and checkpoint discovery themselves do not import Torch or a Hub client.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from hf2l.checkpoint.aggregate import average, aggregate_shards, copy_model_directory, validate_coefficients
from hf2l.checkpoint.format import ArrayOps, accumulator_name, discover as discover_checkpoint, get_ops
from hf2l.checkpoint.layout import CONFIG_FILE, MODEL_FILE, MODEL_INDEX_FILE, CheckpointLayout, TensorSpec, validate_compatible


def average_tensor(reference: Any, candidates: list[Any], coefficients: list[float],
                   accumulator_dtype: Any, name: str) -> Any:
    # The legacy in-memory helper takes Torch tensors. Import only on invocation.
    from hf2l.checkpoint.safetensors_torch import Ops
    return average(reference, candidates, coefficients, accumulator_dtype=accumulator_name(accumulator_dtype),
                   name=name, ops=Ops())


def aggregate_checkpoints(reference: CheckpointLayout, clients: list[CheckpointLayout], coefficients: list[float],
                          output_dir: Path, *, accumulator_dtype: Any = None, array_backend: str = "torch",
                          ops: ArrayOps | None = None, excluded_paths: Iterable[str] = ()) -> CheckpointLayout:
    # Workflow files are deliberately excluded here, outside the generic layer.
    from hf2l.core.protocol import ROUND_FILE, SUBMISSION_FILE
    excluded = (ROUND_FILE, SUBMISSION_FILE, *excluded_paths)
    return aggregate_shards(reference, clients, coefficients, output_dir,
                            ops=ops if ops is not None else get_ops(reference, prefer=array_backend),
                            accumulator_dtype=accumulator_name(accumulator_dtype), exclude=excluded)
