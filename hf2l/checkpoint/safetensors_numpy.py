"""SafeTensors numerical operations for a Torch-free coordinator."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import numpy as np
from safetensors import safe_open
from safetensors.numpy import save_file


class Ops:
    name = "numpy"
    dtypes = frozenset({"BOOL", "U8", "I8", "U16", "I16", "U32", "I32", "U64", "I64", "F16", "F32", "F64"})
    _names = {"bool": "BOOL", "uint8": "U8", "int8": "I8", "uint16": "U16", "int16": "I16",
              "uint32": "U32", "int32": "I32", "uint64": "U64", "int64": "I64",
              "float16": "F16", "float32": "F32", "float64": "F64"}

    def open_shard(self, path: Path):
        return safe_open(path, framework="np")

    def write_shard(self, path: Path, tensors: Mapping[str, Any], metadata: Mapping[str, str] | None) -> None:
        save_file(dict(tensors), path, metadata=None if metadata is None else dict(metadata))

    def is_floating(self, array: np.ndarray) -> bool:
        return bool(np.issubdtype(array.dtype, np.floating))

    def equal(self, left: np.ndarray, right: np.ndarray) -> bool:
        return bool(np.array_equal(left, right))

    def zeros(self, shape: tuple[int, ...], dtype: str) -> np.ndarray:
        return np.zeros(shape, dtype=dtype)

    def add_scaled(self, accumulator: np.ndarray, array: np.ndarray, coefficient: float) -> None:
        with np.errstate(over="ignore", invalid="ignore"):
            accumulator += array * coefficient

    def all_finite(self, array: np.ndarray) -> bool:
        return bool(np.isfinite(array).all())

    def astype(self, array: np.ndarray, dtype: str) -> np.ndarray:
        dtype = {value: key for key, value in self._names.items()}.get(dtype, dtype)
        with np.errstate(over="ignore", invalid="ignore"):
            return array.astype(dtype, copy=False)

    def dtype_name(self, array: np.ndarray) -> str:
        return self._names[str(array.dtype)]

    def clone(self, array: np.ndarray) -> np.ndarray:
        return array.copy()
