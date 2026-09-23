"""Optional Torch operations, retaining the legacy add_(alpha=) arithmetic."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import torch
from safetensors import safe_open
from safetensors.torch import save_file


class Ops:
    name = "torch"
    _types = {"BOOL": torch.bool, "U8": torch.uint8, "I8": torch.int8,
              "I16": torch.int16, "I32": torch.int32, "I64": torch.int64,
              "F16": torch.float16, "BF16": torch.bfloat16, "F32": torch.float32, "F64": torch.float64}
    # Unsigned types exist only in newer Torch versions.
    for _code, _attr in (("U16", "uint16"), ("U32", "uint32"), ("U64", "uint64")):
        if hasattr(torch, _attr):
            _types[_code] = getattr(torch, _attr)
    dtypes = frozenset(_types)

    def open_shard(self, path: Path):
        return safe_open(path, framework="pt", device="cpu")

    def write_shard(self, path: Path, tensors: Mapping[str, Any], metadata: Mapping[str, str] | None) -> None:
        save_file(dict(tensors), path, metadata=None if metadata is None else dict(metadata))

    def is_floating(self, array: torch.Tensor) -> bool:
        return array.is_floating_point()

    def equal(self, left: torch.Tensor, right: torch.Tensor) -> bool:
        return bool(torch.equal(left, right))

    def zeros(self, shape: tuple[int, ...], dtype: str) -> torch.Tensor:
        return torch.zeros(shape, dtype=getattr(torch, dtype))

    def add_scaled(self, accumulator: torch.Tensor, array: torch.Tensor, coefficient: float) -> None:
        accumulator.add_(array, alpha=coefficient)

    def all_finite(self, array: torch.Tensor) -> bool:
        return bool(torch.isfinite(array).all())

    def astype(self, array: torch.Tensor, dtype: str) -> torch.Tensor:
        return array.to(self._types[dtype] if dtype in self._types else getattr(torch, dtype))

    def dtype_name(self, array: torch.Tensor) -> str:
        return next(name for name, dtype in self._types.items() if dtype == array.dtype)

    def clone(self, array: torch.Tensor) -> torch.Tensor:
        return array.clone()
