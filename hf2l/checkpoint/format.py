"""On-disk format discovery and lazy numerical backend selection."""
from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from hf2l.checkpoint.layout import CheckpointLayout
from hf2l.checkpoint import safetensors


class Shard(Protocol):
    def get_tensor(self, name: str) -> Any: ...
    def metadata(self) -> dict[str, str] | None: ...


class ArrayOps(Protocol):
    name: str
    dtypes: frozenset[str]
    def open_shard(self, path: Path) -> AbstractContextManager[Shard]: ...
    def write_shard(self, path: Path, tensors: Mapping[str, Any], metadata: Mapping[str, str] | None) -> None: ...
    def is_floating(self, array: Any) -> bool: ...
    def equal(self, left: Any, right: Any) -> bool: ...
    def zeros(self, shape: tuple[int, ...], dtype: str) -> Any: ...
    def add_scaled(self, accumulator: Any, array: Any, coefficient: float) -> None: ...
    def all_finite(self, array: Any) -> bool: ...
    def astype(self, array: Any, dtype: str) -> Any: ...
    def dtype_name(self, array: Any) -> str: ...
    def clone(self, array: Any) -> Any: ...


@dataclass(frozen=True)
class FormatSpec:
    sniff: Callable[[Path], bool]
    discover: Callable[[Path], CheckpointLayout]
    backends: tuple[str, ...]


FORMATS = {"safetensors": FormatSpec(safetensors.sniff, safetensors.discover,
                                    ("hf2l.checkpoint.safetensors_numpy", "hf2l.checkpoint.safetensors_torch"))}


def discover(root: Path, *, format_name: str | None = None) -> CheckpointLayout:
    root = Path(root)
    if format_name is not None:
        if format_name not in FORMATS:
            raise ValueError(f"Unknown checkpoint format: {format_name}")
        return FORMATS[format_name].discover(root)
    for spec in FORMATS.values():
        if spec.sniff(root):
            return spec.discover(root)
    raise ValueError(f"No supported checkpoint in {root}")


def get_ops(layout: CheckpointLayout, *, prefer: str | None = None) -> ArrayOps:
    """Default to NumPy, falling back to Torch only when the dtype requires it."""
    try:
        modules = FORMATS[layout.format].backends
    except KeyError as exc:
        raise ValueError(f"Unknown checkpoint format: {layout.format}") from exc
    names = {module.rsplit("_", 1)[-1]: module for module in modules}
    if prefer is not None:
        if prefer not in names:
            raise ValueError(f"Unknown array backend for {layout.format}: {prefer}")
        modules = (names[prefer],)
    required = {spec.dtype for spec in layout.tensors.values()}
    failures = []
    for module in modules:
        try:
            ops = import_module(module).Ops()
        except ImportError as exc:
            failures.append(str(exc))
            continue
        if required <= ops.dtypes:
            return ops
    if "BF16" in required:
        raise ValueError("BF16 tensors require the Torch backend; install hf2l[torch] and select array_backend='torch'")
    raise ValueError(f"No available array backend supports {sorted(required)} for {layout.format}: {'; '.join(failures)}")


def accumulator_name(value: Any = None) -> str:
    """Accept legacy torch dtype values without importing torch."""
    name = "float32" if value is None else str(value).removeprefix("torch.")
    names = {"F32": "float32", "F64": "float64", "float32": "float32", "float64": "float64"}
    if name not in names:
        raise ValueError("Accumulator dtype must be float32 or float64")
    return names[name]
