"""Strict, bounded SafeTensors header discovery using only the standard library.

No tensor payload is read, and no tensor framework is imported by discovery.
"""
from __future__ import annotations

import json
import math
import struct
from pathlib import Path
from typing import Any

from hf2l.common.fs import read_json, safe_relative_path
from hf2l.checkpoint.layout import CONFIG_FILE, MODEL_FILE, MODEL_INDEX_FILE, CheckpointLayout, TensorSpec

MAX_HEADER_BYTES = 100_000_000
MAX_JSON_DEPTH = 127
MAX_TENSOR_RANK = 1024
MAX_DIMENSION = (1 << 63) - 1
# Header dtype codes and their storage widths. Backends separately declare which
# of these they can actually calculate with.
DTYPE_BYTES = {"BOOL": 1, "U8": 1, "I8": 1, "I16": 2, "U16": 2, "F16": 2,
               "BF16": 2, "I32": 4, "U32": 4, "F32": 4, "I64": 8, "U64": 8,
               "F64": 8, "F8_E4M3": 1, "F8_E5M2": 1, "F8_E8M0": 1}


def _plain_filename(value: object, source: Path) -> str:
    if (not isinstance(value, str) or not value or "\\" in value or "\x00" in value
            or Path(value).is_absolute() or len(Path(value).parts) != 1 or Path(value).name != value):
        raise ValueError(f"Shard filename must be a plain filename in {source}: {value!r}")
    safe_relative_path(value)
    if not value.endswith(".safetensors"):
        raise ValueError(f"Checkpoint shard is not a SafeTensors file: {value}")
    return value


def _file(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"Refusing checkpoint symlink: {path}")
    if not path.is_file():
        raise ValueError(f"Checkpoint file listed but missing: {path}")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate SafeTensors header key: {key!r}")
        result[key] = value
    return result


def _finite_number(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("SafeTensors JSON number is out of range")
    return number


def _integer(value: str) -> int:
    # serde_json also rejects oversized integer literals in ignored extensions
    # when they cannot be represented by its fallback finite floating number.
    _finite_number(value)
    return int(value)


def _validate_json(value: Any) -> None:
    # Python's JSON parser retains escaped lone surrogates; the SafeTensors
    # reader rejects them, including in metadata and otherwise ignored fields.
    pending = [(value, 1)]
    while pending:
        node, depth = pending.pop()
        if isinstance(node, (dict, list)) and depth > MAX_JSON_DEPTH:
            raise ValueError("SafeTensors JSON nesting exceeds reader limit")
        if isinstance(node, str):
            node.encode("utf-8", errors="strict")
        elif isinstance(node, dict):
            pending.extend((key, depth) for key in node)
            pending.extend((item, depth + 1) for item in node.values())
        elif isinstance(node, list):
            pending.extend((item, depth + 1) for item in node)


def read_header(path: Path) -> dict[str, TensorSpec]:
    """Validate the complete file envelope, including byte-exact payload ranges."""
    _file(path)
    size = path.stat().st_size
    with path.open("rb") as stream:
        prefix = stream.read(8)
        if len(prefix) != 8:
            raise ValueError(f"Truncated SafeTensors length prefix: {path}")
        length = struct.unpack("<Q", prefix)[0]
        if length < 2 or length > MAX_HEADER_BYTES or length > size - 8:
            raise ValueError(f"Invalid SafeTensors header length: {path}")
        raw = stream.read(length)
    if not raw.startswith(b"{"):
        raise ValueError(f"Invalid SafeTensors JSON header: {path}")
    try:
        header = json.loads(raw, object_pairs_hook=_object, parse_float=_finite_number, parse_int=_integer,
                            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        _validate_json(header)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError(f"Invalid SafeTensors JSON header: {path}: {exc}") from exc
    if not isinstance(header, dict):
        raise ValueError(f"SafeTensors header must be an object: {path}")
    metadata = header.pop("__metadata__", {})
    if not isinstance(metadata, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                              for k, v in metadata.items()):
        raise ValueError(f"Invalid SafeTensors metadata: {path}")
    tensors: dict[str, TensorSpec] = {}
    intervals: list[tuple[int, int]] = []
    payload_size = size - 8 - length
    for name, spec in header.items():
        if not isinstance(name, str) or not name or not isinstance(spec, dict):
            raise ValueError(f"Invalid tensor entry in {path}: {name!r}")
        dtype, shape, offsets = spec.get("dtype"), spec.get("shape"), spec.get("data_offsets")
        if not isinstance(dtype, str) or dtype not in DTYPE_BYTES:
            raise ValueError(f"Unknown SafeTensors dtype in {path}: {dtype!r}")
        if (not isinstance(shape, list) or len(shape) > MAX_TENSOR_RANK
                or any(type(n) is not int or n < 0 or n > MAX_DIMENSION for n in shape)):
            raise ValueError(f"Invalid tensor shape for {name!r} in {path}")
        # Empty axes must not hide an overflowing shape. Both backends need
        # representable strides even when the payload itself has zero bytes.
        # Check the product of nonzero axes and the dtype width against signed
        # 64-bit buffer limits, regardless of where an empty axis occurs.
        extent = DTYPE_BYTES[dtype]
        for dimension in shape:
            if dimension:
                if extent > MAX_DIMENSION // dimension:
                    raise ValueError(f"Tensor shape overflows supported buffer size for {name!r} in {path}")
                extent *= dimension
        expected_bytes = 0 if 0 in shape else extent
        if (not isinstance(offsets, list) or len(offsets) != 2
                or any(type(n) is not int or n < 0 for n in offsets)):
            raise ValueError(f"Invalid tensor offsets for {name!r} in {path}")
        start, end = offsets
        if start > end or end > payload_size or end - start != expected_bytes:
            raise ValueError(f"Invalid tensor data bounds for {name!r} in {path}")
        intervals.append((start, end))
        tensors[name] = TensorSpec(path.name, tuple(shape), dtype)
    position = 0
    for start, end in sorted(intervals):
        if start != position:
            raise ValueError(f"Non-contiguous or overlapping SafeTensors data in {path}")
        position = end
    if position != payload_size:
        raise ValueError(f"Trailing or truncated SafeTensors payload in {path}")
    return tensors


def sniff(root: Path) -> bool:
    return (root / MODEL_FILE).exists() or (root / MODEL_INDEX_FILE).exists()


def discover(root: Path) -> CheckpointLayout:
    root = Path(root).resolve()
    _file(root / CONFIG_FILE)
    config = read_json(root / CONFIG_FILE)
    if not isinstance(config, dict):
        raise ValueError(f"Model configuration must be an object: {root / CONFIG_FILE}")
    single, index_path = root / MODEL_FILE, root / MODEL_INDEX_FILE
    expected_map: dict[str, str] | None = None
    if index_path.exists() or index_path.is_symlink():
        _file(index_path)
        index = read_json(index_path)
        raw_map = index.get("weight_map")
        if not isinstance(raw_map, dict) or not raw_map:
            raise ValueError(f"Missing or empty weight_map in {index_path}")
        expected_map = {}
        for tensor_name, filename in raw_map.items():
            if not isinstance(tensor_name, str) or not tensor_name:
                raise ValueError(f"Invalid tensor name in {index_path}: {tensor_name!r}")
            expected_map[tensor_name] = _plain_filename(filename, index_path)
        weight_files = tuple(sorted(set(expected_map.values())))
        if single.exists() and MODEL_FILE not in weight_files:
            raise ValueError(f"Both unsharded and indexed checkpoints exist in {root}")
        index_file: str | None = MODEL_INDEX_FILE
    elif single.exists() or single.is_symlink():
        weight_files, index_file = (MODEL_FILE,), None
    else:
        raise ValueError(f"No supported checkpoint in {root}; expected {MODEL_FILE} or {MODEL_INDEX_FILE}")
    tensors: dict[str, TensorSpec] = {}
    for filename in weight_files:
        for name, spec in read_header(root / filename).items():
            if name in tensors:
                raise ValueError(f"Tensor {name!r} occurs in more than one checkpoint shard")
            tensors[name] = spec
    if not tensors:
        raise ValueError(f"Checkpoint contains no tensors: {root}")
    if expected_map is not None:
        if set(expected_map) != set(tensors):
            raise ValueError(f"Index/tensor keys differ in {root}: "
                             f"missing_from_index={sorted(set(tensors)-set(expected_map))[:5]}, "
                             f"missing_from_shards={sorted(set(expected_map)-set(tensors))[:5]}")
        for key, filename in expected_map.items():
            if tensors[key].filename != filename:
                raise ValueError(f"Index maps {key!r} to {filename}, but it is stored in {tensors[key].filename}")
    return CheckpointLayout(root, config, weight_files, index_file, tensors)
