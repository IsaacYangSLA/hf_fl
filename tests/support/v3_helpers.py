"""Small NumPy checkpoints for cross-layer v3 contract tests."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
from safetensors.numpy import load_file, save_file


def write_checkpoint(folder: Path, value: float) -> Path:
    """Write a real checkpoint without importing a training framework."""
    folder.mkdir(parents=True)
    save_file({"weight": np.array([value], dtype=np.float32)}, folder / "model.safetensors")
    (folder / "config.json").write_text(json.dumps({"model_type": "v3-integration"}), encoding="utf-8")
    return folder


def initialize_model(
    folder: Path, backend: str, *, value: float = 0.0,
    algorithm_spec: dict[str, object] | None = None,
) -> Path:
    write_checkpoint(folder, value)
    hashes = {
        name: hashlib.sha256((folder / name).read_bytes()).hexdigest()
        for name in ("config.json", "model.safetensors")
    }
    record = {"schema_version": 2, "backend": backend, "round": 0,
              "checkpoint_files_sha256": hashes}
    if algorithm_spec is not None:
        record["algorithm_spec"] = algorithm_spec
    (folder / "fedavg_round.json").write_text(json.dumps(record), encoding="utf-8")
    return folder


def checkpoint_value(folder: Path) -> float:
    return float(load_file(folder / "model.safetensors")["weight"][0])
