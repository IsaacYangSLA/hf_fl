"""Checkpoint descriptions contain no framework objects."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
    format: str = "safetensors"

    @property
    def artifact_paths(self) -> tuple[str, ...]:
        return (CONFIG_FILE, *self.weight_files, *((self.index_file,) if self.index_file else ()))


@dataclass(frozen=True)
class CompatibilityPolicy:
    """Strict by default; selected configuration keys can define model identity."""
    identity_keys: tuple[str, ...] | None = None

    def check(self, reference: CheckpointLayout, candidate: CheckpointLayout) -> None:
        if reference.format != candidate.format:
            raise ValueError(f"Checkpoint format changed in {candidate.root}")
        if self.identity_keys is None:
            same_config = candidate.config == reference.config
        else:
            same_config = all(key in reference.config and key in candidate.config
                              and reference.config[key] == candidate.config[key]
                              for key in self.identity_keys)
        if not same_config:
            raise ValueError(f"Model configuration changed in {candidate.root}")
        if candidate.index_file != reference.index_file:
            raise ValueError(f"Checkpoint index layout changed in {candidate.root}")
        if candidate.weight_files != reference.weight_files:
            raise ValueError(f"Checkpoint shard filenames changed in {candidate.root}")
        if candidate.tensors != reference.tensors:
            reference_keys, candidate_keys = set(reference.tensors), set(candidate.tensors)
            missing, extra = sorted(reference_keys - candidate_keys), sorted(candidate_keys - reference_keys)
            if missing or extra:
                raise ValueError(f"Checkpoint tensor keys changed in {candidate.root}: missing={missing[:5]}, extra={extra[:5]}")
            for key in sorted(reference_keys):
                if reference.tensors[key] != candidate.tensors[key]:
                    raise ValueError(f"Checkpoint tensor schema changed for {key!r}: "
                                     f"{reference.tensors[key]} != {candidate.tensors[key]}")
            raise ValueError(f"Checkpoint layout changed in {candidate.root}")


def validate_compatible(reference: CheckpointLayout, candidate: CheckpointLayout) -> None:
    CompatibilityPolicy().check(reference, candidate)
