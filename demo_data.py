#!/usr/bin/env python3
"""Dataset loading and deterministic synthetic data for the LeNet demo."""

from __future__ import annotations

import hashlib
from pathlib import Path

import numpy as np
import torch
from torch.utils.data import TensorDataset


def stable_seed(name: str, seed: int) -> int:
    digest = hashlib.sha256(name.encode("utf-8")).digest()
    return (int.from_bytes(digest[:8], "little") + seed) % (2**63 - 1)


def synthetic_dataset(name: str, num_examples: int, seed: int) -> TensorDataset:
    """Create an easy ten-class, MNIST-shaped dataset with client-specific noise."""
    if num_examples <= 0:
        raise ValueError("num_examples must be positive")
    generator = torch.Generator().manual_seed(stable_seed(name, seed))
    labels = torch.randint(0, 10, (num_examples,), generator=generator)
    images = torch.zeros((num_examples, 1, 28, 28), dtype=torch.float32)

    # Each class has a bright 5x5 marker at a unique grid location. The
    # background noise differs by client, so clients have independent data
    # without requiring a network download.
    for index, label in enumerate(labels.tolist()):
        row = 3 + (label // 5) * 13
        column = 2 + (label % 5) * 5
        images[index, 0, row : row + 5, column : column + 5] = 1.0

    noise = torch.randn(images.shape, generator=generator) * 0.12
    brightness = (torch.rand((num_examples, 1, 1, 1), generator=generator) - 0.5) * 0.15
    images = (images + noise + brightness).clamp_(0.0, 1.0)
    return TensorDataset(images, labels)


def load_npz_dataset(path: Path) -> TensorDataset:
    """Load x/y arrays without allowing pickled Python objects."""
    try:
        with np.load(path, allow_pickle=False) as archive:
            images_array = archive["x"]
            labels_array = archive["y"]
    except (FileNotFoundError, KeyError, ValueError) as exc:
        raise ValueError(f"Cannot load dataset {path}: {exc}") from exc

    images = torch.from_numpy(np.asarray(images_array)).to(torch.float32)
    labels = torch.from_numpy(np.asarray(labels_array)).to(torch.int64)
    if images.ndim == 3 and images.shape[1:] == (28, 28):
        images = images.unsqueeze(1)
    if images.ndim != 4 or images.shape[1:] != (1, 28, 28):
        raise ValueError(f"x must have shape [N, 28, 28] or [N, 1, 28, 28], got {images.shape}")
    if labels.ndim != 1 or labels.shape[0] != images.shape[0]:
        raise ValueError(f"y must have shape [N] matching x; got {labels.shape}")
    if images.shape[0] == 0:
        raise ValueError("Dataset is empty")
    if not bool(torch.isfinite(images).all()):
        raise ValueError("x contains NaN or infinity")
    if int(labels.min()) < 0 or int(labels.max()) > 9:
        raise ValueError("y labels must be integers from 0 through 9")

    # Accept conventional uint8-like image ranges as well as normalized input.
    if float(images.max()) > 1.5:
        images = images / 255.0
    images = images.clamp(0.0, 1.0).contiguous()
    return TensorDataset(images, labels.contiguous())


def get_dataset(
    *,
    dataset_npz: Path | None,
    synthetic_name: str,
    synthetic_examples: int,
    seed: int,
) -> tuple[TensorDataset, str]:
    if dataset_npz is not None:
        return load_npz_dataset(dataset_npz), f"npz:{dataset_npz.name}"
    return (
        synthetic_dataset(synthetic_name, synthetic_examples, seed),
        f"synthetic:{synthetic_name}",
    )
