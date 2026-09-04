#!/usr/bin/env python3
"""CIFAR-10 NPZ loading and deterministic synthetic data for the VGG POC."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import torch
from torch.utils.data import TensorDataset

from data_utils import stable_seed


_CIFAR10_MEAN = torch.tensor((0.4914, 0.4822, 0.4465)).view(1, 3, 1, 1)
_CIFAR10_STD = torch.tensor((0.2470, 0.2435, 0.2616)).view(1, 3, 1, 1)


def _normalize(images: torch.Tensor) -> torch.Tensor:
    return ((images - _CIFAR10_MEAN) / _CIFAR10_STD).contiguous()


def synthetic_dataset(name: str, num_examples: int, seed: int) -> TensorDataset:
    """Create an easy RGB ten-class dataset with client-specific noise."""
    if num_examples <= 0:
        raise ValueError("num_examples must be positive")
    generator = torch.Generator().manual_seed(stable_seed(name, seed))
    labels = torch.randint(0, 10, (num_examples,), generator=generator)
    images = torch.rand((num_examples, 3, 32, 32), generator=generator) * 0.08

    # Each class has a distinct channel, location, and intensity. This is an
    # offline smoke-test dataset, not a substitute for CIFAR-10 evaluation.
    for index, label in enumerate(labels.tolist()):
        channel = label % 3
        row = 2 + (label // 5) * 16
        column = 2 + (label % 5) * 6
        images[index, channel, row : row + 8, column : column + 6] = 0.55 + label * 0.04

    brightness = (torch.rand((num_examples, 1, 1, 1), generator=generator) - 0.5) * 0.08
    return TensorDataset(_normalize((images + brightness).clamp_(0.0, 1.0)), labels)


def load_npz_dataset(path: Path) -> TensorDataset:
    """Load CIFAR-10 x/y arrays without allowing pickled Python objects."""
    try:
        with np.load(path, allow_pickle=False) as archive:
            images_array = archive["x"]
            labels_array = archive["y"]
    except (FileNotFoundError, KeyError, ValueError) as exc:
        raise ValueError(f"Cannot load dataset {path}: {exc}") from exc

    raw_images = np.asarray(images_array)
    integer_pixels = np.issubdtype(raw_images.dtype, np.integer)
    images = torch.from_numpy(raw_images).to(torch.float32)
    labels = torch.from_numpy(np.asarray(labels_array)).to(torch.int64)
    if images.ndim == 4 and images.shape[1:] == (32, 32, 3):
        images = images.permute(0, 3, 1, 2)
    if images.ndim != 4 or images.shape[1:] != (3, 32, 32):
        raise ValueError(
            "x must have shape [N, 32, 32, 3] or [N, 3, 32, 32], "
            f"got {images.shape}"
        )
    if labels.ndim != 1 or labels.shape[0] != images.shape[0]:
        raise ValueError(f"y must have shape [N] matching x; got {labels.shape}")
    if images.shape[0] == 0:
        raise ValueError("Dataset is empty")
    if not bool(torch.isfinite(images).all()):
        raise ValueError("x contains NaN or infinity")
    if int(labels.min()) < 0 or int(labels.max()) > 9:
        raise ValueError("y labels must be integers from 0 through 9")
    if float(images.min()) < 0.0:
        raise ValueError("x pixels must not be negative")
    maximum = float(images.max())
    if integer_pixels and maximum > 255.0:
        raise ValueError("integer x pixels must be in [0, 255]")
    if not integer_pixels and maximum > 1.0:
        raise ValueError("floating-point x pixels must be in [0, 1]")
    if integer_pixels:
        images = images / 255.0

    return TensorDataset(_normalize(images), labels.contiguous())


def get_dataset(
    *,
    dataset_npz: Path | None,
    synthetic_name: str,
    synthetic_examples: int,
    seed: int,
) -> tuple[TensorDataset, str]:
    if dataset_npz is not None:
        return load_npz_dataset(dataset_npz), f"cifar10-npz:{dataset_npz.name}"
    return (
        synthetic_dataset(synthetic_name, synthetic_examples, seed),
        f"synthetic-cifar10:{synthetic_name}",
    )
