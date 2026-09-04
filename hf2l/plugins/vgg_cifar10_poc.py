#!/usr/bin/env python3
"""VGG initialization, CIFAR-10 training, and evaluation plugin for the POC."""

from __future__ import annotations

import random
import shutil
import textwrap
from pathlib import Path
from typing import Any

import numpy as np
import torch

from hf2l.data_utils import stable_seed
from examples.cifar10_data import get_dataset
from examples.vgg_model import VGG
from hf2l.training import choose_device, evaluate, train


def _integer(options: dict[str, Any], name: str, default: int) -> int:
    value = int(options.get(name, default))
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _floating(options: dict[str, Any], name: str, default: float) -> float:
    value = float(options.get(name, default))
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _dropout(options: dict[str, Any]) -> float:
    value = float(options.get("dropout", 0.2))
    if not 0.0 <= value < 1.0:
        raise ValueError("dropout must be in [0, 1)")
    return value


def initialize_model(output_dir: Path, options: dict[str, Any]) -> dict[str, Any]:
    seed = int(options.get("seed", 20260903))
    repo_id = str(options.get("repo_id", "OWNER_OR_ORG/model"))
    width_multiplier = _floating(options, "width_multiplier", 0.25)
    dropout = _dropout(options)
    torch.manual_seed(seed)
    VGG(
        num_classes=10,
        width_multiplier=width_multiplier,
        dropout=dropout,
    ).save_pretrained(output_dir)
    shutil.copy2(
        Path(__file__).resolve().parents[2] / "examples" / "vgg_model.py",
        output_dir / "vgg_model.py",
    )
    (output_dir / "README.md").write_text(
        textwrap.dedent(
            f"""\
            ---
            library_name: pytorch
            tags:
            - pytorch
            - federated-learning
            - vgg
            - cifar10
            ---

            # VGG CIFAR-10 federated learning proof of concept (POC)

            This VGG-11-style checkpoint for `{repo_id}` classifies
            `[N, 3, 32, 32]` RGB images into the ten CIFAR-10 classes. Its width
            multiplier is `{width_multiplier}`. The generic client and owner
            scripts transport, validate, and aggregate it without model-specific
            changes.

            This educational workflow does not provide secure aggregation,
            differential privacy, authentication, or poisoning defenses.
            """
        ),
        encoding="utf-8",
    )
    return {
        "model": "VGG-11",
        "dataset": "CIFAR-10",
        "num_classes": 10,
        "width_multiplier": width_multiplier,
        "dropout": dropout,
        "seed": seed,
    }


def train_model(base_dir: Path, output_dir: Path, options: dict[str, Any]) -> dict[str, Any]:
    participant = str(options.get("participant", "client"))
    seed = int(options.get("seed", 20260903))
    epochs = _integer(options, "epochs", 5)
    batch_size = _integer(options, "batch_size", 64)
    learning_rate = _floating(options, "learning_rate", 0.01)
    synthetic_examples = _integer(options, "synthetic_examples", 1000)
    dataset_value = options.get("dataset_npz")
    dataset_npz = Path(str(dataset_value)).expanduser() if dataset_value else None
    device_name = str(options.get("device", "auto"))

    local_seed = stable_seed(participant, seed)
    random.seed(local_seed)
    np.random.seed(local_seed % (2**32))
    torch.manual_seed(local_seed)
    dataset, dataset_description = get_dataset(
        dataset_npz=dataset_npz,
        synthetic_name=participant,
        synthetic_examples=synthetic_examples,
        seed=seed,
    )
    device = choose_device(device_name)
    model = VGG.from_pretrained(base_dir)
    metrics = train(
        model,
        dataset,
        epochs=epochs,
        batch_size=batch_size,
        learning_rate=learning_rate,
        seed=local_seed,
        device=device,
    )
    model.to("cpu")
    model.save_pretrained(output_dir)
    return {
        "num_examples": len(dataset),
        "dataset": dataset_description,
        "hyperparameters": {
            "epochs": epochs,
            "batch_size": batch_size,
            "learning_rate": learning_rate,
            "seed": seed,
        },
        "metrics": {
            "local_loss": metrics.final_loss,
            "local_accuracy": metrics.accuracy,
        },
    }


def evaluate_model(model_dir: Path, options: dict[str, Any]) -> dict[str, Any]:
    dataset_value = options.get("eval_npz")
    dataset_npz = Path(str(dataset_value)).expanduser() if dataset_value else None
    eval_examples = _integer(options, "eval_examples", 1000)
    eval_seed = int(options.get("eval_seed", 982451653))
    batch_size = _integer(options, "batch_size", 128)
    device = choose_device(str(options.get("device", "auto")))
    validation_data, description = get_dataset(
        dataset_npz=dataset_npz,
        synthetic_name="owner-common-validation",
        synthetic_examples=eval_examples,
        seed=eval_seed,
    )
    model = VGG.from_pretrained(model_dir)
    model.to(device)
    accuracy = evaluate(model, validation_data, batch_size, device)
    return {"dataset": description, "accuracy": accuracy}
