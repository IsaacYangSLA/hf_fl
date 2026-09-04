#!/usr/bin/env python3
"""LeNet initialization, training, and evaluation plugin used by the POC."""

from __future__ import annotations

import random
import shutil
import textwrap
from pathlib import Path
from typing import Any

import numpy as np
import torch

from hf2l.data_utils import stable_seed
from examples.lenet_model import LeNet
from examples.mnist_data import get_dataset
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


def initialize_model(output_dir: Path, options: dict[str, Any]) -> dict[str, Any]:
    seed = int(options.get("seed", 20260903))
    repo_id = str(options.get("repo_id", "OWNER_OR_ORG/model"))
    torch.manual_seed(seed)
    LeNet(num_classes=10).save_pretrained(output_dir)
    shutil.copy2(
        Path(__file__).resolve().parents[2] / "examples" / "lenet_model.py",
        output_dir / "lenet_model.py",
    )
    (output_dir / "README.md").write_text(
        textwrap.dedent(
            f"""\
            ---
            library_name: pytorch
            tags:
            - pytorch
            - federated-learning
            - lenet
            ---

            # LeNet FedAvg proof of concept (POC)

            This is the example LeNet checkpoint for `{repo_id}`. It classifies
            `[N, 1, 28, 28]` grayscale images into ten classes. The repository is
            updated by validated FedAvg commits; client PRs are not merged directly.

            This educational workflow does not provide secure aggregation,
            differential privacy, authentication, or poisoning defenses.
            """
        ),
        encoding="utf-8",
    )
    return {"model": "LeNet", "num_classes": 10, "seed": seed}


def train_model(base_dir: Path, output_dir: Path, options: dict[str, Any]) -> dict[str, Any]:
    participant = str(options.get("participant", "client"))
    seed = int(options.get("seed", 20260903))
    epochs = _integer(options, "epochs", 8)
    batch_size = _integer(options, "batch_size", 64)
    learning_rate = _floating(options, "learning_rate", 0.2)
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
    model = LeNet.from_pretrained(base_dir)
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
    model = LeNet.from_pretrained(model_dir)
    model.to(device)
    accuracy = evaluate(model, validation_data, batch_size, device)
    return {"dataset": description, "accuracy": accuracy}
