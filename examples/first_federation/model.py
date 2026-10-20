#!/usr/bin/env python3
"""Tiny, framework-independent local trainer for the first federation example.

Every checkpoint contains the same config.json and two float32 SafeTensors.
This program never contacts the network or sends an organization's dataset.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import sys
import zipfile

import numpy as np
from safetensors import SafetensorError
from safetensors.numpy import load_file, save_file

CONFIG = {
    "architectures": ["FirstFederationLinearClassifier"],
    "model_type": "first_federation_linear",
    "num_features": 2,
    "num_labels": 2,
    "feature_order": ["feature_0", "feature_1"],
    "label_order": ["negative", "positive"],
    "preprocessing": "identity",
    "tensor_dtype": "float32",
}
TENSOR_SHAPES = {"weight": (2, 2), "bias": (2,)}
CONFIG_BYTES = (json.dumps(CONFIG, indent=2, sort_keys=True) + "\n").encode()


def checked_path(value: str | Path) -> Path:
    """Reject symlinks, including existing ancestors, before reading/writing."""
    path = Path(value).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError(f"Symlinks are not supported: {path}")
    return path


def checkpoint_digest(directory: Path) -> str:
    return hashlib.sha256((directory / "model.safetensors").read_bytes()).hexdigest()


def load_model(directory: str | Path) -> tuple[dict[str, np.ndarray], bytes]:
    directory = checked_path(directory)
    config_path = checked_path(directory / "config.json")
    weights_path = checked_path(directory / "model.safetensors")
    config_bytes = config_path.read_bytes()
    if json.loads(config_bytes) != CONFIG:
        raise ValueError("Model configuration does not match the shared model agreement")
    tensors = load_file(str(weights_path))
    if set(tensors) != set(TENSOR_SHAPES):
        raise ValueError("Checkpoint must contain exactly weight and bias tensors")
    for name, shape in TENSOR_SHAPES.items():
        value = tensors[name]
        if value.shape != shape or value.dtype != np.float32:
            raise ValueError(f"{name} must have shape {shape} and dtype float32")
        if not np.isfinite(value).all():
            raise ValueError(f"{name} contains non-finite values")
    return tensors, config_bytes


def write_model(directory: str | Path, tensors: dict[str, np.ndarray], config: bytes) -> Path:
    directory = checked_path(directory)
    # mkdir's exclusive creation prevents accidentally overwriting a base or result.
    directory.mkdir(parents=True, exist_ok=False)
    try:
        (directory / "config.json").write_bytes(config)
        save_file(tensors, str(directory / "model.safetensors"))
    except Exception:
        for name in ("config.json", "model.safetensors"):
            (directory / name).unlink(missing_ok=True)
        directory.rmdir()
        raise
    return directory


def initialize(output: str | Path) -> dict:
    tensors = {name: np.zeros(shape, dtype=np.float32) for name, shape in TENSOR_SHAPES.items()}
    directory = write_model(output, tensors, CONFIG_BYTES)
    return {"model": str(directory), "checkpoint_sha256": checkpoint_digest(directory)}


def generate_data(output: str | Path, examples: int, seed: int) -> dict:
    if examples < 2 or examples > 1_000_000:
        raise ValueError("examples must be between 2 and 1000000")
    if seed < 0:
        raise ValueError("seed must be non-negative")
    rng = np.random.default_rng(seed)
    # Balanced labels and a common synthetic feature space; each organization
    # generates its own independent draws, and retains the resulting file locally.
    labels = (np.arange(examples) % 2).astype(np.int64)
    rng.shuffle(labels)
    direction = np.array([1.2, -0.9], dtype=np.float32)
    features = (rng.normal(0, 0.65, (examples, 2)) +
                (2 * labels - 1)[:, None] * direction).astype(np.float32)
    destination = checked_path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as handle:
        np.savez(handle, features=features, labels=labels)
    return {"dataset": str(destination), "num_examples": examples, "seed": seed}


def load_data(dataset: str | Path) -> tuple[np.ndarray, np.ndarray]:
    dataset = checked_path(dataset)
    with np.load(dataset, allow_pickle=False) as data:
        if set(data.files) != {"features", "labels"}:
            raise ValueError("Dataset must contain exactly features and labels")
        features, labels = data["features"], data["labels"]
    if (features.ndim != 2 or features.shape[1:] != (2,) or
            features.dtype != np.float32 or not np.isfinite(features).all()):
        raise ValueError("features must be finite float32 with shape (N, 2)")
    if (labels.dtype != np.int64 or labels.shape != (len(features),) or
            len(labels) < 2 or not np.isin(labels, [0, 1]).all()):
        raise ValueError("labels must be int64 with shape (N,), N >= 2, and values 0 or 1")
    return features, labels


def metrics(tensors: dict, features: np.ndarray, labels: np.ndarray) -> dict:
    logits = features.astype(np.float64) @ tensors["weight"] + tensors["bias"]
    logits -= logits.max(axis=1, keepdims=True)
    log_probabilities = logits - np.log(np.exp(logits).sum(axis=1, keepdims=True))
    return {
        "num_examples": len(labels),
        "accuracy": float((logits.argmax(axis=1) == labels).mean()),
        "cross_entropy": float(-log_probabilities[np.arange(len(labels)), labels].mean()),
    }


def train(input_dir: str | Path, output: str | Path, dataset: str | Path,
          steps: int = 80, learning_rate: float = 0.2) -> dict:
    if not 1 <= steps <= 100_000:
        raise ValueError("steps must be between 1 and 100000")
    if not math.isfinite(learning_rate) or not 0 < learning_rate <= 1:
        raise ValueError("learning-rate must be finite, positive, and at most 1")
    source, destination = checked_path(input_dir), checked_path(output)
    # Avoid writing any output inside the immutable downloaded checkpoint.
    if destination == source or source in destination.parents:
        raise ValueError("Training output must be outside the input model directory")
    tensors, config_bytes = load_model(source)
    features, labels = load_data(dataset)
    before = metrics(tensors, features, labels)
    # Float64 arithmetic avoids platform-sensitive low-precision accumulation;
    # outputs remain float32 so every participant shares a tensor layout.
    x = features.astype(np.float64)
    weight, bias = tensors["weight"].astype(np.float64), tensors["bias"].astype(np.float64)
    targets = np.eye(2)[labels]
    for _ in range(steps):
        logits = x @ weight + bias
        logits -= logits.max(axis=1, keepdims=True)
        probabilities = np.exp(logits)
        probabilities /= probabilities.sum(axis=1, keepdims=True)
        delta = (probabilities - targets) / len(labels)
        weight -= learning_rate * (x.T @ delta)
        bias -= learning_rate * delta.sum(axis=0)
    trained = {"weight": weight.astype(np.float32), "bias": bias.astype(np.float32)}
    if any(not np.isfinite(value).all() for value in trained.values()):
        raise ValueError("Training produced non-finite parameters")
    directory = write_model(destination, trained, config_bytes)
    return {
        "model": str(directory),
        "num_examples": len(labels),
        "steps": steps,
        "learning_rate": learning_rate,
        "before": before,
        "after": metrics(trained, features, labels),
        "checkpoint_sha256": checkpoint_digest(directory),
    }


def evaluate(model: str | Path, dataset: str | Path) -> dict:
    tensors, _ = load_model(model)
    features, labels = load_data(dataset)
    return {**metrics(tensors, features, labels), "checkpoint_sha256": checkpoint_digest(Path(model))}


def evaluate_model(model_dir: Path, options: dict) -> dict:
    """HF2L owner evaluation hook; runs before the aggregate is published."""
    if set(options) != {"dataset"} or not isinstance(options["dataset"], str):
        raise ValueError("Evaluation requires exactly --plugin-arg dataset=LOCAL.npz")
    return evaluate(model_dir, options["dataset"])


def verify_aggregate(model: str | Path, alice: str | Path, bob: str | Path,
                     alice_examples: int = 64, bob_examples: int = 96) -> dict:
    if min(alice_examples, bob_examples) <= 0:
        raise ValueError("Participant example counts must be positive")
    aggregate, config = load_model(model)
    alice_tensors, alice_config = load_model(alice)
    bob_tensors, bob_config = load_model(bob)
    if config != alice_config or config != bob_config:
        raise ValueError("Participant and aggregate configurations differ")
    total = alice_examples + bob_examples
    coefficients = [alice_examples / total, bob_examples / total]
    max_error = 0.0
    for name in TENSOR_SHAPES:
        reference = (alice_tensors[name].astype(np.float64) * coefficients[0] +
                     bob_tensors[name].astype(np.float64) * coefficients[1]).astype(np.float32)
        max_error = max(max_error, float(np.abs(aggregate[name] - reference).max()))
        if not np.allclose(aggregate[name], reference, rtol=1e-6, atol=1e-7):
            raise ValueError(f"Aggregate {name} differs from independently calculated FedAvg")
    return {"weights": coefficients, "max_abs_error": max_error,
            "checkpoint_sha256": checkpoint_digest(Path(model))}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create the common initial checkpoint")
    init.add_argument("--output", required=True, type=Path)
    data = commands.add_parser("data", help="Generate private synthetic local data")
    data.add_argument("--output", required=True, type=Path)
    data.add_argument("--examples", required=True, type=int)
    data.add_argument("--seed", required=True, type=int)
    training = commands.add_parser("train", help="Train locally from an immutable downloaded base")
    training.add_argument("--input", dest="input_dir", required=True, type=Path)
    training.add_argument("--output", required=True, type=Path)
    training.add_argument("--dataset", required=True, type=Path)
    training.add_argument("--steps", type=int, default=80)
    training.add_argument("--learning-rate", type=float, default=0.2)
    evaluation = commands.add_parser("evaluate", help="Evaluate on a local held-out dataset")
    evaluation.add_argument("--model", required=True, type=Path)
    evaluation.add_argument("--dataset", required=True, type=Path)
    verification = commands.add_parser("verify-aggregate", help="Independently check weighted FedAvg")
    for name in ("model", "alice", "bob"):
        verification.add_argument("--" + name, required=True, type=Path)
    verification.add_argument("--alice-examples", type=int, default=64)
    verification.add_argument("--bob-examples", type=int, default=96)
    args = vars(parser.parse_args(argv))
    command = args.pop("command")
    operations = {"init": initialize, "data": generate_data, "train": train,
                  "evaluate": evaluate, "verify-aggregate": verify_aggregate}
    try:
        result = operations[command](**args)
    except (OSError, ValueError, TypeError, OverflowError, EOFError,
            zipfile.BadZipFile, SafetensorError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
