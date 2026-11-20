"""Trusted local adapter for the first-federation NumPy model."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
from pathlib import Path
from types import SimpleNamespace

import numpy as np

_MODEL_PATH = Path(__file__).resolve().parents[1] / "first_federation" / "model.py"
_spec = importlib.util.spec_from_file_location("hf2l_kubernetes_demo_model", _MODEL_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError("The first-federation model is missing from this image")
_model = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_model)


def train_model(base_dir: Path, output_dir: Path, options: dict) -> dict:
    """Train only on the dataset this organization mounted in its pod."""
    dataset = options.get("dataset")
    if not isinstance(dataset, str) or not dataset:
        raise ValueError("Pass --plugin-arg dataset=/data/private-data.npz")
    result = _model.train(
        base_dir, output_dir, dataset,
        steps=int(options.get("steps", 80)),
        learning_rate=float(options.get("learning_rate", 0.2)),
    )
    return {"num_examples": result["num_examples"], "metrics": result["after"]}


def _int_option(options, name, default, minimum, maximum):
    value = options.get(name, default)
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def _float_option(options, name, default, minimum, maximum):
    value = options.get(name, default)
    if type(value) not in (int, float) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be a number between {minimum} and {maximum}")
    return float(value)


def _settings(options, data_size):
    return SimpleNamespace(
        steps=_int_option(options, "steps", 80, 1, 100_000),
        checkpoint_every=_int_option(options, "checkpoint_every", 10, 1, 100_000),
        batch_size=_int_option(options, "batch_size", min(data_size, 8), 1, data_size),
        seed=_int_option(options, "seed", 2026, 0, 2**32 - 1),
        learning_rate=_float_option(options, "learning_rate", 0.2, 1e-12, 1.0),
        momentum=_float_option(options, "momentum", 0.8, 0.0, 0.999),
        noise_std=_float_option(options, "noise_std", 0.03, 0.0, 1.0),
    )


def _fresh_state(tensors, data_size, seed):
    random = np.random.Generator(np.random.PCG64(seed))
    return SimpleNamespace(
        step=0,
        position=0,
        seen=0,
        correct=0,
        loss_sum=0.0,
        input_fingerprint="0" * 64,
        random=random,
        order=random.permutation(data_size).astype(np.int64),
        weight=tensors["weight"].astype(np.float64),
        bias=tensors["bias"].astype(np.float64),
        weight_velocity=np.zeros_like(tensors["weight"], dtype=np.float64),
        bias_velocity=np.zeros_like(tensors["bias"], dtype=np.float64),
    )


_SAVE_ARRAYS = ("weight", "bias", "weight_velocity", "bias_velocity", "order")


def _save_state(state, directory):
    for name in _SAVE_ARRAYS:
        np.save(directory / f"{name}.npy", getattr(state, name), allow_pickle=False)
    progress = {
        "version": 1,
        "step": state.step,
        "position": state.position,
        "seen": state.seen,
        "correct": state.correct,
        "loss_sum": state.loss_sum,
        "input_fingerprint": state.input_fingerprint,
        "random": state.random.bit_generator.state,
    }
    (directory / "progress.json").write_text(
        json.dumps(progress, allow_nan=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _restore_state(checkpoint, tensors, data_size, settings, completed_steps):
    with (checkpoint / "progress.json").open(encoding="utf-8") as stream:
        progress = json.load(stream)
    if not isinstance(progress, dict) or progress.get("version") != 1:
        raise ValueError("Recovery checkpoint uses an unsupported trainer state version")
    step = progress.get("step")
    if type(step) is not int or step != completed_steps or not 0 <= step <= settings.steps:
        raise ValueError("Recovery checkpoint does not match the saved step")
    batches = (data_size + settings.batch_size - 1) // settings.batch_size
    completed_epochs, remaining_batches = divmod(step, batches)
    partial_examples = remaining_batches * settings.batch_size
    position = data_size if step and not remaining_batches else partial_examples
    seen = completed_epochs * data_size + partial_examples
    correct, loss_sum = progress.get("correct"), progress.get("loss_sum")
    input_fingerprint = progress.get("input_fingerprint")
    if (
        type(progress.get("position")) is not int
        or progress["position"] != position
        or type(progress.get("seen")) is not int
        or progress["seen"] != seen
        or type(correct) is not int
        or not 0 <= correct <= seen
        or type(loss_sum) not in (int, float)
        or not math.isfinite(loss_sum)
        or loss_sum < 0
        or not isinstance(input_fingerprint, str)
        or len(input_fingerprint) != 64
        or any(c not in "0123456789abcdef" for c in input_fingerprint)
    ):
        raise ValueError("Recovery checkpoint contains invalid training progress")
    random = np.random.Generator(np.random.PCG64())
    try:
        random.bit_generator.state = progress["random"]
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise ValueError("Recovery checkpoint contains invalid random state") from exc
    shapes = {
        "weight": tensors["weight"].shape,
        "bias": tensors["bias"].shape,
        "weight_velocity": tensors["weight"].shape,
        "bias_velocity": tensors["bias"].shape,
        "order": (data_size,),
    }
    arrays = {}
    for name in _SAVE_ARRAYS:
        value = np.load(checkpoint / f"{name}.npy", allow_pickle=False, mmap_mode="r")
        dtype = np.int64 if name == "order" else np.float64
        if not isinstance(value, np.ndarray) or value.shape != shapes[name] or value.dtype != dtype:
            raise ValueError(f"Recovery checkpoint contains invalid {name}")
        if not np.isfinite(value).all():
            raise ValueError(f"Recovery checkpoint contains non-finite {name}")
        arrays[name] = value.copy()
    if not np.array_equal(np.sort(arrays["order"]), np.arange(data_size)):
        raise ValueError("Recovery checkpoint does not contain a valid input permutation")
    return SimpleNamespace(
        step=step,
        position=position,
        seen=seen,
        correct=correct,
        loss_sum=loss_sum,
        input_fingerprint=input_fingerprint,
        random=random,
        **arrays,
    )


def _training_step(state, features, labels, settings):
    if state.position == len(labels):
        state.order = state.random.permutation(len(labels)).astype(np.int64)
        state.position = 0
    end = min(state.position + settings.batch_size, len(labels))
    indices = state.order[state.position:end]
    batch_labels = labels[indices]
    inputs = features[indices] + state.random.normal(0, settings.noise_std, (len(indices), 2))
    logits = inputs @ state.weight + state.bias
    logits -= logits.max(axis=1, keepdims=True)
    exp_logits = np.exp(logits)
    sums = exp_logits.sum(axis=1, keepdims=True)
    delta = exp_logits / sums
    rows = np.arange(len(indices))
    state.loss_sum += float((np.log(sums[:, 0]) - logits[rows, batch_labels]).sum())
    state.correct += int(np.count_nonzero(logits.argmax(axis=1) == batch_labels))
    state.input_fingerprint = hashlib.sha256(
        bytes.fromhex(state.input_fingerprint)
        + indices.astype("<i8", copy=False).tobytes()
        + inputs.astype("<f8", copy=False).tobytes()
    ).hexdigest()
    delta[rows, batch_labels] -= 1
    delta /= len(indices)
    state.weight_velocity *= settings.momentum
    state.weight_velocity += inputs.T @ delta
    state.bias_velocity *= settings.momentum
    state.bias_velocity += delta.sum(axis=0)
    state.weight -= settings.learning_rate * state.weight_velocity
    state.bias -= settings.learning_rate * state.bias_velocity
    if not np.isfinite(state.weight).all() or not np.isfinite(state.bias).all():
        raise ValueError("Training produced non-finite parameters")
    state.seen += len(indices)
    state.position = end
    state.step += 1


def train_recoverable(base_dir: Path, output_dir: Path, options: dict, context) -> dict:
    """Train with synchronous mini-batches and save complete update boundaries."""
    dataset = options.get("dataset")
    if not isinstance(dataset, str) or not dataset:
        raise ValueError("Pass --plugin-arg dataset=/data/private-data.npz")
    source, destination = base_dir.resolve(), output_dir.resolve()
    if destination == source or source in destination.parents:
        raise ValueError("Training output must be outside the input model directory")
    tensors, config = _model.load_model(source)
    features, labels = _model.load_data(dataset)
    settings = _settings(options, len(labels))
    features = features.astype(np.float64)
    if context.checkpoint_dir is None:
        state = _fresh_state(tensors, len(labels), settings.seed)
        context.save(0, lambda directory: _save_state(state, directory))
    else:
        state = _restore_state(
            context.checkpoint_dir, tensors, len(labels), settings, context.completed_steps,
        )

    while True:
        if context.pause_requested():
            if context.last_saved_step != state.step:
                context.save(state.step, lambda directory: _save_state(state, directory))
            context.pause()
        if state.step == settings.steps:
            break
        _training_step(state, features, labels, settings)
        if state.step % settings.checkpoint_every == 0 or state.step == settings.steps:
            context.save(state.step, lambda directory: _save_state(state, directory))

    trained = {"weight": state.weight.astype(np.float32), "bias": state.bias.astype(np.float32)}
    _model.write_model(destination, trained, config)
    metrics = _model.metrics(trained, features, labels)
    metrics["training_accuracy"] = state.correct / state.seen
    metrics["training_cross_entropy"] = state.loss_sum / state.seen
    return {"num_examples": len(labels), "metrics": metrics}
