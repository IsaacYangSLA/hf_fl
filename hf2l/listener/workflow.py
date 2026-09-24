"""Backend-neutral, resumable stages for an individual training listener."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Any

from hf2l.checkpoint.format import discover
from hf2l.checkpoint.layout import CheckpointLayout, validate_compatible
from hf2l.client_steps import download_client_round, upload_client_update
from hf2l.common.fs import artifact_hashes, read_json, validate_artifact_hashes, write_json
from hf2l.core.ports import ModelStore
from hf2l.core.protocol import (
    CLIENT_CONTEXT_FILE, ROUND_FILE, AlgorithmSpec, ClientContext, RoundRecord,
    SubmissionManifest,
)


_BASE_HASHES = "listener_base_files_sha256"


def _validate_base(work_dir: Path) -> tuple[ClientContext, CheckpointLayout, dict[str, str]]:
    """Recheck a saved download before allowing any resumable stage to use it."""
    context_path = work_dir / CLIENT_CONTEXT_FILE
    if context_path.is_symlink():
        raise ValueError("Client context must not be a symlink")
    context = ClientContext.from_dict(read_json(context_path))
    if context.base_model_dir != "base_model":
        raise ValueError("Listener context must use the downloaded base_model directory")
    base_dir = work_dir / "base_model"
    if base_dir.is_symlink() or not base_dir.is_dir():
        raise ValueError("Listener base_model must be a real directory")
    if (base_dir / ROUND_FILE).is_symlink():
        raise ValueError("Listener base round must not be a symlink")
    record = RoundRecord.from_dict(read_json(base_dir / ROUND_FILE))
    round_data = record.to_dict()
    if record.round != context.source_round:
        raise ValueError("Saved base round does not match the listener context")
    if record.schema_version >= 2 and round_data.get("backend") != context.backend:
        raise ValueError("Saved base backend does not match the listener context")
    algorithm = record.algorithm_spec
    if algorithm is None and isinstance(round_data.get("algorithm"), dict):
        algorithm = record.algorithm
    expected_algorithm = (algorithm or AlgorithmSpec("fedavg")).to_dict()
    context_algorithm = (context.algorithm_spec or AlgorithmSpec("fedavg")).to_dict()
    if context_algorithm != expected_algorithm:
        raise ValueError("Saved base algorithm does not match the listener context")
    checkpoint = discover(base_dir)
    checkpoint_hashes = artifact_hashes(base_dir, checkpoint.artifact_paths)
    if record.schema_version >= 2 or "checkpoint_files_sha256" in round_data:
        if round_data.get("checkpoint_files_sha256") != checkpoint_hashes:
            raise ValueError("Checkpoint checksum mismatch in saved listener base")
    hashes = {**checkpoint_hashes, **artifact_hashes(base_dir, [ROUND_FILE])}
    expected_hashes = context.to_dict().get(_BASE_HASHES)
    if expected_hashes is not None and expected_hashes != hashes:
        raise ValueError("Checkpoint checksum mismatch in saved listener base files")
    return context, checkpoint, hashes


def _json_metadata(value: object) -> dict[str, Any]:
    """Validate metadata without silently coercing keys, tuples, or NaN values."""
    if not isinstance(value, dict):
        raise ValueError("Training metadata must be a JSON object")

    def check(item: object) -> None:
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise ValueError("Training metadata JSON objects must have string keys")
            for nested in item.values():
                check(nested)
        elif isinstance(item, list):
            for nested in item:
                check(nested)
        elif item is not None and type(item) not in (str, int, float, bool):
            raise ValueError("Training metadata must contain only JSON values")

    check(value)
    # Round-tripping also makes the returned metadata independent of objects held
    # by the trusted plugin and rejects non-finite floating-point values.
    return json.loads(json.dumps(value, allow_nan=False))


def _example_count(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("train_model(...) must return a positive integer num_examples")
    return value


def _validate_submission_metadata(
    work_dir: Path, participant: str, num_examples: int, training: dict[str, Any],
) -> None:
    """Apply the publication protocol's bounds before recording training success."""
    context = ClientContext.from_dict(read_json(work_dir / CLIENT_CONTEXT_FILE))
    SubmissionManifest.from_dict({
        "schema_version": context.schema_version,
        "backend": context.backend,
        "repo_id": context.repo_id,
        "base_revision": context.base_revision,
        "source_round": context.source_round,
        "participant": participant,
        "num_examples": num_examples,
        "training": training,
    })


def download_round(
    store: ModelStore, repo_id: str, revision: str, work_dir: Path,
) -> dict[str, object]:
    """Download the exact immutable revision scheduled by the listener."""
    context = download_client_round(store, repo_id, revision, work_dir)
    if context["base_revision"] != revision:
        raise ValueError("Listener download rebound the scheduled immutable revision")
    # Keep a local integrity baseline even for legacy rounds without published
    # hashes. Including the round document also detects changes to its metadata.
    work_dir = work_dir.resolve()
    _, _, hashes = _validate_base(work_dir)
    context[_BASE_HASHES] = hashes
    write_json(work_dir / CLIENT_CONTEXT_FILE, context)
    return context


def train_round(
    train_model: Callable[[Path, Path, dict[str, Any]], object],
    options: dict[str, Any],
    participant: str,
    work_dir: Path,
) -> dict[str, Any]:
    """Train and validate once, returning metadata the controller can persist."""
    if not isinstance(participant, str) or not participant.strip():
        raise ValueError("Participant must not be empty")
    work_dir = work_dir.resolve()
    base_dir = work_dir / "base_model"
    trained_dir = work_dir / "trained_model"
    context, reference, base_hashes = _validate_base(work_dir)
    training_options = copy.deepcopy(options)
    training_options["participant"] = participant.strip()
    metadata = _json_metadata(train_model(base_dir, trained_dir, training_options))
    saved_context, _, saved_hashes = _validate_base(work_dir)
    if saved_context.to_dict() != context.to_dict() or saved_hashes != base_hashes:
        raise ValueError("Training modified the saved base model or client context")
    num_examples = _example_count(metadata.pop("num_examples", None))
    _validate_submission_metadata(work_dir, participant.strip(), num_examples, metadata)
    trained = discover(trained_dir)
    validate_compatible(reference, trained)
    return {
        "num_examples": num_examples,
        "training": metadata,
        "checkpoint_files_sha256": artifact_hashes(trained_dir, trained.artifact_paths),
    }


def validate_submission(work_dir: Path, participant: str, metadata: dict[str, Any]) -> None:
    """Validate local inputs before the controller records a publishing attempt."""
    metadata = _json_metadata(metadata)
    num_examples = _example_count(metadata.get("num_examples"))
    training = _json_metadata(metadata.get("training"))
    work_dir = work_dir.resolve()
    _, reference, _ = _validate_base(work_dir)
    _validate_submission_metadata(work_dir, participant, num_examples, training)
    trained_dir = work_dir / "trained_model"
    trained = discover(trained_dir)
    validate_compatible(reference, trained)
    validate_artifact_hashes(
        trained_dir, trained.artifact_paths,
        metadata.get("checkpoint_files_sha256"), "saved listener training output",
    )


def submit_round(
    store: ModelStore, work_dir: Path, participant: str, metadata: dict[str, Any],
) -> dict[str, Any]:
    """Submit validated saved training output without rerunning the plugin."""
    metadata = _json_metadata(metadata)
    validate_submission(work_dir, participant, metadata)
    work_dir = work_dir.resolve()
    result, _ = upload_client_update(
        store, work_dir, work_dir / "trained_model", participant,
        metadata["num_examples"], metadata["training"],
    )
    return asdict(result)
