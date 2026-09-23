#!/usr/bin/env python3
"""Reusable download and upload steps for a federated-learning client."""

from __future__ import annotations

from pathlib import Path

from hf2l.backends.base import ModelStore, PublishResult
from hf2l.core.protocol import AlgorithmSpec, ClientContext, RoundRecord, SubmissionManifest
from hf2l.hub_helpers import (
    CLIENT_CONTEXT_FILE,
    ROUND_FILE,
    SCHEMA_VERSION,
    SUBMISSION_FILE,
    artifact_hashes,
    read_json,
    require_new_directory,
    utc_now,
    validate_artifact_hashes,
    write_json,
)


def _base_model_directory(work_dir: Path, value: str) -> Path:
    """Constrain an untrusted context path to a real directory inside its workspace."""
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("Client context base_model_dir must be a relative directory")
    relative = Path(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError("Client context base_model_dir must stay inside the work directory")
    candidate = work_dir
    for part in relative.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValueError("Client context base_model_dir must not contain symlinks")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(work_dir)
    except (ValueError, FileNotFoundError, OSError) as exc:
        raise ValueError("Client context base_model_dir must be inside the work directory") from exc
    if not resolved.is_dir():
        raise ValueError("Client context base_model_dir must be a directory")
    return resolved


def _algorithm_spec(document: dict[str, object]) -> dict[str, object]:
    """Preserve canonical identity; legacy prose describes historical FedAvg."""
    if "algorithm_spec" in document:
        return AlgorithmSpec.from_dict(document["algorithm_spec"]).to_dict()
    if isinstance(document.get("algorithm"), dict):
        return AlgorithmSpec.from_dict(document["algorithm"]).to_dict()
    return AlgorithmSpec("fedavg").to_dict()


def download_client_round(
    store: ModelStore, repo_id: str, base_revision: str, work_dir: Path
) -> dict[str, object]:
    from hf2l.checkpoint_utils import discover_checkpoint

    if not isinstance(repo_id, str) or not repo_id.strip():
        raise ValueError("repo_id must be a non-empty string")
    if not isinstance(base_revision, str) or not base_revision.strip():
        raise ValueError("base_revision must be a non-empty string")
    work_dir = work_dir.resolve()
    require_new_directory(work_dir)
    resolved_base = store.resolve_revision(repo_id, base_revision)

    base_dir = work_dir / "base_model"
    store.download_snapshot(repo_id, resolved_base, base_dir)
    checkpoint = discover_checkpoint(base_dir)
    round_record = RoundRecord.from_dict(read_json(base_dir / ROUND_FILE))
    round_data = round_record.to_dict()
    if round_record.schema_version >= 2 and round_data.get("backend") != store.name:
        raise ValueError(
            f"Base model declares backend {round_data.get('backend')!r}; expected {store.name!r}"
        )
    if round_record.schema_version >= 2 or "checkpoint_files_sha256" in round_data:
        validate_artifact_hashes(
            base_dir, checkpoint.artifact_paths,
            round_data.get("checkpoint_files_sha256"), "base model",
        )
    source_round = round_record.round

    context = {
        "schema_version": SCHEMA_VERSION,
        "backend": store.name,
        "repo_id": repo_id,
        "requested_revision": base_revision,
        "base_revision": resolved_base,
        "source_round": source_round,
        "algorithm_spec": _algorithm_spec(round_data),
        "base_model_dir": "base_model",
        "downloaded_at": utc_now(),
    }
    context = ClientContext.from_dict(context).to_dict()
    write_json(work_dir / CLIENT_CONTEXT_FILE, context)
    return context


def upload_client_update(
    store: ModelStore,
    work_dir: Path,
    trained_dir: Path,
    participant: str,
    num_examples: int,
    training_metadata: dict[str, object] | None = None,
) -> tuple[PublishResult, dict[str, object]]:
    from hf2l.checkpoint_utils import discover_checkpoint, validate_compatible

    work_dir = work_dir.resolve()
    trained_dir = trained_dir.resolve()
    context_path = work_dir / CLIENT_CONTEXT_FILE
    if context_path.is_symlink():
        raise ValueError("Client context must not be a symlink")
    context = ClientContext.from_dict(read_json(context_path))
    repo_id = context.repo_id
    base_revision = context.base_revision
    context_backend = context.backend
    if context_backend != store.name:
        raise ValueError(
            f"Client context backend is {context_backend!r}, not {store.name!r}"
        )
    if not isinstance(participant, str) or not participant.strip():
        raise ValueError("Participant must not be empty")
    participant = participant.strip()
    if isinstance(num_examples, bool) or not isinstance(num_examples, int) or num_examples <= 0:
        raise ValueError("num_examples must be a positive integer")
    if training_metadata is not None and not isinstance(training_metadata, dict):
        raise ValueError("training_metadata must be a JSON object")
    if not trained_dir.is_dir():
        raise ValueError(f"Trained model directory does not exist: {trained_dir}")

    base_dir = _base_model_directory(work_dir, context.base_model_dir)
    reference = discover_checkpoint(base_dir)
    trained = discover_checkpoint(trained_dir)
    validate_compatible(reference, trained)

    source_round = context.source_round
    submission_revision = store.new_submission_revision(participant, source_round)

    submission = {
        "schema_version": SCHEMA_VERSION,
        "backend": store.name,
        "repo_id": repo_id,
        "participant": participant,
        "base_revision": base_revision,
        "source_round": source_round,
        "algorithm_spec": _algorithm_spec(context.to_dict()),
        "submission_revision": submission_revision,
        "num_examples": num_examples,
        "training": training_metadata or {},
        "checkpoint_files_sha256": artifact_hashes(trained_dir, trained.artifact_paths),
        "submitted_at": utc_now(),
    }
    submission = SubmissionManifest.from_dict(submission).to_dict()
    write_json(trained_dir / SUBMISSION_FILE, submission)
    upload_paths = [*trained.artifact_paths, SUBMISSION_FILE]
    result = store.publish_submission(
        repo_id,
        trained_dir,
        upload_paths,
        participant=participant,
        source_round=source_round,
        base_revision=base_revision,
        submission_revision=submission_revision,
    )
    return result, submission
