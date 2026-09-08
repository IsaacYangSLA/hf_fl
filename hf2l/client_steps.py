#!/usr/bin/env python3
"""Reusable download and upload steps for a federated-learning client."""

from __future__ import annotations

from pathlib import Path

from hf2l.backends.base import ModelStore, PublishResult
from hf2l.checkpoint_utils import discover_checkpoint, validate_compatible
from hf2l.hub_helpers import (
    CLIENT_CONTEXT_FILE,
    ROUND_FILE,
    SCHEMA_VERSION,
    SUBMISSION_FILE,
    artifact_hashes,
    base_revision_from,
    read_json,
    require_new_directory,
    require_supported_schema,
    utc_now,
    write_json,
)


def download_client_round(
    store: ModelStore, repo_id: str, base_revision: str, work_dir: Path
) -> dict[str, object]:
    work_dir = work_dir.resolve()
    require_new_directory(work_dir)
    resolved_base = store.resolve_revision(repo_id, base_revision)

    base_dir = work_dir / "base_model"
    store.download_snapshot(repo_id, resolved_base, base_dir)
    discover_checkpoint(base_dir)
    round_record = read_json(base_dir / ROUND_FILE)
    require_supported_schema(round_record, "base model")
    try:
        source_round = int(round_record["round"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("The base model has an invalid round number") from exc

    context = {
        "schema_version": SCHEMA_VERSION,
        "backend": store.name,
        "repo_id": repo_id,
        "requested_revision": base_revision,
        "base_revision": resolved_base,
        "source_round": source_round,
        "base_model_dir": "base_model",
        "downloaded_at": utc_now(),
    }
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
    work_dir = work_dir.resolve()
    trained_dir = trained_dir.resolve()
    context = read_json(work_dir / CLIENT_CONTEXT_FILE)
    require_supported_schema(context, "client context")
    repo_id = str(context.get("repo_id", "")).strip()
    base_revision = base_revision_from(context)
    if not repo_id or not base_revision:
        raise ValueError("The client context is missing repo_id or base_revision")
    context_backend = str(context.get("backend", "huggingface"))
    if context_backend != store.name:
        raise ValueError(
            f"Client context backend is {context_backend!r}, not {store.name!r}"
        )
    participant = participant.strip()
    if not participant:
        raise ValueError("Participant must not be empty")
    if num_examples <= 0:
        raise ValueError("num_examples must be positive")
    if not trained_dir.is_dir():
        raise ValueError(f"Trained model directory does not exist: {trained_dir}")

    base_dir = work_dir / str(context.get("base_model_dir", "base_model"))
    reference = discover_checkpoint(base_dir)
    trained = discover_checkpoint(trained_dir)
    validate_compatible(reference, trained)

    source_round = int(context["source_round"])
    submission_revision = store.new_submission_revision(participant, source_round)

    submission = {
        "schema_version": SCHEMA_VERSION,
        "backend": store.name,
        "repo_id": repo_id,
        "participant": participant,
        "base_revision": base_revision,
        "source_round": source_round,
        "submission_revision": submission_revision,
        "num_examples": num_examples,
        "training": training_metadata or {},
        "checkpoint_files_sha256": artifact_hashes(trained_dir, trained.artifact_paths),
        "submitted_at": utc_now(),
    }
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
