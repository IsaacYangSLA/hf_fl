#!/usr/bin/env python3
"""Reusable download and upload steps for a federated-learning client."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from huggingface_hub import CommitOperationAdd

from hf2l.checkpoint_utils import discover_checkpoint, validate_compatible
from hf2l.hub_helpers import (
    CLIENT_CONTEXT_FILE,
    ROUND_FILE,
    SCHEMA_VERSION,
    SUBMISSION_FILE,
    read_json,
    require_new_directory,
    utc_now,
    write_json,
)


def download_client_round(
    api: Any, repo_id: str, base_revision: str, work_dir: Path
) -> dict[str, Any]:
    work_dir = work_dir.resolve()
    require_new_directory(work_dir)
    info = api.model_info(repo_id, revision=base_revision)
    base_commit = info.sha
    if not base_commit:
        raise RuntimeError("Hugging Face did not return the base commit SHA")

    base_dir = work_dir / "base_model"
    api.snapshot_download(
        repo_id=repo_id,
        repo_type="model",
        revision=base_commit,
        local_dir=base_dir,
    )
    discover_checkpoint(base_dir)
    round_record = read_json(base_dir / ROUND_FILE)
    if round_record.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("The base model uses an unsupported FedAvg schema")
    try:
        source_round = int(round_record["round"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("The base model has an invalid round number") from exc

    context = {
        "schema_version": SCHEMA_VERSION,
        "repo_id": repo_id,
        "requested_revision": base_revision,
        "base_commit": base_commit,
        "source_round": source_round,
        "base_model_dir": "base_model",
        "downloaded_at": utc_now(),
    }
    write_json(work_dir / CLIENT_CONTEXT_FILE, context)
    return context


def upload_client_update(
    api: Any,
    work_dir: Path,
    trained_dir: Path,
    participant: str,
    num_examples: int,
    training_metadata: dict[str, Any] | None = None,
) -> tuple[Any, dict[str, Any]]:
    work_dir = work_dir.resolve()
    trained_dir = trained_dir.resolve()
    context = read_json(work_dir / CLIENT_CONTEXT_FILE)
    if context.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("The client context uses an unsupported schema")
    repo_id = str(context.get("repo_id", "")).strip()
    base_commit = str(context.get("base_commit", "")).strip()
    if not repo_id or not base_commit:
        raise ValueError("The client context is missing repo_id or base_commit")
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

    submission = {
        "schema_version": SCHEMA_VERSION,
        "repo_id": repo_id,
        "participant": participant,
        "base_commit": base_commit,
        "source_round": int(context["source_round"]),
        "num_examples": num_examples,
        "training": training_metadata or {},
        "submitted_at": utc_now(),
    }
    write_json(trained_dir / SUBMISSION_FILE, submission)
    upload_paths = [*trained.artifact_paths, SUBMISSION_FILE]
    operations = [
        CommitOperationAdd(path_in_repo=path, path_or_fileobj=trained_dir / path)
        for path in upload_paths
    ]
    result = api.create_commit(
        repo_id=repo_id,
        repo_type="model",
        operations=operations,
        commit_message=(
            f"FedAvg client update from {participant} for round {submission['source_round']}"
        ),
        parent_commit=base_commit,
        create_pr=True,
    )
    if not result.pr_revision:
        raise RuntimeError("The Hub did not return a PR revision")
    return result, submission
