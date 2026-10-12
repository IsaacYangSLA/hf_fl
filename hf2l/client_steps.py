#!/usr/bin/env python3
"""Reusable download and upload steps for a federated-learning client."""

from __future__ import annotations

from pathlib import Path
import tempfile

from hf2l.backends.base import ModelStore, PublishResult
from hf2l.core.protocol import AlgorithmSpec, ClientContext, MAX_CYCLIC_PARENTS, RoundRecord, SubmissionManifest
from hf2l.core.json_values import json_values_equal
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


def _round_snapshot(store: ModelStore, repo_id: str, folder: Path) -> dict[str, object]:
    from hf2l.checkpoint_utils import discover_checkpoint

    if (folder / SUBMISSION_FILE).exists():
        raise ValueError("Selected snapshot is a submission; choose the cyclic workflow and a submission source explicitly")
    document = RoundRecord.from_dict(read_json(folder / ROUND_FILE)).to_dict()
    if document.get("repo_id", repo_id) != repo_id:
        raise ValueError("Global root belongs to a different repository")
    if (document.get("schema_version", 1) >= 2 or "backend" in document) and document.get("backend") != store.name:
        raise ValueError(f"Base model declares backend {document.get('backend')!r}; expected {store.name!r}")
    checkpoint = discover_checkpoint(folder)
    if document["schema_version"] >= 2 or "checkpoint_files_sha256" in document:
        validate_artifact_hashes(folder, checkpoint.artifact_paths,
                                 document.get("checkpoint_files_sha256"), "base model")
    return document


def _immutable_revision(store: ModelStore, repo_id: str, revision: str) -> None:
    if store.resolve_revision(repo_id, revision) != revision:
        raise ValueError("Cyclic lineage must use immutable resolved revisions")


def _submission_snapshot(
    store: ModelStore, repo_id: str, revision: str, folder: Path, participant: str,
) -> dict[str, object]:
    from hf2l.checkpoint_utils import discover_checkpoint

    manifest = SubmissionManifest.from_dict(read_json(folder / SUBMISSION_FILE))
    document = manifest.to_dict()
    if manifest.repo_id != repo_id:
        raise ValueError("Cyclic predecessor belongs to a different repository")
    if manifest.backend != store.name:
        raise ValueError("Cyclic predecessor declares a different backend")
    if manifest.participant != participant:
        raise ValueError("Cyclic predecessor participant does not match source_participant")
    checkpoint = discover_checkpoint(folder)
    # Handoffs require integrity evidence even for schema-1 predecessor manifests.
    validate_artifact_hashes(folder, checkpoint.artifact_paths,
                             document.get("checkpoint_files_sha256"), "cyclic predecessor")
    _immutable_revision(store, repo_id, manifest.base_revision)
    if manifest.submission_revision is not None:
        if store.resolve_revision(repo_id, manifest.submission_revision) != revision:
            raise ValueError("Cyclic predecessor submission_revision does not identify the selected snapshot")
    if getattr(getattr(store, "capabilities", None), "binds_participants", False):
        candidates = store.explicit_submissions(repo_id, [revision])
        if len(candidates) != 1 or candidates[0].participant != participant:
            raise ValueError("Cyclic predecessor participant differs from its authenticated storage identity")
        if store.resolve_revision(repo_id, candidates[0].revision) != revision:
            raise ValueError("Cyclic predecessor storage identity resolves to a different snapshot")
    if getattr(store, "supports_ancestry", False) and not store.is_descendant(repo_id, revision, manifest.base_revision):
        raise ValueError("Cyclic predecessor does not descend from its declared base")
    return document


def _cyclic_source(
    store: ModelStore, repo_id: str, revision: str, folder: Path,
    source_kind: str, source_participant: str | None,
) -> tuple[dict[str, object], dict[str, object]]:
    """Verify the complete bounded immutable ancestry before handing off a model."""
    from hf2l.checkpoint_utils import discover_checkpoint, validate_compatible

    _immutable_revision(store, repo_id, revision)
    if source_kind == "global":
        document = _round_snapshot(store, repo_id, folder)
        return document, {"root_revision": revision, "root_round": document["round"], "parents": []}

    document = _submission_snapshot(store, repo_id, revision, folder, source_participant)
    if document.get("workflow") == "cyclic":
        lineage = document["lineage"]
        root_revision, root_round = lineage["root_revision"], lineage["root_round"]
        parents = lineage["parents"]
    else:
        root_revision, root_round = document.get("base_revision", document.get("base_commit")), document["source_round"]
        parents = []
    if len(parents) >= MAX_CYCLIC_PARENTS:
        raise ValueError(f"A cyclic handoff cannot exceed {MAX_CYCLIC_PARENTS} predecessor submissions")
    if revision == root_revision or any(parent["revision"] == revision for parent in parents):
        raise ValueError("Cyclic lineage contains a cycle or duplicate revision")
    algorithm = _algorithm_spec(document)
    reference = discover_checkpoint(folder)
    with tempfile.TemporaryDirectory(prefix="hf2l-cyclic-lineage-") as temporary:
        ancestry_dir = Path(temporary)
        for index, parent in enumerate(parents):
            parent_revision = parent["revision"]
            _immutable_revision(store, repo_id, parent_revision)
            parent_dir = ancestry_dir / f"parent-{index}"
            store.download_snapshot(repo_id, parent_revision, parent_dir)
            ancestor = _submission_snapshot(store, repo_id, parent_revision, parent_dir, parent["participant"])
            expected_lineage = {"root_revision": root_revision, "root_round": root_round, "parents": parents[:index]}
            if ancestor.get("workflow") == "cyclic":
                if ancestor["lineage"] != expected_lineage:
                    raise ValueError("Cyclic predecessor lineage disagrees with its recorded ancestry")
            elif index != 0 or ancestor.get("base_revision", ancestor.get("base_commit")) != root_revision or ancestor["source_round"] != root_round:
                raise ValueError("Cyclic predecessor lineage does not lead to the declared global root")
            if not json_values_equal(_algorithm_spec(ancestor), algorithm):
                raise ValueError("Cyclic predecessor algorithm differs from its ancestry")
            validate_compatible(reference, discover_checkpoint(parent_dir))

        _immutable_revision(store, repo_id, root_revision)
        root_dir = ancestry_dir / "root"
        store.download_snapshot(repo_id, root_revision, root_dir)
        root = _round_snapshot(store, repo_id, root_dir)
        if root["round"] != root_round:
            raise ValueError("Cyclic global root round disagrees with its lineage")
        if not json_values_equal(_algorithm_spec(root), algorithm):
            raise ValueError("Cyclic predecessor algorithm differs from the global root")
        validate_compatible(reference, discover_checkpoint(root_dir))
    return document, {"root_revision": root_revision, "root_round": root_round,
                      "parents": [*parents, {"revision": revision, "participant": source_participant}]}


def add_handoff_arguments(parser) -> None:
    parser.add_argument("--workflow", choices=("fedavg", "cyclic"), default="fedavg",
                        help="Use cyclic to opt into manual sequential training handoffs")
    parser.add_argument("--source-kind", choices=("global", "submission"), default="global",
                        help="Document to validate at the selected immutable revision")
    parser.add_argument("--source-participant", help="Required expected predecessor participant for a submission source")


def download_client_round(
    store: ModelStore, repo_id: str, base_revision: str, work_dir: Path, *,
    workflow: str = "fedavg", source_kind: str = "global", source_participant: str | None = None,
) -> dict[str, object]:
    if not isinstance(repo_id, str) or not repo_id.strip():
        raise ValueError("repo_id must be a non-empty string")
    if not isinstance(base_revision, str) or not base_revision.strip():
        raise ValueError("base_revision must be a non-empty string")
    if workflow not in ("fedavg", "cyclic") or source_kind not in ("global", "submission"):
        raise ValueError("Unknown client workflow or source_kind")
    if source_kind == "submission":
        if workflow != "cyclic":
            raise ValueError("A submission source requires the explicit cyclic workflow")
        if not isinstance(source_participant, str) or not source_participant.strip() or source_participant != source_participant.strip():
            raise ValueError("A submission source requires a nonempty source_participant")
    elif source_participant is not None:
        raise ValueError("A global source does not have a source_participant")
    work_dir = work_dir.resolve()
    require_new_directory(work_dir)
    resolved_base = store.resolve_revision(repo_id, base_revision)

    base_dir = work_dir / "base_model"
    store.download_snapshot(repo_id, resolved_base, base_dir)
    lineage = None
    if workflow == "cyclic":
        round_data, lineage = _cyclic_source(store, repo_id, resolved_base, base_dir, source_kind, source_participant)
        source_round = lineage["root_round"]
    else:
        round_data = _round_snapshot(store, repo_id, base_dir)
        source_round = round_data["round"]

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
    if lineage is not None:
        context.update(workflow="cyclic", source_kind=source_kind, lineage=lineage)
        if source_participant is not None:
            context["source_participant"] = source_participant
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
    context_data = context.to_dict()
    if context_data.get("workflow") != "cyclic" and (base_dir / SUBMISSION_FILE).exists():
        raise ValueError("A submission base requires the explicit cyclic workflow")
    if context_data.get("workflow") == "cyclic":
        # Read the immutable source again: saved context and local metadata are
        # editable, so neither can be the authority for a new handoff's lineage.
        with tempfile.TemporaryDirectory(prefix="hf2l-cyclic-source-") as temporary:
            source_dir = Path(temporary) / "source"
            store.download_snapshot(repo_id, base_revision, source_dir)
            source, lineage = _cyclic_source(store, repo_id, base_revision, source_dir,
                                            context_data["source_kind"], context_data.get("source_participant"))
            if lineage != context_data["lineage"] or not json_values_equal(_algorithm_spec(source), _algorithm_spec(context_data)):
                raise ValueError("Client context lineage or algorithm differs from the immutable cyclic source")
            source_filename = SUBMISSION_FILE if context_data["source_kind"] == "submission" else ROUND_FILE
            if not json_values_equal(read_json(base_dir / source_filename), source):
                raise ValueError("Local cyclic source manifest differs from its immutable snapshot")
            source_checkpoint = discover_checkpoint(source_dir)
            validate_artifact_hashes(base_dir, source_checkpoint.artifact_paths,
                                     artifact_hashes(source_dir, source_checkpoint.artifact_paths), "local cyclic source")
    reference = discover_checkpoint(base_dir)
    trained = discover_checkpoint(trained_dir)
    validate_compatible(reference, trained)

    source_round = context.source_round
    submission = {
        "schema_version": SCHEMA_VERSION,
        "backend": store.name,
        "repo_id": repo_id,
        "participant": participant,
        "base_revision": base_revision,
        "source_round": source_round,
        "algorithm_spec": _algorithm_spec(context.to_dict()),
        "num_examples": num_examples,
        "training": training_metadata or {},
        "checkpoint_files_sha256": artifact_hashes(trained_dir, trained.artifact_paths),
    }
    if context_data.get("workflow") == "cyclic":
        submission.update(workflow="cyclic", source_kind=context_data["source_kind"], lineage=context_data["lineage"])
        if "source_participant" in context_data:
            submission["source_participant"] = context_data["source_participant"]
    # A saved manifest is the durable publication intent. Reconciliation or a
    # confirmed safe retry must reuse its revision, timestamp and exact metadata:
    # Exchange's upload-state idempotency binds metadata as well as file hashes.
    # Changing any payload after crossing this boundary requires a new work dir.
    manifest_path = trained_dir / SUBMISSION_FILE
    intent_path = work_dir / "client-publication-intent.json"
    if intent_path.is_symlink():
        raise ValueError("Client publication intent must not be a symlink")
    if manifest_path.is_symlink():
        raise ValueError("Submission publication intent must not be a symlink")
    if intent_path.exists():
        saved = SubmissionManifest.from_dict(read_json(intent_path)).to_dict()
        if not manifest_path.exists() or not json_values_equal(read_json(manifest_path), saved):
            raise ValueError("Saved publication intent manifest was changed")
        semantic = {key: value for key, value in saved.items()
                    if key not in ("submission_revision", "submitted_at")}
        if (not json_values_equal(semantic, submission)
                or "submission_revision" not in saved
                or not (isinstance(saved["submission_revision"], str) and bool(saved["submission_revision"])
                        or saved["submission_revision"] is None
                        and not store.capabilities.named_submission_revisions)
                or not isinstance(saved.get("submitted_at"), str)
                or not saved["submitted_at"]):
            raise ValueError("Saved publication intent differs from the selected client output")
        submission = saved
    else:
        submission["submission_revision"] = store.new_submission_revision(participant, source_round)
        submission["submitted_at"] = utc_now()
        submission = SubmissionManifest.from_dict(submission).to_dict()
        write_json(manifest_path, submission)
        write_json(intent_path, submission)
    submission_revision = submission["submission_revision"]
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
