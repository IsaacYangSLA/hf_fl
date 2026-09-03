#!/usr/bin/env python3
"""Validate client PR checkpoints, compute generic FedAvg, and optionally publish."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import torch
from huggingface_hub import CommitOperationAdd

from checkpoint_utils import (
    aggregate_checkpoints,
    average_tensor,
    discover_checkpoint,
    validate_coefficients,
    validate_compatible,
)
from hub_helpers import (
    ROUND_FILE,
    SCHEMA_VERSION,
    SUBMISSION_FILE,
    make_api,
    normalize_pr,
    read_json,
    require_new_directory,
    utc_now,
    write_json,
)
from plugin_loader import load_local_plugin, parse_plugin_args, require_callable


def validate_state(reference: dict[str, torch.Tensor], candidate: dict[str, torch.Tensor]) -> None:
    """Compatibility helper retained for small in-memory callers and tests."""
    if reference.keys() != candidate.keys():
        missing = sorted(reference.keys() - candidate.keys())
        extra = sorted(candidate.keys() - reference.keys())
        raise ValueError(f"State-dict keys differ: missing={missing[:5]}, extra={extra[:5]}")
    for key, reference_tensor in reference.items():
        candidate_tensor = candidate[key]
        if reference_tensor.shape != candidate_tensor.shape:
            raise ValueError(
                f"Shape mismatch for {key}: {reference_tensor.shape} != {candidate_tensor.shape}"
            )
        if reference_tensor.dtype != candidate_tensor.dtype:
            raise ValueError(
                f"Dtype mismatch for {key}: {reference_tensor.dtype} != {candidate_tensor.dtype}"
            )


def fedavg_states(
    reference: dict[str, torch.Tensor],
    client_states: list[dict[str, torch.Tensor]],
    coefficients: list[float],
) -> dict[str, torch.Tensor]:
    """Average a small state dict; production CLI aggregation streams by shard."""
    validate_coefficients(coefficients, len(client_states))
    for state in client_states:
        validate_state(reference, state)
    return {
        key: average_tensor(
            reference_tensor,
            [state[key] for state in client_states],
            coefficients,
            torch.float64,
            key,
        )
        for key, reference_tensor in reference.items()
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-id", required=True)
    parser.add_argument(
        "--pr",
        action="append",
        required=True,
        help="PR number or refs/pr/N; repeat once per client",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--weighting",
        choices=("examples", "uniform"),
        default="examples",
        help="FedAvg normally weights clients by their reported example counts",
    )
    parser.add_argument(
        "--accumulator-dtype",
        choices=("float32", "float64"),
        default="float32",
        help="float32 reduces RAM for large checkpoints; float64 improves accumulation precision",
    )
    parser.add_argument(
        "--plugin",
        type=Path,
        help="Optional trusted local plugin defining evaluate_model(model_dir, options)",
    )
    parser.add_argument(
        "--plugin-arg",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Evaluation plugin option; JSON values are decoded, and this option may be repeated",
    )
    parser.add_argument(
        "--publish",
        action="store_true",
        help="After successful aggregation/evaluation, commit the model to main",
    )
    parser.add_argument("--tag", help="Optional immutable tag; requires --publish")
    parser.add_argument(
        "--token",
        help="Token override; prefer HF_TOKEN or `hf auth login` to avoid shell history",
    )
    return parser.parse_args()


def _read_round(path: Path, label: str) -> int:
    record = read_json(path / ROUND_FILE)
    if record.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"The {label} model uses an unsupported FedAvg schema")
    try:
        return int(record["round"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"The {label} model has an invalid round number") from exc


def main() -> None:
    args = parse_args()
    try:
        if args.tag and not args.publish:
            raise ValueError("--tag requires --publish")
        if len(args.pr) < 2:
            raise ValueError("Provide at least two --pr values for FedAvg")

        output_dir = args.output_dir.resolve()
        require_new_directory(output_dir)
        api = make_api(args.token)
        main_info = api.model_info(args.repo_id, revision="main")
        base_commit = main_info.sha
        if not base_commit:
            raise RuntimeError("Hugging Face did not return the current main SHA")

        base_dir = output_dir / "downloads" / "base"
        api.snapshot_download(
            repo_id=args.repo_id,
            repo_type="model",
            revision=base_commit,
            local_dir=base_dir,
        )
        current_round = _read_round(base_dir, "main")
        reference = discover_checkpoint(base_dir)

        submissions: list[dict[str, Any]] = []
        client_layouts = []
        seen_participants: set[str] = set()
        revisions = [normalize_pr(value) for value in args.pr]

        for index, revision in enumerate(revisions, start=1):
            pr_info = api.model_info(args.repo_id, revision=revision)
            pr_commit = pr_info.sha
            if not pr_commit:
                raise RuntimeError(f"Hugging Face did not return a SHA for {revision}")
            history = api.list_repo_commits(args.repo_id, revision=pr_commit)
            if not any(commit.commit_id == base_commit for commit in history):
                raise ValueError(f"{revision} is not descended from current main {base_commit}")

            client_dir = output_dir / "downloads" / f"client-{index}"
            api.snapshot_download(
                repo_id=args.repo_id,
                repo_type="model",
                revision=pr_commit,
                local_dir=client_dir,
            )
            manifest = read_json(client_dir / SUBMISSION_FILE)
            if manifest.get("schema_version") != SCHEMA_VERSION:
                raise ValueError(f"Unsupported manifest schema in {revision}")
            if manifest.get("repo_id") != args.repo_id:
                raise ValueError(f"{revision} declares a different repository")
            if manifest.get("base_commit") != base_commit:
                raise ValueError(
                    f"{revision} used base {manifest.get('base_commit')}; "
                    f"current main is {base_commit}"
                )
            if manifest.get("source_round") != current_round:
                raise ValueError(
                    f"{revision} declares source round {manifest.get('source_round')}; "
                    f"current round is {current_round}"
                )
            participant = str(manifest.get("participant", "")).strip()
            if not participant:
                raise ValueError(f"{revision} has no participant identity")
            if participant in seen_participants:
                raise ValueError(f"Duplicate participant: {participant}")
            seen_participants.add(participant)
            try:
                num_examples = manifest["num_examples"]
            except KeyError as exc:
                raise ValueError(f"Invalid num_examples in {revision}") from exc
            if isinstance(num_examples, bool) or not isinstance(num_examples, int):
                raise ValueError(f"Invalid num_examples in {revision}")
            if num_examples <= 0:
                raise ValueError(f"Non-positive num_examples in {revision}")

            client_layout = discover_checkpoint(client_dir)
            validate_compatible(reference, client_layout)
            client_layouts.append(client_layout)
            submissions.append(
                {
                    "participant": participant,
                    "pr_revision": revision,
                    "commit": pr_commit,
                    "num_examples": num_examples,
                    "training": manifest.get("training", {}),
                }
            )

        if args.weighting == "examples":
            total_examples = sum(item["num_examples"] for item in submissions)
            coefficients = [item["num_examples"] / total_examples for item in submissions]
        else:
            coefficients = [1.0 / len(submissions)] * len(submissions)

        aggregate_dir = output_dir / "aggregated_model"
        accumulator_dtype = torch.float32 if args.accumulator_dtype == "float32" else torch.float64
        aggregate = aggregate_checkpoints(
            reference,
            client_layouts,
            coefficients,
            aggregate_dir,
            accumulator_dtype=accumulator_dtype,
        )

        evaluation: dict[str, Any] | None = None
        if args.plugin:
            plugin = load_local_plugin(args.plugin)
            evaluate_model = require_callable(plugin, "evaluate_model")
            evaluation = evaluate_model(aggregate_dir, parse_plugin_args(args.plugin_arg))
            if not isinstance(evaluation, dict):
                raise ValueError("evaluate_model(...) must return a metadata dictionary")
            json.dumps(evaluation)
        elif args.plugin_arg:
            raise ValueError("--plugin-arg requires --plugin")

        next_round = current_round + 1
        for submission, coefficient in zip(submissions, coefficients, strict=True):
            submission["coefficient"] = coefficient
        round_record = {
            "schema_version": SCHEMA_VERSION,
            "round": next_round,
            "algorithm": f"FedAvg with {args.weighting} weighting",
            "accumulator_dtype": args.accumulator_dtype,
            "base_commit": base_commit,
            "created_at": utc_now(),
            "checkpoint_files": list(aggregate.artifact_paths),
            "evaluation": evaluation,
            "submissions": submissions,
        }
        write_json(aggregate_dir / ROUND_FILE, round_record)

        print(f"base_commit={base_commit}")
        for submission in submissions:
            print(
                f"participant={submission['participant']} "
                f"examples={submission['num_examples']} "
                f"coefficient={submission['coefficient']:.6f}"
            )
        if evaluation is not None:
            print(f"evaluation={json.dumps(evaluation, sort_keys=True)}")
        else:
            print("evaluation=skipped")
        print(f"aggregated_model={aggregate_dir}")

        if args.publish:
            upload_paths = [*aggregate.artifact_paths, ROUND_FILE]
            operations = [
                CommitOperationAdd(path_in_repo=path, path_or_fileobj=aggregate_dir / path)
                for path in upload_paths
            ]
            result = api.create_commit(
                repo_id=args.repo_id,
                repo_type="model",
                revision="main",
                parent_commit=base_commit,
                operations=operations,
                commit_message=f"Publish FedAvg round {next_round}",
            )
            published = api.model_info(args.repo_id, revision="main").sha
            if published != result.oid:
                raise RuntimeError(
                    f"Post-publish verification failed: main={published}, commit={result.oid}"
                )
            print(f"published_commit={result.oid}")
            print(f"commit_url={result.commit_url}")
            if args.tag:
                api.create_tag(
                    args.repo_id,
                    repo_type="model",
                    tag=args.tag,
                    revision=result.oid,
                    tag_message=f"FedAvg round {next_round}",
                    exist_ok=False,
                )
                print(f"tag={args.tag}")
            print("The client PRs were intentionally not merged; close them after review.")
        else:
            print("Not published. Re-run with a new --output-dir and --publish after review.")
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
