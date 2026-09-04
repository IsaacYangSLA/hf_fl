#!/usr/bin/env python3
"""Validate client PR checkpoints, compute generic FedAvg, and optionally publish."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import torch
from huggingface_hub import CommitOperationAdd

from hf2l.checkpoint_utils import (
    aggregate_checkpoints,
    average_tensor,
    discover_checkpoint,
    validate_coefficients,
    validate_compatible,
)
from hf2l.hub_helpers import (
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
from hf2l.plugin_loader import load_local_plugin, parse_plugin_args, require_callable


@dataclass(frozen=True)
class PullRequestCandidate:
    number: int
    revision: str
    author: str


def load_allowlist(path: Path) -> dict[str, str]:
    """Load a one-to-one mapping of HF username to manifest participant ID."""
    raw = read_json(path)
    if not raw:
        raise ValueError(f"Allowlist must not be empty: {path}")
    allowlist: dict[str, str] = {}
    participant_to_author: dict[str, str] = {}
    for raw_author, raw_participant in raw.items():
        author = raw_author.strip() if isinstance(raw_author, str) else ""
        if not author or not isinstance(raw_participant, str):
            raise ValueError("Allowlist entries must map a non-empty HF username to a string")
        participant = raw_participant.strip()
        if not participant:
            raise ValueError(f"Allowlist participant must not be empty for author {author!r}")
        normalized_author = author.casefold()
        if normalized_author in allowlist:
            raise ValueError(f"Duplicate HF username in allowlist: {author}")
        if participant in participant_to_author:
            raise ValueError(
                f"Participant {participant!r} is mapped to both "
                f"{participant_to_author[participant]!r} and {author!r}"
            )
        allowlist[normalized_author] = participant
        participant_to_author[participant] = author
    return allowlist


def discover_open_pull_requests(
    api: Any, repo_id: str, allowlist: dict[str, str] | None
) -> tuple[list[PullRequestCandidate], list[str]]:
    """List open Hub PRs and optionally reject unapproved HF authors."""
    candidates: list[PullRequestCandidate] = []
    skipped: list[str] = []
    discussions = api.get_repo_discussions(
        repo_id=repo_id,
        repo_type="model",
        discussion_type="pull_request",
        discussion_status="open",
    )
    for discussion in discussions:
        if not discussion.is_pull_request:
            continue
        number = int(discussion.num)
        revision = f"refs/pr/{number}"
        author = discussion.author.strip() if isinstance(discussion.author, str) else ""
        if not author:
            skipped.append(f"{revision}: missing HF author")
            continue
        if allowlist is not None and author.casefold() not in allowlist:
            skipped.append(f"{revision} author={author}: not in allowlist")
            continue
        candidates.append(PullRequestCandidate(number, revision, author))
    candidates.sort(key=lambda candidate: candidate.number)
    return candidates, skipped


def explicit_pull_requests(
    api: Any,
    repo_id: str,
    values: list[str],
    allowlist: dict[str, str] | None,
) -> list[PullRequestCandidate]:
    """Resolve explicitly selected PRs and obtain their HF authors."""
    candidates: list[PullRequestCandidate] = []
    seen_numbers: set[int] = set()
    for value in values:
        revision = normalize_pr(value)
        number = int(revision.removeprefix("refs/pr/"))
        if number in seen_numbers:
            raise ValueError(f"Duplicate PR selection: {revision}")
        seen_numbers.add(number)
        details = api.get_discussion_details(
            repo_id=repo_id,
            discussion_num=number,
            repo_type="model",
        )
        if not details.is_pull_request:
            raise ValueError(f"Discussion {number} is not a pull request")
        author = details.author.strip() if isinstance(details.author, str) else ""
        if not author:
            raise ValueError(f"{revision} has no HF author")
        if allowlist is not None and author.casefold() not in allowlist:
            raise ValueError(f"{revision} author {author!r} is not in the allowlist")
        candidates.append(PullRequestCandidate(number, revision, author))
    return candidates


def validate_submission_manifest(
    manifest: dict[str, Any],
    *,
    repo_id: str,
    base_commit: str,
    current_round: int,
    revision: str,
    expected_participant: str | None,
) -> tuple[str, int]:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported manifest schema in {revision}")
    if manifest.get("repo_id") != repo_id:
        raise ValueError(f"{revision} declares a different repository")
    if manifest.get("base_commit") != base_commit:
        raise ValueError(
            f"{revision} used base {manifest.get('base_commit')}; current main is {base_commit}"
        )
    if manifest.get("source_round") != current_round:
        raise ValueError(
            f"{revision} declares source round {manifest.get('source_round')}; "
            f"current round is {current_round}"
        )
    participant = str(manifest.get("participant", "")).strip()
    if not participant:
        raise ValueError(f"{revision} has no participant identity")
    if expected_participant is not None and participant != expected_participant:
        raise ValueError(
            f"{revision} author is approved only as participant "
            f"{expected_participant!r}, not {participant!r}"
        )
    try:
        num_examples = manifest["num_examples"]
    except KeyError as exc:
        raise ValueError(f"invalid num_examples in {revision}") from exc
    if isinstance(num_examples, bool) or not isinstance(num_examples, int):
        raise ValueError(f"invalid num_examples in {revision}")
    if num_examples <= 0:
        raise ValueError(f"non-positive num_examples in {revision}")
    return participant, num_examples


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
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument(
        "--pr",
        action="append",
        help="PR number or refs/pr/N; repeat once per client",
    )
    selection.add_argument(
        "--discover-prs",
        action="store_true",
        help="Automatically consider open PRs whose manifests match the current round",
    )
    parser.add_argument(
        "--allowlist",
        type=Path,
        help="JSON object mapping approved HF usernames to participant IDs",
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
        allowlist = load_allowlist(args.allowlist) if args.allowlist else None
        if args.discover_prs and allowlist is None:
            print(
                "warning: automatic discovery without --allowlist accepts every "
                "compatible open PR",
                file=sys.stderr,
            )

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

        if args.discover_prs:
            candidates, skipped = discover_open_pull_requests(api, args.repo_id, allowlist)
            for reason in skipped:
                print(f"skipped_pr={reason}", file=sys.stderr)
        else:
            candidates = explicit_pull_requests(api, args.repo_id, args.pr or [], allowlist)

        prepared: list[
            tuple[PullRequestCandidate, str, dict[str, Any], str, int]
        ] = []
        seen_participants: set[str] = set()
        for candidate in candidates:
            revision = candidate.revision
            pr_info = api.model_info(args.repo_id, revision=revision)
            pr_commit = pr_info.sha
            if not pr_commit:
                raise RuntimeError(f"Hugging Face did not return a SHA for {revision}")
            history = api.list_repo_commits(args.repo_id, revision=pr_commit)
            if not any(commit.commit_id == base_commit for commit in history):
                reason = f"{revision} is not descended from current main {base_commit}"
                if args.discover_prs:
                    print(f"skipped_pr={reason}", file=sys.stderr)
                    continue
                raise ValueError(reason)

            manifest_dir = output_dir / "discovery" / f"pr-{candidate.number}"
            api.snapshot_download(
                repo_id=args.repo_id,
                repo_type="model",
                revision=pr_commit,
                local_dir=manifest_dir,
                allow_patterns=SUBMISSION_FILE,
            )
            try:
                manifest = read_json(manifest_dir / SUBMISSION_FILE)
                expected_participant = (
                    allowlist[candidate.author.casefold()] if allowlist is not None else None
                )
                participant, num_examples = validate_submission_manifest(
                    manifest,
                    repo_id=args.repo_id,
                    base_commit=base_commit,
                    current_round=current_round,
                    revision=revision,
                    expected_participant=expected_participant,
                )
            except ValueError as exc:
                if args.discover_prs:
                    print(f"skipped_pr={revision}: {exc}", file=sys.stderr)
                    continue
                raise
            if participant in seen_participants:
                raise ValueError(
                    f"Duplicate participant {participant!r} among eligible PRs; "
                    "close the superseded PR or select PRs explicitly"
                )
            seen_participants.add(participant)
            prepared.append((candidate, pr_commit, manifest, participant, num_examples))

        if len(prepared) < 2:
            mode = "eligible" if args.discover_prs else "selected"
            raise ValueError(
                f"FedAvg requires at least two {mode} client PRs; found {len(prepared)}"
            )
        for candidate, pr_commit, _, participant, _ in prepared:
            print(
                f"eligible_pr={candidate.revision} commit={pr_commit} "
                f"hf_author={candidate.author} participant={participant}"
            )

        submissions: list[dict[str, Any]] = []
        client_layouts = []
        for index, item in enumerate(prepared, start=1):
            candidate, pr_commit, manifest, participant, num_examples = item
            client_dir = output_dir / "downloads" / f"client-{index}"
            api.snapshot_download(
                repo_id=args.repo_id,
                repo_type="model",
                revision=pr_commit,
                local_dir=client_dir,
            )
            if read_json(client_dir / SUBMISSION_FILE) != manifest:
                raise ValueError(f"Manifest changed while downloading {candidate.revision}")
            client_layout = discover_checkpoint(client_dir)
            validate_compatible(reference, client_layout)
            client_layouts.append(client_layout)
            submissions.append(
                {
                    "participant": participant,
                    "hf_author": candidate.author,
                    "pr_revision": candidate.revision,
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
            "selection": {
                "mode": "automatic_open_prs" if args.discover_prs else "explicit_prs",
                "allowlist_enforced": allowlist is not None,
            },
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
