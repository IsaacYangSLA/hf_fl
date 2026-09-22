#!/usr/bin/env python3
"""Validate client checkpoints, compute generic FedAvg, and optionally publish."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import torch

from hf2l.allowlist import load_allowlist
from hf2l.backends import SubmissionCandidate, add_store_arguments, make_store
from hf2l.checkpoint_utils import (
    aggregate_checkpoints,
    average_tensor,
    discover_checkpoint,
    validate_coefficients,
    validate_compatible,
)
from hf2l.hub_helpers import (
    ROUND_FILE,
    SUBMISSION_FILE,
    SCHEMA_VERSION,
    artifact_hashes,
    base_revision_from,
    read_json,
    regular_file_paths,
    require_new_directory,
    require_supported_schema,
    utc_now,
    validate_artifact_hashes,
    write_json,
)
from hf2l.plugin_loader import load_plugin, parse_plugin_args, require_callable


def validate_submission_manifest(
    manifest: dict[str, Any],
    *,
    repo_id: str,
    base_revision: str,
    current_round: int,
    revision: str,
    expected_participant: str | None,
    expected_backend: str = "huggingface",
    expected_submission_revision: str | None = None,
) -> tuple[str, int]:
    schema_version = require_supported_schema(manifest, f"manifest in {revision}")
    if manifest.get("repo_id") != repo_id:
        raise ValueError(f"{revision} declares a different repository")
    manifest_backend = str(manifest.get("backend", "huggingface"))
    if manifest_backend != expected_backend:
        raise ValueError(
            f"{revision} declares backend {manifest_backend!r}; expected {expected_backend!r}"
        )
    manifest_base = base_revision_from(manifest)
    if manifest_base != base_revision:
        raise ValueError(
            f"{revision} used base {manifest_base}; current main is {base_revision}"
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
    if schema_version >= 2 and expected_backend == "jfrog":
        declared_revision = str(manifest.get("submission_revision", "")).strip()
        if declared_revision != expected_submission_revision:
            raise ValueError(
                f"{revision} declares submission revision {declared_revision!r}"
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
        "--submission",
        action="append",
        help="Submission revision; repeat once per client",
    )
    selection.add_argument(
        "--discover-submissions",
        action="store_true",
        help="Automatically consider current backend submissions",
    )
    selection.add_argument(
        "--pr",
        action="append",
        help="HF compatibility alias for --submission",
    )
    selection.add_argument(
        "--discover-prs",
        action="store_true",
        help="HF compatibility alias for --discover-submissions",
    )
    selection.add_argument("--claim-submissions", action="store_true",
                           help="Exchange only: acquire a fenced claim for current-round submissions")
    selection.add_argument("--claim-id", help="Exchange only: resume a known active claim")
    parser.add_argument("--claim-lease-seconds", type=int, default=3600,
                        help="Exchange claim lease duration (30 to 86400 seconds)")
    parser.add_argument(
        "--allowlist",
        type=Path,
        help="JSON object mapping approved repository identities to participant IDs",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Check submission metadata and write readiness.json without downloading checkpoints",
    )
    parser.add_argument(
        "--expected-base-revision",
        help="Require main to still match this immutable revision before aggregation",
    )
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
        help=(
            "Optional built-in plugin name (lenet or vgg-cifar10), or a trusted "
            "local Python file defining evaluate_model(model_dir, options)"
        ),
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
        help="After successful aggregation/evaluation, publish the model to main",
    )
    parser.add_argument("--tag", help="Optional immutable tag/revision; requires --publish")
    add_store_arguments(parser)
    return parser.parse_args()


def _read_round(path: Path, label: str) -> int:
    record = read_json(path / ROUND_FILE)
    require_supported_schema(record, f"{label} model")
    try:
        return int(record["round"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"The {label} model has an invalid round number") from exc


def main() -> None:
    args = parse_args()
    store = None
    try:
        if args.tag and not args.publish:
            raise ValueError("--tag requires --publish")
        if args.check_only and (args.publish or args.plugin or args.plugin_arg):
            raise ValueError("--check-only cannot publish or evaluate a model")
        if args.claim_submissions or args.claim_id:
            if args.backend != "exchange" or args.check_only or not args.publish:
                raise ValueError("Claims require --backend exchange and --publish; cannot use --check-only")
        allowlist = load_allowlist(args.allowlist) if args.allowlist else None
        claiming = bool(args.claim_submissions or args.claim_id)
        # Automatic and claim modes skip ineligible submissions instead of failing the whole round.
        automatic = args.discover_submissions or args.discover_prs or claiming
        if args.backend != "huggingface" and (args.pr or args.discover_prs):
            raise ValueError(
                "This backend has no pull requests; use --submission or --discover-submissions"
            )
        if automatic and allowlist is None and args.backend != "exchange":
            print(
                "warning: automatic discovery without --allowlist accepts every "
                "compatible repository submission",
                file=sys.stderr,
            )

        output_dir = args.output_dir.resolve()
        require_new_directory(output_dir)
        store = make_store(args.backend, args.token, args.endpoint)
        base_reference = store.resolve_reference(args.repo_id, "main")
        base_revision = base_reference.revision
        if args.expected_base_revision and base_revision != args.expected_base_revision:
            raise ValueError(
                f"Main changed since readiness check: expected {args.expected_base_revision}; "
                f"found {base_revision}"
            )

        base_dir = output_dir / "downloads" / "base"
        store.download_snapshot(
            args.repo_id, base_revision, base_dir, allow_patterns=ROUND_FILE
        )
        current_round = _read_round(base_dir, "main")
        base_round_record = read_json(base_dir / ROUND_FILE)
        if int(base_round_record.get("schema_version", 1)) >= 2:
            if base_round_record.get("backend") != store.name:
                raise ValueError(
                    f"Main declares backend {base_round_record.get('backend')!r}; "
                    f"expected {store.name!r}"
                )

        if claiming:
            candidates = store.claim_submissions(
                args.repo_id, args.claim_id, args.claim_lease_seconds, state_dir=output_dir
            )
        elif automatic:
            candidates, skipped = store.discover_submissions(args.repo_id)
            for reason in skipped:
                print(f"skipped_submission={reason}", file=sys.stderr)
        else:
            candidates = store.explicit_submissions(
                args.repo_id, args.submission or args.pr or []
            )

        authorized: list[SubmissionCandidate] = []
        for candidate in candidates:
            if allowlist is not None and candidate.author.casefold() not in allowlist:
                reason = (
                    f"{candidate.identifier} author={candidate.author}: not in allowlist"
                )
                if automatic:
                    print(f"skipped_submission={reason}", file=sys.stderr)
                    continue
                raise ValueError(reason)
            authorized.append(candidate)

        prepared: list[
            tuple[SubmissionCandidate, str, dict[str, Any], str, int]
        ] = []
        seen_participants: set[str] = set()
        for candidate_index, candidate in enumerate(authorized, start=1):
            revision = candidate.revision
            resolved_revision = store.resolve_revision(args.repo_id, revision)
            if store.supports_ancestry and not store.is_descendant(
                args.repo_id, resolved_revision, base_revision
            ):
                reason = f"{revision} is not descended from current main {base_revision}"
                if automatic:
                    print(f"skipped_submission={reason}", file=sys.stderr)
                    continue
                raise ValueError(reason)

            manifest_dir = output_dir / "discovery" / f"submission-{candidate_index}"
            try:
                store.download_snapshot(
                    args.repo_id,
                    resolved_revision,
                    manifest_dir,
                    allow_patterns=SUBMISSION_FILE,
                )
                manifest = read_json(manifest_dir / SUBMISSION_FILE)
                expected_participant = (
                    allowlist[candidate.author.casefold()] if allowlist is not None else candidate.participant
                )
                if candidate.participant is not None and expected_participant != candidate.participant:
                    raise ValueError("Allowlist differs from server-bound participant identity")
                participant, num_examples = validate_submission_manifest(
                    manifest,
                    repo_id=args.repo_id,
                    base_revision=base_revision,
                    current_round=current_round,
                    revision=revision,
                    expected_participant=expected_participant,
                    expected_backend=store.name,
                    expected_submission_revision=(
                        candidate.revision if store.name == "jfrog" else None
                    ),
                )
            except (ValueError, OSError) as exc:
                if automatic:
                    print(f"skipped_submission={revision}: {exc}", file=sys.stderr)
                    continue
                raise
            if participant in seen_participants:
                raise ValueError(
                    f"Duplicate participant {participant!r} among eligible submissions; "
                    "withdraw the superseded submission or select revisions explicitly"
                )
            seen_participants.add(participant)
            prepared.append(
                (candidate, resolved_revision, manifest, participant, num_examples)
            )

        if args.check_only:
            readiness = {
                "ready": len(prepared) >= 2,
                "base_revision": base_revision,
                "eligible_count": len(prepared),
            }
            write_json(output_dir / "readiness.json", readiness)
            print(json.dumps(readiness, sort_keys=True))
            return

        if len(prepared) < 2:
            mode = "eligible" if automatic else "selected"
            raise ValueError(
                f"FedAvg requires at least two {mode} client submissions; found {len(prepared)}"
            )
        for candidate, resolved_revision, _, participant, _ in prepared:
            print(
                f"eligible_submission={candidate.identifier} revision={resolved_revision} "
                f"author={candidate.author} participant={participant}"
            )

        store.download_snapshot(args.repo_id, base_revision, base_dir)
        reference = discover_checkpoint(base_dir)
        if int(base_round_record.get("schema_version", 1)) >= 2:
            validate_artifact_hashes(
                base_dir,
                reference.artifact_paths,
                base_round_record.get("checkpoint_files_sha256"),
                "main",
            )

        submissions: list[dict[str, Any]] = []
        client_layouts = []
        for index, item in enumerate(prepared, start=1):
            candidate, resolved_revision, manifest, participant, num_examples = item
            client_dir = output_dir / "downloads" / f"client-{index}"
            store.download_snapshot(args.repo_id, resolved_revision, client_dir)
            if read_json(client_dir / SUBMISSION_FILE) != manifest:
                raise ValueError(f"Manifest changed while downloading {candidate.identifier}")
            client_layout = discover_checkpoint(client_dir)
            validate_compatible(reference, client_layout)
            if int(manifest.get("schema_version", 1)) >= 2:
                validate_artifact_hashes(
                    client_dir,
                    client_layout.artifact_paths,
                    manifest.get("checkpoint_files_sha256"),
                    candidate.identifier,
                )
            client_layouts.append(client_layout)
            submissions.append(
                {
                    "participant": participant,
                    "author": candidate.author,
                    "submission_revision": candidate.revision,
                    "resolved_revision": resolved_revision,
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
            plugin = load_plugin(args.plugin)
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
            "backend": store.name,
            "algorithm": f"FedAvg with {args.weighting} weighting",
            "accumulator_dtype": args.accumulator_dtype,
            "base_revision": base_revision,
            "created_at": utc_now(),
            "checkpoint_files": list(aggregate.artifact_paths),
            "evaluation": evaluation,
            "selection": {
                "mode": "automatic_submissions" if automatic else "explicit_submissions",
                "allowlist_enforced": allowlist is not None,
            },
            "submissions": submissions,
        }
        round_record["checkpoint_files_sha256"] = artifact_hashes(
            aggregate_dir, aggregate.artifact_paths
        )
        write_json(aggregate_dir / ROUND_FILE, round_record)

        print(f"backend={store.name}")
        print(f"base_revision={base_revision}")
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
            upload_paths = regular_file_paths(aggregate_dir)
            result = store.publish_aggregate(
                args.repo_id,
                aggregate_dir,
                upload_paths,
                expected_base=base_revision,
                next_round=next_round,
                tag=args.tag,
                reference=base_reference,
                claim=store.current_claim(),
            )
            print(f"published_revision={result.revision}")
            if result.resolved_revision:
                print(f"resolved_revision={result.resolved_revision}")
            if result.url:
                print(f"published_url={result.url}")
            for warning in result.warnings:
                print(f"warning: {warning}", file=sys.stderr)
            if args.tag and result.tag_created is not False:
                print(f"tag={args.tag}")
            if store.name == "huggingface":
                print("Client PRs were not merged; close them after review.")
        else:
            print("Not published. Re-run with a new --output-dir and --publish after review.")
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        if store is not None:
            try:
                # A held claim must not outlive a failed round, or main stays frozen for its base.
                store.abandon_claim(args.repo_id)
            except Exception as release_error:
                print(f"warning: could not abandon claim: {release_error}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
