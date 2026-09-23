#!/usr/bin/env python3
"""Validate client checkpoints, compute generic FedAvg, and optionally publish."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from hf2l.backends import add_store_arguments, make_store
from hf2l.fedavg_runner import (
    FedAvgRunner, fedavg_states, validate_state, validate_submission_manifest,
)
from hf2l.round.config import RoundConfig
from hf2l.round.result import RoundResult
from hf2l.round.aggregator import AGGREGATORS

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
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
                        help="Exchange claim lease duration (10 to 3600 seconds; renewals use the server lease duration)")
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
    parser.add_argument("--run-state", type=Path,
                        help="Durable claim recovery state; reuse it with a fresh output directory")
    parser.add_argument("--require-concurrent-publication", action="store_true",
                        help="Reject backends without atomic conditional publication before doing work")
    parser.add_argument("--tag", help="Optional immutable tag/revision; requires --publish")
    parser.add_argument("--algorithm", choices=tuple(AGGREGATORS), default="fedavg",
                        help="Registered aggregation algorithm")
    parser.add_argument("--minimum-participants", type=int, default=2,
                        help="Require at least this many valid checkpoints (minimum: 2)")
    parser.add_argument("--array-backend", choices=("numpy", "torch"), default="numpy",
                        help="Array implementation; BF16 checkpoints require torch")
    parser.add_argument("--json", action="store_true", help="Emit one structured round result")
    add_store_arguments(parser)
    return parser.parse_args(argv)


def render_result(result: RoundResult, *, json_output: bool = False, tag: str | None = None) -> None:
    if json_output:
        print(json.dumps(result.to_dict(), sort_keys=True))
        return
    for item in result.skipped:
        print(f"skipped_submission={item.candidate}: {item.reason}", file=sys.stderr)
    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if result.status in {"ready", "not_ready"}:
        print(json.dumps(result.readiness(), sort_keys=True))
        return
    print(f"backend={result.backend}")
    print(f"base_revision={result.base.revision}")
    if result.claim_id:
        print(f"exchange_claim_id={result.claim_id}")
    for submission in result.eligible:
        print(f"participant={submission['participant']} examples={submission['num_examples']} "
              f"coefficient={submission['coefficient']:.6f}")
    print(f"evaluation={json.dumps(result.evaluation, sort_keys=True) if result.evaluation is not None else 'skipped'}")
    print(f"aggregated_model={result.aggregate_dir}")
    if result.publication:
        print(f"published_revision={result.publication.revision}")
        if result.publication.resolved_revision:
            print(f"resolved_revision={result.publication.resolved_revision}")
        if result.publication.url:
            print(f"published_url={result.publication.url}")
        if tag and result.publication.tag_created is not False:
            print(f"tag={tag}")
    else:
        print("Not published. Re-run with a new --output-dir and --publish after review.")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    store = None
    runner = None
    try:
        options = {"principal": args.local_principal} if getattr(args, "local_principal", None) else {}
        store = make_store(args.backend, args.token, args.endpoint, **options)
        runner = FedAvgRunner(store)
        result = runner.run(RoundConfig.from_namespace(args))
        render_result(result, json_output=args.json, tag=args.tag)
        return 0
    except Exception as exc:
        if runner:
            for warning in runner.warnings:
                print(f"warning: {warning}", file=sys.stderr)
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if store is not None:
            try:
                store.close()
            except Exception as exc:
                print(f"warning: could not close backend: {exc}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
