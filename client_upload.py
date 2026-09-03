#!/usr/bin/env python3
"""Step 3: validate a locally trained checkpoint and submit it as an HF PR."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from client_steps import upload_client_update
from hub_helpers import make_api, read_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument(
        "--trained-dir",
        type=Path,
        help="Complete trained checkpoint; defaults to WORK_DIR/trained_model",
    )
    parser.add_argument("--participant", required=True)
    parser.add_argument("--num-examples", type=int, required=True)
    parser.add_argument(
        "--metadata-json",
        type=Path,
        help="Optional non-secret JSON object describing local training and metrics",
    )
    parser.add_argument(
        "--token",
        help="Token override; prefer HF_TOKEN or `hf auth login` to avoid shell history",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        work_dir = args.work_dir.resolve()
        trained_dir = (args.trained_dir or work_dir / "trained_model").resolve()
        metadata = read_json(args.metadata_json) if args.metadata_json else {}
        result, submission = upload_client_update(
            make_api(args.token),
            work_dir,
            trained_dir,
            args.participant,
            args.num_examples,
            metadata,
        )
        print(f"base_commit={submission['base_commit']}")
        print(f"examples={submission['num_examples']}")
        print(f"pr_revision={result.pr_revision}")
        print(f"pr_url={result.pr_url}")
        print("Send pr_revision to the repository owner; do not merge the PR directly.")
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
