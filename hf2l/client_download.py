#!/usr/bin/env python3
"""Step 1: download an immutable base checkpoint for local training."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from hf2l.backends import add_store_arguments, make_store
from hf2l.client_steps import download_client_round
from hf2l.hub_helpers import CLIENT_CONTEXT_FILE


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-id", required=True)
    parser.add_argument(
        "--base-revision",
        required=True,
        help="Exact immutable base revision supplied by the owner for this round",
    )
    parser.add_argument("--work-dir", type=Path, required=True)
    add_store_arguments(parser)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        context = download_client_round(
            make_store(args.backend, args.token, args.endpoint),
            args.repo_id,
            args.base_revision,
            args.work_dir,
        )
        work_dir = args.work_dir.resolve()
        print(f"backend={context['backend']}")
        print(f"base_revision={context['base_revision']}")
        print(f"source_round={context['source_round']}")
        print(f"base_model={work_dir / 'base_model'}")
        print(f"context={work_dir / CLIENT_CONTEXT_FILE}")
        print("Train with your own code and write a complete checkpoint to a different directory.")
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
