#!/usr/bin/env python3
"""Step 1: download an immutable base checkpoint for local training."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from hf2l.backends import add_store_arguments, make_store
from hf2l.client_steps import download_client_round
from hf2l.hub_helpers import CLIENT_CONTEXT_FILE


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-id", required=True)
    parser.add_argument(
        "--base-revision",
        required=True,
        help="Exact immutable base revision supplied by the owner for this round",
    )
    parser.add_argument("--work-dir", type=Path, required=True)
    add_store_arguments(parser)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    store = None
    try:
        options = {"principal": args.local_principal} if getattr(args, "local_principal", None) else {}
        store = make_store(args.backend, args.token, args.endpoint, **options)
        context = download_client_round(
            store,
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
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if store is not None:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())
