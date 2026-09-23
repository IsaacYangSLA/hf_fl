#!/usr/bin/env python3
"""Step 3: validate and publish a locally trained checkpoint submission."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from hf2l.backends import add_store_arguments, make_store
from hf2l.client_steps import upload_client_update
from hf2l.hub_helpers import read_json


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
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
    add_store_arguments(parser)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    store = None
    try:
        work_dir = args.work_dir.resolve()
        trained_dir = (args.trained_dir or work_dir / "trained_model").resolve()
        metadata = read_json(args.metadata_json) if args.metadata_json else {}
        options = {"principal": args.local_principal} if getattr(args, "local_principal", None) else {}
        store = make_store(args.backend, args.token, args.endpoint, **options)
        result, submission = upload_client_update(
            store,
            work_dir,
            trained_dir,
            args.participant,
            args.num_examples,
            metadata,
        )
        print(f"backend={submission['backend']}")
        print(f"base_revision={submission['base_revision']}")
        print(f"examples={submission['num_examples']}")
        print(f"submission_revision={result.revision}")
        if result.resolved_revision:
            print(f"resolved_revision={result.resolved_revision}")
        if result.url:
            print(f"submission_url={result.url}")
        print("Send submission_revision to the repository owner.")
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if store is not None:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())
