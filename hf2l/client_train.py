#!/usr/bin/env python3
"""Run download, a trusted local training plugin, and checkpoint submission."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from hf2l.backends import add_store_arguments, make_store
from hf2l.client_steps import add_handoff_arguments, download_client_round, upload_client_update
from hf2l.common.output import plugin_stdout_to_stderr
from hf2l.plugin_loader import load_plugin, parse_plugin_args, require_callable


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-id", required=True)
    parser.add_argument("--participant", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument(
        "--base-revision",
        required=True,
        help="Global model revision, or the predecessor revision for an explicit cyclic handoff",
    )
    parser.add_argument(
        "--plugin",
        required=True,
        help=(
            "Built-in plugin name (lenet or vgg-cifar10), or a trusted local Python "
            "file defining train_model(base_dir, output_dir, options)"
        ),
    )
    add_handoff_arguments(parser)
    parser.add_argument(
        "--plugin-arg",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Plugin option; JSON values are decoded, and this option may be repeated",
    )
    add_store_arguments(parser)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    store = None
    try:
        plugin = load_plugin(args.plugin)
        train_model = require_callable(plugin, "train_model")
        options = parse_plugin_args(args.plugin_arg)
        options["participant"] = args.participant

        options_store = {"principal": args.local_principal} if getattr(args, "local_principal", None) else {}
        store = make_store(args.backend, args.token, args.endpoint, **options_store)
        context = download_client_round(
            store, args.repo_id, args.base_revision, args.work_dir,
            workflow=args.workflow, source_kind=args.source_kind,
            source_participant=args.source_participant,
        )
        work_dir = args.work_dir.resolve()
        trained_dir = work_dir / "trained_model"
        with plugin_stdout_to_stderr():
            result_metadata = train_model(work_dir / "base_model", trained_dir, options)
        if not isinstance(result_metadata, dict):
            raise ValueError("train_model(...) must return a metadata dictionary")
        try:
            num_examples = result_metadata.pop("num_examples")
        except KeyError as exc:
            raise ValueError(
                "train_model(...) must return a positive integer num_examples"
            ) from exc
        if isinstance(num_examples, bool) or not isinstance(num_examples, int):
            raise ValueError("train_model(...) num_examples must be an integer")
        # Fail before contacting the Hub if the plugin returned non-JSON metadata.
        json.dumps(result_metadata, allow_nan=False)

        result, submission = upload_client_update(
            store,
            work_dir,
            trained_dir,
            args.participant,
            num_examples,
            result_metadata,
        )
        print(f"backend={context['backend']}")
        print(f"base_revision={context['base_revision']}")
        print(f"examples={submission['num_examples']}")
        print(f"submission_revision={result.revision}")
        if result.resolved_revision:
            print(f"resolved_revision={result.resolved_revision}")
        if result.url:
            print(f"submission_url={result.url}")
        if submission.get("workflow") == "cyclic":
            print("Send resolved_revision to the next participant for a cyclic handoff.")
        else:
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
