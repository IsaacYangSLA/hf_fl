#!/usr/bin/env python3
"""Run download, a trusted local training plugin, and HF PR upload."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from hf2l.client_steps import download_client_round, upload_client_update
from hf2l.hub_helpers import make_api
from hf2l.plugin_loader import load_plugin, parse_plugin_args, require_callable


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-id", required=True)
    parser.add_argument("--participant", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument(
        "--base-revision",
        required=True,
        help="Exact main commit SHA provided by the owner for this round",
    )
    parser.add_argument(
        "--plugin",
        required=True,
        help=(
            "Built-in plugin name (lenet or vgg-cifar10), or a trusted local Python "
            "file defining train_model(base_dir, output_dir, options)"
        ),
    )
    parser.add_argument(
        "--plugin-arg",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Plugin option; JSON values are decoded, and this option may be repeated",
    )
    parser.add_argument(
        "--token",
        help="Token override; prefer HF_TOKEN or `hf auth login` to avoid shell history",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        plugin = load_plugin(args.plugin)
        train_model = require_callable(plugin, "train_model")
        options = parse_plugin_args(args.plugin_arg)
        options["participant"] = args.participant

        api = make_api(args.token)
        context = download_client_round(
            api, args.repo_id, args.base_revision, args.work_dir
        )
        work_dir = args.work_dir.resolve()
        trained_dir = work_dir / "trained_model"
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
        json.dumps(result_metadata)

        result, submission = upload_client_update(
            api,
            work_dir,
            trained_dir,
            args.participant,
            num_examples,
            result_metadata,
        )
        print(f"base_commit={context['base_commit']}")
        print(f"examples={submission['num_examples']}")
        print(f"pr_revision={result.pr_revision}")
        print(f"pr_url={result.pr_url}")
        print("Send pr_revision to the repository owner; do not merge the PR directly.")
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
