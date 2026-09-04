#!/usr/bin/env python3
"""Create an HF model repository from a local checkpoint or initialization plugin."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import textwrap
from pathlib import Path

from hf2l.checkpoint_utils import copy_model_directory, discover_checkpoint
from hf2l.hub_helpers import ROUND_FILE, SCHEMA_VERSION, SUBMISSION_FILE, make_api, utc_now, write_json
from hf2l.plugin_loader import load_local_plugin, parse_plugin_args, require_callable


def generic_model_card(repo_id: str) -> str:
    return textwrap.dedent(
        f"""\
        ---
        library_name: pytorch
        tags:
        - pytorch
        - federated-learning
        ---

        # Federated model

        Repository: `{repo_id}`

        This repository is managed by the `fed_avg_on_hf` sample workflow.
        Model weights are stored as SafeTensors.

        Each client must train from the exact same `main` commit for a round.
        Clients submit model updates through Hugging Face pull requests. The
        owner computes dataset-size-weighted FedAvg and publishes a new `main`
        commit. Do not merge a client PR directly: a PR contains one local
        model, not the aggregate.

        This is an educational proof of concept (POC). It does not implement
        secure aggregation, differential privacy, client authentication, or
        poisoning defenses.
        """
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-id", required=True, help="OWNER_OR_ORG/model-name")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--model-dir",
        type=Path,
        help="Existing HF-style directory containing config.json and SafeTensors weights",
    )
    source.add_argument(
        "--plugin",
        type=Path,
        help="Trusted local Python file defining initialize_model(output_dir, options)",
    )
    parser.add_argument(
        "--plugin-arg",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Plugin option; JSON values are decoded, and this option may be repeated",
    )
    parser.add_argument(
        "--private",
        action="store_true",
        help="Create a private repo; participants then need organization access",
    )
    parser.add_argument(
        "--token",
        help="Token override; prefer HF_TOKEN or `hf auth login` to avoid shell history",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        with tempfile.TemporaryDirectory(prefix="hf-fedavg-init-") as temporary:
            staging = Path(temporary) / "model"
            initialization: dict[str, object]
            if args.model_dir:
                copy_model_directory(args.model_dir, staging)
                initialization = {"source": "local_model_directory"}
            else:
                staging.mkdir()
                plugin = load_local_plugin(args.plugin)
                initialize_model = require_callable(plugin, "initialize_model")
                options = parse_plugin_args(args.plugin_arg)
                options["repo_id"] = args.repo_id
                result_metadata = initialize_model(staging, options)
                if result_metadata is None:
                    result_metadata = {}
                if not isinstance(result_metadata, dict):
                    raise ValueError(
                        "initialize_model(...) must return a metadata dictionary or None"
                    )
                json.dumps(result_metadata)
                initialization = {
                    "source": "trusted_local_plugin",
                    "plugin": args.plugin.name,
                    "metadata": result_metadata,
                }

            checkpoint = discover_checkpoint(staging)
            if (staging / SUBMISSION_FILE).exists():
                raise ValueError(f"Initial model directory must not contain {SUBMISSION_FILE}")
            if not (staging / "README.md").exists():
                (staging / "README.md").write_text(
                    generic_model_card(args.repo_id), encoding="utf-8"
                )
            write_json(
                staging / ROUND_FILE,
                {
                    "schema_version": SCHEMA_VERSION,
                    "round": 0,
                    "algorithm": "initial model",
                    "created_at": utc_now(),
                    "checkpoint_files": list(checkpoint.artifact_paths),
                    "initialization": initialization,
                    "submissions": [],
                },
            )

            api = make_api(args.token)
            repo_url = api.create_repo(
                repo_id=args.repo_id,
                repo_type="model",
                private=args.private,
                exist_ok=False,
            )
            result = api.upload_folder(
                repo_id=args.repo_id,
                repo_type="model",
                folder_path=staging,
                commit_message="Initialize FedAvg round 0",
            )

        print(f"Repository: {repo_url}")
        print(f"Initial main commit: {result.oid}")
        print("Give this repo ID and commit SHA to all participants.")
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
