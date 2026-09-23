#!/usr/bin/env python3
"""Initialize a model repository from a checkpoint or trusted local plugin."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import textwrap
from pathlib import Path

from hf2l.backends import add_store_arguments, make_store
from hf2l.core.protocol import AlgorithmSpec, RoundRecord
from hf2l.hub_helpers import (
    ROUND_FILE,
    SCHEMA_VERSION,
    SUBMISSION_FILE,
    artifact_hashes,
    utc_now,
    write_json,
)
from hf2l.plugin_loader import (
    load_plugin,
    parse_plugin_args,
    plugin_reference_name,
    require_callable,
)


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

        Each client must train from the exact same immutable base revision for
        a round. Clients publish isolated submissions. The owner computes
        dataset-size-weighted FedAvg and publishes a new `main` revision. A
        client submission contains one local model, not the aggregate.

        This is an educational proof of concept (POC). It does not implement
        secure aggregation, differential privacy, client authentication, or
        poisoning defenses.
        """
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
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
        help=(
            "Built-in plugin name (lenet or vgg-cifar10), or a trusted local Python "
            "file defining initialize_model(output_dir, options)"
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
        "--private",
        action="store_true",
        help="Create a private repo; participants then need organization access",
    )
    add_store_arguments(parser)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    store = None
    try:
        from hf2l.checkpoint_utils import copy_model_directory, discover_checkpoint

        with tempfile.TemporaryDirectory(prefix="hf-fedavg-init-") as temporary:
            staging = Path(temporary) / "model"
            initialization: dict[str, object]
            if args.model_dir:
                copy_model_directory(args.model_dir, staging)
                initialization = {"source": "local_model_directory"}
            else:
                staging.mkdir()
                plugin = load_plugin(args.plugin)
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
                json.dumps(result_metadata, allow_nan=False)
                initialization = {
                    "source": "trusted_local_plugin",
                    "plugin": plugin_reference_name(args.plugin),
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
                RoundRecord.from_dict({
                    "schema_version": SCHEMA_VERSION,
                    "backend": args.backend,
                    "round": 0,
                    "algorithm": "initial model",
                    "algorithm_spec": AlgorithmSpec("fedavg").to_dict(),
                    "created_at": utc_now(),
                    "checkpoint_files": list(checkpoint.artifact_paths),
                    "checkpoint_files_sha256": artifact_hashes(
                        staging, checkpoint.artifact_paths
                    ),
                    "initialization": initialization,
                    "submissions": [],
                }).to_dict(),
            )

            options_store = {"principal": args.local_principal} if getattr(args, "local_principal", None) else {}
            store = make_store(args.backend, args.token, args.endpoint, **options_store)
            result = store.initialize_repository(
                args.repo_id, staging, private=args.private
            )

        print(f"backend={args.backend}")
        if result.url:
            print(f"repository={result.url}")
        print(f"initial_main_revision={result.revision}")
        print("Give this repository ID and immutable revision to all participants.")
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if store is not None:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())
