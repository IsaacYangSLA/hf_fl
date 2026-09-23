#!/usr/bin/env python3
"""Train one CIFAR-10 participant and submit its update to Exchange."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import subprocess
import sys

from common import load_round, run_hf2l


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--round-file", type=Path, required=True)
    parser.add_argument("--participant", choices=("client1", "client2"), required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, required=True, help="This client's CIFAR-10 NPZ partition")
    parser.add_argument("--work-dir", type=Path, required=True, help="A new directory for this training attempt")
    parser.add_argument("--epochs", type=int, default=1)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--learning-rate", type=float, default=0.01)
    parser.add_argument("--device", default="cpu", help="PyTorch device, for example cpu or cuda:0")
    parser.add_argument("--threads", type=int, default=2)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        round_info = load_round(args.round_file)
        dataset = args.dataset.expanduser().resolve()
        if not dataset.is_file() or dataset.suffix.lower() != ".npz":
            raise ValueError(f"--dataset must name an existing CIFAR-10 .npz file: {dataset}")
        work_dir = args.work_dir.expanduser().absolute()
        if work_dir.exists() or work_dir.is_symlink():
            raise ValueError(f"--work-dir must be a new path; preserve previous attempts: {work_dir}")
        if min(args.epochs, args.batch_size, args.threads) <= 0:
            raise ValueError("--epochs, --batch-size, and --threads must be positive")
        if not math.isfinite(args.learning_rate) or args.learning_rate <= 0:
            raise ValueError("--learning-rate must be finite and positive")

        command = [
            "--backend", "exchange",
            "--repo-id", round_info["space_id"],
            "--base-revision", round_info["base_revision"],
            "--participant", args.participant,
            "--work-dir", str(work_dir),
            "--plugin", "vgg-cifar10",
        ]
        options = {
            "dataset_npz": str(dataset),
            "epochs": args.epochs,
            "batch_size": args.batch_size,
            "learning_rate": args.learning_rate,
            "device": args.device,
        }
        for key, value in options.items():
            command.extend(("--plugin-arg", f"{key}={json.dumps(value)}"))
        run_hf2l(
            "hf2l.client_train", command,
            token_file=args.token_file,
            endpoint=round_info["endpoint"],
            allow_local_http=round_info.get("allow_local_http", False),
            threads=args.threads,
        )
        return 0
    except subprocess.CalledProcessError as exc:
        print(
            f"Client command failed (exit {exc.returncode}). Preserve its work directory; "
            "inspect the submission state before starting another training attempt.",
            file=sys.stderr,
        )
        return 1
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
