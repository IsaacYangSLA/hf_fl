#!/usr/bin/env python3
"""Watch Exchange submissions and publish evaluated CIFAR-10 FedAvg rounds."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys

from common import load_round, run_hf2l


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--round-file", type=Path, required=True,
                        help="Demo descriptor supplying the Exchange endpoint and space; follows current main")
    parser.add_argument("--token-file", type=Path, required=True, help="Coordinator's token file")
    parser.add_argument("--eval-data", type=Path, required=True, help="Owner's held-out CIFAR-10 NPZ partition")
    parser.add_argument("--state-dir", type=Path, required=True,
                        help="Durable private owner directory; reuse the same path when restarting")
    parser.add_argument("--device", default="cpu", help="PyTorch device, for example cpu or cuda:0")
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--poll-interval", type=float, default=2.0,
                        help="Seconds between readiness checks (default: 2)")
    parser.add_argument("--max-backoff", type=float, default=300.0,
                        help="Maximum seconds between retry attempts (default: 300)")
    parser.add_argument("--max-rounds", type=int,
                        help="Exit after publishing this many rounds during this invocation")
    parser.add_argument("--once", action="store_true",
                        help="Check readiness once, publishing at most one ready round, then exit")
    parser.add_argument("--resolve-uncertain", choices=("published", "retry"),
                        help="After checking Exchange, confirm an uncertain publication or explicitly retry it")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        round_info = load_round(args.round_file)
        eval_data = args.eval_data.expanduser().resolve()
        if not eval_data.is_file() or eval_data.suffix.lower() != ".npz":
            raise ValueError(f"--eval-data must name an existing CIFAR-10 .npz file: {eval_data}")
        state_dir = args.state_dir.expanduser().absolute()
        if any(path.is_symlink() for path in (state_dir, *state_dir.parents)):
            raise ValueError("--state-dir must not contain symlinks")
        if state_dir.exists() and not state_dir.is_dir():
            raise ValueError("--state-dir must name a directory")
        if min(args.batch_size, args.threads) <= 0:
            raise ValueError("--batch-size and --threads must be positive")
        if not math.isfinite(args.poll_interval) or args.poll_interval <= 0:
            raise ValueError("--poll-interval must be finite and positive")
        if not math.isfinite(args.max_backoff) or args.max_backoff < args.poll_interval:
            raise ValueError("--max-backoff must be finite and at least --poll-interval")
        if args.max_rounds is not None and args.max_rounds <= 0:
            raise ValueError("--max-rounds must be positive")

        command = [
            "--role", "owner",
            "--backend", "exchange",
            "--repo-id", round_info["space_id"],
            "--reference", "main",
            "--state-dir", str(state_dir),
            "--minimum-participants", "2",
            "--weighting", "examples",
            "--array-backend", "numpy",
            "--accumulator-dtype", "float32",
            "--require-concurrent-publication",
            "--plugin", "vgg-cifar10",
            "--poll-interval", str(args.poll_interval),
            "--max-backoff", str(args.max_backoff),
        ]
        for key, value in {
            "eval_npz": str(eval_data), "batch_size": args.batch_size, "device": args.device,
        }.items():
            command.extend(("--plugin-arg", f"{key}={json.dumps(value, allow_nan=False)}"))
        if args.max_rounds is not None:
            command.extend(("--max-rounds", str(args.max_rounds)))
        if args.once:
            command.append("--once")
        if args.resolve_uncertain:
            command.extend(("--resolve-uncertain", args.resolve_uncertain))
        run_hf2l(
            "hf2l.cli.listen", command,
            token_file=args.token_file,
            endpoint=round_info["endpoint"],
            allow_local_http=round_info.get("allow_local_http", False),
            threads=args.threads,
            replace_process=True,
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
