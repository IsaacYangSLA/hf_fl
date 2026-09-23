#!/usr/bin/env python3
"""Claim two CIFAR-10 updates, publish their FedAvg, and describe the next round."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import subprocess
import sys

from common import load_round, run_hf2l, write_json_exclusive


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--round-file", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True, help="Coordinator's token file")
    parser.add_argument("--eval-data", type=Path, required=True, help="Owner's held-out CIFAR-10 NPZ partition")
    parser.add_argument("--output-dir", type=Path, required=True, help="A new directory for this aggregation attempt")
    parser.add_argument(
        "--run-state", type=Path,
        help="Recovery state to reuse after a failed attempt; defaults to <output-dir>.run-state.json",
    )
    parser.add_argument("--device", default="cpu", help="PyTorch device, for example cpu or cuda:0")
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--threads", type=int, default=2)
    return parser.parse_args(argv)


def verify_result(result: dict, round_info: dict) -> tuple[str, list[dict], float]:
    """Check the persisted application outcome before creating another round file."""
    if result.get("status") != "published" or result.get("backend") != "exchange":
        raise ValueError("The owner result does not confirm publication to Exchange")
    base = result.get("base")
    if not isinstance(base, dict) or base.get("revision") != round_info["base_revision"]:
        raise ValueError("The owner result used a different immutable base revision")
    if result.get("round_number") != round_info["round_number"]:
        raise ValueError("The owner result has an unexpected round number")
    eligible = result.get("eligible")
    if (
        not isinstance(eligible, list)
        or len(eligible) != 2
        or any(not isinstance(item, dict) for item in eligible)
        or {item.get("participant") for item in eligible} != {"client1", "client2"}
    ):
        raise ValueError("The owner result must contain exactly client1 and client2")
    for item in eligible:
        if type(item.get("num_examples")) is not int or item["num_examples"] <= 0:
            raise ValueError("The owner result must report positive integer sample counts")
        coefficient = item.get("coefficient")
        if (
            type(coefficient) not in (int, float)
            or not math.isfinite(coefficient)
            or not 0 < coefficient <= 1
        ):
            raise ValueError("The owner result has an invalid FedAvg coefficient")
    if not math.isclose(sum(item["coefficient"] for item in eligible), 1.0, rel_tol=1e-9, abs_tol=1e-9):
        raise ValueError("The owner result's FedAvg coefficients must sum to one")
    total_examples = sum(item["num_examples"] for item in eligible)
    if any(
        not math.isclose(item["coefficient"], item["num_examples"] / total_examples,
                         rel_tol=1e-9, abs_tol=1e-9)
        for item in eligible
    ):
        raise ValueError("The owner result's FedAvg coefficients do not match its sample counts")
    publication = result.get("publication")
    revision = None
    if isinstance(publication, dict):
        revision = publication.get("resolved_revision") or publication.get("revision")
    if not isinstance(revision, str) or not revision or revision == round_info["base_revision"]:
        raise ValueError("The owner result has no new immutable publication revision")
    evaluation = result.get("evaluation")
    accuracy = evaluation.get("accuracy") if isinstance(evaluation, dict) else None
    if type(accuracy) not in (int, float) or not math.isfinite(accuracy) or not 0 <= accuracy <= 1:
        raise ValueError("The owner result has no valid held-out accuracy")
    return revision, eligible, float(accuracy)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    owner_completed = False
    try:
        round_info = load_round(args.round_file)
        eval_data = args.eval_data.expanduser().resolve()
        if not eval_data.is_file() or eval_data.suffix.lower() != ".npz":
            raise ValueError(f"--eval-data must name an existing CIFAR-10 .npz file: {eval_data}")
        output_dir = args.output_dir.expanduser().absolute()
        if output_dir.exists() or output_dir.is_symlink():
            raise ValueError(f"--output-dir must be a new path; preserve previous attempts: {output_dir}")
        if min(args.batch_size, args.threads) <= 0:
            raise ValueError("--batch-size and --threads must be positive")
        run_state = (
            args.run_state.expanduser().absolute() if args.run_state
            else output_dir.with_name(output_dir.name + ".run-state.json")
        )
        command = [
            "--backend", "exchange",
            "--repo-id", round_info["space_id"],
            "--expected-base-revision", round_info["base_revision"],
            "--claim-submissions",
            "--minimum-participants", "2",
            "--weighting", "examples",
            "--array-backend", "numpy",
            "--accumulator-dtype", "float32",
            "--require-concurrent-publication",
            "--publish",
            "--output-dir", str(output_dir),
            "--run-state", str(run_state),
            "--plugin", "vgg-cifar10",
        ]
        for key, value in {
            "eval_npz": str(eval_data), "batch_size": args.batch_size, "device": args.device,
        }.items():
            command.extend(("--plugin-arg", f"{key}={json.dumps(value)}"))
        run_hf2l(
            "hf2l.owner_fedavg", command,
            token_file=args.token_file,
            endpoint=round_info["endpoint"],
            allow_local_http=round_info.get("allow_local_http", False),
            threads=args.threads,
        )
        owner_completed = True
        result = json.loads((output_dir / "result.json").read_text(encoding="utf-8"))
        if not isinstance(result, dict):
            raise ValueError("The owner result must be a JSON object")
        revision, eligible, accuracy = verify_result(result, round_info)
        next_round = {**round_info, "base_revision": revision, "round_number": round_info["round_number"] + 1}
        next_round_path = output_dir / "next-round.json"
        write_json_exclusive(next_round_path, next_round)
        for item in sorted(eligible, key=lambda item: item["participant"]):
            print(f"{item['participant']}: coefficient={item['coefficient']:.6f}")
        print(f"held_out_accuracy={accuracy:.4%}")
        print(f"new_base_revision={revision}")
        print(f"next_round_file={next_round_path}")
        return 0
    except subprocess.CalledProcessError as exc:
        print(
            f"Owner command failed (exit {exc.returncode}). Preserve its output and run-state files. "
            "Check the publication outcome before retrying with the same run-state and a new output directory.",
            file=sys.stderr,
        )
        return 1
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        if owner_completed:
            print(
                "The owner command already completed and may have published. Preserve its result and "
                "reconcile the current Exchange reference before starting another aggregation.",
                file=sys.stderr,
            )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
