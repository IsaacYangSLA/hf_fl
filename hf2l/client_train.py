#!/usr/bin/env python3
"""Run download, a trusted local training plugin, and checkpoint submission."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

from hf2l.recovery import TrainingCancelled, TrainingPaused
from hf2l.recovery_client import add_recovery_arguments, make_recovery, source_identity
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
            "Built-in plugin name (lenet, vgg-cifar10, or kubernetes), or a trusted local Python "
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
    add_recovery_arguments(parser)
    return parser.parse_args(argv)


def _reuse_submitted_output(recovery, work_dir, trained_dir):
    from hf2l.client_steps import SUBMISSION_FILE

    sidecar = trained_dir / SUBMISSION_FILE
    if not (sidecar.exists() or sidecar.is_symlink()):
        return None
    ready = recovery.ready_result()
    if ready is None:
        raise ValueError("Submission metadata exists without a verified saved training result")
    intent = work_dir / "client-publication-intent.json"
    for record in (sidecar, intent):
        if record.is_symlink() or not record.is_file() or record.stat().st_size > 1024 * 1024:
            raise ValueError("Invalid saved submission metadata")
    if json.loads(sidecar.read_bytes()) != json.loads(intent.read_bytes()):
        raise ValueError("Saved submission metadata differs from its publication intent")

    expected = {
        path.relative_to(ready.output_dir): path
        for path in ready.output_dir.rglob("*") if path.is_file()
    }
    observed = set()
    if trained_dir.is_symlink():
        raise ValueError("Saved trained model cannot be a symlink")
    for path in trained_dir.rglob("*"):
        if path.is_symlink():
            raise ValueError("Saved trained model contains a symlink")
        if path.is_dir() or path == sidecar:
            continue
        relative = path.relative_to(trained_dir)
        source = expected.get(relative)
        if source is None or not path.is_file() or path.stat().st_size != source.stat().st_size:
            raise ValueError("Saved trained model differs from the verified training result")
        with path.open("rb") as actual, source.open("rb") as original:
            if hashlib.file_digest(actual, "sha256").digest() != hashlib.file_digest(original, "sha256").digest():
                raise ValueError("Saved trained model differs from the verified training result")
        observed.add(relative)
    if observed != expected.keys():
        raise ValueError("Saved trained model is missing verified files")
    return ready.metadata


def _publish_recovered(store, round_store, work_dir, trained_dir, participant, context, count, metadata):
    intent = work_dir / "client-publication-intent.json"
    receipt = work_dir / "client-publication-receipt.json"
    with round_store.supervise():
        if receipt.is_symlink():
            raise ValueError("Saved submission receipt cannot be a symlink")
        if receipt.exists():
            saved = json.loads(receipt.read_bytes())
            digest = hashlib.sha256(intent.read_bytes()).hexdigest()
            if saved["intent_sha256"] != digest:
                raise ValueError("Saved submission receipt belongs to a different result")
            return argparse.Namespace(**saved["result"]), json.loads(intent.read_bytes())

        result = None
        if callable(getattr(store, "reconcile_submission", None)):
            result, submission = upload_client_update(
                store, work_dir, trained_dir, participant, count, metadata, _reconcile_only=True,
            )
        elif intent.exists() or intent.is_symlink():
            raise ValueError("Earlier submission outcome is unknown and requires explicit reconciliation")
        if result is None:
            current = store.resolve_reference(context["repo_id"], "main").revision
            if current != context["base_revision"]:
                raise ValueError("Shared model advanced before this result could be submitted")
            result, submission = upload_client_update(
                store, work_dir, trained_dir, participant, count, metadata,
            )

        record = {"intent_sha256": hashlib.sha256(intent.read_bytes()).hexdigest(),
                  "result": asdict(result)}
        descriptor, temporary = tempfile.mkstemp(prefix=".hf2l-receipt-", dir=work_dir)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(record, stream, allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, receipt)
            directory = os.open(work_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return result, submission


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
        recovery = None
        if args.recovery_root is not None or args.recovery_config is not None:
            if args.workflow != "fedavg" or args.source_kind != "global":
                raise ValueError("Recovery requires a shared global model in a FedAvg round")
            recovery = make_recovery(args, plugin, source_identity(store))
        work_dir = args.work_dir.resolve()
        if recovery is not None and (work_dir / "base_model").exists():
            from hf2l.listener.workflow import _validate_base

            saved_context, _, _ = _validate_base(work_dir)
            context = saved_context.to_dict()
            if saved_context.repo_id != args.repo_id or context.get("backend", store.name) != store.name:
                raise ValueError("Saved workspace belongs to a different model source")
            if args.base_revision != saved_context.base_revision:
                reference = store.resolve_reference(args.repo_id, args.base_revision)
                if reference.revision != saved_context.base_revision:
                    raise ValueError("Saved workspace belongs to a different starting model")
        else:
            context = download_client_round(
                store, args.repo_id, args.base_revision, args.work_dir,
                workflow=args.workflow, source_kind=args.source_kind,
                source_participant=args.source_participant,
            )
        trained_dir = work_dir / "trained_model"
        trainer = train_model if recovery is None else recovery
        round_store = recovery.store(work_dir, options) if recovery is not None else None
        if round_store is not None and round_store.ready_result() is None:
            current = store.resolve_reference(args.repo_id, "main").revision
            if current != context["base_revision"]:
                recovery.cancel_obsolete(work_dir, options)
                raise ValueError("Shared model advanced before this round could resume")
        try:
            result_metadata = None if round_store is None else _reuse_submitted_output(round_store, work_dir, trained_dir)
            if result_metadata is None:
                with plugin_stdout_to_stderr():
                    result_metadata = trainer(work_dir / "base_model", trained_dir, options)
        except TrainingPaused as exc:
            if recovery is None:
                raise
            print(f"Training paused after saved step {exc.completed_steps}", file=sys.stderr)
            return 2
        except TrainingCancelled:
            if recovery is None:
                raise
            print("Training cancelled", file=sys.stderr)
            return 2
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

        if round_store is None:
            result, submission = upload_client_update(
                store,
                work_dir,
                trained_dir,
                args.participant,
                num_examples,
                result_metadata,
            )
        else:
            result, submission = _publish_recovered(
                store, round_store, work_dir, trained_dir, args.participant,
                context, num_examples, result_metadata,
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
