"""Watch for client work or ready owner rounds with a durable listener."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import math
from pathlib import Path
import signal
import sys
import threading
from urllib.parse import urlsplit, urlunsplit

from hf2l.backends import add_store_arguments, make_store
from hf2l.plugin_loader import load_plugin, parse_plugin_args, require_callable


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive finite number") from exc
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite number")
    return number


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("client", "owner"), default="client",
                        help="Train client updates or aggregate ready owner rounds (default: client)")
    parser.add_argument("--repo-id", required=True)
    parser.add_argument("--participant", help="Client participant identity; required for --role client")
    parser.add_argument("--state-dir", type=Path, required=True,
                        help="Durable private directory for this listener's state and round artifacts")
    parser.add_argument("--plugin",
                        help="Trusted training plugin for clients, or optional evaluation plugin for owners")
    parser.add_argument("--plugin-arg", action="append", default=[], metavar="KEY=VALUE",
                        help="Training or evaluation option; JSON values are decoded; may be repeated")
    parser.add_argument("--reference", default="main", help="Global model reference to watch (default: main)")
    parser.add_argument("--poll-interval", type=_positive_float, default=30.0,
                        help="Seconds between reference checks (default: 30)")
    parser.add_argument("--max-backoff", type=_positive_float, default=300.0,
                        help="Maximum seconds between retry attempts (default: 300)")
    parser.add_argument("--once", action="store_true",
                        help="Reconcile once, processing at most one round, then exit")
    parser.add_argument("--max-rounds", type=_positive_int,
                        help="Exit after this many client submissions or owner publications in this invocation")
    parser.add_argument("--resolve-uncertain", choices=("submitted", "published", "retry"),
                        help="After checking the backend, confirm the pending operation or explicitly retry it")
    owner = parser.add_argument_group("owner aggregation options")
    owner.add_argument("--minimum-participants", type=_positive_int, default=2,
                       help="Minimum eligible clients from the current immutable base (default: 2)")
    owner.add_argument("--weighting", choices=("examples", "uniform"), default="examples")
    owner.add_argument("--allowlist", type=Path,
                       help="JSON mapping approved repository identities to participant IDs")
    owner.add_argument("--array-backend", choices=("numpy", "torch"), default="numpy")
    owner.add_argument("--accumulator-dtype", choices=("float32", "float64"), default="float32")
    owner.add_argument("--claim-lease-seconds", type=_positive_int, default=3600,
                       help="Exchange claim lease duration, from 10 to 3600 seconds (default: 3600)")
    owner.add_argument("--require-concurrent-publication", action="store_true",
                       help="Reject a backend without atomic conditional publication")
    add_store_arguments(parser)
    args = parser.parse_args(argv)
    if args.max_backoff < args.poll_interval:
        parser.error("--max-backoff must be at least --poll-interval")
    if args.role == "client":
        if not args.participant or not args.plugin:
            parser.error("--role client requires --participant and --plugin")
        if args.resolve_uncertain == "published":
            parser.error("--role client recovery requires submitted or retry")
    else:
        if args.participant is not None:
            parser.error("--participant applies only to --role client")
        if args.reference != "main":
            parser.error("--role owner currently requires --reference main")
        if args.resolve_uncertain == "submitted":
            parser.error("--role owner recovery requires published or retry")
        if args.minimum_participants < 2:
            parser.error("--minimum-participants must be at least 2")
        if not 10 <= args.claim_lease_seconds <= 3600:
            parser.error("--claim-lease-seconds must be between 10 and 3600")
    if args.plugin_arg and not args.plugin:
        parser.error("--plugin-arg requires --plugin")
    return args


def _source_id(store) -> str:
    """Bind state to the constructed store's effective location and local identity.

    Factory defaults and environment configuration have already been resolved by
    this point. Credentials are deliberately absent from the location identity.
    The listener hashes this description before persisting it.
    """
    identity = {"backend": store.name}
    if store.name == "local":
        identity.update(root=str(Path(store.root).resolve()), principal=store.principal)
    else:
        if store.name == "exchange":
            endpoint = store.client.endpoint
        else:
            endpoint = store.api.endpoint
        parts = urlsplit(endpoint)
        # A password or token in a URL must neither identify a repository nor be
        # retained in listener state. Provider endpoints identify their API path.
        authority = parts.netloc.rsplit("@", 1)[-1].lower()
        identity["endpoint"] = urlunsplit((parts.scheme.lower(), authority,
                                            parts.path.rstrip("/"), "", ""))
    return json.dumps(identity, sort_keys=True, separators=(",", ":"))


def _training_id(reference, plugin, options) -> str:
    """Hash plugin content and configuration without retaining option secrets."""
    path = getattr(plugin, "__file__", None)
    if not path:
        raise ValueError("The training plugin must have a source file")
    source = Path(path).resolve()
    identity = {"plugin": str(reference), "source": str(source),
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "options": options}
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _print_event(event: dict) -> None:
    # Raw provider errors can contain signed URLs or credentials. Only the
    # listener's operational fields are suitable for machine-readable output.
    allowed = {"event", "status", "role", "base_revision", "revision", "submission_revision",
               "job_id", "round", "source_round", "attempt", "delay", "retry_seconds", "error_type",
               "eligible_count", "minimum_participants"}
    safe = {key: value for key, value in event.items()
            if key in allowed and (value is None or isinstance(value, (str, int, float, bool)))}
    print(json.dumps(safe, sort_keys=True, allow_nan=False), flush=True)


@contextmanager
def _interrupt_on_termination():
    """Let normal context/finally cleanup handle SIGTERM as well as Ctrl-C."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = signal.getsignal(signal.SIGTERM)

    def stop(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    # Import the engine and load optional providers/plugins only after parsing;
    # every backend's --help works in an installation with base dependencies.
    from hf2l.listener.engine import ListenerStateError, UncertainOperation

    state_errors = (ListenerStateError,)
    uncertain_errors = (UncertainOperation,)
    if args.role == "client":
        from hf2l.listener.client import ClientListener, ListenerStateError as ClientStateError, UncertainSubmission
        # Keep the existing client module's public error and composition points.
        state_errors += (ClientStateError,)
        uncertain_errors += (UncertainSubmission,)
    else:
        from hf2l.listener.owner import OwnerListener
        from hf2l.round.config import RoundConfig

    store = None
    try:
        with _interrupt_on_termination():
            options = parse_plugin_args(args.plugin_arg)
            if args.role == "client":
                options["participant"] = args.participant
                plugin = load_plugin(args.plugin)
                train_model = require_callable(plugin, "train_model")
                training_id = _training_id(args.plugin, plugin, options)
            elif args.plugin:
                plugin = load_plugin(args.plugin)
                require_callable(plugin, "evaluate_model")
                configuration_id = _training_id(args.plugin, plugin, options)
            else:
                configuration_id = "fedavg"
            store = make_store(args.backend, args.token, args.endpoint, principal=args.local_principal)
            if args.role == "client":
                listener = ClientListener(store=store, repo_id=args.repo_id, participant=args.participant,
                                          state_dir=args.state_dir, source_id=_source_id(store), training_id=training_id,
                                          train_model=train_model, options=options, reference=args.reference,
                                          on_event=_print_event)
            else:
                config = RoundConfig(
                    repo_id=args.repo_id, output_dir=args.state_dir / "unused",
                    selection="discover", publish=True,
                    minimum_participants=args.minimum_participants, weighting=args.weighting,
                    allowlist=args.allowlist, array_backend=args.array_backend,
                    accumulator_dtype=args.accumulator_dtype, plugin=args.plugin,
                    plugin_arg=tuple(args.plugin_arg), claim_lease_seconds=args.claim_lease_seconds,
                    require_concurrent_publication=args.require_concurrent_publication,
                )
                listener = OwnerListener(store=store, config=config, state_dir=args.state_dir,
                                         source_id=_source_id(store), configuration_id=configuration_id,
                                         on_event=_print_event)
            with listener:
                if args.resolve_uncertain:
                    listener.resolve_uncertain(args.resolve_uncertain)
                listener.run(poll_interval=args.poll_interval, max_backoff=args.max_backoff,
                             once=args.once, max_rounds=args.max_rounds)
        return 0
    except KeyboardInterrupt:
        _print_event({"event": "stopped"})
        return 130
    except uncertain_errors as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except state_errors as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"error: listener failed ({type(exc).__name__})", file=sys.stderr)
        return 1
    finally:
        if store is not None:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())
