"""Watch a global reference and run a trusted client plugin for new rounds."""

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
    parser.add_argument("--repo-id", required=True)
    parser.add_argument("--participant", required=True)
    parser.add_argument("--state-dir", type=Path, required=True,
                        help="Durable private directory for this client's state and round artifacts")
    parser.add_argument("--plugin", required=True,
                        help="Bundled plugin name or a trusted local Python file defining train_model")
    parser.add_argument("--plugin-arg", action="append", default=[], metavar="KEY=VALUE",
                        help="Training option; JSON values are decoded; may be repeated")
    parser.add_argument("--reference", default="main", help="Global model reference to watch (default: main)")
    parser.add_argument("--poll-interval", type=_positive_float, default=30.0,
                        help="Seconds between reference checks (default: 30)")
    parser.add_argument("--max-backoff", type=_positive_float, default=300.0,
                        help="Maximum seconds between retry attempts (default: 300)")
    parser.add_argument("--once", action="store_true",
                        help="Reconcile once, processing at most the current global model, then exit")
    parser.add_argument("--max-rounds", type=_positive_int,
                        help="Exit after submitting this many rounds during this invocation")
    parser.add_argument("--resolve-uncertain", choices=("submitted", "retry"),
                        help="After checking the backend, confirm a pending upload succeeded or explicitly retry it")
    add_store_arguments(parser)
    args = parser.parse_args(argv)
    if args.max_backoff < args.poll_interval:
        parser.error("--max-backoff must be at least --poll-interval")
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
    allowed = {"event", "status", "base_revision", "revision", "submission_revision",
               "job_id", "round", "source_round", "attempt", "delay", "retry_seconds", "error_type"}
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
    from hf2l.listener.client import ClientListener, ListenerStateError, UncertainSubmission

    store = None
    try:
        with _interrupt_on_termination():
            options = parse_plugin_args(args.plugin_arg)
            options["participant"] = args.participant
            plugin = load_plugin(args.plugin)
            train_model = require_callable(plugin, "train_model")
            training_id = _training_id(args.plugin, plugin, options)
            store = make_store(args.backend, args.token, args.endpoint, principal=args.local_principal)
            with ClientListener(store=store, repo_id=args.repo_id, participant=args.participant,
                                state_dir=args.state_dir, source_id=_source_id(store), training_id=training_id,
                                train_model=train_model, options=options, reference=args.reference,
                                on_event=_print_event) as listener:
                if args.resolve_uncertain:
                    listener.resolve_uncertain(args.resolve_uncertain)
                listener.run(poll_interval=args.poll_interval, max_backoff=args.max_backoff,
                             once=args.once, max_rounds=args.max_rounds)
        return 0
    except KeyboardInterrupt:
        _print_event({"event": "stopped"})
        return 130
    except UncertainSubmission as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ListenerStateError as exc:
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
