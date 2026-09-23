"""Command-specific composition for Exchange API, workers, and administration."""
from __future__ import annotations

import argparse
import json
import logging
import time

log = logging.getLogger("hf2l_exchange.worker")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init-db", "migrate-db", "check-db", "check-storage", "serve", "worker", "repair-transfers", "export-contract"))
    parser.add_argument("--output-dir", help="Contract export directory (default: docs/generated)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--once", action="store_true", help="Worker: run one pass and exit")
    parser.add_argument("--attempt", action="append", default=[], metavar="ID",
                        help="Repair: select one attempt; repeat up to 100 times")
    parser.add_argument("--apply", action="store_true", help="Repair: apply selected repairs; default is a dry run")
    parser.add_argument("--writers-stopped", action="store_true",
                        help="Repair assertion: every API and worker process is stopped")
    parser.add_argument("--provider-quiesced", action="store_true",
                        help="Repair assertion: all in-flight provider mutations have finished or been fenced")
    parser.add_argument("--log-level", default="INFO", choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    args = parser.parse_args(argv)
    if args.output_dir is not None and args.command != "export-contract":
        parser.error("--output-dir requires export-contract")
    if args.workers < 1 or not 1 <= args.port <= 65535:
        parser.error("workers must be positive and port must be between 1 and 65535")
    repair_flags = args.attempt or args.apply or args.writers_stopped or args.provider_quiesced
    if repair_flags and args.command != "repair-transfers":
        parser.error("repair flags require the repair-transfers command")
    if args.command == "repair-transfers":
        if len(args.attempt) > 100 or len(args.attempt) != len(set(args.attempt)):
            parser.error("select at most 100 distinct attempt IDs")
        if any(not value or len(value) > 64 for value in args.attempt):
            parser.error("attempt IDs must contain between 1 and 64 characters")
        if args.apply and not (args.attempt and args.writers_stopped and args.provider_quiesced):
            parser.error("--apply requires explicit --attempt IDs, --writers-stopped and --provider-quiesced")
    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    if args.command == "export-contract":
        from .contracts import export_contracts
        for path in export_contracts(args.output_dir or "docs/generated"):
            print(path)
        return 0

    if args.command in {"init-db", "migrate-db", "check-db"}:
        from .config import DatabaseSettings
        from .models import database
        from .migrations import check, initialize, migrate
        engine, _ = database(DatabaseSettings.from_env())
        try:
            {"init-db": initialize, "migrate-db": migrate, "check-db": check}[args.command](engine)
        finally:
            engine.dispose()
        print("Exchange database revision is current")
        return 0

    if args.command == "repair-transfers":
        # Repair only changes ownership/retry state in the database. Provider I/O
        # remains the worker's responsibility after the operator restarts it.
        from .application import Service
        from .config import DatabaseSettings, Settings
        from .domain import ExchangeError
        from .migrations import check
        from .transfers import inspect_mutations, repair_mutations
        service = Service(Settings(database=DatabaseSettings.from_env()))
        try:
            check(service.engine)
            if args.attempt:
                result = repair_mutations(service, args.attempt, execute=args.apply,
                                          writers_stopped=args.writers_stopped,
                                          provider_quiesced=args.provider_quiesced)
            else:
                result = inspect_mutations(service)
            print(json.dumps(dict(result, dry_run=not args.apply), sort_keys=True))
            return 0
        except ExchangeError as exc:
            print(json.dumps({"error": {"code": exc.code, "detail": exc.detail}}))
            return 1
        except Exception as exc:
            log.error("repair inspection failed class=%s", type(exc).__name__)
            print(json.dumps({"error": {"code": "repair_unavailable"}}))
            return 1
        finally:
            service.engine.dispose()

    if args.command == "check-storage":
        from .config import StorageSettings
        from .storage import S3BlobStore
        S3BlobStore(StorageSettings.from_env()).check()
        print("Exchange storage is ready")
        return 0

    if args.command == "serve":
        import uvicorn
        uvicorn.run("hf2l_exchange.api:create_app", factory=True, host=args.host, port=args.port,
                    workers=args.workers, log_level=args.log_level.lower())
        return 0

    from .application import Service
    from .config import Settings
    from .storage import S3BlobStore
    from .transfers import TransferService
    from .worker import tick
    settings = Settings.from_env(component="worker")
    service = Service(settings)
    transfers = TransferService(service, S3BlobStore(settings.storage))
    failures = 0
    try:
        while True:
            try:
                result = tick(transfers)
                failures = 0
                log.info("worker pass %s", json.dumps(result))
            except Exception as exc:
                failures += 1
                log.error("worker pass failed class=%s consecutive=%d", type(exc).__name__, failures)
            if args.once:
                return 1 if failures else 0
            time.sleep(min(settings.worker.poll_seconds * 2 ** min(failures, 16), 300))
    except KeyboardInterrupt:
        return 0
    finally:
        service.engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
