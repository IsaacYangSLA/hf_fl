"""Run the exchange API and worker using environment configuration."""
import argparse
import json
import logging
import time

log = logging.getLogger("hf2l.exchange.worker")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init-db", "serve", "worker", "check-storage"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--once", action="store_true", help="Worker only: run a single pass and exit")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()
    logging.basicConfig(level=args.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    from .config import Settings
    settings = Settings.from_env()
    if args.command == "init-db":
        from .models import Base, database
        engine, _ = database(settings.database_url)
        Base.metadata.create_all(engine)
        engine.dispose()
        print("Exchange schema v1 initialized")
    elif args.command == "serve":
        import uvicorn
        from .api import create_app
        uvicorn.run(create_app(settings), host=args.host, port=args.port, log_level=args.log_level.lower())
    else:
        from .api import Service
        from .worker import tick
        service = Service(settings)
        service.storage.check()
        if args.command == "check-storage":
            print("Versioned exchange bucket is accessible")
            return
        failures = 0
        while True:
            try:
                counts = tick(service)
                failures = 0
                log.info("tick %s", json.dumps(counts))
            except Exception:
                # A database or storage outage must not turn into a supervisor restart storm.
                failures += 1
                log.exception("worker tick failed (%d consecutive)", failures)
            if args.once:
                break
            time.sleep(min(settings.worker_interval * 2 ** failures, 300))


if __name__ == "__main__":
    main()
