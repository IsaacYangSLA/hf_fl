"""Run the exchange API and worker using environment configuration."""
import argparse
import json
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init-db", "serve", "worker", "check-storage"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
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
        uvicorn.run(create_app(settings), host=args.host, port=args.port)
    else:
        from .api import Service
        from .worker import tick
        service = Service(settings)
        service.storage.check()
        if args.command == "check-storage":
            print("Versioned exchange bucket is accessible")
            return
        while True:
            print(json.dumps(tick(service)), flush=True)
            if args.once:
                break
            time.sleep(5)


if __name__ == "__main__":
    main()
