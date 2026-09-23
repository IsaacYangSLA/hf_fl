#!/usr/bin/env python3
"""Run an isolated, temporary Exchange service for the two-client CIFAR-10 demo.

Keep this process running in its own terminal. Ctrl-C stops its API, worker and
optional Moto subprocess, and deletes only the unique S3 bucket it created.
Database, token files and logs remain for inspection; a stopped run cannot be
resumed. Start each run with a fresh work directory. Tokens expire after the
configured lifetime and this fixture does not offer token refresh.

Moto exercises HTTP transfers, but does not prove S3 authorization or provider
versioning conformance. Use --s3-endpoint for an existing authenticated provider.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import Any
import uuid


ISSUER = "https://hf2l-cifar10-demo.example.test"
AUDIENCE = "exchange-cifar10-demo"


class StopRequested(Exception):
    """A termination signal was received during startup."""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True,
                        help="New or empty directory; contains private tokens, SQLite and logs")
    storage = parser.add_mutually_exclusive_group(required=True)
    storage.add_argument("--emulated-storage", action="store_true",
                         help="Run local Moto for a functional demo, not provider/auth conformance")
    storage.add_argument("--s3-endpoint",
                         help="Existing S3 endpoint; uses the normal AWS credential provider chain")
    parser.add_argument("--s3-region", help="S3 region; defaults to AWS configuration or us-east-1")
    parser.add_argument("--port", type=int, default=8765, help="Loopback API port (default: 8765)")
    parser.add_argument("--storage-port", type=int, default=8766,
                        help="Loopback Moto port with --emulated-storage (default: 8766)")
    parser.add_argument("--token-ttl-hours", type=int, default=24,
                        help="Local token lifetime, 1 to 168 hours (default: 24); no refresh")
    args = parser.parse_args(argv)
    for name in ("port", "storage_port"):
        if not 1 <= getattr(args, name) <= 65535:
            parser.error("ports must be between 1 and 65535")
    if args.emulated_storage and args.port == args.storage_port:
        parser.error("API and emulated storage ports must differ")
    if not 1 <= args.token_ttl_hours <= 168:
        parser.error("--token-ttl-hours must be between 1 and 168")
    return args


def check_port(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        try:
            listener.bind(("127.0.0.1", port))
        except OSError as exc:
            raise RuntimeError(f"Loopback port {port} is unavailable; select a different port") from exc


def private_json(path: Path, value: dict[str, Any]) -> None:
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2)
        output.write("\n")
    path.chmod(0o600)


class Processes:
    def __init__(self, work: Path, env: dict[str, str], stopped: threading.Event):
        self.work, self.env, self.stopped = work, env, stopped
        self.logs = ExitStack()
        self.children: list[tuple[str, subprocess.Popen]] = []
        self.background: list[tuple[str, subprocess.Popen]] = []

    def start(self, name: str, command: list[str], *, background: bool = True) -> subprocess.Popen:
        log = self.logs.enter_context((self.work / f"{name}.log").open("x", encoding="utf-8"))
        child = subprocess.Popen(command, env=self.env, stdout=log, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, start_new_session=True)
        self.children.append((name, child))
        if background:
            self.background.append((name, child))
        return child

    def check(self) -> None:
        if self.stopped.is_set():
            raise StopRequested()
        for name, child in self.background:
            if child.poll() is not None:
                raise RuntimeError(f"{name} exited ({child.returncode}); inspect {self.work / (name + '.log')}")

    def run_cli(self, command: str) -> None:
        child = self.start(command, [sys.executable, "-m", "hf2l_exchange.cli", command], background=False)
        deadline = time.monotonic() + 90
        while child.poll() is None:
            self.check()
            if time.monotonic() >= deadline:
                raise RuntimeError(f"{command} timed out; inspect {self.work / (command + '.log')}")
            self.stopped.wait(0.1)
        self.check()
        if child.returncode:
            raise RuntimeError(f"{command} failed; inspect {self.work / (command + '.log')}")

    def stop(self, *, except_names: tuple[str, ...] = ()) -> None:
        for name, child in reversed(self.children):
            if name in except_names or child.poll() is not None:
                continue
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=10)


def await_http(processes: Processes, endpoint: str, path: str, timeout: int = 60) -> None:
    import httpx

    deadline = time.monotonic() + timeout
    with httpx.Client(timeout=2, trust_env=False) as client:
        while time.monotonic() < deadline:
            processes.check()
            try:
                if client.get(endpoint + path).status_code == 200:
                    return
            except httpx.TransportError:
                pass
            processes.stopped.wait(0.2)
    raise RuntimeError(f"Service readiness timed out: {endpoint}{path}; inspect logs in {processes.work}")


def cleanup_bucket(s3: Any, bucket: str) -> None:
    """Delete only this invocation's newly created bucket and its contents."""
    for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
        for upload in page.get("Uploads", []):
            s3.abort_multipart_upload(Bucket=bucket, Key=upload["Key"], UploadId=upload["UploadId"])
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for item in page.get("Versions", []) + page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=bucket, Key=item["Key"], VersionId=item["VersionId"])
    s3.delete_bucket(Bucket=bucket)


def run(args: argparse.Namespace) -> int:
    # Optional dependencies are intentionally imported after argument parsing so
    # --help works before installing the Exchange server and emulator extras.
    import boto3
    from botocore.config import Config
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import jwt
    from hf2l_exchange.transfer_client import require_tls

    if args.emulated_storage:
        import moto.server  # noqa: F401 - fail before allocating anything if unavailable

    endpoint = f"http://127.0.0.1:{args.port}"
    storage_endpoint = (f"http://127.0.0.1:{args.storage_port}" if args.emulated_storage else args.s3_endpoint)
    require_tls(storage_endpoint, allow_local_http=True)
    check_port(args.port)
    if args.emulated_storage:
        check_port(args.storage_port)
    work = args.work_dir.expanduser().absolute()
    if work.is_symlink():
        raise ValueError("--work-dir must not be a symlink")
    if work.exists() and (not work.is_dir() or any(work.iterdir())):
        raise ValueError("--work-dir must be new or empty; this ephemeral service cannot reuse a prior database")
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    work.chmod(0o700)
    env = {key: value for key, value in os.environ.items() if not key.startswith("EXCHANGE_")}
    if args.emulated_storage:
        from botocore.session import Session as BotocoreSession

        env = {key: value for key, value in env.items() if not key.startswith("AWS_")}
        env.update(AWS_ACCESS_KEY_ID="hf2l-demo", AWS_SECRET_ACCESS_KEY="local-emulator-only",
                   AWS_DEFAULT_REGION="us-east-1", AWS_EC2_METADATA_DISABLED="true",
                   AWS_CONFIG_FILE=os.devnull, AWS_SHARED_CREDENTIALS_FILE=os.devnull,
                   BOTO_CONFIG=os.devnull)
        # Explicit keys alone do not isolate boto3: it still resolves the
        # ambient AWS_PROFILE and configuration files before creating clients.
        # Override this session's config store without changing the caller's
        # environment or the normal provider chain used by external S3 mode.
        core_session = BotocoreSession()
        config_store = core_session.get_component("config_store")
        for name, value in (("profile", None), ("config_file", os.devnull), ("credentials_file", os.devnull)):
            config_store.set_config_variable(name, value)
        session = boto3.Session(aws_access_key_id="hf2l-demo", aws_secret_access_key="local-emulator-only",
                                region_name=args.s3_region or "us-east-1", botocore_session=core_session)
    else:
        session = boto3.Session(region_name=args.s3_region)
    region = session.region_name or "us-east-1"
    bucket = "hf2l-cifar10-demo-" + uuid.uuid4().hex
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    now = int(time.time())
    identities = {}
    for subject in ("owner", "client1", "client2"):
        token_path = work / (subject + ".token")
        token = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": subject, "iat": now,
                            "exp": now + args.token_ttl_hours * 3600, "scope": "exchange"},
                           key, algorithm="RS256", headers={"typ": "at+jwt"})
        with token_path.open("x", encoding="utf-8") as output:
            output.write(token + "\n")
        token_path.chmod(0o600)
        identities[subject] = {"subject": subject, "token_file": str(token_path)}
    env.update(EXCHANGE_DATABASE_URL="sqlite:///" + str(work / "exchange.db"),
               EXCHANGE_ISSUER=ISSUER, EXCHANGE_AUDIENCE=AUDIENCE,
               EXCHANGE_ADMIN_SUBJECT="owner", EXCHANGE_JWT_PUBLIC_KEY=public_key,
               EXCHANGE_ALLOW_LOCAL_HTTP="true", EXCHANGE_S3_ENDPOINT=storage_endpoint,
               EXCHANGE_S3_BUCKET=bucket, EXCHANGE_S3_PREFIX="demo/", EXCHANGE_S3_REGION=region,
               EXCHANGE_WORKER_POLL_SECONDS="1", PYTHONUNBUFFERED="1")
    stopped = threading.Event()
    original_handlers = {sig: signal.signal(sig, lambda *_: stopped.set()) for sig in (signal.SIGINT, signal.SIGTERM)}
    processes = Processes(work, env, stopped)
    s3 = None
    bucket_created = False
    exit_code = 0
    private_json(work / "runtime.json", {"bucket": bucket, "storage_endpoint": storage_endpoint,
                                         "token_expires_at": now + args.token_ttl_hours * 3600,
                                         "ephemeral": True})
    try:
        if args.emulated_storage:
            processes.start("storage", [sys.executable, "-m", "moto.server", "-H", "127.0.0.1",
                                         "-p", str(args.storage_port)])
            await_http(processes, storage_endpoint, "/")
        s3 = session.client("s3", endpoint_url=storage_endpoint, region_name=region,
                            config=Config(signature_version="s3v4", connect_timeout=3, read_timeout=10,
                                          retries={"max_attempts": 2}))
        create_options: dict[str, Any] = {"Bucket": bucket}
        if region != "us-east-1":
            create_options["CreateBucketConfiguration"] = {"LocationConstraint": region}
        s3.create_bucket(**create_options)
        bucket_created = True
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
        processes.check()
        processes.run_cli("init-db")
        processes.run_cli("check-storage")
        processes.start("api", [sys.executable, "-m", "hf2l_exchange.cli", "serve", "--host", "127.0.0.1",
                                 "--port", str(args.port)])
        processes.start("worker", [sys.executable, "-m", "hf2l_exchange.cli", "worker"])
        await_http(processes, endpoint, "/ready")
        processes.check()
        private_json(work / "service.json", {"endpoint": endpoint, "issuer": ISSUER, "allow_local_http": True,
                                             "identities": identities,
                                             "storage_mode": "emulated" if args.emulated_storage else "s3"})
        print(f"Exchange ready: {endpoint}\nService configuration: {work / 'service.json'}", flush=True)
        if args.emulated_storage:
            print("Storage is emulated: this run does not prove provider authorization or versioning conformance.", flush=True)
        print(f"Tokens expire in {args.token_ttl_hours} hours; token refresh is not provided.\n"
              "Keep this terminal open. Ctrl-C removes this run's S3 bucket; logs and SQLite remain for inspection.", flush=True)
        while not stopped.wait(0.5):
            processes.check()
    except StopRequested:
        pass
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        exit_code = 1
    finally:
        # Stop every writer before deleting its bucket. The emulator remains
        # alive until storage cleanup finishes, including partial startup.
        try:
            processes.stop(except_names=("storage",))
            if bucket_created:
                cleanup_bucket(s3, bucket)
                print(f"Removed temporary bucket {bucket}", flush=True)
        except Exception as exc:
            print(f"cleanup error for this run's bucket {bucket}: {exc}; see {work / 'runtime.json'}",
                  file=sys.stderr)
            exit_code = 1
        finally:
            processes.stop()
            processes.logs.close()
            if s3 is not None:
                s3.close()
            for sig, handler in original_handlers.items():
                signal.signal(sig, handler)
        print(f"Service stopped. Preserved {work}; use a fresh directory for the next run.", flush=True)
    return exit_code


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    old_umask = os.umask(0o077)
    try:
        return run(args)
    except (ImportError, OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    raise SystemExit(main())
