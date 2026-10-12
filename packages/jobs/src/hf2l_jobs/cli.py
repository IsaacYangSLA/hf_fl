"""Operational commands for the trusted multi-job control plane.

Imports are lazy: help and manager commands never import training plugins.
"""
from __future__ import annotations
import argparse
import json
import sys


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="hf2l-jobs", description="Manage isolated federated learning jobs")
    commands = root.add_subparsers(dest="command", required=True)
    for name, description in (
        ("init-db", "Create a new manager database with the current schema"),
        ("migrate-db", "Apply manager database schema migrations"),
        ("serve", "Serve the authenticated API and packaged dashboard"),
        ("controller", "Run the scheduler, provisioner, and lifecycle reconciler"),
        ("node-agent", "Run the trusted reservation watchdog and execution agent"),
        ("node-api", "Serve the private manager node mTLS API"),
        ("managed-node", "Serve a registered managed execution node"),
        ("participant-agent", "Serve an approved external participant execution agent"),
        ("gateway", "Serve certificate-bound artifact transfers"),
        ("exchange-edge", "Serve the managed Exchange mTLS boundary"),
        ("proxy", "Serve one execution's trusted operation proxy on a Unix socket"),
    ):
        command = commands.add_parser(name, help=description)
        command.add_argument("--config", required=name in {"managed-node", "participant-agent"},
                             help="Trusted operational JSON configuration file")
        if name in {"serve", "gateway", "exchange-edge", "node-api", "managed-node", "participant-agent"}:
            command.add_argument("--host")
            command.add_argument("--port", type=int)
        if name in {"controller", "node-agent"}:
            command.add_argument("--once", action="store_true", help="Perform one reconciliation/watchdog pass")
            command.add_argument("--interval", type=float, default=5.0, help="Polling interval in seconds (default: 5)")
    runtime = commands.add_parser("runtime", help="Run a managed FL worker inside its assigned sandbox")
    runtime.add_argument("--config", required=True, help="Execution manifest created by the trusted provisioner")
    admin = commands.add_parser("admin", help="Trusted local deployment administration")
    admin.add_argument("--config", help="Trusted operational JSON configuration file")
    operations = admin.add_subparsers(dest="operation", required=True)
    project = operations.add_parser("project-create", help="Create a project with explicit quota and retention")
    project.add_argument("--id", required=True)
    project.add_argument("--name", required=True)
    project.add_argument("--quota-file", required=True, help="JSON resource quota object")
    project.add_argument("--retention-days", type=int, default=90)
    update = operations.add_parser("project-update", help="Update a project's quota or retention policy")
    update.add_argument("--id", required=True)
    update.add_argument("--name")
    update.add_argument("--quota-file", help="Replacement JSON resource quota object")
    update.add_argument("--retention-days", type=int)
    member = operations.add_parser("project-member", help="Grant or revoke project creation permission")
    member.add_argument("--project", required=True)
    member.add_argument("--principal", required=True)
    member.add_argument("--role", choices=("submitter", "admin", "remove"), required=True)
    objects = operations.add_parser("object-store-pool-set", help="Approve capacity on the configured versioned object store")
    objects.add_argument("--file", required=True, help="Trusted JSON object-store pool ID, name and disk capacity")
    storage = operations.add_parser("storage-pool-set", help="Qualify the configured private manager filesystem capacity")
    storage.add_argument("--file", required=True, help="Trusted JSON storage pool ID, name, node ID and disk capacity")
    pool = operations.add_parser("pool-set", help="Register or update explicitly allocatable capacity")
    pool.add_argument("--file", required=True, help="Trusted JSON pool definition")
    for name in ("source-approve", "image-approve", "dataset-approve", "secret-ref-approve"):
        command = operations.add_parser(name, help="Persist an administrator-approved catalog entry")
        command.add_argument("--file", required=True, help="Trusted JSON approval definition")
    return root


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "runtime":
            from .runtime import main as run_worker
            return int(run_worker(["--config", arguments.config]) or 0)
        if arguments.command == "participant-agent":
            from .participants import main as run_participant
            command = ["--config", arguments.config] if arguments.config else []
            if arguments.host:
                command += ["--host", arguments.host]
            if arguments.port is not None:
                command += ["--port", str(arguments.port)]
            return int(run_participant(command) or 0)
        from .composition import dispatch
        result = dispatch(arguments)
        if result is not None:
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        # Do not echo exception strings: configuration may contain credentials.
        code = getattr(exc, "code", "command_failed")
        status = getattr(exc, "status", None)
        message = {"error": str(code), "type": type(exc).__name__}
        if isinstance(status, int):
            message["status"] = status
        print(json.dumps(message, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
