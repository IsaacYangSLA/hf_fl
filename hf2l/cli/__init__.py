"""Small, lazy composition root for the HF2L command line."""

from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path


_COMMANDS = {
    "init": ("hf2l.init_repo", "Initialize a model repository"),
    "download": ("hf2l.client_download", "Download an immutable round base"),
    "upload": ("hf2l.client_upload", "Validate and upload a client checkpoint"),
    "train": ("hf2l.client_train", "Run a trusted local training plugin"),
    "listen": ("hf2l.cli.listen", "Watch global models and run a durable client listener"),
    "round": ("hf2l.owner_fedavg", "Select, aggregate and publish a round"),
    "allowlist": ("hf2l.create_allowlist", "Create participant identity mappings"),
    "exchange": ("hf2l_exchange.cli", "Administer the independent exchange service"),
}


def _export_contract(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="hf2l export-contract", description="Export the FL document JSON schemas")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    from hf2l.common.fs import write_json
    from hf2l.core.protocol import document_schemas

    write_json(args.output, document_schemas())
    print(f"contract={args.output.resolve()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Dispatch explicit arguments without changing the process's ``sys.argv``."""
    parser = argparse.ArgumentParser(
        prog="hf2l",
        description="Federated learning commands and exchange service administration.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Commands:\n" + "\n".join(
            f"  {name:16} {description}" for name, (_, description) in _COMMANDS.items()
        ) + "\n  export-contract  Export the FL document JSON schemas",
    )
    parser.add_argument("command", choices=(*_COMMANDS, "export-contract"))
    parser.add_argument("arguments", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
    values = list(sys.argv[1:] if argv is None else argv)
    if not values:
        parser.print_help()
        return 0
    try:
        args = parser.parse_args(values)
        if args.command == "export-contract":
            return _export_contract(args.arguments)
        module = importlib.import_module(_COMMANDS[args.command][0])
        return int(module.main(args.arguments) or 0)
    except SystemExit as exc:
        # argparse's normal help and usage exits become a reusable library result.
        return exc.code if isinstance(exc.code, int) else 1
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


__all__ = ["main"]
