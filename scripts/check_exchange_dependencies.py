"""Check exchange source boundaries or a deliberately minimal installed environment.

Run from any directory. Installation checks are intended for clean SDK/server
virtualenvs; source checks also work in the full HF2L development environment.
"""
from __future__ import annotations

import argparse
import ast
import importlib
import importlib.metadata
import importlib.util
from pathlib import Path
import re
import sys


ML_MODULES = {"torch", "numpy", "safetensors", "huggingface_hub", "hf2l"}
SERVER_MODULES = {"fastapi", "uvicorn", "sqlalchemy", "psycopg", "boto3", "botocore", "jwt", "jsonschema"}
SDK_FILES = {"__init__.py", "client.py", "client_types.py", "control.py", "transfer_client.py", "client_state.py"}


def _imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported = node.module
                if node.level:
                    imported = "hf2l_exchange." + imported
                yield node.lineno, imported
            elif node.level:
                for alias in node.names:
                    yield node.lineno, "hf2l_exchange." + alias.name


def check_source(root: Path) -> list[str]:
    source = root / "packages/exchange/src/hf2l_exchange"
    files = sorted(source.rglob("*.py"))
    if not files:
        return [f"No exchange package sources found at {source}"]
    problems = []
    for path in files:
        relative = path.relative_to(source)
        is_domain = relative.parts[0] in {"domain", "domain.py"}
        is_sdk = len(relative.parts) == 1 and relative.name in SDK_FILES
        forbidden = ML_MODULES | (SERVER_MODULES if is_sdk else set())
        if is_domain:
            forbidden |= SERVER_MODULES | {"httpx"}
        for line, imported in _imports(path):
            if imported.split(".", 1)[0] in forbidden:
                problems.append(f"{path.relative_to(root)}:{line}: prohibited import {imported}")
            if is_domain and imported.startswith("hf2l_exchange."):
                local = imported.split(".", 2)[1]
                if local in {"api", "application", "auth", "cli", "config", "models", "storage", "worker", "infrastructure"}:
                    problems.append(f"{path.relative_to(root)}:{line}: domain imports {imported}")
    return problems


def _installed_requirements() -> list[str]:
    requirements = importlib.metadata.requires("hf2l-exchange") or []
    unconditional = []
    for requirement in requirements:
        # This package declares optional requirements only through extras.
        if ";" not in requirement:
            match = re.match(r"[A-Za-z0-9_.-]+", requirement)
            if match:
                unconditional.append(match.group(0).lower().replace("_", "-"))
    return unconditional


def check_installation(mode: str) -> list[str]:
    problems = []
    dependencies = _installed_requirements()
    if dependencies != ["httpx"]:
        problems.append(f"SDK unconditional dependencies must be [httpx], got {dependencies}")
    forbidden = ML_MODULES | (SERVER_MODULES if mode == "sdk" else set())
    for name in sorted(forbidden):
        if importlib.util.find_spec(name) is not None:
            problems.append(f"{mode} environment unexpectedly contains {name}")
    for module in ("hf2l_exchange", "hf2l_exchange.client", "hf2l_exchange.client_types"):
        importlib.import_module(module)
    if mode == "server":
        importlib.import_module("hf2l_exchange.api")
        importlib.import_module("hf2l_exchange.cli")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("source", "sdk", "server"), default="source")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    problems = check_source(args.root)
    if args.mode != "source":
        problems.extend(check_installation(args.mode))
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    print(f"Exchange {args.mode} dependency boundaries passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
