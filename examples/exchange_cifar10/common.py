"""Small helpers shared by the source-checkout CIFAR-10 demo commands."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


def load_round(path: Path) -> dict:
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("Expected a demo round.json with schema_version 1")
    for name in ("endpoint", "space_id", "base_revision"):
        if not isinstance(value.get(name), str) or not value[name]:
            raise ValueError(f"Round descriptor requires {name}")
    if value["base_revision"] in {"main", "latest", "HEAD"}:
        raise ValueError("Both clients require an immutable base record ID")
    if type(value.get("round_number")) is not int or value["round_number"] < 1:
        raise ValueError("round_number must be a positive integer")
    if type(value.get("allow_local_http", False)) is not bool:
        raise ValueError("allow_local_http must be a JSON boolean")
    return value


def write_json_exclusive(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(text)


def run_hf2l(module: str, args: list[str], *, token_file: Path, endpoint: str,
             allow_local_http: bool, threads: int = 2) -> None:
    token_file = token_file.resolve(strict=True)
    if not token_file.read_text().strip():
        raise ValueError("Token file is empty")
    if threads < 1:
        raise ValueError("threads must be positive")
    environment = os.environ.copy()
    environment.pop("EXCHANGE_TOKEN", None)
    environment.update(EXCHANGE_TOKEN_FILE=str(token_file), EXCHANGE_ENDPOINT=endpoint,
                       EXCHANGE_ALLOW_LOCAL_HTTP=str(allow_local_http).lower(),
                       OMP_NUM_THREADS=str(threads), MKL_NUM_THREADS=str(threads))
    subprocess.run([sys.executable, "-m", module, *args], env=environment, check=True)
