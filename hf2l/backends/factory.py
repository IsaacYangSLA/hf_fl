"""Explicit, lazy registration of the supported model-store adapters."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from hf2l.core.ports import ModelStore


def _huggingface(token, endpoint, principal):
    from hf2l.backends.huggingface import HuggingFaceStore
    return HuggingFaceStore(token or os.environ.get("HF_TOKEN"), endpoint or os.environ.get("HF_ENDPOINT"))


def _jfrog(token, endpoint, principal):
    from hf2l.backends.jfrog import JFrogStore
    endpoint = endpoint or os.environ.get("HF_ENDPOINT")
    token = token or os.environ.get("JFROG_ACCESS_TOKEN") or os.environ.get("HF_TOKEN")
    if not endpoint:
        raise ValueError("JFrog requires --endpoint or HF_ENDPOINT")
    if not token:
        raise ValueError("JFrog requires --token, JFROG_ACCESS_TOKEN, or HF_TOKEN")
    return JFrogStore(token, endpoint)


def _exchange(token, endpoint, principal):
    from hf2l.backends.exchange import ExchangeStore
    endpoint = endpoint or os.environ.get("EXCHANGE_ENDPOINT")
    token = token or os.environ.get("EXCHANGE_TOKEN")
    if not token and os.environ.get("EXCHANGE_TOKEN_FILE"):
        token_path = Path(os.environ["EXCHANGE_TOKEN_FILE"])
        token = lambda: token_path.read_text(encoding="utf-8").strip()
    if not endpoint or not token:
        raise ValueError("Exchange requires EXCHANGE_ENDPOINT and EXCHANGE_TOKEN (or --endpoint/--token)")
    return ExchangeStore(token, endpoint)


def _local(token, endpoint, principal):
    from hf2l.backends.local import LocalStore
    root = endpoint or os.environ.get("HF2L_LOCAL_ROOT")
    identity = principal or os.environ.get("HF2L_LOCAL_PRINCIPAL")
    if not root or not identity:
        raise ValueError("Local requires --endpoint/HF2L_LOCAL_ROOT and --local-principal/HF2L_LOCAL_PRINCIPAL")
    return LocalStore(root, identity)


# This installed registry is the single source for factory selection and CLI choices.
# Only explicitly registered constructors can be selected; values are not import paths.
STORE_REGISTRY = {
    "huggingface": _huggingface,
    "jfrog": _jfrog,
    "exchange": _exchange,
    "local": _local,
}


def add_store_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--backend", choices=tuple(STORE_REGISTRY), default="huggingface",
                        help="Model repository backend (default: huggingface)")
    parser.add_argument("--endpoint", help="Backend API endpoint, or a filesystem root for local")
    parser.add_argument("--token", help="Token override; prefer an environment variable or credential helper")
    parser.add_argument("--local-principal", help="Local identity, or HF2L_LOCAL_PRINCIPAL (trusted filesystem only)")


def make_store(backend: str, explicit_token: str | None = None, endpoint: str | None = None,
               *, principal: str | None = None) -> ModelStore:
    try:
        create = STORE_REGISTRY[backend]
    except KeyError as exc:
        raise ValueError(f"Unsupported backend: {backend}") from exc
    return create(explicit_token, endpoint, principal)
