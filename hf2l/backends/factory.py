"""Construction and CLI configuration for model-store backends."""

from __future__ import annotations

import argparse
import os

from hf2l.backends.base import ModelStore
from hf2l.backends.huggingface import HuggingFaceStore
from hf2l.backends.jfrog import JFrogStore


def add_store_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--backend",
        choices=("huggingface", "jfrog"),
        default="huggingface",
        help="Model repository backend (default: huggingface)",
    )
    parser.add_argument(
        "--endpoint",
        help=(
            "API endpoint override. JFrog requires "
            "https://HOST/artifactory/api/huggingfaceml/REPO_KEY; may also be set "
            "with HF_ENDPOINT"
        ),
    )
    parser.add_argument(
        "--token",
        help="Token override; prefer an environment variable or credential helper",
    )


def make_store(
    backend: str,
    explicit_token: str | None = None,
    endpoint: str | None = None,
) -> ModelStore:
    endpoint = endpoint or os.environ.get("HF_ENDPOINT")
    if backend == "jfrog":
        token = (
            explicit_token
            or os.environ.get("JFROG_ACCESS_TOKEN")
            or os.environ.get("HF_TOKEN")
        )
        if not endpoint:
            raise ValueError("JFrog requires --endpoint or HF_ENDPOINT")
        if not token:
            raise ValueError(
                "JFrog requires --token, JFROG_ACCESS_TOKEN, or HF_TOKEN"
            )
        return JFrogStore(token, endpoint)
    if backend == "huggingface":
        token = explicit_token or os.environ.get("HF_TOKEN")
        return HuggingFaceStore(token, endpoint)
    raise ValueError(f"Unsupported backend: {backend}")
