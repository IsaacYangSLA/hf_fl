#!/usr/bin/env python3
"""Dataset-independent helpers shared by the example model plugins."""

from __future__ import annotations

import hashlib


def stable_seed(name: str, seed: int) -> int:
    digest = hashlib.sha256(name.encode("utf-8")).digest()
    return (int.from_bytes(digest[:8], "little") + seed) % (2**63 - 1)
