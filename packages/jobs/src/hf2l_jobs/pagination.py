"""Authenticated opaque cursors scoped to a principal and exact query."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from .domain import Error


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


class CursorSigner:
    def __init__(self, secret, ttl_seconds=3600):
        if isinstance(secret, str):
            secret = secret.encode()
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("cursor_secret must contain at least 32 bytes")
        self.secret = secret
        self.ttl_seconds = ttl_seconds

    @staticmethod
    def _scope(principal, kind, filters):
        return hashlib.sha256(canonical([principal, kind, filters])).hexdigest()

    def encode(self, principal, kind, filters, position, now=None):
        payload = canonical({"v": 1, "scope": self._scope(principal, kind, filters),
                             "position": position, "exp": int(time.time() if now is None else now) + self.ttl_seconds})
        signature = hmac.digest(self.secret, payload, "sha256")
        return base64.urlsafe_b64encode(payload + signature).decode().rstrip("=")

    def decode(self, cursor, principal, kind, filters, now=None):
        try:
            if not isinstance(cursor, str) or not cursor or len(cursor) > 4096:
                raise ValueError()
            raw = base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True)
            if len(raw) < 33:
                raise ValueError()
            payload, signature = raw[:-32], raw[-32:]
            if not hmac.compare_digest(signature, hmac.digest(self.secret, payload, "sha256")):
                raise ValueError()
            data = json.loads(payload)
            if set(data) != {"v", "scope", "position", "exp"} or data["v"] != 1:
                raise ValueError()
            if not hmac.compare_digest(data["scope"], self._scope(principal, kind, filters)):
                raise ValueError()
            if type(data["exp"]) is not int:
                raise ValueError()
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise Error(422, "invalid_cursor") from None
        if data["exp"] <= int(time.time() if now is None else now):
            raise Error(409, "cursor_expired")
        return data["position"]


def page_limit(value, maximum=100):
    if type(value) is not int or not 1 <= value <= maximum:
        raise Error(422, "invalid_page_limit")
    return value
