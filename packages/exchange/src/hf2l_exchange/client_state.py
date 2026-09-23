"""Durable recovery state, independent of HTTP and transfer implementation."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import uuid

from .client_types import ExchangeError


def fingerprint(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    allow_nan=False).encode()).hexdigest()


class StateRepository:
    """Atomically persist operation keys before requests that may lose their response.

    A state path belongs to one operation and must not be shared by concurrent jobs.
    It contains recovery identifiers, never bearer tokens or transfer credentials.
    Completed state remains reusable until explicitly removed.
    """

    def __init__(self, path=None):
        self.path = Path(path) if path is not None else None
        self._memory = {}

    def load(self) -> dict:
        if self.path is None:
            return dict(self._memory)
        if self.path.is_symlink():
            raise ValueError("Refusing symlink operation state")
        if not self.path.exists():
            return {}
        value = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Invalid operation state")
        return value

    def save(self, state: dict) -> None:
        if self.path is None:
            self._memory = dict(state)
            return
        if self.path.is_symlink():
            raise ValueError("Refusing symlink operation state")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as target:
                os.fchmod(target.fileno(), 0o600)
                json.dump(state, target, sort_keys=True, allow_nan=False)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, self.path)
            if hasattr(os, "O_DIRECTORY"):
                directory_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def begin(self, operation, identity, *, idempotency_key=None) -> dict:
        expected = fingerprint([operation, identity])
        state = self.load()
        if state:
            if state.get("fingerprint") != expected:
                raise ExchangeError(409, "operation_state_mismatch")
            if idempotency_key is not None and state.get("key") != idempotency_key:
                raise ExchangeError(409, "operation_key_mismatch")
            return state
        state = {"version": 1, "operation": operation, "fingerprint": expected,
                 "key": idempotency_key or uuid.uuid4().hex}
        self.save(state)
        return state

    def remove(self) -> None:
        self._memory = {}
        if self.path:
            self.path.unlink(missing_ok=True)
