"""Transport- and persistence-independent exchange values and failures."""
from dataclasses import dataclass
from typing import Mapping, Protocol, runtime_checkable

from .vocabulary import ROLES, TERMINAL_RECORD_STATES


class ExchangeError(Exception):
    def __init__(self, status: int, code: str, detail: str = "", headers: Mapping[str, str] | None = None):
        super().__init__(detail or code)
        self.status = status
        self.code = code
        self.detail = detail or code
        self.headers = dict(headers or {})


Error = ExchangeError


@dataclass(frozen=True)
class Principal:
    id: str
    subject: str
    bootstrap_admin: bool = False


@dataclass(frozen=True)
class RecordIdentity:
    id: str
    space_id: str
    kind: str
    schema_revision_id: str


@dataclass(frozen=True)
class ReferenceVersion:
    record_id: str
    generation: int

    @property
    def token(self) -> str:
        return str(self.generation)


@dataclass(frozen=True)
class ClaimHandle:
    id: str
    fence: int
    lease_until: float


@dataclass(frozen=True)
class BlobDeclaration:
    path: str
    size: int
    sha256: str
    media_type: str = "application/octet-stream"


@runtime_checkable
class BlobProvider(Protocol):
    """Operational health boundary; transfer operations use the storage module contract."""
    def check(self) -> None: ...
