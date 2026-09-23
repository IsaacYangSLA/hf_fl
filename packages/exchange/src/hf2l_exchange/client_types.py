"""SDK values. Importing this module requires only the Python standard library."""
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping


class ExchangeError(RuntimeError):
    """A control or transfer failure with a stable machine-readable code."""

    def __init__(self, status: int, code: str, details=None):
        self.status = status
        self.code = code
        self.details = details or {}
        super().__init__(f"Exchange HTTP {status}: {code}")


class Descriptor:
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class AttachmentDescriptor(Descriptor):
    id: str
    path: str
    size: int
    sha256: str
    state: str
    media_type: str | None = None

    @classmethod
    def from_dict(cls, value):
        return cls(**{key: value[key] for key in cls.__dataclass_fields__ if key in value})

    @property
    def name(self):
        return self.path

    @property
    def size_bytes(self):
        return self.size


@dataclass(frozen=True)
class RecordDescriptor(Descriptor):
    id: str
    space_id: str
    kind: str
    schema_revision_id: str
    metadata: Mapping[str, Any]
    state: str
    version: int
    shared: bool
    creator: str
    attachments: tuple[AttachmentDescriptor, ...] = ()
    creator_bindings: Mapping[str, Any] = field(default_factory=dict)
    created_at: float | None = None
    published_at: float | None = None
    expires_at: float | None = None

    @classmethod
    def from_dict(cls, value):
        fields = {key: value[key] for key in cls.__dataclass_fields__ if key in value}
        fields["attachments"] = tuple(AttachmentDescriptor.from_dict(item) for item in value.get("attachments", ()))
        return cls(**fields)


@dataclass(frozen=True)
class ReferenceSnapshot(Descriptor):
    name: str
    record_id: str
    token: str

    @classmethod
    def from_dict(cls, value):
        return cls(value["name"], value["record_id"], str(value["token"]))


@dataclass(frozen=True)
class CoordinationHandle(Descriptor):
    id: str
    reference: str
    expected_token: str
    holder: str
    fence: int
    state: str
    lease_until: float
    input_record_ids: tuple[str, ...] = ()
    result_record_id: str | None = None

    @classmethod
    def from_dict(cls, value):
        fields = {key: value[key] for key in cls.__dataclass_fields__ if key in value}
        fields["input_record_ids"] = tuple(value.get("input_record_ids", ()))
        return cls(**fields)

    @property
    def input_ids(self):
        return self.input_record_ids

    @property
    def expires_at(self):
        return self.lease_until


@dataclass(frozen=True)
class TypeRevision(Descriptor):
    id: str
    kind: str
    schema: Mapping[str, Any]
    revision: int = 1
    dialect: str = "https://json-schema.org/draft/2020-12/schema"
    space_id: str | None = None
    profile_version: str | None = None
    digest: str | None = None

    @classmethod
    def from_dict(cls, value):
        return cls(**{key: value[key] for key in cls.__dataclass_fields__ if key in value})


@dataclass(frozen=True)
class SpaceDescriptor(Descriptor):
    id: str
    name: str
    profile: str = "generic.v1"
    quota_bytes: int = 0
    principal_quota_bytes: int = 0
    quota_records: int = 0
    quota_metadata_bytes: int = 0
    allocated: int = 0
    reclaiming: int = 0
    record_count: int = 0
    metadata_bytes: int = 0
    generation: int = 0

    @classmethod
    def from_dict(cls, value):
        return cls(**{key: value[key] for key in cls.__dataclass_fields__ if key in value})


@dataclass(frozen=True)
class MemberDescriptor(Descriptor):
    principal: str
    roles: tuple[str, ...]
    subject: str | None = None
    bindings: Mapping[str, Any] = field(default_factory=dict)

    @property
    def principal_id(self):
        return self.principal

    @classmethod
    def from_dict(cls, value):
        return cls(value.get("principal_id", value.get("principal", value.get("id", ""))), tuple(value["roles"]),
                   value.get("subject"), value.get("bindings", {}))


@dataclass(frozen=True)
class EventDescriptor(Descriptor):
    id: int
    type: str
    resource_id: str | None = None
    data: Mapping[str, Any] = field(default_factory=dict)
    created_at: float | None = None

    @classmethod
    def from_dict(cls, value):
        return cls(value["id"], value.get("type", value.get("kind", "")),
                   value.get("resource_id", value.get("record_id")), value.get("payload", value.get("data", {})), value.get("created_at"))
