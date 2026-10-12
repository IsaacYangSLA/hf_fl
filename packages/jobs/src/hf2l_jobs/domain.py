"""Immutable job inputs and control-plane value types."""
from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Literal, Mapping
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_serializer, field_validator, model_validator

IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
PLUGIN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?::[A-Za-z_][A-Za-z0-9_]*)?$")
FORBIDDEN_OPTIONS = {"command", "commands", "cmd", "mount", "mounts", "host_path", "docker_flags", "executor_flags", "runtime_flags", "privileged", "network_mode"}
SECRET_KEY = re.compile(r"(^|_)(password|passwd|secret|token|credentials|private_key|access_key|api_key)($|_)", re.I)


def new_id() -> str:
    return uuid4().hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [thaw(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    return value


def canonical_json(value: Any) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(thaw(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def spec_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def validate_identifier(value: str) -> str:
    if not IDENTIFIER.fullmatch(value):
        raise ValueError("Expected an approved identifier, not a path or URL")
    return value


def _freeze_json(value: Any, depth: int = 0) -> Any:
    if depth > 8:
        raise ValueError("Options nesting exceeds eight levels")
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 128:
                raise ValueError("Option keys must be bounded strings")
            normal = re.sub(r"[^a-z0-9]+", "_", re.sub(r"([a-z])([A-Z])", r"\1_\2", key).lower()).strip("_")
            if normal in FORBIDDEN_OPTIONS or SECRET_KEY.search(normal) or normal.replace("_", "") in {"apikey", "accesskey", "privatekey", "authorization", "bearertoken", "accesstoken", "refreshtoken"}:
                raise ValueError("Commands, mounts, executor flags and inline secrets are forbidden")
            result[key] = _freeze_json(item, depth + 1)
        return MappingProxyType(result)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item, depth + 1) for item in value)
    if value is None or type(value) in (str, int, bool):
        if isinstance(value, str) and len(value) > 8192:
            raise ValueError("Option string exceeds size limit")
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise ValueError("Options must contain finite JSON values only")


class FrozenInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", validate_default=True)


class ResourceRequest(FrozenInput):
    pool_id: str
    cpu_millicores: StrictInt = Field(ge=1, le=1_000_000)
    memory_bytes: StrictInt = Field(ge=1, le=1 << 50)
    disk_bytes: StrictInt = Field(ge=1, le=1 << 50)
    gpu_count: StrictInt = Field(default=0, ge=0, le=1024)
    gpu_profile: str | None = None
    sandbox_profile: str = "runsc-cpu-v1"

    @field_validator("pool_id", "sandbox_profile")
    @classmethod
    def identifiers(cls, value: str) -> str:
        return validate_identifier(value)

    @field_validator("gpu_profile")
    @classmethod
    def gpu_identifier(cls, value: str | None) -> str | None:
        return validate_identifier(value) if value is not None else None

    @model_validator(mode="after")
    def gpu_binding(self):
        if bool(self.gpu_count) != bool(self.gpu_profile):
            raise ValueError("GPU requests require both count and approved profile")
        return self


class ComponentSpec(FrozenInput):
    component_id: str
    role: Literal["owner", "participant", "build"]
    resources: ResourceRequest
    participant_id: str | None = None

    @field_validator("component_id", "participant_id")
    @classmethod
    def identifiers(cls, value: str | None) -> str | None:
        return validate_identifier(value) if value is not None else None

    @model_validator(mode="after")
    def participant_binding(self):
        if (self.role == "participant") != (self.participant_id is not None):
            raise ValueError("Only participant components require a participant identifier")
        return self


class ParticipantSpec(FrozenInput):
    participant_id: str
    dataset_binding: str
    mode: Literal["external", "managed"] = "external"
    component_id: str | None = None

    @field_validator("participant_id", "dataset_binding", "component_id")
    @classmethod
    def identifiers(cls, value: str | None) -> str | None:
        return validate_identifier(value) if value is not None else None

    @model_validator(mode="after")
    def managed_binding(self):
        if (self.mode == "managed") != (self.component_id is not None):
            raise ValueError("Managed participants require a component binding; external participants cannot request one")
        return self


class JobSpec(FrozenInput):
    project_id: str
    name: str = Field(min_length=1, max_length=200)
    source_id: str
    source_commit: str
    runtime_image: str
    plugin: str
    options: Mapping[str, Any] = Field(default_factory=dict)
    secret_refs: Mapping[str, str] = Field(default_factory=dict)
    participants: tuple[ParticipantSpec, ...] = Field(default=(), max_length=10_000)
    components: tuple[ComponentSpec, ...] = Field(min_length=1, max_length=1024)
    target_round: StrictInt = Field(ge=1, le=1_000_000)
    max_duration_seconds: StrictInt = Field(ge=1, le=2_592_000)

    @field_validator("project_id", "source_id")
    @classmethod
    def identifiers(cls, value: str) -> str:
        return validate_identifier(value)

    @field_validator("name")
    @classmethod
    def display_name(cls, value: str) -> str:
        if not value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Job name cannot be empty or contain control characters")
        return value

    @field_validator("source_commit")
    @classmethod
    def immutable_commit(cls, value: str) -> str:
        if not re.fullmatch(r"(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})", value):
            raise ValueError("Source commit must be an exact SHA-1 or SHA-256 object identifier")
        return value.lower()

    @field_validator("runtime_image")
    @classmethod
    def approved_runtime(cls, value: str) -> str:
        if re.fullmatch(r"sha256:[a-f0-9]{64}", value):
            return value
        return validate_identifier(value)

    @field_validator("plugin")
    @classmethod
    def plugin_identifier(cls, value: str) -> str:
        if len(value) > 256 or not PLUGIN.fullmatch(value):
            raise ValueError("Plugin must be a Python module or module:entry identifier")
        return value

    @field_validator("options", mode="after")
    @classmethod
    def immutable_options(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        frozen = _freeze_json(dict(value))
        if len(canonical_json(frozen).encode("utf-8")) > 65536:
            raise ValueError("Options exceed 64 KiB")
        return frozen

    @field_validator("secret_refs", mode="after")
    @classmethod
    def approved_secret_refs(cls, value: Mapping[str, str]) -> Mapping[str, str]:
        if len(value) > 64:
            raise ValueError("Too many secret references")
        return MappingProxyType({validate_identifier(k): validate_identifier(v) for k, v in value.items()})

    @field_serializer("options", "secret_refs")
    def serialize_mappings(self, value):
        return thaw(value)

    @model_validator(mode="after")
    def validate_components(self):
        components = {item.component_id: item for item in self.components}
        participants = {item.participant_id: item for item in self.participants}
        if len(components) != len(self.components) or len(participants) != len(self.participants):
            raise ValueError("Component and participant identifiers must be unique")
        if sum(item.role == "owner" for item in self.components) != 1:
            raise ValueError("Exactly one owner component is required")
        external_components = {"participant-" + hashlib.sha256(canonical_json([item.participant_id]).encode()).hexdigest()[:40]
                               for item in self.participants if item.mode == "external"}
        if external_components.intersection(components):
            raise ValueError("Managed components cannot use a reserved external participant identity")
        for participant in self.participants:
            if participant.mode == "managed":
                component = components.get(participant.component_id)
                if component is None or component.role != "participant" or component.participant_id != participant.participant_id:
                    raise ValueError("Managed participant component must match its participant binding")
        for component in self.components:
            if component.role == "participant":
                participant = participants.get(component.participant_id)
                if participant is None or participant.mode != "managed" or participant.component_id != component.component_id:
                    raise ValueError("Participant component must have a matching managed participant")
        return self

    @model_validator(mode="after")
    def validate_managed_round_options(self):
        # The fixed managed FedAvg owner consumes this flat option only.
        # Remaining plugin options stay opaque finite JSON, without imports.
        if "minimum_participants" in self.options:
            minimum = self.options["minimum_participants"]
            if type(minimum) is not int or minimum < 2:
                raise ValueError("minimum_participants must be an integer of at least two")
            if minimum > len(self.participants):
                raise ValueError("minimum_participants exceeds the immutable participant set")
        return self

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")

    @property
    def digest(self) -> str:
        return spec_hash(self)


class JobState(str, Enum):
    QUEUED = "QUEUED"
    PROVISIONING = "PROVISIONING"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    RECONCILING = "RECONCILING"
    NEEDS_ATTENTION = "NEEDS_ATTENTION"
    CANCELLING = "CANCELLING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


TERMINAL_STATES = frozenset({"SUCCEEDED", "FAILED", "CANCELLED"})
ACTIVE_STATES = frozenset(set(item.value for item in JobState) - TERMINAL_STATES)
JOB_ROLES = frozenset({"reader", "operator", "admin"})
ROLE_LEVEL = {"reader": 1, "operator": 2, "admin": 3}

class Error(Exception):
    """Stable structured manager error without leaking internal details."""
    def __init__(self, status: int, code: str, details: Any = None):
        super().__init__(code)
        self.status = self.status_code = status
        self.code = code
        self.details = details

ServiceError = Error


class ArtifactLocator(FrozenInput):
    """Trusted, structured location; never a URL or unrestricted host path.

    This validates shape only. The download broker must check current job ACL,
    resource ownership and transfer ownership before resolving the location.
    """
    kind: Literal["exchange", "local"]
    space_id: str | None = None
    record_id: str | None = None
    attachment_id: str | None = None
    resource_id: str | None = None
    relative_path: str | None = None

    @field_validator("space_id", "record_id", "attachment_id", "resource_id")
    @classmethod
    def opaque_identifiers(cls, value):
        return validate_identifier(value) if value is not None else None

    @field_validator("relative_path")
    @classmethod
    def confined_relative_path(cls, value):
        if value is None:
            return value
        if len(value) > 1024 or not value or value.startswith("/") or "\\" in value or any(ord(c) < 32 for c in value):
            raise ValueError("Artifact location must be a confined relative file path")
        pieces = value.split("/")
        if len(pieces) > 64 or any(piece in ("", ".", "..") for piece in pieces):
            raise ValueError("Artifact location cannot traverse outside its owned resource")
        return value

    @model_validator(mode="after")
    def binding(self):
        exchange = (self.space_id, self.record_id, self.attachment_id)
        local = (self.resource_id, self.relative_path)
        if self.kind == "exchange" and (not all(exchange) or any(local)):
            raise ValueError("Exchange artifacts require only space, record and attachment identifiers")
        if self.kind == "local" and (not all(local) or any(exchange)):
            raise ValueError("Local artifacts require only an owned resource identifier and relative path")
        return self

    def to_dict(self):
        return self.model_dump(mode="json", exclude_none=True)
