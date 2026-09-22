"""Bounded request models; server-controlled properties are never accepted."""
from typing import Literal
from pathlib import PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .protocol import METADATA_LIMIT_BYTES, metadata_size

ROLES = Literal["reader", "contributor", "coordinator", "admin"]

# The built-in v1 FedAvg profile. The API keys its FL guarantees to these names: participant-bound updates that
# require a base, a shared global model that main resolves to, and the provenance field a claimed result declares.
UPDATE_KIND = "training.update"
GLOBAL_KIND = "model.global"
MAIN_REF = "main"
PROVENANCE_FIELD = "input_record_ids"
# Kinds a space's rules must always contain; custom rule sets may add kinds around them.
PROFILE_KINDS = (UPDATE_KIND, GLOBAL_KIND)


class MetadataTooLarge(ValueError):
    def __init__(self, size):
        self.size, self.limit = size, METADATA_LIMIT_BYTES
        super().__init__(f"Metadata is {size} bytes; the limit is {METADATA_LIMIT_BYTES} bytes")


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class KindRule(Input):
    creators: list[ROLES] = Field(min_length=1, max_length=4)
    shared: bool = False
    metadata_schema: dict = Field(default_factory=dict)


def default_rules():
    return {
        "message": KindRule(creators=["contributor", "coordinator"], shared=True),
        "configuration": KindRule(creators=["coordinator"], shared=True),
        UPDATE_KIND: KindRule(creators=["contributor"], shared=False),
        GLOBAL_KIND: KindRule(creators=["coordinator"], shared=True),
        "evaluation.result": KindRule(creators=["coordinator"], shared=True),
    }


class SpaceInput(Input):
    name: str = Field(min_length=1, max_length=128)
    tenant: str = Field(min_length=1, max_length=128)
    quota_bytes: int = Field(default=1024**4, gt=0, le=2**62)
    # Outstanding draft reservations one principal may hold; defaults to a quarter of the space quota.
    principal_quota_bytes: int | None = Field(default=None, gt=0, le=2**62)
    rules: dict[str, KindRule] = Field(default_factory=default_rules, max_length=64)


class SpacePatch(Input):
    quota_bytes: int | None = Field(default=None, gt=0, le=2**62)
    principal_quota_bytes: int | None = Field(default=None, gt=0, le=2**62)
    rules: dict[str, KindRule] | None = Field(default=None, max_length=64)


class MemberInput(Input):
    subject: str = Field(min_length=1, max_length=256)
    roles: list[ROLES] = Field(max_length=4)
    participant: str | None = Field(default=None, min_length=1, max_length=128)


class Attachment(Input):
    name: str = Field(min_length=1, max_length=256)
    size_bytes: int = Field(ge=0, le=5 * 1024**4)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("name")
    @classmethod
    def safe_name(cls, value):
        path = PurePosixPath(value)
        if path.is_absolute() or any(p in (".", "..", "") for p in value.split("/")) or "\\" in value:
            raise ValueError("Attachment name must be a safe relative path")
        if any(ord(c) < 32 for c in value):
            raise ValueError("Control characters are forbidden")
        return value


class MetadataInput(Input):
    metadata: dict = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def bounded_metadata(cls, value):
        size = metadata_size(value)
        if size > METADATA_LIMIT_BYTES:
            raise MetadataTooLarge(size)
        def depth(node, level=0):
            if level > 16:
                raise ValueError("Metadata nesting exceeds 16 levels")
            if isinstance(node, dict):
                for item in node.values():
                    depth(item, level + 1)
            elif isinstance(node, list):
                for item in node:
                    depth(item, level + 1)
        depth(value)
        return value


class RecordInput(MetadataInput):
    kind: str = Field(min_length=1, max_length=128)
    schema_version: int = Field(default=1, ge=1)
    base_record_id: str | None = Field(default=None, max_length=64)
    attachments: list[Attachment] = Field(default_factory=list, max_length=256)


class PartsInput(Input):
    part_numbers: list[int] = Field(min_length=1, max_length=100)


class RefInput(Input):
    record_id: str = Field(min_length=1, max_length=64)


class ClaimInput(Input):
    workflow: str = Field(default="fedavg", min_length=1, max_length=128)
    minimum: int = Field(default=2, ge=2, le=256)
    lease_seconds: int = Field(default=3600, ge=30, le=86400)
    # Explicit coordinator-chosen inputs; otherwise the newest ready update per participant is frozen.
    inputs: list[str] | None = Field(default=None, min_length=1, max_length=256)


class ClaimResult(RefInput):
    fence: int = Field(ge=1)


class ClaimAbandon(Input):
    fence: int | None = Field(default=None, ge=1)


class LeaseInput(Input):
    fence: int = Field(ge=1)
    lease_seconds: int = Field(default=3600, ge=30, le=86400)
