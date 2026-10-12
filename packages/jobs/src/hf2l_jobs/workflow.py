"""Trusted, immutable inputs for sandboxed federated job workers.

This module does not import plugins, trainers or checkpoints. The same contract
is consumed by the provisioner and the sandbox entrypoint.
"""
from __future__ import annotations

import math
import hashlib
import re
from pathlib import Path, PurePosixPath
from typing import Literal, Mapping
from urllib.parse import urlsplit

from pydantic import ConfigDict, Field, StrictInt, field_validator, model_validator
from .domain import FrozenInput, JobSpec, canonical_json, validate_identifier


class DatasetBinding(FrozenInput):
    kind: Literal["synthetic", "npz"]
    path: str | None = None

    @model_validator(mode="after")
    def local_dataset(self):
        if self.kind == "synthetic":
            if self.path is not None:
                raise ValueError("Synthetic bindings cannot select a filesystem path")
        elif not self.path or not self.path.startswith("/job/data/"):
            raise ValueError("Dataset paths must be beneath the assigned read-only /job/data volume")
        if self.path and any(part in (".", "..") for part in self.path.split("/")):
            raise ValueError("Dataset paths must be canonical")
        return self


class PublicationResolution(FrozenInput):
    """Trusted manager proof, supplied only after old execution fencing.

    The worker still verifies confirmed publication bytes against its retained
    intent; an absent proof requires a confirmed cancelled/failed draft or no
    record after revocation, never a timeout or a guessed current-round value.
    """
    role: Literal["init", "owner", "client"]
    action: Literal["confirmed", "absent"]
    intent_sha256: str
    old_attempt_id: str
    old_epoch: StrictInt = Field(ge=1)
    revocation_operation_id: str
    termination_operation_id: str
    grants_revoked: Literal[True]
    termination_confirmed: Literal[True]
    record_id: str | None = None
    acquisition_id: str | None = None

    @field_validator("old_attempt_id", "revocation_operation_id", "termination_operation_id",
                     "record_id", "acquisition_id")
    @classmethod
    def identifiers(cls, value):
        return validate_identifier(value) if value is not None else None

    @field_validator("grants_revoked", "termination_confirmed", mode="before")
    @classmethod
    def confirmed_fence(cls, value):
        if type(value) is not bool or not value:
            raise ValueError("Fencing must be explicitly confirmed")
        return value

    @field_validator("intent_sha256")
    @classmethod
    def sha(cls, value):
        if not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ValueError("A reconciliation must identify the exact retained intent")
        return value

    @model_validator(mode="after")
    def publication(self):
        if self.action == "confirmed" and self.record_id is None:
            raise ValueError("Confirmed publication requires its immutable record identifier")
        return self


def publication_intent_fingerprint(role: str, document: dict) -> str:
    """Read-only canonical intent identity, usable without HF2L or ML imports.

    init: initialization.json; client: client-publication-intent.json;
    owner: the active job object from listener/state.json. Phase, error strings
    and confirmed result fields are deliberately excluded from initialization.
    """
    if role == "init":
        fields = ("binding", "manifest_sha256", "checkpoint_files_sha256")
        if not all(field in document for field in fields):
            raise ValueError("Incomplete retained initialization intent")
        value = {field: document[field] for field in fields}
    elif role == "owner":
        fields = ("revision", "source_round", "publication_intent")
        if not all(field in document for field in fields) or not document["publication_intent"]:
            raise ValueError("Incomplete retained owner publication intent")
        value = {field: document[field] for field in fields}
    elif role == "client":
        fields = ("repo_id", "participant", "base_revision", "submission_revision",
                  "submitted_at", "checkpoint_files_sha256")
        if not all(field in document for field in fields):
            raise ValueError("Incomplete retained client publication intent")
        value = document
    else:
        raise ValueError("Unknown publication intent role")
    encoded = canonical_json(value).encode("utf-8")
    if len(encoded) > 1024 * 1024:
        raise ValueError("Retained publication intent exceeds the control-plane bound")
    return hashlib.sha256(encoded).hexdigest()


class BuiltArtifact(FrozenInput):
    sha256: str
    size_bytes: StrictInt = Field(ge=1, le=1 << 40)

    @field_validator("sha256")
    @classmethod
    def sha(cls, value):
        if not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ValueError("Built artifacts must identify immutable wheel bytes")
        return value


class RuntimeConfig(FrozenInput):
    schema_version: Literal[1] = 1
    role: Literal["init", "owner", "client"]
    job_id: str
    attempt_id: str
    component_id: str
    space_id: str
    epoch: StrictInt = Field(ge=1)
    spec: JobSpec
    spec_digest: str
    source_dir: str = "/job/source"
    state_dir: str = "/job/state"
    exchange_endpoint: str = "http://proxy"
    proxy_socket: str = "/run/hf2l/proxy.sock"
    participant_id: str | None = None
    poll_interval: float = Field(default=2.0, gt=0, le=300)
    max_backoff: float = Field(default=30.0, gt=0, le=300)
    source_manifest: Mapping[str, str] = Field(default_factory=dict)
    dataset_bindings: Mapping[str, DatasetBinding] = Field(default_factory=dict)
    participant_principals: Mapping[str, str] = Field(default_factory=dict)
    reconciliation: tuple[PublicationResolution, ...] = ()
    secret_options_file: Literal["/run/hf2l/secrets.json"] | None = None
    secret_option_names: tuple[str, ...] = ()
    deadline_at: float | None = Field(default=None, gt=0)
    build_dir: Literal["/job/build"] = "/job/build"
    built_artifacts: Mapping[str, BuiltArtifact] = Field(default_factory=dict)

    @field_validator("job_id", "attempt_id", "component_id", "space_id", "participant_id")
    @classmethod
    def identifiers(cls, value):
        return validate_identifier(value) if value is not None else None

    @field_validator("source_dir", "state_dir", "proxy_socket")
    @classmethod
    def absolute_paths(cls, value):
        if not Path(value).is_absolute() or any(part in (".", "..") for part in value.split("/")):
            raise ValueError("Worker roots must be canonical absolute paths")
        return value.rstrip("/")

    @field_validator("exchange_endpoint")
    @classmethod
    def proxy_endpoint(cls, value):
        parsed = urlsplit(value)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname or
            parsed.username or parsed.password or parsed.query or parsed.fragment or
            parsed.path not in ("", "/")):
            raise ValueError("Worker endpoint must be its assigned execution proxy origin")
        return value.rstrip("/")

    @field_validator("source_manifest")
    @classmethod
    def manifest(cls, value):
        for name, digest in value.items():
            path = PurePosixPath(name)
            if (not name or path.is_absolute() or "\\" in name or
                any(part in ("", ".", "..") for part in name.split("/")) or
                not re.fullmatch(r"[a-f0-9]{64}", digest)):
                raise ValueError("Invalid immutable source manifest")
        return dict(value)

    @field_validator("built_artifacts")
    @classmethod
    def wheels(cls, value):
        if len(value) > 256:
            raise ValueError("Too many private build artifacts")
        for name in value:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+\-]{0,240}\.whl", name):
                raise ValueError("Private build artifacts must be portable wheel basenames")
        return dict(value)

    @model_validator(mode="after")
    def binding(self):
        if self.spec_digest != self.spec.digest:
            raise ValueError("Worker specification digest differs from the immutable job")
        if len(self.secret_option_names) != len(set(self.secret_option_names)) or not set(self.secret_option_names) <= set(self.spec.secret_refs):
            raise ValueError("Secret options must name approved immutable references")
        if bool(self.secret_option_names) != bool(self.secret_options_file):
            raise ValueError("Approved component secret options require their private runtime manifest")
        if self.deadline_at is not None and not math.isfinite(self.deadline_at):
            raise ValueError("Job deadline must be finite")
        if len({item.role for item in self.reconciliation}) != len(self.reconciliation):
            raise ValueError("A role can have only one reconciliation directive")
        allowed_recovery_roles = {"client"} if self.role == "client" else {"init", "owner"}
        for item in self.reconciliation:
            if item.role not in allowed_recovery_roles:
                raise ValueError("Reconciliation does not belong to this worker role")
            if item.old_attempt_id == self.attempt_id or item.old_epoch >= self.epoch:
                raise ValueError("Reconciliation requires a fenced older attempt")
        if self.max_backoff < self.poll_interval:
            raise ValueError("Maximum backoff must cover the poll interval")
        component = next((c for c in self.spec.components if c.component_id == self.component_id), None)
        if self.role in ("owner", "init"):
            if component is None or component.role != "owner" or self.participant_id is not None:
                raise ValueError("Owner worker must bind its owner component")
        else:
            participant = next((p for p in self.spec.participants if p.participant_id == self.participant_id), None)
            if participant is None:
                raise ValueError("Client worker must bind an assigned participant")
            if participant.mode == "managed":
                if component is None or component.role != "participant" or component.participant_id != self.participant_id:
                    raise ValueError("Client component does not match its assignment")
            elif component is not None:
                raise ValueError("External participants cannot impersonate a managed component")
            if participant.dataset_binding not in self.dataset_bindings:
                raise ValueError("The participant dataset must be locally approved before execution")
        if self.role in ("owner", "init") and self.spec.participants:
            if set(self.participant_principals) != {p.participant_id for p in self.spec.participants}:
                raise ValueError("The owner must bind every immutable participant to its stable Exchange principal")
            if len(set(self.participant_principals.values())) != len(self.participant_principals):
                raise ValueError("Participant principals must be unique")
            for principal in self.participant_principals.values():
                validate_identifier(principal)
        if (Path(self.source_dir) == Path(self.state_dir) or Path(self.source_dir) in Path(self.state_dir).parents
                or Path(self.state_dir) in Path(self.source_dir).parents):
            raise ValueError("Immutable source and writable state must be separate roots")
        return self

    @property
    def durable_binding(self):
        # Attempts and epochs rotate while the durable component identity remains.
        return {"job_id": self.job_id, "component_id": self.component_id,
                "space_id": self.space_id, "spec_digest": self.spec_digest,
                "source_commit": self.spec.source_commit,
                "source_manifest": dict(self.source_manifest),
                "role": "owner" if self.role == "init" else self.role,
                "participant_id": self.participant_id,
                "participant_principals": dict(self.participant_principals),
                "dataset_bindings": {key: value.model_dump(mode="json") for key, value in self.dataset_bindings.items()},
                **({"built_artifacts": {name: artifact.model_dump(mode="json") for name, artifact in self.built_artifacts.items()}} if self.built_artifacts else {})}

    @property
    def source_identity(self):
        return canonical_json(self.durable_binding)

    def to_dict(self):
        return self.model_dump(mode="json")
