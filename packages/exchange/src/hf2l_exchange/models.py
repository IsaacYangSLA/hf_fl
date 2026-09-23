"""V2 persistence mappings. Database time is authoritative for leases."""
import time
from sqlalchemy import (BigInteger, Boolean, ForeignKeyConstraint, Index, Integer, JSON,
                        String, Text, UniqueConstraint, create_engine, event, func, select)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, synonym
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


JSON_VALUE = JSON().with_variant(JSONB(), "postgresql")


def database_time(session):
    if session.bind.dialect.name == "postgresql":
        return float(session.scalar(select(func.extract("epoch", func.clock_timestamp()))))
    return float(session.scalar(select((func.julianday("now") - 2440587.5) * 86400)))


class Space(Base):
    __tablename__ = "v2_spaces"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    profile: Mapped[str] = mapped_column(String(64), default="generic.v1")
    generation: Mapped[int] = mapped_column(Integer, default=1)
    quota_bytes: Mapped[int] = mapped_column(BigInteger, default=107374182400)
    principal_quota_bytes: Mapped[int] = mapped_column(BigInteger, default=107374182400)
    allocated: Mapped[int] = mapped_column(BigInteger, default=0)
    reclaiming: Mapped[int] = mapped_column(BigInteger, default=0)
    quota_records: Mapped[int] = mapped_column(BigInteger, default=100000)
    record_count: Mapped[int] = mapped_column(BigInteger, default=0)
    quota_metadata_bytes: Mapped[int] = mapped_column(BigInteger, default=1073741824)
    metadata_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    event_floor: Mapped[int] = mapped_column(BigInteger, default=0)


class Member(Base):
    __tablename__ = "v2_members"
    space_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    principal_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    subject: Mapped[str | None] = mapped_column(String(256), nullable=True)
    roles: Mapped[list] = mapped_column(JSON_VALUE, default=list)
    bindings: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)
    __table_args__ = (ForeignKeyConstraint(["space_id"], ["v2_spaces.id"]),)


class SchemaRevision(Base):
    __tablename__ = "v2_schema_revisions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    space_id: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(128))
    revision: Mapped[int] = mapped_column(Integer)
    schema: Mapped[dict] = mapped_column(JSON_VALUE)
    profile_version: Mapped[str] = mapped_column(String(64), default="generic.v1")
    dialect: Mapped[str] = mapped_column(String(256), default="https://json-schema.org/draft/2020-12/schema")
    digest: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[float] = mapped_column(default=time.time)
    __table_args__ = (ForeignKeyConstraint(["space_id"], ["v2_spaces.id"]),
                     UniqueConstraint("space_id", "kind", "revision"),
                     UniqueConstraint("space_id", "id"))


class KindPolicy(Base):
    __tablename__ = "v2_kind_policies"
    space_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(128), primary_key=True)
    publish_roles: Mapped[list] = mapped_column(JSON_VALUE, default=lambda: ["contributor", "publisher"])
    visibility: Mapped[str] = mapped_column(String(24), default="shared")
    generation: Mapped[int] = mapped_column(Integer, default=1)
    __table_args__ = (ForeignKeyConstraint(["space_id"], ["v2_spaces.id"]),)


class Record(Base):
    __tablename__ = "v2_records"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    space_id: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(128))
    schema_revision_id: Mapped[str] = mapped_column(String(64))
    creator: Mapped[str] = mapped_column(String(64))
    creator_bindings: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)
    attribution = synonym("creator_bindings")
    base_record_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)
    state: Mapped[str] = mapped_column(String(24), default="draft")
    shared: Mapped[bool] = mapped_column(Boolean, default=False)
    generation: Mapped[int] = mapped_column(Integer, default=1)
    draft_version = synonym("generation")
    declared_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    metadata_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    created_at: Mapped[float] = mapped_column(default=time.time)
    published_at: Mapped[float | None] = mapped_column(nullable=True)
    expires_at: Mapped[float] = mapped_column()
    __table_args__ = (UniqueConstraint("space_id", "id"),
        ForeignKeyConstraint(["space_id"], ["v2_spaces.id"]),
        ForeignKeyConstraint(["space_id", "schema_revision_id"], ["v2_schema_revisions.space_id", "v2_schema_revisions.id"]),
        ForeignKeyConstraint(["space_id", "base_record_id"], ["v2_records.space_id", "v2_records.id"]),
        Index("ix_v2_records_discovery", "space_id", "kind", "state", "published_at", "id"),
        Index("ix_v2_records_creator_state", "space_id", "creator", "state"),
        Index("ix_v2_records_expiry", "state", "expires_at", "id"))


class Blob(Base):
    __tablename__ = "v2_blobs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    space_id: Mapped[str] = mapped_column(String(64))
    record_id: Mapped[str] = mapped_column(String(64))
    path: Mapped[str] = mapped_column(String(256))
    size: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    media_type: Mapped[str] = mapped_column(String(256), default="application/octet-stream")
    state: Mapped[str] = mapped_column(String(24), default="reserved")
    object_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    object_version: Mapped[str | None] = mapped_column(String(512), nullable=True)
    verified_size: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    verified_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    part_size: Mapped[int] = mapped_column(BigInteger, default=8388608)
    part_bytes = synonym("part_size")
    grant_expires_at: Mapped[float] = mapped_column(default=0.0)
    last_grant_expires_at = synonym("grant_expires_at")
    pending_deletion: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[float] = mapped_column()
    __table_args__ = (UniqueConstraint("record_id", "path"),
        ForeignKeyConstraint(["space_id", "record_id"], ["v2_records.space_id", "v2_records.id"]),
        Index("ix_v2_blobs_record", "record_id", "id"),
        Index("ix_v2_blobs_cleanup", "state", "expires_at", "id"))


class TransferAttempt(Base):
    __tablename__ = "v2_transfer_attempts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    blob_id: Mapped[str] = mapped_column(String(64))
    operation: Mapped[str] = mapped_column(String(24), default="upload")
    object_key: Mapped[str] = mapped_column(String(1024), unique=True)
    state: Mapped[str] = mapped_column(String(24), default="initiating")
    token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_until: Mapped[float | None] = mapped_column(nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt: Mapped[float] = mapped_column(default=0.0)
    last_error: Mapped[str | None] = mapped_column(String(256), nullable=True)
    upload_handle: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)
    # Outstanding provider mutations survive worker lease loss and process crashes.
    # Replace the complete list on update so JSON changes are persisted atomically.
    mutation_tokens: Mapped[list] = mapped_column(JSON_VALUE, default=list)
    grant_expires_at: Mapped[float] = mapped_column(default=0.0)
    created_at: Mapped[float] = mapped_column(default=time.time)
    updated_at: Mapped[float] = mapped_column(default=time.time)
    __table_args__ = (ForeignKeyConstraint(["blob_id"], ["v2_blobs.id"]),
        Index("ix_v2_attempt_blob", "blob_id", "state"),
        Index("ix_v2_attempt_scheduler", "state", "next_attempt", "lease_until", "id"))


class Reference(Base):
    __tablename__ = "v2_references"
    space_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), primary_key=True)
    record_id: Mapped[str] = mapped_column(String(64))
    generation: Mapped[int] = mapped_column(Integer, default=1)
    fence: Mapped[int] = mapped_column(Integer, default=0)
    fence_counter = synonym("fence")
    __table_args__ = (ForeignKeyConstraint(["space_id", "record_id"], ["v2_records.space_id", "v2_records.id"]),)


class Coordination(Base):
    __tablename__ = "v2_coordinations"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    space_id: Mapped[str] = mapped_column(String(64))
    reference_name: Mapped[str] = mapped_column(String(128))
    expected_generation: Mapped[int] = mapped_column(Integer)
    holder: Mapped[str] = mapped_column(String(64))
    fence: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(24), default="active")
    lease_until: Mapped[float] = mapped_column()
    result_record_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[float] = mapped_column(default=time.time)
    __table_args__ = (UniqueConstraint("space_id", "id"),
        ForeignKeyConstraint(["space_id", "reference_name"], ["v2_references.space_id", "v2_references.name"]),
        ForeignKeyConstraint(["space_id", "result_record_id"], ["v2_records.space_id", "v2_records.id"]),
        Index("ix_v2_coord_reference", "space_id", "reference_name", "state"))


class CoordinationInput(Base):
    __tablename__ = "v2_coordination_inputs"
    attempt_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    record_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    space_id: Mapped[str] = mapped_column(String(64))
    __table_args__ = (ForeignKeyConstraint(["space_id", "attempt_id"], ["v2_coordinations.space_id", "v2_coordinations.id"]),
        ForeignKeyConstraint(["space_id", "record_id"], ["v2_records.space_id", "v2_records.id"]))


class Event(Base):
    __tablename__ = "v2_events"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    space_id: Mapped[str] = mapped_column(String(64))
    record_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    type: Mapped[str] = mapped_column(String(64))
    principal_id: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)
    created_at: Mapped[float] = mapped_column(default=time.time)
    __table_args__ = (ForeignKeyConstraint(["space_id"], ["v2_spaces.id"]),
        Index("ix_v2_events_space_cursor", "space_id", "id"),
        Index("ix_v2_events_retention", "created_at", "id"))


class Operation(Base):
    __tablename__ = "v2_operations"
    space_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    principal_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scope: Mapped[str] = mapped_column(String(256), primary_key=True)
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    request_hash: Mapped[str] = mapped_column(String(64))
    response: Mapped[dict] = mapped_column(JSON_VALUE)
    created_at: Mapped[float] = mapped_column(default=time.time)
    __table_args__ = (Index("ix_v2_operation_retention", "created_at"),)


def database(url_or_settings, settings=None):
    if not isinstance(url_or_settings, str):
        settings = url_or_settings
        url = settings.url
    else:
        url = url_or_settings
    kwargs = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
        if url in {"sqlite://", "sqlite:///:memory:"}:
            kwargs["poolclass"] = StaticPool
    elif settings:
        kwargs.update(pool_size=settings.pool_size, max_overflow=settings.pool_overflow,
                      pool_timeout=settings.pool_timeout, pool_recycle=settings.pool_recycle)
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def configure(connection, _):
            connection.isolation_level = None
            connection.execute("PRAGMA foreign_keys=ON")

        @event.listens_for(engine, "begin")
        def begin(connection):
            connection.exec_driver_sql("BEGIN IMMEDIATE" if connection.get_execution_options().get("exchange_write", True) else "BEGIN")
    return engine, sessionmaker(engine, expire_on_commit=False)
