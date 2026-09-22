"""Schema v2. PostgreSQL for deployment; SQLite for local development/tests."""
import time
from sqlalchemy import (
    BigInteger, ForeignKeyConstraint, Index, Integer, JSON, String, UniqueConstraint,
    create_engine, event, func, select,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


JSON_VALUE = JSON().with_variant(JSONB(), "postgresql")


def database_time(session):
    """Database clock, shared by all API/worker processes for lease decisions."""
    if session.bind.dialect.name == "postgresql":
        return float(session.scalar(select(func.extract("epoch", func.clock_timestamp()))))
    return float(session.scalar(select((func.julianday("now") - 2440587.5) * 86400)))


class Space(Base):
    __tablename__ = "exchange_spaces"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant: Mapped[str] = mapped_column(String(128))
    name: Mapped[str] = mapped_column(String(128))
    quota: Mapped[int] = mapped_column(BigInteger)
    principal_quota: Mapped[int] = mapped_column(BigInteger)
    allocated: Mapped[int] = mapped_column(BigInteger, default=0)
    reclaiming: Mapped[int] = mapped_column(BigInteger, default=0)
    event_floor: Mapped[int] = mapped_column(BigInteger, default=0)
    rules: Mapped[dict] = mapped_column(JSON_VALUE)
    generation: Mapped[int] = mapped_column(Integer, default=1)


class Member(Base):
    __tablename__ = "exchange_members"
    space_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    principal: Mapped[str] = mapped_column(String(64), primary_key=True)
    roles: Mapped[list] = mapped_column(JSON_VALUE)
    participant: Mapped[str | None] = mapped_column(String(128), nullable=True)
    subject: Mapped[str | None] = mapped_column(String(256), nullable=True)
    __table_args__ = (
        ForeignKeyConstraint(["space_id"], ["exchange_spaces.id"]),
        UniqueConstraint("space_id", "participant"),
    )


class Record(Base):
    __tablename__ = "exchange_records"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    space_id: Mapped[str] = mapped_column(String(64), index=True)
    creator: Mapped[str] = mapped_column(String(64))
    participant: Mapped[str | None] = mapped_column(String(128), nullable=True)
    kind: Mapped[str] = mapped_column(String(128), index=True)
    base_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    data: Mapped[dict] = mapped_column(JSON_VALUE)
    schema_version: Mapped[int] = mapped_column(Integer, default=1)
    state: Mapped[str] = mapped_column(String(24), default="draft", index=True)
    shared: Mapped[bool] = mapped_column(default=False)
    generation: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[float] = mapped_column(default=time.time, index=True)
    published_at: Mapped[float | None] = mapped_column(nullable=True, index=True)
    expires_at: Mapped[float] = mapped_column()
    __table_args__ = (
        UniqueConstraint("space_id", "id"),
        ForeignKeyConstraint(["space_id"], ["exchange_spaces.id"]),
        ForeignKeyConstraint(["space_id", "base_id"], ["exchange_records.space_id", "exchange_records.id"]),
        Index("ix_exchange_records_discovery", "space_id", "kind", "state", "base_id", "published_at"),
        Index("ix_exchange_records_creator_state", "space_id", "creator", "state"),
        Index("ix_exchange_records_expiry", "state", "expires_at", "id"),
    )


class Blob(Base):
    __tablename__ = "exchange_blobs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    space_id: Mapped[str] = mapped_column(String(64))
    record_id: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(256))
    size: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    verified_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    key: Mapped[str] = mapped_column(String(512), unique=True)
    version: Mapped[str | None] = mapped_column(String(256), nullable=True)
    upload_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    state: Mapped[str] = mapped_column(String(24), default="reserved", index=True)
    part_bytes: Mapped[int] = mapped_column(BigInteger)
    expires_at: Mapped[float] = mapped_column()
    updated_at: Mapped[float] = mapped_column(default=time.time)
    worker_lease_until: Mapped[float | None] = mapped_column(nullable=True)
    worker_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    __table_args__ = (
        UniqueConstraint("record_id", "name"),
        Index("ix_exchange_blobs_state_updated", "state", "updated_at"),
        Index("ix_exchange_blobs_cleanup", "record_id", "expires_at", "id"),
        ForeignKeyConstraint(["space_id", "record_id"], ["exchange_records.space_id", "exchange_records.id"]),
    )


class Ref(Base):
    __tablename__ = "exchange_refs"
    space_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), primary_key=True)
    record_id: Mapped[str] = mapped_column(String(64))
    generation: Mapped[int] = mapped_column(Integer, default=1)
    __table_args__ = (
        ForeignKeyConstraint(["space_id", "record_id"], ["exchange_records.space_id", "exchange_records.id"]),
    )


class Operation(Base):
    __tablename__ = "exchange_operations"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    digest: Mapped[str] = mapped_column(String(64))
    result: Mapped[dict] = mapped_column(JSON_VALUE)
    created_at: Mapped[float] = mapped_column(default=time.time, index=True)


class Event(Base):
    __tablename__ = "exchange_events"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    space_id: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(64))
    record_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    principal: Mapped[str] = mapped_column(String(64))
    data: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)
    created_at: Mapped[float] = mapped_column(default=time.time)
    __table_args__ = (Index("ix_exchange_events_space_id_id", "space_id", "id"),)


class Claim(Base):
    __tablename__ = "exchange_claims"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    space_id: Mapped[str] = mapped_column(String(64))
    workflow: Mapped[str] = mapped_column(String(128))
    base_id: Mapped[str] = mapped_column(String(64))
    ref_generation: Mapped[int] = mapped_column(Integer)
    inputs: Mapped[list] = mapped_column(JSON_VALUE)
    holder: Mapped[str] = mapped_column(String(64))
    fence: Mapped[int] = mapped_column(Integer, default=1)
    lease_until: Mapped[float] = mapped_column()
    result_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    __table_args__ = (
        UniqueConstraint("space_id", "workflow", "base_id"),
        ForeignKeyConstraint(["space_id", "base_id"], ["exchange_records.space_id", "exchange_records.id"]),
    )


def database(url, settings=None):
    engine = create_engine(url, pool_pre_ping=True,
                           **({"pool_size": settings.pool_size, "max_overflow": settings.pool_overflow,
                               "pool_timeout": settings.pool_timeout, "pool_recycle": settings.pool_recycle}
                              if settings and not url.startswith("sqlite") else {}),
                           connect_args={"check_same_thread": False, "timeout": 30} if url.startswith("sqlite") else {})
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def configure(connection, _):
            connection.isolation_level = None
            connection.execute("PRAGMA foreign_keys=ON")

        @event.listens_for(engine, "begin")
        def begin(connection):
            connection.exec_driver_sql("BEGIN IMMEDIATE" if connection.get_execution_options().get("exchange_write", True)
                                       else "BEGIN")
    return engine, sessionmaker(engine, expire_on_commit=False)
