"""Schema v1. PostgreSQL for deployment; SQLite for local development/tests."""
import time
from sqlalchemy import (
    BigInteger, ForeignKeyConstraint, Integer, JSON, String, UniqueConstraint,
    create_engine, event,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class Space(Base):
    __tablename__ = "exchange_spaces"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant: Mapped[str] = mapped_column(String(128))
    name: Mapped[str] = mapped_column(String(128))
    quota: Mapped[int] = mapped_column(BigInteger)
    allocated: Mapped[int] = mapped_column(BigInteger, default=0)
    rules: Mapped[dict] = mapped_column(JSON)


class Member(Base):
    __tablename__ = "exchange_members"
    space_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    principal: Mapped[str] = mapped_column(String(64), primary_key=True)
    roles: Mapped[list] = mapped_column(JSON)
    participant: Mapped[str | None] = mapped_column(String(128), nullable=True)
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
    data: Mapped[dict] = mapped_column(JSON)
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
    __table_args__ = (
        UniqueConstraint("record_id", "name"),
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
    result: Mapped[dict] = mapped_column(JSON)


class Event(Base):
    __tablename__ = "exchange_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    space_id: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(64))
    record_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    principal: Mapped[str] = mapped_column(String(64))
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[float] = mapped_column(default=time.time)


class Claim(Base):
    __tablename__ = "exchange_claims"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    space_id: Mapped[str] = mapped_column(String(64))
    workflow: Mapped[str] = mapped_column(String(128))
    base_id: Mapped[str] = mapped_column(String(64))
    ref_generation: Mapped[int] = mapped_column(Integer)
    inputs: Mapped[list] = mapped_column(JSON)
    holder: Mapped[str] = mapped_column(String(64))
    fence: Mapped[int] = mapped_column(Integer, default=1)
    lease_until: Mapped[float] = mapped_column()
    result_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    __table_args__ = (
        UniqueConstraint("space_id", "workflow", "base_id"),
        ForeignKeyConstraint(["space_id", "base_id"], ["exchange_records.space_id", "exchange_records.id"]),
    )


def database(url):
    engine = create_engine(url, pool_pre_ping=True,
                           connect_args={"check_same_thread": False, "timeout": 30} if url.startswith("sqlite") else {})
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def configure(connection, _):
            connection.isolation_level = None
            connection.execute("PRAGMA foreign_keys=ON")

        @event.listens_for(engine, "begin")
        def begin(connection):
            connection.exec_driver_sql("BEGIN IMMEDIATE")
    return engine, sessionmaker(engine, expire_on_commit=False)
