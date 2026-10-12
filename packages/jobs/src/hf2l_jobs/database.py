"""Database/session construction with explicit durable transaction boundaries."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from .migrations import check_schema, migrate


@dataclass
class Database:
    engine: object
    session_factory: sessionmaker

    @property
    def sessions(self):
        return self.session_factory

    @contextmanager
    def transaction(self, *, immediate: bool = True):
        session = self.session_factory()
        try:
            if immediate and self.engine.dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            yield session
            session.commit()
        except BaseException:
            session.rollback()
            raise
        finally:
            session.close()

    def migrate(self):
        return migrate(self.engine)

    def check_schema(self):
        return check_schema(self.engine)

    def close(self):
        self.engine.dispose()


def create_database(url: str, *, initialize: bool = True, **engine_options) -> Database:
    """Create connections; callers serving requests should set initialize=False.

    SQLite is suitable for isolated tests and single-controller pilots only.
    Production durable multi-controller operation requires PostgreSQL.
    """
    if url.startswith("sqlite"):
        options = {"connect_args": {"check_same_thread": False, "timeout": 30}}
        if url in ("sqlite://", "sqlite:///:memory:", "sqlite+pysqlite:///:memory:"):
            options["poolclass"] = StaticPool
        options.update(engine_options)
        engine = create_engine(url, **options)

        @event.listens_for(engine, "connect")
        def sqlite_integrity(connection, record):
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.close()
    else:
        engine = create_engine(url, pool_pre_ping=True, **engine_options)
    database = Database(engine, sessionmaker(bind=engine, expire_on_commit=False))
    if initialize:
        migrate(engine)
    return database
