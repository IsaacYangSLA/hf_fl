"""Explicit, transactionally locked manager schema migrations."""
from __future__ import annotations

from sqlalchemy import inspect, select
from sqlalchemy.schema import CreateColumn
from .domain import utcnow
from .models import AdministrativeAudit, Artifact, AuthSession, Base, LogChunk, SchemaRevision

REVISIONS = ("0001_manager", "0002_artifact_locator", "0003_administrative_audit")
CURRENT_REVISION = REVISIONS[-1]
UPGRADE_COLUMNS = {"jm_artifacts": {"locator_json"}, "jm_log_chunks": {"charged_bytes"}}


class SchemaError(RuntimeError):
    pass


def _register_tables():
    # Register auth-owned tables without provider I/O or credential reads.
    from . import auth  # noqa: F401


def _verify_tables(connection, tables, *, legacy=False):
    required = set(Base.metadata.tables) - ({AdministrativeAudit.__tablename__} if legacy else set())
    if not required.issubset(tables):
        raise SchemaError("Manager schema is incomplete; migration required")
    inspector = inspect(connection)
    for name, table in Base.metadata.tables.items():
        if legacy and name == AdministrativeAudit.__tablename__:
            continue
        actual = {item["name"] for item in inspector.get_columns(name)}
        expected = set(table.columns.keys())
        if legacy:
            expected -= UPGRADE_COLUMNS.get(name, set())
        if not expected.issubset(actual):
            raise SchemaError("Manager schema columns are incomplete; migration required")
    if not legacy:
        indexes = {item["name"] for item in inspector.get_indexes(AuthSession.__tablename__)}
        if "ix_jm_sessions_expiry" not in indexes:
            raise SchemaError("Manager schema indexes are incomplete; migration required")
        indexes = {item["name"] for item in inspector.get_indexes(AdministrativeAudit.__tablename__)}
        if not {"ix_jm_admin_audit_resource", "ix_jm_admin_audit_actor"}.issubset(indexes):
            raise SchemaError("Manager audit indexes are incomplete; migration required")


def _revision_status(connection, tables):
    if SchemaRevision.__tablename__ not in tables:
        return set()
    revisions = set(connection.scalars(select(SchemaRevision.revision)))
    if revisions not in [set(REVISIONS[:count]) for count in range(1, len(REVISIONS) + 1)]:
        raise SchemaError("Manager schema revision is unsupported")
    return revisions


def check_schema(engine) -> str:
    _register_tables()
    with engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())
        revisions = _revision_status(connection, tables)
        if not revisions:
            raise SchemaError("Manager schema is absent; run hf2l-jobs init-db")
        if revisions != set(REVISIONS):
            raise SchemaError("Manager schema upgrade is required")
        _verify_tables(connection, tables)
    return CURRENT_REVISION


def _upgrade_artifact_locator(connection):
    inspector = inspect(connection)
    for table, column in ((Artifact.__table__, Artifact.__table__.c.locator_json),
                          (LogChunk.__table__, LogChunk.__table__.c.charged_bytes)):
        existing = {item["name"] for item in inspector.get_columns(table.name)}
        if column.name not in existing:
            definition = str(CreateColumn(column).compile(dialect=connection.dialect))
            if column.name == "charged_bytes":
                definition += " CHECK (charged_bytes >= 0)"
            connection.exec_driver_sql("ALTER TABLE " + table.name + " ADD COLUMN " + definition)
    for index in AuthSession.__table__.indexes:
        if index.name == "ix_jm_sessions_expiry":
            index.create(connection, checkfirst=True)
    connection.execute(SchemaRevision.__table__.insert().values(revision=REVISIONS[1], applied_at=utcnow()))


def _verify_artifact_schema(connection, tables):
    """Validate the complete v2 schema before applying the additive v3 table."""
    _verify_tables(connection, tables, legacy=True)
    inspector = inspect(connection)
    for name, columns in UPGRADE_COLUMNS.items():
        if not columns.issubset({item["name"] for item in inspector.get_columns(name)}):
            raise SchemaError("Manager schema columns are incomplete; migration required")
    indexes = {item["name"] for item in inspector.get_indexes(AuthSession.__tablename__)}
    if "ix_jm_sessions_expiry" not in indexes:
        raise SchemaError("Manager schema indexes are incomplete; migration required")


def _upgrade_administrative_audit(connection):
    # A versioned v2 database may not silently repair a partial v3 schema.
    if AdministrativeAudit.__tablename__ in set(inspect(connection).get_table_names()):
        raise SchemaError("Unversioned administrative audit table requires operator recovery")
    AdministrativeAudit.__table__.create(connection)
    connection.execute(SchemaRevision.__table__.insert().values(revision=REVISIONS[2], applied_at=utcnow()))


def migrate(engine) -> str:
    """Apply locked additive migrations, preserving old artifacts and history.

    Existing descriptors receive a null trusted locator and fail closed until
    the trusted collector registers one. They are never resolved from strings.
    PostgreSQL advisory locking and SQLite BEGIN IMMEDIATE serialize DDL.
    All schema changes and revision records commit or roll back together.
    Administrative audit history has no cascading link to mutable resources.
    """
    _register_tables()
    with engine.connect() as connection:
        try:
            if engine.dialect.name == "sqlite":
                connection.exec_driver_sql("BEGIN IMMEDIATE")
            else:
                connection.begin()
                if engine.dialect.name == "postgresql":
                    connection.exec_driver_sql("SELECT pg_advisory_xact_lock(714295130845211)")
            tables = set(inspect(connection).get_table_names())
            revisions = _revision_status(connection, tables)
            if revisions == set(REVISIONS):
                _verify_tables(connection, tables)
            elif revisions:
                if revisions == {REVISIONS[0]}:
                    _verify_tables(connection, tables, legacy=True)
                    _upgrade_artifact_locator(connection)
                _verify_artifact_schema(connection, set(inspect(connection).get_table_names()))
                _upgrade_administrative_audit(connection)
                _verify_tables(connection, set(inspect(connection).get_table_names()))
            else:
                if any(name in Base.metadata.tables for name in tables):
                    raise SchemaError("Unversioned partial manager schema requires operator recovery")
                Base.metadata.create_all(connection)
                for revision in REVISIONS:
                    connection.execute(SchemaRevision.__table__.insert().values(revision=revision, applied_at=utcnow()))
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
    return CURRENT_REVISION


initialize = migrate
upgrade = migrate
