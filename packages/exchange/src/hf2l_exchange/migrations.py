"""Immutable, ordered schema revisions for fresh v2 deployments.

The baseline DDL below is a frozen migration artifact, not compiled from current
ORM mappings at runtime. Future upgrades append a new immutable migration and
advance the ledger only after that migration succeeds. V1 databases are rejected.
"""
import sqlite3
from sqlalchemy import inspect, text
from sqlalchemy.exc import DBAPIError
from .domain import Error

SCHEMA_REVISION = "0001_initial"
REVISION = SCHEMA_REVISION
LEDGER = "v2_schema_ledger"

SQLITE_BASELINE = (
    'CREATE TABLE v2_operations (\n\tspace_id VARCHAR(64) NOT NULL, \n\tprincipal_id VARCHAR(64) NOT NULL, \n\tscope VARCHAR(256) NOT NULL, \n\t"key" VARCHAR(128) NOT NULL, \n\trequest_hash VARCHAR(64) NOT NULL, \n\tresponse JSON NOT NULL, \n\tcreated_at FLOAT NOT NULL, \n\tPRIMARY KEY (space_id, principal_id, scope, "key")\n)',
    'CREATE TABLE v2_spaces (\n\tid VARCHAR(64) NOT NULL, \n\tname VARCHAR(128) NOT NULL, \n\tprofile VARCHAR(64) NOT NULL, \n\tgeneration INTEGER NOT NULL, \n\tquota_bytes BIGINT NOT NULL, \n\tprincipal_quota_bytes BIGINT NOT NULL, \n\tallocated BIGINT NOT NULL, \n\treclaiming BIGINT NOT NULL, \n\tquota_records BIGINT NOT NULL, \n\trecord_count BIGINT NOT NULL, \n\tquota_metadata_bytes BIGINT NOT NULL, \n\tmetadata_bytes BIGINT NOT NULL, \n\tevent_floor BIGINT NOT NULL, \n\tPRIMARY KEY (id)\n)',
    'CREATE TABLE v2_events (\n\tid INTEGER NOT NULL, \n\tspace_id VARCHAR(64) NOT NULL, \n\trecord_id VARCHAR(64), \n\ttype VARCHAR(64) NOT NULL, \n\tprincipal_id VARCHAR(64) NOT NULL, \n\tpayload JSON NOT NULL, \n\tcreated_at FLOAT NOT NULL, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(space_id) REFERENCES v2_spaces (id)\n)',
    'CREATE TABLE v2_kind_policies (\n\tspace_id VARCHAR(64) NOT NULL, \n\tkind VARCHAR(128) NOT NULL, \n\tpublish_roles JSON NOT NULL, \n\tvisibility VARCHAR(24) NOT NULL, \n\tgeneration INTEGER NOT NULL, \n\tPRIMARY KEY (space_id, kind), \n\tFOREIGN KEY(space_id) REFERENCES v2_spaces (id)\n)',
    'CREATE TABLE v2_members (\n\tspace_id VARCHAR(64) NOT NULL, \n\tprincipal_id VARCHAR(64) NOT NULL, \n\tsubject VARCHAR(256), \n\troles JSON NOT NULL, \n\tbindings JSON NOT NULL, \n\tPRIMARY KEY (space_id, principal_id), \n\tFOREIGN KEY(space_id) REFERENCES v2_spaces (id)\n)',
    'CREATE TABLE v2_schema_revisions (\n\tid VARCHAR(64) NOT NULL, \n\tspace_id VARCHAR(64) NOT NULL, \n\tkind VARCHAR(128) NOT NULL, \n\trevision INTEGER NOT NULL, \n\tschema JSON NOT NULL, \n\tprofile_version VARCHAR(64) NOT NULL, \n\tdialect VARCHAR(256) NOT NULL, \n\tdigest VARCHAR(64) NOT NULL, \n\tcreated_at FLOAT NOT NULL, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(space_id) REFERENCES v2_spaces (id), \n\tUNIQUE (space_id, kind, revision), \n\tUNIQUE (space_id, id)\n)',
    'CREATE TABLE v2_records (\n\tid VARCHAR(64) NOT NULL, \n\tspace_id VARCHAR(64) NOT NULL, \n\tkind VARCHAR(128) NOT NULL, \n\tschema_revision_id VARCHAR(64) NOT NULL, \n\tcreator VARCHAR(64) NOT NULL, \n\tcreator_bindings JSON NOT NULL, \n\tbase_record_id VARCHAR(64), \n\tmetadata_json JSON NOT NULL, \n\tstate VARCHAR(24) NOT NULL, \n\tshared BOOLEAN NOT NULL, \n\tgeneration INTEGER NOT NULL, \n\tdeclared_bytes BIGINT NOT NULL, \n\tmetadata_bytes BIGINT NOT NULL, \n\tcreated_at FLOAT NOT NULL, \n\tpublished_at FLOAT, \n\texpires_at FLOAT NOT NULL, \n\tPRIMARY KEY (id), \n\tUNIQUE (space_id, id), \n\tFOREIGN KEY(space_id) REFERENCES v2_spaces (id), \n\tFOREIGN KEY(space_id, schema_revision_id) REFERENCES v2_schema_revisions (space_id, id), \n\tFOREIGN KEY(space_id, base_record_id) REFERENCES v2_records (space_id, id)\n)',
    'CREATE TABLE v2_blobs (\n\tid VARCHAR(64) NOT NULL, \n\tspace_id VARCHAR(64) NOT NULL, \n\trecord_id VARCHAR(64) NOT NULL, \n\tpath VARCHAR(256) NOT NULL, \n\tsize BIGINT NOT NULL, \n\tsha256 VARCHAR(64) NOT NULL, \n\tmedia_type VARCHAR(256) NOT NULL, \n\tstate VARCHAR(24) NOT NULL, \n\tobject_key VARCHAR(1024), \n\tobject_version VARCHAR(512), \n\tverified_size BIGINT, \n\tverified_sha256 VARCHAR(64), \n\tpart_size BIGINT NOT NULL, \n\tgrant_expires_at FLOAT NOT NULL, \n\tpending_deletion BOOLEAN NOT NULL, \n\texpires_at FLOAT NOT NULL, \n\tPRIMARY KEY (id), \n\tUNIQUE (record_id, path), \n\tFOREIGN KEY(space_id, record_id) REFERENCES v2_records (space_id, id)\n)',
    'CREATE TABLE v2_references (\n\tspace_id VARCHAR(64) NOT NULL, \n\tname VARCHAR(128) NOT NULL, \n\trecord_id VARCHAR(64) NOT NULL, \n\tgeneration INTEGER NOT NULL, \n\tfence INTEGER NOT NULL, \n\tPRIMARY KEY (space_id, name), \n\tFOREIGN KEY(space_id, record_id) REFERENCES v2_records (space_id, id)\n)',
    'CREATE TABLE v2_coordinations (\n\tid VARCHAR(64) NOT NULL, \n\tspace_id VARCHAR(64) NOT NULL, \n\treference_name VARCHAR(128) NOT NULL, \n\texpected_generation INTEGER NOT NULL, \n\tholder VARCHAR(64) NOT NULL, \n\tfence INTEGER NOT NULL, \n\tstate VARCHAR(24) NOT NULL, \n\tlease_until FLOAT NOT NULL, \n\tresult_record_id VARCHAR(64), \n\tcreated_at FLOAT NOT NULL, \n\tPRIMARY KEY (id), \n\tUNIQUE (space_id, id), \n\tFOREIGN KEY(space_id, reference_name) REFERENCES v2_references (space_id, name), \n\tFOREIGN KEY(space_id, result_record_id) REFERENCES v2_records (space_id, id)\n)',
    'CREATE TABLE v2_transfer_attempts (\n\tid VARCHAR(64) NOT NULL, \n\tblob_id VARCHAR(64) NOT NULL, \n\toperation VARCHAR(24) NOT NULL, \n\tobject_key VARCHAR(1024) NOT NULL, \n\tstate VARCHAR(24) NOT NULL, \n\ttoken VARCHAR(64), \n\tlease_until FLOAT, \n\tretry_count INTEGER NOT NULL, \n\tnext_attempt FLOAT NOT NULL, \n\tlast_error VARCHAR(256), \n\tupload_handle JSON NOT NULL, \n\tmutation_tokens JSON NOT NULL, \n\tgrant_expires_at FLOAT NOT NULL, \n\tcreated_at FLOAT NOT NULL, \n\tupdated_at FLOAT NOT NULL, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(blob_id) REFERENCES v2_blobs (id), \n\tUNIQUE (object_key)\n)',
    'CREATE TABLE v2_coordination_inputs (\n\tattempt_id VARCHAR(64) NOT NULL, \n\trecord_id VARCHAR(64) NOT NULL, \n\tspace_id VARCHAR(64) NOT NULL, \n\tPRIMARY KEY (attempt_id, record_id), \n\tFOREIGN KEY(space_id, attempt_id) REFERENCES v2_coordinations (space_id, id), \n\tFOREIGN KEY(space_id, record_id) REFERENCES v2_records (space_id, id)\n)',
    'CREATE INDEX ix_v2_operation_retention ON v2_operations (created_at)',
    'CREATE INDEX ix_v2_events_retention ON v2_events (created_at, id)',
    'CREATE INDEX ix_v2_events_space_cursor ON v2_events (space_id, id)',
    'CREATE INDEX ix_v2_records_creator_state ON v2_records (space_id, creator, state)',
    'CREATE INDEX ix_v2_records_discovery ON v2_records (space_id, kind, state, published_at, id)',
    'CREATE INDEX ix_v2_records_expiry ON v2_records (state, expires_at, id)',
    'CREATE INDEX ix_v2_blobs_cleanup ON v2_blobs (state, expires_at, id)',
    'CREATE INDEX ix_v2_blobs_record ON v2_blobs (record_id, id)',
    'CREATE INDEX ix_v2_coord_reference ON v2_coordinations (space_id, reference_name, state)',
    'CREATE INDEX ix_v2_attempt_blob ON v2_transfer_attempts (blob_id, state)',
    'CREATE INDEX ix_v2_attempt_scheduler ON v2_transfer_attempts (state, next_attempt, lease_until, id)',
)

POSTGRESQL_BASELINE = (
    'CREATE TABLE v2_operations (\n\tspace_id VARCHAR(64) NOT NULL, \n\tprincipal_id VARCHAR(64) NOT NULL, \n\tscope VARCHAR(256) NOT NULL, \n\tkey VARCHAR(128) NOT NULL, \n\trequest_hash VARCHAR(64) NOT NULL, \n\tresponse JSONB NOT NULL, \n\tcreated_at FLOAT NOT NULL, \n\tPRIMARY KEY (space_id, principal_id, scope, key)\n)',
    'CREATE TABLE v2_spaces (\n\tid VARCHAR(64) NOT NULL, \n\tname VARCHAR(128) NOT NULL, \n\tprofile VARCHAR(64) NOT NULL, \n\tgeneration INTEGER NOT NULL, \n\tquota_bytes BIGINT NOT NULL, \n\tprincipal_quota_bytes BIGINT NOT NULL, \n\tallocated BIGINT NOT NULL, \n\treclaiming BIGINT NOT NULL, \n\tquota_records BIGINT NOT NULL, \n\trecord_count BIGINT NOT NULL, \n\tquota_metadata_bytes BIGINT NOT NULL, \n\tmetadata_bytes BIGINT NOT NULL, \n\tevent_floor BIGINT NOT NULL, \n\tPRIMARY KEY (id)\n)',
    'CREATE TABLE v2_events (\n\tid BIGSERIAL NOT NULL, \n\tspace_id VARCHAR(64) NOT NULL, \n\trecord_id VARCHAR(64), \n\ttype VARCHAR(64) NOT NULL, \n\tprincipal_id VARCHAR(64) NOT NULL, \n\tpayload JSONB NOT NULL, \n\tcreated_at FLOAT NOT NULL, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(space_id) REFERENCES v2_spaces (id)\n)',
    'CREATE TABLE v2_kind_policies (\n\tspace_id VARCHAR(64) NOT NULL, \n\tkind VARCHAR(128) NOT NULL, \n\tpublish_roles JSONB NOT NULL, \n\tvisibility VARCHAR(24) NOT NULL, \n\tgeneration INTEGER NOT NULL, \n\tPRIMARY KEY (space_id, kind), \n\tFOREIGN KEY(space_id) REFERENCES v2_spaces (id)\n)',
    'CREATE TABLE v2_members (\n\tspace_id VARCHAR(64) NOT NULL, \n\tprincipal_id VARCHAR(64) NOT NULL, \n\tsubject VARCHAR(256), \n\troles JSONB NOT NULL, \n\tbindings JSONB NOT NULL, \n\tPRIMARY KEY (space_id, principal_id), \n\tFOREIGN KEY(space_id) REFERENCES v2_spaces (id)\n)',
    'CREATE TABLE v2_schema_revisions (\n\tid VARCHAR(64) NOT NULL, \n\tspace_id VARCHAR(64) NOT NULL, \n\tkind VARCHAR(128) NOT NULL, \n\trevision INTEGER NOT NULL, \n\tschema JSONB NOT NULL, \n\tprofile_version VARCHAR(64) NOT NULL, \n\tdialect VARCHAR(256) NOT NULL, \n\tdigest VARCHAR(64) NOT NULL, \n\tcreated_at FLOAT NOT NULL, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(space_id) REFERENCES v2_spaces (id), \n\tUNIQUE (space_id, kind, revision), \n\tUNIQUE (space_id, id)\n)',
    'CREATE TABLE v2_records (\n\tid VARCHAR(64) NOT NULL, \n\tspace_id VARCHAR(64) NOT NULL, \n\tkind VARCHAR(128) NOT NULL, \n\tschema_revision_id VARCHAR(64) NOT NULL, \n\tcreator VARCHAR(64) NOT NULL, \n\tcreator_bindings JSONB NOT NULL, \n\tbase_record_id VARCHAR(64), \n\tmetadata_json JSONB NOT NULL, \n\tstate VARCHAR(24) NOT NULL, \n\tshared BOOLEAN NOT NULL, \n\tgeneration INTEGER NOT NULL, \n\tdeclared_bytes BIGINT NOT NULL, \n\tmetadata_bytes BIGINT NOT NULL, \n\tcreated_at FLOAT NOT NULL, \n\tpublished_at FLOAT, \n\texpires_at FLOAT NOT NULL, \n\tPRIMARY KEY (id), \n\tUNIQUE (space_id, id), \n\tFOREIGN KEY(space_id) REFERENCES v2_spaces (id), \n\tFOREIGN KEY(space_id, schema_revision_id) REFERENCES v2_schema_revisions (space_id, id), \n\tFOREIGN KEY(space_id, base_record_id) REFERENCES v2_records (space_id, id)\n)',
    'CREATE TABLE v2_blobs (\n\tid VARCHAR(64) NOT NULL, \n\tspace_id VARCHAR(64) NOT NULL, \n\trecord_id VARCHAR(64) NOT NULL, \n\tpath VARCHAR(256) NOT NULL, \n\tsize BIGINT NOT NULL, \n\tsha256 VARCHAR(64) NOT NULL, \n\tmedia_type VARCHAR(256) NOT NULL, \n\tstate VARCHAR(24) NOT NULL, \n\tobject_key VARCHAR(1024), \n\tobject_version VARCHAR(512), \n\tverified_size BIGINT, \n\tverified_sha256 VARCHAR(64), \n\tpart_size BIGINT NOT NULL, \n\tgrant_expires_at FLOAT NOT NULL, \n\tpending_deletion BOOLEAN NOT NULL, \n\texpires_at FLOAT NOT NULL, \n\tPRIMARY KEY (id), \n\tUNIQUE (record_id, path), \n\tFOREIGN KEY(space_id, record_id) REFERENCES v2_records (space_id, id)\n)',
    'CREATE TABLE v2_references (\n\tspace_id VARCHAR(64) NOT NULL, \n\tname VARCHAR(128) NOT NULL, \n\trecord_id VARCHAR(64) NOT NULL, \n\tgeneration INTEGER NOT NULL, \n\tfence INTEGER NOT NULL, \n\tPRIMARY KEY (space_id, name), \n\tFOREIGN KEY(space_id, record_id) REFERENCES v2_records (space_id, id)\n)',
    'CREATE TABLE v2_coordinations (\n\tid VARCHAR(64) NOT NULL, \n\tspace_id VARCHAR(64) NOT NULL, \n\treference_name VARCHAR(128) NOT NULL, \n\texpected_generation INTEGER NOT NULL, \n\tholder VARCHAR(64) NOT NULL, \n\tfence INTEGER NOT NULL, \n\tstate VARCHAR(24) NOT NULL, \n\tlease_until FLOAT NOT NULL, \n\tresult_record_id VARCHAR(64), \n\tcreated_at FLOAT NOT NULL, \n\tPRIMARY KEY (id), \n\tUNIQUE (space_id, id), \n\tFOREIGN KEY(space_id, reference_name) REFERENCES v2_references (space_id, name), \n\tFOREIGN KEY(space_id, result_record_id) REFERENCES v2_records (space_id, id)\n)',
    'CREATE TABLE v2_transfer_attempts (\n\tid VARCHAR(64) NOT NULL, \n\tblob_id VARCHAR(64) NOT NULL, \n\toperation VARCHAR(24) NOT NULL, \n\tobject_key VARCHAR(1024) NOT NULL, \n\tstate VARCHAR(24) NOT NULL, \n\ttoken VARCHAR(64), \n\tlease_until FLOAT, \n\tretry_count INTEGER NOT NULL, \n\tnext_attempt FLOAT NOT NULL, \n\tlast_error VARCHAR(256), \n\tupload_handle JSONB NOT NULL, \n\tmutation_tokens JSONB NOT NULL, \n\tgrant_expires_at FLOAT NOT NULL, \n\tcreated_at FLOAT NOT NULL, \n\tupdated_at FLOAT NOT NULL, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(blob_id) REFERENCES v2_blobs (id), \n\tUNIQUE (object_key)\n)',
    'CREATE TABLE v2_coordination_inputs (\n\tattempt_id VARCHAR(64) NOT NULL, \n\trecord_id VARCHAR(64) NOT NULL, \n\tspace_id VARCHAR(64) NOT NULL, \n\tPRIMARY KEY (attempt_id, record_id), \n\tFOREIGN KEY(space_id, attempt_id) REFERENCES v2_coordinations (space_id, id), \n\tFOREIGN KEY(space_id, record_id) REFERENCES v2_records (space_id, id)\n)',
    'CREATE INDEX ix_v2_operation_retention ON v2_operations (created_at)',
    'CREATE INDEX ix_v2_events_retention ON v2_events (created_at, id)',
    'CREATE INDEX ix_v2_events_space_cursor ON v2_events (space_id, id)',
    'CREATE INDEX ix_v2_records_creator_state ON v2_records (space_id, creator, state)',
    'CREATE INDEX ix_v2_records_discovery ON v2_records (space_id, kind, state, published_at, id)',
    'CREATE INDEX ix_v2_records_expiry ON v2_records (state, expires_at, id)',
    'CREATE INDEX ix_v2_blobs_cleanup ON v2_blobs (state, expires_at, id)',
    'CREATE INDEX ix_v2_blobs_record ON v2_blobs (record_id, id)',
    'CREATE INDEX ix_v2_coord_reference ON v2_coordinations (space_id, reference_name, state)',
    'CREATE INDEX ix_v2_attempt_blob ON v2_transfer_attempts (blob_id, state)',
    'CREATE INDEX ix_v2_attempt_scheduler ON v2_transfer_attempts (state, next_attempt, lease_until, id)',
)

EXPECTED_COLUMNS = {'v2_operations': ('space_id', 'principal_id', 'scope', 'key', 'request_hash', 'response', 'created_at'), 'v2_spaces': ('id', 'name', 'profile', 'generation', 'quota_bytes', 'principal_quota_bytes', 'allocated', 'reclaiming', 'quota_records', 'record_count', 'quota_metadata_bytes', 'metadata_bytes', 'event_floor'), 'v2_events': ('id', 'space_id', 'record_id', 'type', 'principal_id', 'payload', 'created_at'), 'v2_kind_policies': ('space_id', 'kind', 'publish_roles', 'visibility', 'generation'), 'v2_members': ('space_id', 'principal_id', 'subject', 'roles', 'bindings'), 'v2_schema_revisions': ('id', 'space_id', 'kind', 'revision', 'schema', 'profile_version', 'dialect', 'digest', 'created_at'), 'v2_records': ('id', 'space_id', 'kind', 'schema_revision_id', 'creator', 'creator_bindings', 'base_record_id', 'metadata_json', 'state', 'shared', 'generation', 'declared_bytes', 'metadata_bytes', 'created_at', 'published_at', 'expires_at'), 'v2_blobs': ('id', 'space_id', 'record_id', 'path', 'size', 'sha256', 'media_type', 'state', 'object_key', 'object_version', 'verified_size', 'verified_sha256', 'part_size', 'grant_expires_at', 'pending_deletion', 'expires_at'), 'v2_references': ('space_id', 'name', 'record_id', 'generation', 'fence'), 'v2_coordinations': ('id', 'space_id', 'reference_name', 'expected_generation', 'holder', 'fence', 'state', 'lease_until', 'result_record_id', 'created_at'), 'v2_transfer_attempts': ('id', 'blob_id', 'operation', 'object_key', 'state', 'token', 'lease_until', 'retry_count', 'next_attempt', 'last_error', 'upload_handle', 'mutation_tokens', 'grant_expires_at', 'created_at', 'updated_at'), 'v2_coordination_inputs': ('attempt_id', 'record_id', 'space_id')}

def _check_connection(connection):
    inspector = inspect(connection)
    tables = set(inspector.get_table_names())
    if any(name.startswith("exchange_") for name in tables):
        raise Error(503, "legacy_database_not_supported", "Deploy v2 into a fresh database and storage prefix")
    if LEDGER not in tables:
        raise Error(503, "database_not_initialized")
    versions = tuple(connection.execute(text("SELECT revision FROM " + LEDGER)).scalars())
    if versions != (SCHEMA_REVISION,):
        raise Error(503, "database_revision_incompatible")
    for table, columns in EXPECTED_COLUMNS.items():
        if table not in tables or not set(columns).issubset({col["name"] for col in inspector.get_columns(table)}):
            raise Error(503, "database_schema_incomplete")
    return SCHEMA_REVISION


def check_revision(engine):
    """Fail closed on unavailable or incompatible ledgers without catalog scans.

    Request paths use this check. Startup and readiness additionally call ``check``
    to validate table structure; neither function initializes or repairs a database.
    """
    try:
        with engine.connect().execution_options(exchange_write=False) as connection:
            versions = tuple(connection.execute(text("SELECT revision FROM " + LEDGER + " ORDER BY revision")).scalars())
    except DBAPIError as exc:
        missing_ledger = (getattr(exc.orig, "sqlstate", None) == "42P01" or
                          isinstance(exc.orig, sqlite3.OperationalError) and
                          str(exc.orig) == "no such table: " + LEDGER)
        raise Error(503, "database_not_initialized" if missing_ledger else "database_unavailable") from None
    if versions != (SCHEMA_REVISION,):
        raise Error(503, "database_revision_incompatible")
    return SCHEMA_REVISION


def check(engine):
    """Readiness check: never create or upgrade a schema."""
    with engine.connect().execution_options(exchange_write=False) as connection:
        return _check_connection(connection)


def initialize(engine):
    """Create the frozen baseline only in an empty v2 namespace."""
    dialect = engine.dialect.name
    if dialect not in {"sqlite", "postgresql"}:
        raise Error(503, "unsupported_database")
    with engine.begin() as connection:
        if dialect == "postgresql":
            connection.execute(text("SELECT pg_advisory_xact_lock(734802341)"))
        tables = set(inspect(connection).get_table_names())
        if any(name.startswith("exchange_") for name in tables):
            raise Error(503, "legacy_database_not_supported", "Deploy v2 into a fresh database and storage prefix")
        if LEDGER in tables:
            return _check_connection(connection)
        if any(name.startswith("v2_") for name in tables):
            raise Error(503, "database_schema_incomplete", "A partial unversioned schema cannot be initialized")
        statements = SQLITE_BASELINE if dialect == "sqlite" else POSTGRESQL_BASELINE
        for statement in statements:
            connection.exec_driver_sql(statement)
        connection.exec_driver_sql("CREATE TABLE " + LEDGER + " (revision VARCHAR(64) PRIMARY KEY)")
        connection.execute(text("INSERT INTO " + LEDGER + " (revision) VALUES (:revision)"), {"revision": SCHEMA_REVISION})
        return _check_connection(connection)


def migrate(engine):
    """Apply known ordered revisions; this initial release supports only its baseline."""
    return initialize(engine)
