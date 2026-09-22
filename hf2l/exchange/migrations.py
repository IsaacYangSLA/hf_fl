"""Explicit, transactional v1 -> v2 upgrade. Stop API/workers and back up the database first."""
from sqlalchemy import inspect, text

from .models import Base


def initialize(engine):
    present = inspect(engine)
    if present.has_table("exchange_blobs") and "worker_token" not in {c["name"] for c in present.get_columns("exchange_blobs")}:
        raise ValueError("Existing schema v1 requires migrate-db; init-db does not silently migrate")
    Base.metadata.create_all(engine)


def migrate(engine):
    with engine.begin() as connection:
        inspector = inspect(connection)
        if not inspector.has_table("exchange_spaces"):
            Base.metadata.create_all(connection)
            return
        pg = connection.dialect.name == "postgresql"
        now = float(connection.scalar(text("SELECT EXTRACT(EPOCH FROM clock_timestamp())" if pg else
                                           "SELECT (julianday('now') - 2440587.5) * 86400")))
        additions = {
            "exchange_spaces": {"reclaiming": "BIGINT NOT NULL DEFAULT 0", "event_floor": "BIGINT NOT NULL DEFAULT 0"},
            "exchange_members": {"subject": "VARCHAR(256)"},
            "exchange_blobs": {"worker_token": "VARCHAR(64)"},
            "exchange_operations": {"created_at": f"DOUBLE PRECISION NOT NULL DEFAULT {now}"},
        }
        new_budget = "reclaiming" not in {c["name"] for c in inspector.get_columns("exchange_spaces")}
        for table, columns in additions.items():
            existing = {c["name"] for c in inspector.get_columns(table)}
            for name, ddl in columns.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
        if new_budget:
            connection.execute(text("""UPDATE exchange_spaces SET reclaiming = COALESCE((
                SELECT SUM(b.size) FROM exchange_blobs b JOIN exchange_records r ON r.id = b.record_id
                WHERE b.space_id = exchange_spaces.id AND b.state <> 'cleaned'
                AND r.state IN ('cancelled','expired','withdrawn','failed')), 0)"""))
        if pg:
            for table in Base.metadata.sorted_tables:
                for column in table.columns:
                    if column.type.__class__.__name__ == "JSON":
                        connection.execute(text(f"ALTER TABLE {table.name} ALTER COLUMN {column.name} "
                                                f"TYPE JSONB USING {column.name}::jsonb"))
        for table in Base.metadata.sorted_tables:
            for index in table.indexes:
                index.create(connection, checkfirst=True)
