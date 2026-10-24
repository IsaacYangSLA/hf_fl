"""Regenerate the Go store schema from the Python reference metadata.

Development-only: run from the repository with the jobs server dependencies.
The Go runtime embeds the resulting JSON and never imports Python.
"""
import json
from pathlib import Path
from sqlalchemy.schema import CreateColumn, CreateIndex, CreateTable
from sqlalchemy import CheckConstraint, MetaData, text
from sqlalchemy.dialects import sqlite, postgresql
from hf2l_jobs import auth
from hf2l_jobs.models import Base, Artifact, LogChunk
from hf2l_jobs.migrations import REVISIONS

def main():
    dialects = {"sqlite": sqlite.dialect(), "postgresql": postgresql.dialect()}
    result = {"revisions": list(REVISIONS), "tables": [], "upgrades": {}}
    for table in Base.metadata.sorted_tables:
        columns = []
        for column in table.columns:
            kind = type(column.type).__name__
            item = {"name": column.name, "nullable": column.nullable,
                    "primary_key": column.primary_key,
                    "kind": "json" if kind == "JSON" else "bool" if kind == "Boolean"
                        else "time" if kind in ("UTCDateTime", "DateTime") else "value"}
            if column.default is not None:
                value = column.default.arg
                if callable(value):
                    name = value.__name__
                    item["default"] = {"kind": {"new_id": "id", "utcnow": "now",
                        "list": "list", "dict": "map"}[name]}
                else:
                    item["default"] = {"kind": "value", "value": value}
            columns.append(item)
        result["tables"].append({
            "name": table.name, "columns": columns,
            "create": {name: str(CreateTable(table).compile(dialect=dialect))
                for name, dialect in dialects.items()},
            "indexes": [{"name": index.name,
                "create": {name: str(CreateIndex(index).compile(dialect=dialect))
                    for name, dialect in dialects.items()}}
                for index in sorted(table.indexes, key=lambda value: value.name)],
        })
    for table, column in ((Artifact.__table__, Artifact.__table__.c.locator_json),
                           (LogChunk.__table__, LogChunk.__table__.c.charged_bytes)):
        result["upgrades"][table.name] = {
            "column": column.name,
            "definition": {name: str(CreateColumn(column).compile(dialect=dialect)) +
                (" CHECK (charged_bytes >= 0)" if column.name == "charged_bytes" else "")
                for name, dialect in dialects.items()},
        }
    Path(__file__).with_name("schema.json").write_text(json.dumps(result,
        sort_keys=True, indent=2) + "\n")
    fixtures = Path(__file__).with_name("testdata")
    fixtures.mkdir(exist_ok=True)
    for revision in (1, 2):
        snapshot = MetaData()
        for table in Base.metadata.sorted_tables:
            if table.name != "jm_admin_audit":
                table.to_metadata(snapshot)
        if revision == 1:
            snapshot.tables["jm_artifacts"]._columns.remove(
                snapshot.tables["jm_artifacts"].c.locator_json)
            logs = snapshot.tables["jm_log_chunks"]
            logs._columns.remove(logs.c.charged_bytes)
            for constraint in logs.constraints:
                if isinstance(constraint, CheckConstraint):
                    constraint.sqltext = text(str(constraint.sqltext).replace(
                        " AND charged_bytes >= 0", ""))
            sessions = snapshot.tables["jm_auth_sessions"]
            sessions.indexes = {index for index in sessions.indexes
                if index.name != "ix_jm_sessions_expiry"}
        # Table.to_metadata copies constraints from sets. Restore a stable
        # creation order so fixtures regenerate byte-for-byte across processes.
        for table in snapshot.tables.values():
            def constraint_key(constraint):
                return (type(constraint).__name__, str(constraint.name or ""),
                    str(getattr(constraint, "sqltext", "")),
                    tuple(column.name for column in constraint.columns),
                    tuple(element.target_fullname for element in
                        getattr(constraint, "elements", ())))
            for order, constraint in enumerate(sorted(table.constraints,
                    key=constraint_key)):
                constraint._creation_order = order
        for dialect_name, dialect in dialects.items():
            ddl = []
            for table in snapshot.sorted_tables:
                ddl.append(str(CreateTable(table).compile(dialect=dialect)))
            for table in snapshot.sorted_tables:
                ddl.extend(str(CreateIndex(index).compile(dialect=dialect))
                    for index in sorted(table.indexes, key=lambda value: value.name))
            for name in REVISIONS[:revision]:
                ddl.append("INSERT INTO jm_schema_revisions (revision, applied_at) "
                    "VALUES ('" + name + "', '2026-01-01 00:00:00.000000')")
            (fixtures / ("schema_v%d.%s.sql" % (revision, dialect_name))).write_text(
                "-- Frozen Python-reference schema before additive upgrades.\n" +
                ";\n".join(ddl) + ";\n")

if __name__ == "__main__":
    main()
