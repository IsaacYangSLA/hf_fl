"""Reference-only persistence oracle for native Go Exchange tests.

This is test tooling; the Go production service does not invoke Python.
"""
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
from sqlalchemy import select
from hf2l_exchange import models, migrations

action, url = sys.argv[1:3]
if url.startswith("postgresql://"):
    url = url.replace("postgresql://", "postgresql+psycopg://", 1)
elif url.startswith("postgres://"):
    url = url.replace("postgres://", "postgresql+psycopg://", 1)
engine, sessions = models.database(url)
input_file = "orm_null_inputs.json" if action == "create_nulls" or action == "snapshot_nulls" else "orm_inputs.json"
inputs = json.loads((Path(__file__).parent / input_file).read_text())
classes = {c.__table__.name: c for c in [
    models.Space, models.ManagedSpace, models.WorkloadRevocation,
    models.WorkloadGrant, models.Member, models.SchemaRevision, models.KindPolicy,
    models.Record, models.Blob, models.TransferAttempt, models.Reference,
    models.Coordination, models.CoordinationInput, models.Event, models.Operation,
]}
try:
    if action in {"create", "create_nulls"}:
        migrations.initialize(engine)
        with sessions.begin() as session:
            for item in inputs:
                session.add(classes[item["table"]](**item["values"]))
                session.flush()
    migrations.check(engine)
    out = {}
    with sessions.begin() as session:
        for item in inputs:
            cls = classes[item["table"]]
            rows = session.scalars(select(cls)).all()
            out[item["table"]] = [
                {column.name: getattr(row, column.key) for column in cls.__table__.columns}
                for row in rows
            ]
    print(json.dumps(out, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False))
finally:
    engine.dispose()
