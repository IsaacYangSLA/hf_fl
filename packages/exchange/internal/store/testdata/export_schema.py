"""Export/check the reference Exchange DDL and ORM-default manifest for Go.

Test/developer tooling only; native services never import this script or Python.
"""
from pathlib import Path
import argparse
import ast
import json
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from hf2l_exchange.models import Base
from sqlalchemy import JSON, Boolean, Float, Integer

def export():
    tables = []
    for table in Base.metadata.sorted_tables:
        columns = []
        for column in table.columns:
            kind = ("json" if isinstance(column.type, JSON) else
                    "bool" if isinstance(column.type, Boolean) else
                    "float" if isinstance(column.type, Float) else
                    "integer" if isinstance(column.type, Integer) else "string")
            default = None
            if column.default is not None:
                arg = column.default.arg
                if callable(arg):
                    value = arg(None)
                    if isinstance(value, dict):
                        default = {"kind": "map"}
                    elif isinstance(value, list):
                        default = {"kind": "list"}
                    elif isinstance(value, float):
                        default = {"kind": "now"}
                    else:
                        raise ValueError("Unsupported callable default")
                else:
                    default = {"kind": "value", "value": arg}
            columns.append({
                "name": column.name, "kind": kind, "nullable": column.nullable,
                "primary_key": column.primary_key,
                "auto": table.name == "v2_events" and column.name == "id",
                "default": default,
            })
        tables.append({"name": table.name, "columns": columns})
    frozen = {}
    tree = ast.parse((ROOT / "src/hf2l_exchange/migrations.py").read_text())
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        if names and names[0] in {"SQLITE_BASELINE", "POSTGRESQL_BASELINE", "SCHEMA_REVISION"}:
            frozen[names[0]] = ast.literal_eval(node.value)
    return json.dumps({
        "revision": frozen["SCHEMA_REVISION"], "tables": tables,
        "sqlite_baseline": frozen["SQLITE_BASELINE"],
        "postgresql_baseline": frozen["POSTGRESQL_BASELINE"],
    }, indent=2) + "\n"

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    path = ROOT / "internal/store/schema.json"
    expected = export()
    if args.write:
        path.write_text(expected)
    elif path.read_text() != expected:
        raise SystemExit("Go Exchange schema/default manifest differs from Python reference")
