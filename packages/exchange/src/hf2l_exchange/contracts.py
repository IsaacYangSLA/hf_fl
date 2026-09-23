"""Export contracts from the installed source without opening external services.

OpenAPI describes the actual HTTP request models and routes. The error inventory
is deliberately evidence based: dynamic forwarding remains explicitly unmapped,
and provider failures are listed separately from HTTP/SDK status-code pairs.
"""
from __future__ import annotations

import ast
from dataclasses import fields
import inspect
import json
from pathlib import Path

from . import config
from .vocabulary import RECORD_STATES, ROLES, TRANSFER_STATES

SOURCE = Path(__file__).resolve().parent


def _constants(expression, expected_type):
    if isinstance(expression, ast.Constant) and type(expression.value) is expected_type:
        return [expression.value]
    if isinstance(expression, ast.IfExp):
        left = _constants(expression.body, expected_type)
        right = _constants(expression.orelse, expected_type)
        if left and right:
            return sorted(set(left + right))
    return []


def error_catalog(source=SOURCE):
    """Inventory literal call sites, retaining every unresolved expression.

    A code may legitimately have multiple statuses. Client-only errors and
    server errors are distinguished by their source rather than pretending that
    every SDK failure came from an HTTP response.
    """
    errors, storage, dynamic = {}, {}, []
    for path in sorted(Path(source).glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
                continue
            name = call.func.id
            location = f"{path.name}:{call.lineno}"
            if name == "StorageFailure" and call.args:
                codes = _constants(call.args[0], str)
                options = {kw.arg: kw.value for kw in call.keywords}
                retryable = options.get("retryable", ast.Constant(False))
                uncertain = options.get("uncertain", ast.Constant(False))
                for code in codes:
                    item = storage.setdefault(code, {"code": code, "call_sites": []})
                    item["call_sites"].append({"source": location,
                                              "retryable": ast.unparse(retryable),
                                              "uncertain": ast.unparse(uncertain)})
                if not codes:
                    dynamic.append({"source": location, "call": name,
                                    "code_expression": ast.unparse(call.args[0])})
            if name not in {"Error", "ExchangeError", "_error", "reject"} or len(call.args) < 2:
                continue
            statuses = _constants(call.args[0], int)
            codes = _constants(call.args[1], str)
            if isinstance(call.args[0], ast.IfExp) and isinstance(call.args[1], ast.IfExp):
                # Correlated branches cannot be combined as a Cartesian product.
                # Keep them explicit rather than inventing code/status pairs.
                statuses = []
            if statuses and codes:
                for code in codes:
                    item = errors.setdefault(code, {"code": code, "statuses": set(), "sources": []})
                    item["statuses"].update(statuses)
                    item["sources"].append(location)
            else:
                dynamic.append({"source": location, "call": name,
                                "status_expression": ast.unparse(call.args[0]),
                                "code_expression": ast.unparse(call.args[1])})
    return {
        "description": "Static source inventory; dynamic forwarding is explicitly unresolved. "
                       "Sources in client modules denote SDK errors, not necessarily HTTP responses. "
                       "Provider failure status is selected by the HTTP storage-error handler.",
        "vocabulary": {"roles": sorted(ROLES), "record_states": sorted(RECORD_STATES),
                       "transfer_states": sorted(TRANSFER_STATES)},
        "errors": [dict(item, statuses=sorted(item["statuses"]), sources=sorted(set(item["sources"])))
                   for _, item in sorted(errors.items())],
        "storage_failures": [dict(item, call_sites=sorted(item["call_sites"], key=lambda site: site["source"]))
                             for _, item in sorted(storage.items())],
        "dynamic_calls": sorted(dynamic, key=lambda item: (item["source"], item["call"])),
    }


def _default_value(node, cls):
    """Read literal/field defaults without consulting the process environment."""
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "cls":
        return getattr(cls, node.attr), ""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "getenv":
        return ast.literal_eval(node.args[1]), f"Falls back to `{ast.literal_eval(node.args[0])}`."
    return ast.literal_eval(node), ""


def environment_contract():
    """Read loader expressions and dataclass defaults, never credential values."""
    result = []
    classes = (config.DatabaseSettings, config.AuthSettings, config.StorageSettings,
               config.WorkerSettings, config.Settings)
    for cls in classes:
        defaults = {field.name: field for field in fields(cls)}
        tree = ast.parse(inspect.getsource(cls))
        if cls is config.WorkerSettings:
            # This loader intentionally computes names from dataclass fields.
            # Refuse to silently describe it if that naming expression changes.
            expressions = {ast.unparse(call.args[0]) for call in ast.walk(tree)
                           if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                           and call.func.id == "_env"}
            if expressions != {"'WORKER_' + name.upper()", "name.upper()"}:
                raise ValueError("Worker environment naming changed; update contract extraction")
            for field in fields(cls):
                name = "EXCHANGE_WORKER_" + field.name.upper()
                result.append({"variable": name, "default": field.default,
                               "field": f"{cls.__name__}.{field.name}", "notes": ""})
                if field.name.endswith("retention_seconds"):
                    result.append({"variable": "EXCHANGE_" + field.name.upper(), "default": field.default,
                                   "field": f"{cls.__name__}.{field.name}",
                                   "notes": f"Overrides `{name}` when set."})
            continue
        for construct in ast.walk(tree):
            if not (isinstance(construct, ast.Call) and isinstance(construct.func, ast.Name)
                    and construct.func.id == "cls"):
                continue
            for keyword in construct.keywords:
                if keyword.arg not in defaults:
                    continue
                for call in ast.walk(keyword.value):
                    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                            and call.func.id in {"_env", "_bool"}):
                        continue
                    variable = "EXCHANGE_" + ast.literal_eval(call.args[0])
                    default = call.args[1] if len(call.args) > 1 else ast.Constant(False if call.func.id == "_bool" else "")
                    value, notes = _default_value(default, cls)
                    # Environment defaults are textual, while the dataclass
                    # owns the public value's type. Make divergence visible.
                    field = defaults[keyword.arg]
                    typed = field.type(value) if field.type in {int, float} else value
                    if typed != field.default:
                        raise ValueError(f"Loader and dataclass defaults disagree for {cls.__name__}.{field.name}")
                    result.append({"variable": variable, "default": field.default,
                                   "field": f"{cls.__name__}.{field.name}", "notes": notes})
    return sorted(result, key=lambda row: (row["variable"], row["field"]))


def environment_markdown():
    lines = ["# Exchange environment variables", "",
             "Generated by `hf2l-exchange export-contract`; edit settings/loader code and regenerate.", "",
             "Defaults are read from dataclasses and environment-loader expressions, never from credentials.",
             "Required combinations and bounds are enforced by the settings validators. SDK/application",
             "configuration is separate; this table covers the Exchange server and worker settings.", "",
             "| Variable | Default | Settings field | Notes |", "|---|---|---|---|"]
    for row in environment_contract():
        default = json.dumps(row["default"], ensure_ascii=False)
        lines.append(f"| `{row['variable']}` | `{default}` | `{row['field']}` | {row['notes']} |")
    return "\n".join(lines) + "\n"


class _NoRuntime:
    """Schema composition must never invoke a database, provider, or identity API."""
    def __getattr__(self, name):
        raise RuntimeError(f"Contract export unexpectedly requested runtime collaborator {name}")


def openapi_contract():
    from .api import create_app
    unused = _NoRuntime()
    return create_app(settings=config.Settings(), service=unused, transfers=unused,
                      authenticator=unused).openapi()


def render_contracts():
    def formatted(value):
        return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
    return {"exchange-api.json": formatted(openapi_contract()),
            "exchange-errors.json": formatted(error_catalog()),
            "exchange-environment.md": environment_markdown()}


def export_contracts(output_dir):
    """Render first so a failed export does not leave partially updated documents."""
    documents = render_contracts()
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    for name, contents in documents.items():
        (directory / name).write_text(contents, encoding="utf-8")
    return tuple(directory / name for name in documents)
