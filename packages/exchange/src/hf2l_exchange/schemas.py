"""Bounded, local-only JSON Schema validation and attachment path contracts."""
import hashlib
import json
import re
from jsonschema import Draft202012Validator, SchemaError, ValidationError
from referencing import Registry
from referencing.exceptions import Unresolvable
from .domain import Error

MAX_METADATA_BYTES = 65536
MAX_SCHEMA_BYTES = 65536
MAX_ATTACHMENTS = 256
DIALECT = "https://json-schema.org/draft/2020-12/schema"


def canonical_bytes(value):
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError):
        raise Error(422, "invalid_json") from None


def _bounded_json(value, depth=0):
    if depth > 16:
        raise Error(422, "metadata_too_deep")
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise Error(422, "invalid_json")
        for item in value.values():
            _bounded_json(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _bounded_json(item, depth + 1)


def metadata_size(metadata):
    if not isinstance(metadata, dict):
        raise Error(422, "metadata_must_be_object")
    _bounded_json(metadata)
    size = len(canonical_bytes(metadata))
    if size > MAX_METADATA_BYTES:
        raise Error(422, "metadata_too_large")
    return size


def schema_digest(schema):
    return hashlib.sha256(canonical_bytes(schema)).hexdigest()


def validate_schema(schema):
    if not isinstance(schema, dict) or len(canonical_bytes(schema)) > MAX_SCHEMA_BYTES:
        raise Error(422, "invalid_schema")
    if schema.get("$schema", DIALECT) != DIALECT or schema.get("type") != "object":
        raise Error(422, "unsupported_schema_dialect_or_root")
    def inspect(value, depth=0):
        if depth > 16:
            raise Error(422, "schema_too_deep")
        if isinstance(value, dict):
            if "$id" in value or "$dynamicRef" in value or "$recursiveRef" in value:
                raise Error(422, "schema_reference_unsupported")
            if "$ref" in value:
                ref = value["$ref"]
                if not isinstance(ref, str) or not ref.startswith("#/"):
                    raise Error(422, "schema_reference_unsupported")
                # Recursive references can consume unbounded validator work. Resolve all local
                # pointers and reject cycles before accepting the immutable revision.
                target = schema
                try:
                    for token in ref[2:].split("/"):
                        token = token.replace("~1", "/").replace("~0", "~")
                        target = target[int(token)] if isinstance(target, list) else target[token]
                except (KeyError, TypeError, ValueError, IndexError):
                    raise Error(422, "schema_reference_missing") from None
                inspect(target, depth + 1)
            for child in value.values():
                inspect(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                inspect(child, depth + 1)
    try:
        inspect(schema)
        Draft202012Validator.check_schema(schema)
    except (SchemaError, RecursionError):
        raise Error(422, "invalid_schema") from None


def validate_metadata(metadata, schema):
    size = metadata_size(metadata)
    try:
        Draft202012Validator(schema, registry=Registry()).validate(metadata)
    except (ValidationError, Unresolvable, RecursionError):
        raise Error(422, "metadata_schema_mismatch") from None
    return size


def validate_path(path):
    if (not isinstance(path, str) or not path or len(path.encode("utf-8")) > 256 or
            "\\" in path or path.startswith("/") or any(ord(c) < 32 or ord(c) == 127 for c in path) or
            any(part in {"", ".", ".."} for part in path.split("/")) or ":" in path):
        raise Error(422, "invalid_attachment_path")
    return path


def validate_kind(kind):
    if not isinstance(kind, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", kind):
        raise Error(422, "invalid_kind")
    return kind
