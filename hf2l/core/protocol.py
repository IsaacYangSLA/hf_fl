"""Typed FL document boundaries; architecture v3 retains wire schemas 1 and 2.

Unknown JSON fields survive round trips. Schema revision checks, JSON bounds and
field validation happen before a document reaches a backend. Whether an opaque
revision really is immutable is verified by the selected backend; this module
rejects known mutable reference spellings rather than assuming every provider
uses a Git SHA.
"""

from __future__ import annotations

import copy
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Callable, ClassVar, Mapping

from hf2l.common.fs import safe_relative_path
from hf2l.core.errors import ProtocolError

SUBMISSION_FILE = "fedavg_submission.json"
ROUND_FILE = "fedavg_round.json"
CLIENT_CONTEXT_FILE = "fedavg_client_context.json"
SCHEMA_VERSION = 2
SUPPORTED_SCHEMA_VERSIONS = frozenset((1, 2))
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024
MAX_JSON_DEPTH = 16
MAX_COLLECTION_ITEMS = 10000
MAX_INTEGER = 2**63 - 1
_TEXT_PATTERN = r"^[^\x00-\x20\x7f](?:[^\x00-\x1f\x7f]*[^\x00-\x20\x7f])?$"
_MUTABLE_REFERENCES = ("main", "master", "latest", "HEAD")


def _copy_json(value: Any, depth: int = 0) -> Any:
    if depth > MAX_JSON_DEPTH:
        raise ProtocolError(f"JSON exceeds maximum depth {MAX_JSON_DEPTH}")
    if value is None or isinstance(value, (str, bool)):
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError as exc:
                raise ProtocolError("JSON contains an invalid Unicode string") from exc
        return value
    if type(value) is int:
        if not -MAX_INTEGER <= value <= MAX_INTEGER:
            raise ProtocolError("JSON integer exceeds the supported signed 64-bit range")
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ProtocolError("JSON numbers must be finite")
        return value
    if isinstance(value, dict):
        if len(value) > MAX_COLLECTION_ITEMS or any(not isinstance(key, str) for key in value):
            raise ProtocolError("JSON objects require string keys and at most 10000 entries")
        return {key: _copy_json(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ProtocolError("JSON arrays may contain at most 10000 entries")
        return [_copy_json(item, depth + 1) for item in value]
    raise ProtocolError(f"Value of type {type(value).__name__} is not JSON compatible")


def _object(value: Any, label: str, maximum: int = MAX_DOCUMENT_BYTES) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolError(f"{label} must be a JSON object")
    result = _copy_json(value)
    if len(json.dumps(result, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")) > maximum:
        raise ProtocolError(f"{label} exceeds the {maximum}-byte JSON limit")
    return result


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 4096 or not re.fullmatch(_TEXT_PATTERN, value):
        raise ProtocolError(f"{label} must be non-empty text without surrounding whitespace or control characters")
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_INTEGER:
        raise ProtocolError(f"{label} must be an integer between {minimum} and {MAX_INTEGER}")
    return value


def _revision(value: Any, label: str) -> str:
    revision = _text(value, label)
    if revision in _MUTABLE_REFERENCES or revision.startswith(("refs/heads/", "refs/tags/")):
        raise ProtocolError(f"{label} must identify an immutable revision, not a mutable reference")
    return revision


def _path(value: Any, label: str) -> str:
    try:
        return safe_relative_path(value)
    except ValueError as exc:
        raise ProtocolError(f"Invalid {label}: {exc}") from exc


def require_supported_schema(value: Mapping[str, Any], label: str) -> int:
    version = value.get("schema_version")
    if type(version) is not int or version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ProtocolError(f"The {label} uses an unsupported schema")
    return version


def base_revision_from(value: Mapping[str, Any]) -> str:
    """Read the immutable revision or its legacy base_commit spelling."""
    revision, legacy = value.get("base_revision"), value.get("base_commit")
    if revision is not None and legacy is not None and revision != legacy:
        raise ProtocolError("base_revision and base_commit disagree")
    selected = revision if revision is not None else legacy
    return "" if selected is None else _revision(selected, "base_revision")


@dataclass(frozen=True)
class AlgorithmSpec:
    """Explicit algorithm identity; legacy descriptive strings remain readable."""

    name: str
    version: int = 1
    params: Mapping[str, Any] = field(default_factory=dict)
    _extensions: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    def __post_init__(self) -> None:
        _text(self.name, "algorithm.name")
        _integer(self.version, "algorithm.version", 1)
        if not isinstance(self.params, Mapping):
            raise ProtocolError("algorithm.params must be a JSON object")
        object.__setattr__(self, "params", _object(dict(self.params), "algorithm.params", MAX_METADATA_BYTES))
        extras = _object(dict(self._extensions), "algorithm extensions", MAX_METADATA_BYTES)
        if set(extras) & {"name", "version", "params"}:
            raise ProtocolError("Algorithm extension fields overlap reserved fields")
        object.__setattr__(self, "_extensions", extras)

    @classmethod
    def from_dict(cls, value: Any) -> AlgorithmSpec:
        if isinstance(value, str):
            return cls(_text(value, "algorithm"))
        document = _object(value, "algorithm", MAX_METADATA_BYTES)
        if "name" not in document:
            raise ProtocolError("algorithm.name is required")
        params = document.get("params", {})
        if not isinstance(params, dict):
            raise ProtocolError("algorithm.params must be a JSON object")
        return cls(document["name"], document.get("version", 1), params,
                   {key: item for key, item in document.items() if key not in {"name", "version", "params"}})

    def to_dict(self) -> dict[str, Any]:
        return _object({**self._extensions, "name": self.name, "version": self.version,
                        "params": dict(self.params)}, "algorithm", MAX_METADATA_BYTES)


def _algorithm_spec(value: Any, label: str) -> AlgorithmSpec:
    if not isinstance(value, dict):
        raise ProtocolError(f"{label} must be an algorithm object")
    return AlgorithmSpec.from_dict(value)


def _hashes(value: Any, label: str) -> dict[str, str]:
    result = _object(value, label)
    if not result:
        raise ProtocolError(f"{label} must not be empty")
    for path, digest in result.items():
        _path(path, label)
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ProtocolError(f"{label} requires lowercase SHA-256 digests")
    return result


def _paths(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ProtocolError(f"{label} must be a non-empty array")
    for path in value:
        _path(path, label)
    if len(value) != len(set(value)):
        raise ProtocolError(f"{label} contains duplicate paths")
    return value


@dataclass(frozen=True)
class _Rule:
    validate: Callable[[Any, str], Any]
    schema: dict[str, Any]
    required: bool = False


_TEXT = {"type": "string", "minLength": 1, "maxLength": 4096, "pattern": _TEXT_PATTERN}
_COUNT = {"type": "integer", "minimum": 0, "maximum": MAX_INTEGER}
_REFERENCE = {**_TEXT, "allOf": [{"not": {"enum": list(_MUTABLE_REFERENCES)}},
                               {"not": {"pattern": r"^refs/(heads|tags)/"}}]}
_PATH = {"type": "string", "minLength": 1, "maxLength": 4096,
         "pattern": r"^(?!/)(?!.*(?:^|/)\.{1,2}(?:/|$))(?!.*//)(?!.*[/]$)(?![^/]*:)[^\\\x00-\x1f\x7f]+$"}
_HASHES = {"type": "object", "minProperties": 1, "maxProperties": MAX_COLLECTION_ITEMS,
           "propertyNames": _PATH, "additionalProperties": {"type": "string", "pattern": "^[0-9a-f]{64}$"}}
_ALGORITHM = {"anyOf": [_TEXT, {"$ref": "#/$defs/AlgorithmSpec"}]}
_COMMON = {
    "schema_version": _Rule(lambda value, label: require_supported_schema({"schema_version": value}, label),
                            {"type": "integer", "enum": sorted(SUPPORTED_SCHEMA_VERSIONS)}, True),
    "backend": _Rule(_text, _TEXT),
    "base_revision": _Rule(_revision, _REFERENCE),
    "base_commit": _Rule(_revision, _REFERENCE),
    "checkpoint_files_sha256": _Rule(_hashes, _HASHES),
    "checkpoint_files": _Rule(_paths, {"type": "array", "items": _PATH, "minItems": 1,
                                     "maxItems": MAX_COLLECTION_ITEMS, "uniqueItems": True}),
    "algorithm": _Rule(lambda value, label: AlgorithmSpec.from_dict(value), _ALGORITHM),
    "algorithm_spec": _Rule(_algorithm_spec, {"$ref": "#/$defs/AlgorithmSpec"}),
}


@dataclass(frozen=True)
class _Document:
    _wire: dict[str, Any] = field(repr=False, compare=False)
    rules: ClassVar[dict[str, _Rule]]
    requires_base: ClassVar[bool] = False

    @classmethod
    def _read(cls, value: Any) -> dict[str, Any]:
        document = _object(value, cls.__name__)
        for key, rule in cls.rules.items():
            if key not in document:
                if rule.required:
                    raise ProtocolError(f"{cls.__name__}.{key} is required")
                continue
            rule.validate(document[key], f"{cls.__name__}.{key}")
        if cls.requires_base and not base_revision_from(document):
            raise ProtocolError(f"{cls.__name__}.base_revision is required")
        if "base_revision" in document or "base_commit" in document:
            base_revision_from(document)
        return document

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self._wire)

    @property
    def checkpoint_files_sha256(self) -> dict[str, str]:
        return copy.deepcopy(self._wire.get("checkpoint_files_sha256", {}))

    @property
    def algorithm_spec(self) -> AlgorithmSpec | None:
        value = self._wire.get("algorithm_spec")
        return None if value is None else AlgorithmSpec.from_dict(value)

    @property
    def algorithm(self) -> AlgorithmSpec | None:
        value = self._wire.get("algorithm")
        return None if value is None else AlgorithmSpec.from_dict(value)


@dataclass(frozen=True)
class SubmissionManifest(_Document):
    schema_version: int
    backend: str
    repo_id: str
    base_revision: str
    source_round: int
    participant: str
    num_examples: int
    submission_revision: str | None
    requires_base: ClassVar[bool] = True
    rules: ClassVar[dict[str, _Rule]] = {
        **_COMMON,
        "repo_id": _Rule(_text, _TEXT, True),
        "source_round": _Rule(_integer, _COUNT, True),
        "participant": _Rule(_text, _TEXT, True),
        "num_examples": _Rule(lambda value, label: _integer(value, label, 1), {**_COUNT, "minimum": 1}, True),
        "submission_revision": _Rule(lambda value, label: None if value is None else _text(value, label),
                                     {"anyOf": [{"type": "null"}, _TEXT]}),
        "training": _Rule(lambda value, label: _object(value, label, MAX_METADATA_BYTES), {"type": "object"}),
    }

    @classmethod
    def from_dict(cls, value: Any) -> SubmissionManifest:
        doc = cls._read(value)
        return cls(doc, doc["schema_version"], doc.get("backend", "huggingface"), doc["repo_id"],
                   base_revision_from(doc), doc["source_round"], doc["participant"], doc["num_examples"],
                   doc.get("submission_revision"))

    @property
    def training(self) -> dict[str, Any]:
        return copy.deepcopy(self._wire.get("training", {}))


@dataclass(frozen=True)
class RoundRecord(_Document):
    schema_version: int
    backend: str
    round: int
    base_revision: str
    rules: ClassVar[dict[str, _Rule]] = {
        **_COMMON,
        "round": _Rule(_integer, _COUNT, True),
        "submissions": _Rule(lambda value, label: _submission_summaries(value, label),
                             {"type": "array", "maxItems": MAX_COLLECTION_ITEMS, "items": {
                                 "type": "object", "properties": {
                                     "participant": _TEXT, "author": _TEXT, "submission_revision": _TEXT,
                                     "resolved_revision": _TEXT, "num_examples": {**_COUNT, "minimum": 1},
                                     "coefficient": {"type": "number", "minimum": 0, "maximum": 1}}}}),
        "evaluation": _Rule(lambda value, label: None if value is None else _object(value, label, MAX_METADATA_BYTES),
                            {"type": ["object", "null"]}),
    }

    @classmethod
    def from_dict(cls, value: Any) -> RoundRecord:
        doc = cls._read(value)
        return cls(doc, doc["schema_version"], doc.get("backend", "huggingface"), doc["round"],
                   base_revision_from(doc))


def _submission_summaries(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ProtocolError(f"{label} must be an array")
    for summary in value:
        _object(summary, label)
        for key in ("participant", "author", "submission_revision", "resolved_revision"):
            if key in summary:
                _text(summary[key], f"{label}.{key}")
        if "num_examples" in summary:
            _integer(summary["num_examples"], f"{label}.num_examples", 1)
        if "coefficient" in summary:
            coefficient = summary["coefficient"]
            if type(coefficient) not in (int, float) or not 0 <= coefficient <= 1:
                raise ProtocolError(f"{label}.coefficient must be a number between zero and one")
    return value


@dataclass(frozen=True)
class ClientContext(_Document):
    schema_version: int
    backend: str
    repo_id: str
    base_revision: str
    source_round: int
    base_model_dir: str
    requires_base: ClassVar[bool] = True
    rules: ClassVar[dict[str, _Rule]] = {
        **_COMMON,
        "repo_id": _Rule(_text, _TEXT, True),
        "source_round": _Rule(_integer, _COUNT, True),
        "base_model_dir": _Rule(_path, _PATH),
        "requested_revision": _Rule(_text, _TEXT),
    }

    @classmethod
    def from_dict(cls, value: Any) -> ClientContext:
        doc = cls._read(value)
        return cls(doc, doc["schema_version"], doc.get("backend", "huggingface"), doc["repo_id"],
                   base_revision_from(doc), doc["source_round"], doc.get("base_model_dir", "base_model"))


def _schema_for(document_type: type) -> dict[str, Any]:
    if document_type is AlgorithmSpec:
        return {"type": "object", "required": ["name"], "properties": {
            "name": _TEXT, "version": {**_COUNT, "minimum": 1}, "params": {"type": "object"}},
            "additionalProperties": True}
    if document_type not in (SubmissionManifest, RoundRecord, ClientContext):
        raise TypeError("Expected an FL document class")
    schema: dict[str, Any] = {"type": "object", "required": [key for key, rule in document_type.rules.items() if rule.required],
                              "properties": {key: rule.schema for key, rule in document_type.rules.items()},
                              "additionalProperties": True}
    if document_type.requires_base:
        schema["anyOf"] = [{"required": ["base_revision"]}, {"required": ["base_commit"]}]
    return schema


def document_schemas() -> dict[str, Any]:
    """Export wire schemas from the same field rules used by typed readers.

JSON Schema describes field shapes. Runtime additionally checks UTF-8 byte
budgets, JSON depth, finite numbers, and equality when both base aliases appear.
"""
    return copy.deepcopy({"$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "HF2L FL documents (wire schemas 1 and 2)",
        "description": "Architecture v3; existing wire schemas and document names are retained.",
        "x-runtime-limits": {"document_bytes": MAX_DOCUMENT_BYTES, "metadata_bytes": MAX_METADATA_BYTES,
                             "json_depth": MAX_JSON_DEPTH, "collection_items": MAX_COLLECTION_ITEMS,
                             "integers": "signed 64-bit; integer fields reject boolean and floating-point values",
                             "base_aliases": "must be equal when both present",
                             "numbers": "finite", "strings": "valid UTF-8"},
        "x-document-files": {"SubmissionManifest": SUBMISSION_FILE, "RoundRecord": ROUND_FILE,
                             "ClientContext": CLIENT_CONTEXT_FILE},
        "$defs": {cls.__name__: _schema_for(cls) for cls in (AlgorithmSpec, SubmissionManifest, RoundRecord, ClientContext)}})


def json_schema(document_type: type) -> dict[str, Any]:
    bundle = document_schemas()
    if document_type.__name__ not in bundle["$defs"]:
        raise TypeError("Expected an FL document class")
    return {**bundle, "$ref": f"#/$defs/{document_type.__name__}"}
