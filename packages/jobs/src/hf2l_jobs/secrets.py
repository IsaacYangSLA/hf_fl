"""Offline secret references approved by the trusted deployment operator.

Job inputs contain opaque reference identifiers only. Secret bytes are read from
private administrator-approved files and delivered in one identity-bound,
read-only manifest outside source/state/artifact directories. This module does
not fetch URLs, use environment fallbacks, or evaluate repository content.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import fcntl
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping
from uuid import uuid4

from .domain import JobSpec, validate_identifier
from .resources import stable_key

MAX_SECRET_BYTES = 8192
MAX_MANIFEST_BYTES = 64 * 1024
_ALLOWED_ROLES = frozenset({"owner", "participant"})
_RESERVED_OPTIONS = frozenset({
    "repo_id", "space_id", "dataset_npz", "eval_npz", "data_path", "dataset_path",
    "source_dir", "state_dir", "command", "mounts", "resources", "target_round",
    "max_duration_seconds", "participant", "participant_id", "minimum_participants",
})
_FORBIDDEN_OPTIONS = re.compile(
    r"(^|_)(git|github|hf|huggingface|s3|aws|azure|gcp|database|db|postgres|oidc|human|"
    r"signing|jwt|docker|container|runtime|ssh|host|proxy|manager|deployment)($|_)", re.I)


class SecretError(ValueError):
    code = "secret_reference_refused"


def _identifier(value):
    try:
        return validate_identifier(value)
    except (ValueError, TypeError):
        raise SecretError("Invalid secret binding identifier") from None


def _private_file(path: Path, limit: int) -> bytes:
    """Descriptor-relative no-link reads; errors never disclose paths or bytes."""
    descriptor = -1
    parent = -1
    try:
        if not path.is_absolute() or ".." in path.parts:
            raise SecretError("Secret source must be an approved absolute private file")
        parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
            os.close(parent)
            parent = child
        information = os.fstat(parent)
        if information.st_uid not in {0, os.geteuid()} or information.st_mode & 0o077:
            raise SecretError("Secret parent directory must be private")
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=parent)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid not in {0, os.geteuid()} or before.st_mode & 0o077
                or before.st_size > limit):
            raise SecretError("Secret file must be bounded, private and without links")
        result = bytearray()
        while len(result) <= limit:
            chunk = os.read(descriptor, min(65536, limit - len(result) + 1))
            if not chunk:
                break
            result.extend(chunk)
        after = os.fstat(descriptor)
        if (len(result) > limit or len(result) != after.st_size
                or (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise SecretError("Secret file changed during resolution")
        return bytes(result)
    except (OSError, ValueError):
        raise SecretError("Approved private secret file is unavailable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent >= 0:
            os.close(parent)


def _secret_text(content: bytes) -> str:
    try:
        value = content.decode("utf-8")
        # Conventional file-backed secrets may have one final line terminator.
        if value.endswith("\n"):
            value = value[:-1]
            if value.endswith("\r"):
                value = value[:-1]
        if not value or "\x00" in value or len(value.encode("utf-8")) > MAX_SECRET_BYTES:
            raise ValueError()
        return value
    except (ValueError, UnicodeError):
        raise SecretError("Secret material must be bounded nonempty UTF-8 text") from None


@dataclass(frozen=True)
class ApprovedSecretReference:
    id: str
    project_id: str
    path: Path = field(repr=False)
    roles: frozenset[str] = field(default_factory=frozenset)
    option_names: frozenset[str] = field(default_factory=frozenset)
    component_ids: frozenset[str] = field(default_factory=frozenset)
    purpose: str = "plugin_option"

    def __post_init__(self):
        _identifier(self.id)
        _identifier(self.project_id)
        path = Path(self.path)
        if not path.is_absolute() or ".." in path.parts or path == Path("/"):
            raise SecretError("Secret source must be an approved absolute private file")
        if any(not isinstance(value, (list, tuple, set, frozenset))
               for value in (self.roles, self.option_names, self.component_ids)):
            raise SecretError("Secret approval scopes must be explicit collections")
        if not self.roles or set(self.roles) - _ALLOWED_ROLES:
            raise SecretError("Secret roles must explicitly permit owner or participant")
        if not self.option_names or len(self.option_names) > 64 or self.purpose != "plugin_option":
            raise SecretError("Only explicitly approved plugin option secrets can enter a job")
        for name in self.option_names:
            _identifier(name)
            normalized = re.sub(r"[^a-z0-9]+", "_", name.lower())
            if normalized in _RESERVED_OPTIONS or _FORBIDDEN_OPTIONS.search(normalized):
                raise SecretError("Control-plane, source and broad infrastructure credentials are forbidden")
        for value in self.component_ids:
            _identifier(value)
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "roles", frozenset(self.roles))
        object.__setattr__(self, "option_names", frozenset(self.option_names))
        object.__setattr__(self, "component_ids", frozenset(self.component_ids))


SecretApproval = ApprovedSecretReference


@dataclass(frozen=True)
class ResolvedSecrets:
    job_id: str
    attempt_id: str
    component_id: str
    epoch: int
    privatepath: Path | None = field(repr=False)
    redaction_values: tuple[str, ...] = field(repr=False)
    option_names: tuple[str, ...] = ()

    @property
    def private_path(self):
        return self.privatepath

    @property
    def path(self):
        return self.privatepath

    @property
    def manifest_path(self):
        return self.privatepath


def _binding(identity):
    if isinstance(identity, ResolvedSecrets):
        values = (identity.job_id, identity.attempt_id, identity.component_id, identity.epoch)
    elif isinstance(identity, Mapping):
        values = tuple(identity[key] for key in ("job_id", "attempt_id", "component_id", "epoch"))
    else:
        values = tuple(getattr(identity, key) for key in ("job_id", "attempt_id", "component_id", "epoch"))
    for value in values[:3]:
        _identifier(value)
    if type(values[3]) is not int or not 1 <= values[3] < 1 << 63:
        raise SecretError("Secret delivery requires a positive execution epoch")
    return dict(zip(("job_id", "attempt_id", "component_id", "epoch"), values))


def read_secret_manifest(path, identity) -> dict:
    """Trusted node collection helper; never serialize the result into job history."""
    try:
        value = json.loads(_private_file(Path(path), MAX_MANIFEST_BYTES))
        binding = _binding(identity)
        if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value.get("schema_version") != 1:
            raise ValueError()
        if type(value.get("epoch")) is not int or any(value.get(key) != expected for key, expected in binding.items()):
            raise ValueError()
        if value.get("role") not in _ALLOWED_ROLES:
            raise ValueError()
        options, references = value["options"], value["references"]
        if not isinstance(options, dict) or not isinstance(references, dict) or set(options) != set(references):
            raise ValueError()
        if not options or len(options) > 64:
            raise ValueError()
        for key, secret in options.items():
            _identifier(key)
            _identifier(references[key])
            if not isinstance(secret, str) or not secret or "\x00" in secret or len(secret.encode()) > MAX_SECRET_BYTES:
                raise ValueError()
        return value
    except (OSError, ValueError, KeyError, TypeError, UnicodeError):
        raise SecretError("Secret delivery manifest is unavailable or belongs to another execution") from None


@dataclass(frozen=True)
class _SecretComponent:
    component_id: str
    role: str
    participant_id: str | None


def _secret_components(spec: JobSpec):
    """Include only immutable external participants with canonical identities."""
    components = list(spec.components)
    identifiers = {component.component_id for component in components}
    for participant in spec.participants:
        if participant.mode != "external":
            continue
        component_id = "participant-" + stable_key(participant.participant_id)[:40]
        if component_id in identifiers:
            raise SecretError("External secret component conflicts with its immutable job")
        identifiers.add(component_id)
        components.append(_SecretComponent(component_id, "participant", participant.participant_id))
    return tuple(components)


class SecretResolver:
    def __init__(self, database, root, approved_secret_files: Mapping[str, object]):
        self.database = database
        self.root = Path(root)
        if not self.root.is_absolute() or self.root == Path("/") or ".." in self.root.parts:
            raise SecretError("Secret delivery root must be a private absolute directory")
        if not isinstance(approved_secret_files, Mapping) or len(approved_secret_files) > 10000:
            raise SecretError("Expected an administrator-approved secret reference catalog")
        self.approvals = {}
        for identifier, value in approved_secret_files.items():
            _identifier(identifier)
            if isinstance(value, ApprovedSecretReference):
                approval = value
            elif isinstance(value, Mapping):
                allowed = {"project_id", "path", "roles", "option_names", "component_ids", "purpose"}
                if set(value) - allowed:
                    raise SecretError("Unknown secret approval property")
                try:
                    approval = ApprovedSecretReference(
                        identifier, value["project_id"], Path(value["path"]),
                        value["roles"], value["option_names"],
                        value.get("component_ids", ()), value.get("purpose", "plugin_option"))
                except (KeyError, TypeError, ValueError):
                    raise SecretError("Secret approval must bind project, role and plugin option names") from None
            else:
                raise SecretError("Secret references cannot be unscoped paths or literal values")
            if approval.id != identifier:
                raise SecretError("Secret approval identifier differs from catalog key")
            self.approvals[identifier] = approval

    def _current(self, spec):
        """Recheck mutable approvals without reading secret material."""
        from .models import SecretReference
        if self.database is None:
            raise SecretError("Current secret approval ledger is required")
        result = {}
        with self.database.transaction(immediate=False) as session:
            for option, reference in spec.secret_refs.items():
                approval = self.approvals.get(reference)
                row = session.get(SecretReference, reference)
                if (approval is None or row is None or not row.enabled
                        or approval.project_id != spec.project_id or row.project_id != spec.project_id
                        or row.reference != str(approval.path) or option not in approval.option_names
                        or option in spec.options):
                    raise SecretError("Secret reference is not currently approved for this job")
                result[option] = approval
        return result

    def validate_spec(self, spec: JobSpec):
        current = self._current(spec) if spec.secret_refs else {}
        components = _secret_components(spec)
        for approval in current.values():
            if not any(component.role in approval.roles
                       and (not approval.component_ids or component.component_id in approval.component_ids)
                       for component in components):
                raise SecretError("Secret reference is not approved for any assigned component")
        return True

    def _directory(self, binding, *, create):
        parts = (*self.root.parts[1:], binding["job_id"], binding["attempt_id"],
                 binding["component_id"], str(binding["epoch"]))
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for index, part in enumerate(parts):
                if create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                if index >= len(self.root.parts) - 2:
                    info = os.fstat(descriptor)
                    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                        raise SecretError("Secret delivery directories must be exclusively node-owned")
            return descriptor
        except FileNotFoundError:
            os.close(descriptor)
            if not create:
                raise
            raise SecretError("Secret delivery root is unavailable or unsafe") from None
        except (OSError, ValueError):
            os.close(descriptor)
            raise SecretError("Secret delivery root is unavailable or unsafe") from None

    def _path(self, binding):
        return self.root / binding["job_id"] / binding["attempt_id"] / binding["component_id"] / str(binding["epoch"]) / "secrets.json"

    @staticmethod
    def _lock(descriptor):
        lock = os.open(".secret-lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                       0o600, dir_fd=descriptor)
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            os.close(lock)
            raise SecretError("Secret delivery lock is unsafe")
        fcntl.flock(lock, fcntl.LOCK_EX)
        return lock

    def _selection(self, job, attempt, component):
        spec = JobSpec.model_validate(job.spec_json)
        if (job.project_id != spec.project_id or attempt.job_id != job.id
                or getattr(job, "spec_hash", spec.digest) != spec.digest
                or getattr(job, "epoch", attempt.epoch) != attempt.epoch
                or getattr(job, "state", "PROVISIONING") not in {"PROVISIONING", "STARTING", "RUNNING"}):
            raise SecretError("Secret delivery identity differs from its current immutable job")
        self.validate_spec(spec)
        target = next((item for item in _secret_components(spec) if item.component_id == component.component_id), None)
        if target is None or target.role != component.role or target.participant_id != component.participant_id:
            raise SecretError("Secret delivery component differs from its immutable job")
        binding = _binding({"job_id": job.id, "attempt_id": attempt.id,
                            "component_id": component.component_id, "epoch": attempt.epoch})
        current = self._current(spec) if spec.secret_refs else {}
        selected = {option: approval for option, approval in current.items()
                    if target.role in approval.roles
                    and (not approval.component_ids or target.component_id in approval.component_ids)}
        if target.role == "build":
            selected = {}
        return binding, target, selected

    def planned(self, job, attempt, component) -> ResolvedSecrets:
        """Validate current approvals and plan a path without touching secret files.

        Reservations can persist this path before materialization. A plan contains
        no secret bytes, redaction values, files or directories.
        """
        binding, target, selected = self._selection(job, attempt, component)
        return ResolvedSecrets(**binding,
            privatepath=self._path(binding) if selected else None,
            redaction_values=(), option_names=tuple(sorted(selected)))

    def plan_path(self, job, attempt, component):
        return self.planned(job, attempt, component).privatepath

    def resolve(self, job, attempt, component) -> ResolvedSecrets:
        binding, target, selected = self._selection(job, attempt, component)
        if not selected:
            return ResolvedSecrets(**binding, privatepath=None, redaction_values=(), option_names=())
        references = {key: approval.id for key, approval in selected.items()}
        descriptor = self._directory(binding, create=True)
        lock = -1
        try:
            lock = self._lock(descriptor)
            path = self._path(binding)
            try:
                os.stat("secrets.json", dir_fd=descriptor, follow_symlinks=False)
                manifest = read_secret_manifest(path, binding)
                if manifest["references"] != references or manifest["role"] != target.role:
                    raise SecretError("Idempotent secret delivery approval changed")
            except FileNotFoundError:
                values = {key: _secret_text(_private_file(approval.path, MAX_SECRET_BYTES))
                          for key, approval in selected.items()}
                manifest = {"schema_version": 1, **binding, "role": target.role,
                            "options": values, "references": references}
                content = json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode("utf-8")
                if len(content) > MAX_MANIFEST_BYTES:
                    raise SecretError("Secret delivery exceeds its size bound")
                temporary = ".secret-tmp-" + uuid4().hex
                output = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 0o400, dir_fd=descriptor)
                try:
                    with os.fdopen(output, "wb") as stream:
                        stream.write(content)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temporary, "secrets.json", src_dir_fd=descriptor, dst_dir_fd=descriptor)
                    os.fsync(descriptor)
                finally:
                    try:
                        os.unlink(temporary, dir_fd=descriptor)
                    except FileNotFoundError:
                        pass
            return ResolvedSecrets(**binding, privatepath=path,
                redaction_values=tuple(sorted(set(manifest["options"].values()), key=lambda value: (-len(value), value))),
                option_names=tuple(sorted(manifest["options"])))
        finally:
            if lock >= 0:
                os.close(lock)
            os.close(descriptor)

    def cleanup(self, identity, *, termination_confirmed=False):
        """Remove only the bound manifest after authoritative runtime termination."""
        if termination_confirmed is not True:
            raise SecretError("Secret cleanup requires confirmed runtime termination")
        binding = _binding(identity)
        try:
            descriptor = self._directory(binding, create=False)
        except FileNotFoundError:
            return True
        lock = -1
        try:
            lock = self._lock(descriptor)
            try:
                os.stat("secrets.json", dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                return True
            read_secret_manifest(self._path(binding), binding)
            os.unlink("secrets.json", dir_fd=descriptor)
            os.fsync(descriptor)
            # The non-secret lock inode is retained for cross-process exclusion.
            return True
        finally:
            if lock >= 0:
                os.close(lock)
            os.close(descriptor)
