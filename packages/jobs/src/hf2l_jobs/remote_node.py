"""Trusted mTLS transport and node-local immutable assignment materialization.

Wire assignments contain approved identifiers and immutable job inputs. Host
paths, shell commands, runtime flags, keys, and raw participant data never cross
this API. The local NodeAgent remains the durable resource/epoch/lease authority.
"""
from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import math
import os
import threading
from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable
from urllib.parse import quote, urlsplit

import httpx
from starlette.requests import Request

from .collection import CollectionError, RetainedFile, SafeCollector
from .domain import JobSpec, canonical_json, validate_identifier
from .executor import (
    ExecutionIdentity, ExecutionSpec, ExecutorRefused, Reservation, ResourceLimits,
    RuntimeObservation, UncertainExecution,
)
from .resources import OwnedDirectories, atomic_json, private_root
from .workflow import RuntimeConfig

_WORKER_ARGV = ("python", "-m", "hf2l_jobs.runtime", "--config", "/run/hf2l/runtime.json")


@dataclass(frozen=True)
class NodeRoute:
    node_id: str
    pool_id: str
    resources: ResourceLimits

    def __post_init__(self):
        validate_identifier(self.node_id)
        validate_identifier(self.pool_id)
        if not isinstance(self.resources, ResourceLimits):
            raise ExecutorRefused("Route requires exact resource limits", "invalid_assignment")


@dataclass(frozen=True)
class NodeEndpoint:
    node_id: str
    origin: str
    ca_file: str
    client_certificate: str
    client_key: str
    timeout_seconds: float = 90
    max_reply_bytes: int = 2 * 1024 * 1024

    def __post_init__(self):
        validate_identifier(self.node_id)
        parsed = urlsplit(self.origin)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment
                or any(c in self.origin for c in "\r\n\x00")):
            raise ExecutorRefused("Node endpoint must be an approved HTTPS origin", "invalid_node_endpoint")
        if (type(self.max_reply_bytes) is not int or not 1 <= self.max_reply_bytes <= 16 * 1024 * 1024
                or type(self.timeout_seconds) not in (int, float)
                or not math.isfinite(self.timeout_seconds) or not 1 <= self.timeout_seconds <= 300):
            raise ExecutorRefused("Invalid node transport limits", "invalid_node_endpoint")
        object.__setattr__(self, "origin", self.origin.rstrip("/"))

    def client(self):
        from .gateway import tls_context
        for value in (self.ca_file, self.client_certificate, self.client_key):
            path = Path(value)
            if not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents)):
                raise ExecutorRefused("Node TLS material must use approved paths", "unsafe_node_credentials")
            information = path.lstat()
            import stat
            if not stat.S_ISREG(information.st_mode) or information.st_nlink != 1 or information.st_size > 65536:
                raise ExecutorRefused("Node TLS material must be bounded regular files", "unsafe_node_credentials")
            if value == self.client_key and information.st_mode & 0o077:
                raise ExecutorRefused("Node client key must remain private", "unsafe_node_credentials")
        context = tls_context(self.ca_file)
        context.load_cert_chain(self.client_certificate, self.client_key)
        return httpx.Client(verify=context, trust_env=False, follow_redirects=False, timeout=self.timeout_seconds)


@dataclass(frozen=True)
class RemoteAssignment:
    identity: ExecutionIdentity
    node_id: str
    pool_id: str
    resources: ResourceLimits
    job_spec: JobSpec
    image_digest: str
    lease_seconds: float = 120
    deadline: float | None = None
    external_participant_id: str | None = None
    source_limits: Mapping[str, int] | None = None

    def __post_init__(self):
        NodeRoute(self.node_id, self.pool_id, self.resources)
        if self.source_limits is not None:
            from types import MappingProxyType
            if (not isinstance(self.source_limits, Mapping) or set(self.source_limits) != {
                    "max_bytes", "max_files", "max_git_bytes", "max_git_files"}
                    or any(type(value) is not int or not 1 <= value <= 1 << 40
                           for value in self.source_limits.values())):
                raise ExecutorRefused("Invalid approved source bounds", "invalid_assignment")
            object.__setattr__(self, "source_limits", MappingProxyType(dict(self.source_limits)))
        if not isinstance(self.identity, ExecutionIdentity) or not isinstance(self.job_spec, JobSpec):
            raise ExecutorRefused("Assignment requires validated immutable inputs", "invalid_assignment")
        if type(self.lease_seconds) not in (int, float) or not 0 < self.lease_seconds <= 300:
            raise ExecutorRefused("Invalid assignment lease", "invalid_lease")
        if self.deadline is not None and (
            type(self.deadline) not in (int, float) or not math.isfinite(self.deadline) or self.deadline <= 0
        ):
            raise ExecutorRefused("Invalid assignment deadline", "invalid_deadline")
        import re
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", self.image_digest):
            raise ExecutorRefused("Remote runtime image must be immutable", "image_not_pinned")
        if self.external_participant_id is None:
            component = next((c for c in self.job_spec.components if c.component_id == self.identity.component_id), None)
            if component is None or component.resources.pool_id != self.pool_id:
                raise ExecutorRefused("Assignment differs from its immutable component", "invalid_assignment")
            expected = component.resources
            if (
                expected.cpu_millicores != self.resources.cpu_millis
                or expected.memory_bytes != self.resources.memory_bytes
                or expected.disk_bytes != self.resources.disk_bytes
                or expected.gpu_count != self.resources.gpus
            ):
                raise ExecutorRefused("Assignment resources differ from immutable component", "invalid_resources")
        else:
            from .provisioning import Provisioner
            validate_identifier(self.external_participant_id)
            participant = next((p for p in self.job_spec.participants if p.participant_id == self.external_participant_id), None)
            if (participant is None or participant.mode != "external"
                    or self.identity.component_id != Provisioner.external_component(self.external_participant_id)):
                raise ExecutorRefused("External assignment participant differs", "invalid_assignment")

    @property
    def component(self):
        if self.external_participant_id is not None:
            return SimpleNamespace(component_id=self.identity.component_id, role="participant",
                                   participant_id=self.external_participant_id)
        return next(c for c in self.job_spec.components if c.component_id == self.identity.component_id)

    def to_dict(self):
        return {
            "identity": asdict(self.identity), "node_id": self.node_id, "pool_id": self.pool_id,
            "resources": asdict(self.resources), "job_spec": self.job_spec.to_dict(),
            "image_digest": self.image_digest, "lease_seconds": self.lease_seconds,
            "deadline": self.deadline, "external_participant_id": self.external_participant_id,
            "source_limits": dict(self.source_limits) if self.source_limits is not None else None,
        }

    @classmethod
    def from_dict(cls, document):
        if not isinstance(document, dict) or set(document) - set(cls.__dataclass_fields__):
            raise ExecutorRefused("Remote assignments cannot select host paths or commands", "invalid_assignment")
        try:
            value = dict(document)
            value["identity"] = ExecutionIdentity(**value["identity"])
            value["resources"] = ResourceLimits(**value["resources"])
            value["job_spec"] = JobSpec.model_validate(value["job_spec"])
            return cls(**value)
        except (KeyError, TypeError, ValueError) as error:
            raise ExecutorRefused("Invalid structured remote assignment", "invalid_assignment") from error




@dataclass(frozen=True)
class NodePurgeReceipt:
    job_id: str
    attempt_id: str
    component_id: str
    epoch: int
    node_id: str
    pool_id: str
    spec_digest: str
    operation_id: str
    purpose: str = "managed_node_purge"
    termination_confirmed: bool = True
    source_deleted: bool = True
    config_deleted: bool = True
    build_deleted: bool = True
    private_credentials_deleted: bool = True
    private_secrets_deleted: bool = True
    retained_deleted: bool = True
    auxiliary_deleted: bool = True
    confirmed: bool = True

    def __post_init__(self):
        import re
        identity = ExecutionIdentity(self.job_id, self.attempt_id, self.component_id, self.epoch)
        validate_identifier(self.node_id)
        validate_identifier(self.pool_id)
        if (not re.fullmatch("[a-f0-9]{64}", self.spec_digest)
                or self.operation_id != "purge-" + identity.key or self.purpose != "managed_node_purge"
                or any(getattr(self, name) is not True for name in (
                    "termination_confirmed", "source_deleted", "config_deleted", "build_deleted",
                    "private_credentials_deleted", "private_secrets_deleted", "retained_deleted",
                    "auxiliary_deleted", "confirmed"))):
            raise ExecutorRefused("Invalid authoritative node purge receipt", "invalid_purge_receipt")

    def as_dict(self):
        return asdict(self)


class RemoteNodeMaterializer:
    """Materialize each assigned source/config/cache only in approved node roots."""

    def __init__(self, root, registry, *, node_id, pool_id, proxy_endpoint=None,
                 execution_bindings=None, dataset_bindings=None, secret_planner=None,
                 secret_materializer=None, build_preparer=None, auxiliary_reserver=None,
                 require_source_limits=False, shared_auxiliary_reserver=None):
        self.root = private_root(root)
        self.registry, self.node_id, self.pool_id = registry, validate_identifier(node_id), validate_identifier(pool_id)
        self.proxy_endpoint, self.execution_bindings = proxy_endpoint, execution_bindings
        self.dataset_bindings = dataset_bindings
        self.secret_planner, self.secret_materializer = secret_planner, secret_materializer
        self.build_preparer = build_preparer
        self.auxiliary_reserver = auxiliary_reserver
        self.require_source_limits = require_source_limits
        self.shared_auxiliary_reserver = shared_auxiliary_reserver
        self._locks = {}
        self._pending = {}
        self.directories = OwnedDirectories(self.root / "jobs")
        self.assignments = self.root / "assignments"
        self.assignments.mkdir(mode=0o700, exist_ok=True)
        self.purge_receipts = self.root / "purge-receipts"
        self.purge_receipts.mkdir(mode=0o700, exist_ok=True)
        with SafeCollector(self.purge_receipts):
            pass
        with SafeCollector(self.assignments):
            pass

    def _read(self, path):
        with SafeCollector(path.parent, max_file_bytes=4 * 1024 * 1024) as collector:
            return json.loads(collector.read(path.name))

    def assignment(self, identity):
        try:
            assignment = RemoteAssignment.from_dict(self._read(self.assignments / (identity.key + ".json")))
        except CollectionError as error:
            cause = error
            while cause.__cause__ is not None:
                cause = cause.__cause__
            assignment = self._pending.get(identity.key)
            if not isinstance(cause, FileNotFoundError) or assignment is None:
                raise
        if assignment.identity != identity:
            raise ExecutorRefused("Node assignment identity changed", "assignment_conflict")
        return assignment

    def _paths(self, assignment):
        identity = assignment.identity
        job = self.directories.ensure_job(identity.job_id, assignment.job_spec.digest)
        parent = job / "components" / identity.component_id
        for path in (job / "components", parent, parent / "attempts",
                     parent / "attempts" / identity.attempt_id,
                     parent / "attempts" / identity.attempt_id / str(identity.epoch)):
            if path.is_symlink():
                raise ExecutorRefused("Node component paths cannot be linked", "unsafe_mount")
            path.mkdir(mode=0o700, exist_ok=True)
        return parent, parent / "attempts" / identity.attempt_id / str(identity.epoch)

    def _registry(self, assignment):
        import copy
        registry = self.registry.refreshed()
        if assignment.source_limits is None:
            if self.require_source_limits:
                raise ExecutorRefused("Managed source bounds are required", "source_not_approved")
            return registry
        approval = registry.source_registry.authorize(assignment.job_spec.project_id,
            assignment.job_spec.source_id, assignment.job_spec.source_commit)
        effective = replace(approval, **{
            key: min(getattr(approval, key), value) for key, value in assignment.source_limits.items()})
        source_registry = copy.copy(registry.source_registry)
        source_registry.approvals = dict(source_registry.approvals)
        source_registry.approvals[approval.source_id] = effective
        bounded = copy.copy(registry)
        bounded.source_registry, bounded.database = source_registry, None
        return bounded

    def _validate_registry(self, assignment):
        # A participant node approves only its own dataset binding. Owner/build
        # nodes never require other participants' locally held datasets.
        participant = assignment.component.participant_id
        scoped = assignment.job_spec.model_copy(update={
            "participants": tuple(p for p in assignment.job_spec.participants if p.participant_id == participant),
            "secret_refs": {key: reference for key, reference in assignment.job_spec.secret_refs.items()
                            if reference in self.registry.secret_refs},
        })
        return self._registry(assignment).validate(scoped)

    def plan(self, assignment: RemoteAssignment):
        """Validate approvals and return fixed paths without filesystem effects."""
        if (assignment.node_id, assignment.pool_id) != (self.node_id, self.pool_id):
            raise ExecutorRefused("Assignment targets a different approved node/pool", "node_mismatch")
        if self._validate_registry(assignment) != assignment.image_digest:
            raise ExecutorRefused("Node runtime approval differs from assignment", "image_not_approved")
        parent = self.root / "jobs" / assignment.identity.job_id / "components" / assignment.identity.component_id
        attempt = parent / "attempts" / assignment.identity.attempt_id / str(assignment.identity.epoch)
        role = "client" if assignment.component.role == "participant" else assignment.component.role
        proxy = None if role == "build" else (
            self.proxy_endpoint(assignment.identity) if self.proxy_endpoint else str(attempt / "proxy.sock")
        )
        secret = self.secret_planner(assignment) if self.secret_planner else None
        participant = assignment.component.participant_id
        dataset = next((p.dataset_binding for p in assignment.job_spec.participants if p.participant_id == participant), None)
        return ExecutionSpec(
            identity=assignment.identity, image_digest=assignment.image_digest,
            source_path=str(parent / "source"), state_path=str(parent / "state"),
            argv=_WORKER_ARGV, proxy_endpoint=proxy, resources=assignment.resources,
            lease_seconds=assignment.lease_seconds, pool_id=self.pool_id, node_id=self.node_id,
            deadline=assignment.deadline, config_path=str(attempt / "runtime.json"), role=role,
            secret_path=str(secret) if secret is not None else None,
            dataset_binding_id=dataset, participant_id=participant,
            build_input_path=(str(parent / "build-inputs") if role != "build"
                              and any(c.role == "build" for c in assignment.job_spec.components) else None),
        )

    def reserve(self, assignment: RemoteAssignment):
        """Persist the recipe only after the caller durably reserves local space."""
        spec = self.plan(assignment)
        path = self.assignments / (assignment.identity.key + ".json")
        if path.exists() or path.is_symlink():
            if self._read(path) != assignment.to_dict():
                raise ExecutorRefused("Immutable assignment identity changed", "assignment_conflict")
        else:
            atomic_json(path, assignment.to_dict())
        self._paths(assignment)
        return spec

    def pending_assignment(self, assignment):
        from contextlib import contextmanager
        @contextmanager
        def pending():
            previous = self._pending.get(assignment.identity.key)
            if previous is not None and previous != assignment:
                raise ExecutorRefused("Concurrent assignment identity changed", "assignment_conflict")
            self._pending[assignment.identity.key] = assignment
            try:
                yield
            finally:
                if previous is None:
                    self._pending.pop(assignment.identity.key, None)
        return pending()

    def binding(self, identity, space_id, principal_id):
        assignment = self.assignment(identity)
        validate_identifier(space_id)
        if self.execution_bindings is None:
            raise ExecutorRefused("Node-local proxy provisioning is required", "missing_proxy")
        self._charge_auxiliary(assignment)
        value = dict(self.execution_bindings(assignment, space_id, principal_id))
        expected = self.plan(assignment).proxy_endpoint
        if value.get("proxy_endpoint") != expected or not value.get("certificate_thumbprint"):
            raise ExecutorRefused("Node-local proxy differs from its reservation", "missing_proxy")
        return {
            "certificate_thumbprint": value["certificate_thumbprint"],
            "proxy_endpoint": "remote:" + identity.key,
            "dataset_bindings": self.dataset_bindings(assignment) if self.dataset_bindings else {},
        }

    def auxiliary_peak_bytes(self, assignment, build_bytes=0):
        source = self._registry(assignment).source_registry.authorize(
            assignment.job_spec.project_id, assignment.job_spec.source_id, assignment.job_spec.source_commit)
        # Reserve source + simultaneous object reception + file/directory metadata,
        # immutable configs, proxy keys/certs, secret manifest, and staged wheels.
        from .source import metadata_peak_bytes, git_peak_bytes
        builders = sum(component.role == "build" for component in assignment.job_spec.components)
        # Each immutable builder publishes one wheel. Its resumable .part file
        # becomes the final wheel by rename, so staging never duplicates payload
        # blocks. Allow blocks/inodes per wheel plus the manifest and directories.
        wheel_metadata = 8192 * (builders + 4) if build_bytes else 0
        return (source.max_bytes + metadata_peak_bytes(source) + git_peak_bytes(source)
                + 4 * 1024**2 + 256 * 1024 + build_bytes + wheel_metadata)

    def _charge_auxiliary(self, assignment, build_bytes=0):
        if self.shared_auxiliary_reserver is not None:
            self.shared_auxiliary_reserver(assignment.identity,
                self.auxiliary_peak_bytes(assignment, build_bytes) - (4 * 1024**2 + 256 * 1024))
            self.auxiliary_reserver(assignment.identity, 4 * 1024**2 + 256 * 1024)
        elif self.auxiliary_reserver is not None:
            self.auxiliary_reserver(assignment.identity, self.auxiliary_peak_bytes(assignment, build_bytes))

    def stage_build_input(self, identity, artifacts, filename, offset, data_base64):
        """Stage opaque manager-verified wheels, with bounded resumable chunks."""
        import base64
        import re
        import stat
        from .workflow import BuiltArtifact
        from .collection import _rename_no_replace
        with self._locks.setdefault(identity.key, threading.RLock()):
            assignment = self.assignment(identity)
            if assignment.component.role == "build" or not any(
                    c.role == "build" for c in assignment.job_spec.components):
                raise ExecutorRefused("This job has no training build inputs", "build_not_approved")
            builders = sum(component.role == "build" for component in assignment.job_spec.components)
            if (not isinstance(artifacts, dict) or not artifacts
                    or len(artifacts) > min(256, builders)):
                raise ExecutorRefused("Invalid bounded build manifest", "invalid_assignment")
            validated = {}
            for name, descriptor in artifacts.items():
                if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+\-]{0,240}\.whl", name):
                    raise ExecutorRefused("Build input must be a portable wheel basename", "invalid_assignment")
                validated[name] = BuiltArtifact.model_validate(descriptor).model_dump(mode="json")
            limit = min(256 * 1024**2, assignment.resources.disk_bytes)
            if sum(item["size_bytes"] for item in validated.values()) > limit or filename not in validated:
                raise ExecutorRefused("Build input exceeds admitted disk bound", "invalid_assignment")
            self._charge_auxiliary(assignment, sum(item["size_bytes"] for item in validated.values()))
            descriptor = validated[filename]
            if type(offset) is not int or not 0 <= offset < descriptor["size_bytes"]:
                raise ExecutorRefused("Invalid bounded wheel chunk offset", "invalid_assignment")
            if not isinstance(data_base64, str) or len(data_base64) > 4 * ((1024**2 + 2) // 3):
                raise ExecutorRefused("Wheel chunk exceeds transport bound", "invalid_assignment")
            try:
                chunk = base64.b64decode(data_base64, validate=True)
            except (ValueError, UnicodeError) as error:
                raise ExecutorRefused("Invalid wheel chunk encoding", "invalid_assignment") from error
            if not 0 < len(chunk) <= 1024**2 or offset + len(chunk) > descriptor["size_bytes"]:
                raise ExecutorRefused("Wheel chunk exceeds immutable artifact", "invalid_assignment")
            parent, _ = self._paths(assignment)
            manifest_path = parent / "build-input-manifest.json"
            manifest = {"job_id": identity.job_id, "component_id": identity.component_id,
                        "spec_digest": assignment.job_spec.digest, "artifacts": validated}
            if manifest_path.exists() or manifest_path.is_symlink():
                if self._read(manifest_path) != manifest:
                    raise ExecutorRefused("Immutable build input manifest changed", "assignment_conflict")
            else:
                atomic_json(manifest_path, manifest, mode=0o400)
            destination = parent / "build-inputs"
            if destination.is_symlink():
                raise ExecutorRefused("Build input root cannot be linked", "unsafe_mount")
            destination.mkdir(mode=0o700, exist_ok=True)
            with SafeCollector(destination, max_file_bytes=limit, max_total_bytes=limit) as collector:
                directory = collector._root_fd
                information = os.fstat(directory)
                if information.st_uid != os.geteuid() or information.st_mode & 0o077:
                    raise ExecutorRefused("Build input root must be node private", "unsafe_mount")
                try:
                    final = collector.read(filename, max_bytes=descriptor["size_bytes"])
                except CollectionError as error:
                    cause = error
                    while cause.__cause__ is not None:
                        cause = cause.__cause__
                    if not isinstance(cause, FileNotFoundError):
                        raise
                else:
                    if len(final) != descriptor["size_bytes"] or hashlib.sha256(final).hexdigest() != descriptor["sha256"]:
                        raise ExecutorRefused("Existing opaque wheel changed", "unsafe_output")
                    if final[offset:offset + len(chunk)] != chunk:
                        raise ExecutorRefused("Idempotent wheel chunk changed", "assignment_conflict")
                    return True
                temporary = "." + filename + ".part"
                output = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 0o600, dir_fd=directory)
                try:
                    information = os.fstat(output)
                    if (not stat.S_ISREG(information.st_mode) or information.st_nlink != 1
                            or information.st_uid != os.geteuid() or information.st_mode & 0o077
                            or information.st_size > descriptor["size_bytes"]):
                        raise ExecutorRefused("Wheel staging file is unsafe", "unsafe_output")
                    if information.st_size == offset:
                        os.lseek(output, offset, os.SEEK_SET)
                        remaining = memoryview(chunk)
                        while remaining:
                            written = os.write(output, remaining)
                            if written <= 0:
                                raise UncertainExecution("Wheel chunk write was not confirmed")
                            remaining = remaining[written:]
                        os.fsync(output)
                    elif information.st_size >= offset + len(chunk):
                        os.lseek(output, offset, os.SEEK_SET)
                        if os.read(output, len(chunk)) != chunk:
                            raise ExecutorRefused("Wheel chunk retry changed bytes", "assignment_conflict")
                    else:
                        raise ExecutorRefused("Wheel chunk requires its exact next offset", "assignment_conflict")
                    if os.fstat(output).st_size == descriptor["size_bytes"]:
                        os.lseek(output, 0, os.SEEK_SET)
                        digest = hashlib.sha256()
                        while data := os.read(output, 1024**2):
                            digest.update(data)
                        if digest.hexdigest() != descriptor["sha256"]:
                            raise ExecutorRefused("Opaque wheel differs from declared hash", "unsafe_output")
                        os.fchmod(output, 0o400)
                        os.fsync(output)
                        _rename_no_replace(temporary, filename, directory)
                        os.fsync(directory)
                finally:
                    os.close(output)
            return True

    def purge(self, identity):
        parent = self.root / "jobs" / identity.job_id / "components" / identity.component_id
        with self._locks.setdefault(identity.key, threading.RLock()):
            return purge_private_tree(parent, max_total_bytes=2 * 1024**3)

    def prepare(self, identity, document, execution_binding=None):
        with self._locks.setdefault(identity.key, threading.RLock()):
            return self._prepare(identity, document, execution_binding)

    def _prepare(self, identity, document, execution_binding=None):
        assignment = self.assignment(identity)
        spec = self.plan(assignment)
        parent, _ = self._paths(assignment)
        self._charge_auxiliary(assignment, sum(
            item.get("size_bytes", 0) for item in (document.get("built_artifacts", {}) if isinstance(document, dict) else {}).values()
            if isinstance(item, dict) and type(item.get("size_bytes")) is int and item["size_bytes"] > 0))
        if spec.role == "build":
            if self.build_preparer is None:
                raise ExecutorRefused("Node has no approved offline build configuration", "build_not_approved")
            from .build import BuildConfig
            configuration = BuildConfig.model_validate(document)
            self.build_preparer(assignment, configuration)
        else:
            configuration = RuntimeConfig.model_validate(document)
            from .workflow import DatasetBinding
            local_data = {key: DatasetBinding.model_validate(value).model_dump(mode="json")
                          for key, value in (self.dataset_bindings(assignment) if self.dataset_bindings else {}).items()}
            supplied_data = {k: v.model_dump(mode="json") for k, v in configuration.dataset_bindings.items()}
            if supplied_data != local_data:
                raise ExecutorRefused("Dataset binding differs from locally approved inputs", "dataset_not_approved")
            if (configuration.source_dir != "/job/source" or configuration.state_dir != "/job/state"
                    or configuration.proxy_socket != "/run/hf2l/proxy.sock"
                    or configuration.exchange_endpoint != "http://proxy"):
                raise ExecutorRefused("Worker paths and endpoint are fixed by the node", "invalid_assignment")
        if (
            configuration.job_id, configuration.attempt_id, configuration.component_id, configuration.epoch
        ) != (
            identity.job_id, identity.attempt_id, identity.component_id, identity.epoch
        ) or configuration.spec.digest != assignment.job_spec.digest:
            raise ExecutorRefused("Worker configuration differs from assignment", "assignment_conflict")
        if configuration.role != spec.role and not (spec.role == "owner" and configuration.role == "init"):
            raise ExecutorRefused("Worker role differs from assignment", "assignment_conflict")
        if spec.build_input_path:
            build_root = Path(spec.build_input_path)
            if not configuration.built_artifacts:
                raise ExecutorRefused("Training requires its verified opaque wheels", "build_inputs_missing")
            if self._read(parent / "build-input-manifest.json").get("artifacts") != {
                    name: item.model_dump(mode="json") for name, item in configuration.built_artifacts.items()}:
                raise ExecutorRefused("Build input manifest differs from worker config", "assignment_conflict")
            with SafeCollector(build_root, max_file_bytes=min(256 * 1024**2, spec.resources.disk_bytes),
                               max_total_bytes=min(256 * 1024**2, spec.resources.disk_bytes)) as collector:
                manifest = collector.collect()
            if {item.path: {"sha256": item.sha256, "size_bytes": item.size_bytes} for item in manifest} != {
                    name: item.model_dump(mode="json") for name, item in configuration.built_artifacts.items()}:
                raise ExecutorRefused("Opaque build inputs are incomplete or changed", "unsafe_output")
        elif getattr(configuration, "built_artifacts", {}):
            raise ExecutorRefused("Unexpected build inputs for immutable job", "build_not_approved")
        source = parent / "source"
        registry = self._registry(assignment)
        self._validate_registry(assignment)
        if not source.exists() and not source.is_symlink():
            registry.source_registry.materialize(
                assignment.job_spec.project_id, assignment.job_spec.source_id,
                assignment.job_spec.source_commit, source,
            )
        with SafeCollector(source, max_files=100000, max_entries=200000,
                           max_file_bytes=1024**3, max_total_bytes=1024**3) as collector:
            actual_manifest = {item.path: item.sha256 for item in collector.collect()}
        if actual_manifest != dict(configuration.source_manifest):
            raise ExecutorRefused("Node approved source does not match immutable manifest", "source_conflict")
        if spec.role != "build" and execution_binding is not None:
            from .broker import stable_workload_principal
            if (not isinstance(execution_binding, dict)
                    or execution_binding.get("proxy_endpoint") != "remote:" + identity.key
                    or not execution_binding.get("certificate_thumbprint")):
                raise ExecutorRefused("Logical remote proxy binding differs", "missing_proxy")
            if self.execution_bindings is None:
                raise ExecutorRefused("Local execution binding is required", "missing_proxy")
            issuer = getattr(self, "workload_issuer", None)
            if issuer is None:
                raise ExecutorRefused("Local workload identity issuer is required", "missing_proxy")
            principal = stable_workload_principal(issuer, identity.job_id, identity.component_id,
                                                 assignment.component.participant_id)
            actual = self.binding(identity, configuration.space_id, principal)
            if actual["certificate_thumbprint"] != execution_binding["certificate_thumbprint"]:
                raise ExecutorRefused("Prepared proxy certificate differs", "missing_proxy")
        if spec.role != "build" and configuration.secret_option_names:
            if not spec.secret_path or self.secret_materializer is None:
                raise ExecutorRefused("Node secret delivery is not approved", "secret_not_approved")
            self.secret_materializer(assignment, configuration.model_dump(mode="json"), spec.secret_path)
        state = parent / "state"
        if state.is_symlink():
            raise ExecutorRefused("Node state cannot be linked", "unsafe_mount")
        state.mkdir(mode=0o700, exist_ok=True)
        for name in ("cache", "logs", "artifacts"):
            path = state / name
            if path.is_symlink():
                raise ExecutorRefused("Node state directory cannot be linked", "unsafe_mount")
            path.mkdir(mode=0o700, exist_ok=True)
        output = configuration.model_dump(mode="json")
        config_path = Path(spec.config_path)
        if config_path.exists() or config_path.is_symlink():
            if self._read(config_path) != output:
                raise ExecutorRefused("Prepared execution configuration changed", "assignment_conflict")
        else:
            atomic_json(config_path, output, mode=0o400)
        return True


class RemoteExecutor:
    """Route every operation to its operator-approved node, without fallback."""

    def __init__(self, endpoints: Mapping[str, NodeEndpoint], *, route: Callable,
                 assignment_provider: Callable, token_provider: Callable,
                 prepared_provider: Callable | None = None, client_factory=None):
        self.endpoints = dict(endpoints)
        if any(key != endpoint.node_id for key, endpoint in self.endpoints.items()):
            raise ExecutorRefused("Node registry identity mismatch", "invalid_node_endpoint")
        self.route, self.assignment_provider, self.token_provider = route, assignment_provider, token_provider
        self.prepared_provider = prepared_provider
        self.clients = {key: (client_factory(endpoint) if client_factory else endpoint.client())
                        for key, endpoint in self.endpoints.items()}

    def close(self):
        for client in self.clients.values():
            client.close()

    def _route(self, identity, pool_id=None):
        route = self.route(identity, pool_id)
        if not isinstance(route, NodeRoute) or route.node_id not in self.endpoints:
            raise ExecutorRefused("No approved endpoint for assigned node", "node_not_approved")
        if pool_id is not None and route.pool_id != pool_id:
            raise ExecutorRefused("Routing changed the admitted resource pool", "pool_mismatch")
        return route

    def _post(self, route, identity, operation, body, *, byte_limit=None):
        endpoint = self.endpoints[route.node_id]
        scope = {"prepare": "assignment", "binding": "assignment", "stage-build": "assignment", "proxy-alive": "inspect", "health": "heartbeat",
                 "read-artifact": "collect", "read-state": "collect", "read-logs": "logs"}.get(operation, operation)
        token = self.token_provider(route, identity, scope)
        if not isinstance(token, str) or not token or len(token) > 16384:
            raise ExecutorRefused("Node grant could not be issued", "node_grant_unavailable")
        limit = endpoint.max_reply_bytes if byte_limit is None else byte_limit
        try:
            with self.clients[route.node_id].stream(
                "POST", endpoint.origin + "/internal/nodes/v1/" + operation,
                json=body, headers={"Authorization": "Bearer " + token, "Accept-Encoding": "identity"},
            ) as response:
                content = bytearray()
                for chunk in response.iter_bytes():
                    if len(content) + len(chunk) > limit:
                        raise UncertainExecution("Node reply exceeded its trusted bound")
                    content.extend(chunk)
                if response.status_code >= 500 or 300 <= response.status_code < 400:
                    raise UncertainExecution("Node operation outcome is unknown")
                if response.status_code >= 400:
                    try:
                        code = json.loads(content).get("error", {}).get("code", "node_operation_refused")
                    except (ValueError, AttributeError):
                        code = "node_operation_refused"
                    raise ExecutorRefused("Approved node refused execution operation", str(code))
                if byte_limit is not None:
                    return bytes(content)
                return json.loads(content)
        except httpx.HTTPError as error:
            raise UncertainExecution("Approved node transport outcome is unknown") from error
        except (ValueError, UnicodeError) as error:
            raise UncertainExecution("Node returned an invalid operation receipt") from error

    def reserve(self, spec):
        route = self._route(spec.identity, spec.pool_id)
        if spec.resources != route.resources:
            raise ExecutorRefused("Execution resources differ from admitted node route", "invalid_resources")
        assignment = self.assignment_provider(spec, route)
        if (not isinstance(assignment, RemoteAssignment) or assignment.identity != spec.identity
                or (assignment.node_id, assignment.pool_id, assignment.resources) !=
                (route.node_id, route.pool_id, route.resources)):
            raise ExecutorRefused("Assignment provider changed admission binding", "assignment_conflict")
        reply = self._post(route, spec.identity, "reserve", {"assignment": assignment.to_dict()})
        try:
            reservation = Reservation(identity=ExecutionIdentity(**reply["identity"]),
                                      acknowledged=reply["acknowledged"], node_id=reply["node_id"],
                                      state=reply.get("state", "RESERVED"))
            if reservation.identity != spec.identity or reservation.node_id != route.node_id or reservation.acknowledged is not True:
                raise ValueError()
            return reservation
        except (TypeError, KeyError, ValueError) as error:
            raise UncertainExecution("Remote reservation ACK does not match assignment") from error

    def _observe(self, identity, operation, **options):
        route = self._route(identity)
        reply = self._post(route, identity, operation, {"identity": asdict(identity), **options})
        try:
            reply = dict(reply)
            reply["identity"] = ExecutionIdentity(**reply["identity"])
            observation = RuntimeObservation(**reply)
            if (
                observation.identity != identity or type(observation.termination_confirmed) is not bool
                or not isinstance(observation.state, str)
                or observation.state not in {"RESERVING", "RESERVED", "STARTING", "RUNNING", "STOPPING", "STOPPED",
                                             "EXITED", "RELEASED", "QUARANTINED", "UNKNOWN"}
                or not isinstance(observation.metrics, dict)
                or any(type(value) not in (int, float) or not math.isfinite(value)
                       for value in observation.metrics.values())
            ):
                raise ValueError()
            return observation
        except (KeyError, TypeError, ValueError) as error:
            raise UncertainExecution("Remote observation does not match execution") from error

    def start(self, identity):
        if self.prepared_provider:
            value = self.prepared_provider(identity)
            self.prepare(identity, value["runtime_config"], value.get("execution_binding"),
                         build_products=value.get("build_products"))
        return self._observe(identity, "start")

    def inspect(self, identity):
        return self._observe(identity, "inspect")

    def stop(self, identity, grace_seconds=60):
        if type(grace_seconds) is not int or not 0 <= grace_seconds <= 60:
            raise ExecutorRefused("Invalid bounded stop grace", "invalid_assignment")
        return self._observe(identity, "stop", grace_seconds=grace_seconds)

    def _confirmed(self, identity, operation, **options):
        reply = self._post(self._route(identity), identity, operation, {"identity": asdict(identity), **options})
        if not isinstance(reply, dict) or reply.get("confirmed") is not True:
            raise UncertainExecution("Remote completion was not confirmed")
        return True

    def prepare(self, identity, runtime_config, execution_binding=None, *, build_products=None):
        import base64
        declared = runtime_config.get("built_artifacts", {})
        payloads = build_products or {}
        if not isinstance(payloads, Mapping) or set(payloads) != set(declared):
            raise ExecutorRefused("Remote training requires exact verified build products", "build_inputs_missing")
        configuration = RuntimeConfig.model_validate(runtime_config) if runtime_config.get("role") != "build" else None
        limit = min(256 * 1024**2, self._route(identity).resources.disk_bytes)
        if sum(len(data) for data in payloads.values() if isinstance(data, bytes)) > limit:
            raise ExecutorRefused("Build products exceed remote admitted disk", "invalid_assignment")
        for filename, data in payloads.items():
            descriptor = configuration.built_artifacts[filename]
            if (not isinstance(data, bytes) or len(data) != descriptor.size_bytes
                    or hashlib.sha256(data).hexdigest() != descriptor.sha256):
                raise ExecutorRefused("Build products differ from verified runtime manifest", "unsafe_output")
            for offset in range(0, len(data), 1024**2):
                self._confirmed(identity, "stage-build", artifacts=declared, filename=filename,
                    offset=offset, data_base64=base64.b64encode(data[offset:offset + 1024**2]).decode("ascii"))
        return self._confirmed(identity, "prepare", runtime_config=runtime_config,
                               execution_binding=execution_binding)

    def binding(self, identity, space_id, principal_id):
        return self._post(self._route(identity), identity, "binding",
                          {"identity": asdict(identity), "space_id": space_id, "principal_id": principal_id})

    def renew(self, identity, lease_seconds=120):
        if type(lease_seconds) not in (int, float) or not 0 < lease_seconds <= 300:
            raise ExecutorRefused("Invalid bounded lease", "invalid_lease")
        return self._confirmed(identity, "renew", lease_seconds=lease_seconds)

    def release(self, identity):
        return self._confirmed(identity, "release")

    def purge_receipt(self, identity, *, spec_digest=None):
        route = self._route(identity)
        reply = self._post(route, identity, "purge", {"identity": asdict(identity), "spec_digest": spec_digest})
        try:
            if not isinstance(reply, dict) or set(reply) != set(NodePurgeReceipt.__dataclass_fields__):
                raise ValueError("Every deletion proof field is mandatory")
            receipt = NodePurgeReceipt(**reply)
        except (TypeError, ValueError, ExecutorRefused) as error:
            raise UncertainExecution("Node did not prove owned auxiliary deletion") from error
        expected = {**asdict(identity), "node_id": route.node_id, "pool_id": route.pool_id}
        if (any(getattr(receipt, name) != value for name, value in expected.items())
                or spec_digest is not None and receipt.spec_digest != spec_digest):
            raise UncertainExecution("Node purge receipt has a foreign ownership binding")
        return receipt.as_dict()

    def purge(self, identity):
        return self.purge_receipt(identity)["confirmed"]

    def collect(self, identity):
        route = self._route(identity)
        reply = self._post(route, identity, "collect", {"identity": asdict(identity)})
        if not isinstance(reply, list) or len(reply) > 1000:
            raise UncertainExecution("Remote artifact inventory is invalid")
        result = []
        for item in reply:
            try:
                path = item["path"]
                if not isinstance(path, str) or path.startswith("/") or any(p in ("", ".", "..") for p in path.split("/")) or "\\" in path:
                    raise ValueError()
                if type(item["size_bytes"]) is not int or item["size_bytes"] < 0:
                    raise ValueError()
                import re
                if not re.fullmatch(r"[a-f0-9]{64}", item["sha256"]):
                    raise ValueError()
                locator = "hf2l-node://" + route.node_id + "/" + identity.key + "/" + quote(path, safe="/")
                result.append(RetainedFile(path, locator, item["size_bytes"], item["sha256"]))
            except (KeyError, TypeError, ValueError) as error:
                raise UncertainExecution("Remote artifact receipt is invalid") from error
        return tuple(result)

    def _read_bytes(self, identity, path, max_bytes, operation):
        if type(max_bytes) is not int or not 0 <= max_bytes <= 1024**3:
            raise ExecutorRefused("Invalid artifact read bound", "invalid_assignment")
        route = self._route(identity)
        limit = min(max_bytes, route.resources.disk_bytes)
        return self._post(route, identity, operation,
                          {"identity": asdict(identity), "path": path, "max_bytes": limit},
                          byte_limit=limit)

    def read_logs(self, identity, offset=0, *, max_bytes=65536):
        if type(offset) is not int or offset < 0 or type(max_bytes) is not int or not 4 <= max_bytes <= 65536:
            raise ExecutorRefused("Invalid bounded log cursor", "invalid_assignment")
        reply = self._post(self._route(identity), identity, "read-logs",
                           {"identity": asdict(identity), "offset": offset, "max_bytes": max_bytes})
        try:
            if (not isinstance(reply, dict) or set(reply) != {
                    "identity", "source_id", "offset", "next_offset", "content", "complete", "truncated"}
                    or reply["identity"] != asdict(identity) or reply["source_id"] != identity.key
                    or type(reply["offset"]) is not int or reply["offset"] != offset
                    or type(reply["next_offset"]) is not int or not offset <= reply["next_offset"] <= 1048576
                    or not isinstance(reply["content"], str) or len(reply["content"].encode()) > max_bytes
                    or reply["next_offset"] - offset != len(reply["content"].encode())
                    or type(reply["complete"]) is not bool or type(reply["truncated"]) is not bool):
                raise ValueError()
        except (KeyError, TypeError, ValueError, UnicodeError) as error:
            raise UncertainExecution("Remote canonical log receipt is invalid") from error
        return reply

    def read_artifact(self, identity, path, *, max_bytes=64 * 1024**2):
        return self._read_bytes(identity, path, max_bytes, "read-artifact")

    def read_state(self, identity, path, *, max_bytes=1024**2):
        try:
            return self._read_bytes(identity, path, max_bytes, "read-state")
        except ExecutorRefused as error:
            if error.code == "state_file_missing":
                return None
            raise

    def proxy_alive(self, identity):
        reply = self._post(self._route(identity), identity, "proxy-alive", {"identity": asdict(identity)})
        if (not isinstance(reply, dict) or reply.get("identity") != asdict(identity)
                or type(reply.get("alive")) is not bool):
            raise UncertainExecution("Remote proxy liveness receipt is invalid")
        return reply["alive"]

    def reconciliation_root(self, identity):
        raise ExecutorRefused("Remote state requires bounded read_state, not a host path", "remote_state")

    def health(self, identity):
        route = self._route(identity)
        reply = self._post(route, identity, "health", {
            "identity": asdict(identity), "resources": asdict(route.resources),
        })
        if (
            not isinstance(reply, dict) or reply.get("node_id") != route.node_id
            or reply.get("pool_id") != route.pool_id or reply.get("healthy") is not True
        ):
            raise ExecutorRefused("Approved node health was not confirmed", "runtime_unhealthy")
        return reply

    def watchdog_once(self):
        # Lease enforcement is autonomous on each node, not an RPC guess.
        return ()


def create_remote_node_app(agent, authenticate, materializer: RemoteNodeMaterializer, *,
                           qualify_authenticate=None, registration_id=None,
                           manager_certificate_thumbprint=None, stop_callback=None, purge_callback=None,
                           proxy_alive_callback=None):
    """Strict mTLS assignment API; reuse the actual durable local NodeAgent."""
    if authenticate is None:
        raise ExecutorRefused("Remote node requires current-grant authentication", "authentication_required")
    from fastapi import FastAPI, Request, HTTPException
    from fastapi.responses import JSONResponse, Response
    from starlette.concurrency import run_in_threadpool
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    async def body(request, allowed):
        content = bytearray()
        async for chunk in request.stream():
            if len(content) + len(chunk) > 4 * 1024**2:
                raise HTTPException(413, "Assignment body exceeds its bound")
            content.extend(chunk)
        try:
            from .collection import _json_object
            value = json.loads(content, object_pairs_hook=_json_object)
        except (ValueError, UnicodeError):
            raise HTTPException(422, "Structured assignment required") from None
        if not isinstance(value, dict) or set(value) - set(allowed):
            raise HTTPException(422, "Host paths, commands and unknown fields are forbidden")
        return value

    async def authorize(request, operation, identity, assignment=None):
        if not request.scope.get("state", {}).get("verified_certificate_thumbprint"):
            raise HTTPException(401, "Verified mutual TLS peer is required")
        scope = {"prepare": "assignment", "binding": "assignment", "stage-build": "assignment", "proxy-alive": "inspect",
                 "read-artifact": "collect", "read-state": "collect", "read-logs": "logs"}.get(operation, operation)
        if inspect.iscoroutinefunction(authenticate):
            principal = await authenticate(request, scope)
        else:
            principal = await run_in_threadpool(authenticate, request, scope)
            if inspect.isawaitable(principal):
                principal = await principal
        expected = {"node_id": agent.node_id, "pool_id": agent.pool_id, **asdict(identity)}
        if any(getattr(principal, name, None) != value for name, value in expected.items()):
            raise HTTPException(403, "Node grant differs from assignment identity")
        peer = request.scope["state"]["verified_certificate_thumbprint"]
        bound_peer = getattr(principal, "certificate_thumbprint", None)
        if not isinstance(bound_peer, str) or not hmac.compare_digest(bound_peer, peer):
            raise HTTPException(403, "Node grant differs from its verified certificate")
        if scope not in getattr(principal, "scopes", ()):
            raise HTTPException(403, "Node grant cannot perform this operation")
        if assignment is None:
            try:
                assignment = await run_in_threadpool(materializer.assignment, identity)
            except CollectionError as error:
                cause = error
                while cause.__cause__ is not None:
                    cause = cause.__cause__
                if operation not in {"inspect", "stop", "collect", "release", "purge", "read-state", "read-artifact", "read-logs"} or not isinstance(cause, FileNotFoundError):
                    raise
                limits = await run_in_threadpool(agent.assignment_resources, identity, allow_stale=True)
                assignment = SimpleNamespace(resources=ResourceLimits(
                    limits["cpu_millicores"], limits["memory_bytes"], limits["disk_bytes"]))
        expected_resources = {"cpu_millicores": assignment.resources.cpu_millis,
                              "memory_bytes": assignment.resources.memory_bytes,
                              "disk_bytes": assignment.resources.disk_bytes}
        limits = getattr(principal, "resources", {})
        if any(limits.get(name) != value for name, value in expected_resources.items()) or limits.get("gpu_uuids"):
            raise HTTPException(403, "Node grant resources differ from assignment")
        return assignment

    @app.post("/internal/nodes/v1/qualify")
    async def qualify(request: Request):
        document = await body(request, {"node_id", "pool_id", "registration_id"})
        peer = request.scope.get("state", {}).get("verified_certificate_thumbprint")
        if not peer or qualify_authenticate is None or registration_id is None:
            raise HTTPException(401, "Registered platform qualification authority required")
        if manager_certificate_thumbprint is None or not hmac.compare_digest(peer, manager_certificate_thumbprint):
            raise HTTPException(403, "Registered manager certificate required")
        expected = {"node_id": agent.node_id, "pool_id": agent.pool_id, "registration_id": registration_id}
        if document != expected:
            raise HTTPException(403, "Qualification registration differs")
        principal = await run_in_threadpool(qualify_authenticate, request)
        if inspect.isawaitable(principal):
            principal = await principal
        if (any(getattr(principal, name, None) != value for name, value in expected.items())
                or getattr(principal, "certificate_thumbprint", None) != peer
                or getattr(principal, "scopes", None) != frozenset({"qualify"})):
            raise HTTPException(403, "Invalid platform qualification binding")
        if not hasattr(agent.executor, "qualify_health") or not hasattr(agent.executor, "profile"):
            raise ExecutorRefused("Node has no actual runtime qualification", "unqualified_profile")
        await run_in_threadpool(agent.executor.qualify_health)
        profile = agent.executor.profile
        if any(profile.get(key) != value for key, value in {
                "qualified": True, "runtime": "runsc", "network": "none",
                "bounded_volumes": "loop-ext4"}.items()):
            raise ExecutorRefused("Node isolation profile is incomplete", "unqualified_profile")
        digest = hashlib.sha256(canonical_json(profile).encode()).hexdigest()
        return {**expected, "healthy": True,
                "capacity": {"cpu_millicores": agent.capacity.cpu_millis,
                             "memory_bytes": agent.capacity.memory_bytes,
                             "disk_bytes": agent.capacity.disk_bytes},
                "sandbox_profiles": ["runsc-cpu-v1"],
                "profile_attestations": {"runsc-cpu-v1": {
                    "qualified": True, "profile_sha256": digest, "runtime": "runsc",
                    "network": "none", "bounded_volumes": "loop-ext4"}}}

    @app.post("/internal/nodes/v1/health")
    async def health(request: Request):
        document = await body(request, {"identity", "resources"})
        try:
            identity = ExecutionIdentity(**document["identity"])
            resources = ResourceLimits(**document["resources"])
        except (TypeError, KeyError, ValueError):
            raise HTTPException(422, "Invalid health assignment") from None
        peer = request.scope.get("state", {}).get("verified_certificate_thumbprint")
        if not peer:
            raise HTTPException(401, "Verified mutual TLS peer is required")
        if inspect.iscoroutinefunction(authenticate):
            principal = await authenticate(request, "heartbeat")
        else:
            principal = await run_in_threadpool(authenticate, request, "heartbeat")
            if inspect.isawaitable(principal):
                principal = await principal
        expected = {"node_id": agent.node_id, "pool_id": agent.pool_id, **asdict(identity)}
        if (
            any(getattr(principal, name, None) != value for name, value in expected.items())
            or "heartbeat" not in getattr(principal, "scopes", ())
            or getattr(principal, "certificate_thumbprint", None) != peer
        ):
            raise HTTPException(403, "Health grant is not bound to this node")
        limits = getattr(principal, "resources", {})
        expected_limits = {"cpu_millicores": resources.cpu_millis,
                           "memory_bytes": resources.memory_bytes, "disk_bytes": resources.disk_bytes}
        if any(limits.get(name) != value for name, value in expected_limits.items()) or limits.get("gpu_uuids"):
            raise HTTPException(403, "Health resources differ from node grant")
        if not hasattr(agent.executor, "qualify_health"):
            raise ExecutorRefused("Node has no actual sandbox qualification", "unqualified_profile")
        await run_in_threadpool(agent.executor.qualify_health)
        return {"node_id": agent.node_id, "pool_id": agent.pool_id, "healthy": True,
                "capacity": {"cpu_millicores": agent.capacity.cpu_millis,
                             "memory_bytes": agent.capacity.memory_bytes,
                             "disk_bytes": agent.capacity.disk_bytes},
                "sandbox_profiles": ["runsc-cpu-v1"]}

    @app.post("/internal/nodes/v1/reserve")
    async def reserve(request: Request):
        document = await body(request, {"assignment"})
        assignment = RemoteAssignment.from_dict(document.get("assignment"))
        await authorize(request, "reserve", assignment.identity, assignment)
        def reserve_owned():
            with agent.component_resource_guard(assignment.identity), materializer.pending_assignment(assignment):
                spec = materializer.plan(assignment)
                receipt = agent.reserve(spec)
                if materializer.auxiliary_reserver is not None:
                    materializer.auxiliary_reserver(assignment.identity, 4 * 1024**2 + 256 * 1024)
                materializer.reserve(assignment)
                return receipt
        return asdict(await run_in_threadpool(reserve_owned))

    def endpoint(operation):
        allowed = {
            "stop": {"grace_seconds"}, "renew": {"lease_seconds"}, "purge": {"spec_digest"},
            "prepare": {"runtime_config", "execution_binding"},
            "binding": {"space_id", "principal_id"},
            "stage-build": {"artifacts", "filename", "offset", "data_base64"},
            "read-artifact": {"path", "max_bytes"}, "read-state": {"path", "max_bytes"},
            "read-logs": {"offset", "max_bytes"},
        }.get(operation, set())
        def mutate_owned(identity, function, *arguments):
            with agent.component_resource_guard(identity):
                agent.assignment_resources(identity)
                return function(*arguments)
        async def call(request: Request):
            document = await body(request, {"identity", *allowed})
            try:
                identity = ExecutionIdentity(**document["identity"])
            except (TypeError, KeyError, ValueError):
                raise HTTPException(422, "Invalid execution identity") from None
            assignment = await authorize(request, operation, identity)
            if operation == "read-logs":
                offset, limit = document.get("offset", 0), document.get("max_bytes", 65536)
                if type(offset) is not int or offset < 0 or type(limit) is not int or not 4 <= limit <= 65536:
                    raise HTTPException(422, "Invalid bounded log cursor")
                if not hasattr(agent, "read_logs"):
                    raise ExecutorRefused("Node log stream is unavailable", "logs_unavailable")
                return await run_in_threadpool(agent.read_logs, identity, offset=offset, max_bytes=limit)
            elif operation == "proxy-alive":
                await run_in_threadpool(agent.assignment_resources, identity)
                if proxy_alive_callback is None:
                    raise ExecutorRefused("Node-local proxy liveness is unavailable", "proxy_restart_required")
                alive = await run_in_threadpool(proxy_alive_callback, identity)
                if type(alive) is not bool:
                    raise UncertainExecution("Node proxy liveness is unknown")
                return {"alive": alive, "identity": asdict(identity)}
            elif operation == "stage-build":
                await run_in_threadpool(agent.assignment_resources, identity)
                result = await run_in_threadpool(mutate_owned, identity, materializer.stage_build_input, identity,
                    document.get("artifacts"), document.get("filename"), document.get("offset"),
                    document.get("data_base64"))
            elif operation == "prepare":
                if hasattr(agent, "assignment_resources"):
                    await run_in_threadpool(agent.assignment_resources, identity)
                else:
                    await run_in_threadpool(agent._row, identity)
                result = await run_in_threadpool(
                    mutate_owned, identity, materializer.prepare, identity,
                    document.get("runtime_config"), document.get("execution_binding")
                )
            elif operation == "binding":
                return await run_in_threadpool(
                    mutate_owned, identity, materializer.binding, identity,
                    document.get("space_id"), document.get("principal_id")
                )
            elif operation in ("read-artifact", "read-state"):
                limit = document.get("max_bytes", 1024**2)
                if type(limit) is not int or not 0 <= limit <= min(1024**3, assignment.resources.disk_bytes):
                    raise HTTPException(422, "Invalid file read bound")
                if operation == "read-state":
                    if not (await run_in_threadpool(agent.inspect, identity)).termination_confirmed:
                        raise ExecutorRefused("Output requires confirmed runtime termination", "runtime_active")
                    root = await run_in_threadpool(agent.reconciliation_root, identity)
                    item = None
                else:
                    if hasattr(agent, "retained_manifest"):
                        retained = await run_in_threadpool(agent.retained_manifest, identity)
                    else:
                        if not (await run_in_threadpool(agent.inspect, identity)).termination_confirmed:
                            raise ExecutorRefused("Output requires confirmed runtime termination", "runtime_active")
                        retained = await run_in_threadpool(agent.collect, identity)
                    item = next((item for item in retained if item.path == document.get("path")), None)
                    if item is None:
                        raise HTTPException(404, "Retained artifact is unavailable")
                    root = Path(item.locator)
                    for _ in Path(item.path).parts:
                        root = root.parent
                    if Path(item.locator) != root / item.path:
                        raise ExecutorRefused("Retained locator differs from owned file", "unsafe_output")
                with SafeCollector(root, max_file_bytes=max(1, limit),
                                   max_total_bytes=max(1, assignment.resources.disk_bytes)) as collector:
                    try:
                        content = await run_in_threadpool(collector.read, document.get("path"), max_bytes=limit)
                    except CollectionError as error:
                        cause = error
                        while cause.__cause__ is not None:
                            cause = cause.__cause__
                        if operation == "read-state" and isinstance(cause, FileNotFoundError):
                            return JSONResponse({"error": {"code": "state_file_missing"}}, status_code=404)
                        raise
                if item is not None and (
                    len(content) != item.size_bytes or hashlib.sha256(content).hexdigest() != item.sha256
                ):
                    raise ExecutorRefused("Retained bytes differ from their immutable manifest", "unsafe_output")
                return Response(content, media_type="application/octet-stream",
                                headers={"X-Content-Type-Options": "nosniff"})
            elif operation == "purge":
                def purge_owned():
                    with agent.component_purge_guard(identity):
                        allowed = (agent.component_purge_allowed(identity) if hasattr(agent, "component_purge_allowed")
                                   else agent.inspect(identity).state == "RELEASED")
                        if not allowed:
                            raise ExecutorRefused("Cannot purge active component", "runtime_active")
                        expected_digest = document.get("spec_digest")
                        if hasattr(assignment, "job_spec"):
                            local_digest = assignment.job_spec.digest
                            if expected_digest is not None and expected_digest != local_digest:
                                raise ExecutorRefused("Purge specification differs from assignment", "assignment_conflict")
                        else:
                            local_digest = expected_digest
                        import re
                        if not isinstance(local_digest, str) or not re.fullmatch("[a-f0-9]{64}", local_digest):
                            raise ExecutorRefused("Purge requires immutable provenance", "invalid_purge_receipt")
                        if purge_callback:
                            if purge_callback(identity) is not True:
                                raise UncertainExecution("Private node resource deletion is unconfirmed")
                        elif materializer.execution_bindings is not None or materializer.secret_materializer is not None:
                            raise ExecutorRefused("Node private deletion authority unavailable", "invalid_purge_receipt")
                        if not materializer.purge(identity):
                            raise UncertainExecution("Component data deletion is unconfirmed")
                        if agent.purge(identity, auxiliary_deleted=True) is not True:
                            raise UncertainExecution("Retained node deletion is unconfirmed")
                        receipt = NodePurgeReceipt(**asdict(identity), node_id=agent.node_id, pool_id=agent.pool_id,
                            spec_digest=local_digest, operation_id="purge-" + identity.key)
                        receipt_path = materializer.purge_receipts / (identity.key + ".json")
                        if receipt_path.exists() or receipt_path.is_symlink():
                            if materializer._read(receipt_path) != receipt.as_dict():
                                raise ExecutorRefused("Durable purge ownership receipt changed", "assignment_conflict")
                        else:
                            atomic_json(receipt_path, receipt.as_dict(), mode=0o400)
                        return receipt.as_dict()
                return await run_in_threadpool(purge_owned)
            elif operation == "release":
                if stop_callback and await run_in_threadpool(stop_callback, identity) is not True:
                    raise UncertainExecution("Private execution proxy stop is unconfirmed")
                result = await run_in_threadpool(agent.release, identity)
            elif operation == "stop":
                grace = document.get("grace_seconds", 60)
                if type(grace) is not int or not 0 <= grace <= 60:
                    raise HTTPException(422, "Invalid bounded stop grace")
                result = await run_in_threadpool(agent.stop, identity, grace_seconds=grace)
                if result.termination_confirmed and stop_callback:
                    if await run_in_threadpool(stop_callback, identity) is not True:
                        raise UncertainExecution("Private execution proxy stop is unconfirmed")
            elif operation == "renew":
                result = await run_in_threadpool(agent.renew, identity, lease_seconds=document.get("lease_seconds", 120))
            else:
                result = await run_in_threadpool(getattr(agent, operation), identity)
            if hasattr(result, "__dataclass_fields__"):
                return asdict(result)
            if isinstance(result, (tuple, list)):
                return [{k: v for k, v in asdict(item).items() if k != "locator"} for item in result]
            return {"confirmed": result}
        return call

    for operation in ("start", "inspect", "stop", "collect", "release", "renew", "purge",
                      "prepare", "binding", "stage-build", "proxy-alive", "read-artifact", "read-state", "read-logs"):
        app.add_api_route("/internal/nodes/v1/" + operation, endpoint(operation), methods=["POST"])

    @app.exception_handler(ExecutorRefused)
    async def refused(request, error):
        return JSONResponse({"error": {"code": error.code}}, status_code=409)

    @app.exception_handler(UncertainExecution)
    async def uncertain(request, error):
        return JSONResponse({"error": {"code": error.code}}, status_code=503)

    @app.exception_handler(ValueError)
    async def invalid(request, error):
        return JSONResponse({"error": {"code": "invalid_assignment"}}, status_code=422)
    return app


class NodeCredentialClient:
    """Fixed manager mTLS calls using only the node's registered identity key."""

    def __init__(self, endpoint: NodeEndpoint, *, route_prefix="nodes", token_provider=None,
                 http=None):
        if route_prefix not in {"nodes", "participants"}:
            raise ExecutorRefused("Invalid central assignment service", "invalid_node_endpoint")
        self.endpoint, self.route_prefix, self.token_provider = endpoint, route_prefix, token_provider
        self.http = http or endpoint.client()

    def close(self):
        self.http.close()

    def _path(self, identity, operation):
        return "/internal/jobs/v1/" + self.route_prefix + "/" + "/".join((
            identity.job_id, identity.attempt_id, identity.component_id, str(identity.epoch), operation,
        ))

    def request(self, identity, operation, body=None, *, method="POST"):
        headers = {"Accept-Encoding": "identity"}
        if operation != "bootstrap":
            token = (self.token_provider(identity, operation) if self.token_provider else
                     self.request(identity, "bootstrap", {}).get("token"))
            if not isinstance(token, str) or not token or len(token) > 16384:
                raise ExecutorRefused("Node bootstrap grant is unavailable", "node_grant_unavailable")
            headers["Authorization"] = "Bearer " + token
        try:
            with self.http.stream(method, self.endpoint.origin + self._path(identity, operation),
                                  json=body, headers=headers) as response:
                content = bytearray()
                for chunk in response.iter_bytes():
                    if len(content) + len(chunk) > self.endpoint.max_reply_bytes:
                        raise UncertainExecution("Central node reply exceeded its bound")
                    content.extend(chunk)
                if response.status_code >= 500 or 300 <= response.status_code < 400:
                    raise UncertainExecution("Central assignment operation outcome is unknown")
                if response.status_code >= 400:
                    raise ExecutorRefused("Central assignment operation was refused", "node_assignment_refused")
                value = json.loads(content)
                if not isinstance(value, dict):
                    raise ValueError()
                return value
        except httpx.HTTPError as error:
            raise UncertainExecution("Central assignment transport outcome is unknown") from error
        except (ValueError, UnicodeError) as error:
            raise UncertainExecution("Central assignment reply is invalid") from error

    def certificate(self, identity, csr_pem, space_id, principal_id):
        if not isinstance(csr_pem, str) or len(csr_pem.encode("utf-8")) > 16384:
            raise ExecutorRefused("Invalid bounded execution CSR", "invalid_assignment")
        return self.request(identity, "certificate", {
            "csr_pem": csr_pem, "space_id": space_id, "principal_id": principal_id,
        })

    def credentials(self, identity, certificate_thumbprint, audience):
        if audience not in {"exchange", "gateway"}:
            raise ExecutorRefused("Invalid workload credential audience", "invalid_assignment")
        if self.route_prefix == "participants":
            value = self.request(identity, "credentials", {})
            return value["exchange_token" if audience == "exchange" else "gateway_token"]
        value = self.request(identity, "credentials", {
            "certificate_thumbprint": certificate_thumbprint, "audience": audience,
        })
        token = value.get("token")
        if not isinstance(token, str) or not token or len(token) > 16384:
            raise UncertainExecution("Central workload credential reply is invalid")
        return token

    def validate(self, principal):
        identity = ExecutionIdentity(principal.job_id, principal.attempt_id, principal.component_id, principal.epoch)
        value = self.request(identity, "validate", {
            "node_id": principal.node_id, "pool_id": principal.pool_id,
            "grant_id": principal.grant_id, "certificate_thumbprint": principal.certificate_thumbprint,
            "scopes": sorted(principal.scopes), "resources": dict(principal.resources),
        })
        return value.get("valid") is True

    def assignment(self, identity):
        return self.request(identity, "plan", method="GET")


class NodeCertificateProvider:
    """Public-CSR adapter; ProxySupervisor owns every execution private key."""

    def __init__(self, client: NodeCredentialClient, *, workload_issuer, assignment_lookup):
        self.client, self.workload_issuer, self.assignment_lookup = client, workload_issuer, assignment_lookup

    def __call__(self, binding_fields, csr_pem):
        from .broker import stable_workload_principal
        identity = ExecutionIdentity(
            binding_fields["job_id"], binding_fields["attempt_id"],
            binding_fields["component_id"], binding_fields["epoch"],
        )
        assignment = self.assignment_lookup(identity)
        participant_id = assignment.component.participant_id
        principal = stable_workload_principal(
            self.workload_issuer, identity.job_id, identity.component_id, participant_id,
        )
        return self.client.certificate(identity, csr_pem, binding_fields["space_id"], principal)


def load_node_catalog(document):
    """Read local approvals without manager credentials.

    datasets maps binding IDs to lists of permitted participant IDs. Physical
    NPZ paths/project scopes belong in node.dataset_bindings, outside this catalog.
    """
    from .source import SourceApproval, SourceRegistry, RegistryCatalog
    if not isinstance(document, dict) or set(document) - {
        "sources", "runtime_images", "allowed_source_hosts", "datasets", "secret_refs",
    } or not {"sources", "runtime_images"} <= document.keys():
        raise ExecutorRefused("Invalid local source/runtime approval catalog", "invalid_node_configuration")
    approvals = []
    for item in document["sources"]:
        if not isinstance(item, dict) or set(item) - {
            "source_id", "projects", "commits", "mirror_path", "url",
            "max_bytes", "max_files", "max_git_bytes", "max_git_files",
        }:
            raise ExecutorRefused("Unknown local source approval option", "invalid_node_configuration")
        value = dict(item)
        value["projects"] = frozenset(value["projects"])
        value["commits"] = frozenset(value["commits"])
        if value.get("mirror_path") is not None:
            value["mirror_path"] = Path(value["mirror_path"])
        approvals.append(SourceApproval(**value))
    return RegistryCatalog(
        SourceRegistry(approvals, allowed_hosts=document.get("allowed_source_hosts", ())),
        document["runtime_images"], dataset_bindings=document.get("datasets", {}),
        secret_refs=document.get("secret_refs", ()),
    )


class NodePlatformClient:
    """Qualification transport for operator registrations, with no job authority."""
    def __init__(self, endpoint: NodeEndpoint, *, http=None):
        self.endpoint, self.http = endpoint, http or endpoint.client()

    def close(self):
        self.http.close()

    def qualify(self, pool_id, registration_id, token):
        validate_identifier(pool_id)
        validate_identifier(registration_id)
        if not isinstance(token, str) or not token or len(token) > 16384:
            raise ExecutorRefused("Platform qualification grant unavailable", "node_grant_unavailable")
        try:
            with self.http.stream("POST", self.endpoint.origin + "/internal/nodes/v1/qualify",
                    json={"node_id": self.endpoint.node_id, "pool_id": pool_id, "registration_id": registration_id},
                    headers={"Authorization": "Bearer " + token, "Accept-Encoding": "identity"}) as response:
                content = bytearray()
                for chunk in response.iter_bytes():
                    if len(content) + len(chunk) > self.endpoint.max_reply_bytes:
                        raise UncertainExecution("Node qualification reply exceeded its bound")
                    content.extend(chunk)
                if response.status_code >= 500 or 300 <= response.status_code < 400:
                    raise UncertainExecution("Node qualification is unknown")
                if response.status_code >= 400:
                    raise ExecutorRefused("Node qualification was refused", "runtime_unhealthy")
                value = json.loads(content)
        except (httpx.HTTPError, ValueError, UnicodeError) as error:
            raise UncertainExecution("Node qualification transport is unknown") from error
        if (not isinstance(value, dict) or value.get("node_id") != self.endpoint.node_id
                or value.get("pool_id") != pool_id or value.get("registration_id") != registration_id
                or value.get("healthy") is not True or value.get("sandbox_profiles") != ["runsc-cpu-v1"]):
            raise ExecutorRefused("Qualification differs from operator registration", "runtime_unhealthy")
        capacity = value.get("capacity")
        if not isinstance(capacity, dict) or set(capacity) != {"cpu_millicores", "memory_bytes", "disk_bytes"}:
            raise ExecutorRefused("Invalid node capacity attestation", "runtime_unhealthy")
        ResourceLimits(capacity["cpu_millicores"], capacity["memory_bytes"], capacity["disk_bytes"])
        attestation = value.get("profile_attestations", {}).get("runsc-cpu-v1", {})
        import re
        if (attestation.get("qualified") is not True or attestation.get("runtime") != "runsc"
                or attestation.get("network") != "none" or attestation.get("bounded_volumes") != "loop-ext4"
                or not re.fullmatch("[a-f0-9]{64}", attestation.get("profile_sha256", ""))):
            raise ExecutorRefused("Incomplete runtime qualification attestation", "runtime_unhealthy")
        return value


@dataclass
class ManagedNodeService:
    agent: object
    materializer: RemoteNodeMaterializer
    supervisor: object
    credential_client: NodeCredentialClient
    app: object
    server: object = None
    _closed: bool = False

    def close(self):
        if self._closed:
            return
        self._closed = True
        errors = []
        for callback in (
            *((self.server.shutdown, self.server.server_close) if self.server else ()),
            self.agent.close, self.supervisor.close, self.credential_client.close,
        ):
            try:
                callback()
            except Exception as error:
                errors.append(error)
        if errors:
            raise errors[0]


def _node_document(path):
    value = Path(path)
    if not value.is_absolute():
        raise ExecutorRefused("Node approvals require an absolute trusted file", "invalid_node_configuration")
    with SafeCollector(value.parent, max_file_bytes=1024**2, max_total_bytes=1024**2) as collector:
        content = collector.read(value.name)
    metadata = value.lstat()
    if metadata.st_uid not in (0, os.geteuid()) or metadata.st_mode & 0o022:
        raise ExecutorRefused("Node approval catalog must be operator owned", "invalid_node_configuration")
    document = json.loads(content)
    if not isinstance(document, dict):
        raise ExecutorRefused("Node approval catalog must be an object", "invalid_node_configuration")
    return document


class LocalNodeSecrets:
    """Local plugin-option approvals; never needs manager DB or control keys."""
    def __init__(self, root, references):
        from .secrets import SecretResolver
        self.resolver = SecretResolver(None, root, references)

    def _selected(self, assignment):
        from .secrets import SecretError
        selected = {}
        target = assignment.component
        for option, reference in assignment.job_spec.secret_refs.items():
            approval = self.resolver.approvals.get(reference)
            if approval is None:
                continue
            if (approval.project_id != assignment.job_spec.project_id or option not in approval.option_names
                    or option in assignment.job_spec.options):
                raise SecretError("Local secret approval differs from immutable job")
            if target.role in approval.roles and (
                    not approval.component_ids or target.component_id in approval.component_ids):
                selected[option] = approval
        return selected

    def planned(self, assignment):
        if not self._selected(assignment):
            return None
        return self.resolver._path(asdict(assignment.identity))

    def materialize(self, assignment, configuration, path):
        from .secrets import (_private_file, _secret_text, MAX_SECRET_BYTES, MAX_MANIFEST_BYTES,
                              SecretError, read_secret_manifest)
        selected = self._selected(assignment)
        if set(configuration["secret_option_names"]) != set(selected) or Path(path) != self.planned(assignment):
            raise SecretError("Node secret options differ from local approval")
        binding = asdict(assignment.identity)
        descriptor = self.resolver._directory(binding, create=True)
        lock = -1
        try:
            lock = self.resolver._lock(descriptor)
            try:
                os.stat("secrets.json", dir_fd=descriptor, follow_symlinks=False)
                manifest = read_secret_manifest(path, assignment.identity)
                if (manifest["references"] != {key: value.id for key, value in selected.items()}
                        or manifest["role"] != assignment.component.role):
                    raise SecretError("Existing node secret references changed")
            except FileNotFoundError:
                manifest = {"schema_version": 1, **binding, "role": assignment.component.role,
                            "references": {key: value.id for key, value in selected.items()},
                            "options": {key: _secret_text(_private_file(value.path, MAX_SECRET_BYTES))
                                        for key, value in selected.items()}}
                if len(canonical_json(manifest).encode()) > MAX_MANIFEST_BYTES:
                    raise SecretError("Node secret manifest exceeds bound")
                atomic_json(path, manifest, mode=0o400)
        finally:
            if lock >= 0:
                os.close(lock)
            os.close(descriptor)


def compose_node(settings):
    """Compose an isolated managed node with verification keys and local approvals."""
    import stat
    from fastapi import HTTPException
    from .broker import WorkloadBroker, BrokerError
    from .composition import ConfigurationError, _keys, _integer, section
    from .executor import LinuxExecutor
    from .execution_proxy import ProxySupervisor
    from .node_agent import NodeAgent
    node = section(settings, "node")
    required = {
        "node_id", "pool_id", "registration_id", "ledger_path", "capacity", "registry_file",
        "manager_endpoint", "manager_ca_file", "identity_certificate", "identity_key",
        "manager_certificate_thumbprint", "execution_ca_certificate", "exchange_endpoint",
        "gateway_endpoint", "service_ca_file",
    }
    _keys(node, required, {"dataset_bindings", "secret_refs", "proxy_socket_root", "build_inputs", "service"})
    if settings.broker is None or settings.broker.private_key is not None:
        raise ConfigurationError("Managed node must have a verification-only broker")
    # Explicitly reject accidentally shared manager operational credentials.
    if any(section(settings, key, required=False) for key in (
            "provisioner", "gateway", "proxy", "participants", "nodes", "secrets")):
        raise ConfigurationError("Managed node config cannot carry manager operational services")
    executor_config = section(settings, "executor")
    _keys(executor_config, {"root", "profile_path"})
    root = private_root(executor_config["root"])
    materializer_ref = {}
    datasets = node.get("dataset_bindings", {})
    if not isinstance(datasets, dict) or len(datasets) > 10000:
        raise ConfigurationError("Invalid local dataset approval map")
    def approved_dataset(assignment, binding_id, participant_id):
        item = datasets.get(binding_id)
        participant = next((p for p in assignment.job_spec.participants
                            if p.participant_id == participant_id), None)
        if (not isinstance(item, dict) or participant is None
                or participant.dataset_binding != binding_id
                or assignment.component.role != "participant"
                or assignment.component.participant_id != participant_id
                or item.get("project_id") != assignment.job_spec.project_id
                or item.get("participant_id") != participant_id):
            raise ExecutorRefused("Dataset differs from this participant assignment", "dataset_not_approved")
        _keys(item, {"kind", "project_id", "participant_id"}, {"host_path"})
        if item["kind"] == "synthetic" and "host_path" not in item:
            return {"kind": "synthetic"}
        if item["kind"] != "npz" or "host_path" not in item:
            raise ExecutorRefused("Dataset format is not locally approved", "dataset_not_approved")
        path = Path(item["host_path"])
        if not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents)):
            raise ExecutorRefused("Dataset path is not a local trusted file", "unsafe_dataset")
        information = path.lstat()
        if not stat.S_ISREG(information.st_mode) or information.st_nlink != 1:
            raise ExecutorRefused("Dataset must be a regular singly named file", "unsafe_dataset")
        return path
    def dataset_authorizer(binding_id, identity, participant_id):
        return approved_dataset(materializer_ref["value"].assignment(identity), binding_id, participant_id)
    def runtime_datasets(assignment):
        participant_id = assignment.component.participant_id
        if participant_id is None:
            return {}
        participant = next(p for p in assignment.job_spec.participants if p.participant_id == participant_id)
        result = approved_dataset(assignment, participant.dataset_binding, participant_id)
        return {participant.dataset_binding: (result if isinstance(result, dict)
                else {"kind": "npz", "path": "/job/data/data.npz"})}
    executor = LinuxExecutor(executor_config["profile_path"], root, dataset_authorizer=dataset_authorizer)
    capacity = node["capacity"]
    _keys(capacity, {"cpu_millicores", "memory_bytes", "disk_bytes"}, {"pids", "io_bps"})
    resources = ResourceLimits(_integer(capacity["cpu_millicores"], 1),
        _integer(capacity["memory_bytes"], 1), _integer(capacity["disk_bytes"], 32 * 1024**2),
        pids=_integer(capacity.get("pids", 128), 1, 65536),
        io_bps=_integer(capacity.get("io_bps", 16 * 1024**2), 1))
    ledger = Path(node["ledger_path"])
    if not ledger.is_absolute() or (ledger != root and root not in ledger.parents):
        raise ConfigurationError("Managed node ledger must belong to its private executor root")
    private_root(ledger.parent)
    if ledger.exists() or ledger.is_symlink():
        with SafeCollector(ledger.parent):
            information = ledger.lstat()
            if (not stat.S_ISREG(information.st_mode) or information.st_nlink != 1
                    or information.st_uid != os.geteuid() or information.st_mode & 0o077):
                raise ConfigurationError("Managed node ledger is unsafe")
    agent = NodeAgent(executor, ledger, node["node_id"], node["pool_id"], resources)
    client = None
    supervisor = None
    try:
        broker = WorkloadBroker(settings.broker)
        client = NodeCredentialClient(NodeEndpoint(node["node_id"], node["manager_endpoint"],
            node["manager_ca_file"], node["identity_certificate"], node["identity_key"]))
        local_secrets = LocalNodeSecrets(root / "private-secrets", node.get("secret_refs", {}))
        def token_provider(binding, participant_id, audience):
            identity = ExecutionIdentity(binding.job_id, binding.attempt_id, binding.component_id, binding.epoch)
            return client.credentials(identity, binding.certificate_thumbprint, audience)
        provider = NodeCertificateProvider(client, workload_issuer=settings.broker.workload_issuer,
                                           assignment_lookup=lambda identity: materializer_ref["value"].assignment(identity))
        socket_root = Path(node.get("proxy_socket_root", str(executor.owned_root)))
        if not socket_root.is_absolute() or socket_root != executor.owned_root:
            raise ConfigurationError("Node proxy socket root must exactly match the qualified profile")
        private_root(socket_root)
        supervisor = ProxySupervisor(root / "private-proxies",
            client_ca_certificate=node["execution_ca_certificate"], client_ca_key=None, broker=broker,
            exchange_endpoint=node["exchange_endpoint"], gateway_endpoint=node["gateway_endpoint"],
            service_ca_file=node["service_ca_file"], grant_lookup=None, socket_root=socket_root,
            token_provider=token_provider, certificate_provider=provider)
        def execution_binding(assignment, space, principal):
            import socket
            identity = assignment.identity
            observation = agent.inspect(identity)
            if not observation.termination_confirmed and observation.state in {
                    "RUNNING", "STARTING", "UNKNOWN", "QUARANTINED"}:
                endpoint = Path(supervisor.endpoint(identity))
                try:
                    if not stat.S_ISSOCK(endpoint.lstat().st_mode):
                        raise OSError()
                    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    try:
                        connection.settimeout(1)
                        connection.connect(str(endpoint))
                    finally:
                        connection.close()
                except OSError:
                    raise ExecutorRefused("Running execution proxy must be fenced before recreation",
                                          "proxy_restart_required") from None
            return supervisor.binding(
                SimpleNamespace(id=identity.job_id, deadline_at=assignment.deadline),
                SimpleNamespace(id=identity.attempt_id, job_id=identity.job_id, epoch=identity.epoch),
                assignment.component, space, principal)
        def build_preparer(assignment, configuration):
            approval = node.get("build_inputs", {}).get(assignment.component.component_id)
            if (not isinstance(approval, dict) or set(approval) - {"approved_dependencies", "project_subdir"}
                    or dict(configuration.approved_dependencies) != approval.get("approved_dependencies")
                    or configuration.project_subdir != approval.get("project_subdir", ".")
                    or configuration.source_dir != "/job/source" or configuration.state_dir != "/job/state"):
                raise ExecutorRefused("Offline build dependencies are not locally approved", "build_not_approved")
        registry = load_node_catalog(_node_document(node["registry_file"]))
        materializer = RemoteNodeMaterializer(root / "private-inputs", registry,
            node_id=node["node_id"], pool_id=node["pool_id"], proxy_endpoint=supervisor.endpoint,
            execution_bindings=execution_binding, dataset_bindings=runtime_datasets,
            secret_planner=local_secrets.planned, secret_materializer=local_secrets.materialize,
            build_preparer=build_preparer, auxiliary_reserver=agent.charge_auxiliary_bytes,
            require_source_limits=True, shared_auxiliary_reserver=agent.charge_shared_auxiliary_bytes)
        materializer.workload_issuer = settings.broker.workload_issuer
        materializer_ref["value"] = materializer
        manager_thumbprint = node["manager_certificate_thumbprint"]
        from .broker import _thumbprint
        _thumbprint(manager_thumbprint)
        registration_id = validate_identifier(node["registration_id"])
        def authenticate(request, scope):
            peer = request.scope.get("state", {}).get("verified_certificate_thumbprint")
            if not isinstance(peer, str) or not hmac.compare_digest(peer, manager_thumbprint):
                raise HTTPException(403, "Registered manager certificate required")
            try:
                return broker.authenticate_node(request.headers.get("authorization", ""),
                    verified_peer_thumbprint=peer, grant_validator=client.validate)
            except BrokerError as error:
                raise HTTPException(error.status, error.code) from None
        def qualify_authenticate(request):
            peer = request.scope.get("state", {}).get("verified_certificate_thumbprint")
            if not isinstance(peer, str) or not hmac.compare_digest(peer, manager_thumbprint):
                raise HTTPException(403, "Registered manager certificate required")
            try:
                return broker.authenticate_node_platform(request.headers.get("authorization", ""),
                    verified_peer_thumbprint=peer,
                    registration_validator=lambda principal: (
                        principal.node_id, principal.pool_id, principal.registration_id,
                        principal.certificate_thumbprint) == (
                            node["node_id"], node["pool_id"], registration_id, manager_thumbprint))
            except BrokerError as error:
                raise HTTPException(error.status, error.code) from None
        def proxy_alive(identity):
            from cryptography import x509
            from cryptography.hazmat.primitives.serialization import Encoding
            from .gateway import certificate_thumbprint
            from .execution_proxy import ExecutionBinding, _private_proxy_operation
            directory = supervisor.root / identity.job_id / "attempts" / identity.attempt_id / identity.component_id
            try:
                with SafeCollector(directory, max_file_bytes=65536, max_total_bytes=256 * 1024) as collector:
                    metadata = json.loads(collector.read("proxy-identity.json"))
                    certificate = x509.load_pem_x509_certificate(collector.read("proxy-cert.pem"))
            except CollectionError as error:
                cause = error
                while cause.__cause__ is not None:
                    cause = cause.__cause__
                if isinstance(cause, FileNotFoundError):
                    return False
                raise
            if any(metadata.get(key) != value for key, value in asdict(identity).items()):
                raise ExecutorRefused("Proxy liveness identity differs", "missing_proxy")
            binding = ExecutionBinding(**metadata, certificate_thumbprint=certificate_thumbprint(
                certificate.public_bytes(Encoding.DER)))
            try:
                return _private_proxy_operation(supervisor.endpoint(identity), binding, "status")["running"]
            except (FileNotFoundError, ConnectionRefusedError):
                return False
        def stop_private(identity):
            try:
                terminated = agent.inspect(identity).termination_confirmed
            except ExecutorRefused as error:
                if error.code != "stale_epoch":
                    raise
                terminated = agent.component_purge_allowed(identity)
            if not terminated:
                raise ExecutorRefused("Proxy stop requires confirmed runtime termination", "runtime_active")
            return supervisor.stop(identity.job_id, identity.attempt_id, identity.component_id,
                                   termination_confirmed=True)
        def purge_private(identity):
            if not stop_private(identity):
                return False
            secrets_root = local_secrets.resolver._path(asdict(identity)).parent
            if supervisor.purge(identity, termination_confirmed=True) is not True:
                return False
            return purge_private_tree(secrets_root)
        app = create_remote_node_app(agent, authenticate, materializer,
            qualify_authenticate=qualify_authenticate, registration_id=registration_id,
            manager_certificate_thumbprint=manager_thumbprint,
            stop_callback=stop_private, purge_callback=purge_private,
            proxy_alive_callback=proxy_alive)
        return ManagedNodeService(agent, materializer, supervisor, client, app)
    except BaseException:
        if supervisor:
            supervisor.close()
        if client:
            client.close()
        agent.close()
        raise


def serve_node(settings, arguments):
    """Serve the isolated managed node using an actual verified-mTLS adapter."""
    import signal
    from .composition import section, _keys
    from .execution_proxy import start_mtls_server
    service = compose_node(settings)
    configuration = section(settings, "service", required=False) or section(settings, "node")["service"]
    _keys(configuration, {"certificate", "key", "client_ca"}, {"host", "port"})
    stopped = threading.Event()
    previous = {}
    try:
        service.server = start_mtls_server(service.app,
            host=getattr(arguments, "host", None) or configuration.get("host", "127.0.0.1"),
            port=getattr(arguments, "port", None) or configuration.get("port", 9444),
            certificate=configuration["certificate"], key=configuration["key"],
            client_ca=configuration["client_ca"], max_request_bytes=4 * 1024**2)
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, lambda *_: stopped.set())
        while not stopped.wait(0.5):
            if not service.server.thread.is_alive():
                raise UncertainExecution("Managed node TLS listener stopped")
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        service.close()


def purge_private_tree(root, *, max_files=100000, max_total_bytes=1024**3,
                       max_entries=200000, max_depth=32):
    """Delete one component-owned tree without following links or trusting archives."""
    import stat
    path = Path(root)
    if not path.is_absolute() or path == Path("/") or ".." in path.parts:
        raise ExecutorRefused("Invalid component purge authority", "unsafe_output")
    try:
        collector = SafeCollector(path, max_files=max_files, max_entries=max_entries,
            max_depth=max_depth, max_file_bytes=max_total_bytes, max_total_bytes=max_total_bytes)
    except CollectionError as error:
        cause = error
        while cause.__cause__ is not None:
            cause = cause.__cause__
        if isinstance(cause, FileNotFoundError):
            return True
        raise
    with collector:
        descriptor = collector._root_fd
        authority = os.fstat(descriptor)
        if authority.st_uid != os.geteuid() or authority.st_mode & 0o077:
            raise ExecutorRefused("Component purge root must be private and owned", "unsafe_output")
        manifest = collector.collect()
        files = {item.path: item for item in manifest}
        identities, directories = {}, {}
        count = 0
        def inventory(current, prefix):
            nonlocal count
            with os.scandir(current) as entries:
                for entry in entries:
                    count += 1
                    if count > max_entries or len(prefix) >= max_depth:
                        raise ExecutorRefused("Component purge inventory exceeds bound", "unsafe_output")
                    relative = "/".join((*prefix, entry.name))
                    info = os.stat(entry.name, dir_fd=current, follow_symlinks=False)
                    if info.st_uid != os.geteuid() or info.st_dev != authority.st_dev:
                        raise ExecutorRefused("Component purge crosses ownership/device", "unsafe_output")
                    if stat.S_ISDIR(info.st_mode):
                        if info.st_mode & 0o022:
                            raise ExecutorRefused("Component purge directory is not operator owned", "unsafe_output")
                        child = collector._directory(entry.name, current)
                        try:
                            directories[relative] = (info.st_dev, info.st_ino)
                            inventory(child, (*prefix, entry.name))
                        finally:
                            os.close(child)
                    else:
                        collector._validate_file(info)
                        if relative not in files:
                            raise ExecutorRefused("Component purge file inventory changed", "unsafe_output")
                        identities[relative] = (info.st_dev, info.st_ino)
        inventory(descriptor, ())
        if set(identities) != set(files):
            raise ExecutorRefused("Component purge manifest changed", "unsafe_output")
        def parent(relative):
            parts = relative.split("/")
            result = os.dup(descriptor)
            try:
                for part in parts[:-1]:
                    child = collector._directory(part, result)
                    os.close(result)
                    result = child
                return result, parts[-1]
            except BaseException:
                os.close(result)
                raise
        # All roots are validated before permissions change or deletion begins.
        os.fchmod(descriptor, 0o700)
        for name, identity in sorted(directories.items(), key=lambda item: item[0].count("/")):
            owner, leaf = parent(name)
            try:
                child = collector._directory(leaf, owner)
                try:
                    info = os.fstat(child)
                    if (info.st_dev, info.st_ino) != identity:
                        raise ExecutorRefused("Component purge directory changed", "unsafe_output")
                    os.fchmod(child, 0o700)
                finally:
                    os.close(child)
            finally:
                os.close(owner)
        for name, item in files.items():
            owner, leaf = parent(name)
            try:
                data = collector._read_file(leaf, owner, max_total_bytes)
                info = os.stat(leaf, dir_fd=owner, follow_symlinks=False)
                collector._validate_file(info)
                if ((info.st_dev, info.st_ino) != identities[name] or len(data) != item.size_bytes
                        or hashlib.sha256(data).hexdigest() != item.sha256):
                    raise ExecutorRefused("Component purge file changed", "unsafe_output")
                os.unlink(leaf, dir_fd=owner)
                os.fsync(owner)
            finally:
                os.close(owner)
        for name, identity in sorted(directories.items(), key=lambda item: -item[0].count("/")):
            owner, leaf = parent(name)
            try:
                info = os.stat(leaf, dir_fd=owner, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != identity:
                    raise ExecutorRefused("Component purge directory changed", "unsafe_output")
                os.rmdir(leaf, dir_fd=owner)
                os.fsync(owner)
            finally:
                os.close(owner)
        with SafeCollector(path.parent) as parent_collector:
            parent_fd = parent_collector._root_fd
            info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != (authority.st_dev, authority.st_ino):
                raise ExecutorRefused("Component purge authority changed", "unsafe_output")
            os.rmdir(path.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
    return True
