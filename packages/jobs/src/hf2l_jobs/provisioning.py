"""Idempotent job resources; no plugin import, checkpoint load or build runs here."""
from __future__ import annotations

from datetime import timedelta
import hashlib
import json
from pathlib import Path
import stat
import tempfile
from typing import Callable, Mapping, Any
from urllib.parse import quote

from .domain import JobSpec, canonical_json, utcnow
from .broker import stable_workload_subject, stable_workload_principal
from .executor import ExecutionIdentity, ExecutionSpec, ResourceLimits
from .reconciliation import PublicationObservation
from .resources import (ComponentPaths, OwnedDirectories, ResourceBundle, ResourceError,
                        ResourceLedger, atomic_json, stable_key)
from .source import RegistryCatalog, metadata_peak_bytes, git_peak_bytes, source_physical_bytes


def value(item, name, default=None):
    return item.get(name, default) if isinstance(item, Mapping) else getattr(item, name, default)


def job_spec(job) -> JobSpec:
    raw = value(job, "spec_json", value(job, "spec"))
    return raw if isinstance(raw, JobSpec) else JobSpec.model_validate(raw)


class Provisioner:
    def __init__(self, database, exchange, registry: RegistryCatalog, root: Path | str, *,
                 workload_issuer: str, execution_bindings: Callable | None = None,
                 publication_observer: Callable | None = None, worker_spec_builder: Callable | None = None,
                 proxy_endpoint: Callable | None = None, secret_resolver=None, build_approvals: Mapping[str, Any] | None = None,
                 artifact_reader: Callable | None = None, external_cleanup: Callable | None = None,
                 storage_pool_id: str | None = None, auxiliary_storage: Callable | None = None,
                 remote_auxiliary_cleanup: Callable | None = None, exchange_storage_pool_id: str | None = None):
        if not workload_issuer:
            raise ResourceError("Explicit managed workload issuer is required")
        self.database, self.exchange, self.registry = database, exchange, registry
        self.root = Path(root)
        self.workload_issuer = workload_issuer
        self.execution_bindings = execution_bindings
        self.publication_observer = publication_observer
        self.worker_spec_builder = worker_spec_builder
        self.proxy_endpoint = proxy_endpoint
        self.secret_resolver = secret_resolver
        self.build_approvals = dict(build_approvals or {})
        self.artifact_reader = artifact_reader
        self.external_cleanup = external_cleanup
        if storage_pool_id is not None:
            from .domain import validate_identifier
            validate_identifier(storage_pool_id)
        self.storage_pool_id = storage_pool_id
        if exchange_storage_pool_id is not None:
            from .domain import validate_identifier
            validate_identifier(exchange_storage_pool_id)
            if exchange_storage_pool_id == storage_pool_id:
                raise ResourceError("Exchange objects require a separate approved storage pool")
        self.exchange_storage_pool_id = exchange_storage_pool_id
        self.auxiliary_storage = auxiliary_storage
        self.remote_auxiliary_cleanup = remote_auxiliary_cleanup
        self.ledger = ResourceLedger(database)

    def _identity(self, job, attempt):
        jid, aid = value(job, "id"), value(attempt, "id")
        if value(attempt, "job_id") != jid:
            raise ResourceError("Attempt belongs to another job")
        spec = job_spec(job)
        if value(job, "spec_hash", spec.digest) != spec.digest:
            raise ResourceError("Immutable specification digest changed")
        return jid, aid, spec

    def _subject(self, job_id: str, component_id: str, participant_id: str | None = None) -> str:
        return stable_workload_subject(job_id, component_id, participant_id)

    def principal(self, job_id: str, component_id: str, participant_id: str | None = None) -> str:
        return stable_workload_principal(self.workload_issuer, job_id, component_id, participant_id)

    @staticmethod
    def external_component(participant_id: str) -> str:
        return "participant-" + stable_key(participant_id)[:40]

    def _paths(self, jid, spec):
        job_path = self.root / jid
        return {c.component_id: ComponentPaths(job_path / "source", job_path / "components" / c.component_id / "state",
                    job_path / "components" / c.component_id / "state/cache",
                    job_path / "components" / c.component_id / "state/logs",
                    job_path / "components" / c.component_id / "state/artifacts") for c in spec.components}

    def _proxy_endpoint(self, identity):
        if self.proxy_endpoint is not None:
            return str(self.proxy_endpoint(identity))
        return str(self.root / identity.job_id / "attempts" / identity.attempt_id / identity.component_id / "proxy.sock")

    def _specs(self, job, attempt, spec, image, paths, bindings=None, configs=None):
        jid, aid = value(job, "id"), value(attempt, "id")
        deadline = value(job, "deadline_at")
        result = {}
        for component in spec.components:
            identity = ExecutionIdentity(jid, aid, component.component_id, value(attempt, "epoch"))
            limits = ResourceLimits(component.resources.cpu_millicores, component.resources.memory_bytes,
                                    component.resources.disk_bytes, gpus=component.resources.gpu_count)
            if component.role == "build" and self.worker_spec_builder is not None:
                result[component.component_id] = self.worker_spec_builder(job, attempt, component, paths[component.component_id])
                continue
            if component.role == "build" and not self.build_approvals.get(component.component_id):
                raise ResourceError("An approved offline build configuration is not registered")
            binding = (bindings or {}).get(component.component_id, {})
            proxy = None if component.role == "build" else binding.get("proxy_endpoint", self._proxy_endpoint(identity))
            planned_secrets = self.secret_resolver.planned(job, attempt, component) if self.secret_resolver is not None else None
            dataset = next((p.dataset_binding for p in spec.participants if p.participant_id == component.participant_id), None)
            result[component.component_id] = ExecutionSpec(identity=identity, image_digest=image,
                source_path=str(paths[component.component_id].source), state_path=str(paths[component.component_id].state),
                argv=("python", "-m", "hf2l_jobs.runtime", "--config", "/run/hf2l/runtime.json"),
                proxy_endpoint=proxy, resources=limits, pool_id=component.resources.pool_id,
                deadline=deadline.timestamp() if deadline else None,
                config_path=(configs or {}).get(component.component_id, str(self.root / jid / "attempts" / aid / component.component_id / "runtime.json")),
                profile=component.resources.sandbox_profile, role="build" if component.role == "build" else "client" if component.role == "participant" else "owner",
                secret_path=str(planned_secrets.privatepath) if planned_secrets and planned_secrets.privatepath else None,
                dataset_binding_id=dataset, participant_id=component.participant_id,
                build_input_path=str(self.root / jid / "build-products") if component.role != "build" and any(c.role == "build" for c in spec.components) else None)
        return result

    def _storage_pool(self, spec):
        return self.storage_pool_id or next(c.resources.pool_id for c in spec.components if c.role == "owner")

    @staticmethod
    def _build_storage_cap(spec):
        builders = [component for component in spec.components if component.role == "build"]
        raw_cap = min(256 * 1024**2, sum(component.resources.disk_bytes for component in builders))
        # File block rounding plus products/staging directory entries are physical bytes.
        return raw_cap + 8192 * (len(builders) + 4)

    def admission_storage(self, job) -> list[dict]:
        """Plan conservative owned raw-copy budgets without creating resources."""
        spec = job_spec(job)
        jid = value(job, "id")
        if value(job, "spec_hash", spec.digest) != spec.digest:
            raise ResourceError("Immutable storage specification digest changed")
        current = self.registry.refreshed()
        approval = current.source_registry.authorize(spec.project_id, spec.source_id, spec.source_commit)
        owner = next(component for component in spec.components if component.role == "owner")
        existing = {(row["kind"], row["external_id"]): row for row in self.ledger.resources(jid)
                    if row["state"] != "deleted"}
        source_row = existing.get(("source", str(self.root / jid / "source")))
        complete_source = bool(source_row and source_row["details"].get("retention_charge_settled"))
        budgets = [("source", self.root / jid / "source", approval.max_bytes + metadata_peak_bytes(approval),
                    {"source_id": spec.source_id, "commit": spec.source_commit})]
        if not complete_source:
            budgets.append(("source_fetch_workspace", self.root / jid / "source-fetch" / str(max(1, value(job, "current_attempt", 1))),
                            git_peak_bytes(approval), {"source_id": spec.source_id, "commit": spec.source_commit}))
        builders = [component for component in spec.components if component.role == "build"]
        if builders:
            budgets.append(("build_products", self.root / jid / "build-products",
                            self._build_storage_cap(spec), {}))
        result = []
        for kind, path, maximum, details in budgets:
            row = existing.get((kind, str(path)))
            if row is not None:
                if row["ownership"] != {"job_id": jid, "component_id": owner.component_id, "kind": kind}:
                    raise ResourceError("Admission storage resource belongs to another job")
                if "retention_charged_bytes" in row["details"] and not row["details"].get("retention_charge_released"):
                    continue
            result.append({"kind": kind, "external_id": str(path), "component_id": owner.component_id,
                "pool_id": self._storage_pool(spec), "max_bytes": maximum,
                "details": {**details, "spec_digest": spec.digest, "pool_id": self._storage_pool(spec),
                            "reservation_max_bytes": maximum}})
        attempt_number = max(1, value(job, "current_attempt", 1))
        for component in spec.components:
            external_id = "hf2l-collection://" + jid + "/" + str(attempt_number) + "/" + component.component_id
            row = existing.get(("collection_budget", external_id))
            ownership = {"job_id": jid, "component_id": component.component_id, "kind": "collection_budget"}
            if row is not None:
                if row["ownership"] != ownership:
                    raise ResourceError("Admission collection resource belongs to another job")
                if "retention_charged_bytes" in row["details"] and not row["details"].get("retention_charge_released"):
                    continue
            maximum = component.resources.disk_bytes + 4 * 1024**2
            result.append({"kind": "collection_budget", "external_id": external_id,
                "component_id": component.component_id, "pool_id": component.resources.pool_id, "max_bytes": maximum,
                "details": {"spec_digest": spec.digest, "pool_id": component.resources.pool_id,
                            "component_id": component.component_id, "attempt_number": attempt_number,
                            "reservation_max_bytes": maximum}})
        log_components = [component.component_id for component in spec.components]
        log_components.extend(self.external_component(participant.participant_id)
                              for participant in spec.participants if participant.mode == "external")
        for component_id in log_components:
            external_id = "hf2l-log://" + jid + "/" + str(attempt_number) + "/" + component_id
            row = existing.get(("log_budget", external_id))
            ownership = {"job_id": jid, "component_id": component_id, "kind": "log_budget"}
            if row is not None:
                if row["ownership"] != ownership:
                    raise ResourceError("Admission log resource belongs to another job")
                if "retention_charged_bytes" in row["details"] and not row["details"].get("retention_charge_released"):
                    continue
            maximum = 1024**2
            result.append({"kind": "log_budget", "external_id": external_id,
                "component_id": component_id, "pool_id": self._storage_pool(spec), "max_bytes": maximum,
                "details": {"spec_digest": spec.digest, "pool_id": self._storage_pool(spec),
                            "component_id": component_id, "attempt_number": attempt_number,
                            "reservation_max_bytes": maximum}})
        for component in spec.components:
            external_id = "hf2l-state://" + jid + "/" + str(attempt_number) + "/" + component.component_id
            row = existing.get(("execution_state", external_id))
            ownership = {"job_id": jid, "component_id": component.component_id, "kind": "execution_state"}
            if row is not None:
                if row["ownership"] != ownership:
                    raise ResourceError("Admission execution state belongs to another job")
                if "retention_charged_bytes" in row["details"] and not row["details"].get("retention_charge_released"):
                    continue
            maximum = component.resources.disk_bytes
            result.append({"kind": "execution_state", "external_id": external_id,
                "component_id": component.component_id, "pool_id": component.resources.pool_id, "max_bytes": maximum,
                "covered_by_allocation": True,
                "details": {"spec_digest": spec.digest, "pool_id": component.resources.pool_id,
                            "component_id": component.component_id, "attempt_number": attempt_number,
                            "covered_by_allocation": True, "reservation_max_bytes": maximum}})
        from .blob_budget import plan_blob_budget
        blob_plan = plan_blob_budget(job, self.exchange_storage_pool_id, self.ledger.resources(jid, kind="exchange_blob_budget"))
        if blob_plan["pool_id"] == self._storage_pool(spec) or blob_plan["pool_id"] in {
                component.resources.pool_id for component in spec.components}:
            raise ResourceError("Exchange objects require a separate approved storage pool")
        result.append(blob_plan)
        if self.auxiliary_storage is not None:
            result.extend(self.auxiliary_storage(job))
        return result

    def plan(self, job, attempt, *, remaining_rounds=None) -> ResourceBundle:
        """Create reservation specifications without filesystem/network side effects."""
        jid, aid, spec = self._identity(job, attempt)
        image = self.registry.validate(spec)
        if spec.secret_refs:
            if self.secret_resolver is None:
                raise ResourceError("Runtime secret delivery is not configured")
            self.secret_resolver.validate_spec(spec)
        paths = self._paths(jid, spec)
        principals = {c.component_id: self.principal(jid, c.component_id, c.participant_id) for c in spec.components}
        return ResourceBundle(jid, aid, "", self.root / jid / "source", {}, image, principals,
                              paths, self._specs(job, attempt, spec, image, paths))

    def _run(self, jid, aid, component, operation, desired, action, *, attempt_scoped=False):
        key = stable_key("hf2l", jid, aid if attempt_scoped else "", component, operation)
        return self.ledger.run(job_id=jid, attempt_id=aid, component_id=component, operation=operation,
                               key=key, desired=desired, action=lambda: action(key))

    @staticmethod
    def _write_worker_config(path, configuration):
        # Match prepared_component's fixed transport bound before any private
        # file write; avoid constructing a second unbounded serialized payload.
        encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        size = 0
        for chunk in encoder.iterencode(configuration):
            size += len(chunk.encode("utf-8"))
            if size > 2 * 1024**2:
                raise ResourceError("Worker configuration exceeds the approved 2 MiB bound")
        atomic_json(path, configuration, mode=0o400)

    @staticmethod
    def _manifest(path: Path) -> dict[str, str]:
        result = {}
        if path.is_symlink() or not path.is_dir():
            raise ResourceError("Source snapshot is missing or unsafe")
        for item in sorted(path.rglob("*")):
            mode = item.lstat().st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                raise ResourceError("Snapshot contains an unsafe source file")
            if stat.S_ISREG(mode):
                digest = hashlib.sha256()
                with item.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(64 * 1024), b""):
                        digest.update(chunk)
                result[item.relative_to(path).as_posix()] = digest.hexdigest()
        return result

    def _source(self, jid, aid, spec, directories):
        root = directories.validate_job(jid, spec.digest)
        source = root / "source"
        metadata = root / ".source.json"
        desired = {"source_id": spec.source_id, "commit": spec.source_commit, "path": str(source)}
        approved = self.registry.refreshed().source_registry.authorize(spec.project_id, spec.source_id, spec.source_commit)
        owner = next(component for component in spec.components if component.role == "owner")
        resource_id = self.ledger.own(job_id=jid, attempt_id=aid, component_id=owner.component_id, kind="source",
            external_id=str(source), details={"source_id": spec.source_id, "commit": spec.source_commit,
                "pool_id": self._storage_pool(spec), "reservation_max_bytes": approved.max_bytes + metadata_peak_bytes(approved),
                "spec_digest": spec.digest}, retained=True)
        from .retention import RetentionService
        retention = RetentionService(self.database)
        # Quota is reserved before Git fetch/extraction can retain raw source.
        # Interrupted extraction stays charged until owned cleanup is confirmed.
        retention.reserve_resource(resource_id, jid, approved.max_bytes + metadata_peak_bytes(approved))
        workspace, workspace_id = None, None
        if not source.exists():
            from .models import Attempt
            with self.database.transaction(immediate=False) as session:
                owned_attempt = session.get(Attempt, aid)
                if owned_attempt is None or owned_attempt.job_id != jid:
                    raise ResourceError("Source workspace attempt belongs to another job")
                attempt_number = owned_attempt.number
            workspace = root / "source-fetch" / str(attempt_number)
            workspace_id = self.ledger.own(job_id=jid, attempt_id=aid, component_id=owner.component_id,
                kind="source_fetch_workspace", external_id=str(workspace), retained=True,
                details={"pool_id": self._storage_pool(spec), "spec_digest": spec.digest,
                         "reservation_max_bytes": git_peak_bytes(approved)})
            retention.reserve_resource(workspace_id, jid, git_peak_bytes(approved))
            for directory in (root / "source-fetch", workspace):
                if directory.is_symlink():
                    raise ResourceError("Source workspace parent is unsafe")
                directory.mkdir(mode=0o700, exist_ok=True)
        def action(_):
            current_registry = self.registry.refreshed()
            current_registry.validate(spec)
            if source.exists():
                if not metadata.is_file() or metadata.is_symlink():
                    raise ResourceError("Existing snapshot has no trusted manifest")
                document = json.loads(metadata.read_text())
                if any(document.get(key) != desired[key] for key in ("source_id", "commit")):
                    raise ResourceError("Existing source belongs to another commit")
                if self._manifest(source) != document["manifest"]:
                    raise ResourceError("Existing source differs from its verified manifest")
                return document
            stage = root / ("source-stage-" + stable_key(jid, spec.source_commit)[:16])
            if stage.exists():
                # A prior successful extraction is adopted only with the original manifest.
                if not metadata.is_file() or self._manifest(stage) != json.loads(metadata.read_text())["manifest"]:
                    raise ResourceError("Interrupted source extraction requires reconciliation")
                document = json.loads(metadata.read_text())
            else:
                snapshot = current_registry.source_registry.materialize(spec.project_id, spec.source_id, spec.source_commit, stage,
                                                                        workspace_parent=workspace)
                document = {**desired, "manifest": dict(snapshot.manifest), "digest": snapshot.digest, "bytes": snapshot.bytes}
                atomic_json(metadata, document)
            stage.chmod(0o700)
            stage.rename(source)
            source.chmod(0o555)
            return document
        try:
            document = self._run(jid, aid, owner.component_id, "source", desired, action)
        finally:
            if workspace is not None and workspace.exists() and not workspace.is_symlink() and not any(workspace.iterdir()):
                workspace.rmdir()
                if not any(workspace.parent.iterdir()):
                    workspace.parent.rmdir()
                self.ledger.deleted(workspace_id, jid)
                retention.confirm_resource_deleted(workspace_id, jid)
        if self._manifest(source) != document["manifest"]:
            raise ResourceError("Snapshot changed after provisioning")
        physical_bytes = source_physical_bytes(source, approved)
        for metadata_file in (metadata, root / ".owner.json"):
            info = metadata_file.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ResourceError("Source ownership metadata is unsafe")
            physical_bytes += info.st_blocks * 512
        physical_bytes += root.lstat().st_blocks * 512
        retention.settle_resource(resource_id, jid, physical_bytes)
        from .models import ProvisioningResource
        with self.database.transaction() as session:
            resource = session.get(ProvisioningResource, resource_id)
            if resource.job_id != jid or resource.ownership_json.get("job_id") != jid:
                raise ResourceError("Source accounting resource belongs to another job")
            if resource.details_json.get("sha256") not in (None, document["digest"]):
                raise ResourceError("Immutable source resource digest changed")
            resource.details_json = {**resource.details_json, "sha256": document["digest"],
                                     "size_bytes": document["bytes"], "logical_bytes": document["bytes"]}
            resource.state = "ready"
            resource.updated_at = utcnow()
            from .source_artifacts import publish_source_artifacts
            publish_source_artifacts(session, job_id=jid, resource_id=resource_id, job_root=root,
                manifest=document["manifest"], expected_digest=document["digest"],
                max_files=approved.max_files, max_bytes=approved.max_bytes)
        return document

    def owned_space(self, job_id):
        """Return only a ledger-owned job space, without accepting user space IDs."""
        return self._space_id(job_id)

    def _space_id(self, jid):
        resources = self.ledger.resources(jid, kind="exchange_space")
        live = [row for row in resources if row["state"] != "deleted"]
        if len(live) > 1:
            raise ResourceError("Job owns multiple unexpected Exchange spaces")
        return live[0]["external_id"] if live else None

    def _provision_space(self, job, attempt_id, *, for_cleanup=False):
        """Adopt only the original idempotent namespace with its actual paid limits."""
        from .blob_budget import require_blob_budget, bind_blob_space
        jid = value(job, "id")
        prepaid = require_blob_budget(self.database, job, for_cleanup=for_cleanup)
        desired = {"name": "hf2l-" + jid, "profile": "fedavg.v1",
                   "quota_bytes": prepaid["quota_bytes"],
                   "principal_quota_bytes": prepaid["principal_quota_bytes"]}
        def create(key):
            current = require_blob_budget(self.database, job, for_cleanup=for_cleanup)
            if any(current[name] != desired[name] for name in ("quota_bytes", "principal_quota_bytes")):
                raise ResourceError("Namespace allowance changed before creation")
            descriptor = self.exchange.create_space(desired["name"], profile=desired["profile"],
                quota_bytes=desired["quota_bytes"], principal_quota_bytes=desired["principal_quota_bytes"],
                idempotency_key=key)
            return {"space_id": descriptor.id}
        document = self._run(jid, attempt_id, "owner", "exchange_space", desired, create)
        space = document["space_id"]
        self.ledger.own(job_id=jid, attempt_id=attempt_id, component_id="owner", kind="exchange_space",
            external_id=space, details={"job_id": jid, "profile": "fedavg.v1"}, retained=True)
        # Cached/lost acknowledgements never substitute for actual server policy.
        policy = self.exchange.get_space(space)
        bind_blob_space(self.database, job, space, space_policy=policy, for_cleanup=for_cleanup)
        managed = self._run(jid, attempt_id, "owner", "managed_space", {"space_id": space, "job_id": jid},
            lambda key: self.exchange.request("PUT", self.exchange.path(space, "/managed"),
                body={"job_id": jid}, headers={"Idempotency-Key": key}))
        if managed.get("space_id") != space or managed.get("job_id") != jid:
            raise ResourceError("Managed namespace receipt belongs to another job or space")
        return space

    def ensure(self, job, attempt, *, remaining_rounds=None) -> ResourceBundle:
        """Provision resources after transactional gang reservation/acknowledgement."""
        jid, aid, spec = self._identity(job, attempt)
        from .blob_budget import require_blob_budget
        require_blob_budget(self.database, job)
        image = self.registry.validate(spec)
        directories = OwnedDirectories(self.root)
        job_path = directories.ensure_job(jid, spec.digest)
        self.ledger.own(job_id=jid, attempt_id=aid, component_id="owner", kind="job_directory",
                        external_id=str(job_path), details={"spec_digest": spec.digest}, retained=True)
        source = self._source(jid, aid, spec, directories)
        paths = directories.components(jid, [c.component_id for c in spec.components])
        for cid, component_path in paths.items():
            self.ledger.own(job_id=jid, attempt_id=aid, component_id=cid, kind="component_state",
                            external_id=str(component_path.state), details={"spec_digest": spec.digest}, retained=True)
        space = self._provision_space(job, aid)
        schemas = {
            "model.global": {"type": "object", "properties": {"hf2l_files": {"type": "object"},
                "inputs": {"type": "array"}, "base_record_id": {"type": "string"}}, "required": ["hf2l_files", "inputs"]},
            "training.update": {"type": "object", "properties": {"hf2l_files": {"type": "object"},
                "sample_count": {"type": "integer"}, "base_record_id": {"type": "string"}},
                "required": ["hf2l_files", "sample_count", "base_record_id"]},
        }
        for kind, schema in schemas.items():
            self._run(jid, aid, "owner", "type_" + kind, {"space_id": space, "kind": kind, "schema": schema},
                lambda key, kind=kind, schema=schema: {"revision_id": self.exchange.register_type(space, kind, schema, idempotency_key=key).id})
        principals, participants = {}, {}
        member_specs = [(c.component_id, c.role, c.participant_id) for c in spec.components if c.role != "build"]
        for participant in spec.participants:
            if participant.mode == "external":
                member_specs.append((self.external_component(participant.participant_id), "participant", participant.participant_id))
        for component_id, role, participant_id in member_specs:
            principal = self.principal(jid, component_id, participant_id)
            principals[component_id] = principal
            roles = ["reader", "contributor", "publisher"] if role == "owner" else ["reader", "contributor"]
            bindings = {"participant": participant_id} if participant_id else {}
            if participant_id:
                participants[participant_id] = principal
            desired = {"space_id": space, "principal_id": principal, "roles": roles, "bindings": bindings}
            self._run(jid, aid, component_id, "membership", desired,
                lambda key, p=principal, r=roles, b=bindings: {"principal_id": self.exchange.set_member(space, p, r, bindings=b).principal_id})
            self.ledger.own(job_id=jid, attempt_id=aid, component_id=component_id, kind="exchange_member",
                            external_id=space + ":" + principal, details=desired, retained=True)
        if self.execution_bindings is None:
            raise ResourceError("Certificate-bound execution proxy provisioning is not configured")
        grants, execution, configs = {}, {}, {}
        deadline = value(job, "deadline_at")
        expiry = (deadline or (value(attempt, "created_at", utcnow()) + timedelta(seconds=spec.max_duration_seconds))).timestamp()
        for component in spec.components:
            cid = component.component_id
            if component.role == "build":
                if self.worker_spec_builder is not None:
                    continue
                from .build import BuildConfig
                approval = self.build_approvals.get(cid)
                if (not isinstance(approval, Mapping) or not approval.get("approved_dependencies") or
                        set(approval) - {"approved_dependencies", "project_subdir"}):
                    raise ResourceError("Approved offline build inputs are unavailable or contain forbidden overrides")
                configuration = {"schema_version": 1, "role": "build", "job_id": jid, "attempt_id": aid,
                    "component_id": cid, "epoch": value(attempt, "epoch"), "spec": spec.to_dict(), "spec_digest": spec.digest,
                    "source_manifest": source["manifest"], "source_dir": "/job/source", "state_dir": "/job/state", **approval}
                BuildConfig.model_validate(configuration)
                config_parent = job_path / "attempts" / aid / cid
                config_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                config = config_parent / "runtime.json"
                self._write_worker_config(config, configuration)
                configs[cid] = str(config)
                self.ledger.own(job_id=jid, attempt_id=aid, component_id=cid, kind="runtime_config",
                    external_id=str(config), details={"spec_digest": spec.digest})
                continue
            binding = dict(self.execution_bindings(job, attempt, component, space, principals[cid]))
            expected_proxy = self._proxy_endpoint(ExecutionIdentity(jid, aid, cid, value(attempt, "epoch")))
            if binding.get("proxy_endpoint") != str(expected_proxy):
                raise ResourceError("Execution proxy differs from the acknowledged reservation")
            execution[cid] = binding
            thumbprint = binding.get("certificate_thumbprint", binding.get("cert_thumbprint"))
            if not thumbprint or not binding.get("proxy_endpoint"):
                raise ResourceError("Execution binding lacks a certificate or assigned proxy")
            body = {"subject": self._subject(jid, cid, component.participant_id), "job_id": jid, "attempt_id": aid, "component_id": cid,
                    "epoch": value(attempt, "epoch"), "expires_at": expiry, "certificate_thumbprint": thumbprint,
                    "roles": ["reader", "contributor", "publisher"] if component.role == "owner" else ["reader", "contributor"],
                    "bindings": {"participant": component.participant_id} if component.participant_id else {}}
            grant = self._run(jid, aid, cid, "workload_grant", {"space_id": space, **body},
                lambda key, body=body: self.exchange.request("POST", self.exchange.path(space, "/workload-grants"),
                                          body=body, headers={"Idempotency-Key": key}), attempt_scoped=True)
            if grant.get("principal_id") != principals[cid] or grant.get("space_id") != space:
                raise ResourceError("Grant returned a foreign principal or space")
            grants[cid] = grant
            self.ledger.own(job_id=jid, attempt_id=aid, component_id=cid, kind="workload_grant",
                            external_id=grant["grant_id"], details=dict(grant))
            configuration = {"schema_version": 1, "role": "owner" if component.role == "owner" else "client",
                 "job_id": jid, "attempt_id": aid, "component_id": cid, "space_id": space, "epoch": value(attempt, "epoch"),
                 "spec": spec.to_dict(), "spec_digest": spec.digest, "source_dir": "/job/source", "state_dir": "/job/state",
                 "exchange_endpoint": "http://proxy", "proxy_socket": "/run/hf2l/proxy.sock",
                 "source_manifest": source["manifest"], "participant_principals": participants,
                 "dataset_bindings": binding.get("dataset_bindings", {}),
                 "deadline_at": deadline.timestamp() if deadline else None,
                 "reconciliation": self._directives(jid, cid, value(attempt, "epoch"))}
            if self.secret_resolver is not None:
                delivered = self.secret_resolver.resolve(job, attempt, component)
                if delivered.privatepath:
                    configuration["secret_options_file"] = "/run/hf2l/secrets.json"
                    configuration["secret_option_names"] = list(delivered.option_names)
                    self.ledger.own(job_id=jid, attempt_id=aid, component_id=cid, kind="runtime_secret",
                        external_id=str(delivered.privatepath), details={"epoch": value(attempt, "epoch")})
            if component.participant_id:
                configuration["participant_id"] = component.participant_id
            built = self._built_artifacts(jid, spec)
            if built:
                configuration["built_artifacts"] = built
                configuration["build_dir"] = "/job/build"
            from .workflow import RuntimeConfig
            RuntimeConfig.model_validate(configuration)
            config_parent = job_path / "attempts" / aid / cid
            for ancestor in (job_path / "attempts", job_path / "attempts" / aid, config_parent):
                if ancestor.is_symlink():
                    raise ResourceError("Execution config parent is unsafe")
                ancestor.mkdir(mode=0o700, exist_ok=True)
            config = config_parent / "runtime.json"
            self._write_worker_config(config, configuration)
            configs[cid] = str(config)
            self.ledger.own(job_id=jid, attempt_id=aid, component_id=cid, kind="runtime_config",
                            external_id=str(config), details={"spec_digest": spec.digest})
        current_round = self.current_round(job)
        return ResourceBundle(jid, aid, space, job_path / "source", source["manifest"], image, principals, paths,
                              self._specs(job, attempt, spec, image, paths, execution, configs), grants, current_round == 0)

    def _built_artifacts(self, jid, spec) -> dict:
        """Revalidate retained private build inputs before every config replay."""
        from .collection import SafeCollector
        rows = [row for row in self.ledger.resources(jid, kind="build_products") if row["state"] != "deleted"]
        if not rows:
            return {}
        if len(rows) != 1:
            raise ResourceError("Job has multiple unexpected build product directories")
        row = rows[0]
        path = self.root / jid / "build-products"
        if (row["external_id"] != str(path) or row["ownership"].get("job_id") != jid or
                row["details"].get("spec_digest") != spec.digest):
            raise ResourceError("Retained build inputs belong to another immutable job")
        if not path.exists():
            # Charging is durably recorded before staging. Interrupted staging
            # is retried by the bound build output operation before any launch.
            return {}
        artifacts = row["details"].get("artifacts")
        if not isinstance(artifacts, dict) or not artifacts or len(artifacts) > 1024:
            raise ResourceError("Retained build inputs have no bounded manifest")
        with SafeCollector(path, max_files=1024, max_entries=1024, max_file_bytes=256 * 1024**2,
                           max_total_bytes=256 * 1024**2) as collector:
            actual = {item.path: {"sha256": item.sha256, "size_bytes": item.size_bytes}
                      for item in collector.collect()}
        if actual != artifacts:
            raise ResourceError("Retained private build products changed")
        return artifacts

    def external_secret_options(self, job, attempt, participant_id) -> tuple[str, ...]:
        """Plan approved external option names without reading secret values."""
        from types import SimpleNamespace
        _, _, spec = self._identity(job, attempt)
        participant = next((item for item in spec.participants if item.participant_id == participant_id), None)
        if participant is None or participant.mode != "external":
            raise ResourceError("External secret participant is not in the immutable job")
        if self.secret_resolver is None:
            if spec.secret_refs:
                raise ResourceError("Scoped external secret planning is unavailable")
            return ()
        component = SimpleNamespace(component_id=self.external_component(participant_id),
                                    role="participant", participant_id=participant_id)
        return tuple(self.secret_resolver.planned(job, attempt, component).option_names)

    def source_bounds(self, job) -> dict[str, int]:
        spec = job_spec(job)
        approval = self.registry.refreshed().source_registry.authorize(spec.project_id, spec.source_id, spec.source_commit)
        return {name: getattr(approval, name) for name in ("max_bytes", "max_files", "max_git_bytes", "max_git_files")}

    def build_manifest(self, job) -> dict:
        """Expose only verified immutable wheel identities for scoped assignments."""
        spec = job_spec(job)
        if value(job, "spec_hash", spec.digest) != spec.digest:
            raise ResourceError("Immutable build specification digest changed")
        artifacts = self._built_artifacts(value(job, "id"), spec)
        if any(component.role == "build" for component in spec.components) and not artifacts:
            raise ResourceError("Verified build products are not ready")
        return artifacts

    def read_build_product(self, job, filename, *, max_bytes=256 * 1024**2) -> bytes:
        """Read one ledger-owned immutable wheel for an authorized node transport."""
        from .collection import SafeCollector
        if (not isinstance(filename, str) or "/" in filename or "\\" in filename or
                not filename.endswith(".whl") or filename in {"", ".", ".."} or
                type(max_bytes) is not int or not 0 < max_bytes <= 256 * 1024**2):
            raise ResourceError("Build product request exceeds its fixed file policy")
        expected = self.build_manifest(job).get(filename)
        if expected is None or expected["size_bytes"] > max_bytes:
            raise ResourceError("Build product is not owned or exceeds its read bound")
        with SafeCollector(self.root / value(job, "id") / "build-products",
                           max_file_bytes=max_bytes, max_total_bytes=256 * 1024**2) as collector:
            data = collector.read(filename, max_bytes=max_bytes)
        if len(data) != expected["size_bytes"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
            raise ResourceError("Immutable build product changed during transport")
        return data

    def prepared_build_products(self, job, attempt, component_id) -> dict[str, bytes]:
        """Return bounded opaque wheels for only the prepared immutable execution."""
        from .collection import SafeCollector
        jid, aid, spec = self._identity(job, attempt)
        component = next((item for item in spec.components if item.component_id == component_id), None)
        if component is None:
            raise ResourceError("Build transport component is not in the immutable job")
        configuration = self.prepared_component(job, attempt, component_id)
        declared = configuration.get("built_artifacts", {})
        if not declared:
            return {}
        if component.role == "build" or declared != self._built_artifacts(jid, spec):
            raise ResourceError("Build transport differs from the prepared execution")
        limit = min(256 * 1024**2, component.resources.disk_bytes)
        if sum(item["size_bytes"] for item in declared.values()) > limit:
            raise ResourceError("Build products exceed the receiving component's disk limit")
        with SafeCollector(self.root / jid / "build-products", max_files=1024,
                           max_entries=1024, max_file_bytes=limit, max_total_bytes=limit) as collector:
            result = {}
            for name, expected in declared.items():
                data = collector.read(name, max_bytes=expected["size_bytes"])
                if len(data) != expected["size_bytes"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
                    raise ResourceError("Private build product changed during transport")
                result[name] = data
        return result

    def _artifact_bytes(self, identity, descriptor, *, max_bytes):
        """Resolve output only through the assigned node or its exact retained root."""
        from .collection import SafeCollector
        from urllib.parse import urlsplit, unquote
        path = value(descriptor, "path")
        locator = value(descriptor, "locator")
        if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path or any(
                part in {"", ".", ".."} for part in path.split("/")):
            raise ResourceError("Build descriptor has an unsafe relative path")
        if type(value(descriptor, "size_bytes")) is not int or not 0 <= value(descriptor, "size_bytes") <= max_bytes:
            raise ResourceError("Build descriptor exceeds its byte limit")
        if self.artifact_reader is not None:
            if not isinstance(locator, str):
                raise ResourceError("Build descriptor has no trusted locator")
            if locator.startswith("hf2l-node://"):
                parsed = urlsplit(locator)
                if (not parsed.netloc or parsed.query or parsed.fragment or
                        unquote(parsed.path) != "/" + identity.key + "/" + path):
                    raise ResourceError("Remote artifact locator belongs to another execution")
            data = self.artifact_reader(identity, path, max_bytes=max_bytes)
        else:
            target = Path(locator)
            suffix = Path(path).parts
            if (not target.is_absolute() or target.parts[-len(suffix):] != suffix or
                    target.parents[len(suffix) - 1].name != identity.key or
                    target.parents[len(suffix)].name != "retained"):
                raise ResourceError("Local build output is not retained by its exact execution")
            root = target.parents[len(suffix) - 1]
            with SafeCollector(root, max_file_bytes=max_bytes, max_total_bytes=max_bytes) as collector:
                data = collector.read(path, max_bytes=max_bytes)
        if (not isinstance(data, bytes) or len(data) != value(descriptor, "size_bytes") or
                hashlib.sha256(data).hexdigest() != value(descriptor, "sha256")):
            raise ResourceError("Retained build bytes differ from the node receipt")
        return data

    def prepare_build_outputs(self, job, attempt, outputs: Mapping[str, Any]) -> dict:
        """Stage opaque verified wheels after build termination; no archive loading.

        outputs contains the trusted node collector's RetainedFile descriptors,
        one list per immutable build component. Input wheels remain data until
        the owner/client's qualified sandbox installs them into its private state.
        """
        from .build import BuildConfig, BuildResult
        from .collection import SafeCollector
        from .retention import RetentionService
        jid, aid, spec = self._identity(job, attempt)
        builds = {c.component_id: c for c in spec.components if c.role == "build"}
        if not builds or set(outputs) != set(builds):
            raise ResourceError("Build collection differs from the immutable component gang")
        directories = OwnedDirectories(self.root)
        job_path = directories.validate_job(jid, spec.digest)
        artifacts, payloads = {}, {}
        for cid, files in outputs.items():
            descriptors = {value(item, "path"): item for item in files}
            report = descriptors.get("artifacts/build.json")
            if report is None:
                raise ResourceError("Stopped build has no owned build result")
            identity = ExecutionIdentity(jid, aid, cid, value(attempt, "epoch"))
            report_bytes = self._artifact_bytes(identity, report, max_bytes=1024 * 1024)
            result = BuildResult.model_validate(json.loads(report_bytes))
            expected = BuildConfig.model_validate(self.prepared_component(job, attempt, cid))
            result.validate_binding(expected)
            wheel = result.wheel
            descriptor = descriptors.get("artifacts/" + wheel.filename)
            if descriptor is None or value(descriptor, "sha256") != wheel.sha256 or value(descriptor, "size_bytes") != wheel.size_bytes:
                raise ResourceError("Node build artifact differs from its bound result")
            # Aggregate output is bounded before reading any wheel into memory.
            previous_bytes = sum(len(data) for name, data in payloads.items() if name != wheel.filename)
            if previous_bytes + wheel.size_bytes > 256 * 1024**2:
                raise ResourceError("Build outputs exceed the approved aggregate staging limit")
            wheel_bytes = self._artifact_bytes(identity, descriptor,
                max_bytes=min(builds[cid].resources.disk_bytes, 256 * 1024**2))
            descriptor_value = {"sha256": wheel.sha256, "size_bytes": wheel.size_bytes}
            if wheel.filename in artifacts and artifacts[wheel.filename] != descriptor_value:
                raise ResourceError("Build components produced conflicting package names")
            artifacts[wheel.filename] = descriptor_value
            payloads[wheel.filename] = wheel_bytes
        destination = job_path / "build-products"
        existing = self._built_artifacts(jid, spec)
        previous = [row for row in self.ledger.resources(jid, kind="build_products") if row["state"] != "deleted"]
        if ((existing and existing != artifacts) or
                any(row["details"].get("artifacts") not in (None, artifacts) for row in previous)):
            raise ResourceError("New build differs from retained immutable job products")
        owner = next(component for component in spec.components if component.role == "owner")
        resource_id = self.ledger.own(job_id=jid, attempt_id=aid, component_id=owner.component_id, kind="build_products",
                    external_id=str(destination), details={"size_bytes": sum(len(data) for data in payloads.values()),
                    "artifacts": artifacts, "spec_digest": spec.digest, "pool_id": self._storage_pool(spec)}, retained=True)
        retention = RetentionService(self.database)
        total_bytes = sum(len(data) for data in payloads.values())
        from .models import ProvisioningResource
        with self.database.transaction() as session:
            resource = session.get(ProvisioningResource, resource_id)
            if resource.ownership_json != {"job_id": jid, "component_id": owner.component_id, "kind": "build_products"}:
                raise ResourceError("Build budget belongs to another job")
            if resource.details_json.get("artifacts") not in (None, artifacts):
                raise ResourceError("Immutable build budget manifest changed")
            reserved = resource.details_json.get("retention_reservation_bytes", self._build_storage_cap(spec))
            resource.details_json = {**resource.details_json, "artifacts": artifacts, "spec_digest": spec.digest,
                                     "pool_id": self._storage_pool(spec), "size_bytes": total_bytes,
                                     "logical_bytes": total_bytes}
        retention.reserve_resource(resource_id, jid, reserved)
        if destination.exists():
            with SafeCollector(destination, max_file_bytes=256 * 1024**2, max_total_bytes=1024**3) as collector:
                if {item.path for item in collector.list_files()} != set(artifacts):
                    raise ResourceError("Existing private build products have a different file set")
                for filename, descriptor in artifacts.items():
                    data = collector.read(filename)
                    if len(data) != descriptor["size_bytes"] or hashlib.sha256(data).hexdigest() != descriptor["sha256"]:
                        raise ResourceError("Existing private build inputs changed")
        else:
            with tempfile.TemporaryDirectory(prefix=".build-staging-", dir=job_path) as temporary:
                stage = Path(temporary) / "products"
                stage.mkdir(mode=0o700)
                for filename, data in payloads.items():
                    with (stage / filename).open("xb") as stream:
                        stream.write(data)
                        stream.flush()
                        import os
                        os.fsync(stream.fileno())
                    (stage / filename).chmod(0o444)
                stage.rename(destination)
                destination.chmod(0o555)
        # Keep the full copy/staging reservation until the completed immutable
        # directory is verified and its actual filesystem blocks are measured.
        from types import SimpleNamespace
        physical_bytes = source_physical_bytes(destination, SimpleNamespace(
            max_files=max(1, len(builds)), max_bytes=min(256 * 1024**2,
                sum(component.resources.disk_bytes for component in builds.values()))))
        if physical_bytes < total_bytes:
            raise ResourceError("Build product filesystem does not prove its physical footprint")
        retention.settle_resource(resource_id, jid, physical_bytes)
        for component in spec.components:
            if component.role == "build":
                continue
            configuration = self.prepared_component(job, attempt, component.component_id)
            configuration["built_artifacts"] = artifacts
            configuration["build_dir"] = "/job/build"
            from .workflow import RuntimeConfig
            RuntimeConfig.model_validate(configuration)
            path = job_path / "attempts" / aid / component.component_id / "runtime.json"
            self._write_worker_config(path, configuration)
        with self.database.transaction() as session:
            resource = session.get(ProvisioningResource, resource_id)
            resource.state = "ready"
            resource.updated_at = utcnow()
        return {"built_artifacts": artifacts, "resource_id": resource_id, "path": str(destination)}

    def _directives(self, job_id, component_id, epoch):
        from sqlalchemy import select
        from .models import Attempt
        with self.database.transaction(immediate=False) as session:
            attempts = session.scalars(select(Attempt).where(Attempt.job_id == job_id, Attempt.epoch < epoch)
                .order_by(Attempt.epoch.desc()).limit(32))
            for previous in attempts:
                directives = (previous.details_json or {}).get("reconciliation_directives", {}).get(component_id)
                if directives:
                    return directives
        return []

    def prepared_component(self, job, attempt, component_id) -> dict:
        """Return a validated immutable worker payload, never manager host paths."""
        from .collection import SafeCollector
        from .workflow import RuntimeConfig
        jid, aid, spec = self._identity(job, attempt)
        component = next((c for c in spec.components if c.component_id == component_id), None)
        if component is None:
            raise ResourceError("Unknown component")
        parent = self.root / jid / "attempts" / aid / component_id
        with SafeCollector(parent, max_file_bytes=2 * 1024**2, max_total_bytes=2 * 1024**2) as collector:
            document = json.loads(collector.read("runtime.json"))
        if document.get("job_id") != jid or document.get("attempt_id") != aid or document.get("epoch") != value(attempt, "epoch"):
            raise ResourceError("Prepared worker payload belongs to another execution")
        if component.role == "build":
            from .build import BuildConfig
            return BuildConfig.model_validate(document).model_dump(mode="json")
        return RuntimeConfig.model_validate(document).model_dump(mode="json")

    def revoke(self, job, attempt) -> bool:
        jid, aid, _ = self._identity(job, attempt)
        space = self._space_id(jid)
        if space is None:
            return True
        result = self._run(jid, aid, "owner", "revoke_attempt", {"space_id": space, "attempt_id": aid},
            lambda key: self.exchange.request("POST", self.exchange.path(space, "/workload-grants/revoke"),
                                body={"attempt_id": aid}, headers={"Idempotency-Key": key}), attempt_scoped=True)
        return result.get("attempt_id") == aid and bool(result.get("revoked_at"))

    def current_round(self, job) -> int:
        space = self._space_id(value(job, "id"))
        if space is None:
            return 0
        try:
            reference = self.exchange.request("GET", self.exchange.path(space, "/refs/main"))
        except Exception as exc:
            if getattr(exc, "code", None) == "reference_not_found":
                return 0
            raise
        record = self.exchange.get_record(space, reference["record_id"])
        metadata = value(record, "metadata", {})
        inline = metadata.get("hf2l_files", {})
        round_document = inline.get("fedavg_round.json", {}) if isinstance(inline, Mapping) else {}
        round_number = round_document.get("round") if isinstance(round_document, Mapping) else None
        if round_number is None:
            round_number = metadata.get("round")
        if type(round_number) is not int or round_number < 0:
            raise ResourceError("Published global model has no valid absolute round")
        return round_number

    def reconcile(self, job, attempt) -> PublicationObservation:
        jid, aid, _ = self._identity(job, attempt)
        if self.publication_observer is not None:
            result = self.publication_observer(job, attempt, self._space_id(jid))
            if not isinstance(result, PublicationObservation):
                raise ResourceError("Publication observer returned no validated evidence")
            return result
        # A default/stale callback cannot prove that a publication did not occur.
        # In particular a start acknowledgement can be lost before the first heartbeat.
        return PublicationObservation(False, "unknown", None, {"reason": "publication_evidence_required"})

    def cleanup(self, job, attempt) -> bool:
        """Attempt cleanup retains code/state/history; caller confirms runtime stopped."""
        jid, aid, _ = self._identity(job, attempt)
        if not value(attempt, "termination_confirmed", False):
            return False
        if not self.revoke(job, attempt):
            return False
        for row in self.ledger.resources(jid, attempt_id=aid):
            if row["state"] == "deleted" or row["retained"]:
                continue
            if row["kind"] == "workload_grant":
                self.ledger.deleted(row["id"], jid)
            elif row["kind"] == "runtime_secret":
                if self.secret_resolver is None:
                    return False
                identity = ExecutionIdentity(jid, aid, row["component_id"], value(attempt, "epoch"))
                self.secret_resolver.cleanup(identity, termination_confirmed=True)
                self.ledger.deleted(row["id"], jid)
            elif row["kind"] == "runtime_config":
                path = Path(row["external_id"])
                if path.is_symlink() or self.root / jid not in path.parents or row["ownership"].get("job_id") != jid:
                    raise ResourceError("Cleanup resource is not owned by this job")
                path.unlink(missing_ok=True)
                self.ledger.deleted(row["id"], jid)
            else:
                return False
        return True

    def _confirm_remote_auxiliary(self, job) -> bool:
        """Release owned input-copy budgets only after exact registered-node receipts."""
        from sqlalchemy import select
        from .models import Allocation
        from .retention import RetentionService
        jid, spec = value(job, "id"), job_spec(job)
        rows = [row for row in self.ledger.resources(jid, kind="remote_auxiliary") if row["state"] != "deleted"]
        if not rows:
            return True
        if self.remote_auxiliary_cleanup is None:
            return False
        proofs = self.remote_auxiliary_cleanup(job, tuple(rows))
        if not isinstance(proofs, Mapping) or set(proofs) != {row["id"] for row in rows}:
            return False
        required = ("confirmed", "termination_confirmed", "source_deleted", "config_deleted", "build_deleted",
                    "private_credentials_deleted", "private_secrets_deleted", "retained_deleted", "auxiliary_deleted")
        for row in rows:
            details = row["details"]
            if (row["ownership"] != {"job_id": jid, "component_id": row["component_id"], "kind": "remote_auxiliary"} or
                    details.get("spec_digest") != spec.digest or not details.get("node_id") or not details.get("pool_id")):
                raise ResourceError("Remote auxiliary budget has foreign ownership")
            with self.database.transaction(immediate=False) as session:
                allocations = list(session.scalars(select(Allocation).where(
                    Allocation.job_id == jid, Allocation.component_id == row["component_id"],
                    Allocation.pool_id == details["pool_id"])))
                # Historical pool reassignment must not move old node ownership.
                # Missing affinity cannot be reconstructed from the pool's current node.
                if any(not (item.details_json or {}).get("node_id") for item in allocations):
                    return False
                allocations = [item for item in allocations
                               if item.details_json["node_id"] == details["node_id"]]
                expected = {(item.attempt_id, item.epoch) for item in allocations}
                if not expected or any(item.released_at is None or not item.termination_confirmed for item in allocations):
                    return False
            receipts = proofs[row["id"]]
            if isinstance(receipts, Mapping):
                receipts = (receipts,)
            if not isinstance(receipts, (tuple, list)):
                return False
            observed = set()
            for receipt in receipts:
                if not isinstance(receipt, Mapping):
                    return False
                identity = (receipt.get("attempt_id"), receipt.get("epoch"))
                if type(identity[1]) is not int or not isinstance(identity[0], str):
                    return False
                if identity in observed or identity not in expected:
                    return False
                execution = ExecutionIdentity(jid, identity[0], row["component_id"], identity[1])
                binding = {"job_id": jid, "component_id": row["component_id"], "node_id": details["node_id"],
                           "pool_id": details["pool_id"], "spec_digest": spec.digest,
                           "purpose": "managed_node_purge", "operation_id": "purge-" + execution.key}
                if any(receipt.get(key) != expected_value for key, expected_value in binding.items()) or any(
                        receipt.get(key) is not True for key in required):
                    return False
                observed.add(identity)
            if observed != expected:
                return False
        # Every receipt is validated before any independently owned resource is released.
        for row in rows:
            from .models import ProvisioningResource
            with self.database.transaction() as session:
                stored = session.get(ProvisioningResource, row["id"])
                if stored.job_id != jid or stored.ownership_json != row["ownership"]:
                    raise ResourceError("Remote auxiliary ownership changed during cleanup")
                stored.details_json = {**stored.details_json, "purge_receipts": list(proofs[row["id"]]) if
                    isinstance(proofs[row["id"]], (tuple, list)) else [dict(proofs[row["id"]])]}
            self.ledger.deleted(row["id"], jid)
            RetentionService(self.database).confirm_resource_deleted(row["id"], jid)
        return True

    def purge_job(self, job) -> bool:
        jid, spec = value(job, "id"), job_spec(job)
        if value(job, "state") not in {"SUCCEEDED", "FAILED", "CANCELLED"}:
            raise ResourceError("Only terminal jobs can be purged")
        from sqlalchemy import select
        from .models import Allocation
        with self.database.transaction(immediate=False) as session:
            if session.scalar(select(Allocation.id).where(Allocation.job_id == jid, Allocation.released_at.is_(None))):
                raise ResourceError("Job has an active or quarantined allocation")
        if not self._confirm_remote_auxiliary(job):
            return False
        space = self._space_id(jid)
        from .blob_budget import confirm_blob_cleanup, confirm_unused_blob_budget
        if space is None:
            from .models import ProvisioningOperation
            with self.database.transaction(immediate=False) as session:
                creations = list(session.scalars(select(ProvisioningOperation).where(
                    ProvisioningOperation.job_id == jid, ProvisioningOperation.operation == "exchange_space")))
                session.expunge_all()
            if creations:
                if len(creations) != 1 or creations[0].component_id != "owner":
                    raise ResourceError("Unknown namespace creation has foreign ownership")
                # The same immutable request/key safely adopts a lost create ACK.
                # No execution grant is minted while retiring terminal resources.
                space = self._provision_space(job, creations[0].attempt_id, for_cleanup=True)
            elif not confirm_unused_blob_budget(self.database, job):
                return False
        if space:
            # Historical download grants are distinct from execution attempts.
            # Revoke every owned attempt binding, retaining ledger tombstones.
            grant_attempts = {row["details"].get("attempt_id") for row in self.ledger.resources(jid, kind="workload_grant")
                              if row["details"].get("attempt_id")}
            for grant_attempt in sorted(grant_attempts):
                receipt = self.exchange.request("POST", self.exchange.path(space, "/workload-grants/revoke"),
                    body={"attempt_id": grant_attempt}, headers={"Idempotency-Key": stable_key("retention-revoke", jid, grant_attempt)})
                if receipt.get("attempt_id") != grant_attempt or not receipt.get("revoked_at"):
                    return False
        external = [row for row in self.ledger.resources(jid) if row["kind"] in {
            "external_enrollment", "external_execution_certificate", "external_execution"} and row["state"] != "deleted"]
        if external and (self.external_cleanup is None or self.external_cleanup(job) is not True):
            # Central enrollment rows cannot attest remote raw-data deletion.
            return False
        if space:
            self.exchange.request("POST", self.exchange.path(space, "/managed/retire"), body={"job_id": jid},
                                  headers={"Idempotency-Key": stable_key("retire-space", jid)})
            observed = self.exchange.request("GET", self.exchange.path(space, "/managed"))
            if not confirm_blob_cleanup(self.database, job, space, observed):
                return False
        import os
        owned_root = self.root / jid
        if owned_root.exists():
            device = owned_root.lstat().st_dev
            for directory, _, _ in os.walk(owned_root, followlinks=False):
                if Path(directory).lstat().st_dev != device or os.path.ismount(directory):
                    return False
        OwnedDirectories(self.root).purge(jid, spec.digest)
        for row in self.ledger.resources(jid):
            if row["kind"] in {"collection_budget", "log_budget", "execution_state", "exchange_blob_budget"}:
                # The controller confirms node-copy and raw database-log deletion
                # before releasing these independently prepaid budgets.
                continue
            if row["kind"] in {"exchange_space", "exchange_member"}:
                from .models import ProvisioningResource
                with self.database.transaction() as session:
                    retained = session.get(ProvisioningResource, row["id"])
                    if retained.job_id != jid or retained.ownership_json.get("job_id") != jid:
                        raise ResourceError("Cannot retire foreign provenance")
                    retained.state = "retired"
                    retained.retained = False
                    retained.size_bytes = 0
                    retained.updated_at = utcnow()
            else:
                self.ledger.deleted(row["id"], jid)
        return True

    def expire_artifacts(self, job) -> bool:
        """Delete expired raw resources while retaining authorization/history/provenance."""
        return self.purge_job(job)
