"""Trusted deployment composition; no job plugins execute in these processes."""
from __future__ import annotations
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import threading
from dataclasses import dataclass, replace
from urllib.parse import urlsplit


class ConfigurationError(ValueError):
    code = "invalid_deployment_configuration"


def read_json(path, *, limit=1_048_576):
    value = Path(path)
    metadata = value.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_mode & 0o022:
        raise ConfigurationError("Configuration must be a private regular file")
    if metadata.st_size > limit:
        raise ConfigurationError("Configuration exceeds the size bound")
    result = json.loads(value.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        raise ConfigurationError("Configuration must be a JSON object")
    return result


def read_secret(path):
    value = Path(path)
    metadata = value.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_mode & 0o077:
        raise ConfigurationError("Secret files must be private regular files")
    if not 1 <= metadata.st_size <= 65536:
        raise ConfigurationError("Invalid secret file size")
    return value.read_text(encoding="utf-8").strip()


def load_settings(config_path=None, *, component="database"):
    from .config import Settings
    settings = Settings.from_env(component=component)
    if config_path:
        extra = read_json(config_path)
        allowed = {"executor", "node", "provisioner", "service", "gateway", "proxy", "retention", "boundaries", "controller", "secrets", "participants", "nodes"}
        if set(extra) - allowed:
            raise ConfigurationError("Unknown operational configuration section")
        settings = replace(settings, extra=extra).validate(component)
    return settings


def section(settings, name, *, required=True):
    value = settings.extra.get(name, {})
    if not isinstance(value, dict) or (required and not value):
        raise ConfigurationError("Missing trusted operational section")
    return value


def _keys(value, required, optional=()):
    if not required <= value.keys() or value.keys() - required - set(optional):
        raise ConfigurationError("Missing or unknown trusted configuration field")


def _identifier(value):
    from .domain import validate_identifier
    return validate_identifier(value)


def _integer(value, minimum=0, maximum=1 << 50):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ConfigurationError("Invalid bounded integer")
    return value


def _boolean(value):
    if type(value) is not bool:
        raise ConfigurationError("Expected a Boolean")
    return value


def _text(value, maximum=200):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ConfigurationError("Invalid bounded display string")
    return value


def _database(settings, *, initialize=False):
    # Import private auth records before migrations construct the complete schema.
    from . import auth
    from .database import create_database
    database = create_database(settings.database_url, initialize=initialize)
    if not initialize:
        database.check_schema()
    return database


@dataclass
class Services:
    settings: object
    database: object
    manager: object
    auth: object
    controller: object = None
    node: object = None
    provisioner: object = None
    artifact_broker: object = None
    participants: object = None
    managed_nodes: object = None
    close_callbacks: tuple = ()
    _closed: bool = False

    def close(self):
        if self._closed:
            return
        self._closed = True
        callbacks = list(self.close_callbacks)
        if self.provisioner is not None and hasattr(self.provisioner, "close"):
            callbacks.append(self.provisioner.close)
        if self.node is not None:
            callbacks.append(self.node.close)
        callbacks.append(self.database.close)
        first_error = None
        for callback in callbacks:
            try:
                callback()
            except Exception as error:
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise first_error


def create_services(settings, *, with_controller=False):
    from .application import Manager
    from .auth import AuthService
    from .controller import Controller
    _production_database(settings)
    database = _database(settings)
    services = None
    try:
        manager = Manager(database, settings.cursor_secret, platform_operator_ids=settings.platform_operator_ids,
                          pool_qualifier=lambda value: qualify_pool(settings, value))
        services = Services(settings, database, manager, None, controller=Controller(database, None, None))
        def current_node_grant(actor):
            from sqlalchemy import select
            from .models import Allocation
            if services.managed_nodes is not None and services.managed_nodes.check_node_grant(actor):
                return True
            if not services.controller.check_assignment(actor.node_id, actor.pool_id, actor.job_id,
                    actor.attempt_id, actor.component_id, actor.epoch):
                return bool(services.participants and services.participants.check_node_grant(actor))
            with database.transaction(immediate=False) as session:
                allocation = session.scalar(select(Allocation).where(
                    Allocation.job_id == actor.job_id, Allocation.attempt_id == actor.attempt_id,
                    Allocation.component_id == actor.component_id, Allocation.epoch == actor.epoch,
                    Allocation.pool_id == actor.pool_id, Allocation.released_at.is_(None)))
                if allocation is None:
                    return False
                for key in ("cpu_millicores", "memory_bytes", "disk_bytes"):
                    if actor.resources.get(key) != getattr(allocation, key):
                        return False
                return not allocation.gpu_count and not actor.resources.get("gpu_uuids", ())
        services.auth = AuthService(database.session_factory, settings, node_grant_validator=current_node_grant)
        remote = None
        if section(settings, "nodes", required=False):
            remote = create_remote_executor(database, settings, provisioner_provider=lambda: services.provisioner,
                                            control_service_provider=lambda: services.managed_nodes)
            services.node = RegisteredExecutor(remote)
        if with_controller:
            local = create_node_agent(settings, database) if section(settings, "node", required=False) else None
            if local is None and remote is None:
                raise ConfigurationError("The controller requires an explicitly approved local or registered node")
            services.node = RegisteredExecutor(remote, local) if remote is not None else local
        if section(settings, "provisioner", required=False):
            services.provisioner = create_provisioner(database, settings, node=services.node)
            services.manager.storage_planner = services.provisioner.admission_storage
            services.artifact_broker, close = create_artifact_broker(manager, database, settings, remote_executor=remote)
            services.close_callbacks = (close,)
        if section(settings, "nodes", required=False):
            services.managed_nodes = create_managed_node_service(database, settings, services.provisioner)
        if with_controller:
            if services.provisioner is None:
                raise ConfigurationError("The controller requires actual provisioning services")
            services.controller = Controller(database, services.node, services.provisioner)
        if section(settings, "participants", required=False):
            if services.provisioner is None:
                raise ConfigurationError("External participation requires actual provisioning services")
            from .broker import WorkloadBroker
            from .participants import compose_external_services
            services.participants = compose_external_services(settings, database, manager, services.provisioner,
                                                              WorkloadBroker(settings.broker), node=services.node)
            if services.controller is not None:
                services.controller.participants = services.participants
            services.provisioner.external_cleanup = services.participants.purge_job
            if services.provisioner.publication_observer is not None:
                services.provisioner.publication_observer.external_state_reader = services.participants.read_publication_state
            services.close_callbacks += (services.participants.close,)
        return services
    except BaseException:
        if services is not None:
            services.close()
        else:
            database.close()
        raise


def create_node_agent(settings, database=None):
    from .executor import LinuxExecutor, ResourceLimits
    from .node_agent import NodeAgent
    executor_config = section(settings, "executor")
    _keys(executor_config, {"root", "profile_path"})
    node = section(settings, "node")
    _keys(node, {"node_id", "pool_id", "ledger_path", "capacity"}, {"service", "identity_certificate", "identity_key", "identity_ca", "dataset_bindings"})
    capacity = dict(node["capacity"])
    _keys(capacity, {"cpu_millicores", "memory_bytes", "disk_bytes"}, {"pids", "io_bps"})
    resources = ResourceLimits(
        cpu_millis=_integer(capacity["cpu_millicores"], 1),
        memory_bytes=_integer(capacity["memory_bytes"], 1),
        disk_bytes=_integer(capacity["disk_bytes"], 32 * 1024**2),
        pids=_integer(capacity.get("pids", 128), 1, 65536),
        io_bps=_integer(capacity.get("io_bps", 16 * 1024**2), 1),
    )
    def dataset_authorizer(binding_id, identity, participant_id):
        from .domain import JobSpec
        from .models import Job, Attempt, ParticipantBinding
        if database is None:
            raise ConfigurationError("Dataset access requires the current assignment ledger")
        with database.transaction(immediate=False) as session:
            job = session.get(Job, identity.job_id)
            attempt = session.get(Attempt, identity.attempt_id)
            approved = session.get(ParticipantBinding, binding_id)
            if (job is None or attempt is None or attempt.job_id != job.id or
                    attempt.epoch != identity.epoch or job.epoch != identity.epoch or
                    attempt.number != job.current_attempt or approved is None or not approved.enabled or
                    approved.project_id != job.project_id or approved.participant_id != participant_id or
                    approved.node_id not in (None, node["node_id"])):
                raise ConfigurationError("Dataset is not approved for this assignment")
            spec = JobSpec.model_validate(job.spec_json)
            component = next((c for c in spec.components if c.component_id == identity.component_id), None)
            participant = next((p for p in spec.participants if p.participant_id == participant_id), None)
            if (component is None or component.role != "participant" or component.participant_id != participant_id or
                    participant is None or participant.dataset_binding != binding_id or participant.mode != "managed"):
                raise ConfigurationError("Dataset differs from the immutable participant")
            data = _dataset_config(settings, binding_id, job.project_id, participant_id)
            if data["kind"] == "synthetic":
                # This binding has passed immutable participant and current
                # project/node approval checks; no host file is mounted.
                return {"kind": "synthetic"}
            path = Path(data["host_path"])
            if not path.is_absolute() or any(item.is_symlink() for item in (path, *path.parents)):
                raise ConfigurationError("Dataset path must be a trusted absolute regular file")
            metadata = path.stat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ConfigurationError("Dataset file must have a single trusted name")
            return path
    executor = LinuxExecutor(profile_path=executor_config["profile_path"], root=executor_config["root"],
                             dataset_authorizer=dataset_authorizer)
    return NodeAgent(executor, node["ledger_path"], _identifier(node["node_id"]),
                     _identifier(node["pool_id"]), resources)


def load_catalog(database, settings=None):
    from .source import RegistryCatalog
    return RegistryCatalog.from_database(database)

def admin(database, settings, arguments):
    from sqlalchemy import func, select
    from .authorization import validate_member_id
    from .domain import utcnow
    from .models import Project, ProjectMember, Pool, Allocation, ApprovedSource, RuntimeImage, ParticipantBinding, SecretReference
    operation = arguments.operation
    data = read_json(arguments.file) if hasattr(arguments, "file") else None
    def policy(row, keys):
        return {key: getattr(row, key) for key in keys}
    project_fields = ("name", "retention_days", "quotas_json", "version")
    pool_fields = ("name", "node_id", "cpu_millicores", "memory_bytes", "disk_bytes", "gpu_uuids",
                   "gpu_profiles", "sandbox_profiles", "healthy", "quarantined", "version")
    with database.transaction() as session:
        if operation == "project-create":
            identifier = _identifier(arguments.id)
            if session.get(Project, identifier):
                raise ConfigurationError("Project already exists")
            quotas = read_json(arguments.quota_file)
            allowed = {"cpu_millicores", "memory_bytes", "disk_bytes", "gpu_count", "max_running_jobs", "retained_bytes"}
            if set(quotas) - allowed:
                raise ConfigurationError("Unknown project quota")
            for value in quotas.values():
                _integer(value)
            retention = _integer(arguments.retention_days, 0, 36500)
            project = Project(id=identifier, name=_text(arguments.name), retention_days=retention, quotas_json=quotas, version=1)
            session.add(project)
            from .admin_audit import record_admin_audit
            record_admin_audit(session, actor_id="unix:" + str(os.getuid()), operation=operation,
                               resource_type="project", resource_id=identifier, after=policy(project, project_fields))
        elif operation == "project-update":
            identifier = _identifier(arguments.id)
            project = session.scalar(select(Project).where(Project.id == identifier).with_for_update())
            if project is None:
                raise ConfigurationError("Unknown project")
            audit_before = policy(project, project_fields)
            if arguments.name is None and arguments.quota_file is None and arguments.retention_days is None:
                raise ConfigurationError("An explicit project change is required")
            if arguments.name is not None:
                project.name = _text(arguments.name)
            if arguments.retention_days is not None:
                project.retention_days = _integer(arguments.retention_days, 0, 36500)
            if arguments.quota_file is not None:
                quotas = read_json(arguments.quota_file)
                allowed = {"cpu_millicores", "memory_bytes", "disk_bytes", "gpu_count", "max_running_jobs", "retained_bytes"}
                if quotas.keys() - allowed:
                    raise ConfigurationError("Unknown project quota")
                for quota in quotas.values():
                    _integer(quota)
                if quotas.get("retained_bytes", project.retained_bytes) < project.retained_bytes:
                    raise ConfigurationError("Retention quota cannot shrink beneath charged owned storage")
                from .models import Job
                active = list(session.scalars(select(Allocation).join(Job, Allocation.job_id == Job.id).where(
                    Job.project_id == identifier, Allocation.released_at.is_(None))))
                floors = {key: sum(getattr(item, key) for item in active)
                          for key in ("cpu_millicores", "memory_bytes", "disk_bytes")}
                floors["gpu_count"] = sum(item.gpu_count for item in active)
                floors["max_running_jobs"] = len({item.job_id for item in active})
                if any(key in quotas and quotas[key] < minimum for key, minimum in floors.items()):
                    raise ConfigurationError("Quota cannot shrink beneath current admitted usage")
                project.quotas_json = quotas
                for key, column in (("cpu_millicores", "quota_cpu_millicores"), ("memory_bytes", "quota_memory_bytes"),
                                    ("disk_bytes", "quota_disk_bytes"), ("gpu_count", "quota_gpus"),
                                    ("max_running_jobs", "max_active_jobs")):
                    setattr(project, column, quotas.get(key))
            project.version += 1
            from .admin_audit import record_admin_audit
            record_admin_audit(session, actor_id="unix:" + str(os.getuid()), operation=operation,
                               resource_type="project", resource_id=identifier,
                               before=audit_before, after=policy(project, project_fields))
        elif operation == "project-member":
            identifier = _identifier(arguments.project)
            if session.get(Project, identifier) is None:
                raise ConfigurationError("Unknown project")
            principal = validate_member_id(arguments.principal)
            row = session.get(ProjectMember, (identifier, principal))
            if arguments.role == "remove":
                if row is not None:
                    session.delete(row)
            elif row is not None:
                row.role = arguments.role
            else:
                session.add(ProjectMember(project_id=identifier, principal_id=principal, role=arguments.role))
        elif operation == "object-store-pool-set":
            _keys(data, {"id", "name", "disk_bytes"})
            identifier = _identifier(data["id"])
            approved_id, binding = qualify_object_store(settings)
            if identifier != approved_id:
                raise ConfigurationError("Object-store pool must match the fixed manager configuration")
            capacity = _integer(data["disk_bytes"], 1)
            if capacity > binding["capacity_bound_bytes"]:
                raise ConfigurationError("Object-store capacity exceeds the approved allocation")
            row = session.scalar(select(Pool).where(Pool.id == identifier).with_for_update())
            def object_policy(item):
                if item is None:
                    return None
                info = item.details_json or {}
                return {**policy(item, pool_fields), "digest": info.get("backend_id"),
                        "quota_disk_bytes": info.get("capacity_bound_bytes"), "status": "object_store"}
            audit_before = object_policy(row)
            for existing in session.scalars(select(Pool).where(Pool.id != identifier).with_for_update()):
                info = existing.details_json or {}
                if info.get("object_store") and info.get("locator_id") == binding["locator_id"]:
                    raise ConfigurationError("This object-store bucket and prefix are already registered")
            if row is not None:
                info = row.details_json or {}
                if (not info.get("object_store") or info.get("manager_storage") or
                    any(info.get(key) != binding[key] for key in ("registration_id", "backend_id", "locator_id"))):
                    raise ConfigurationError("Existing object-store backend identity changed")
                row.version += 1
                row.updated_at = utcnow()
            else:
                row = Pool(id=identifier, name=_text(data["name"]),
                           node_id=binding["node_id"], version=1,
                           disk_bytes=capacity, cpu_millicores=0, memory_bytes=0,
                           gpu_uuids=[], gpu_profiles=[], sandbox_profiles=[], healthy=True, quarantined=False)
                session.add(row)
            from .retention import RetentionService
            if capacity < RetentionService.pool_used_bytes(session, identifier):
                raise ConfigurationError("Object-store capacity cannot shrink beneath owned reservations or retained objects")
            row.name, row.disk_bytes = _text(data["name"]), capacity
            row.cpu_millicores, row.memory_bytes = 0, 0
            row.gpu_uuids, row.gpu_profiles, row.sandbox_profiles = [], [], []
            row.healthy, row.quarantined, row.details_json = True, False, binding
            from .admin_audit import record_admin_audit
            record_admin_audit(session, actor_id="unix:" + str(os.getuid()), operation=operation,
                               resource_type="pool", resource_id=identifier,
                               before=audit_before, after=object_policy(row))
        elif operation == "storage-pool-set":
            _keys(data, {"id", "name", "node_id", "disk_bytes"})
            identifier, node_id = _identifier(data["id"]), _identifier(data["node_id"])
            values = section(settings, "provisioner")
            if values.get("storage_pool_id") != identifier:
                raise ConfigurationError("Storage pool must match the fixed manager configuration")
            root = Path(values["root"])
            if not root.is_absolute() or any(item.is_symlink() for item in (root, *root.parents)):
                raise ConfigurationError("Manager storage requires its fixed private root")
            metadata = root.stat()
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
                raise ConfigurationError("Manager storage root must be owned and private")
            volume = os.statvfs(root)
            _integer(data["disk_bytes"], 1)
            if volume.f_flag & getattr(os, "ST_RDONLY", 1) or data["disk_bytes"] > volume.f_bavail * volume.f_frsize:
                raise ConfigurationError("Storage capacity exceeds the writable manager filesystem")
            row = session.scalar(select(Pool).where(Pool.id == identifier).with_for_update())
            audit_before = policy(row, pool_fields) if row is not None else None
            for existing in session.scalars(select(Pool).where(Pool.id != identifier).with_for_update()):
                info = existing.details_json or {}
                if info.get("manager_storage") and info.get("filesystem_device") == metadata.st_dev:
                    raise ConfigurationError("Another manager pool already advertises this backing filesystem")
            if row is not None:
                info = row.details_json or {}
                if (not info.get("manager_storage") or row.node_id != node_id or row.quarantined or
                    info.get("filesystem_device") != metadata.st_dev or info.get("root_inode") != metadata.st_ino):
                    raise ConfigurationError("Existing manager storage ownership or backing identity changed")
                row.version += 1
                row.updated_at = utcnow()
            else:
                row = Pool(id=identifier, version=1, name=_text(data["name"]), node_id=node_id,
                           disk_bytes=data["disk_bytes"], cpu_millicores=0, memory_bytes=0,
                           gpu_uuids=[], gpu_profiles=[], sandbox_profiles=[], healthy=True, quarantined=False)
                session.add(row)
            from .retention import RetentionService
            if data["disk_bytes"] < RetentionService.pool_used_bytes(session, identifier):
                raise ConfigurationError("Storage capacity cannot shrink beneath owned reserved or retained data")
            row.name, row.node_id, row.disk_bytes = _text(data["name"]), node_id, data["disk_bytes"]
            row.cpu_millicores, row.memory_bytes = 0, 0
            row.gpu_uuids, row.gpu_profiles, row.sandbox_profiles = [], [], []
            row.healthy, row.quarantined = True, False
            row.details_json = {"manager_storage": True, "filesystem_device": metadata.st_dev,
                                "root_inode": metadata.st_ino, "root_owner": metadata.st_uid}
            from .admin_audit import record_admin_audit
            record_admin_audit(session, actor_id="unix:" + str(os.getuid()), operation=operation,
                               resource_type="pool", resource_id=identifier,
                               before=audit_before, after=policy(row, pool_fields))
        elif operation == "pool-set":
            _keys(data, {"id", "name", "node_id", "cpu_millicores", "memory_bytes", "disk_bytes"},
                  {"gpu_uuids", "gpu_profiles", "sandbox_profiles", "healthy", "quarantined"})
            identifier = _identifier(data["id"])
            node_id = _identifier(data["node_id"])
            for key in ("cpu_millicores", "memory_bytes", "disk_bytes"):
                _integer(data[key])
            gpus = data.get("gpu_uuids", [])
            gpu_profiles = data.get("gpu_profiles", [])
            profiles = data.get("sandbox_profiles", [])
            for values in (gpus, gpu_profiles, profiles):
                if not isinstance(values, list) or len(values) != len(set(values)):
                    raise ConfigurationError("Profiles/GPUs must be unique lists")
                for value in values:
                    _identifier(value)
            if gpus or gpu_profiles or set(profiles) - {"runsc-cpu-v1"}:
                raise ConfigurationError("Only the qualified CPU profile is supported")
            healthy = _boolean(data.get("healthy", False))
            quarantine = _boolean(data.get("quarantined", False))
            if healthy:
                _qualified_pool_capacity(settings, data)
            row = session.scalar(select(Pool).where(Pool.id == identifier).with_for_update())
            audit_before = policy(row, pool_fields) if row is not None else None
            if row is not None:
                if (row.details_json or {}).get("manager_storage") or (row.details_json or {}).get("object_store"):
                    raise ConfigurationError("Storage pools require their storage-specific command")
                allocations = list(session.scalars(select(Allocation).where(
                    Allocation.pool_id == identifier, Allocation.released_at.is_(None))))
                if allocations and (row.node_id != node_id or row.quarantined and not quarantine):
                    raise ConfigurationError("Cannot move or unquarantine active allocations")
                for key in ("cpu_millicores", "memory_bytes"):
                    if data[key] < sum(getattr(item, key) for item in allocations):
                        raise ConfigurationError("Capacity cannot shrink beneath allocations")
                from .retention import RetentionService
                if data["disk_bytes"] < RetentionService.pool_used_bytes(session, identifier):
                    raise ConfigurationError("Capacity cannot shrink beneath owned reserved or retained storage")
                row.version += 1
                row.updated_at = utcnow()
            else:
                row = Pool(id=identifier, version=1)
                session.add(row)
            for key in ("name", "node_id", "cpu_millicores", "memory_bytes", "disk_bytes"):
                setattr(row, key, _text(data[key]) if key == "name" else data[key])
            row.gpu_uuids, row.gpu_profiles, row.sandbox_profiles = gpus, gpu_profiles, profiles
            row.healthy, row.quarantined = healthy, quarantine
            row.details_json = {**(row.details_json or {}), "min_disk_bytes": 32 * 1024**2}
            from .admin_audit import record_admin_audit
            record_admin_audit(session, actor_id="unix:" + str(os.getuid()), operation=operation,
                               resource_type="pool", resource_id=identifier,
                               before=audit_before, after=policy(row, pool_fields))
        elif operation == "source-approve":
            _keys(data, {"id", "project_id", "allowed_commits"},
                  {"url", "mirror_path", "enabled", "max_bytes", "max_files", "max_git_bytes", "max_git_files"})
            identifier = _identifier(data["id"])
            project = _identifier(data["project_id"])
            if session.get(Project, project) is None:
                raise ConfigurationError("Unknown project")
            from .source import SourceApproval, SourceRegistry
            commits = data["allowed_commits"]
            if not isinstance(commits, list) or not commits or len(commits) != len(set(commits)):
                raise ConfigurationError("Source approval requires pinned commits")
            approval = SourceApproval(identifier, frozenset({project}), url=data.get("url"),
                mirror_path=Path(data["mirror_path"]) if data.get("mirror_path") else None,
                commits=frozenset(commits), max_bytes=_integer(data.get("max_bytes", 256 * 1024**2), 1),
                max_files=_integer(data.get("max_files", 100_000), 1, 100_000),
                max_git_bytes=_integer(data.get("max_git_bytes", 256 * 1024**2), 1, 1024**3),
                max_git_files=_integer(data.get("max_git_files", 100_000), 1, 100_000))
            if approval.url:
                allowed_hosts = section(settings, "provisioner").get("allowed_source_hosts", [])
                SourceRegistry([approval], allowed_hosts=allowed_hosts)._remote(approval)
            row = session.get(ApprovedSource, identifier)
            if row is not None and row.project_id != project:
                raise ConfigurationError("Approval cannot move to another project")
            row = row or ApprovedSource(id=identifier, project_id=project)
            row.url = approval.url or ""
            row.allowed_commits = list(commits)
            row.enabled = _boolean(data.get("enabled", True))
            row.allowed_hosts = list(section(settings, "provisioner", required=False).get("allowed_source_hosts", []))
            row.status = "approved" if row.enabled else "disabled"
            row.details_json = {"max_bytes": approval.max_bytes, "max_files": approval.max_files,
                                "max_git_bytes": approval.max_git_bytes, "max_git_files": approval.max_git_files}
            if approval.mirror_path:
                row.details_json["mirror_path"] = str(approval.mirror_path)
            session.add(row)
        elif operation == "image-approve":
            _keys(data, {"id", "digest"}, {"enabled", "project_id"})
            identifier = _identifier(data["id"])
            if not isinstance(data["digest"], str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", data["digest"]):
                raise ConfigurationError("Image must resolve to an immutable SHA256 digest")
            row = session.get(RuntimeImage, identifier)
            if row is not None and row.digest != data["digest"]:
                raise ConfigurationError("Register a new image approval for a different digest")
            if row is not None and row.project_id != data.get("project_id"):
                raise ConfigurationError("Image approval cannot move to another project")
            row = row or RuntimeImage(id=identifier)
            row.digest = data["digest"]
            row.enabled = _boolean(data.get("enabled", True))
            row.approved = row.enabled
            row.status = "approved" if row.enabled else "disabled"
            if data.get("project_id"):
                project = _identifier(data["project_id"])
                if session.get(Project, project) is None:
                    raise ConfigurationError("Unknown project")
                row.project_id = project
            session.add(row)
        elif operation == "dataset-approve":
            _keys(data, {"id", "project_id", "participant_id", "dataset_label"}, {"node_id", "enabled"})
            identifier = _identifier(data["id"])
            project = _identifier(data["project_id"])
            if session.get(Project, project) is None:
                raise ConfigurationError("Unknown project")
            row = session.get(ParticipantBinding, identifier)
            if row is not None and row.project_id != project:
                raise ConfigurationError("Binding cannot move to another project")
            row = row or ParticipantBinding(id=identifier, project_id=project)
            row.participant_id = _identifier(data["participant_id"])
            row.node_id = _identifier(data["node_id"]) if data.get("node_id") else None
            row.dataset_label = _text(data["dataset_label"])
            row.enabled = _boolean(data.get("enabled", True))
            session.add(row)
        elif operation == "secret-ref-approve":
            _keys(data, {"id", "project_id", "reference"}, {"enabled"})
            identifier = _identifier(data["id"])
            project = _identifier(data["project_id"])
            if session.get(Project, project) is None:
                raise ConfigurationError("Unknown project")
            secret_file = Path(data["reference"])
            # Validate permissions without returning or printing the secret.
            read_secret(secret_file)
            row = session.get(SecretReference, identifier)
            if row is not None and row.project_id != project:
                raise ConfigurationError("Secret cannot move to another project")
            row = row or SecretReference(id=identifier, project_id=project)
            row.reference = str(secret_file.resolve())
            row.enabled = _boolean(data.get("enabled", True))
            session.add(row)
        else:
            raise ConfigurationError("Unknown administration operation")
    return {"operation": operation, "id": identifier, "status": "ok"}

def _stop_event():
    stopped = threading.Event()
    previous = {}
    if threading.current_thread() is threading.main_thread():
        for name in (signal.SIGINT, signal.SIGTERM):
            previous[name] = signal.signal(name, lambda *_: stopped.set())
    return stopped, previous


def _restore_signals(previous):
    for name, handler in previous.items():
        signal.signal(name, handler)


def _poll(tick, *, once, interval):
    if not 0.1 <= interval <= 60:
        raise ConfigurationError("Polling interval must be between 0.1 and 60 seconds")
    stopped, previous = _stop_event()
    try:
        while not stopped.is_set():
            value = tick()
            if once:
                return value
            stopped.wait(interval)
    finally:
        _restore_signals(previous)


def _uvicorn(app, settings, arguments, *, default_port=8082):
    import uvicorn
    service = section(settings, "service", required=False)
    host = arguments.host or service.get("host", "127.0.0.1")
    port = arguments.port if arguments.port is not None else service.get("port", default_port)
    _integer(port, 1, 65535)
    graceful_timeout = _integer(service.get("graceful_shutdown_timeout_seconds",
        settings.graceful_shutdown_timeout_seconds), 1, 60)
    cert, key = service.get("tls_certificate"), service.get("tls_key")
    try:
        local = ipaddress.ip_address(host).is_loopback
    except ValueError:
        local = host == "localhost"
    if bool(cert) != bool(key) or not cert and (not local or not settings.oidc.allow_local_http):
        raise ConfigurationError("Nonloopback services require TLS")
    if key:
        read_secret(key)
    uvicorn.run(app, host=host, port=port, ssl_certfile=cert, ssl_keyfile=key,
                proxy_headers=False, access_log=False, timeout_graceful_shutdown=graceful_timeout)


def dispatch(arguments):
    name = arguments.command
    settings = load_settings(arguments.config, component="server" if name in {"serve", "node-api"} else "database")
    if name in {"init-db", "migrate-db"}:
        from .migrations import CURRENT_REVISION
        database = _database(settings, initialize=True)
        try:
            return {"schema_revision": CURRENT_REVISION, "status": "ok"}
        finally:
            database.close()
    if name == "admin":
        database = _database(settings)
        try:
            return admin(database, settings, arguments)
        finally:
            database.close()
    if name == "serve":
        _production_database(settings)
        from .api import create_app
        services = create_services(settings)
        try:
            app = create_app(services.manager, services.auth,
                allow_local_http=settings.oidc.allow_local_http,
                cursor_secret=settings.cursor_secret, artifact_broker=services.artifact_broker,
                controller=services.controller, participants=services.participants,
                managed_nodes=services.managed_nodes, max_body_bytes=settings.max_body_bytes)
            _uvicorn(app, settings, arguments)
        finally:
            services.close()
        return None
    if name == "participant-agent":
        from .participants import main as run_participant
        argv = ["--config", arguments.config] if arguments.config else []
        if arguments.host:
            argv += ["--host", arguments.host]
        if arguments.port is not None:
            argv += ["--port", str(arguments.port)]
        return run_participant(argv)
    if name == "node-api":
        return run_node_api(settings, arguments)
    if name == "managed-node":
        from .remote_node import serve_node
        return serve_node(settings, arguments)
    if name == "node-agent":
        node = create_node_agent(settings)
        try:
            def tick():
                stopped = node.watchdog_once()
                return {"stopped": len(stopped), "reservations": len(node.inventory())}
            return _poll(tick, once=arguments.once, interval=arguments.interval)
        finally:
            node.close()
    if name == "controller":
        return run_controller(settings, arguments)
    if name == "gateway":
        return run_gateway(settings, arguments)
    if name == "exchange-edge":
        return run_exchange_edge(settings, arguments)
    if name == "proxy":
        return run_proxy(settings)
    raise ConfigurationError("Unknown command")

def _qualified_pool_capacity(settings, value):
    node_id, pool_id = value["node_id"], value["id"]
    remote_config = section(settings, "nodes", required=False)
    if node_id in remote_config.get("endpoints", {}):
        from .broker import WorkloadBroker
        from .remote_node import NodePlatformClient
        endpoints, registrations = _registered_node_config(settings)
        endpoint, registration = endpoints.get(node_id), registrations.get(node_id)
        if endpoint is None or registration is None or registration["pool_id"] != pool_id:
            raise ConfigurationError("Pool differs from current registered node")
        if settings.broker is None or settings.broker.private_key is None:
            raise ConfigurationError("The manager must sign the separate platform qualification grant")
        broker = WorkloadBroker(settings.broker)
        token = broker.issue_node_platform(node_id=node_id, pool_id=pool_id,
            registration_id=registration["registration_id"],
            certificate_thumbprint=_certificate_thumbprint(remote_config["client_certificate"]))
        client = NodePlatformClient(endpoint)
        try:
            report = client.qualify(pool_id, registration["registration_id"], token)
        finally:
            client.close()
        if (not isinstance(report, dict) or report.get("node_id") != node_id or report.get("pool_id") != pool_id or
            report.get("registration_id") != registration["registration_id"] or report.get("healthy") is not True):
            raise ConfigurationError("Registered node did not confirm its live qualification")
        profiles = report.get("sandbox_profiles", [])
        attestation = report.get("profile_attestations", {}).get("runsc-cpu-v1", {})
        if (profiles != ["runsc-cpu-v1"] or attestation.get("qualified") is not True or
            attestation.get("runtime") != "runsc" or attestation.get("network") != "none" or
            attestation.get("bounded_volumes") != "loop-ext4" or
            not re.fullmatch(r"[a-f0-9]{64}", attestation.get("profile_sha256", ""))):
            raise ConfigurationError("The registered sandbox profile was not qualified")
        capacity = report.get("capacity", {})
        _keys(capacity, {"cpu_millicores", "memory_bytes", "disk_bytes"})
        capacity = {key: _integer(capacity[key], 1) for key in capacity}
    else:
        agent = create_node_agent(settings)
        try:
            if (agent.node_id, agent.pool_id) != (node_id, pool_id):
                raise ConfigurationError("Pool differs from qualified local node")
            capacity = {"cpu_millicores": agent.capacity.cpu_millis,
                        "memory_bytes": agent.capacity.memory_bytes, "disk_bytes": agent.capacity.disk_bytes}
        finally:
            agent.close()
    if value.get("gpu_uuids") or value.get("gpu_profiles") or set(value.get("sandbox_profiles", [])) - {"runsc-cpu-v1"}:
        raise ConfigurationError("Only the qualified CPU profile is available")
    from .node_agent import EXECUTION_STORAGE_HEADROOM_BYTES
    for key in ("cpu_millicores", "memory_bytes", "disk_bytes"):
        maximum = max(0, (capacity[key] - EXECUTION_STORAGE_HEADROOM_BYTES) // 2) if key == "disk_bytes" else capacity[key]
        if _integer(value[key]) > maximum:
            raise ConfigurationError("Pool exceeds qualified capacity or retention headroom")
    return capacity


def qualify_pool(settings, value):
    from .domain import Error
    try:
        _qualified_pool_capacity(settings, value)
    except Exception:
        raise Error(409, "pool_qualification_required") from None
    return True


def _production_database(settings):
    if settings.database_url.startswith("sqlite:") and not settings.oidc.allow_local_http:
        raise ConfigurationError("PostgreSQL is required; SQLite needs explicit local development mode")


def object_store_approval(settings):
    """Describe a fixed operator-approved S3 allocation without credentials."""
    from hashlib import sha256
    from .domain import canonical_json
    from hf2l_exchange.config import StorageSettings, require_tls
    values = section(settings, "provisioner")
    pool_id = _identifier(values.get("exchange_storage_pool_id"))
    allocation = values.get("exchange_storage")
    if not isinstance(allocation, dict):
        raise ConfigurationError("An explicit object-store allocation is required")
    _keys(allocation, {"registration_id", "endpoint", "bucket", "prefix", "region", "capacity_bytes"})
    registration = _identifier(allocation["registration_id"])
    capacity = _integer(allocation["capacity_bytes"], 1)
    allow_local = bool(settings.oidc.allow_local_http)
    require_tls(allocation["endpoint"], allow_local)
    require_tls(values["exchange_endpoint"], values.get("allow_local_exchange_http", False))
    require_tls(values["managed_exchange_endpoint"], values.get("allow_local_exchange_http", False))
    expected = StorageSettings(endpoint=allocation["endpoint"], bucket=_text(allocation["bucket"]),
        prefix=allocation["prefix"], region=_text(allocation["region"]), allow_local_http=allow_local).validate()
    from urllib.parse import urlsplit, urlunsplit
    def canonical_endpoint(endpoint):
        parsed = urlsplit(endpoint)
        if parsed.query:
            raise ConfigurationError("Object-store backend endpoints cannot contain query parameters")
        hostname = parsed.hostname.lower()
        port = parsed.port
        authority = ("[" + hostname + "]") if ":" in hostname else hostname
        if port and port != (443 if parsed.scheme == "https" else 80):
            authority += ":" + str(port)
        return urlunsplit((parsed.scheme.lower(), authority, parsed.path.rstrip("/"), "", ""))
    location = {"endpoint": canonical_endpoint(expected.endpoint), "bucket": expected.bucket,
                "prefix": expected.prefix.strip("/")}
    identity = {**location, "region": expected.region, "registration_id": registration,
                "exchange_endpoint": canonical_endpoint(values["exchange_endpoint"]),
                "managed_exchange_endpoint": canonical_endpoint(values["managed_exchange_endpoint"])}
    metadata = {"object_store": True, "registration_id": registration,
        "backend_id": sha256(canonical_json(identity).encode()).hexdigest(),
        "locator_id": sha256(canonical_json(location).encode()).hexdigest(),
        "capacity_bound_bytes": capacity, "node_id": "object-store-" + sha256(registration.encode()).hexdigest()[:32]}
    return pool_id, metadata, expected


def qualify_object_store(settings):
    """Verify the exact versioned bucket using operator command credentials."""
    from hf2l_exchange.config import StorageSettings
    from hf2l_exchange.storage import S3BlobStore
    pool_id, metadata, expected = object_store_approval(settings)
    configured = StorageSettings.from_env()
    if ((configured.endpoint.rstrip("/"), configured.bucket, configured.prefix.strip("/"), configured.region) !=
        (expected.endpoint.rstrip("/"), expected.bucket, expected.prefix.strip("/"), expected.region)):
        raise ConfigurationError("Object-store command credentials do not match the approved backend")
    storage = S3BlobStore(configured)
    try:
        storage.check()
    finally:
        client = getattr(storage, "_client", None)
        if client is not None and hasattr(client, "close"):
            client.close()
    return pool_id, metadata


def validate_object_store_pool(database, settings):
    """Bind model-object accounting to the approved separate object store."""
    from .models import Pool
    pool_id, expected, _ = object_store_approval(settings)
    with database.transaction(immediate=False) as session:
        pool = session.get(Pool, pool_id)
        if (pool is None or pool.cpu_millicores or pool.memory_bytes or pool.gpu_uuids or pool.gpu_profiles or
            pool.sandbox_profiles or (pool.details_json or {}).get("manager_storage") or
            pool.node_id != expected["node_id"]):
            raise ConfigurationError("A separate approved object-store pool is required")
        metadata = pool.details_json or {}
        if any(type(metadata.get(key)) is not type(value) or metadata.get(key) != value for key, value in expected.items()):
            raise ConfigurationError("Object-store backend or capacity approval changed")
        if pool.disk_bytes > expected["capacity_bound_bytes"] or pool.disk_bytes < 1:
            raise ConfigurationError("Object-store capacity exceeds its approved allocation")
    return pool_id


def validate_manager_storage_pool(database, settings, pool_id):
    """Bind manager raw-copy accounting to its actual local filesystem."""
    from .models import Pool
    values = section(settings, "provisioner")
    root = Path(values["root"])
    if not root.is_absolute() or any(item.is_symlink() for item in (root, *root.parents)):
        raise ConfigurationError("Manager storage requires its fixed private root")
    metadata = root.stat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise ConfigurationError("Manager storage root must be owned and private")
    with database.transaction(immediate=False) as session:
        pool = session.get(Pool, pool_id)
        if pool is None:
            raise ConfigurationError("The manager storage pool is not approved")
        information = pool.details_json or {}
        if information.get("object_store"):
            raise ConfigurationError("Object-store capacity cannot account for manager filesystem copies")
        if information.get("manager_storage"):
            if (information.get("filesystem_device") != metadata.st_dev or
                information.get("root_inode") != metadata.st_ino or information.get("root_owner") != metadata.st_uid or
                pool.cpu_millicores or pool.memory_bytes or pool.gpu_uuids or pool.gpu_profiles or pool.sandbox_profiles):
                raise ConfigurationError("Manager storage backing ownership changed")
            return True
        local = section(settings, "node", required=False)
        executor = section(settings, "executor", required=False)
        if (local.get("pool_id") != pool.id or local.get("node_id") != pool.node_id or
            not executor.get("root") or Path(executor["root"]).stat().st_dev != metadata.st_dev):
            raise ConfigurationError("Manager raw copies require an approved pool on their physical filesystem")
        return True


def remote_auxiliary_storage(database, settings, job):
    from sqlalchemy import select
    from .domain import JobSpec
    from .models import Pool
    from .source import metadata_peak_bytes, git_peak_bytes
    spec = JobSpec.model_validate(job.spec_json)
    source = load_catalog(database).source_registry.authorize(spec.project_id, spec.source_id, spec.source_commit)
    limits = {name: getattr(source, name) for name in ("max_bytes", "max_files", "max_git_bytes", "max_git_files")}
    endpoint_config = section(settings, "nodes", required=False).get("endpoints", {})
    if not endpoint_config:
        return []
    entries = []
    with database.transaction(immediate=False) as session:
        for component in spec.components:
            pool = session.get(Pool, component.resources.pool_id)
            if pool is None:
                raise ConfigurationError("The component's pool is unavailable")
            registration = endpoint_config.get(pool.node_id)
            if registration is None:
                continue
            if not registration.get("enabled", True) or registration["pool_id"] != pool.id:
                raise ConfigurationError("The component's registered node is unavailable")
            builders = [item for item in spec.components if item.role == "build"]
            build_bytes = (min(256 * 1024**2, component.resources.disk_bytes) + 8192 * (len(builders) + 4)
                           if component.role != "build" and builders else 0)
            shared_maximum = source.max_bytes + metadata_peak_bytes(source) + git_peak_bytes(source) + build_bytes
            private_maximum = 4 * 1024**2 + 256 * 1024
            attempt_number = max(1, job.current_attempt)
            prefix = "hf2l-node-inputs://" + pool.node_id + "/" + job.id + "/" + component.component_id
            common = {"node_id": pool.node_id, "pool_id": pool.id, "spec_digest": spec.digest}
            entries.append({"kind": "remote_auxiliary", "external_id": prefix + "/shared",
                "component_id": component.component_id, "pool_id": pool.id, "max_bytes": shared_maximum,
                "details": {**common, "scope": "shared", "source_limits": limits,
                            "reservation_max_bytes": shared_maximum}})
            entries.append({"kind": "remote_auxiliary",
                "external_id": prefix + "/attempt/" + str(attempt_number),
                "component_id": component.component_id, "pool_id": pool.id, "max_bytes": private_maximum,
                "details": {**common, "scope": "attempt_private", "attempt_number": attempt_number,
                            "reservation_max_bytes": private_maximum}})
    return entries


def create_provisioner(database, settings, *, node=None):
    import httpx
    from .broker import WorkloadBroker
    from .execution_proxy import ProxySupervisor
    from .gateway import tls_context, service_endpoint
    from .provisioning import Provisioner
    from hf2l_exchange.client import ExchangeClient
    if settings.broker is None or settings.broker.private_key is None:
        raise ConfigurationError("A fixed workload signing/verification key is required")
    values = section(settings, "provisioner")
    required = {"root", "exchange_endpoint", "admin_token_file", "client_ca_certificate",
                "client_ca_key", "managed_exchange_endpoint", "gateway_endpoint", "service_ca_file",
                "exchange_storage_pool_id", "exchange_storage"}
    _keys(values, required, {"exchange_ca_file", "allowed_source_hosts", "allow_local_exchange_http", "build_approvals", "socket_root", "storage_pool_id"})
    exchange_storage_pool_id = validate_object_store_pool(database, settings)
    read_secret(values["client_ca_key"])
    # The provisioner uses a human/trusted provisioning identity only outside jobs.
    # Job proxies receive short-lived, certificate-bound, job-specific grants.
    endpoint = values["exchange_endpoint"]
    from .config import require_tls
    require_tls(endpoint, values.get("allow_local_exchange_http", False))
    http = httpx.Client(verify=tls_context(values.get("exchange_ca_file", "")),
                        timeout=60, follow_redirects=False, trust_env=False)
    exchange = ExchangeClient(endpoint, lambda: read_secret(values["admin_token_file"]),
                              http=http, allow_local_http=values.get("allow_local_exchange_http", False))
    # Validate the secret before creating any job resource.
    read_secret(values["admin_token_file"])
    broker = WorkloadBroker(settings.broker)

    def lookup(job_id, attempt_id, component_id):
        from sqlalchemy import select
        from .models import Job, Attempt, ProvisioningResource
        from .gateway import GatewayError
        with database.transaction(immediate=False) as session:
            job = session.get(Job, job_id)
            attempt = session.get(Attempt, attempt_id)
            if (job is None or attempt is None or attempt.job_id != job_id or
                attempt.epoch != job.epoch or attempt.number != job.current_attempt or
                job.state not in {"PROVISIONING", "STARTING", "RUNNING"}):
                raise GatewayError(401, "execution_grant_revoked")
            rows = list(session.scalars(select(ProvisioningResource).where(
                ProvisioningResource.job_id == job_id, ProvisioningResource.attempt_id == attempt_id,
                ProvisioningResource.component_id == component_id, ProvisioningResource.kind == "workload_grant",
                ProvisioningResource.deleted_at.is_(None))))
            if len(rows) != 1 or rows[0].state == "deleted":
                raise GatewayError(503, "execution_grant_unavailable")
            grant = dict(rows[0].details_json)
            grant_id = rows[0].external_id
        # The Exchange ledger is authoritative for revocation, not a cached
        # manager event or the self-contained JWT.
        current = exchange.get_workload_grant(grant["space_id"], grant_id)
        if hasattr(current, "to_dict"):
            current = current.to_dict()
        if not isinstance(current, dict):
            raise GatewayError(503, "execution_grant_unavailable")
        if current.get("revoked_at") or not current.get("enabled", True):
            raise GatewayError(401, "execution_grant_revoked")
        return {**grant, **current}

    supervisor = ProxySupervisor(values["root"], client_ca_certificate=values["client_ca_certificate"],
        client_ca_key=values["client_ca_key"], broker=broker,
        exchange_endpoint=values["managed_exchange_endpoint"], gateway_endpoint=values["gateway_endpoint"],
        service_ca_file=values["service_ca_file"], grant_lookup=lookup,
        socket_root=values.get("socket_root"))
    approved_datasets = section(settings, "node", required=False).get("dataset_bindings", {})
    if not isinstance(approved_datasets, dict):
        raise ConfigurationError("Approved dataset bindings must be a mapping")

    def remote_identity(identity):
        return node is not None and hasattr(node, "is_remote") and node.is_remote(identity)

    def planned_proxy(identity):
        return "remote:" + identity.key if remote_identity(identity) else supervisor.endpoint(identity)

    local_node = node.local if isinstance(node, RegisteredExecutor) else node
    if local_node is not None:
        if Path(supervisor.socket_root).resolve() != local_node.executor.owned_root:
            supervisor.close()
            exchange.close()
            http.close()
            raise ConfigurationError("The proxy socket root must equal the qualified node owned root")

    storage_pool_id = values.get("storage_pool_id")
    if storage_pool_id is None:
        storage_pool_id = local_node.pool_id if local_node is not None else section(settings, "node", required=False).get("pool_id")
    if storage_pool_id is None:
        raise ConfigurationError("Remote-only deployment requires an explicit qualified manager storage pool")
    _identifier(storage_pool_id)
    try:
        validate_manager_storage_pool(database, settings, storage_pool_id)
    except BaseException:
        supervisor.close()
        exchange.close()
        http.close()
        raise

    def auxiliary_storage(job):
        return remote_auxiliary_storage(database, settings, job)

    def remote_auxiliary_cleanup(job, resources):
        from sqlalchemy import select
        from .models import Allocation
        from .executor import ExecutionIdentity
        if node is None or not hasattr(node, "purge_receipt"):
            raise ConfigurationError("The registered node purge receipt adapter is unavailable")
        proofs = {}
        for resource in resources:
            details = (resource.get("details", resource.get("details_json", {})) if isinstance(resource, dict)
                       else resource.details_json) or {}
            component_id = resource["component_id"] if isinstance(resource, dict) else resource.component_id
            resource_id = resource["id"] if isinstance(resource, dict) else resource.id
            with database.transaction(immediate=False) as session:
                allocations = list(session.scalars(select(Allocation).where(
                    Allocation.job_id == job.id, Allocation.component_id == component_id,
                    Allocation.pool_id == details.get("pool_id"))))
                allocations = [item for item in allocations
                               if (item.details_json or {}).get("node_id") == details.get("node_id")]
                session.expunge_all()
            if not allocations:
                raise ConfigurationError("Remote auxiliary ownership has no durable allocation")
            receipts = []
            for allocation in allocations:
                identity = ExecutionIdentity(job.id, allocation.attempt_id, allocation.component_id, allocation.epoch)
                if not remote_identity(identity):
                    raise ConfigurationError("Remote auxiliary ownership does not match its admitted node")
                receipts.append(node.purge_receipt(identity, spec_digest=job.spec_hash))
            proofs[resource_id] = receipts
        return proofs

    def bindings(job, attempt, component, space_id, principal_id):
        from .executor import ExecutionIdentity
        identity = ExecutionIdentity(job.id, attempt.id, component.component_id, attempt.epoch)
        if remote_identity(identity):
            return node.binding(identity, space_id, principal_id)
        binding = supervisor.binding(job, attempt, component, space_id, principal_id)
        if component.participant_id:
            from .domain import JobSpec
            from .workflow import DatasetBinding
            spec = JobSpec.model_validate(job.spec_json)
            participant = next(item for item in spec.participants if item.participant_id == component.participant_id)
            data = _dataset_config(settings, participant.dataset_binding, job.project_id, component.participant_id)
            runtime_data = {"kind": data["kind"]}
            if data["kind"] == "npz":
                runtime_data["path"] = "/job/data/data.npz"
            approved = DatasetBinding.model_validate(runtime_data)
            binding["dataset_bindings"] = {participant.dataset_binding: approved.model_dump(mode="json")}
        return binding

    from .managed_client import ManagedArtifactBroker
    artifact_fences = ManagedArtifactBroker(None, database, exchange, broker, values["root"],
        client_ca_certificate=values["client_ca_certificate"], client_ca_key=values["client_ca_key"],
        gateway_endpoint=values["gateway_endpoint"], service_ca_file=values["service_ca_file"],
        executor_root=section(settings, "executor", required=False).get("root"))
    secret_settings = section(settings, "secrets", required=False)
    secret_resolver = None
    if secret_settings:
        from .secrets import SecretResolver
        _keys(secret_settings, {"private_root", "references"})
        secret_resolver = SecretResolver(database, secret_settings["private_root"], secret_settings["references"])

    class ManagedProvisioner(Provisioner):
        def purge_job(self, job):
            if not artifact_fences.revoke(job.id):
                return False
            return super().purge_job(job)

        def expire_artifacts(self, job):
            if not artifact_fences.revoke(job.id):
                return False
            return super().expire_artifacts(job)

        def cleanup(self, job, attempt):
            completed = super().cleanup(job, attempt)
            if completed:
                from .domain import JobSpec
                for component in JobSpec.model_validate(job.spec_json).components:
                    from .executor import ExecutionIdentity
                    identity = ExecutionIdentity(job.id, attempt.id, component.component_id, attempt.epoch)
                    if (component.role != "build" and not remote_identity(identity) and
                        not supervisor.stop(job.id, attempt.id, component.component_id, termination_confirmed=True)):
                        return False
            return completed

        def close(self):
            supervisor.close()
            exchange.close()
            http.close()

        def restore_job_proxies(self, job, attempt):
            """Called only by a controller holding the durable dispatch lease."""
            from .domain import JobSpec
            space = self._space_id(job.id)
            if space:
                for component in JobSpec.model_validate(job.spec_json).components:
                    if component.role != "build":
                        if node is not None:
                            from .executor import ExecutionIdentity, ExecutorRefused
                            identity = ExecutionIdentity(job.id, attempt.id, component.component_id, attempt.epoch)
                            observed = node.inspect(identity)
                            if (not remote_identity(identity) and observed.state.upper() == "RUNNING"
                                and not self._proxy_alive(identity)):
                                # A per-file Docker mount retains the old socket
                                # inode. A new listener cannot repair it in place.
                                error = ExecutorRefused("Proxy restart requires confirmed execution fencing",
                                                        "proxy_restart_required")
                                error.transient = True
                                raise error
                        bindings(job, attempt, component, space, self.principal(job.id, component.component_id, component.participant_id))
            return True

        def _proxy_alive(self, identity):
            if remote_identity(identity):
                return node.proxy_alive(identity)
            import socket
            peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                peer.settimeout(.5)
                peer.connect(supervisor.endpoint(identity))
                return True
            except (OSError, ValueError):
                return False
            finally:
                peer.close()

        def proxies_need_restore(self, job, attempt):
            from .domain import JobSpec
            from .executor import ExecutionIdentity
            identities = [ExecutionIdentity(job.id, attempt.id, c.component_id, attempt.epoch)
                          for c in JobSpec.model_validate(job.spec_json).components if c.role != "build"]
            return any(not self._proxy_alive(identity) for identity in identities)

    provisioner = ManagedProvisioner(database, exchange, load_catalog(database, settings), values["root"],
        workload_issuer=settings.broker.workload_issuer, execution_bindings=bindings,
        proxy_endpoint=planned_proxy, secret_resolver=secret_resolver,
        build_approvals=values.get("build_approvals", {}),
        artifact_reader=node.read_artifact if node is not None and hasattr(node, "read_artifact") else None,
        storage_pool_id=storage_pool_id, exchange_storage_pool_id=exchange_storage_pool_id,
        auxiliary_storage=auxiliary_storage,
        remote_auxiliary_cleanup=remote_auxiliary_cleanup)
    if node is not None:
        from .publications import AuthoritativePublicationObserver
        if hasattr(node, "read_state"):
            provisioner.publication_observer = AuthoritativePublicationObserver(database, exchange, None,
                provisioner.principal, state_reader=node.read_state)
        else:
            from .executor import ExecutionIdentity
            from .domain import JobSpec
            def state_roots(job, attempt):
                return {component.component_id: node.reconciliation_root(
                        ExecutionIdentity(job.id, attempt.id, component.component_id, attempt.epoch))
                        for component in JobSpec.model_validate(job.spec_json).components if component.role != "build"}
            provisioner.publication_observer = AuthoritativePublicationObserver(database, exchange, state_roots,
                                                                                provisioner.principal)
    return provisioner


def run_controller(settings, arguments):
    services = create_services(settings, with_controller=True)
    try:
        def tick():
            services.node.watchdog_once()
            result = services.controller.run_once()
            if services.participants is not None:
                services.participants.dispatch_pending()
            return result
        return _poll(tick, once=arguments.once, interval=arguments.interval)
    finally:
        services.close()


def _mtls(settings, arguments, app, values):
    from .execution_proxy import start_mtls_server
    _keys(values, {"tls_certificate", "tls_key", "client_ca_file"},
          {"host", "port", "origin_endpoints", "origin_ca_file", "allow_local_origin_http",
           "max_part_bytes", "max_download_bytes", "backend_endpoint", "backend_secret_file", "ca_file"})
    read_secret(values["tls_key"])
    host = arguments.host or values.get("host", "127.0.0.1")
    port = arguments.port if arguments.port is not None else values.get("port", 8443)
    _integer(port, 1, 65535)
    server = start_mtls_server(app, host=host, port=port, certificate=values["tls_certificate"],
                               key=values["tls_key"], client_ca=values["client_ca_file"])
    stopped, previous = _stop_event()
    try:
        while not stopped.wait(1):
            if not server.thread.is_alive():
                raise ConfigurationError("mTLS listener stopped unexpectedly")
    finally:
        _restore_signals(previous)
        server.shutdown()
        server.server_close()


def run_gateway(settings, arguments):
    from .gateway import GatewaySettings, ExchangeTransferBackend, create_gateway_app
    from hf2l_exchange.config import Settings as ExchangeSettings
    from hf2l_exchange.application import Service
    from hf2l_exchange.storage import S3BlobStore
    from hf2l_exchange.transfers import TransferService
    from hf2l_exchange.migrations import check_revision
    values = section(settings, "gateway")
    exchange_settings = ExchangeSettings.from_env(component="server")
    service = Service(exchange_settings)
    try:
        check_revision(service.engine)
        gateway = GatewaySettings(auth=exchange_settings.auth,
            origin_endpoints=tuple(values.get("origin_endpoints", [])),
            gateway_audience=settings.broker.gateway_audience if settings.broker else "hf2l-transfer",
            origin_ca_file=values.get("origin_ca_file", ""),
            allow_local_origin_http=values.get("allow_local_origin_http", False),
            max_part_bytes=values.get("max_part_bytes", 64 * 1024**2),
            max_download_bytes=values.get("max_download_bytes", 1024**4))
        backend = ExchangeTransferBackend(service, TransferService(service, S3BlobStore(exchange_settings.storage)))
        app = create_gateway_app(gateway, backend)
        _mtls(settings, arguments, app, values)
    finally:
        service.engine.dispose()


def run_exchange_edge(settings, arguments):
    from .execution_proxy import create_tls_forwarder_app
    values = section(settings, "boundaries").get("exchange")
    if not isinstance(values, dict):
        raise ConfigurationError("Missing managed Exchange boundary")
    app = create_tls_forwarder_app(backend_endpoint=values["backend_endpoint"],
        backend_secret=read_secret(values["backend_secret_file"]), ca_file=values.get("ca_file", ""))
    _mtls(settings, arguments, app, values)


def run_proxy(settings):
    import uvicorn
    from .execution_proxy import ExecutionBinding, ProxySettings, create_proxy_app
    if settings.broker is None:
        raise ConfigurationError("Fixed workload issuer and verification key are required")
    values = section(settings, "proxy")
    _keys(values, {"exchange_endpoint", "gateway_endpoint", "client_certificate", "client_key", "ca_file",
                  "binding", "exchange_token_file", "gateway_token_file", "socket_path"})
    read_secret(values["client_key"])
    socket = Path(values["socket_path"])
    if not socket.is_absolute() or socket.is_symlink() or socket.exists():
        raise ConfigurationError("Proxy requires an unused private absolute Unix socket")
    socket.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if socket.parent.stat().st_mode & 0o077:
        raise ConfigurationError("Proxy socket parent must be private")
    proxy = ProxySettings(exchange_endpoint=values["exchange_endpoint"], gateway_endpoint=values["gateway_endpoint"],
        client_certificate=values["client_certificate"], client_key=values["client_key"], ca_file=values["ca_file"],
        binding=ExecutionBinding(**values["binding"]),
        exchange_token=lambda: read_secret(values["exchange_token_file"]),
        gateway_token=lambda: read_secret(values["gateway_token_file"]),
        workload_issuer=settings.broker.workload_issuer, workload_public_key=settings.broker.public_key,
        exchange_audience=settings.broker.exchange_audience, gateway_audience=settings.broker.gateway_audience)
    uvicorn.run(create_proxy_app(proxy), uds=str(socket), proxy_headers=False, access_log=False)

def _dataset_config(settings, binding_id, project_id, participant_id):
    datasets = section(settings, "node", required=False).get("dataset_bindings", {})
    data = datasets.get(binding_id) if isinstance(datasets, dict) else None
    if not isinstance(data, dict) or data.get("kind") not in {"synthetic", "npz"}:
        raise ConfigurationError("Dataset has not been approved on this node")
    if data["kind"] == "npz":
        _keys(data, {"kind", "host_path", "project_id", "participant_id"})
    else:
        _keys(data, {"kind"}, {"project_id", "participant_id"})
    if data.get("project_id", project_id) != project_id or data.get("participant_id", participant_id) != participant_id:
        raise ConfigurationError("Local dataset belongs to another project or participant")
    return dict(data)

def create_artifact_broker(manager, database, settings, *, remote_executor=None):
    import httpx
    from .broker import WorkloadBroker
    from .gateway import tls_context
    from .managed_client import ManagedArtifactBroker
    from hf2l_exchange.client import ExchangeClient
    values = section(settings, "provisioner")
    if settings.broker is None or settings.broker.private_key is None:
        raise ConfigurationError("Download broker requires the workload signing key")
    required = {"root", "exchange_endpoint", "admin_token_file", "client_ca_certificate",
                "client_ca_key", "gateway_endpoint", "service_ca_file"}
    if not required <= values.keys():
        raise ConfigurationError("Missing download broker configuration")
    read_secret(values["admin_token_file"])
    read_secret(values["client_ca_key"])
    from .config import require_tls
    require_tls(values["exchange_endpoint"], values.get("allow_local_exchange_http", False))
    http = httpx.Client(verify=tls_context(values.get("exchange_ca_file", "")),
                        timeout=60, trust_env=False, follow_redirects=False)
    exchange = ExchangeClient(values["exchange_endpoint"], lambda: read_secret(values["admin_token_file"]), http=http,
                              allow_local_http=values.get("allow_local_exchange_http", False))
    root = Path(values["root"])
    if not root.is_absolute() or root.is_symlink():
        raise ConfigurationError("Private resource root must be absolute")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    broker = ManagedArtifactBroker(manager, database, exchange, WorkloadBroker(settings.broker), root,
        client_ca_certificate=values["client_ca_certificate"], client_ca_key=values["client_ca_key"],
        gateway_endpoint=values["gateway_endpoint"], service_ca_file=values["service_ca_file"],
        executor_root=section(settings, "executor", required=False).get("root"), remote_executor=remote_executor)
    def close():
        exchange.close()
        http.close()
    return broker, close

def run_node_api(settings, arguments):
    from .api import create_app
    _production_database(settings)
    values = section(settings, "boundaries").get("nodes")
    if not isinstance(values, dict):
        raise ConfigurationError("Missing private node mTLS listener configuration")
    _keys(values, {"tls_certificate", "tls_key", "client_ca_file"}, {"host", "port"})
    if settings.broker is None:
        raise ConfigurationError("A fixed node issuer and verification key are required")
    services = create_services(settings)
    try:
        app = create_app(services.manager, services.auth, controller=services.controller,
            participants=services.participants, artifact_broker=services.artifact_broker,
            managed_nodes=services.managed_nodes, cursor_secret=settings.cursor_secret, max_body_bytes=settings.max_body_bytes,
            allow_local_http=False)
        _mtls(settings, arguments, app, values)
    finally:
        services.close()


def _registered_node_config(settings):
    values = section(settings, "nodes")
    _keys(values, {"client_certificate", "client_key", "endpoints"})
    if not isinstance(values["endpoints"], dict) or not values["endpoints"]:
        raise ConfigurationError("Registered nodes must be an explicit nonempty mapping")
    from .remote_node import NodeEndpoint
    endpoints, approvals = {}, {}
    read_secret(values["client_key"])
    for node_id, entry in values["endpoints"].items():
        _identifier(node_id)
        _keys(entry, {"origin", "ca_file", "pool_id", "registration_id"},
              {"certificate_file", "certificate_thumbprint", "enabled", "dataset_bindings"})
        if bool(entry.get("certificate_file")) == bool(entry.get("certificate_thumbprint")):
            raise ConfigurationError("Register exactly one node identity certificate or thumbprint")
        _identifier(entry["pool_id"])
        _identifier(entry["registration_id"])
        if not _boolean(entry.get("enabled", True)):
            continue
        endpoints[node_id] = NodeEndpoint(node_id, entry["origin"], entry["ca_file"],
                                         values["client_certificate"], values["client_key"])
        approvals[node_id] = {key: entry[key] for key in
            ("pool_id", "registration_id", "certificate_file", "certificate_thumbprint") if key in entry}
        approvals[node_id]["enabled"] = True
    if not endpoints:
        raise ConfigurationError("There is no enabled registered node")
    return endpoints, approvals


def _certificate_thumbprint(path):
    import base64
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    value = Path(path)
    metadata = value.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > 65536:
        raise ConfigurationError("Identity certificate must be a bounded regular file")
    certificate = x509.load_pem_x509_certificate(value.read_bytes())
    return base64.urlsafe_b64encode(certificate.fingerprint(hashes.SHA256())).rstrip(b"=").decode()


def create_remote_executor(database, settings, *, provisioner_provider=None, control_service_provider=None, client_factory=None):
    from sqlalchemy import select
    from .broker import WorkloadBroker
    from .domain import JobSpec, utcnow
    from .executor import ResourceLimits, ExecutorRefused
    from .models import Job, Attempt, Allocation, Pool
    from .remote_node import RemoteExecutor, RemoteAssignment, NodeRoute
    endpoints, approvals = _registered_node_config(settings)
    if settings.broker is None or settings.broker.private_key is None:
        raise ConfigurationError("The manager requires its workload signing key")
    broker = WorkloadBroker(settings.broker)
    manager_thumbprint = _certificate_thumbprint(section(settings, "nodes")["client_certificate"])

    def admitted(identity, pool_id=None):
        with database.transaction(immediate=False) as session:
            job = session.get(Job, identity.job_id)
            attempt = session.get(Attempt, identity.attempt_id)
            rows = list(session.scalars(select(Allocation).where(
                Allocation.job_id == identity.job_id, Allocation.attempt_id == identity.attempt_id,
                Allocation.component_id == identity.component_id, Allocation.epoch == identity.epoch)))
            if job is None or attempt is None or attempt.job_id != job.id or attempt.epoch != identity.epoch or len(rows) != 1:
                raise ExecutorRefused("No exact durable allocation exists", "assignment_unavailable")
            allocation = rows[0]
            pool = session.get(Pool, allocation.pool_id)
            if pool is None or pool_id is not None and pool.id != pool_id:
                raise ExecutorRefused("Allocation differs from its requested pool", "pool_mismatch")
            node_id = (allocation.details_json or {}).get("node_id")
            if not node_id:
                if allocation.released_at is not None:
                    raise ExecutorRefused("Historical node ownership is unavailable", "assignment_unavailable")
                node_id = pool.node_id
            resources = ResourceLimits(allocation.cpu_millicores, allocation.memory_bytes,
                                       allocation.disk_bytes, gpus=allocation.gpu_count)
            snapshot = JobSpec.model_validate(job.spec_json)
            if snapshot.digest != job.spec_hash:
                raise ExecutorRefused("Immutable job snapshot changed", "assignment_conflict")
            component = next((item for item in snapshot.components if item.component_id == identity.component_id), None)
            if component is None or component.resources.pool_id != allocation.pool_id:
                raise ExecutorRefused("Component differs from its allocation", "assignment_conflict")
            if (component.resources.cpu_millicores, component.resources.memory_bytes, component.resources.disk_bytes,
                component.resources.gpu_count) != (allocation.cpu_millicores, allocation.memory_bytes,
                                                   allocation.disk_bytes, allocation.gpu_count):
                raise ExecutorRefused("Allocation resources changed", "invalid_resources")
            session.expunge_all()
            return job, attempt, allocation, NodeRoute(node_id, pool.id, resources), snapshot

    def route(identity, pool_id=None):
        return admitted(identity, pool_id)[3]

    def assignment(specification, target):
        job, attempt, allocation, actual, snapshot = admitted(specification.identity, target.pool_id)
        if actual != target or allocation.released_at is not None:
            raise ExecutorRefused("Admission was released or changed", "assignment_conflict")
        image = load_catalog(database).validate(snapshot)
        if image != specification.image_digest:
            raise ExecutorRefused("Approved runtime differs from admitted image", "image_not_pinned")
        from .models import ProvisioningResource
        with database.transaction(immediate=False) as session:
            prepaid = list(session.scalars(select(ProvisioningResource).where(
                ProvisioningResource.job_id == job.id, ProvisioningResource.component_id == specification.identity.component_id,
                ProvisioningResource.kind == "remote_auxiliary", ProvisioningResource.deleted_at.is_(None))))
            matching = [row for row in prepaid if (row.details_json or {}).get("node_id") == actual.node_id
                        and row.details_json.get("pool_id") == actual.pool_id and row.details_json.get("spec_digest") == snapshot.digest]
            charged = [row for row in matching if (row.details_json or {}).get("retention_charged_bytes", 0) > 0
                       and not row.details_json.get("retention_charge_released")]
            shared = [row for row in charged if row.details_json.get("scope") == "shared"]
            private = [row for row in charged if row.details_json.get("scope") == "attempt_private"
                       and row.details_json.get("attempt_number") == attempt.number]
            if len(shared) != 1 or len(private) != 1:
                raise ExecutorRefused("Remote source and attempt storage were not prepaid", "source_capacity_not_reserved")
            source_limits = dict(shared[0].details_json.get("source_limits", {}))
        if set(source_limits) != {"max_bytes", "max_files", "max_git_bytes", "max_git_files"}:
            raise ExecutorRefused("Prepaid source bounds are unavailable", "source_capacity_not_reserved")
        return RemoteAssignment(specification.identity, actual.node_id, actual.pool_id, actual.resources,
                                snapshot, image, specification.lease_seconds, specification.deadline,
                                source_limits=source_limits)

    def token(target, identity, scope):
        job, attempt, allocation, actual, snapshot = admitted(identity, target.pool_id)
        registration = approvals.get(actual.node_id)
        if actual != target or registration is None or registration["pool_id"] != actual.pool_id:
            raise ExecutorRefused("Node is not registered for this pool", "node_not_approved")
        if scope in {"reserve", "start", "renew", "assignment", "heartbeat"}:
            if (job.epoch != identity.epoch or attempt.number != job.current_attempt or
                allocation.released_at is not None or job.state not in {"PROVISIONING", "STARTING", "RUNNING"} or
                job.deadline_at is None or job.deadline_at <= utcnow()):
                raise ExecutorRefused("Current execution grant is fenced", "execution_grant_revoked")
        elif scope not in {"inspect", "stop", "collect", "release", "purge", "logs"}:
            raise ExecutorRefused("Unsupported node operation", "invalid_node_scope")
        if control_service_provider is not None:
            service = control_service_provider()
            if service is None:
                raise ExecutorRefused("The current node control service is unavailable", "node_grant_unavailable")
            return service.issue_control_token(identity, node_id=actual.node_id, pool_id=actual.pool_id,
                scope=scope, certificate_thumbprint=manager_thumbprint,
                resources={"cpu_millicores": actual.resources.cpu_millis,
                           "memory_bytes": actual.resources.memory_bytes, "disk_bytes": actual.resources.disk_bytes})
        return broker.issue_node(node_id=actual.node_id, pool_id=actual.pool_id,
            job_id=identity.job_id, attempt_id=identity.attempt_id, component_id=identity.component_id,
            grant_id=allocation.id, epoch=identity.epoch, certificate_thumbprint=manager_thumbprint,
            scopes=[scope], resources={"cpu_millicores": actual.resources.cpu_millis,
                                      "memory_bytes": actual.resources.memory_bytes,
                                      "disk_bytes": actual.resources.disk_bytes})

    def prepared(identity):
        job, attempt, allocation, target, snapshot = admitted(identity)
        if provisioner_provider is None:
            raise ExecutorRefused("Prepared worker configuration is unavailable", "configuration_unavailable")
        provisioner = provisioner_provider()
        if provisioner is None:
            raise ExecutorRefused("Prepared worker configuration is unavailable", "configuration_unavailable")
        return {"runtime_config": provisioner.prepared_component(job, attempt, identity.component_id),
                "build_products": provisioner.prepared_build_products(job, attempt, identity.component_id)}

    remote = RemoteExecutor(endpoints, route=route, assignment_provider=assignment,
                            token_provider=token, prepared_provider=prepared, client_factory=client_factory)
    remote.registered_nodes = approvals
    return remote


class RegisteredExecutor:
    """Choose only the admitted node; node availability never changes placement."""

    def __init__(self, remote, local=None):
        self.remote, self.local = remote, local

    def _executor(self, identity, pool_id=None):
        target = self.remote.route(identity, pool_id)
        if self.local is not None and (target.node_id, target.pool_id) == (self.local.node_id, self.local.pool_id):
            return self.local
        if target.node_id not in self.remote.endpoints:
            from .executor import ExecutorRefused
            raise ExecutorRefused("No approved executor owns this allocation", "node_not_approved")
        return self.remote

    def is_remote(self, identity):
        return self._executor(identity) is self.remote

    def reserve(self, spec):
        return self._executor(spec.identity, spec.pool_id).reserve(spec)

    def start(self, identity):
        return self._executor(identity).start(identity)

    def inspect(self, identity):
        return self._executor(identity).inspect(identity)

    def stop(self, identity, grace_seconds=60):
        return self._executor(identity).stop(identity, grace_seconds=grace_seconds)

    def renew(self, identity, lease_seconds=120):
        return self._executor(identity).renew(identity, lease_seconds=lease_seconds)

    def collect(self, identity):
        return self._executor(identity).collect(identity)

    def release(self, identity):
        return self._executor(identity).release(identity)

    def purge(self, identity):
        return self._executor(identity).purge(identity)

    def purge_receipt(self, identity, *, spec_digest=None):
        if not self.is_remote(identity):
            raise ConfigurationError("Remote purge receipts require a registered remote allocation")
        return self.remote.purge_receipt(identity, spec_digest=spec_digest)

    def proxy_alive(self, identity):
        if not self.is_remote(identity):
            raise ConfigurationError("A local proxy must be inspected by its local supervisor")
        return self.remote.proxy_alive(identity)

    def binding(self, identity, space_id, principal_id):
        if not self.is_remote(identity):
            raise ConfigurationError("A local binding must use the local supervisor")
        return self.remote.binding(identity, space_id, principal_id)

    def read_state(self, identity, relative_path, *, max_bytes=1024**2):
        executor = self._executor(identity)
        if executor is self.remote:
            return self.remote.read_state(identity, relative_path, max_bytes=max_bytes)
        from .collection import SafeCollector, CollectionError
        root = executor.reconciliation_root(identity)
        try:
            with SafeCollector(root, max_file_bytes=max_bytes, max_total_bytes=max_bytes) as collector:
                return collector.read(relative_path, max_bytes=max_bytes)
        except CollectionError as error:
            if isinstance(error.__cause__, FileNotFoundError):
                return None
            raise

    def read_logs(self, identity, offset=0, *, max_bytes=65536):
        return self._executor(identity).read_logs(identity, offset=offset, max_bytes=max_bytes)

    def read_artifact(self, identity, relative_path, *, max_bytes=64 * 1024**2):
        return self._executor(identity).read_artifact(identity, relative_path, max_bytes=max_bytes)

    def watchdog_once(self):
        return self.local.watchdog_once() if self.local is not None else ()

    def close(self):
        try:
            self.remote.close()
        finally:
            if self.local is not None:
                self.local.close()


def create_managed_node_service(database, settings, provisioner):
    from .broker import WorkloadBroker
    from .managed_nodes import NodeAssignmentService, SharedCertificateIssuer
    if provisioner is None or settings.broker is None or settings.broker.private_key is None:
        raise ConfigurationError("Registered nodes require central provisioning and workload signing")
    endpoints, registrations = _registered_node_config(settings)
    values = section(settings, "provisioner")
    issuer = SharedCertificateIssuer(values["client_ca_certificate"], values["client_ca_key"])
    return NodeAssignmentService(database, provisioner, WorkloadBroker(settings.broker), registrations, issuer,
        manager_certificate_thumbprint=_certificate_thumbprint(section(settings, "nodes")["client_certificate"]))
