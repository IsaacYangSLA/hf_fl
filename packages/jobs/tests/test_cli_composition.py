"""CLI bootstrapping and operational configuration acceptance."""
from __future__ import annotations
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

from hf2l_jobs.cli import main
from hf2l_jobs.composition import ConfigurationError, read_json, read_secret
from hf2l_jobs.database import create_database
from hf2l_jobs.migrations import CURRENT_REVISION
from hf2l_jobs.models import Project, ProjectMember, Pool, ApprovedSource, RuntimeImage, ParticipantBinding, SecretReference
from hf2l_jobs.source import RegistryCatalog


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.environment = patch.dict(os.environ, {"HF2L_JOBS_DATABASE_URL": "sqlite:///" + str(self.root / "manager.sqlite")}, clear=True)
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.temporary.cleanup()

    def json_file(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return str(path)

    def run_command(self, *args, expected=0):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = main(list(args))
        self.assertEqual(status, expected, err.getvalue())
        return json.loads(out.getvalue() if expected == 0 else err.getvalue())

    def test_explicit_schema_and_admin_bootstrap_are_durable(self):
        self.assertEqual(self.run_command("init-db")["schema_revision"], CURRENT_REVISION)
        self.assertEqual(self.run_command("migrate-db")["status"], "ok")
        quota = self.json_file("quota.json", {"cpu_millicores": 4000, "memory_bytes": 1024**3, "disk_bytes": 2 * 1024**3, "max_running_jobs": 2})
        self.run_command("admin", "project-create", "--id", "research", "--name", "Research", "--quota-file", quota)
        self.run_command("admin", "project-member", "--project", "research", "--principal", "alice", "--role", "submitter")
        pool = self.json_file("pool.json", {"id": "cpu", "name": "CPU", "node_id": "node1", "cpu_millicores": 2000,
            "memory_bytes": 1024**3, "disk_bytes": 1024**3, "sandbox_profiles": ["runsc-cpu-v1"], "healthy": False})
        self.run_command("admin", "pool-set", "--file", pool)
        mirror = self.root / "mirror"
        mirror.mkdir()
        source = self.json_file("source.json", {"id": "code", "project_id": "research", "mirror_path": str(mirror), "allowed_commits": ["a" * 40]})
        self.run_command("admin", "source-approve", "--file", source)
        image = self.json_file("image.json", {"id": "runtime", "digest": "sha256:" + "b" * 64})
        self.run_command("admin", "image-approve", "--file", image)
        dataset = self.json_file("dataset.json", {"id": "data", "project_id": "research", "participant_id": "alice", "dataset_label": "Locally approved synthetic data"})
        self.run_command("admin", "dataset-approve", "--file", dataset)
        secret = self.root / "private-secret"
        secret.write_text("synthetic-private-value")
        secret.chmod(0o600)
        reference = self.json_file("reference.json", {"id": "credential", "project_id": "research", "reference": str(secret)})
        response = self.run_command("admin", "secret-ref-approve", "--file", reference)
        self.assertNotIn("synthetic-private-value", json.dumps(response))
        database = create_database(os.environ["HF2L_JOBS_DATABASE_URL"], initialize=False)
        try:
            with database.transaction(immediate=False) as session:
                self.assertEqual(session.get(Project, "research").quotas_json["max_running_jobs"], 2)
                self.assertEqual(session.get(ProjectMember, ("research", "alice")).role, "submitter")
                self.assertFalse(session.get(Pool, "cpu").healthy)
                self.assertEqual(session.get(ApprovedSource, "code").details_json["mirror_path"], str(mirror))
                self.assertEqual(session.get(RuntimeImage, "runtime").digest, "sha256:" + "b" * 64)
                self.assertEqual(session.get(ParticipantBinding, "data").participant_id, "alice")
                self.assertEqual(session.get(SecretReference, "credential").reference, str(secret))
            catalog = RegistryCatalog.from_database(database)
            self.assertEqual(catalog.source_registry.authorize("research", "code", "a" * 40).mirror_path, mirror)
        finally:
            database.close()
        self.run_command("admin", "project-member", "--project", "research", "--principal", "alice", "--role", "remove")

    def test_pool_cannot_claim_health_without_qualified_executor(self):
        self.run_command("init-db")
        pool = self.json_file("unsafe-pool.json", {"id": "cpu", "name": "CPU", "node_id": "node1",
            "cpu_millicores": 2000, "memory_bytes": 1024**3, "disk_bytes": 1024**3,
            "sandbox_profiles": ["runsc-cpu-v1"], "healthy": True})
        self.assertEqual(self.run_command("admin", "pool-set", "--file", pool, expected=1)["error"], "invalid_deployment_configuration")

    def test_pool_disk_capacity_requires_retained_copy_headroom(self):
        from hf2l_jobs.composition import qualify_pool
        from hf2l_jobs.config import Settings
        from hf2l_jobs.domain import Error
        from hf2l_jobs.executor import ResourceLimits
        node = Mock(node_id="node1", pool_id="cpu", capacity=ResourceLimits(2000, 2048, 96 * 1024**2))
        healthy = {"id": "cpu", "name": "CPU", "node_id": "node1", "cpu_millicores": 2000,
                   "memory_bytes": 2048, "disk_bytes": 46 * 1024**2, "healthy": True, "sandbox_profiles": ["runsc-cpu-v1"]}
        with patch("hf2l_jobs.composition.create_node_agent", return_value=node):
            self.assertTrue(qualify_pool(Settings(), healthy))
            with self.assertRaises(Error):
                qualify_pool(Settings(), dict(healthy, disk_bytes=46 * 1024**2 + 1))
            self.run_command("init-db")
            safe = self.json_file("safe-capacity.json", healthy)
            self.run_command("admin", "pool-set", "--file", safe)
            unsafe = self.json_file("unsafe-capacity.json", dict(healthy, disk_bytes=46 * 1024**2 + 1))
            self.assertEqual(self.run_command("admin", "pool-set", "--file", unsafe, expected=1)["error"],
                             "invalid_deployment_configuration")

    def test_node_api_requires_a_separate_certificate_verified_listener(self):
        from hf2l_jobs.composition import run_node_api
        from hf2l_jobs.config import Settings, OIDCSettings
        settings = Settings(database_url="sqlite://", oidc=OIDCSettings(allow_local_http=True),
                            extra={"boundaries": {"nodes": {"host": "127.0.0.1", "port": 8444}}})
        with patch("hf2l_jobs.composition.create_services") as build:
            with self.assertRaises(ConfigurationError):
                run_node_api(settings, Mock(host=None, port=None))
            build.assert_not_called()

    def test_image_alias_digest_is_immutable(self):
        self.run_command("init-db")
        original = self.json_file("immutable-image.json", {"id": "runtime", "digest": "sha256:" + "a" * 64})
        self.run_command("admin", "image-approve", "--file", original)
        modified = self.json_file("modified-image.json", {"id": "runtime", "digest": "sha256:" + "b" * 64})
        self.assertEqual(self.run_command("admin", "image-approve", "--file", modified, expected=1)["error"],
                         "invalid_deployment_configuration")
        database = create_database(os.environ["HF2L_JOBS_DATABASE_URL"], initialize=False)
        try:
            with database.transaction(immediate=False) as session:
                self.assertEqual(session.get(RuntimeImage, "runtime").digest, "sha256:" + "a" * 64)
        finally:
            database.close()

    def test_deployment_errors_never_print_arbitrary_exception_contents(self):
        with patch("hf2l_jobs.composition.dispatch", side_effect=ValueError("SECRET=synthetic-private-value")):
            error = self.run_command("init-db", expected=1)
        self.assertEqual(error, {"error": "command_failed", "type": "ValueError"})

    def test_config_and_secret_files_reject_links_or_unsafe_permissions(self):
        path = self.root / "secret"
        path.write_text("synthetic-value")
        path.chmod(0o644)
        with self.assertRaises(ConfigurationError):
            read_secret(path)
        path.chmod(0o600)
        self.assertEqual(read_secret(path), "synthetic-value")
        link = self.root / "link"
        link.symlink_to(path)
        with self.assertRaises(ConfigurationError):
            read_secret(link)
        config = Path(self.json_file("config.json", {}))
        os.link(config, self.root / "second-name")
        with self.assertRaises(ConfigurationError):
            read_json(config)

    def test_help_imports_no_ml_or_runtime(self):
        script = "import sys; from hf2l_jobs.cli import main; " + "\ntry: main(['--help'])\nexcept SystemExit as e: assert e.code == 0\n" + "assert not any(n == 'hf2l' or n.startswith('hf2l.') or n.startswith('torch') or n.startswith('hf2l_jobs.runtime') for n in sys.modules)"
        environment = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
        result = subprocess.run([sys.executable, "-c", script], env=environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_services_close_all_resources_even_after_a_cleanup_error(self):
        from hf2l_jobs.composition import Services
        called = []
        def failed():
            called.append("failed")
            raise ValueError("synthetic failure")
        service = Services(None, Mock(close=lambda: called.append("database")), None, None,
                           node=Mock(close=lambda: called.append("node")),
                           provisioner=Mock(close=lambda: called.append("provisioner")),
                           close_callbacks=(failed, lambda: called.append("callback")))
        with self.assertRaises(ValueError):
            service.close()
        self.assertEqual(called, ["failed", "callback", "provisioner", "node", "database"])
        service.close()
        self.assertEqual(len(called), 5)

    def test_participant_entrypoint_propagates_failure_without_success_output(self):
        out = io.StringIO()
        with patch("hf2l_jobs.participants.main", return_value=7) as run:
            with contextlib.redirect_stdout(out):
                status = main(["participant-agent", "--config", "/operator/config.json", "--port", "8445"])
        self.assertEqual(status, 7)
        self.assertEqual(out.getvalue(), "")
        run.assert_called_once_with(["--config", "/operator/config.json", "--port", "8445"])

    def test_remote_routing_and_tokens_use_exact_durable_assignment(self):
        from datetime import timedelta
        from hf2l_jobs import models
        from hf2l_jobs.broker import WorkloadBroker, BrokerSettings
        from hf2l_jobs.composition import create_remote_executor, RegisteredExecutor
        from hf2l_jobs.config import Settings
        from hf2l_jobs.domain import JobSpec, utcnow
        from hf2l_jobs.executor import ExecutionIdentity, ExecutorRefused
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        broker_settings = BrokerSettings(workload_issuer="https://broker.example", exchange_audience="exchange",
            gateway_audience="gateway", node_audience="nodes", private_key=key, public_key=key.public_key())
        manager_key = self.root / "manager.key"
        manager_key.write_text("synthetic-key-file")
        manager_key.chmod(0o600)
        settings = Settings(broker=broker_settings, extra={"nodes": {
            "client_certificate": str(self.root / "manager.crt"), "client_key": str(manager_key),
            "endpoints": {"node1": {"origin": "https://node1.example", "ca_file": str(self.root / "ca.crt"),
                "pool_id": "cpu", "registration_id": "registration1", "certificate_thumbprint": "n" * 43}}}})
        database = create_database("sqlite://")
        resources = {"pool_id": "cpu", "cpu_millicores": 1000, "memory_bytes": 2048, "disk_bytes": 4096}
        spec = JobSpec.model_validate({"project_id": "project", "name": "Job", "source_id": "source",
            "source_commit": "a" * 40, "runtime_image": "sha256:" + "b" * 64, "plugin": "plugin",
            "target_round": 1, "max_duration_seconds": 3600,
            "components": [{"component_id": "owner", "role": "owner", "resources": resources}]})
        try:
            with database.transaction() as session:
                session.add(models.Project(id="project", name="Project"))
                session.add(models.Pool(id="cpu", name="CPU", node_id="node1",
                    cpu_millicores=1000, memory_bytes=2048, disk_bytes=4096))
                session.flush()
                session.add(models.Job(id="job", project_id="project", name="Job", creator_id="creator",
                    spec_json=spec.to_dict(), spec_hash=spec.digest, state="RUNNING", current_attempt=1,
                    epoch=1, target_round=1, deadline_at=utcnow() + timedelta(hours=1)))
                session.flush()
                session.add(models.Attempt(id="attempt", job_id="job", number=1, epoch=1))
                session.flush()
                session.add(models.Allocation(id="allocation", job_id="job", attempt_id="attempt",
                    component_id="owner", pool_id="cpu", epoch=1, cpu_millicores=1000,
                    memory_bytes=2048, disk_bytes=4096, details_json={"node_id": "node1"}))
            with patch("hf2l_jobs.composition._certificate_thumbprint", return_value="bW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW0"):
                remote = create_remote_executor(database, settings, client_factory=lambda endpoint: Mock())
            try:
                identity = ExecutionIdentity("job", "attempt", "owner", 1)
                route = remote.route(identity)
                self.assertEqual((route.node_id, route.pool_id), ("node1", "cpu"))
                token = remote.token_provider(route, identity, "start")
                principal = WorkloadBroker(broker_settings).authenticate_node("Bearer " + token,
                    verified_peer_thumbprint="bW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW0", grant_validator=lambda value: True)
                self.assertEqual(principal.scopes, frozenset({"start"}))
                self.assertEqual(principal.resources["disk_bytes"], 4096)
                self.assertEqual(principal.grant_id, "allocation")
                from hf2l_jobs.executor import ExecutionSpec
                mirror = self.root / "assignment-mirror"
                mirror.mkdir()
                limits = {"max_bytes": 4096, "max_files": 10, "max_git_bytes": 4096, "max_git_files": 10}
                common = {"node_id": "node1", "pool_id": "cpu", "spec_digest": spec.digest,
                          "retention_charged_bytes": 8192, "retention_charge_released": False}
                with database.transaction() as session:
                    session.add(models.ApprovedSource(id="source", project_id="project", allowed_commits=["a" * 40],
                        status="approved", url="", details_json={"mirror_path": str(mirror), **limits}))
                    session.add(models.RuntimeImage(id="runtime", digest=spec.runtime_image, approved=True, status="approved"))
                    session.add(models.ProvisioningResource(id="shared-input", job_id="job", component_id="owner",
                        kind="remote_auxiliary", external_id="shared-input", state="reserved", retained=True,
                        details_json={**common, "scope": "shared", "source_limits": limits}))
                    session.add(models.ProvisioningResource(id="private-input", job_id="job", component_id="owner",
                        kind="remote_auxiliary", external_id="private-input", state="reserved", retained=True,
                        details_json={**common, "scope": "attempt_private", "attempt_number": 1}))
                execution = ExecutionSpec(identity, spec.runtime_image, "/unused/source", "/unused/state",
                    ("python", "-m", "hf2l_jobs.runtime", "--config", "/run/hf2l/runtime.json"),
                    "remote:" + identity.key, route.resources, pool_id="cpu", node_id="node1")
                assignment = remote.assignment_provider(execution, route)
                self.assertEqual(assignment.source_limits, limits)
                with database.transaction() as session:
                    row = session.get(models.ProvisioningResource, "private-input")
                    row.details_json = {**row.details_json, "attempt_number": 2}
                with self.assertRaises(ExecutorRefused):
                    remote.assignment_provider(execution, route)
                with database.transaction() as session:
                    row = session.get(models.ProvisioningResource, "private-input")
                    row.details_json = {**row.details_json, "attempt_number": 1, "retention_charge_released": True}
                with self.assertRaises(ExecutorRefused):
                    remote.assignment_provider(execution, route)
                with self.assertRaises(ExecutorRefused):
                    remote.route(identity, "different-pool")
                with database.transaction() as session:
                    session.get(models.Pool, "cpu").node_id = "replacement"
                    session.get(models.Job, "job").epoch = 2
                self.assertEqual(remote.route(identity).node_id, "node1")
                with self.assertRaises(ExecutorRefused):
                    remote.token_provider(route, identity, "start")
                stopped_token = remote.token_provider(route, identity, "inspect")
                self.assertTrue(stopped_token)
                with database.transaction() as session:
                    allocation = session.get(models.Allocation, "allocation")
                    allocation.released_at = utcnow()
                    allocation.details_json = {}
                with self.assertRaises(ExecutorRefused):
                    RegisteredExecutor(remote)._executor(identity)
            finally:
                remote.close()
        finally:
            database.close()

    def test_project_updates_are_atomic_usage_bounded_and_audited(self):
        from sqlalchemy import select
        from hf2l_jobs.models import AdministrativeAudit
        self.run_command("init-db")
        quota = self.json_file("initial-quota.json", {"max_running_jobs": 2, "retained_bytes": 1024})
        self.run_command("admin", "project-create", "--id", "project", "--name", "Project", "--quota-file", quota)
        database = create_database(os.environ["HF2L_JOBS_DATABASE_URL"], initialize=False)
        try:
            with database.transaction() as session:
                session.get(Project, "project").retained_bytes = 512
            unsafe = self.json_file("too-small-quota.json", {"retained_bytes": 511})
            self.run_command("admin", "project-update", "--id", "project", "--quota-file", unsafe, expected=1)
            updated = self.json_file("new-quota.json", {"max_running_jobs": 3, "retained_bytes": 2048})
            self.run_command("admin", "project-update", "--id", "project", "--quota-file", updated,
                             "--name", "Updated", "--retention-days", "30")
            with database.transaction(immediate=False) as session:
                project = session.get(Project, "project")
                self.assertEqual(project.name, "Updated")
                self.assertEqual(project.retention_days, 30)
                self.assertEqual(project.max_active_jobs, 3)
                self.assertEqual(project.version, 2)
                rows = list(session.scalars(select(AdministrativeAudit).where(
                    AdministrativeAudit.resource_id == "project").order_by(AdministrativeAudit.created_at)))
                self.assertEqual(len(rows), 2)
                update = next(row for row in rows if row.operation == "project-update")
                self.assertEqual(update.before_json["retention_days"], 90)
                self.assertEqual(update.after_json["retention_days"], 30)
                self.assertEqual(update.after_json["quotas_json"]["max_running_jobs"], 3)
                self.assertTrue(update.actor_id.startswith("unix:"))
        finally:
            database.close()

    def test_storage_pool_creation_qualification_and_backing_ownership(self):
        from sqlalchemy import select
        from hf2l_jobs.models import AdministrativeAudit
        self.run_command("init-db")
        private = self.root / "manager-private"
        private.mkdir(mode=0o700)
        config = self.json_file("storage-config.json", {"provisioner": {
            "root": str(private), "storage_pool_id": "source-storage"}})
        definition = {"id": "source-storage", "name": "Manager sources", "node_id": "manager-storage",
                      "disk_bytes": 64 * 1024**2}
        pool_file = self.json_file("storage-pool.json", definition)
        self.run_command("admin", "--config", config, "storage-pool-set", "--file", pool_file)
        database = create_database(os.environ["HF2L_JOBS_DATABASE_URL"], initialize=False)
        try:
            with database.transaction(immediate=False) as session:
                pool = session.get(Pool, "source-storage")
                self.assertEqual((pool.cpu_millicores, pool.memory_bytes, pool.gpu_uuids, pool.sandbox_profiles),
                                 (0, 0, [], []))
                self.assertTrue(pool.healthy)
                self.assertEqual(pool.details_json["filesystem_device"], private.stat().st_dev)
                self.assertEqual(pool.details_json["root_inode"], private.stat().st_ino)
                self.assertNotIn(str(private), json.dumps(pool.details_json))
            from hf2l_jobs.config import Settings
            from hf2l_jobs.composition import validate_manager_storage_pool
            deployment = Settings(extra={"provisioner": {"root": str(private)}})
            self.assertTrue(validate_manager_storage_pool(database, deployment, "source-storage"))
            execution = self.json_file("execution-over-storage.json", {
                **definition, "cpu_millicores": 0, "memory_bytes": 0})
            self.run_command("admin", "pool-set", "--file", execution, expected=1)
            duplicate_config = self.json_file("duplicate-storage-config.json", {"provisioner": {
                "root": str(private), "storage_pool_id": "duplicate"}})
            duplicate = self.json_file("duplicate-storage.json", {**definition, "id": "duplicate"})
            self.run_command("admin", "--config", duplicate_config, "storage-pool-set", "--file", duplicate, expected=1)
            private.chmod(0o755)
            self.run_command("admin", "--config", config, "storage-pool-set", "--file", pool_file, expected=1)
            with database.transaction(immediate=False) as session:
                self.assertIsNone(session.get(Pool, "duplicate"))
                self.assertEqual(session.get(Pool, "source-storage").version, 1)
                rows = list(session.scalars(select(AdministrativeAudit).where(
                    AdministrativeAudit.resource_id == "source-storage")))
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0].operation, "storage-pool-set")
            private.chmod(0o700)
            private.rename(self.root / "previous-root")
            private.mkdir(mode=0o700)
            with self.assertRaises(ConfigurationError):
                validate_manager_storage_pool(database, deployment, "source-storage")
        finally:
            database.close()

    def test_remote_storage_reuses_shared_inputs_but_prepays_each_attempt(self):
        from types import SimpleNamespace
        from hf2l_jobs.config import Settings
        from hf2l_jobs.composition import remote_auxiliary_storage
        from hf2l_jobs.domain import JobSpec
        from hf2l_jobs.source import metadata_peak_bytes, git_peak_bytes
        database = create_database("sqlite://")
        mirror = self.root / "approved-mirror"
        mirror.mkdir()
        limits = {"max_bytes": 1024, "max_files": 10, "max_git_bytes": 2048, "max_git_files": 20}
        resources = {"pool_id": "cpu", "cpu_millicores": 1000, "memory_bytes": 1024**3, "disk_bytes": 32 * 1024**2}
        spec = JobSpec.model_validate({"project_id": "project", "name": "Job", "source_id": "source",
            "source_commit": "a" * 40, "runtime_image": "sha256:" + "b" * 64, "plugin": "plugin",
            "target_round": 1, "max_duration_seconds": 3600,
            "components": [{"component_id": "owner", "role": "owner", "resources": resources}]})
        settings = Settings(extra={"nodes": {"endpoints": {"node1": {"pool_id": "cpu"}}}})
        try:
            with database.transaction() as session:
                session.add(Project(id="project", name="Project"))
                session.add(Pool(id="cpu", name="CPU", node_id="node1", disk_bytes=1024**3))
                session.flush()
                session.add(ApprovedSource(id="source", project_id="project", allowed_commits=["a" * 40],
                    status="approved", enabled=True, url="", details_json={"mirror_path": str(mirror), **limits}))
            job = SimpleNamespace(id="job", spec_json=spec.to_dict(), spec_hash=spec.digest, current_attempt=1)
            first = remote_auxiliary_storage(database, settings, job)
            job.current_attempt = 2
            second = remote_auxiliary_storage(database, settings, job)
            shared1 = next(item for item in first if item["details"]["scope"] == "shared")
            shared2 = next(item for item in second if item["details"]["scope"] == "shared")
            private1 = next(item for item in first if item["details"]["scope"] == "attempt_private")
            private2 = next(item for item in second if item["details"]["scope"] == "attempt_private")
            source = RegistryCatalog.from_database(database).source_registry.authorize("project", "source", "a" * 40)
            self.assertEqual(shared1["max_bytes"], source.max_bytes + metadata_peak_bytes(source) + git_peak_bytes(source))
            self.assertEqual(shared1, shared2)
            self.assertEqual(shared1["details"]["source_limits"], limits)
            self.assertNotEqual(private1["external_id"], private2["external_id"])
            self.assertEqual(private1["max_bytes"], 4 * 1024**2 + 256 * 1024)
            self.assertEqual(private2["details"]["attempt_number"], 2)
            built = spec.to_dict()
            built["components"].append({"component_id": "builder", "role": "build", "resources": resources})
            built_spec = JobSpec.model_validate(built)
            job.spec_json, job.spec_hash = built_spec.to_dict(), built_spec.digest
            with_build = remote_auxiliary_storage(database, settings, job)
            owner_shared = next(item for item in with_build if item["component_id"] == "owner"
                                and item["details"]["scope"] == "shared")
            builder_shared = next(item for item in with_build if item["component_id"] == "builder"
                                  and item["details"]["scope"] == "shared")
            self.assertEqual(owner_shared["max_bytes"] - shared1["max_bytes"],
                             resources["disk_bytes"] + 8192 * 5)
            self.assertEqual(builder_shared["max_bytes"], shared1["max_bytes"])
        finally:
            database.close()

    def test_object_store_pool_requires_actual_backend_and_preserves_capacity_identity(self):
        from sqlalchemy import select
        from hf2l_jobs.config import Settings
        from hf2l_jobs.composition import validate_object_store_pool
        from hf2l_jobs.models import AdministrativeAudit, Job, ProvisioningResource
        from hf2l_exchange.config import StorageSettings
        self.run_command("init-db")
        allocation = {"registration_id": "approved-s3", "endpoint": "https://s3.example",
                      "bucket": "approved-bucket", "prefix": "", "region": "us-east-1",
                      "capacity_bytes": 128 * 1024**2}
        provisioner = {"exchange_storage_pool_id": "objects", "exchange_storage": allocation,
                       "exchange_endpoint": "https://exchange.example",
                       "managed_exchange_endpoint": "https://managed-exchange.example"}
        config = self.json_file("object-store-config.json", {"provisioner": provisioner})
        definition = {"id": "objects", "name": "Model objects", "disk_bytes": 64 * 1024**2}
        pool_file = self.json_file("object-store-pool.json", definition)
        expected_storage = StorageSettings(endpoint=allocation["endpoint"], bucket=allocation["bucket"],
                                          prefix=allocation["prefix"], region=allocation["region"])
        storage = Mock(_client=Mock())
        with patch("hf2l_exchange.config.StorageSettings.from_env", return_value=expected_storage), \
             patch("hf2l_exchange.storage.S3BlobStore", return_value=storage):
            self.run_command("admin", "--config", config, "object-store-pool-set", "--file", pool_file)
            storage.check.assert_called_once()
            database = create_database(os.environ["HF2L_JOBS_DATABASE_URL"], initialize=False)
            try:
                self.assertEqual(validate_object_store_pool(database, Settings(extra={"provisioner": provisioner})),
                                 "objects")
                with database.transaction() as session:
                    pool = session.get(Pool, "objects")
                    self.assertEqual((pool.cpu_millicores, pool.memory_bytes, pool.sandbox_profiles), (0, 0, []))
                    self.assertTrue(pool.details_json["object_store"])
                    self.assertNotIn("approved-bucket", json.dumps(pool.details_json))
                    session.add(Project(id="storage-project", name="Project"))
                    session.flush()
                    session.add(Job(id="storage-job", project_id="storage-project", name="Job", creator_id="actor",
                                    spec_json={}, spec_hash="a" * 64, target_round=1))
                    session.flush()
                    session.add(ProvisioningResource(id="model-reservation", job_id="storage-job",
                        component_id="owner", kind="exchange_blob_budget", external_id="owned-model-objects",
                        state="reserved", retained=True, size_bytes=48 * 1024**2, details_json={"pool_id": "objects",
                        "retention_charged_bytes": 48 * 1024**2, "retention_charge_released": False}))
                too_small = self.json_file("small-object-pool.json", {**definition, "disk_bytes": 32 * 1024**2})
                self.run_command("admin", "--config", config, "object-store-pool-set", "--file", too_small, expected=1)
                too_large = self.json_file("large-object-pool.json", {**definition, "disk_bytes": 129 * 1024**2})
                self.run_command("admin", "--config", config, "object-store-pool-set", "--file", too_large, expected=1)
                duplicate_config = self.json_file("duplicate-object-config.json", {
                    "provisioner": {**provisioner, "exchange_storage_pool_id": "alias"}})
                duplicate = self.json_file("duplicate-object-pool.json", {**definition, "id": "alias"})
                self.run_command("admin", "--config", duplicate_config, "object-store-pool-set", "--file", duplicate, expected=1)
                changed = self.json_file("changed-object-config.json", {"provisioner": {
                    **provisioner, "exchange_storage": {**allocation, "registration_id": "different-approval"}}})
                self.run_command("admin", "--config", changed, "object-store-pool-set", "--file", pool_file, expected=1)
                generic = self.json_file("generic-object-pool.json", {
                    **definition, "node_id": "object-store", "cpu_millicores": 0, "memory_bytes": 0})
                self.run_command("admin", "pool-set", "--file", generic, expected=1)
                with self.assertRaises(ConfigurationError):
                    validate_object_store_pool(database, Settings(extra={"provisioner": {
                        **provisioner, "exchange_storage": {**allocation, "capacity_bytes": 256 * 1024**2}}}))
                with database.transaction(immediate=False) as session:
                    self.assertIsNone(session.get(Pool, "alias"))
                    self.assertEqual(session.get(Pool, "objects").disk_bytes, 64 * 1024**2)
                    audits = list(session.scalars(select(AdministrativeAudit).where(
                        AdministrativeAudit.resource_id == "objects")))
                    self.assertEqual(len(audits), 1)
                    self.assertEqual(audits[0].operation, "object-store-pool-set")
                    self.assertEqual(audits[0].after_json["quota_disk_bytes"], 128 * 1024**2)
                    self.assertEqual(len(audits[0].after_json["digest"]), 64)
            finally:
                database.close()

    def test_object_store_configuration_and_backend_checks_fail_closed(self):
        from hf2l_jobs.config import Settings
        from hf2l_jobs.composition import qualify_object_store, validate_object_store_pool
        from hf2l_exchange.config import StorageSettings
        allocation = {"registration_id": "approval", "endpoint": "https://s3.example", "bucket": "bucket",
                      "prefix": "models/", "region": "us-east-1", "capacity_bytes": 1024**3}
        settings = Settings(extra={"provisioner": {"exchange_storage_pool_id": "objects",
            "exchange_storage": allocation, "exchange_endpoint": "https://exchange.example",
            "managed_exchange_endpoint": "https://managed.example"}})
        wrong = StorageSettings(endpoint="https://foreign.example", bucket="bucket", prefix="models/")
        with patch("hf2l_exchange.config.StorageSettings.from_env", return_value=wrong), \
             patch("hf2l_exchange.storage.S3BlobStore") as storage:
            with self.assertRaises(ConfigurationError):
                qualify_object_store(settings)
            storage.assert_not_called()
        right = StorageSettings(endpoint="https://s3.example", bucket="bucket", prefix="models/")
        with patch("hf2l_exchange.config.StorageSettings.from_env", return_value=right), \
             patch("hf2l_exchange.storage.S3BlobStore", return_value=Mock(check=Mock(side_effect=RuntimeError("unavailable")))):
            with self.assertRaises(RuntimeError):
                qualify_object_store(settings)
        database = create_database("sqlite://")
        try:
            with self.assertRaises(ConfigurationError):
                validate_object_store_pool(database, settings)
            with self.assertRaises(ConfigurationError):
                validate_object_store_pool(database, Settings(extra={"provisioner": {}}))
        finally:
            database.close()


@unittest.skipUnless(os.environ.get("JOBS_TEST_DATABASE_URL"), "JOBS_TEST_DATABASE_URL is not configured")
class PostgreSQLStorageBootstrapTests(unittest.TestCase):
    def test_storage_pool_is_complete_before_real_postgresql_autoflush(self):
        from uuid import uuid4
        from sqlalchemy import create_engine, text
        from sqlalchemy.engine import make_url
        supplied = make_url(os.environ["JOBS_TEST_DATABASE_URL"])
        self.assertEqual(supplied.get_backend_name(), "postgresql")
        schema = "jm_cli_storage_" + uuid4().hex
        admin_engine = create_engine(supplied, pool_pre_ping=True)
        self.addCleanup(admin_engine.dispose)
        with admin_engine.begin() as connection:
            connection.execute(text('CREATE SCHEMA "' + schema + '"'))
        def drop():
            with admin_engine.begin() as connection:
                connection.execute(text('DROP SCHEMA IF EXISTS "' + schema + '" CASCADE'))
        self.addCleanup(drop)
        url = supplied.update_query_dict({"options": "-csearch_path=" + schema}).render_as_string(hide_password=False)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private"
            private.mkdir(mode=0o700)
            config = root / "config.json"
            config.write_text(json.dumps({"provisioner": {"root": str(private), "storage_pool_id": "storage"}}))
            config.chmod(0o600)
            definition = root / "storage.json"
            definition.write_text(json.dumps({"id": "storage", "name": "Storage", "node_id": "manager-storage",
                                             "disk_bytes": 64 * 1024**2}))
            definition.chmod(0o600)
            with patch.dict(os.environ, {"HF2L_JOBS_DATABASE_URL": url}, clear=True):
                for arguments in (["init-db"], ["admin", "--config", str(config), "storage-pool-set",
                                               "--file", str(definition)]):
                    output, error = io.StringIO(), io.StringIO()
                    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                        status = main(arguments)
                    self.assertEqual(status, 0, error.getvalue())
                database = create_database(url, initialize=False)
                try:
                    with database.transaction(immediate=False) as session:
                        pool = session.get(Pool, "storage")
                        self.assertEqual((pool.name, pool.node_id), ("Storage", "manager-storage"))
                        self.assertEqual(pool.sandbox_profiles, [])
                        self.assertTrue(pool.details_json["manager_storage"])
                finally:
                    database.close()


    @unittest.skipUnless(os.environ.get("JOBS_TEST_S3_FIXTURE_FILE"), "S3 fixture is not configured")
    def test_actual_versioned_s3_object_store_bootstrap_is_postgresql_atomic(self):
        from uuid import uuid4
        from sqlalchemy import create_engine, text, select
        from sqlalchemy.engine import make_url
        from hf2l_jobs.models import AdministrativeAudit
        from hf2l_exchange.config import StorageSettings
        from hf2l_exchange.storage import S3BlobStore
        fixture = json.loads(Path(os.environ["JOBS_TEST_S3_FIXTURE_FILE"]).read_text())
        supplied = make_url(os.environ["JOBS_TEST_DATABASE_URL"])
        self.assertEqual(supplied.get_backend_name(), "postgresql")
        schema = "jm_cli_object_" + uuid4().hex
        engine = create_engine(supplied, pool_pre_ping=True)
        self.addCleanup(engine.dispose)
        with engine.begin() as connection:
            connection.execute(text('CREATE SCHEMA "' + schema + '"'))
        def drop():
            with engine.begin() as connection:
                connection.execute(text('DROP SCHEMA IF EXISTS "' + schema + '" CASCADE'))
        self.addCleanup(drop)
        url = supplied.update_query_dict({"options": "-csearch_path=" + schema}).render_as_string(hide_password=False)
        bucket = "hf2l-cli-objects-" + uuid4().hex[:20]
        storage_settings = StorageSettings(endpoint=fixture["s3_endpoint"], bucket=bucket, prefix="",
            access_key=fixture["s3_access_key"], secret_key=fixture["s3_secret_key"], allow_local_http=True)
        client = S3BlobStore(storage_settings).client
        try:
            client.create_bucket(Bucket=bucket)
            client.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config = root / "config.json"
                config.write_text(json.dumps({"provisioner": {
                    "exchange_storage_pool_id": "objects",
                    "exchange_storage": {"registration_id": "real-s3-allocation",
                        "endpoint": fixture["s3_endpoint"], "bucket": bucket, "prefix": "",
                        "region": "us-east-1", "capacity_bytes": 128 * 1024**2},
                    "exchange_endpoint": "https://exchange.example",
                    "managed_exchange_endpoint": "https://managed-exchange.example"}}))
                config.chmod(0o600)
                definition = root / "objects.json"
                definition.write_text(json.dumps({"id": "objects", "name": "Actual S3 objects", "disk_bytes": 64 * 1024**2}))
                definition.chmod(0o600)
                environment = {"HF2L_JOBS_DATABASE_URL": url, "HF2L_JOBS_ALLOW_LOCAL_HTTP": "true",
                    "EXCHANGE_S3_ENDPOINT": fixture["s3_endpoint"], "EXCHANGE_S3_BUCKET": bucket,
                    "EXCHANGE_S3_PREFIX": "", "EXCHANGE_S3_REGION": "us-east-1",
                    "EXCHANGE_S3_ACCESS_KEY": fixture["s3_access_key"], "EXCHANGE_S3_SECRET_KEY": fixture["s3_secret_key"],
                    "EXCHANGE_ALLOW_LOCAL_HTTP": "true"}
                with patch.dict(os.environ, environment, clear=True):
                    arguments = ["admin", "--config", str(config), "object-store-pool-set", "--file", str(definition)]
                    for command, expected in ((["init-db"], 0), (arguments, 0)):
                        output, error = io.StringIO(), io.StringIO()
                        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                            status = main(command)
                        self.assertEqual(status, expected, error.getvalue())
                        self.assertTrue(fixture["s3_secret_key"] not in output.getvalue() + error.getvalue(),
                                        "CLI output leaked an object-store credential")
                    client.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Suspended"})
                    output, error = io.StringIO(), io.StringIO()
                    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                        self.assertEqual(main(arguments), 1)
                    database = create_database(url, initialize=False)
                    try:
                        with database.transaction(immediate=False) as session:
                            pool = session.get(Pool, "objects")
                            self.assertTrue(pool.details_json["object_store"])
                            self.assertEqual(pool.version, 1)
                            self.assertEqual(len(list(session.scalars(select(AdministrativeAudit).where(
                                AdministrativeAudit.resource_id == "objects")))), 1)
                    finally:
                        database.close()
        finally:
            try:
                client.delete_bucket(Bucket=bucket)
            finally:
                client.close()



if __name__ == "__main__":
    unittest.main()
