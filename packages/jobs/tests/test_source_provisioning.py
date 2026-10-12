"""Source authorization and crash-safe resources, including actual Git object reads."""
from __future__ import annotations
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from hf2l_jobs.database import create_database
from hf2l_jobs.domain import JobSpec, utcnow
from hf2l_jobs.models import Project, Job, Attempt, ProvisioningOperation, ApprovedSource, RuntimeImage, Pool
from hf2l_jobs.provisioning import Provisioner
from hf2l_jobs.resources import OwnedDirectories, ResourceError, ResourceLedger
from hf2l_jobs.source import SourceApproval, SourceError, SourceRegistry, RegistryCatalog, metadata_peak_bytes


def git(path, *args):
    return subprocess.check_output(["git", "-C", str(path), *args], stderr=subprocess.DEVNULL).decode().strip()


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repository = self.root / "repo"
        self.repository.mkdir()
        git(self.repository, "init", "-q")
        git(self.repository, "config", "user.name", "Source Test")
        git(self.repository, "config", "user.email", "source@example.invalid")
        (self.repository / "plugin.py").write_text("VALUE = 7\n")
        git(self.repository, "add", ".")
        git(self.repository, "commit", "-qm", "approved")
        self.commit = git(self.repository, "rev-parse", "HEAD")

    def tearDown(self):
        # Read-only snapshots deliberately need parent permissions restored for cleanup.
        for path in self.root.rglob("*"):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o700)
        self.temp.cleanup()

    def registry(self, **kwargs):
        return SourceRegistry([SourceApproval("src", frozenset({"project"}), mirror_path=self.repository,
                                             commits=frozenset({self.commit}), **kwargs)])

    def test_pinned_snapshot_has_no_history_or_executed_hooks(self):
        sentinel = self.root / "executed"
        hook = self.repository / ".git/hooks/post-checkout"
        hook.write_text("#!/bin/sh\ntouch " + str(sentinel) + "\n")
        hook.chmod(0o700)
        result = self.registry().materialize("project", "src", self.commit, self.root / "snapshot")
        self.assertFalse(sentinel.exists())
        self.assertFalse((result.path / ".git").exists())
        self.assertEqual(result.manifest, {"plugin.py": hashlib.sha256(b"VALUE = 7\n").hexdigest()})
        self.assertEqual((result.path / "plugin.py").stat().st_mode & 0o222, 0)

    def test_unapproved_commit_or_project_cannot_resolve(self):
        for project, commit in [("foreign", self.commit), ("project", "0" * 40)]:
            with self.assertRaises(SourceError):
                self.registry().materialize(project, "src", commit, self.root / "snapshot")

    def test_symlinks_and_submodules_rejected(self):
        (self.repository / "foreign").symlink_to("/etc/passwd")
        git(self.repository, "add", ".")
        git(self.repository, "commit", "-qm", "unsafe")
        self.commit = git(self.repository, "rev-parse", "HEAD")
        with self.assertRaisesRegex(SourceError, "Symlinks"):
            self.registry().materialize("project", "src", self.commit, self.root / "snapshot")

    def test_source_size_bound(self):
        with self.assertRaisesRegex(SourceError, "bytes"):
            self.registry(max_bytes=1).materialize("project", "src", self.commit, self.root / "snapshot")

    def test_ssrf_local_metadata_redirect_credentials_rejected(self):
        for url in ("http://example.invalid/repo", "file:///tmp/repo", "https://user:secret@example.invalid/repo",
                    "https://169.254.169.254/repo", "https://example.invalid/repo?redirect=x"):
            approval = SourceApproval("src", frozenset({"project"}), url=url, commits=frozenset({self.commit}))
            registry = SourceRegistry([approval], allowed_hosts=["example.invalid", "169.254.169.254"],
                resolver=lambda *args, **kwargs: [(2, 1, 6, "", ("169.254.169.254", 443))])
            with self.assertRaises(SourceError):
                registry._remote(approval)


class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.database = create_database("sqlite://")
        self.spec = JobSpec.model_validate({"project_id": "project", "name": "Example", "source_id": "source",
            "source_commit": "a" * 40, "runtime_image": "runtime", "plugin": "plugin", "components": [{
                "component_id": "owner", "role": "owner", "resources": {"pool_id": "pool", "cpu_millicores": 100,
                    "memory_bytes": 64 * 1024**2, "disk_bytes": 64 * 1024**2}}],
            "target_round": 2, "max_duration_seconds": 600})
        with self.database.transaction() as session:
            session.add(Project(id="project", name="Project"))
            session.flush()
            self.job = Job(id="job", project_id="project", creator_id="human", name="Example", spec_json=self.spec.to_dict(),
                           spec_hash=self.spec.digest, target_round=2, deadline_at=utcnow() + timedelta(seconds=600))
            session.add(self.job)
            session.flush()
            self.attempt = Attempt(id="attempt", job_id="job", number=1, epoch=1)
            session.add(self.attempt)
        self.ledger = ResourceLedger(self.database)

    def tearDown(self):
        self.database.close()
        self.temp.cleanup()

    def test_durable_unknown_operation_reuses_original_key(self):
        effects, failed = {}, [False]
        def action():
            effects.setdefault("resource", "same")
            if not failed[0]:
                failed[0] = True
                raise ConnectionError("lost acknowledgement")
            return {"resource_id": effects["resource"]}
        arguments = dict(job_id="job", attempt_id="attempt", component_id="owner",
                         operation="test", key="stable", desired={"name": "same"}, action=action)
        with self.assertRaises(ConnectionError):
            self.ledger.run(**arguments)
        self.assertEqual(self.ledger.run(**arguments), {"resource_id": "same"})
        self.assertEqual(self.ledger.run(**arguments), {"resource_id": "same"})
        self.assertEqual(len(effects), 1)
        arguments["desired"] = {"name": "changed"}
        with self.assertRaises(ResourceError):
            self.ledger.run(**arguments)

    def test_owned_paths_do_not_adopt_or_delete_foreign_job(self):
        directories = OwnedDirectories(self.root / "jobs")
        owned = directories.ensure_job("job", self.spec.digest)
        foreign = directories.ensure_job("foreign", "different")
        sentinel = foreign / "secret"
        sentinel.write_text("must survive")
        with self.assertRaises(ResourceError):
            directories.ensure_job("foreign", self.spec.digest)
        component = directories.components("job", ["owner"])["owner"]
        (component.state / "foreign-link").symlink_to(foreign, target_is_directory=True)
        directories.purge("job", self.spec.digest)
        self.assertFalse(owned.exists())
        self.assertEqual(sentinel.read_text(), "must survive")

    def test_cleanup_requires_confirmed_termination(self):
        registry = RegistryCatalog(SourceRegistry(), {})
        provisioner = Provisioner(self.database, None, registry, self.root, workload_issuer="https://workload.invalid")
        self.assertFalse(provisioner.cleanup(self.job, self.attempt))
        self.attempt.termination_confirmed = True
        self.assertTrue(provisioner.cleanup(self.job, self.attempt))

    def test_durable_catalog_revocation_applies_without_restart(self):
        mirror = self.root / "mirror"
        mirror.mkdir()
        with self.database.transaction() as session:
            session.add(ApprovedSource(id="source", project_id="project", url="", allowed_commits=["a" * 40],
                                      details_json={"mirror_path": str(mirror), "max_git_bytes": 8 * 1024**2, "max_git_files": 4096}))
            session.add(RuntimeImage(id="runtime", project_id="project", digest="sha256:" + "b" * 64))
        registry = RegistryCatalog.from_database(self.database)
        approval = registry.source_registry.authorize("project", "source", "a" * 40)
        self.assertEqual((approval.max_git_bytes, approval.max_git_files), (8 * 1024**2, 4096))
        self.assertEqual(registry.validate(self.spec), "sha256:" + "b" * 64)
        with self.database.transaction() as session:
            session.get(RuntimeImage, "runtime").enabled = False
        with self.assertRaisesRegex(SourceError, "not approved"):
            registry.validate(self.spec)


class ProvisioningHTTPTests(unittest.TestCase):
    registry = SourceTests.registry
    """Use the real SDK with recorded HTTP; no fake provisioner bypass."""
    def setUp(self):
        SourceTests.setUp(self)
        import httpx
        from hf2l_exchange.client import ExchangeClient
        from hf2l_jobs.broker import principal_id
        self.database = create_database("sqlite://")
        self.spec = JobSpec.model_validate({"project_id": "project", "name": "Example", "source_id": "src",
            "source_commit": self.commit, "runtime_image": "runtime", "plugin": "plugin",
            "participants": [{"participant_id": "alice", "dataset_binding": "synthetic"},
                             {"participant_id": "bob", "dataset_binding": "synthetic"}],
            "components": [{"component_id": "owner", "role": "owner", "resources": {"pool_id": "pool",
                "cpu_millicores": 100, "memory_bytes": 64 * 1024**2, "disk_bytes": 64 * 1024**2}}],
            "target_round": 2, "max_duration_seconds": 600})
        with self.database.transaction() as session:
            session.add(Project(id="project", name="Project"))
            session.add(Pool(id="pool", name="Pool", node_id="node", cpu_millicores=1000,
                             memory_bytes=1024**3, disk_bytes=8 * 1024**3,
                             sandbox_profiles=["runsc-cpu-v1"], healthy=True))
            session.add(Pool(id="objects", name="Object store", node_id="object-store",
                             disk_bytes=16 * 1024**3, healthy=True, details_json={"object_store": True}))
            session.flush()
            self.job = Job(id="job", project_id="project", creator_id="human", name="Example", spec_json=self.spec.to_dict(),
                           spec_hash=self.spec.digest, target_round=2, state="PROVISIONING", current_attempt=1, epoch=1,
                           deadline_at=utcnow() + timedelta(seconds=600))
            session.add(self.job)
            session.flush()
            self.attempt = Attempt(id="attempt", job_id="job", number=1, epoch=1)
            session.add(self.attempt)
        self.requests, self.grants = [], {}
        self.fail_grant_once = False
        self.cleanup_pending = False
        self.workload_issuer = "https://workloads.example.invalid"
        fixture = self
        def handler(request):
            self.requests.append(request)
            body = json.loads(request.content) if request.content else {}
            path = request.url.path
            if path == "/v2/spaces" and request.method == "POST":
                self.space_policy = {"id": "space", "name": body["name"], "profile": body["profile"],
                    "quota_bytes": body["quota_bytes"], "principal_quota_bytes": body["principal_quota_bytes"]}
                response = self.space_policy
            elif path == "/v2/spaces/space" and request.method == "GET":
                response = self.space_policy
            elif path.endswith("/managed/retire"):
                response = {"space_id": "space", "job_id": "job", "status": "retired", "cleanup_pending": self.cleanup_pending}
            elif path.endswith("/managed") and request.method == "GET":
                response = {"space_id": "space", "job_id": "job", "status": "retired", "cleanup_pending": self.cleanup_pending}
            elif path.endswith("/managed"):
                response = {"space_id": "space", "job_id": body["job_id"], "managed": True}
            elif "/types/" in path:
                response = {"id": "schema-" + path.split("/types/")[1].split("/")[0],
                            "kind": path.split("/types/")[1].split("/")[0], "schema": body["schema"], "revision": 1}
            elif "/members/" in path:
                response = {"principal_id": path.rsplit("/", 1)[-1], **body}
            elif path.endswith("/workload-grants/revoke"):
                response = {"attempt_id": body["attempt_id"], "revoked": 1, "revoked_at": 1}
            elif path.endswith("/workload-grants"):
                key = request.headers["Idempotency-Key"]
                response = self.grants.setdefault(key, {**body, "space_id": "space", "grant_id": "grant",
                    "principal_id": principal_id(self.workload_issuer, body["subject"]), "enabled": True})
                if self.fail_grant_once:
                    self.fail_grant_once = False
                    raise httpx.ReadTimeout("Synthetic lost accepted response")
            elif path.endswith("/refs/main"):
                return httpx.Response(404, json={"error": {"code": "reference_not_found"}})
            else:
                raise AssertionError(path)
            return httpx.Response(200, json=response)
        self.http = httpx.Client(transport=httpx.MockTransport(handler))
        self.exchange = ExchangeClient("https://exchange.example.invalid", "control-plane-only", http=self.http, retries=1)
        self.catalog = RegistryCatalog(self.registry(), {"runtime": "sha256:" + "b" * 64},
                                      dataset_bindings={"synthetic": {"alice", "bob"}})
        self.provisioner = Provisioner(self.database, self.exchange, self.catalog, self.root / "jobs",
            workload_issuer=self.workload_issuer, exchange_storage_pool_id="objects",
            execution_bindings=lambda job, attempt, component, space, principal: {
                "certificate_thumbprint": "a" * 43,
                "proxy_endpoint": str(self.root / "jobs" / job.id / "attempts" / attempt.id / component.component_id / "proxy.sock")})

    def prepay_blob(self):
        from hf2l_jobs.blob_budget import plan_blob_budget
        from hf2l_jobs.retention import RetentionService
        plan = plan_blob_budget(self.job, "objects", self.provisioner.ledger.resources(self.job.id, kind="exchange_blob_budget"))
        resource_id = self.provisioner.ledger.own(job_id=self.job.id, attempt_id=self.attempt.id,
            component_id=plan["component_id"], kind=plan["kind"], external_id=plan["external_id"],
            details=plan["details"], retained=True)
        RetentionService(self.database).reserve_resource(resource_id, self.job.id, plan["max_bytes"])
        return plan["max_bytes"]

    def tearDown(self):
        self.http.close()
        self.exchange.close()
        self.database.close()
        SourceTests.tearDown(self)

    def test_source_pool_limit_rejection_precedes_any_fetch(self):
        from hf2l_jobs.domain import Error
        blob_bytes = self.prepay_blob()
        with self.database.transaction() as session:
            session.get(Pool, "pool").disk_bytes = 8
        with self.assertRaises(Error) as captured:
            self.prepay_blob()
            self.provisioner.ensure(self.job, self.attempt)
        self.assertEqual(captured.exception.code, "retained_pool_storage_unavailable")
        self.assertFalse((self.provisioner.root / self.job.id / "source").exists())
        self.assertEqual(self.requests, [])
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.get(Project, "project").retained_bytes, blob_bytes)

    def test_source_quota_rejection_precedes_any_fetch_or_retained_bytes(self):
        from hf2l_jobs.domain import Error
        blob_bytes = self.prepay_blob()
        with self.database.transaction() as session:
            session.get(Project, "project").quotas_json = {"retained_bytes": blob_bytes + 8}
        with self.assertRaises(Error) as captured:
            self.prepay_blob()
            self.provisioner.ensure(self.job, self.attempt)
        self.assertEqual(captured.exception.code, "retained_storage_quota_exceeded")
        self.assertFalse((self.provisioner.root / self.job.id / "source").exists())
        self.assertFalse((self.provisioner.root / self.job.id / ".source.json").exists())
        self.assertEqual(self.requests, [])
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.get(Project, "project").retained_bytes, blob_bytes)

    def test_failed_fetch_keeps_reserved_source_charge_until_owned_cleanup(self):
        from hf2l_jobs.retention import RetentionService
        def fail(*args, **kwargs):
            raise SourceError("Injected bounded fetch failure")
        self.catalog.source_registry.materialize = fail
        blob_bytes = self.prepay_blob()
        with self.assertRaises(SourceError):
            self.provisioner.ensure(self.job, self.attempt)
        approval = self.catalog.source_registry.authorize("project", "src", self.commit)
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.get(Project, "project").retained_bytes,
                             blob_bytes + approval.max_bytes + metadata_peak_bytes(approval))
        source = self.provisioner.ledger.resources("job", kind="source")[0]
        self.assertEqual(source["size_bytes"], approval.max_bytes +
                         metadata_peak_bytes(approval))
        self.assertEqual(source["details"]["pool_id"], "pool")
        self.job.state = "FAILED"
        with self.database.transaction() as session:
            session.get(Job, "job").state = "FAILED"
        self.assertTrue(self.provisioner.purge_job(self.job))
        RetentionService(self.database).confirm_job_data_deleted("job")
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.get(Project, "project").retained_bytes, 0)

    def test_external_cleanup_needs_authoritative_node_receipt_before_retirement(self):
        blob_bytes = self.prepay_blob()
        self.provisioner.ensure(self.job, self.attempt)
        self.job.state = "FAILED"
        with self.database.transaction() as session:
            session.get(Job, self.job.id).state = "FAILED"
        self.provisioner.ledger.own(job_id=self.job.id, attempt_id=self.attempt.id,
            component_id="participant-external", kind="external_enrollment",
            external_id="owned-node-enrollment", retained=True)
        self.assertFalse(self.provisioner.purge_job(self.job))
        self.assertTrue((self.provisioner.root / self.job.id / "source").exists())
        self.assertFalse(any(request.url.path.endswith("/managed/retire") for request in self.requests))
        self.provisioner.external_cleanup = lambda job: False
        self.assertFalse(self.provisioner.expire_artifacts(self.job))
        self.assertTrue((self.provisioner.root / self.job.id / "source").exists())
        calls = []
        self.provisioner.external_cleanup = lambda job: calls.append(job.id) or True
        self.assertTrue(self.provisioner.expire_artifacts(self.job))
        self.assertEqual(calls, [self.job.id])
        self.assertFalse((self.provisioner.root / self.job.id).exists())

    def test_oversized_worker_metadata_is_rejected_before_file_write(self):
        path = self.root / "runtime.json"
        path.write_bytes(b"previous verified configuration")
        from hf2l_jobs.resources import ResourceError
        with self.assertRaises(ResourceError):
            self.provisioner._write_worker_config(path, {"source_manifest": {
                "file.py": "x" * (2 * 1024**2)}})
        self.assertEqual(path.read_bytes(), b"previous verified configuration")
        self.assertFalse(list(self.root.glob("runtime.json.tmp-*")))
        self.provisioner._write_worker_config(path, {"schema_version": 1})
        self.assertEqual(json.loads(path.read_bytes()), {"schema_version": 1})
        self.assertEqual(path.stat().st_mode & 0o777, 0o400)

    def test_real_sdk_managed_resources_and_repeat_are_idempotent(self):
        blob_bytes = self.prepay_blob()
        plan = self.provisioner.plan(self.job, self.attempt)
        self.assertEqual(self.requests, [])
        bundle = self.provisioner.ensure(self.job, self.attempt)
        request_count = len(self.requests)
        repeated = self.provisioner.ensure(self.job, self.attempt)
        self.assertEqual(repeated.space_id, bundle.space_id)
        self.assertEqual(len(self.grants), 1)
        self.assertEqual(len(self.requests), request_count + 2)  # space policy and current main refreshed
        self.assertEqual(plan.component_specs["owner"].proxy_endpoint, bundle.component_specs["owner"].proxy_endpoint)
        self.assertEqual(plan.component_specs["owner"].config_path, bundle.component_specs["owner"].config_path)
        prepared = self.provisioner.prepared_component(self.job, self.attempt, "owner")
        self.assertEqual(set(prepared["participant_principals"]), {"alice", "bob"})
        self.assertEqual(prepared["source_manifest"], {"plugin.py": hashlib.sha256(b"VALUE = 7\n").hexdigest()})
        self.assertNotIn("control-plane-only", json.dumps(prepared))
        with self.database.transaction(immediate=False) as session:
            measured = self.provisioner.ledger.resources("job", kind="source")[0]["size_bytes"]
            self.assertEqual(session.get(Project, "project").retained_bytes, measured + blob_bytes)
            self.assertGreaterEqual(measured, len(b"VALUE = 7\n"))

    def test_lost_grant_response_adopts_same_idempotent_grant(self):
        blob_bytes = self.prepay_blob()
        self.fail_grant_once = True
        with self.assertRaises(Exception):
            self.provisioner.ensure(self.job, self.attempt)
        bundle = self.provisioner.ensure(self.job, self.attempt)
        self.assertEqual(len(self.grants), 1)
        self.assertEqual(bundle.workload_grants["owner"]["grant_id"], "grant")

    def test_retirement_waits_for_physical_cleanup_keeps_provenance(self):
        blob_bytes = self.prepay_blob()
        self.provisioner.ensure(self.job, self.attempt)
        self.attempt.termination_confirmed = True
        self.assertTrue(self.provisioner.cleanup(self.job, self.attempt))
        self.job.state = "CANCELLED"
        with self.database.transaction() as session:
            session.get(Job, self.job.id).state = "CANCELLED"
        self.cleanup_pending = True
        self.assertFalse(self.provisioner.purge_job(self.job))
        self.assertTrue((self.root / "jobs/job/source").exists())
        self.cleanup_pending = False
        self.assertTrue(self.provisioner.purge_job(self.job))
        self.assertFalse((self.root / "jobs/job").exists())
        resources = self.provisioner.ledger.resources("job", kind="exchange_space")
        self.assertEqual(resources[0]["state"], "retired")


if __name__ == "__main__":
    unittest.main()
