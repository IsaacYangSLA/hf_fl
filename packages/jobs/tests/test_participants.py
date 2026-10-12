"""External participant isolation, HTTP authority, CSR, and durable node lifecycle.

Uses real manager SQL, broker verification, node ledger, materializer, central
CSR issuer, and Unix proxy. HTTP peer evidence and execution are deterministic
fixtures; these tests do not claim real TLS or OCI sandbox qualification.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import subprocess
from types import SimpleNamespace
import unittest

from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import func, select

from hf2l_jobs import models
from hf2l_jobs.application import Manager
from hf2l_jobs.broker import BrokerError, BrokerSettings, WorkloadBroker, principal_id
from hf2l_jobs.collection import CollectionError
from hf2l_jobs.database import create_database
from hf2l_jobs.domain import Error, JobSpec
from hf2l_jobs.participants import (ApprovedExternalNode, ExternalParticipantService,
    ExternalParticipantAgent, ExternalManagerClient, create_participant_node_app)
from hf2l_jobs.resources import stable_key
from hf2l_jobs.source import RegistryCatalog, SourceApproval, SourceRegistry
from hf2l_jobs.workflow import DatasetBinding, RuntimeConfig


def certificate(name):
    return base64.urlsafe_b64encode(hashlib.sha256(name.encode()).digest()).decode().rstrip("=")


class RecordedExchange:
    """Trusted grant adapter fixture, retaining immutable request receipts."""
    def __init__(self, issuer):
        self.issuer = issuer
        self.grants = {}
        self.calls = []

    @staticmethod
    def path(space_id, suffix=""):
        return "/v2/spaces/" + space_id + suffix

    def request(self, method, target, *, body=None, headers=None):
        self.calls.append((method, target, body, headers))
        if method == "POST" and target.endswith("/workload-grants"):
            identity = hashlib.sha256(headers["Idempotency-Key"].encode()).hexdigest()
            grant = {**body, "space_id": target.split("/")[3], "grant_id": identity,
                     "principal_id": principal_id(self.issuer, body["subject"]), "enabled": True}
            previous = self.grants.setdefault(identity, grant)
            if previous != grant:
                raise AssertionError("Immutable grant request changed")
            return dict(previous)
        if method == "GET" and "/workload-grants/" in target:
            return dict(self.grants[target.rsplit("/", 1)[-1]])
        raise AssertionError((method, target))


class ExternalParticipantFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hf2l-external-participants-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database_url = "sqlite:///" + str(self.root / "manager.sqlite")
        self.database = self.fixture_database(self.database_url)
        self.addCleanup(lambda: self.database.close())
        self.now = datetime.now(timezone.utc)
        self.manager = Manager(self.database, b"fixture-pagination-secret-32-bytes", clock=lambda: self.now)
        self.node_certificate = certificate("trusted external node")
        self.execution_certificate = certificate("alice private execution")
        self.broker = WorkloadBroker(BrokerSettings("https://workloads.example.test", "exchange-managed",
            "hf2l-transfer", "hf2l-nodes", self.signing_key.public_key(), self.signing_key,
            key_id="fixture-broker"), clock=lambda: self.now.timestamp())
        mirror = self.root / "approved-mirror"
        mirror.mkdir()
        with self.database.transaction() as session:
            session.add(models.Project(id="project", name="Project"))
            session.flush()
            session.add_all([models.ProjectMember(project_id="project", principal_id="alice", role="submitter"),
                             models.ProjectMember(project_id="project", principal_id="bob", role="submitter")])
            session.add(models.ApprovedSource(id="source", project_id="project", url="",
                allowed_commits=["a" * 40], details_json={"mirror_path": str(mirror)}))
            session.add(models.RuntimeImage(id="runtime", project_id="project", digest="sha256:" + "b" * 64))
            session.add(models.Pool(id="cpu", name="CPU", node_id="server-node", cpu_millicores=4000,
                memory_bytes=8 << 30, disk_bytes=8 << 30, healthy=True, sandbox_profiles=["runsc-cpu-v1"]))
            for participant in ("alice", "bob"):
                session.add(models.ParticipantBinding(id="data-" + participant, project_id="project",
                    participant_id=participant, node_id="external-node", dataset_label="Approved " + participant))
        self.exchange = RecordedExchange(self.broker.settings.workload_issuer)
        self.provisioner = SimpleNamespace(root=self.root / "owned-jobs", exchange=self.exchange,
            registry=RegistryCatalog.from_database(self.database), _space_id=lambda job_id: "space-" + job_id)
        self.node = ApprovedExternalNode("external-node", self.node_certificate,
            {"data-alice": DatasetBinding(kind="npz", path="/job/data/alice.npz"),
             "data-bob": DatasetBinding(kind="synthetic")},
            resources={"cpu_millicores": 500, "memory_bytes": 128 << 20, "disk_bytes": 256 << 20})
        self.service = ExternalParticipantService(self.manager, self.provisioner, self.broker, [self.node])
        self.job = self.new_job()

    def fixture_database(self, url):
        return create_database(url)

    def spec(self):
        return {"project_id": "project", "name": "External job", "source_id": "source", "source_commit": "a" * 40,
            "runtime_image": "runtime", "plugin": "plugin", "target_round": 2, "max_duration_seconds": 3600,
            "participants": [{"participant_id": name, "dataset_binding": "data-" + name, "mode": "external"}
                             for name in ("alice", "bob")],
            "components": [{"component_id": "owner", "role": "owner", "resources": {
                "pool_id": "cpu", "cpu_millicores": 1000, "memory_bytes": 1 << 30, "disk_bytes": 1 << 30}}]}

    def new_job(self, actor="alice", key="job-a"):
        job = self.manager.create_job(actor, self.spec(), key)
        path = self.provisioner.root / job["id"]
        (path / "source").mkdir(parents=True)
        content = b"VALUE = 7\n"
        (path / "source" / "plugin.py").write_bytes(content)
        self.manifest = {"plugin.py": hashlib.sha256(content).hexdigest()}
        (path / ".source.json").write_text(json.dumps({"source_id": "source", "commit": "a" * 40,
                                                       "manifest": self.manifest}))
        return job

    def enroll(self, participant="alice", *, job=None, actor="alice", key="enroll", expected=None):
        job = job or self.job
        version = self.manager.get_job(actor, job["id"])["version"] if expected is None else expected
        return self.service.enroll(actor, job["id"], participant, "external-node", version, key)

    def activate(self, job=None, *, log_budget_bytes=1024**2):
        job = job or self.job
        with self.database.transaction() as session:
            row = session.get(models.Job, job["id"])
            row.state, row.epoch = "RUNNING", 1
            row.deadline_at = self.now + timedelta(seconds=3600)
            attempt = session.scalar(select(models.Attempt).where(models.Attempt.job_id == row.id,
                                                                 models.Attempt.number == 1))
            attempt.state = "RUNNING"
        self.reserve_log_budgets(job=job, attempt_number=1, max_bytes=log_budget_bytes)

    def reserve_log_budgets(self, *, job=None, attempt_number=None, max_bytes=1024**2):
        """Model scheduler admission through the real ownership/retention ledger."""
        from hf2l_jobs.resources import ResourceLedger
        from hf2l_jobs.retention import RetentionService
        job = job or self.job
        with self.database.transaction(immediate=False) as session:
            row = session.get(models.Job, job["id"])
            spec = JobSpec.model_validate(row.spec_json)
            number = row.current_attempt if attempt_number is None else attempt_number
            attempt = session.scalar(select(models.Attempt).where(
                models.Attempt.job_id == row.id, models.Attempt.number == number))
            attempt_id = attempt.id
        budgets = {}
        for participant in spec.participants:
            if participant.mode != "external":
                continue
            component = self.service.component_id(participant.participant_id)
            amount = max_bytes
            resource_id = ResourceLedger(self.database).own(job_id=job["id"], attempt_id=attempt_id,
                component_id=component, kind="log_budget",
                external_id="hf2l-log://" + job["id"] + "/" + str(number) + "/" + component,
                details={"spec_digest": spec.digest, "pool_id": "cpu", "component_id": component,
                         "attempt_number": number, "reservation_max_bytes": amount})
            RetentionService(self.database).reserve_resource(resource_id, job["id"], amount)
            budgets[participant.participant_id] = resource_id
        return budgets

    def node_actor(self, enrollment):
        document = self.service.bootstrap_credentials(enrollment["id"])
        actor = self.broker.authenticate_node("Bearer " + document["node_token"],
            verified_peer_thumbprint=self.node_certificate, grant_validator=self.service.check_node_grant)
        return actor, document

    def assigned(self, participant="alice", *, job=None, execution_certificate=None):
        enrollment = self.enroll(participant, job=job, key="enroll-" + participant)
        self.activate(job)
        actor, bootstrap = self.node_actor(enrollment)
        assignment = self.service.assignment(actor,
            execution_certificate_thumbprint=execution_certificate or self.execution_certificate,
            proxy_id="proxy-" + participant)
        return enrollment, actor, assignment

    def assert_error(self, status, code, function, *args, **kwargs):
        with self.assertRaises(Error) as caught:
            function(*args, **kwargs)
        self.assertEqual((caught.exception.status, caught.exception.code), (status, code))


class ExternalPrepaidBudgetTests(ExternalParticipantFixture):
    def prepared(self, *, amount=1024**2):
        enrollment = self.enroll()
        self.activate(log_budget_bytes=amount)
        return enrollment, self.reserve_log_budgets(max_bytes=amount)["alice"]

    def assert_budget_denied_without_dispatch_effects(self, enrollment):
        from unittest.mock import patch
        with self.database.transaction(immediate=False) as session:
            before = dict(session.get(models.ProvisioningResource, enrollment["id"]).details_json)
            before_charge = session.get(models.Project, "project").retained_bytes
        dispatched = []
        self.service.node_dispatch = lambda node, document: dispatched.append(document)
        with patch.object(self.broker, "issue_node", wraps=self.broker.issue_node) as issue_node:
            self.assert_error(409, "participant_log_budget_unavailable", self.service.bootstrap_credentials, enrollment["id"])
            self.service.dispatch_pending()
            issue_node.assert_not_called()
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.get(models.ProvisioningResource, enrollment["id"]).details_json, before)
            self.assertEqual(session.get(models.Project, "project").retained_bytes, before_charge)
            self.assertEqual(session.scalar(select(func.count()).select_from(models.ProvisioningResource).where(
                models.ProvisioningResource.kind == "external_execution")), 0)
            self.assertEqual(session.scalar(select(func.count()).select_from(models.Allocation)), 0)
        self.assertEqual(dispatched, [])
        self.assertEqual(self.exchange.grants, {})

    def test_missing_prepaid_budget_blocks_bootstrap_and_dispatch_before_history_or_token(self):
        enrollment, budget_id = self.prepared()
        with self.database.transaction() as session:
            session.delete(session.get(models.ProvisioningResource, budget_id))
        self.assert_budget_denied_without_dispatch_effects(enrollment)

    def test_foreign_ownership_attempt_spec_and_pool_budget_cannot_be_adopted(self):
        enrollment, budget_id = self.prepared()
        with self.database.transaction() as session:
            session.add(models.Attempt(id="foreign-attempt", job_id=self.job["id"], number=2, epoch=2, state="QUEUED"))
            session.add(models.Pool(id="foreign-pool", name="Foreign", node_id="other-manager", cpu_millicores=4000,
                memory_bytes=8 << 30, disk_bytes=8 << 30, healthy=True, sandbox_profiles=["runsc-cpu-v1"]))
            row = session.get(models.ProvisioningResource, budget_id)
            original = {"component_id": row.component_id, "attempt_id": row.attempt_id,
                        "ownership_json": dict(row.ownership_json), "details_json": dict(row.details_json)}
        patches = [{"ownership_json": {**original["ownership_json"], "job_id": "foreign-job"}},
                   {"component_id": self.service.component_id("bob")}, {"attempt_id": "foreign-attempt"},
                   {"details_json": {**original["details_json"], "spec_digest": "0" * 64}},
                   {"details_json": {**original["details_json"], "attempt_number": 2}},
                   {"details_json": {**original["details_json"], "pool_id": "foreign-pool"}}]
        for change in patches:
            with self.database.transaction() as session:
                row = session.get(models.ProvisioningResource, budget_id)
                for name, value in {**original, **change}.items():
                    setattr(row, name, dict(value) if isinstance(value, dict) else value)
            with self.subTest(change=change):
                self.assert_budget_denied_without_dispatch_effects(enrollment)

    def test_released_deleted_and_unretained_budgets_cannot_dispatch_runtime(self):
        enrollment, budget_id = self.prepared()
        with self.database.transaction(immediate=False) as session:
            details = dict(session.get(models.ProvisioningResource, budget_id).details_json)
        for change in ({"details_json": {**details, "retention_charge_released": True}},
                       {"state": "deleted"}, {"deleted_at": self.now}, {"retained": False}):
            with self.database.transaction() as session:
                row = session.get(models.ProvisioningResource, budget_id)
                for name, value in {"details_json": dict(details), "state": "ready", "deleted_at": None,
                                    "retained": True, **change}.items():
                    setattr(row, name, value)
            with self.subTest(change=change):
                self.assert_budget_denied_without_dispatch_effects(enrollment)

    def test_consistently_charged_short_budget_is_insufficient_for_participant_dispatch(self):
        enrollment, budget_id = self.prepared(amount=512 * 1024)
        with self.database.transaction(immediate=False) as session:
            row = session.get(models.ProvisioningResource, budget_id)
            self.assertEqual(row.size_bytes, 512 * 1024)
            self.assertEqual(row.details_json["retention_charged_bytes"], 512 * 1024)
            self.assertEqual(session.get(models.Project, "project").retained_bytes, 1024**2)
        self.assert_budget_denied_without_dispatch_effects(enrollment)

    def test_claimed_budget_without_full_retention_charge_is_rejected_before_dispatch(self):
        enrollment, budget_id = self.prepared()
        with self.database.transaction(immediate=False) as session:
            details = dict(session.get(models.ProvisioningResource, budget_id).details_json)
        for name in ("retention_charged_bytes", "retention_reservation_bytes", "reservation_max_bytes"):
            with self.database.transaction() as session:
                row = session.get(models.ProvisioningResource, budget_id)
                row.details_json = {**details, name: 0}
            with self.subTest(name=name):
                self.assert_budget_denied_without_dispatch_effects(enrollment)

    def test_repeated_bootstrap_binds_the_prepaid_ledger_without_extra_storage_charge(self):
        enrollment, budget_id = self.prepared()
        for _ in range(3):
            document = self.service.bootstrap_credentials(enrollment["id"])
            self.assertEqual(document["operation"], "start")
        with self.database.transaction(immediate=False) as session:
            resource = session.get(models.ProvisioningResource, enrollment["id"])
            historical = session.get(models.ProvisioningResource, resource.details_json["external_execution_id"])
            self.assertEqual(resource.details_json["log_resource_id"], budget_id)
            self.assertEqual(historical.details_json["log_resource_id"], budget_id)
            self.assertEqual(session.get(models.Project, "project").retained_bytes, 2 * 1024**2)
            self.assertEqual(session.scalar(select(func.count()).select_from(models.ProvisioningResource).where(
                models.ProvisioningResource.kind == "log_budget")), 2)
            self.assertEqual(session.scalar(select(func.count()).select_from(models.ProvisioningResource).where(
                models.ProvisioningResource.kind == "external_execution")), 1)


class ExternalEnrollmentTests(ExternalParticipantFixture):
    def test_enrollment_exposes_no_credentials_and_allocates_no_server_capacity(self):
        result = self.enroll()
        self.assertTrue(result["external"])
        self.assertFalse(result["manager_allocation"])
        self.assertEqual(result["version"], 2)
        self.assertNotIn("node_token", json.dumps(result))
        self.assertNotIn("exchange_token", json.dumps(result))
        self.assertEqual(self.manager.get_job("alice", self.job["id"])["resource_summary"]["cpu_millicores"], 1000)
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(models.Allocation)), 0)
            self.assertEqual(session.scalar(select(func.count()).select_from(models.ProvisioningResource)), 1)

    def test_enrollment_requires_current_job_operator_role(self):
        self.assert_error(404, "job_not_found", self.service.enroll,
                          "bob", self.job["id"], "alice", "external-node", 1, "forbidden")
        self.manager.put_member("alice", self.job["id"], "bob", "reader", 1, "reader")
        self.assert_error(403, "job_role_required", self.service.enroll,
                          "bob", self.job["id"], "alice", "external-node", 2, "reader-enroll")

    def test_queued_enrollment_is_durable_and_idempotent_across_service_restart(self):
        first = self.enroll(expected=1)
        self.assertEqual(self.enroll(expected=1), first)
        self.assert_error(409, "idempotency_conflict", self.service.enroll,
                          "alice", self.job["id"], "bob", "external-node", 2, "enroll")
        self.database.close()
        self.database = create_database(self.database_url)
        self.manager = Manager(self.database, b"fixture-pagination-secret-32-bytes", clock=lambda: self.now)
        self.provisioner.registry = RegistryCatalog.from_database(self.database)
        self.service = ExternalParticipantService(self.manager, self.provisioner, self.broker, [self.node])
        self.assertEqual(self.service.get_enrollment("alice", self.job["id"], "alice"), first)
        self.assertEqual(self.enroll(expected=1), first)
        self.assert_error(409, "participant_assignment_not_ready", self.service.bootstrap_credentials, first["id"])

    def test_cached_enrollment_replay_rechecks_current_job_membership(self):
        self.enroll()
        with self.database.transaction() as session:
            session.add(models.JobMember(job_id=self.job["id"], principal_id="bob", role="admin"))
            session.delete(session.get(models.JobMember, (self.job["id"], "alice")))
        self.assert_error(404, "job_not_found", self.service.enroll,
                          "alice", self.job["id"], "alice", "external-node", 1, "enroll")
        self.assert_error(404, "job_not_found", self.service.get_enrollment,
                          "alice", self.job["id"], "alice")

    def test_binding_must_match_current_project_participant_node_and_enabled_approval(self):
        patches = ({"node_id": None}, {"node_id": "other-node"}, {"participant_id": "other-participant"},
                   {"enabled": False})
        for patch in patches:
            with self.database.transaction() as session:
                binding = session.get(models.ParticipantBinding, "data-alice")
                for name, value in patch.items():
                    setattr(binding, name, value)
            with self.subTest(patch=patch):
                self.assert_error(403, "external_node_not_approved", self.service.enroll,
                                  "alice", self.job["id"], "alice", "external-node", 1, "bad")
            with self.database.transaction() as session:
                binding = session.get(models.ParticipantBinding, "data-alice")
                binding.node_id, binding.participant_id, binding.enabled = "external-node", "alice", True
        with self.database.transaction() as session:
            session.add(models.Project(id="foreign", name="Foreign"))
            session.flush()
            session.get(models.ParticipantBinding, "data-alice").project_id = "foreign"
        self.assert_error(403, "external_node_not_approved", self.service.enroll,
                          "alice", self.job["id"], "alice", "external-node", 1, "foreign")

    def test_node_local_dataset_approval_is_required_and_may_be_revoked(self):
        for node in (replace(self.node, enabled=False),
                     replace(self.node, dataset_bindings={"data-bob": DatasetBinding(kind="synthetic")})):
            self.service.nodes["external-node"] = node
            self.assert_error(403, "external_node_not_approved", self.service.enroll,
                              "alice", self.job["id"], "alice", "external-node", 1, "missing-local-approval")

    def test_enrollment_rejects_unknown_participants_and_stale_job_version(self):
        self.assert_error(404, "participant_not_found", self.service.enroll,
                          "alice", self.job["id"], "unknown", "external-node", 1, "unknown")
        self.assert_error(409, "job_version_conflict", self.service.enroll,
                          "alice", self.job["id"], "alice", "external-node", 99, "stale")
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(models.ProvisioningResource)), 0)

    def test_expired_or_terminal_jobs_cannot_enroll_new_participants(self):
        with self.database.transaction() as session:
            job = session.get(models.Job, self.job["id"])
            job.deadline_at = self.now
        self.assert_error(409, "job_not_enrollable", self.service.enroll,
                          "alice", self.job["id"], "alice", "external-node", 1, "expired")
        with self.database.transaction() as session:
            job = session.get(models.Job, self.job["id"])
            job.deadline_at, job.state = None, "SUCCEEDED"
        self.assert_error(409, "job_not_enrollable", self.service.enroll,
                          "alice", self.job["id"], "alice", "external-node", 1, "terminal")

    def test_external_dataset_binding_requires_explicit_node_at_job_admission(self):
        with self.database.transaction() as session:
            session.get(models.ParticipantBinding, "data-alice").node_id = None
        self.assert_error(422, "participant_binding_not_approved", self.manager.create_job,
                          "alice", self.spec(), "missing-node")

    def test_enrollment_node_certificate_binding_is_immutable(self):
        self.enroll()
        self.service.nodes["external-node"] = replace(self.node, certificate_thumbprint=certificate("rotated node"))
        self.assert_error(409, "external_node_binding_immutable", self.service.enroll,
                          "alice", self.job["id"], "alice", "external-node", 2, "replace-node")


class ExternalAssignmentTests(ExternalParticipantFixture):
    def test_assignment_fixes_private_runtime_dataset_image_and_resources(self):
        enrollment, actor, assignment = self.assigned()
        config = RuntimeConfig.model_validate(assignment["runtime_config"])
        self.assertEqual(config.role, "client")
        self.assertEqual(config.job_id, self.job["id"])
        self.assertEqual(config.spec.runtime_image, "sha256:" + "b" * 64)
        self.assertEqual(config.participant_id, "alice")
        self.assertEqual(set(config.dataset_bindings), {"data-alice"})
        self.assertEqual(config.dataset_bindings["data-alice"].path, "/job/data/alice.npz")
        self.assertEqual(config.source_manifest, self.manifest)
        self.assertEqual(assignment["image_digest"], "sha256:" + "b" * 64)
        self.assertEqual(assignment["resources"], dict(self.node.resources))
        self.assertEqual(assignment["grant"]["roles"], ["reader", "contributor"])
        self.assertEqual(assignment["grant"]["bindings"], {"participant": "alice"})
        self.assertEqual(assignment["grant"]["certificate_thumbprint"], self.execution_certificate)
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(config.spec_digest, session.get(models.Job, self.job["id"]).spec_hash)
            self.assertEqual(session.scalar(select(func.count()).select_from(models.Allocation)), 0)

    def test_workload_tokens_are_execution_bound_with_separate_exchange_gateway_audiences(self):
        _, actor, assignment = self.assigned()
        credentials = assignment["credentials"]
        for audience, field in (("exchange", "exchange_token"), ("gateway", "gateway_token")):
            principal = self.broker.authenticate_workload("Bearer " + credentials[field], audience=audience,
                            verified_peer_thumbprint=self.execution_certificate)
            self.assertEqual(principal.job_id, self.job["id"])
            self.assertEqual(principal.participant_id, "alice")
            self.assertEqual(principal.grant_id, assignment["grant"]["grant_id"])
            self.assertLessEqual(principal.expires_at - principal.issued_at, 300)
            with self.assertRaises(BrokerError):
                self.broker.authenticate_workload("Bearer " + credentials[field], audience=audience,
                                                  verified_peer_thumbprint=self.node_certificate)
        with self.assertRaises(BrokerError):
            self.broker.authenticate_workload("Bearer " + credentials["gateway_token"],
                                              verified_peer_thumbprint=self.execution_certificate)

    def test_node_bootstrap_tokens_require_the_current_node_certificate_and_ledger(self):
        enrollment = self.enroll()
        self.activate()
        actor, document = self.node_actor(enrollment)
        self.assertEqual(actor.pool_id, "external")
        self.assertEqual(actor.scopes, frozenset({"assignment", "heartbeat", "stopped", "logs", "collect"}))
        with self.assertRaises(BrokerError):
            self.broker.authenticate_node("Bearer " + document["node_token"],
                verified_peer_thumbprint=certificate("copied other node"), grant_validator=self.service.check_node_grant)
        self.now += timedelta(seconds=301)
        with self.assertRaises(BrokerError):
            self.broker.authenticate_node("Bearer " + document["node_token"],
                verified_peer_thumbprint=self.node_certificate, grant_validator=self.service.check_node_grant)

    def test_execution_certificate_cannot_equal_shared_node_identity(self):
        enrollment = self.enroll()
        self.activate()
        actor, _ = self.node_actor(enrollment)
        self.assert_error(403, "execution_certificate_required", self.service.assignment, actor,
                          execution_certificate_thumbprint=self.node_certificate, proxy_id="proxy-alice")

    def test_each_participant_execution_requires_a_distinct_certificate(self):
        self.assigned()
        other = self.enroll("bob", key="bob-enroll")
        actor, _ = self.node_actor(other)
        self.assert_error(409, "execution_certificate_already_bound", self.service.assignment, actor,
                          execution_certificate_thumbprint=self.execution_certificate, proxy_id="proxy-bob")
        assigned = self.service.assignment(actor, execution_certificate_thumbprint=certificate("bob execution"),
                                          proxy_id="proxy-bob")
        self.assertEqual(assigned["runtime_config"]["participant_id"], "bob")
        self.assertNotEqual(assigned["grant"]["principal_id"], self.exchange.grants[next(iter(self.exchange.grants))]["principal_id"])

    def test_assignment_is_idempotent_and_execution_proxy_binding_cannot_change(self):
        _, actor, first = self.assigned()
        self.now += timedelta(seconds=15)
        repeated = self.service.assignment(actor, execution_certificate_thumbprint=self.execution_certificate,
                                           proxy_id="proxy-alice")
        self.assertEqual(repeated["grant"], first["grant"])
        self.assertEqual(repeated["runtime_config"], first["runtime_config"])
        self.assertEqual(sum(method == "POST" for method, *_ in self.exchange.calls), 1)
        self.assert_error(409, "participant_execution_binding_immutable", self.service.assignment, actor,
                          execution_certificate_thumbprint=certificate("substituted execution"), proxy_id="proxy-alice")
        self.assert_error(409, "participant_execution_binding_immutable", self.service.assignment, actor,
                          execution_certificate_thumbprint=self.execution_certificate, proxy_id="foreign-proxy")

    def test_same_human_jobs_still_have_disjoint_node_and_workload_authority(self):
        _, first_actor, first = self.assigned()
        second_job = self.new_job(key="job-b")
        _, second_actor, second = self.assigned(job=second_job, execution_certificate=certificate("second job execution"))
        self.assertNotEqual(first_actor.grant_id, second_actor.grant_id)
        self.assertNotEqual(first["grant"]["principal_id"], second["grant"]["principal_id"])
        self.assertNotEqual(first["grant"]["space_id"], second["grant"]["space_id"])
        foreign_actor = replace(first_actor, job_id=second_actor.job_id, attempt_id=second_actor.attempt_id)
        self.assertFalse(self.service.check_node_grant(foreign_actor))
        self.assert_error(404, "participant_assignment_not_found", self.service.assignment, foreign_actor,
                          execution_certificate_thumbprint=self.execution_certificate, proxy_id="foreign")
        with self.assertRaises(BrokerError):
            self.broker.authenticate_workload("Bearer " + second["credentials"]["exchange_token"],
                                              verified_peer_thumbprint=self.execution_certificate)

    def test_assignment_requires_scope_and_cannot_outlive_job_deadline(self):
        enrollment = self.enroll()
        self.activate()
        actor, _ = self.node_actor(enrollment)
        self.assert_error(403, "node_scope_required", self.service.assignment,
                          replace(actor, scopes=frozenset({"stopped"})),
                          execution_certificate_thumbprint=self.execution_certificate, proxy_id="proxy")
        self.now += timedelta(seconds=3601)
        self.assert_error(404, "participant_assignment_not_found", self.service.assignment, actor,
                          execution_certificate_thumbprint=self.execution_certificate, proxy_id="proxy")

    def test_fresh_credentials_stop_when_exchange_grant_is_revoked_or_expired(self):
        _, actor, assignment = self.assigned()
        grant = self.exchange.grants[assignment["grant"]["grant_id"]]
        grant["enabled"] = False
        self.assert_error(401, "participant_grant_revoked", self.service.credentials, actor)
        grant["enabled"] = True
        grant["expires_at"] = self.now.timestamp()
        self.assert_error(401, "participant_grant_revoked", self.service.credentials, actor)

    def test_takeover_waits_for_previous_termination_and_revocation_before_rotating_epoch(self):
        enrollment, old_actor, assigned = self.assigned()
        with self.database.transaction() as session:
            job = session.get(models.Job, self.job["id"])
            previous = session.get(models.Attempt, old_actor.attempt_id)
            previous.state = "RECONCILING"
            job.current_attempt, job.epoch = 2, 2
            session.add(models.Attempt(job_id=job.id, number=2, epoch=2, state="RUNNING"))
        self.reserve_log_budgets(attempt_number=2)
        self.assert_error(409, "previous_participant_termination_unconfirmed", self.service.bootstrap_credentials,
                          enrollment["id"])
        with self.database.transaction() as session:
            resource = session.get(models.ProvisioningResource, enrollment["id"])
            resource.details_json = {**resource.details_json, "termination_confirmed": True}
        self.assert_error(409, "previous_participant_revocation_unconfirmed", self.service.bootstrap_credentials,
                          enrollment["id"])
        with self.database.transaction() as session:
            session.get(models.Attempt, old_actor.attempt_id).revocation_confirmed = True
        actor, _ = self.node_actor(enrollment)
        self.assertEqual(actor.epoch, 2)
        self.assertFalse(self.service.check_node_grant(old_actor))
        self.assertTrue(self.service.check_node_grant(actor))
        self.assert_error(409, "participant_assignment_not_ready", self.service.credentials, actor)

    def test_confirmed_stopped_execution_cannot_reopen_or_fetch_source_in_same_attempt(self):
        _, actor, _ = self.assigned()
        self.service.confirm_stopped(actor)
        self.assertFalse(self.service.source_access_valid(actor))
        self.assert_error(404, "participant_assignment_not_found", self.service.assignment, actor,
                          execution_certificate_thumbprint=self.execution_certificate, proxy_id="proxy-alice")
        self.assert_error(404, "participant_assignment_not_found", self.service.open_source, actor, "plugin.py")

    def test_assignment_retry_keeps_first_grant_expiry_when_no_deadline_is_available(self):
        enrollment = self.enroll()
        self.activate()
        with self.database.transaction() as session:
            session.get(models.Job, self.job["id"]).deadline_at = None
        actor, _ = self.node_actor(enrollment)
        first = self.service.assignment(actor, execution_certificate_thumbprint=self.execution_certificate,
                                        proxy_id="proxy-alice")
        self.now += timedelta(seconds=15)
        repeated = self.service.assignment(actor, execution_certificate_thumbprint=self.execution_certificate,
                                           proxy_id="proxy-alice")
        self.assertEqual(repeated["grant"], first["grant"])
        self.assertEqual(sum(method == "POST" for method, *_ in self.exchange.calls), 1)

    def test_stop_dispatch_does_not_substitute_for_authoritative_termination(self):
        _, actor, _ = self.assigned()
        documents = []
        self.service.node_dispatch = lambda node, document: documents.append((node, document))
        with self.database.transaction() as session:
            job = session.get(models.Job, self.job["id"])
            job.state = "CANCELLING"
            attempt = session.get(models.Attempt, actor.attempt_id)
        self.assertFalse(self.service.attempt_termination_confirmed(job.id, attempt.id))
        self.assertFalse(self.service.request_stop(job, attempt))
        self.assertEqual(len(documents), 1)
        self.assertEqual(documents[0][0], "external-node")
        self.assertEqual(documents[0][1]["operation"], "stop")
        stop_actor = self.broker.authenticate_node("Bearer " + documents[0][1]["node_token"],
            verified_peer_thumbprint=self.node_certificate, grant_validator=self.service.check_node_grant)
        self.assertEqual(stop_actor.scopes, frozenset({"stopped", "logs", "collect"}))
        self.service.confirm_stopped(stop_actor)
        self.assertTrue(self.service.attempt_termination_confirmed(job.id, attempt.id))
        self.assertTrue(self.service.request_stop(job, attempt))
        self.assertEqual(len(documents), 1)

    def test_retained_certificate_cannot_be_reused_by_a_successor_attempt(self):
        enrollment, old_actor, _ = self.assigned()
        self.service.confirm_stopped(old_actor)
        with self.database.transaction() as session:
            previous = session.get(models.Attempt, old_actor.attempt_id)
            previous.revocation_confirmed = True
            job = session.get(models.Job, self.job["id"])
            job.current_attempt, job.epoch = 2, 2
            session.add(models.Attempt(job_id=job.id, number=2, epoch=2, state="RUNNING"))
        self.reserve_log_budgets(attempt_number=2)
        actor, _ = self.node_actor(enrollment)
        self.assert_error(409, "execution_certificate_already_bound", self.service.assignment, actor,
                          execution_certificate_thumbprint=self.execution_certificate, proxy_id="successor-proxy")
        assignment = self.service.assignment(actor, execution_certificate_thumbprint=certificate("fresh successor"),
                                             proxy_id="successor-proxy")
        self.assertEqual(assignment["identity"]["epoch"], 2)

    def test_heartbeat_is_scoped_and_rejects_unapproved_phase_or_boolean_round(self):
        _, actor, _ = self.assigned()
        self.assertEqual(self.service.heartbeat(actor, phase="training", current_round=1), {"accepted": True})
        self.assert_error(403, "node_scope_required", self.service.heartbeat,
                          replace(actor, scopes=frozenset({"assignment"})))
        self.assert_error(422, "invalid_participant_phase", self.service.heartbeat, actor, phase="arbitrary")
        self.assert_error(422, "invalid_participant_round", self.service.heartbeat, actor, current_round=True)

    def stop_snapshot(self, enrollment):
        with self.database.transaction(immediate=False) as session:
            resource = session.get(models.ProvisioningResource, enrollment["id"])
            historical = session.get(models.ProvisioningResource, resource.details_json["external_execution_id"])
            events = list(session.scalars(select(models.Event).where(
                models.Event.job_id == self.job["id"], models.Event.kind == "participant.stopped").order_by(models.Event.sequence)))
            return (dict(resource.details_json), dict(historical.details_json),
                    tuple((event.id, event.sequence, event.created_at, dict(event.data_json)) for event in events))

    def test_exact_stopped_receipt_replay_preserves_event_timestamp_and_history(self):
        enrollment, actor, _ = self.assigned()
        self.assertEqual(self.service.confirm_stopped(actor), {"accepted": True})
        before = self.stop_snapshot(enrollment)
        self.now += timedelta(seconds=30)
        self.assertEqual(self.service.confirm_stopped(actor), {"accepted": True})
        self.assertEqual(self.stop_snapshot(enrollment), before)
        self.assertEqual(len(before[2]), 1)
        self.assertIs(before[0]["never_started"], False)
        self.assertIs(before[1]["never_started"], False)
        self.assert_error(409, "external_stop_receipt_immutable", self.service.confirm_stopped, actor, never_started=True)
        self.assertEqual(self.stop_snapshot(enrollment), before)

    def test_never_started_receipt_is_idempotent_and_cannot_change_to_started(self):
        enrollment = self.enroll()
        self.activate()
        actor, _ = self.node_actor(enrollment)
        self.service.confirm_stopped(actor, never_started=True)
        before = self.stop_snapshot(enrollment)
        self.now += timedelta(seconds=30)
        self.assertEqual(self.service.confirm_stopped(actor, never_started=True), {"accepted": True})
        self.assertEqual(self.stop_snapshot(enrollment), before)
        self.assertIs(before[0]["never_started"], True)
        self.assertIs(before[1]["never_started"], True)
        self.assert_error(409, "external_stop_receipt_immutable", self.service.confirm_stopped, actor, never_started=False)
        self.assertEqual(self.stop_snapshot(enrollment), before)

    def test_stopped_receipt_replay_still_requires_current_authority_and_strict_boolean(self):
        enrollment, actor, _ = self.assigned()
        self.service.confirm_stopped(actor)
        before = self.stop_snapshot(enrollment)
        self.assert_error(403, "confirmed_node_stop_required", self.service.confirm_stopped, actor, never_started=0)
        self.assert_error(403, "confirmed_node_stop_required", self.service.confirm_stopped,
            replace(actor, scopes=frozenset({"logs"})))
        with self.database.transaction() as session:
            session.get(models.Job, actor.job_id).epoch += 1
        self.assert_error(404, "participant_assignment_not_found", self.service.confirm_stopped, actor)
        self.assertEqual(self.stop_snapshot(enrollment), before)

    def test_stop_confirmation_requires_its_own_scope_and_explicit_true(self):
        _, actor, _ = self.assigned()
        self.assert_error(403, "confirmed_node_stop_required", self.service.confirm_stopped, actor,
                          termination_confirmed=False)
        self.assert_error(403, "confirmed_node_stop_required", self.service.confirm_stopped,
                          replace(actor, scopes=frozenset({"assignment"})))
        self.assertEqual(self.service.confirm_stopped(actor), {"accepted": True})


class ExternalSourceIsolationTests(ExternalParticipantFixture):
    def test_source_reads_only_pinned_opaque_bytes_and_closes_stream(self):
        _, actor, _ = self.assigned()
        stream = self.service.open_source(actor, "plugin.py")
        self.assertEqual(stream.size_bytes, 10)
        self.assertEqual(stream.sha256, self.manifest["plugin.py"])
        self.assertEqual(b"".join(stream.chunks()), b"VALUE = 7\n")
        self.assertTrue(stream.content.closed)

    def test_non_manifest_traversal_and_foreign_source_paths_are_not_discoverable(self):
        _, actor, _ = self.assigned()
        for path in ("../.source.json", "../../another-job/source/secret.py", "/etc/passwd", ".source.json", "unknown.py"):
            with self.subTest(path=path):
                self.assert_error(404, "participant_source_file_not_found", self.service.open_source, actor, path)

    def test_source_hash_changes_and_wrong_snapshot_identity_fail_closed(self):
        _, actor, _ = self.assigned()
        root = self.provisioner.root / self.job["id"]
        (root / "source" / "plugin.py").write_bytes(b"tampered code")
        self.assert_error(409, "participant_source_mismatch", self.service.open_source, actor, "plugin.py")
        document = json.loads((root / ".source.json").read_text())
        document["commit"] = "f" * 40
        (root / ".source.json").write_text(json.dumps(document))
        self.assert_error(409, "participant_source_mismatch", self.service.open_source, actor, "plugin.py")

    def test_poisoned_manifest_cannot_escape_source_root(self):
        _, actor, _ = self.assigned()
        root = self.provisioner.root / self.job["id"]
        secret = root / "private-secret"
        secret.write_bytes(b"foreign private bytes")
        document = json.loads((root / ".source.json").read_text())
        document["manifest"]["../private-secret"] = hashlib.sha256(secret.read_bytes()).hexdigest()
        (root / ".source.json").write_text(json.dumps(document))
        with self.assertRaises(CollectionError):
            self.service.open_source(actor, "../private-secret")

    def test_symlink_and_hardlink_sources_cannot_escape_descriptor_boundary(self):
        _, actor, _ = self.assigned()
        root = self.provisioner.root / self.job["id"]
        secret = self.root / "foreign-private-bytes"
        secret.write_bytes(b"foreign private bytes")
        path = root / "source" / "plugin.py"
        path.unlink()
        path.symlink_to(secret)
        with self.assertRaises(CollectionError):
            self.service.open_source(actor, "plugin.py")
        path.unlink()
        import os
        os.link(secret, path)
        with self.assertRaises(CollectionError):
            self.service.open_source(actor, "plugin.py")

    def test_source_endpoint_requires_assignment_scope_and_current_node_epoch(self):
        _, actor, _ = self.assigned()
        self.assert_error(403, "node_scope_required", self.service.open_source,
                          replace(actor, scopes=frozenset({"heartbeat"})), "plugin.py")
        self.assert_error(404, "participant_assignment_not_found", self.service.open_source,
                          replace(actor, epoch=actor.epoch + 1), "plugin.py")


class ExternalDispatchTests(ExternalParticipantFixture):
    def two_nodes(self):
        self.service.nodes["second-node"] = replace(self.node, node_id="second-node", certificate_thumbprint=certificate("second-node"))
        with self.database.transaction() as session:
            session.get(models.ParticipantBinding, "data-bob").node_id = "second-node"
        alice = self.enroll()
        bob = self.service.enroll("alice", self.job["id"], "bob", "second-node", 2, "second-enrollment")
        self.activate()
        return alice, bob

    def test_offline_node_failure_is_private_backed_off_and_does_not_stop_other_node_dispatch(self):
        alice, bob = self.two_nodes()
        calls = []
        def dispatch(node, document):
            calls.append(node)
            if node == "external-node":
                raise RuntimeError("sensitive transport details must not enter the ledger")
            return {"accepted": True}
        self.service.node_dispatch = dispatch
        self.assertEqual(self.service.dispatch_pending(), {"dispatched": 1})
        self.assertEqual(set(calls), {"external-node", "second-node"})
        with self.database.transaction(immediate=False) as session:
            details = session.get(models.ProvisioningResource, alice["id"]).details_json
            self.assertEqual(details["last_dispatch_error"], "external_node_dispatch_failed")
            self.assertEqual(details["dispatch_retry_at"], self.now.timestamp() + 30)
            self.assertNotIn("sensitive", json.dumps(details))
            self.assertNotIn("last_dispatch_error", session.get(models.ProvisioningResource, bob["id"]).details_json)
        self.service.dispatch_pending()
        self.assertEqual(calls.count("external-node"), 1)
        self.now += timedelta(seconds=31)
        self.service.node_dispatch = lambda node, document: {"accepted": True}
        self.assertEqual(self.service.dispatch_pending(), {"dispatched": 2})
        with self.database.transaction(immediate=False) as session:
            details = session.get(models.ProvisioningResource, alice["id"]).details_json
            self.assertNotIn("last_dispatch_error", details)
            self.assertNotIn("dispatch_retry_at", details)

    def test_stopped_and_terminal_historical_enrollments_do_not_require_live_node_dispatch(self):
        enrollment = self.enroll()
        self.activate()
        actor, _ = self.node_actor(enrollment)
        self.service.confirm_stopped(actor, termination_confirmed=True)
        calls = []
        self.service.node_dispatch = lambda node, document: calls.append(document)
        for state in ("RUNNING", "CANCELLING", "SUCCEEDED", "CANCELLED"):
            with self.subTest(state=state):
                with self.database.transaction() as session:
                    session.get(models.Job, self.job["id"]).state = state
                self.assertEqual(self.service.dispatch_pending(), {"dispatched": 0})
                self.assertEqual(calls, [])
        historical = self.service.get_enrollment("alice", self.job["id"], "alice")
        self.assertEqual(historical["status"], "stopped")
        with self.database.transaction(immediate=False) as session:
            execution = session.scalar(select(models.ProvisioningResource).where(
                models.ProvisioningResource.kind == "external_execution"))
            self.assertTrue(execution.retained)
            self.assertTrue(execution.details_json["termination_confirmed"])

    def test_background_dispatch_keeps_blocked_node_outside_tick_and_deduplicates_inflight_delivery(self):
        import threading
        self.two_nodes()
        blocked, healthy, release = (threading.Event() for _ in range(3))
        calls = []
        def dispatch(node, document):
            calls.append(node)
            if node == "external-node":
                blocked.set()
                if not release.wait(timeout=5):
                    raise AssertionError("Test node dispatch did not receive its release")
            else:
                healthy.set()
            return {"accepted": True}
        self.service.node_dispatch = dispatch
        self.service.enable_async_dispatch()
        self.addCleanup(self.service.close)
        try:
            self.assertEqual(self.service.dispatch_pending(), {"dispatched": 2})
            self.assertTrue(blocked.wait(timeout=3))
            self.assertTrue(healthy.wait(timeout=3))
            self.assertEqual(self.manager.get_job("alice", self.job["id"])["state"], "RUNNING")
            self.service.dispatch_pending()
            self.assertEqual(calls.count("external-node"), 1)
            self.assertLessEqual(len(self.service._dispatch_futures), 8)
        finally:
            release.set()


class ApplicationExchangeAdapter:
    """Real Exchange transaction adapter without HTTP/S3 infrastructure."""
    def __init__(self, service, provisioner):
        self.service, self.provisioner = service, provisioner

    @staticmethod
    def path(space_id, suffix=""):
        return "/v2/spaces/" + space_id + suffix

    def request(self, method, target, *, body=None, headers=None):
        space_id = target.split("/")[3]
        if method == "POST" and target.endswith("/workload-grants"):
            return self.service.create_workload_grant(self.provisioner, space_id, body, headers["Idempotency-Key"])
        if method == "GET" and "/workload-grants/" in target:
            return self.service.get_workload_grant(self.provisioner, space_id, target.rsplit("/", 1)[-1])
        raise AssertionError((method, target))


class ExchangeBackedParticipantTests(ExternalParticipantFixture):
    def setUp(self):
        super().setUp()
        from cryptography.hazmat.primitives import serialization
        from hf2l_exchange.application import Service
        from hf2l_exchange.auth import Authenticator
        from hf2l_exchange.config import AuthSettings, DatabaseSettings, Settings, StorageSettings
        from hf2l_exchange.domain import Principal
        from hf2l_exchange.migrations import initialize
        from hf2l_jobs.broker import stable_workload_subject
        owner_id = principal_id("https://humans.example.test", "provisioner")
        self.exchange_owner = Principal(owner_id, "provisioner", bootstrap_admin=True)
        public_key = self.signing_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        settings = Settings(database=DatabaseSettings(url="sqlite:///" + str(self.root / "exchange.sqlite")),
            auth=AuthSettings(issuer="https://humans.example.test", public_key=public_key,
                workload_issuer=self.broker.settings.workload_issuer,
                workload_audience=self.broker.settings.exchange_audience, workload_public_key=public_key,
                trusted_backend_secret="trusted-fixture-terminator-secret-32-bytes",
                provisioning_principal_ids=(owner_id,)), storage=StorageSettings(bucket="fixture"))
        self.actual_exchange = Service(settings)
        self.addCleanup(self.actual_exchange.engine.dispose)
        initialize(self.actual_exchange.engine)
        self.exchange_auth = Authenticator(settings.auth)
        self.space = self.actual_exchange.create_space(self.exchange_owner,
                                                      {"name": "External participants"}, self.job["id"])["id"]
        self.actual_exchange.enable_managed_space(self.exchange_owner, self.space,
                                                 {"job_id": self.job["id"]}, "managed")
        for participant in ("alice", "bob"):
            subject = stable_workload_subject(self.job["id"], self.service.component_id(participant), participant)
            self.actual_exchange.put_member(self.exchange_owner, self.space,
                principal_id(self.broker.settings.workload_issuer, subject),
                {"subject": subject, "roles": ["reader", "contributor"], "bindings": {"participant": participant}})
        self.provisioner.exchange = ApplicationExchangeAdapter(self.actual_exchange, self.exchange_owner)
        self.provisioner._space_id = lambda job_id: self.space if job_id == self.job["id"] else None

    def test_external_assignment_token_is_accepted_only_in_its_real_exchange_space(self):
        from hf2l_exchange.domain import Error as ExchangeError
        _, actor, assignment = self.assigned()
        principal = self.exchange_auth.authenticate("Bearer " + assignment["credentials"]["exchange_token"],
            managed=True, certificate_thumbprint=self.execution_certificate)
        verified = self.actual_exchange.verify_workload_grant(principal, self.space)
        self.assertEqual(verified["effective_roles"], ["contributor", "reader"])
        self.assertEqual(verified["bindings"], {"participant": "alice"})
        self.assertEqual(verified["job_id"], self.job["id"])
        foreign = self.actual_exchange.create_space(self.exchange_owner, {"name": "Foreign"}, "foreign")["id"]
        self.actual_exchange.enable_managed_space(self.exchange_owner, foreign, {"job_id": "foreign"}, "foreign-managed")
        self.actual_exchange.put_member(self.exchange_owner, foreign, principal.id,
            {"subject": principal.subject, "roles": ["reader", "contributor", "admin"], "bindings": {"participant": "alice"}})
        with self.assertRaises(ExchangeError) as caught:
            self.actual_exchange.get_space(principal, foreign)
        self.assertEqual(caught.exception.status, 404)
        with self.assertRaises(ExchangeError) as copied:
            self.exchange_auth.authenticate("Bearer " + assignment["credentials"]["exchange_token"],
                managed=True, certificate_thumbprint=self.node_certificate)
        self.assertEqual(copied.exception.status, 401)

    def test_confirmed_exchange_revocation_blocks_old_token_and_participant_refresh(self):
        from hf2l_exchange.domain import Error as ExchangeError
        _, actor, assignment = self.assigned()
        principal = self.exchange_auth.authenticate("Bearer " + assignment["credentials"]["exchange_token"],
            managed=True, certificate_thumbprint=self.execution_certificate)
        receipt = self.actual_exchange.revoke_workload_grants(self.exchange_owner, self.space,
                                    {"attempt_id": actor.attempt_id}, "confirmed-revoke")
        self.assertEqual(receipt["revoked"], 1)
        self.assert_error(401, "participant_grant_revoked", self.service.credentials, actor)
        with self.assertRaises(ExchangeError) as caught:
            self.actual_exchange.verify_workload_grant(principal, self.space)
        self.assertEqual(caught.exception.code, "workload_grant_invalid")


class VerifiedPeerFixture:
    """Inject trusted ASGI peer evidence; this does not simulate a TLS handshake."""
    def __init__(self, app, thumbprint):
        self.app, self.thumbprint = app, thumbprint

    async def __call__(self, scope, receive, send):
        scope = dict(scope)
        if scope["type"] == "http":
            scope["hf2l.verified_peer_thumbprint"] = self.thumbprint
        await self.app(scope, receive, send)


class RecordingManagerTransport:
    """Real manager ASGI HTTP requests, recording the operation ordering."""
    def __init__(self, client):
        self.client, self.calls = client, []
        self.rewrite = None

    def request(self, method, url, **kwargs):
        self.calls.append((method, url.rsplit("/", 1)[-1], kwargs.get("json")))
        response = self.client.request(method, url, **kwargs)
        return self.rewrite(response, url) if self.rewrite else response

    @contextmanager
    def stream(self, method, url, **kwargs):
        self.calls.append((method, url.rsplit("/", 1)[-1], kwargs.get("json")))
        with self.client.stream(method, url, **kwargs) as response:
            if self.rewrite:
                response.read()
                yield self.rewrite(response, url)
            else:
                yield response


class DeterministicRuntimeExecutor:
    """Check the executor contract without claiming OCI sandbox qualification."""
    def __init__(self):
        self.specs, self.states, self.calls = {}, {}, []
        self.qualified = 0
        self.confirm_stop = True
        self.log_spools, self.log_reads, self.state_reads = {}, [], []

    def qualify_health(self):
        self.qualified += 1

    def reserve(self, spec):
        from hf2l_jobs.executor import Reservation
        self.calls.append(("reserve", spec.identity.key))
        self.specs[spec.identity.key] = spec
        self.states[spec.identity.key] = "RESERVED"
        return Reservation(spec.identity, True)

    def start(self, identity):
        from hf2l_jobs.executor import RuntimeObservation
        spec = self.specs[identity.key]
        assert spec.argv == ("python", "-m", "hf2l_jobs.runtime", "--config", "/run/hf2l/runtime.json")
        config = RuntimeConfig.model_validate_json(Path(spec.config_path).read_bytes())
        assert config.job_id == identity.job_id and config.epoch == identity.epoch
        assert (Path(spec.source_path) / "plugin.py").read_bytes() == b"VALUE = 7\n"
        self.calls.append(("start", identity.key))
        self.states[identity.key] = "RUNNING"
        return RuntimeObservation(identity, "RUNNING")

    def inspect(self, identity):
        from hf2l_jobs.executor import RuntimeObservation
        state = self.states[identity.key]
        return RuntimeObservation(identity, state, termination_confirmed=state in {"RESERVED", "EXITED", "STOPPED", "RELEASED"},
                                  exit_code=0 if state == "EXITED" else None)

    def stop(self, identity, grace_seconds=60):
        from hf2l_jobs.executor import RuntimeObservation
        self.calls.append(("stop", identity.key))
        self.states[identity.key] = "STOPPED" if self.confirm_stop else "RUNNING"
        if self.confirm_stop and identity.key in self.log_spools:
            self.log_spools[identity.key].mark_complete()
        return RuntimeObservation(identity, self.states[identity.key], termination_confirmed=self.confirm_stop)

    def read_logs(self, identity, offset=0, max_bytes=65536):
        from dataclasses import asdict
        self.log_reads.append((identity.key, offset, max_bytes))
        if identity.key in self.log_spools:
            return self.log_spools[identity.key].read(identity, offset=offset, max_bytes=max_bytes)
        return {"identity": asdict(identity), "source_id": identity.key,
                "offset": offset, "next_offset": offset, "content": "",
                "complete": self.states[identity.key] in {"EXITED", "STOPPED", "RELEASED"},
                "truncated": False}

    def reconciliation_root(self, identity):
        self.state_reads.append(identity.key)
        return Path(self.specs[identity.key].state_path)

    def collect(self, identity):
        return ()

    def confirm_absent(self, identity):
        return identity.key not in self.specs

    def release(self, identity):
        self.calls.append(("release", identity.key))
        self.states[identity.key] = "RELEASED"
        return True


class ExternalAgentFixture(ExternalParticipantFixture):
    def setUp(self):
        super().setUp()
        from fastapi.testclient import TestClient
        from hf2l_jobs.api import create_app
        from hf2l_jobs.executor import ResourceLimits
        from hf2l_jobs.node_agent import NodeAgent
        from hf2l_jobs.remote_node import RemoteNodeMaterializer
        mirror = self.root / "approved-mirror"
        (mirror / "plugin.py").write_bytes(b"VALUE = 7\n")
        for arguments in (("init", "--quiet"), ("add", "plugin.py"),
                ("-c", "user.name=HF2L Test", "-c", "user.email=fixture@example.test", "commit", "--quiet", "-m", "Approved fixture")):
            subprocess.run(("git", "-C", str(mirror), *arguments), check=True, capture_output=True)
        self.source_commit = subprocess.run(("git", "-C", str(mirror), "rev-parse", "HEAD"),
                                           check=True, capture_output=True, text=True).stdout.strip()
        with self.database.transaction() as session:
            session.get(models.ApprovedSource, "source").allowed_commits = [self.source_commit]
        self.job = self.new_job(key="runtime-job")
        metadata = self.provisioner.root / self.job["id"] / ".source.json"
        document = json.loads(metadata.read_text())
        document["commit"] = self.source_commit
        metadata.write_text(json.dumps(document))
        self.provisioner.registry = RegistryCatalog.from_database(self.database)
        auth = SimpleNamespace(authenticate_node=lambda authorization, fingerprint:
            self.broker.authenticate_node(authorization, verified_peer_thumbprint=fingerprint,
                                           grant_validator=self.service.check_node_grant))
        self.manager_app = create_app(self.manager, auth, participants=self.service)
        self.http = TestClient(VerifiedPeerFixture(self.manager_app, self.node_certificate),
                               base_url="https://manager.example.test")
        self.addCleanup(self.http.close)
        self.transport = RecordingManagerTransport(self.http)
        self.client = ExternalManagerClient("https://manager.example.test", http=self.transport)
        # Independent local approvals contain neither Manager SQL nor signing keys.
        self.local_registry = RegistryCatalog(SourceRegistry([SourceApproval("source", frozenset({"project"}),
            mirror_path=mirror, commits=frozenset({self.source_commit}), max_bytes=1024**2, max_files=16,
            max_git_bytes=1024**2, max_git_files=128)]), {"runtime": "sha256:" + "b" * 64},
            dataset_bindings={"data-alice": ["alice"], "data-bob": ["bob"]})
        self.node_root = self.root / "node-owned"
        self.proxy_root = self.root / "local-proxy-sockets"
        self.proxy_root.mkdir(mode=0o700)
        self.bindings = []

        def endpoint(identity):
            return str(self.proxy_root / (identity.key + ".sock"))

        def binding(assignment, space_id, principal_id):
            self.bindings.append(assignment.identity.key)
            return {"proxy_endpoint": endpoint(assignment.identity),
                    "certificate_thumbprint": certificate("execution-" + assignment.identity.key)}

        def datasets(assignment):
            participant = assignment.external_participant_id
            return {"data-" + participant: self.node.dataset_bindings["data-" + participant].model_dump(mode="json")}

        self.materializer = RemoteNodeMaterializer(self.node_root, self.local_registry,
            node_id="external-node", pool_id="external", proxy_endpoint=endpoint,
            execution_bindings=binding, dataset_bindings=datasets)
        self.materializer.workload_issuer = self.broker.settings.workload_issuer
        self.executor = DeterministicRuntimeExecutor()
        self.ticks = 1000
        self.runtime_node = NodeAgent(self.executor, self.root / "local-node.sqlite", "external-node", "external",
            ResourceLimits(cpu_millis=4000, memory_bytes=8 << 30, disk_bytes=8 << 30),
            clock=lambda: self.ticks, wall_clock=lambda: self.now.timestamp(),
            boot_id="fixture-local-boot", watchdog_interval=60)
        self.addCleanup(self.runtime_node.close)
        self.materializer.auxiliary_reserver = lambda identity, size: self.runtime_node.charge_auxiliary_bytes(identity, size)
        self.verifier = WorkloadBroker(replace(self.broker.settings, private_key=None), clock=lambda: self.now.timestamp())
        self.agent = ExternalParticipantAgent(self.client, self.materializer, self.runtime_node, self.verifier,
                                              node_certificate_thumbprint=self.node_certificate)
        self.addCleanup(self.agent.close)

    def spec(self):
        result = super().spec()
        result["source_commit"] = getattr(self, "source_commit", "a" * 40)
        return result

    def bootstrap(self, participant="alice", job=None):
        enrollment = self.enroll(participant, job=job, key="agent-" + participant)
        self.activate(job)
        actor, document = self.node_actor(enrollment)
        from hf2l_jobs.executor import ExecutionIdentity
        identity = ExecutionIdentity(actor.job_id, actor.attempt_id, actor.component_id, actor.epoch)
        return enrollment, actor, identity, document

    def local_effects(self):
        files = tuple(sorted(str(path.relative_to(self.node_root)) for path in self.node_root.rglob("*")
                             if path.is_file()))
        return files, self.runtime_node.inventory(), tuple(self.executor.calls), tuple(self.bindings)


class ExternalAgentRuntimeTests(ExternalAgentFixture):
    def test_http_start_uses_shared_materializer_real_node_ledger_and_private_fixed_runtime(self):
        enrollment, actor, identity, document = self.bootstrap()
        self.assertEqual(self.agent.receive(document), {"accepted": True, "state": "RUNNING"})
        spec = self.executor.specs[identity.key]
        configuration = RuntimeConfig.model_validate_json(Path(spec.config_path).read_bytes())
        self.assertEqual((spec.node_id, spec.pool_id, spec.role, spec.participant_id),
                         ("external-node", "external", "client", "alice"))
        self.assertEqual(spec.resources.cpu_millis, 500)
        self.assertEqual(configuration.source_manifest, self.manifest)
        self.assertEqual(configuration.dataset_bindings["data-alice"].path, "/job/data/alice.npz")
        self.assertEqual((configuration.source_dir, configuration.state_dir, configuration.exchange_endpoint),
                         ("/job/source", "/job/state", "http://proxy"))
        self.assertEqual(self.runtime_node.inventory()[0]["state"], "RUNNING")
        self.assertGreater(self.executor.qualified, 0)
        self.assertIsNone(self.verifier.settings.private_key)
        self.assertIsNone(self.materializer.registry.database)
        self.assertEqual([operation for _, operation, _ in self.transport.calls],
                         ["plan", "assignment", "credentials", "heartbeat"])
        serialized = Path(spec.config_path).read_text()
        self.assertNotIn(document["node_token"], serialized)
        self.assertNotIn("PRIVATE KEY", serialized)
        self.assertEqual(Path(spec.config_path).stat().st_mode & 0o777, 0o400)
        self.assertEqual(Path(spec.state_path).stat().st_mode & 0o777, 0o700)
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(models.Allocation)), 0)
            resource = session.get(models.ProvisioningResource, enrollment["id"])
            self.assertEqual(resource.details_json["execution_certificate_thumbprint"], certificate("execution-" + identity.key))

    def test_replayed_start_renews_local_lease_without_second_launch_or_changed_grant(self):
        _, _, identity, document = self.bootstrap()
        self.agent.receive(document)
        old_lease = self.runtime_node.inventory()[0]["lease_until"]
        self.ticks += 20
        self.agent.receive(document)
        self.assertEqual(self.executor.calls.count(("start", identity.key)), 1)
        self.assertEqual(self.executor.calls.count(("reserve", identity.key)), 1)
        self.assertGreater(self.runtime_node.inventory()[0]["lease_until"], old_lease)
        self.assertEqual(len(self.exchange.grants), 1)

    def test_cancelled_job_rejects_start_before_source_proxy_or_local_admission(self):
        _, _, _, document = self.bootstrap()
        with self.database.transaction() as session:
            session.get(models.Job, self.job["id"]).state = "CANCELLING"
        before = self.local_effects()
        self.assert_error(404, "participant_assignment_not_found", self.agent.receive, document)
        self.assertEqual(self.local_effects(), before)
        self.assertEqual([operation for _, operation, _ in self.transport.calls], ["plan"])
        self.assertEqual(self.exchange.grants, {})

    def test_stale_current_epoch_rejects_start_and_stop_before_local_effects(self):
        _, _, identity, document = self.bootstrap()
        self.agent.receive(document)
        with self.database.transaction() as session:
            session.get(models.Job, self.job["id"]).epoch = 2
        before = self.local_effects()
        for operation in ("start", "stop"):
            self.assert_error(401, "invalid_node_grant", self.agent.receive, {**document, "operation": operation})
            self.assertEqual(self.local_effects(), before)
        self.assertEqual(self.executor.calls.count(("stop", identity.key)), 0)

    def test_manager_certificate_or_token_binding_mismatch_never_changes_local_state(self):
        _, _, _, document = self.bootstrap()
        self.agent.node_certificate_thumbprint = certificate("copied-node-certificate")
        before = self.local_effects()
        self.assert_error(401, "invalid_node_grant", self.agent.receive, document)
        self.assertEqual(self.local_effects(), before)
        self.assertEqual(self.transport.calls, [])

    def test_online_plan_identity_mismatch_rejected_before_local_materialization(self):
        import httpx
        _, _, _, document = self.bootstrap()
        def rewrite(response, url):
            if url.endswith("/plan"):
                plan = response.json()
                plan["identity"] = {**plan["identity"], "job_id": "foreign-job"}
                return httpx.Response(200, json=plan)
            return response
        self.transport.rewrite = rewrite
        before = self.local_effects()
        self.assert_error(403, "external_node_assignment_mismatch", self.agent.receive, document)
        self.assertEqual(self.local_effects(), before)
        self.assertEqual(self.exchange.grants, {})

    def test_local_capacity_refusal_precedes_exchange_grant_and_proxy_binding(self):
        from hf2l_jobs.executor import ExecutorRefused, ResourceLimits
        _, _, _, document = self.bootstrap()
        self.runtime_node.capacity = ResourceLimits(cpu_millis=100, memory_bytes=8 << 30, disk_bytes=8 << 30)
        with self.assertRaises(ExecutorRefused) as caught:
            self.agent.receive(document)
        self.assertEqual(caught.exception.code, "capacity")
        self.assertEqual(self.bindings, [])
        self.assertEqual(self.runtime_node.inventory(), ())
        self.assertEqual(self.exchange.grants, {})
        self.assertEqual([operation for _, operation, _ in self.transport.calls], ["plan"])

    def test_node_local_approval_removal_rejects_before_runtime_or_workload_grant(self):
        from hf2l_jobs.source import SourceError
        _, _, _, document = self.bootstrap()
        self.local_registry.dataset_bindings.pop("data-alice")
        before = self.local_effects()
        with self.assertRaises(SourceError):
            self.agent.receive(document)
        self.assertEqual(self.local_effects(), before)
        self.assertEqual(self.exchange.grants, {})

    def test_confirmed_stop_releases_node_and_acknowledges_manager_then_replay_is_harmless(self):
        enrollment, actor, identity, document = self.bootstrap()
        self.agent.receive(document)
        with self.database.transaction() as session:
            session.get(models.Job, self.job["id"]).state = "CANCELLING"
        stopping = self.service.bootstrap_credentials(enrollment["id"])
        self.assertEqual(stopping["operation"], "stop")
        self.transport.calls.clear()
        self.assertEqual(self.agent.receive(stopping), {"accepted": True, "state": "stopped"})
        self.assertEqual([operation for _, operation, _ in self.transport.calls], ["control", "logs", "stopped"])
        self.assertEqual(self.runtime_node.inventory()[0]["state"], "RELEASED")
        self.assertTrue(self.service.attempt_termination_confirmed(actor.job_id, actor.attempt_id))
        self.assertEqual(self.agent.receive(stopping), {"accepted": True, "state": "stopped"})
        self.assertEqual(self.executor.calls.count(("stop", identity.key)), 1)
        self.assertEqual(self.executor.calls.count(("release", identity.key)), 1)

    def test_unconfirmed_stop_retains_capacity_and_does_not_acknowledge_termination(self):
        from hf2l_jobs.executor import UncertainExecution
        enrollment, actor, _, document = self.bootstrap()
        self.agent.receive(document)
        self.executor.confirm_stop = False
        with self.database.transaction() as session:
            session.get(models.Job, self.job["id"]).state = "CANCELLING"
        with self.assertRaises(UncertainExecution):
            self.agent.receive(self.service.bootstrap_credentials(enrollment["id"]))
        self.assertEqual(self.runtime_node.inventory()[0]["state"], "QUARANTINED")
        self.assertFalse(self.service.attempt_termination_confirmed(actor.job_id, actor.attempt_id))
        self.assertNotIn("stopped", [operation for _, operation, _ in self.transport.calls])

    def test_online_control_identity_mismatch_cannot_stop_the_local_runtime(self):
        import httpx
        enrollment, _, identity, document = self.bootstrap()
        self.agent.receive(document)
        with self.database.transaction() as session:
            session.get(models.Job, self.job["id"]).state = "CANCELLING"
        def rewrite(response, url):
            if url.endswith("/control"):
                control = response.json()
                control["node_id"] = "foreign-node"
                return httpx.Response(200, json=control)
            return response
        self.transport.rewrite = rewrite
        before = self.local_effects()
        self.assert_error(403, "external_node_assignment_mismatch", self.agent.receive,
                          self.service.bootstrap_credentials(enrollment["id"]))
        self.assertEqual(self.local_effects(), before)
        self.assertEqual(self.executor.calls.count(("stop", identity.key)), 0)

    def test_http_credentials_refresh_requires_current_exchange_grant_and_source_is_opaque(self):
        _, _, identity, document = self.bootstrap()
        self.agent.receive(document)
        self.assertEqual(self.client.request(identity, document["node_token"], "source/plugin.py", raw=True), b"VALUE = 7\n")
        binding = {"job_id": identity.job_id, "attempt_id": identity.attempt_id,
                   "component_id": identity.component_id, "epoch": identity.epoch}
        token = self.agent.delegated_token(binding, "alice", "exchange")
        principal = self.broker.authenticate_workload("Bearer " + token,
            verified_peer_thumbprint=certificate("execution-" + identity.key), audience="exchange")
        self.assertEqual(principal.job_id, identity.job_id)
        self.assertEqual(principal.certificate_thumbprint, certificate("execution-" + identity.key))
        next(iter(self.exchange.grants.values()))["enabled"] = False
        self.assert_error(401, "participant_grant_revoked", self.agent.delegated_token, binding, "alice", "gateway")

    def test_two_jobs_on_same_node_use_disjoint_sources_state_config_and_certificates(self):
        _, _, first_identity, first = self.bootstrap()
        self.agent.receive(first)
        other = self.new_job(key="second-runtime-job")
        metadata = self.provisioner.root / other["id"] / ".source.json"
        data = json.loads(metadata.read_text()); data["commit"] = self.source_commit
        metadata.write_text(json.dumps(data))
        _, _, second_identity, second = self.bootstrap(job=other)
        self.agent.receive(second)
        first_spec, second_spec = self.executor.specs[first_identity.key], self.executor.specs[second_identity.key]
        for attribute in ("source_path", "state_path", "config_path", "proxy_endpoint"):
            self.assertNotEqual(getattr(first_spec, attribute), getattr(second_spec, attribute))
        first_state = Path(first_spec.state_path) / "private-result"
        first_state.write_text("first-job-only")
        self.assertFalse((Path(second_spec.state_path) / "private-result").exists())
        self.assertEqual(len({grant["certificate_thumbprint"] for grant in self.exchange.grants.values()}), 2)
        foreign = replace(first_identity, job_id=second_identity.job_id, attempt_id=second_identity.attempt_id)
        self.assert_error(404, "assignment_not_found", self.client.request, foreign, first["node_token"], "plan")
        self.assertEqual(len(self.runtime_node.inventory()), 2)

    def test_dispatch_rejects_malformed_documents_unknown_fields_and_unapproved_operation(self):
        _, _, _, document = self.bootstrap()
        before = self.local_effects()
        for value in (None, [], {**document, "host_path": "/foreign"}):
            self.assert_error(422, "invalid_participant_dispatch", self.agent.receive, value)
        self.assert_error(422, "invalid_participant_dispatch", self.agent.receive, {})
        self.assert_error(403, "node_scope_required", self.agent.receive, {**document, "operation": "purge"})
        self.assertEqual(self.local_effects(), before)
        self.assertEqual(self.transport.calls, [])

    def test_public_manager_ingress_ignores_raw_certificate_headers_and_wrong_verified_peer(self):
        from fastapi.testclient import TestClient
        _, _, identity, document = self.bootstrap()
        target = self.client.prefix(identity) + "/plan"
        headers = {"Authorization": "Bearer " + document["node_token"],
                   "X-HF2L-TLS-Thumbprint": self.node_certificate, "X-Client-Cert-Thumbprint": self.node_certificate}
        with TestClient(self.manager_app, base_url="https://manager.example.test") as public:
            response = public.get(target, headers=headers)
            self.assertEqual((response.status_code, response.json()["error"]["code"]),
                             (401, "verified_node_certificate_required"))
        with TestClient(VerifiedPeerFixture(self.manager_app, certificate("foreign-node")),
                        base_url="https://manager.example.test") as wrong:
            response = wrong.get(target, headers=headers)
            self.assertEqual((response.status_code, response.json()["error"]["code"]), (401, "invalid_node_grant"))


    def test_actual_node_ingress_delivers_valid_runtime_start_and_rejects_unknown_dispatch_fields(self):
        from fastapi.testclient import TestClient
        _, _, identity, document = self.bootstrap()
        manager_certificate = certificate("trusted-manager-dispatch")
        app = create_participant_node_app(self.agent, [manager_certificate])
        with TestClient(VerifiedPeerFixture(app, manager_certificate), base_url="https://node.example.test") as client:
            response = client.post("/internal/nodes/v1/participants", json=document)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json(), {"accepted": True, "state": "RUNNING"})
            before = self.local_effects()
            invalid = client.post("/internal/nodes/v1/participants", json={**document, "mount": "/foreign"})
            self.assertEqual((invalid.status_code, invalid.json()["error"]["code"]),
                             (422, "invalid_participant_dispatch"))
            self.assertEqual(self.local_effects(), before)
        self.assertEqual(self.executor.calls.count(("start", identity.key)), 1)

    def test_proxy_stop_refusal_does_not_confirm_manager_termination(self):
        enrollment, actor, identity, document = self.bootstrap()
        self.agent.receive(document)
        calls = []
        def stop(job_id, attempt_id, component_id, *, termination_confirmed=False):
            calls.append((job_id, attempt_id, component_id, termination_confirmed))
            return False
        self.agent.proxy_supervisor = SimpleNamespace(stop=stop)
        with self.database.transaction() as session:
            session.get(models.Job, self.job["id"]).state = "CANCELLING"
        stopping = self.service.bootstrap_credentials(enrollment["id"])
        self.assert_error(503, "participant_proxy_termination_unconfirmed", self.agent.receive, stopping)
        self.assertEqual(calls, [(identity.job_id, identity.attempt_id, identity.component_id, True)])
        self.assertFalse(self.service.attempt_termination_confirmed(actor.job_id, actor.attempt_id))
        self.assertNotIn("stopped", [operation for _, operation, _ in self.transport.calls])

    def test_manager_client_refuses_redirect_or_nonobject_reply_without_accepting_authority(self):
        import httpx
        _, _, identity, document = self.bootstrap()
        for response, code in ((httpx.Response(307, json={"accepted": True}, headers={"Location": "https://foreign.example.test"}),
                                "external_manager_redirect_forbidden"),
                               (httpx.Response(200, json=[]), "invalid_external_manager_reply"),
                               (httpx.Response(200, content=b"{bad"), "invalid_external_manager_reply")):
            with self.subTest(code=code), httpx.Client(transport=httpx.MockTransport(lambda request: response),
                                                      follow_redirects=False) as http:
                client = ExternalManagerClient("https://manager.example.test", http=http)
                status = 503 if code == "external_manager_redirect_forbidden" else 502
                self.assert_error(status, code, client.request, identity, document["node_token"], "plan")

    def test_manager_client_bounds_success_reply_while_reading_chunks(self):
        import httpx
        _, _, identity, document = self.bootstrap()
        class OversizedReply(httpx.SyncByteStream):
            def __iter__(self):
                for _ in range(17):
                    yield b" " * (1024**2)
        with httpx.Client(transport=httpx.MockTransport(lambda request:
                httpx.Response(200, stream=OversizedReply()))) as http:
            client = ExternalManagerClient("https://manager.example.test", http=http)
            self.assert_error(502, "external_manager_reply_too_large", client.request, identity,
                              document["node_token"], "plan")


    def test_cancel_before_local_assignment_requires_explicit_no_reservation_stop_proof(self):
        enrollment, actor, _, document = self.bootstrap()
        self.assertFalse(self.service.attempt_termination_confirmed(actor.job_id, actor.attempt_id))
        self.assertEqual(self.runtime_node.inventory(), ())
        with self.database.transaction(immediate=False) as session:
            execution = session.scalar(select(models.ProvisioningResource).where(
                models.ProvisioningResource.kind == "external_execution",
                models.ProvisioningResource.job_id == actor.job_id))
            self.assertIsNotNone(execution)
            self.assertTrue(execution.retained)
            self.assertFalse(execution.details_json["termination_confirmed"])
        calls = []
        def stop(job_id, attempt_id, component_id, *, termination_confirmed=False):
            calls.append(termination_confirmed)
            return True
        self.agent.proxy_supervisor = SimpleNamespace(stop=stop)
        with self.database.transaction() as session:
            session.get(models.Job, self.job["id"]).state = "CANCELLING"
        stopping = self.service.bootstrap_credentials(enrollment["id"])
        self.assertEqual(self.agent.receive(stopping), {"accepted": True, "state": "stopped"})
        self.assertTrue(self.service.attempt_termination_confirmed(actor.job_id, actor.attempt_id))
        self.assertEqual(calls, [True])
        with self.database.transaction(immediate=False) as session:
            execution = session.scalar(select(models.ProvisioningResource).where(
                models.ProvisioningResource.kind == "external_execution",
                models.ProvisioningResource.job_id == actor.job_id))
            self.assertTrue(execution.details_json["termination_confirmed"])
        self.assertEqual(self.executor.calls, [])
        self.assertEqual(self.runtime_node.inventory(), ())
        before = self.local_effects()
        self.assert_error(404, "participant_assignment_not_found", self.agent.receive, document)
        self.assertEqual(self.local_effects(), before)

    def test_start_and_stop_share_guard_so_stop_cannot_acknowledge_before_pending_reservation(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        enrollment, actor, identity, document = self.bootstrap()
        reserve_entered, allow_reserve, stop_entered, control_called = (threading.Event() for _ in range(4))
        real_reserve = self.materializer.plan
        def gated_reserve(assignment):
            if not reserve_entered.is_set():
                reserve_entered.set()
                if not allow_reserve.wait(timeout=5):
                    raise AssertionError("Timed out waiting for the cancellation gate")
            return real_reserve(assignment)
        self.materializer.plan = gated_reserve
        real_request = self.client.request
        def request(identity, token, operation, **kwargs):
            if operation == "control":
                control_called.set()
            return real_request(identity, token, operation, **kwargs)
        self.client.request = request
        with ThreadPoolExecutor(max_workers=2) as workers:
            starting = workers.submit(self.agent.receive, document)
            try:
                self.assertTrue(reserve_entered.wait(timeout=3))
                with self.database.transaction() as session:
                    session.get(models.Job, self.job["id"]).state = "CANCELLING"
                stopping_document = self.service.bootstrap_credentials(enrollment["id"])
                def stop():
                    stop_entered.set()
                    return self.agent.receive(stopping_document)
                stopping = workers.submit(stop)
                self.assertTrue(stop_entered.wait(timeout=3))
                self.assertFalse(control_called.wait(timeout=0.15))
                self.assertFalse(self.service.attempt_termination_confirmed(actor.job_id, actor.attempt_id))
                self.assertEqual(self.runtime_node.inventory(), ())
            finally:
                allow_reserve.set()
            self.assert_error(404, "participant_assignment_not_found", starting.result, timeout=5)
            self.assertEqual(stopping.result(timeout=5), {"accepted": True, "state": "stopped"})
        self.assertEqual(self.executor.calls, [("reserve", identity.key), ("stop", identity.key), ("release", identity.key)])
        self.assertEqual(self.runtime_node.inventory()[0]["state"], "RELEASED")
        self.assertTrue(self.service.attempt_termination_confirmed(actor.job_id, actor.attempt_id))
        self.assertEqual(self.exchange.grants, {})


    def assert_disabled_approval_can_stop(self, disable):
        enrollment, actor, identity, document = self.bootstrap()
        self.agent.receive(document)
        disable()
        self.assert_error(403, "external_node_not_approved", self.service.assignment_plan, actor)
        self.assert_error(403, "external_node_not_approved", self.service.credentials, actor)
        self.assert_error(403, "external_node_not_approved", self.service.open_source, actor, "plugin.py")
        stopping = self.service.bootstrap_credentials(enrollment["id"])
        self.assertEqual(stopping["operation"], "stop")
        stop_actor = self.broker.authenticate_node("Bearer " + stopping["node_token"],
            verified_peer_thumbprint=self.node_certificate, grant_validator=self.service.check_node_grant)
        self.assertEqual(stop_actor.scopes, frozenset({"stopped", "logs", "collect"}))
        self.assertEqual(self.agent.receive(stopping), {"accepted": True, "state": "stopped"})
        self.assertEqual(self.runtime_node.inventory()[0]["state"], "RELEASED")
        self.assertTrue(self.service.attempt_termination_confirmed(actor.job_id, actor.attempt_id))
        self.assertNotIn(identity.key, self.agent._tokens)

    def test_disabled_node_approval_fences_new_authority_but_permits_authenticated_stop(self):
        self.assert_disabled_approval_can_stop(lambda: self.service.nodes.update({"external-node": replace(self.node, enabled=False)}))

    def test_disabled_dataset_approval_fences_new_authority_but_permits_authenticated_stop(self):
        def disable():
            with self.database.transaction() as session:
                session.get(models.ParticipantBinding, "data-alice").enabled = False
        self.assert_disabled_approval_can_stop(disable)



    def test_missing_node_row_cannot_confirm_absence_when_executor_has_private_reservation(self):
        from hf2l_jobs.executor import ResourceLimits
        from hf2l_jobs.remote_node import RemoteAssignment
        _, actor, identity, document = self.bootstrap()
        plan = self.service.assignment_plan(actor)
        assignment = RemoteAssignment(identity=identity, node_id="external-node", pool_id="external",
            resources=ResourceLimits(cpu_millis=plan["resources"]["cpu_millicores"],
                memory_bytes=plan["resources"]["memory_bytes"], disk_bytes=plan["resources"]["disk_bytes"]),
            job_spec=JobSpec.model_validate(plan["job_spec"]), image_digest=plan["image_digest"],
            deadline=plan["deadline"], external_participant_id="alice")
        # Simulate a crash after executor reservation but before NodeAgent's row.
        self.executor.reserve(self.materializer.reserve(assignment))
        self.assertEqual(self.runtime_node.inventory(), ())
        self.assertFalse(self.executor.confirm_absent(identity))
        with self.database.transaction() as session:
            session.get(models.Job, self.job["id"]).state = "CANCELLING"
        stopping = self.service.bootstrap_credentials(document["enrollment"]["id"])
        with self.assertRaises(Error) as caught:
            self.agent.receive(stopping)
        self.assertEqual(caught.exception.status, 503)
        self.assertFalse(self.service.attempt_termination_confirmed(actor.job_id, actor.attempt_id))
        self.assertNotIn("stopped", [operation for _, operation, _ in self.transport.calls])
        self.assertIn(identity.key, self.executor.specs)


    def test_separate_agent_and_node_instances_share_os_guard_before_pending_admission_and_stop(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        from hf2l_jobs.node_agent import NodeAgent
        enrollment, actor, identity, document = self.bootstrap()
        other_node = NodeAgent(self.executor, self.runtime_node.ledger_path, "external-node", "external",
            self.runtime_node.capacity, clock=lambda: self.ticks, wall_clock=lambda: self.now.timestamp(),
            boot_id="fixture-local-boot", watchdog_interval=60)
        self.addCleanup(other_node.close)
        other_agent = ExternalParticipantAgent(self.client, self.materializer, other_node, self.verifier,
                                               node_certificate_thumbprint=self.node_certificate)
        self.addCleanup(other_agent.close)
        planned, continue_start, stop_entered, control_called = (threading.Event() for _ in range(4))
        real_plan = self.materializer.plan
        def plan(assignment):
            if not planned.is_set():
                planned.set()
                if not continue_start.wait(timeout=5):
                    raise AssertionError("The pending start did not receive its release")
            return real_plan(assignment)
        self.materializer.plan = plan
        real_request = self.client.request
        def request(identity, token, operation, **kwargs):
            if operation == "control":
                control_called.set()
            return real_request(identity, token, operation, **kwargs)
        self.client.request = request
        with ThreadPoolExecutor(max_workers=2) as workers:
            starting = workers.submit(self.agent.receive, document)
            try:
                self.assertTrue(planned.wait(timeout=3))
                with self.database.transaction() as session:
                    session.get(models.Job, self.job["id"]).state = "CANCELLING"
                stopping_document = self.service.bootstrap_credentials(enrollment["id"])
                def stop():
                    stop_entered.set()
                    return other_agent.receive(stopping_document)
                stopping = workers.submit(stop)
                self.assertTrue(stop_entered.wait(timeout=3))
                self.assertFalse(control_called.wait(timeout=0.15))
                self.assertEqual(other_node.inventory(), ())
                self.assertFalse(self.service.attempt_termination_confirmed(actor.job_id, actor.attempt_id))
            finally:
                continue_start.set()
            self.assert_error(404, "participant_assignment_not_found", starting.result, timeout=5)
            self.assertEqual(stopping.result(timeout=5), {"accepted": True, "state": "stopped"})
        self.assertEqual(self.executor.calls, [("reserve", identity.key), ("stop", identity.key), ("release", identity.key)])
        self.assertTrue(self.service.attempt_termination_confirmed(actor.job_id, actor.attempt_id))
        self.assertEqual(other_node.inventory()[0]["state"], "RELEASED")

    def test_pure_plan_and_pending_recipe_precede_node_ack_auxiliary_charge_and_persistence(self):
        _, actor, identity, document = self.bootstrap()
        before = tuple(sorted(str(path.relative_to(self.node_root)) for path in self.node_root.rglob("*")))
        sequence = []
        real_plan, real_persist = self.materializer.plan, self.materializer.reserve
        real_reserve, real_charge = self.runtime_node.reserve, self.runtime_node.charge_auxiliary_bytes
        real_effect = self.executor.reserve
        def plan(assignment):
            sequence.append("plan")
            return real_plan(assignment)
        def effect(spec):
            sequence.append("executor-reserve")
            self.assertEqual(self.runtime_node.inventory()[0]["state"], "RESERVING")
            self.assertEqual(self.materializer.assignment(identity).identity, identity)
            self.assertEqual(tuple(sorted(str(path.relative_to(self.node_root)) for path in self.node_root.rglob("*"))), before)
            self.assertFalse(Path(spec.source_path).exists())
            self.assertFalse(Path(spec.config_path).exists())
            return real_effect(spec)
        def reserve(spec):
            result = real_reserve(spec)
            sequence.append("node-ack")
            self.assertEqual(self.runtime_node.inventory()[0]["state"], "RESERVED")
            return result
        def charge(key, size):
            sequence.append("auxiliary-charge")
            return real_charge(key, size)
        def persist(assignment):
            sequence.append("persist")
            row = self.runtime_node.inventory()[0]
            self.assertEqual(row["state"], "RESERVED")
            self.assertGreaterEqual(row["auxiliary_bytes"], 4 * 1024**2 + 256 * 1024)
            return real_persist(assignment)
        self.materializer.plan, self.materializer.reserve = plan, persist
        self.runtime_node.reserve, self.runtime_node.charge_auxiliary_bytes = reserve, charge
        self.executor.reserve = effect
        self.agent.receive(document)
        self.assertEqual(sequence[:5], ["plan", "executor-reserve", "node-ack", "auxiliary-charge", "persist"])
        self.assertTrue((self.materializer.assignments / (identity.key + ".json")).exists())
        self.assertTrue(Path(self.executor.specs[identity.key].source_path).is_dir())
        self.assertEqual(self.materializer._pending, {})

    def test_local_admission_failure_leaves_no_job_recipe_source_proxy_or_pending_assignment(self):
        from hf2l_jobs.executor import ExecutorRefused, ResourceLimits
        _, _, _, document = self.bootstrap()
        before = tuple(sorted(str(path.relative_to(self.node_root)) for path in self.node_root.rglob("*")))
        self.runtime_node.capacity = ResourceLimits(cpu_millis=100, memory_bytes=8 << 30, disk_bytes=8 << 30)
        with self.assertRaises(ExecutorRefused) as caught:
            self.agent.receive(document)
        self.assertEqual(caught.exception.code, "capacity")
        self.assertEqual(tuple(sorted(str(path.relative_to(self.node_root)) for path in self.node_root.rglob("*"))), before)
        self.assertEqual(self.materializer._pending, {})
        self.assertEqual(self.bindings, [])
        self.assertEqual(self.executor.calls, [])
        self.assertEqual(self.exchange.grants, {})

    def test_background_stop_request_fences_authority_without_blocking_healthy_job_lease_renewal(self):
        import threading
        enrollment, actor, _, first = self.bootstrap()
        self.agent.receive(first)
        other_job = self.new_job(key="healthy-during-offline-stop")
        metadata = self.provisioner.root / other_job["id"] / ".source.json"
        snapshot = json.loads(metadata.read_text()); snapshot["commit"] = self.source_commit
        metadata.write_text(json.dumps(snapshot))
        _, _, healthy_identity, second = self.bootstrap(job=other_job)
        self.agent.receive(second)
        prior_lease = next(row["lease_until"] for row in self.runtime_node.inventory()
                           if row["execution_key"] == healthy_identity.key)
        self.ticks += 20
        blocked, healthy, release = (threading.Event() for _ in range(3))
        def dispatch(node, document):
            if document["enrollment"]["job_id"] == self.job["id"]:
                self.assertEqual(document["operation"], "stop")
                blocked.set()
                if not release.wait(timeout=5):
                    raise AssertionError("Offline stop test did not receive its release")
                raise Error(503, "external_node_dispatch_failed")
            result = self.agent.receive(document)
            healthy.set()
            return result
        self.service.node_dispatch = dispatch
        self.service.enable_async_dispatch()
        self.addCleanup(self.service.close)
        with self.database.transaction(immediate=False) as session:
            job = session.get(models.Job, actor.job_id)
            attempt = session.get(models.Attempt, actor.attempt_id)
            session.expunge(job); session.expunge(attempt)
        try:
            self.assertFalse(self.service.request_stop(job, attempt))
            self.assertTrue(blocked.wait(timeout=3))
            self.assertTrue(healthy.wait(timeout=3))
            self.assertFalse(self.service.attempt_termination_confirmed(actor.job_id, actor.attempt_id))
            current = next(row for row in self.runtime_node.inventory() if row["execution_key"] == healthy_identity.key)
            self.assertEqual(current["state"], "RUNNING")
            self.assertGreater(current["lease_until"], prior_lease)
            self.assertEqual(self.manager.get_job("alice", other_job["id"])["state"], "RUNNING")
            self.assert_error(404, "participant_assignment_not_found", self.service.assignment_plan, actor)
            self.assert_error(404, "participant_assignment_not_found", self.service.credentials, actor)
            self.assert_error(404, "participant_assignment_not_found", self.service.open_source, actor, "plugin.py")
            with self.database.transaction(immediate=False) as session:
                details = session.get(models.ProvisioningResource, enrollment["id"]).details_json
                self.assertTrue(details["stop_requested"])
                self.assertFalse(details["termination_confirmed"])
        finally:
            release.set()

    def test_natural_runtime_exit_releases_and_confirms_completion_without_second_launch(self):
        enrollment, actor, identity, document = self.bootstrap()
        self.agent.receive(document)
        self.executor.states[identity.key] = "EXITED"
        result = self.agent.receive(document)
        self.assertTrue(result["accepted"])
        self.assertEqual(self.executor.calls.count(("start", identity.key)), 1)
        self.assertEqual(self.runtime_node.inventory()[0]["state"], "RELEASED")
        self.assertTrue(self.service.attempt_termination_confirmed(actor.job_id, actor.attempt_id))
        self.assertIn(("POST", "heartbeat", {"phase": "completed"}), self.transport.calls)
        self.assertNotIn(identity.key, self.agent._tokens)
        self.assertEqual(self.service.get_enrollment("alice", self.job["id"], "alice")["status"], "stopped")

    def test_watchdog_stopped_runtime_is_acknowledged_as_retry_and_never_revived(self):
        _, actor, identity, document = self.bootstrap()
        self.agent.receive(document)
        self.ticks = self.runtime_node.inventory()[0]["lease_until"] + 1
        self.runtime_node.watchdog_once()
        self.assertEqual(self.runtime_node.inventory()[0]["state"], "STOPPED")
        self.assertTrue(self.agent.receive(document)["accepted"])
        self.assertEqual(self.executor.calls.count(("start", identity.key)), 1)
        self.assertEqual(self.runtime_node.inventory()[0]["state"], "RELEASED")
        self.assertTrue(self.service.attempt_termination_confirmed(actor.job_id, actor.attempt_id))
        self.assertIn(("POST", "heartbeat", {"phase": "retry"}), self.transport.calls)

    def test_natural_exit_does_not_confirm_manager_until_proxy_cleanup_is_proven(self):
        _, actor, identity, document = self.bootstrap()
        self.agent.receive(document)
        self.executor.states[identity.key] = "EXITED"
        calls = []
        def stop(job_id, attempt_id, component_id, *, termination_confirmed=False):
            calls.append(termination_confirmed)
            return False
        self.agent.proxy_supervisor = SimpleNamespace(stop=stop)
        self.assert_error(503, "participant_proxy_termination_unconfirmed", self.agent.receive, document)
        self.assertFalse(self.service.attempt_termination_confirmed(actor.job_id, actor.attempt_id))
        self.assertEqual(calls, [True])
        self.assertEqual(self.executor.calls.count(("start", identity.key)), 1)


class ExternalPublicationLogTests(ExternalAgentFixture):
    def start(self):
        enrollment, actor, identity, document = self.bootstrap()
        self.agent.receive(document)
        return enrollment, actor, identity, document

    def stopping(self, enrollment):
        with self.database.transaction() as session:
            session.get(models.Job, self.job["id"]).state = "CANCELLING"
        return self.service.bootstrap_credentials(enrollment["id"])

    def stopped_and_revoked(self):
        enrollment, actor, identity, document = self.start()
        self.agent.receive(self.stopping(enrollment))
        with self.database.transaction() as session:
            session.get(models.Attempt, identity.attempt_id).revocation_confirmed = True
        return enrollment, actor, identity, document

    def spool(self, identity, content):
        from hf2l_jobs.log_stream import CanonicalLogSpool
        spool = CanonicalLogSpool(self.root / ("canonical-" + identity.key))
        spool.update(content)
        self.executor.log_spools[identity.key] = spool
        return spool

    def log_bytes(self, identity):
        response = self.manager.list_logs("alice", identity.job_id, component=identity.component_id)
        return b"".join(item["data"].encode("utf-8") for item in response["items"])

    def test_full_prepaid_log_budget_delivers_canonical_bytes_with_no_free_project_quota(self):
        from hf2l_jobs.retention import RetentionService
        enrollment, actor, identity, document = self.start()
        maximum = 2 * 1024**2
        with self.database.transaction() as session:
            project = session.get(models.Project, "project")
            self.assertEqual(project.retained_bytes, maximum)
            project.quotas_json = {**project.quotas_json, "retained_bytes": maximum}
        content = "x" * (1024**2 - 65536)
        spool = self.spool(identity, content)
        spool.mark_complete()
        self.assertEqual(self.agent.poll_logs(identity, document["node_token"], max_chunks=16, terminal=True),
            {"next_offset": len(content), "complete": True})
        self.assertEqual(self.log_bytes(identity), content.encode())
        # Retry the entire stream from offset zero, as after a helper restart.
        replay = ExternalParticipantAgent(self.client, self.materializer, self.runtime_node, self.verifier,
            node_certificate_thumbprint=self.node_certificate)
        self.addCleanup(replay.close)
        self.assertTrue(replay.poll_logs(identity, document["node_token"], max_chunks=16, terminal=True)["complete"])
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.get(models.Project, "project").retained_bytes, maximum)
            self.assertEqual(RetentionService.pool_used_bytes(session, "cpu"), maximum)
            resource = session.get(models.ProvisioningResource, enrollment["id"])
            budget = session.get(models.ProvisioningResource, resource.details_json["log_resource_id"])
            self.assertEqual(budget.size_bytes, 1024**2)
            self.assertEqual(budget.details_json["retention_charged_bytes"], 1024**2)
            self.assertEqual(budget.details_json["log_consumed_bytes"], len(content))
            chunks = list(session.scalars(select(models.LogChunk)))
            self.assertEqual(len(chunks), 15)
            self.assertTrue(all(chunk.charged_bytes == 0 for chunk in chunks))

    def test_foreign_prepaid_log_pointer_cannot_borrow_another_participants_budget(self):
        enrollment, actor, identity, document = self.start()
        foreign_budget = self.reserve_log_budgets()["bob"]
        with self.database.transaction() as session:
            resource = session.get(models.ProvisioningResource, enrollment["id"])
            historical = session.get(models.ProvisioningResource, resource.details_json["external_execution_id"])
            historical.details_json = {**historical.details_json, "log_resource_id": foreign_budget}
        self.spool(identity, "bounded training progress\n")
        self.assert_error(409, "retained_log_budget_ownership_mismatch", self.agent.poll_logs, identity, document["node_token"])
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(models.LogChunk)), 0)
            self.assertNotIn("log_consumed_bytes", session.get(models.ProvisioningResource, foreign_budget).details_json)
            self.assertEqual(session.get(models.Project, "project").retained_bytes, 2 * 1024**2)
        self.assertNotIn(identity.key, self.agent._log_offsets)

    def test_actual_plan_intersects_all_four_manager_and_local_source_limits(self):
        manager_limits = {"max_bytes": 512 * 1024, "max_files": 32,
                          "max_git_bytes": 2 * 1024**2, "max_git_files": 96}
        approval = SourceApproval("source", frozenset({"project"}),
            mirror_path=self.root / "approved-mirror", commits=frozenset({self.source_commit}), **manager_limits)
        self.provisioner.registry = RegistryCatalog(SourceRegistry([approval]),
            {"runtime": "sha256:" + "b" * 64}, dataset_bindings={"data-alice": ["alice"], "data-bob": ["bob"]})
        self.materializer.require_source_limits = True
        _, _, identity, document = self.bootstrap()
        plan = self.client.request(identity, document["node_token"], "plan")
        self.assertEqual(plan["source_limits"], manager_limits)
        self.assertEqual(plan["built_artifacts"], {})
        self.agent.receive(document)
        assignment = self.materializer.assignment(identity)
        self.assertEqual(dict(assignment.source_limits), manager_limits)
        effective = self.materializer._registry(assignment).source_registry.authorize(
            "project", "source", self.source_commit)
        self.assertEqual({key: getattr(effective, key) for key in manager_limits},
            {"max_bytes": 512 * 1024, "max_files": 16, "max_git_bytes": 1024**2, "max_git_files": 96})
        config = RuntimeConfig.model_validate_json(Path(self.executor.specs[identity.key].config_path).read_bytes())
        self.assertEqual(config.reconciliation, ())
        self.assertEqual((Path(self.executor.specs[identity.key].source_path) / "plugin.py").read_bytes(), b"VALUE = 7\n")

    def test_publication_whitelist_reads_only_owned_metadata_after_real_stop_and_revocation(self):
        _, _, identity, _ = self.stopped_and_revoked()
        self.service.node_dispatch = lambda node_id, document: self.agent.receive(document)
        root = Path(self.executor.specs[identity.key].state_path)
        paths = ["progress.json", "listener/state.json"] + [
            "listener/jobs/" + "a" * 64 + "/work/" + name for name in (
                "client-publication-intent.json", "trained_model.exchange-upload.json", "trained_model/fedavg_submission.json")]
        for number, path in enumerate(paths):
            content = json.dumps({"sequence": number}).encode()
            file = root / path
            file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            file.write_bytes(content)
            with self.subTest(path=path):
                self.assertEqual(self.service.read_publication_state(identity, path), content)
        self.assertIsNone(self.service.read_publication_state(identity,
            "listener/jobs/" + "b" * 64 + "/work/client-publication-intent.json"))
        self.assertEqual(len(self.executor.state_reads), 6)

    def test_publication_path_and_bound_validation_precedes_dispatch_or_local_read(self):
        _, _, identity, _ = self.stopped_and_revoked()
        calls = []
        self.service.node_dispatch = lambda node, document: calls.append(document)
        for path in ("../secret", "/etc/passwd", "source/plugin.py", "runtime.json", "listener/jobs/x/work/client-publication-intent.json",
                     "listener/jobs/" + "a" * 64 + "/work/private-key.pem"):
            with self.subTest(path=path):
                self.assert_error(422, "invalid_publication_state_request", self.service.read_publication_state, identity, path)
        for size in (True, 0, -1, 1024**2 + 1, "128"):
            with self.subTest(size=size):
                self.assert_error(422, "invalid_publication_state_request", self.service.read_publication_state,
                    identity, "progress.json", size)
        self.assertEqual(calls, [])
        self.assertEqual(self.executor.state_reads, [])

    def test_publication_requires_central_termination_and_revocation_plus_local_absence(self):
        enrollment, actor, identity, _ = self.start()
        self.service.node_dispatch = lambda node, document: self.agent.receive(document)
        self.assert_error(409, "participant_termination_unconfirmed", self.service.read_publication_state, identity, "progress.json")
        self.agent.receive(self.stopping(enrollment))
        self.assert_error(409, "participant_publication_fence_unconfirmed", self.service.read_publication_state, identity, "progress.json")
        with self.database.transaction() as session:
            session.get(models.Attempt, identity.attempt_id).revocation_confirmed = True
        self.executor.states[identity.key] = "RUNNING"
        self.assert_error(409, "participant_termination_unconfirmed", self.service.read_publication_state, identity, "progress.json")
        self.assertEqual(self.executor.state_reads, [])

    def test_stale_epoch_and_forged_control_never_read_publication_files(self):
        enrollment, _, identity, _ = self.stopped_and_revoked()
        stopped = self.service.bootstrap_credentials(enrollment["id"])
        document = {**stopped, "operation": "publication-state", "state_request": {"path": "progress.json", "max_bytes": 128}}
        import httpx
        for patch in ({"revocation_confirmed": 1}, {"termination_confirmed": 1},
                      {"node_id": "another-node"}, {"identity": {"job_id": "foreign"}}):
            def rewrite(response, url, patch=patch):
                return httpx.Response(200, json={**response.json(), **patch}) if url.endswith("/control") else response
            self.transport.rewrite = rewrite
            with self.subTest(patch=patch):
                self.assert_error(409, "participant_publication_fence_unconfirmed", self.agent.receive, document)
        self.transport.rewrite = None
        with self.database.transaction() as session:
            session.get(models.Job, identity.job_id).epoch = 2
        self.assert_error(401, "invalid_node_grant", self.agent.receive, document)
        self.assertEqual(self.executor.state_reads, [])

    def test_publication_service_rejects_forged_identity_hash_encoding_and_bounds(self):
        _, _, identity, _ = self.stopped_and_revoked()
        from dataclasses import asdict
        receipt = {"identity": asdict(identity), "exists": True,
                   "content_base64": base64.b64encode(b"safe").decode(), "sha256": hashlib.sha256(b"safe").hexdigest()}
        for patch in ({"identity": {"job_id": "foreign"}}, {"exists": 1}, {"content_base64": "?"},
                      {"sha256": "0" * 64}, {"content_base64": base64.b64encode(b"12345").decode(),
                                             "sha256": hashlib.sha256(b"12345").hexdigest()}):
            self.service.node_dispatch = lambda node, document, patch=patch: {**receipt, **patch}
            with self.subTest(patch=patch):
                self.assert_error(502, "invalid_publication_state_receipt", self.service.read_publication_state,
                    identity, "progress.json", 4)
        self.assertEqual(self.executor.state_reads, [])

    def test_redacted_canonical_bytes_are_durable_and_restart_replay_never_duplicates_logs(self):
        from hf2l_jobs.collection import SafeCollector
        _, _, identity, document = self.start()
        raw = self.root / "raw-logs"
        raw.mkdir(mode=0o700)
        (raw / "stdout.log").write_text("token=very-private-test-token\nmetric=π\n")
        with SafeCollector(raw, secret_values=["very-private-test-token"]) as collector:
            redacted = collector.logs("stdout.log")
        self.assertNotIn("very-private-test-token", redacted)
        spool = self.spool(identity, redacted)
        first = self.agent.poll_logs(identity, document["node_token"])
        self.assertEqual(first, {"next_offset": len(redacted.encode()), "complete": False})
        self.assertEqual(self.log_bytes(identity), redacted.encode())
        replay = ExternalParticipantAgent(self.client, self.materializer, self.runtime_node, self.verifier,
            node_certificate_thumbprint=self.node_certificate)
        self.addCleanup(replay.close)
        self.assertEqual(replay.poll_logs(identity, document["node_token"]), first)
        self.assertEqual(self.log_bytes(identity), redacted.encode())
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(models.LogChunk)), 1)
        self.assert_error(404, "job_not_found", self.manager.list_logs, "bob", identity.job_id)

    def test_terminal_stop_catches_up_multiple_utf8_chunks_before_release_and_central_ack(self):
        enrollment, actor, identity, _ = self.start()
        content = "2026-10-09T00:00:00Z metric=π token=[REDACTED]\n" * 3000
        expected = content.encode()
        self.assertGreater(len(expected), 65536)
        self.spool(identity, content)
        self.transport.calls.clear()
        self.assertEqual(self.agent.receive(self.stopping(enrollment)), {"accepted": True, "state": "stopped"})
        operations = [operation for _, operation, _ in self.transport.calls]
        self.assertGreater(operations.count("logs"), 1)
        self.assertEqual(operations[0], "control")
        self.assertEqual(operations[-1], "stopped")
        self.assertEqual(self.log_bytes(identity), expected)
        self.assertEqual(self.agent._log_offsets[identity.key], len(expected))
        self.assertEqual(self.runtime_node.inventory()[0]["state"], "RELEASED")
        self.assertTrue(self.service.attempt_termination_confirmed(actor.job_id, actor.attempt_id))
        with self.database.transaction(immediate=False) as session:
            historical = session.scalar(select(models.ProvisioningResource).where(
                models.ProvisioningResource.kind == "external_execution", models.ProvisioningResource.external_id == identity.key))
            self.assertTrue(historical.details_json["log_stream"]["complete"])

    def test_unconfirmed_terminal_logs_hold_release_and_manager_stop_barrier(self):
        enrollment, actor, identity, _ = self.start()
        original = self.executor.read_logs
        self.executor.read_logs = lambda *args, **kwargs: {**original(*args, **kwargs), "complete": False}
        self.assert_error(503, "participant_terminal_logs_unconfirmed", self.agent.receive, self.stopping(enrollment))
        self.assertEqual(self.runtime_node.inventory()[0]["state"], "STOPPED")
        self.assertEqual(self.executor.calls.count(("release", identity.key)), 0)
        self.assertFalse(self.service.attempt_termination_confirmed(actor.job_id, actor.attempt_id))
        self.assertNotIn("stopped", [operation for _, operation, _ in self.transport.calls])

    def test_lost_log_ack_retries_from_old_cursor_without_duplicate_committed_bytes(self):
        import httpx
        _, _, identity, document = self.start()
        self.spool(identity, "metric=7 token=[REDACTED]\n")
        def rewrite(response, url):
            return httpx.Response(200, json={"accepted": False, "next_offset": 0}) if url.endswith("/logs") else response
        self.transport.rewrite = rewrite
        self.assert_error(502, "invalid_external_log_acknowledgment", self.agent.poll_logs, identity, document["node_token"])
        self.assertNotIn(identity.key, self.agent._log_offsets)
        committed = self.log_bytes(identity)
        self.transport.rewrite = None
        self.agent.poll_logs(identity, document["node_token"])
        self.assertEqual(self.log_bytes(identity), committed)
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(models.LogChunk)), 1)

    def test_log_scope_current_epoch_and_foreign_receipt_are_fenced_before_insert(self):
        _, actor, identity, document = self.start()
        spool = self.spool(identity, "metric=7\n")
        receipt = spool.read(identity)
        self.assert_error(403, "node_scope_required", self.service.append_logs,
            replace(actor, scopes=frozenset({"stopped"})), receipt)
        for patch in ({"source_id": "foreign-execution"}, {"next_offset": receipt["next_offset"] + 1},
                      {"complete": 1}):
            with self.subTest(patch=patch):
                self.assert_error(422, "invalid_log_receipt", self.service.append_logs, actor, {**receipt, **patch})
                self.assert_error(422, "invalid_request", self.client.request,
                    identity, document["node_token"], "logs", body={**receipt, **patch})
        with self.database.transaction() as session:
            session.get(models.Job, identity.job_id).epoch = 2
        self.assert_error(401, "invalid_node_grant", self.client.request,
            identity, document["node_token"], "logs", body=receipt)
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(models.LogChunk)), 0)


class ExternalCSRTests(ExternalAgentFixture):
    def setUp(self):
        super().setUp()
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import NameOID
        from hf2l_jobs.certificates import CertificateIssuer
        central = self.root / "central-issuer"
        central.mkdir(mode=0o700)
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Central Workload CA")])
        self.ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(self.ca_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(self.now - timedelta(minutes=1)).not_valid_after(self.now + timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key())), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .sign(self.ca_key, hashes.SHA256()))
        self.ca_file = central / "public-ca.pem"
        self.ca_file.write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))
        self.ca_file.chmod(0o644)
        ca_key_file = central / "private-ca.key"
        ca_key_file.write_bytes(self.ca_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        ca_key_file.chmod(0o600)
        actual_issuer = CertificateIssuer(self.ca_file, ca_key_file, clock=lambda: self.now.timestamp())
        self.issuer_calls = []
        def issue(csr_pem, **kwargs):
            self.issuer_calls.append((csr_pem, kwargs))
            return actual_issuer.issue(csr_pem, **kwargs)
        self.service.certificate_issuer = SimpleNamespace(issue=issue)

    @staticmethod
    def csr():
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import NameOID
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "untrusted-subject")]))
               .sign(private, hashes.SHA256()))
        return private, csr.public_bytes(serialization.Encoding.PEM).decode()

    def issue(self, actor, csr_pem, **overrides):
        plan = self.service.assignment_plan(actor)
        arguments = {"csr_pem": csr_pem, "space_id": plan["space_id"], "principal_id": plan["principal_id"]}
        arguments.update(overrides)
        return self.service.issue_certificate(actor, **arguments)

    def test_central_csr_issuer_returns_only_public_leaf_bound_to_node_private_key(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import ExtendedKeyUsageOID
        _, actor, identity, document = self.bootstrap()
        private, csr = self.csr()
        plan = self.service.assignment_plan(actor)
        receipt = self.client.request(identity, document["node_token"], "certificate", body={
            "csr_pem": csr, "space_id": plan["space_id"], "principal_id": plan["principal_id"]})
        cert = x509.load_pem_x509_certificate(receipt["certificate_pem"].encode())
        cert.verify_directly_issued_by(self.ca)
        self.assertEqual(cert.public_key().public_numbers(), private.public_key().public_numbers())
        self.assertFalse(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertIn(ExtendedKeyUsageOID.CLIENT_AUTH, cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
        fingerprint = base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA256())).decode().rstrip("=")
        self.assertEqual(receipt["certificate_thumbprint"], fingerprint)
        self.assertNotIn("PRIVATE KEY", json.dumps(receipt))
        self.assertNotIn("PRIVATE KEY", json.dumps(self.transport.calls))
        self.assertEqual(len(self.issuer_calls), 1)
        self.assertEqual(self.issuer_calls[0][1]["identity"], identity)
        self.assertEqual(self.issuer_calls[0][1]["space_id"], plan["space_id"])
        self.assertLessEqual(cert.not_valid_after_utc, self.ca.not_valid_after_utc)

    def test_csr_retry_is_durable_and_cannot_rotate_to_a_different_private_key(self):
        _, actor, _, _ = self.bootstrap()
        _, csr = self.csr()
        first = self.issue(actor, csr)
        self.now += timedelta(seconds=10)
        second = self.issue(actor, csr)
        self.assertEqual(first, second)
        self.assertEqual(len(self.issuer_calls), 1)
        _, foreign_csr = self.csr()
        self.assert_error(409, "participant_execution_binding_immutable", self.issue, actor, foreign_csr)
        self.assertEqual(len(self.issuer_calls), 1)
        with self.database.transaction(immediate=False) as session:
            receipts = list(session.scalars(select(models.ProvisioningOperation).where(
                models.ProvisioningOperation.operation == "external_client_certificate")))
            self.assertEqual(len(receipts), 1)
            self.assertNotIn("PRIVATE KEY", json.dumps(receipts[0].observed_json))

    def test_csr_cannot_select_foreign_space_or_principal_and_no_authority_is_issued(self):
        _, actor, _, _ = self.bootstrap()
        _, csr = self.csr()
        for override in ({"space_id": "foreign-space"}, {"principal_id": "foreign-principal"}):
            self.assert_error(403, "participant_foreign_certificate_binding", self.issue, actor, csr, **override)
        self.assertEqual(self.issuer_calls, [])

    def test_uncertified_execution_fingerprint_cannot_get_grant_when_central_issuer_is_configured(self):
        _, actor, _, _ = self.bootstrap()
        self.assert_error(403, "approved_execution_certificate_required", self.service.assignment, actor,
                          execution_certificate_thumbprint=certificate("uncertified-node-fingerprint"), proxy_id="uncertified")
        self.assertEqual(self.exchange.grants, {})
        _, csr = self.csr()
        receipt = self.issue(actor, csr)
        assignment = self.service.assignment(actor, execution_certificate_thumbprint=receipt["certificate_thumbprint"],
                                             proxy_id="approved-csr-proxy")
        principal = self.broker.authenticate_workload("Bearer " + assignment["credentials"]["exchange_token"],
                              verified_peer_thumbprint=receipt["certificate_thumbprint"])
        self.assertEqual(principal.certificate_thumbprint, receipt["certificate_thumbprint"])

    def test_stale_certificate_or_missing_assignment_scope_rejected_before_issuer_side_effect(self):
        _, actor, _, _ = self.bootstrap()
        _, csr = self.csr()
        plan = self.service.assignment_plan(actor)
        arguments = {"csr_pem": csr, "space_id": plan["space_id"], "principal_id": plan["principal_id"]}
        self.assert_error(403, "node_scope_required", self.service.issue_certificate,
                          replace(actor, scopes=frozenset({"stopped"})), **arguments)
        with self.database.transaction() as session:
            session.get(models.Job, self.job["id"]).epoch = actor.epoch + 1
        self.assert_error(404, "participant_assignment_not_found", self.service.issue_certificate, actor, **arguments)
        self.assertEqual(self.issuer_calls, [])


    def test_invalid_csr_does_not_poison_durable_identity_before_valid_key_can_be_issued(self):
        _, actor, _, _ = self.bootstrap()
        plan = self.service.assignment_plan(actor)
        arguments = {"space_id": plan["space_id"], "principal_id": plan["principal_id"]}
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import NameOID
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_csr = (x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "arbitrary-authority")]))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(private, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
        for invalid in ("not-a-certificate-request", ca_csr):
            with self.subTest(csr=invalid[:30]):
                self.assert_error(422, "invalid_execution_csr", self.service.issue_certificate, actor,
                                  csr_pem=invalid, **arguments)
                with self.database.transaction(immediate=False) as session:
                    self.assertEqual(session.scalar(select(func.count()).select_from(models.ProvisioningOperation)
                        .where(models.ProvisioningOperation.operation == "external_client_certificate")), 0)
        self.assertEqual(self.issuer_calls, [])
        _, csr = self.csr()
        receipt = self.service.issue_certificate(actor, csr_pem=csr, **arguments)
        self.assertIn("certificate_pem", receipt)
        self.assertEqual(len(self.issuer_calls), 1)


    def test_external_agent_composition_uses_local_ledger_public_keys_and_local_catalog_without_manager_db(self):
        from unittest.mock import patch
        from cryptography.hazmat.primitives import serialization
        from hf2l_jobs.participants import compose_external_agent
        local_root = self.root / "independent-agent"
        local_root.mkdir(mode=0o700)
        node_key, csr = self.csr()
        _, actor, _, _ = self.bootstrap()
        node_certificate = self.issue(actor, csr)
        cert_file, key_file = local_root / "registered-node.pem", local_root / "registered-node.key"
        cert_file.write_text(node_certificate["certificate_pem"]); cert_file.chmod(0o644)
        key_file.write_bytes(node_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); key_file.chmod(0o600)
        settings = SimpleNamespace(broker=self.verifier.settings, extra={
            "participants": {"agent": {"manager_endpoint": "https://manager.example.test",
                "manager_ca_file": str(self.ca_file), "node_certificate": str(cert_file), "node_key": str(key_file),
                "certificate_ca_file": str(self.ca_file), "managed_exchange_endpoint": "https://exchange.example.test",
                "gateway_endpoint": "https://gateway.example.test", "service_ca_file": str(self.ca_file),
                "manager_certificate_thumbprints": [certificate("trusted-manager")],
                "proxy_socket_root": str(self.root / "s"), "catalog": {
                    "sources": [{"source_id": "source", "projects": ["project"], "commits": [self.source_commit],
                                 "mirror_path": str(self.root / "approved-mirror")}],
                    "runtime_images": {"runtime": "sha256:" + "b" * 64}}}},
            "node": {"node_id": "external-node", "pool_id": "external", "ledger_path": str(local_root / "node.sqlite"),
                "capacity": {"cpu_millicores": 2000, "memory_bytes": 2 << 30, "disk_bytes": 2 << 30},
                "dataset_bindings": {"data-alice": {"kind": "synthetic", "project_id": "project", "participant_id": "alice"}}},
            "executor": {"root": str(local_root), "profile_path": str(local_root / "qualified-profile.json")}})
        with patch("hf2l_jobs.composition._database", side_effect=AssertionError("Manager SQL must not be opened")) as manager_db, \
                patch("hf2l_jobs.executor.LinuxExecutor", return_value=self.executor) as executor_factory, \
                patch("hf2l_jobs.participants.ExternalManagerClient", return_value=self.client):
            agent, close = compose_external_agent(settings)
            try:
                self.assertIsNone(agent.broker.settings.private_key)
                self.assertIsNone(agent.proxy_supervisor.ca_key)
                self.assertIsNone(agent.materializer.registry.database)
                self.assertEqual(agent.materializer.registry.dataset_projects, {"data-alice": "project"})
                self.assertEqual(agent.node.pool_id, "external")
                self.assertTrue((local_root / "node.sqlite").is_file())
                self.assertTrue(agent._log_thread.is_alive())
                from hf2l_jobs.executor import ExecutionIdentity, ResourceLimits
                from hf2l_jobs.remote_node import RemoteAssignment
                identity = ExecutionIdentity(actor.job_id, actor.attempt_id, actor.component_id, actor.epoch)
                plan = self.service.assignment_plan(actor)
                assignment = RemoteAssignment(identity=identity, node_id="external-node", pool_id="external",
                    resources=ResourceLimits(cpu_millis=500, memory_bytes=128 << 20, disk_bytes=256 << 20),
                    job_spec=JobSpec.model_validate(plan["job_spec"]), image_digest=plan["image_digest"],
                    external_participant_id="alice", source_limits=plan["source_limits"])
                agent.materializer.reserve(assignment)
                callback = executor_factory.call_args.kwargs["dataset_authorizer"]
                self.assertEqual(callback("data-alice", identity, "alice"), {"kind": "synthetic"})
                with self.assertRaises(ValueError):
                    callback("data-alice", identity, "bob")
                manager_db.assert_not_called()
            finally:
                close()


    def test_durable_stop_intent_blocks_current_csr_before_issuer_or_receipt_side_effect(self):
        _, actor, _, _ = self.bootstrap()
        _, csr = self.csr()
        plan = self.service.assignment_plan(actor)
        with self.database.transaction(immediate=False) as session:
            job, attempt = session.get(models.Job, actor.job_id), session.get(models.Attempt, actor.attempt_id)
            session.expunge(job); session.expunge(attempt)
        self.assertFalse(self.service.request_stop(job, attempt))
        self.assertEqual(self.manager.get_job("alice", actor.job_id)["state"], "RUNNING")
        self.assert_error(404, "participant_assignment_not_found", self.service.issue_certificate, actor,
            csr_pem=csr, space_id=plan["space_id"], principal_id=plan["principal_id"])
        self.assertEqual(self.issuer_calls, [])
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(models.ProvisioningOperation)
                .where(models.ProvisioningOperation.operation == "external_client_certificate")), 0)

    def test_actual_csr_proxy_keeps_keys_local_starts_runtime_and_confirms_proxy_stop(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from hf2l_jobs.execution_proxy import ProxySupervisor
        from hf2l_jobs.remote_node import NodeCertificateProvider, NodeCredentialClient, NodeEndpoint
        enrollment, actor, identity, document = self.bootstrap()
        credential_client = NodeCredentialClient(NodeEndpoint(node_id="external-node",
            origin="https://manager.example.test", ca_file=str(self.ca_file),
            client_certificate=str(self.root / "registered-node.pem"), client_key=str(self.root / "registered-node.key")),
            route_prefix="participants", token_provider=lambda identity, operation: self.agent._tokens[identity.key],
            http=self.transport)
        provider = NodeCertificateProvider(credential_client, workload_issuer=self.verifier.settings.workload_issuer,
                                           assignment_lookup=self.materializer.assignment)
        supervisor = ProxySupervisor(self.node_root / "proxies", client_ca_certificate=self.ca_file,
            client_ca_key=None, certificate_provider=provider, broker=self.verifier,
            exchange_endpoint="https://exchange.example.test", gateway_endpoint="https://gateway.example.test",
            service_ca_file=str(self.ca_file), grant_lookup=None, socket_root=self.root / "s",
            token_provider=lambda binding, participant, audience: self.agent.delegated_token(binding, participant, audience))
        self.addCleanup(supervisor.close)
        self.materializer.proxy_endpoint = supervisor.endpoint
        self.materializer.execution_bindings = lambda assignment, space, principal: supervisor.binding(
            SimpleNamespace(id=assignment.identity.job_id, deadline_at=assignment.deadline),
            SimpleNamespace(id=assignment.identity.attempt_id, job_id=assignment.identity.job_id, epoch=assignment.identity.epoch),
            SimpleNamespace(component_id=assignment.identity.component_id, participant_id=assignment.external_participant_id),
            space, principal)
        self.agent.proxy_supervisor = supervisor
        self.assertEqual(self.agent.receive(document), {"accepted": True, "state": "RUNNING"})
        spec = self.executor.specs[identity.key]
        self.assertTrue(Path(spec.proxy_endpoint).is_socket())
        self.assertIsNone(supervisor.ca_key)
        self.assertIsNone(self.agent.broker.settings.private_key)
        proxy_directory = self.node_root / "proxies" / identity.job_id / "attempts" / identity.attempt_id / identity.component_id
        key_path, certificate_path = proxy_directory / "proxy-key.pem", proxy_directory / "proxy-cert.pem"
        private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert = x509.load_pem_x509_certificate(certificate_path.read_bytes())
        self.assertEqual(private.public_key().public_numbers(), cert.public_key().public_numbers())
        self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
        self.assertNotEqual(private.public_key().public_numbers(), self.ca_key.public_key().public_numbers())
        self.assertNotIn("PRIVATE KEY", json.dumps(self.transport.calls))
        self.assertEqual([operation for _, operation, _ in self.transport.calls], ["plan", "certificate", "assignment", "credentials", "heartbeat"])
        self.agent.receive(document)
        self.assertEqual(len(self.issuer_calls), 1)
        # Pause the real service at its durable grant handoff after the first
        # enrollment transaction. A same-binding replay must keep the running
        # proxy's current credential authority while this handoff is in flight.
        from concurrent.futures import ThreadPoolExecutor
        import threading
        entered, continue_assignment = threading.Event(), threading.Event()
        real_run = self.service.ledger.run
        def blocked_grant(**kwargs):
            if kwargs["operation"] == "external_workload_grant":
                entered.set()
                if not continue_assignment.wait(timeout=5):
                    raise AssertionError("Re-dispatch grant handoff was not released")
            return real_run(**kwargs)
        self.service.ledger.run = blocked_grant
        with self.database.transaction(immediate=False) as session:
            saved = dict(session.get(models.ProvisioningResource, enrollment["id"]).details_json)
        proxy = supervisor._active[(identity.job_id, identity.attempt_id, identity.component_id)]
        try:
            with ThreadPoolExecutor(max_workers=1) as workers:
                redispatch = workers.submit(self.service.assignment, actor,
                    execution_certificate_thumbprint=saved["execution_certificate_thumbprint"], proxy_id=saved["proxy_id"])
                try:
                    self.assertTrue(entered.wait(timeout=3))
                    with self.database.transaction(immediate=False) as session:
                        self.assertEqual(session.get(models.ProvisioningResource, enrollment["id"]).details_json["status"], "assigned")
                    self.assertTrue(proxy.thread.is_alive())
                    token = self.agent.delegated_token(proxy.binding, "alice", "exchange")
                    self.assertIsInstance(token, str)
                    self.assertEqual(self.executor.states[identity.key], "RUNNING")
                    self.exchange.grants[saved["workload_grant"]["grant_id"]]["enabled"] = False
                    self.assert_error(401, "participant_grant_revoked", self.agent.delegated_token,
                        proxy.binding, "alice", "exchange")
                    self.exchange.grants[saved["workload_grant"]["grant_id"]]["enabled"] = True
                finally:
                    continue_assignment.set()
                self.assertEqual(redispatch.result(timeout=5)["grant"], saved["workload_grant"])
        finally:
            continue_assignment.set()
            self.service.ledger.run = real_run
        with self.database.transaction() as session:
            session.get(models.Job, self.job["id"]).state = "CANCELLING"
        self.assertEqual(self.agent.receive(self.service.bootstrap_credentials(enrollment["id"])),
                         {"accepted": True, "state": "stopped"})
        self.assertFalse(Path(spec.proxy_endpoint).exists())
        self.assertEqual(self.runtime_node.inventory()[0]["state"], "RELEASED")
        self.assertTrue(self.service.attempt_termination_confirmed(actor.job_id, actor.attempt_id))
        self.assertEqual(supervisor._active, {})


class ExternalNodeIngressTests(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        self.calls = []
        def receive(document):
            if not isinstance(document, dict):
                raise Error(422, "invalid_participant_dispatch")
            self.calls.append(document)
            return {"accepted": True}
        self.manager_certificate = certificate("allowed-manager")
        self.app = create_participant_node_app(SimpleNamespace(receive=receive), [self.manager_certificate])
        self.client = TestClient(VerifiedPeerFixture(self.app, self.manager_certificate), base_url="https://node.example.test")
        self.addCleanup(self.client.close)
        self.target = "/internal/nodes/v1/participants"

    def assert_response(self, response, status, code):
        self.assertEqual((response.status_code, response.json()["error"]["code"]), (status, code))
        self.assertEqual(self.calls, [])

    def test_verified_manager_allowlist_required_even_with_raw_certificate_headers(self):
        from fastapi.testclient import TestClient
        for app in (self.app, VerifiedPeerFixture(self.app, certificate("foreign-manager"))):
            with TestClient(app, base_url="https://node.example.test") as client:
                response = client.post(self.target, json={"node_token": "opaque"}, headers={
                    "X-HF2L-TLS-Thumbprint": self.manager_certificate,
                    "X-Client-Cert-Thumbprint": self.manager_certificate})
                self.assert_response(response, 401, "verified_manager_certificate_required")
        self.assertEqual(self.client.post(self.target, json={"node_token": "opaque"}).status_code, 200)
        self.assertEqual(self.calls, [{"node_token": "opaque"}])

    def test_empty_or_malformed_manager_allowlist_rejected_at_composition(self):
        for values in ([], ["not-a-canonical-certificate"], [self.manager_certificate + "="]):
            with self.assertRaises((ValueError, Error)):
                create_participant_node_app(SimpleNamespace(receive=lambda document: document), values)

    def test_invalid_negative_oversized_or_duplicate_content_lengths_fail_before_dispatch(self):
        for value in ("garbage", "-1", "1.0", "99999999999"):
            with self.subTest(value=value):
                self.assert_response(self.client.post(self.target, content=b"{}", headers={"Content-Length": value}),
                                     400, "invalid_content_length")
        self.assert_response(self.client.post(self.target, content=b"{}", headers=[("Content-Length", "2"),
                             ("Content-Length", "2")]), 400, "invalid_content_length")

    def test_declared_or_streamed_oversized_payload_is_bounded(self):
        self.assert_response(self.client.post(self.target, content=b"{}", headers={"Content-Length": str(1024**2 + 1)}),
                             413, "request_too_large")
        def chunks():
            yield b" " * (1024**2)
            yield b"{}"
        self.assert_response(self.client.post(self.target, content=chunks()), 413, "request_too_large")

    def test_invalid_json_and_structured_body_errors_return_422(self):
        self.assert_response(self.client.post(self.target, content=b"{bad json"), 422, "invalid_participant_dispatch")
        self.assert_response(self.client.post(self.target, json=[]), 422, "invalid_participant_dispatch")

    def test_manager_endpoint_cannot_select_plaintext_or_path_query_or_credentials(self):
        for endpoint in ("http://manager.example.test", "https://manager.example.test/api",
                         "https://manager.example.test?redirect=foreign", "https://user:password@manager.example.test"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                ExternalManagerClient(endpoint, http=SimpleNamespace())


if __name__ == "__main__":
    unittest.main()
