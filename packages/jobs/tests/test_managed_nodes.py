"""Real CSR/RS256 tests for the central managed-node service."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import time
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import jwt
from sqlalchemy import select

from hf2l_jobs.broker import BrokerSettings, WorkloadBroker, stable_workload_principal
from hf2l_jobs.certificates import CertificateIssuer
from hf2l_jobs.database import create_database
from hf2l_jobs.domain import Error, JobSpec
from hf2l_jobs.executor import ExecutionIdentity
from hf2l_jobs.managed_nodes import ApprovedManagedNode, NodeAssignmentService
from hf2l_jobs.models import Allocation, Attempt, Job, Pool, Project, ProvisioningOperation, ProvisioningResource
from hf2l_jobs.resources import ResourceLedger


def thumb(value):
    return base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).decode().rstrip("=")


def pem_private(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def csr(key, *, extension=False):
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "untrusted requested identity")]))
    if extension:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


class FakeExchange:
    def __init__(self):
        self.grants = {}
        self.calls = []

    @staticmethod
    def path(space, suffix):
        return "/v2/spaces/" + space + suffix

    def request(self, method, path):
        self.calls.append((method, path))
        identifier = path.rsplit("/", 1)[-1]
        return dict(self.grants[identifier])


class FakeProvisioner:
    def __init__(self):
        self.exchange = FakeExchange()
        self.foreign_plan = False

    def _space_id(self, job_id):
        return "space-" + job_id

    def prepared_component(self, job, attempt, component_id):
        from hf2l_jobs.workflow import RuntimeConfig
        result = RuntimeConfig(
            role="owner", job_id=job.id, attempt_id=attempt.id, component_id=component_id,
            epoch=attempt.epoch, space_id=self._space_id(job.id),
            spec=JobSpec.model_validate(job.spec_json), spec_digest=job.spec_hash,
            deadline_at=job.deadline_at.timestamp()).model_dump(mode="json")
        if self.foreign_plan:
            result["job_id"] = "foreign-job"
        return result


class CountingIssuer:
    def __init__(self, issuer):
        self.issuer, self.calls = issuer, 0

    def issue(self, *args, **kwargs):
        self.calls += 1
        return self.issuer.issue(*args, **kwargs)


class ManagedNodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.execution_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_execution_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.started = int(time.time())
        current = datetime.fromtimestamp(cls.started, timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test control-plane CA")])
        cls.ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                  .public_key(cls.ca_key.public_key()).serial_number(x509.random_serial_number())
                  .not_valid_before(current - timedelta(minutes=1))
                  .not_valid_after(current + timedelta(days=60))
                  .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                  .add_extension(x509.SubjectKeyIdentifier.from_public_key(cls.ca_key.public_key()), critical=False)
                  .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                      x509.SubjectKeyIdentifier.from_public_key(cls.ca_key.public_key())), critical=False)
                  .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                      key_encipherment=False, data_encipherment=False, key_agreement=False,
                      key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
                  .sign(cls.ca_key, hashes.SHA256()))

    def setUp(self):
        self.now = self.started
        self.database = create_database("sqlite:///:memory:")
        self.node_thumb, self.manager_thumb = thumb("registered-node"), thumb("manager-client")
        self.settings = BrokerSettings(
            "https://jobs.example.test/workloads", "managed-exchange", "managed-transfer", "managed-nodes",
            self.signing_key.public_key(), self.signing_key)
        self.broker = WorkloadBroker(self.settings, clock=lambda: self.now)
        self.provisioner = FakeProvisioner()
        self.issuer = CountingIssuer(CertificateIssuer(
            self.ca.public_bytes(serialization.Encoding.PEM), pem_private(self.ca_key), clock=lambda: self.now))
        self.registrations = {"node-a": ApprovedManagedNode("node-a", "cpu", self.node_thumb, "registration-a")}
        self.service = self.new_service()
        resources = dict(pool_id="cpu", cpu_millicores=1000, memory_bytes=1024**3, disk_bytes=1024**3)
        self.spec = JobSpec(
            project_id="project-a", name="Training", source_id="source", source_commit="a" * 40,
            runtime_image="approved-image", plugin="plugin", components=[
                dict(component_id="owner", role="owner", resources=resources),
                dict(component_id="builder", role="build", resources=resources)],
            target_round=2, max_duration_seconds=3600)
        self.identity = ExecutionIdentity("job-a", "attempt-a", "owner", 1)
        with self.database.transaction() as session:
            session.add(Project(id="project-a", name="A"))
            session.flush()
            session.add(Pool(id="cpu", name="CPU", node_id="node-a", healthy=True,
                             cpu_millicores=10000, memory_bytes=16 * 1024**3, disk_bytes=16 * 1024**3,
                             details_json={"registration_id": "registration-a"}))
            session.add(Job(id="job-a", project_id="project-a", creator_id="human", name=self.spec.name,
                            spec_json=self.spec.to_dict(), spec_hash=self.spec.digest, state="PROVISIONING",
                            target_round=2, epoch=1, current_attempt=1, current_round=0,
                            deadline_at=datetime.fromtimestamp(self.now + 3600, timezone.utc)))
            session.flush()
            session.add(Attempt(id="attempt-a", job_id="job-a", number=1, epoch=1))
            session.flush()
            for component in self.spec.components:
                session.add(Allocation(
                    id="allocation-" + component.component_id, job_id="job-a", attempt_id="attempt-a",
                    component_id=component.component_id, pool_id="cpu", epoch=1, state="ACKNOWLEDGED",
                    acknowledged=True, cpu_millicores=1000, memory_bytes=1024**3, disk_bytes=1024**3,
                    details_json={"node_id": "node-a", "registration_id": "registration-a"}))
        self.csr = csr(self.execution_key)

    def new_service(self):
        return NodeAssignmentService(self.database, self.provisioner, self.broker, self.registrations,
            issuer=self.issuer, manager_certificate_thumbprint=self.manager_thumb, clock=lambda: self.now)

    def tearDown(self):
        self.database.close()

    def bootstrap(self, identity=None, fingerprint=None):
        identity = identity or self.identity
        return self.service.bootstrap(fingerprint or self.node_thumb,
            job_id=identity.job_id, attempt_id=identity.attempt_id,
            component_id=identity.component_id, epoch=identity.epoch)

    def actor(self, identity=None):
        return self.service.authenticate_node("Bearer " + self.bootstrap(identity)["token"],
                                              verified_peer_thumbprint=self.node_thumb)

    def issue(self, actor=None, **kwargs):
        actor = actor or self.actor()
        data = {"csr_pem": self.csr, "space_id": "space-job-a",
                "principal_id": stable_workload_principal(self.settings.workload_issuer, "job-a", "owner")}
        data.update(kwargs)
        return self.service.issue_certificate(actor, **data)

    def grant(self, certificate=None):
        certificate = certificate or self.issue()
        value = {"job_id": "job-a", "attempt_id": "attempt-a", "component_id": "owner", "epoch": 1,
                 "space_id": "space-job-a",
                 "principal_id": stable_workload_principal(self.settings.workload_issuer, "job-a", "owner"),
                 "grant_id": "workload-grant", "certificate_thumbprint": certificate["certificate_thumbprint"],
                 "enabled": True, "expires_at": self.now + 3000}
        self.provisioner.exchange.grants["workload-grant"] = value
        ResourceLedger(self.database).own(job_id="job-a", attempt_id="attempt-a", component_id="owner",
            kind="workload_grant", external_id="workload-grant", details=value)
        return value

    def test_bootstrap_is_registered_cert_bound_current_allocation(self):
        bootstrap = self.bootstrap()
        actor = self.service.authenticate_node("Bearer " + bootstrap["token"],
                                              verified_peer_thumbprint=self.node_thumb)
        claims = jwt.decode(bootstrap["token"], options={"verify_signature": False})
        self.assertEqual(actor.grant_id, "allocation-owner")
        self.assertEqual(actor.scopes, frozenset({"assignment"}))
        self.assertEqual(claims["cnf"]["x5t#S256"], self.node_thumb)
        self.assertEqual(claims["exp"] - claims["iat"], 300)
        self.assertEqual(actor.resources["cpu_millicores"], 1000)
        with self.assertRaises(Error):
            self.service.authenticate_node("Bearer " + bootstrap["token"],
                                            verified_peer_thumbprint=self.manager_thumb)

    def test_unknown_cert_foreign_node_epoch_and_job_are_refused(self):
        for fingerprint in (thumb("unknown"), self.manager_thumb):
            with self.subTest(fingerprint=fingerprint), self.assertRaises(Error):
                self.bootstrap(fingerprint=fingerprint)
        for identity in (ExecutionIdentity("other-job", "attempt-a", "owner", 1),
                         ExecutionIdentity("job-a", "other-attempt", "owner", 1),
                         ExecutionIdentity("job-a", "attempt-a", "owner", 2)):
            with self.subTest(identity=identity), self.assertRaises(Error):
                self.bootstrap(identity)
        with self.database.transaction() as session:
            session.get(Pool, "cpu").node_id = "unregistered-node"
        actor = self.actor()
        with self.assertRaises(Error):
            self.service.assignment(actor)
        self.assertIsInstance(self.service.issue_control_token(
            self.identity, node_id="node-a", pool_id="cpu", scope="stop"), str)

    def test_full_gang_ack_required_for_start_source_csr_and_credentials(self):
        with self.database.transaction() as session:
            session.get(Allocation, "allocation-builder").acknowledged = False
        actor = self.actor()
        token = self.service.issue_control_token(self.identity, node_id="node-a", pool_id="cpu", scope="reserve")
        self.assertIsInstance(token, str)
        for action in (lambda: self.issue(actor),
                       lambda: self.service.assignment(actor),
                       lambda: self.service.credentials(actor, certificate_thumbprint=thumb("execution"), audience="exchange"),
                       lambda: self.service.issue_control_token(self.identity, node_id="node-a", pool_id="cpu", scope="start")):
            with self.assertRaises(Error):
                action()

    def test_actual_public_csr_issuance_is_durable_and_outlives_jwt(self):
        receipt = self.issue()
        cert = x509.load_pem_x509_certificate(receipt["certificate_pem"].encode())
        self.assertEqual(cert.public_key().public_numbers(), self.execution_key.public_key().public_numbers())
        self.assertFalse(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertGreater(receipt["expires_at"] - self.now, 300)
        self.assertNotIn("PRIVATE KEY", json.dumps(receipt))
        self.assertEqual(set(receipt), {"certificate_pem", "certificate_thumbprint", "expires_at"})
        self.assertEqual(self.issue(), receipt)
        self.service = self.new_service()
        self.assertEqual(self.issue(), receipt)
        self.assertEqual(self.issuer.calls, 1)
        with self.database.transaction(immediate=False) as session:
            operation = session.scalar(select(ProvisioningOperation))
            self.assertEqual(operation.state, "ready")
            self.assertNotIn("PRIVATE KEY", json.dumps(operation.observed_json))

    def test_invalid_csr_cannot_poison_durable_execution_binding(self):
        for value in ("invalid CSR", csr(self.execution_key, extension=True)):
            with self.subTest(value=value[:12]), self.assertRaises(Error) as invalid:
                self.issue(csr_pem=value)
            self.assertEqual(invalid.exception.status, 422)
        with self.database.transaction(immediate=False) as session:
            self.assertIsNone(session.scalar(select(ProvisioningOperation)))
            self.assertIsNone(session.scalar(select(ProvisioningResource)))
        self.assertEqual(self.issuer.calls, 0)
        self.issue()
        self.assertEqual(self.issuer.calls, 1)

    def test_foreign_space_or_principal_cannot_receive_certificate(self):
        for changes in ({"space_id": "space-other-job"}, {"principal_id": "other-principal"}):
            with self.subTest(changes=changes), self.assertRaises(Error):
                self.issue(**changes)
        self.assertEqual(self.issuer.calls, 0)

    def test_execution_csr_cannot_change_after_receipt(self):
        original = self.issue()
        with self.assertRaises(Error) as conflict:
            self.issue(csr_pem=csr(self.other_execution_key))
        self.assertEqual(conflict.exception.status, 409)
        self.assertEqual(self.issue(), original)
        self.assertEqual(self.issuer.calls, 1)

    def test_manager_and_node_credentials_have_distinct_certificate_binding(self):
        token = self.service.issue_control_token(
            self.identity, node_id="node-a", pool_id="cpu", scope="start")
        principal = self.broker.authenticate_node(
            "Bearer " + token, verified_peer_thumbprint=self.manager_thumb,
            grant_validator=self.service.check_node_grant)
        self.assertEqual(principal.scopes, frozenset({"start"}))
        with self.assertRaises(Error):
            self.service.authenticate_node("Bearer " + token, verified_peer_thumbprint=self.node_thumb)
        with self.assertRaises(Error):
            self.service.issue_certificate(principal, csr_pem=self.csr, space_id="space-job-a",
                principal_id=stable_workload_principal(self.settings.workload_issuer, "job-a", "owner"))

    def test_node_introspection_checks_exact_manager_scope_resources_and_identity(self):
        actor = self.actor()
        payload = dict(node_id="node-a", pool_id="cpu", grant_id=actor.grant_id,
                       certificate_thumbprint=self.manager_thumb, scopes=["start"],
                       resources=dict(actor.resources))
        self.assertEqual(self.service.validate(actor, **payload), {"valid": True})
        for changes in ({"node_id": "other"}, {"pool_id": "other"}, {"grant_id": "foreign"},
                        {"certificate_thumbprint": self.node_thumb}, {"scopes": ["qualify"]},
                        {"resources": {"cpu_millicores": 2000, "memory_bytes": 1024**3, "disk_bytes": 1024**3}}):
            with self.subTest(changes=changes):
                self.assertEqual(self.service.validate(actor, **dict(payload, **changes)), {"valid": False})

    def test_current_registered_node_and_pool_revocation_take_effect(self):
        token = self.bootstrap()["token"]
        self.service.nodes["node-a"] = ApprovedManagedNode("node-a", "cpu", self.node_thumb, "registration-a", False)
        with self.assertRaises(Error):
            self.bootstrap()
        with self.assertRaises(Error):
            self.service.authenticate_node("Bearer " + token, verified_peer_thumbprint=self.node_thumb)
        self.service.nodes["node-a"] = self.registrations["node-a"]
        with self.database.transaction() as session:
            session.get(Pool, "cpu").details_json = {"registration_id": "superseded-registration"}
        actor = self.actor()
        with self.assertRaises(Error):
            self.service.assignment(actor)
        with self.assertRaises(Error):
            self.service.issue_control_token(self.identity, node_id="node-a", pool_id="cpu", scope="start")

    def test_prepared_plan_contains_only_current_component_metadata(self):
        actor = self.actor()
        result = self.service.assignment(actor)
        self.assertEqual(result["job_id"], actor.job_id)
        self.assertEqual(result["source_dir"], "/job/source")
        self.provisioner.foreign_plan = True
        with self.assertRaises(Error) as error:
            self.service.assignment(actor)
        self.assertEqual(error.exception.status, 503)

    def test_prepared_plan_rejects_manager_host_paths_and_extra_credentials(self):
        actor = self.actor()
        original = self.provisioner.prepared_component
        for changes in ({"source_dir": "/localhome/private/source"},
                        {"state_dir": "/localhome/other-job/state"},
                        {"private_key_file": "/localhome/signing.pem"}):
            self.provisioner.prepared_component = lambda *args, **kwargs: dict(original(*args, **kwargs), **changes)
            with self.subTest(changes=changes), self.assertRaises(Error):
                self.service.assignment(actor)

    def test_cancellation_during_grant_introspection_prevents_fresh_token(self):
        receipt = self.issue()
        self.grant(receipt)
        actor = self.actor()
        original = self.provisioner.exchange.request
        def racing(method, path):
            value = original(method, path)
            with self.database.transaction() as session:
                session.get(Job, "job-a").state = "CANCELLING"
            return value
        self.provisioner.exchange.request = racing
        with self.assertRaises(Error):
            self.service.credentials(actor, certificate_thumbprint=receipt["certificate_thumbprint"], audience="exchange")

    def test_workload_refresh_checks_actual_exchange_grant_every_time(self):
        receipt = self.issue()
        self.grant(receipt)
        actor = self.actor()
        for audience, expected_audience in (("exchange", "managed-exchange"), ("gateway", "managed-transfer")):
            result = self.service.credentials(actor, certificate_thumbprint=receipt["certificate_thumbprint"],
                                              audience=audience)
            principal = self.broker.authenticate_workload(
                "Bearer " + result["token"], verified_peer_thumbprint=receipt["certificate_thumbprint"], audience=audience)
            self.assertEqual(principal.audience, expected_audience)
            self.assertEqual(principal.grant_id, "workload-grant")
            self.assertEqual(principal.epoch, 1)
        self.assertEqual(len(self.provisioner.exchange.calls), 2)
        self.provisioner.exchange.grants["workload-grant"]["enabled"] = False
        with self.assertRaises(Error) as revoked:
            self.service.credentials(actor, certificate_thumbprint=receipt["certificate_thumbprint"], audience="exchange")
        self.assertEqual(revoked.exception.status, 401)

    def test_unknown_audience_and_wrong_certificate_cannot_refresh(self):
        receipt = self.issue()
        self.grant(receipt)
        actor = self.actor()
        with self.assertRaises(Error):
            self.service.credentials(actor, certificate_thumbprint=thumb("foreign-execution"), audience="exchange")
        for audience in ("managed-exchange", "human", "node", ""):
            with self.subTest(audience=audience), self.assertRaises(Error):
                self.service.credentials(actor, certificate_thumbprint=receipt["certificate_thumbprint"], audience=audience)

    def test_exchange_binding_forgery_expiration_and_nonfinite_receipts_refused(self):
        receipt = self.issue()
        grant = self.grant(receipt)
        actor = self.actor()
        for changes in ({"attempt_id": "foreign"}, {"epoch": 2}, {"component_id": "foreign"},
                        {"space_id": "foreign"}, {"principal_id": "foreign"},
                        {"expires_at": self.now}, {"expires_at": float("nan")}):
            self.provisioner.exchange.grants["workload-grant"] = dict(grant, **changes)
            with self.subTest(changes=changes), self.assertRaises(Error):
                self.service.credentials(actor, certificate_thumbprint=receipt["certificate_thumbprint"], audience="exchange")

    def test_stale_attempt_can_stop_but_cannot_start_read_source_or_refresh(self):
        actor = self.actor()
        with self.database.transaction() as session:
            job = session.get(Job, "job-a")
            job.epoch = 2
            job.current_attempt = 2
        for action in (lambda: self.issue(actor), lambda: self.service.assignment(actor),
                       lambda: self.service.issue_control_token(self.identity, node_id="node-a", pool_id="cpu", scope="start")):
            with self.assertRaises(Error):
                action()
        token = self.service.issue_control_token(self.identity, node_id="node-a", pool_id="cpu", scope="stop")
        self.assertIsInstance(token, str)

    def test_deadline_does_not_prevent_safe_stop_but_forbids_new_work(self):
        actor = self.actor()
        self.now += 3600
        for action in (lambda: self.issue(actor), lambda: self.service.assignment(actor),
                       lambda: self.service.issue_control_token(self.identity, node_id="node-a", pool_id="cpu", scope="start")):
            with self.assertRaises(Error):
                action()
        self.assertIsInstance(self.service.issue_control_token(
            self.identity, node_id="node-a", pool_id="cpu", scope="stop"), str)

    def test_quarantine_blocks_new_execution_and_credentials(self):
        actor = self.actor()
        with self.database.transaction() as session:
            session.get(Pool, "cpu").quarantined = True
        with self.assertRaises(Error):
            self.issue(actor)
        with self.assertRaises(Error):
            self.service.issue_control_token(self.identity, node_id="node-a", pool_id="cpu", scope="start")
        self.assertIsInstance(self.service.issue_control_token(
            self.identity, node_id="node-a", pool_id="cpu", scope="stop"), str)

    def test_historical_purge_requires_terminal_authorized_cleanup_and_stop(self):
        with self.assertRaises(Error):
            self.service.issue_control_token(self.identity, node_id="node-a", pool_id="cpu", scope="purge")
        with self.database.transaction() as session:
            job = session.get(Job, "job-a")
            job.state = "SUCCEEDED"
            job.cleanup_status = "purge_pending"
            allocation = session.get(Allocation, "allocation-owner")
            allocation.state = "RELEASED"
            allocation.released_at = datetime.fromtimestamp(self.now, timezone.utc)
        with self.assertRaises(Error):
            self.service.issue_control_token(self.identity, node_id="node-a", pool_id="cpu", scope="purge")
        with self.database.transaction() as session:
            session.get(Allocation, "allocation-owner").termination_confirmed = True
        self.assertIsInstance(self.service.issue_control_token(
            self.identity, node_id="node-a", pool_id="cpu", scope="purge"), str)
        with self.assertRaises(Error):
            self.service.issue_control_token(self.identity, node_id="node-a", pool_id="cpu", scope="start")

    def test_pool_reassignment_preserves_historical_node_ownership(self):
        self.service.nodes["node-b"] = ApprovedManagedNode("node-b", "cpu", thumb("node-b"), "registration-b")
        with self.database.transaction() as session:
            pool = session.get(Pool, "cpu")
            pool.node_id = "node-b"
            pool.details_json = {"registration_id": "registration-b"}
        actor = self.actor()
        with self.assertRaises(Error):
            self.service.assignment(actor)
        self.assertIsInstance(self.service.issue_control_token(
            self.identity, node_id="node-a", pool_id="cpu", scope="stop"), str)
        with self.assertRaises(Error):
            self.service.issue_control_token(self.identity, node_id="node-b", pool_id="cpu", scope="stop")
        with self.database.transaction() as session:
            job = session.get(Job, "job-a")
            job.state = "SUCCEEDED"
            job.cleanup_status = "purge_pending"
            allocation = session.get(Allocation, "allocation-owner")
            allocation.state = "RELEASED"
            allocation.termination_confirmed = True
            allocation.released_at = datetime.fromtimestamp(self.now, timezone.utc)
        self.assertIsInstance(self.service.issue_control_token(
            self.identity, node_id="node-a", pool_id="cpu", scope="purge"), str)

    def test_log_read_grant_binds_current_and_retained_allocation(self):
        actor = self.actor()
        for historical in (False, True):
            if historical:
                with self.database.transaction() as session:
                    job = session.get(Job, "job-a")
                    job.state = "SUCCEEDED"
                    allocation = session.get(Allocation, "allocation-owner")
                    allocation.state = "RELEASED"
                    allocation.termination_confirmed = True
                    allocation.released_at = datetime.fromtimestamp(self.now, timezone.utc)
            token = self.service.issue_control_token(
                self.identity, node_id="node-a", pool_id="cpu", scope="logs")
            principal = self.service.authenticate_node("Bearer " + token,
                verified_peer_thumbprint=self.manager_thumb)
            self.assertEqual(principal.scopes, frozenset({"logs"}))
            self.assertEqual(principal.grant_id, "allocation-owner")
            self.assertEqual((principal.job_id, principal.attempt_id, principal.component_id, principal.epoch),
                             ("job-a", "attempt-a", "owner", 1))
            self.assertEqual(self.service.validate(actor, node_id="node-a", pool_id="cpu",
                grant_id=principal.grant_id, certificate_thumbprint=self.manager_thumb,
                scopes=["logs"], resources=dict(principal.resources)), {"valid": True})
            with self.assertRaises(Error):
                self.service.authenticate_node("Bearer " + token, verified_peer_thumbprint=self.node_thumb)
        with self.assertRaises(Error):
            self.service.issue_control_token(self.identity, node_id="node-a", pool_id="cpu", scope="start")

    def test_historical_log_read_cannot_adopt_foreign_node_or_resources(self):
        self.service.nodes["node-b"] = ApprovedManagedNode("node-b", "cpu", thumb("node-b"), "registration-b")
        with self.database.transaction() as session:
            job = session.get(Job, "job-a")
            job.state = "SUCCEEDED"
            allocation = session.get(Allocation, "allocation-owner")
            allocation.state = "RELEASED"
            allocation.termination_confirmed = True
            allocation.released_at = datetime.fromtimestamp(self.now, timezone.utc)
            pool = session.get(Pool, "cpu")
            pool.node_id = "node-b"
            pool.details_json = {"registration_id": "registration-b"}
        actor = self.actor()
        token = self.service.issue_control_token(self.identity, node_id="node-a", pool_id="cpu", scope="logs")
        principal = self.service.authenticate_node("Bearer " + token, verified_peer_thumbprint=self.manager_thumb)
        payload = dict(node_id="node-a", pool_id="cpu", grant_id=principal.grant_id,
                       certificate_thumbprint=self.manager_thumb, scopes=["logs"],
                       resources=dict(principal.resources))
        for changes in ({"node_id": "node-b"}, {"grant_id": "other-allocation"},
                        {"certificate_thumbprint": self.node_thumb},
                        {"resources": dict(principal.resources, disk_bytes=1)}):
            with self.subTest(changes=changes):
                self.assertEqual(self.service.validate(actor, **dict(payload, **changes)), {"valid": False})
        with self.assertRaises(Error):
            self.service.issue_control_token(self.identity, node_id="node-b", pool_id="cpu", scope="logs")
        with self.database.transaction() as session:
            session.get(Allocation, "allocation-owner").details_json = {}
        with self.assertRaises(Error):
            self.service.authenticate_node("Bearer " + token, verified_peer_thumbprint=self.manager_thumb)

    def test_released_assignment_without_node_ownership_is_not_adopted(self):
        with self.database.transaction() as session:
            allocation = session.get(Allocation, "allocation-owner")
            allocation.state = "RELEASED"
            allocation.released_at = datetime.fromtimestamp(self.now, timezone.utc)
            allocation.details_json = {}
        with self.assertRaises(Error):
            self.bootstrap()

    def test_build_component_never_receives_execution_certificate_or_tokens(self):
        actor = self.actor(ExecutionIdentity("job-a", "attempt-a", "builder", 1))
        with self.assertRaises(Error):
            self.service.issue_certificate(actor, csr_pem=self.csr, space_id="space-job-a",
                principal_id=stable_workload_principal(self.settings.workload_issuer, "job-a", "builder"))
        with self.assertRaises(Error):
            self.service.credentials(actor, certificate_thumbprint=thumb("execution"), audience="exchange")

    def test_platform_registration_is_distinct_from_job_grants(self):
        token = self.service.issue_platform_token(node_id="node-a", pool_id="cpu", registration_id="registration-a")
        principal = self.broker.authenticate_node_platform(
            "Bearer " + token, verified_peer_thumbprint=self.manager_thumb,
            registration_validator=self.service.check_registration)
        self.assertEqual(principal.scopes, frozenset({"qualify"}))
        self.assertFalse(hasattr(principal, "job_id"))
        self.service.nodes["node-a"] = ApprovedManagedNode("node-a", "cpu", self.node_thumb, "registration-b")
        self.assertFalse(self.service.check_registration(principal))

    def test_manager_node_certificate_identity_and_resource_overrides_refused(self):
        with self.assertRaises(ValueError):
            NodeAssignmentService(self.database, self.provisioner, self.broker, self.registrations,
                                  manager_certificate_thumbprint=self.node_thumb)
        for changes in ({"certificate_thumbprint": self.node_thumb},
                        {"resources": {"cpu_millicores": 2000, "memory_bytes": 1024**3, "disk_bytes": 1024**3}}):
            with self.subTest(changes=changes), self.assertRaises(Error):
                self.service.issue_control_token(self.identity, node_id="node-a", pool_id="cpu", scope="reserve", **changes)


if __name__ == "__main__":
    unittest.main()
