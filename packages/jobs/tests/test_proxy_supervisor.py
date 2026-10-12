"""Real UDS execution supervision with generated private keys and live grant ACLs."""
from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import json
import os
import socket
import shutil
from pathlib import Path
import stat
import time
import unittest
from unittest.mock import patch
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import httpx

from hf2l_exchange.auth import Authenticator
from hf2l_exchange.domain import Error
from hf2l_jobs.broker import WorkloadBroker, stable_workload_principal, stable_workload_subject
from hf2l_jobs.execution_proxy import ExecutionBinding, ProxySupervisor, start_mtls_server
from hf2l_jobs.gateway import GatewayError, certificate_thumbprint
from hf2l_jobs.participants import ExternalManagerClient
from hf2l_jobs.executor import ExecutionIdentity

from test_gateway import GatewayFixture


class ProxySupervisorTests(GatewayFixture):
    def setUp(self):
        super().setUp()
        self.lookups = []
        self.grants = {}
        exchange = FastAPI()
        authentication = Authenticator(self.auth)
        service = self.service

        @exchange.exception_handler(Error)
        async def failure(request, error):
            return JSONResponse({"error": {"code": error.code}}, status_code=error.status)

        @exchange.get("/v2/spaces/{space}/membership")
        async def membership(request: Request, space: str):
            identity = authentication.authenticate(request.headers.get("Authorization", ""), managed=True,
                certificate_thumbprint=request.scope["state"]["verified_certificate_thumbprint"])
            service.verify_workload_grant(identity, space)
            return service.get_membership(identity, space)

        self.exchange_server = start_mtls_server(exchange, certificate=self.bundle["server"][2],
            key=self.bundle["server"][3], client_ca=self.bundle["ca"][2])
        self.addCleanup(self.exchange_server.server_close)
        self.addCleanup(self.exchange_server.shutdown)
        self.gateway_server = start_mtls_server(self.app, certificate=self.bundle["server"][2],
            key=self.bundle["server"][3], client_ca=self.bundle["ca"][2])
        self.addCleanup(self.gateway_server.server_close)
        self.addCleanup(self.gateway_server.shutdown)
        self.proxy_root = Path(self.directory.name) / "proxies"
        self.supervisor = self.new_supervisor()
        self.job = {"id": "job-a", "deadline_at": datetime.now(timezone.utc) + timedelta(minutes=20)}
        self.attempt = {"id": "attempt-a", "job_id": "job-a", "epoch": 1}
        self.component = {"component_id": "owner", "participant_id": None}
        self.pid = stable_workload_principal(self.workload_issuer, "job-a", "owner")

    def lookup(self, job, attempt, component):
        identity = (job, attempt, component)
        self.lookups.append(identity)
        stored = self.grants.get(identity)
        if stored is None:
            return None
        return self.service.get_workload_grant(self.provisioner, stored["space_id"], stored["grant_id"])

    def new_supervisor(self, root=None):
        supervisor = ProxySupervisor(root if root is not None else self.proxy_root,
            client_ca_certificate=self.bundle["ca"][2],
            client_ca_key=self.bundle["ca"][3], broker=self.broker,
            exchange_endpoint="https://127.0.0.1:" + str(self.exchange_server.server_address[1]),
            gateway_endpoint="https://127.0.0.1:" + str(self.gateway_server.server_address[1]),
            service_ca_file=self.bundle["ca"][2], grant_lookup=self.lookup)
        self.addCleanup(supervisor.close)
        return supervisor

    def bind(self, *, supervisor=None, job=None, attempt=None, component=None, space=None):
        job, attempt, component = job or self.job, attempt or self.attempt, component or self.component
        principal = stable_workload_principal(self.workload_issuer, job["id"], component["component_id"],
                                             component.get("participant_id"))
        return (supervisor or self.supervisor).binding(job, attempt, component, space or self.sid, principal)

    def register(self, binding, *, job=None, attempt=None, component=None, space=None):
        job, attempt, component = job or self.job, attempt or self.attempt, component or self.component
        space = space or self.sid
        subject = stable_workload_subject(job["id"], component["component_id"], component.get("participant_id"))
        principal = stable_workload_principal(self.workload_issuer, job["id"], component["component_id"],
                                             component.get("participant_id"))
        self.service.put_member(self.provisioner, space, principal,
            {"subject": subject, "roles": ["reader", "contributor", "publisher"], "bindings": {}})
        grant = self.service.create_workload_grant(self.provisioner, space,
            {"subject": subject, "job_id": job["id"], "attempt_id": attempt["id"],
             "component_id": component["component_id"], "epoch": attempt["epoch"],
             "certificate_thumbprint": binding["certificate_thumbprint"],
             "roles": ["reader", "contributor", "publisher"], "bindings": {},
             "expires_at": time.time() + 120}, "supervised-grant-" + uuid.uuid4().hex)
        self.grants[(job["id"], attempt["id"], component["component_id"])] = grant
        return grant

    def uds_client(self, binding):
        # Use the same directory alias technique as supervision while keeping
        # returned physical mount paths independent of open file descriptors.
        directory = Path(binding["proxy_endpoint"]).parent
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        endpoint = "/proc/self/fd/" + str(descriptor) + "/" + Path(binding["proxy_endpoint"]).name
        client = httpx.Client(transport=httpx.HTTPTransport(uds=endpoint), base_url="http://execution.local", timeout=5)
        self.addCleanup(client.close)
        return client

    def test_live_uds_generates_private_material_and_only_returns_binding(self):
        binding = self.bind()
        self.assertEqual(set(binding), {"certificate_thumbprint", "proxy_endpoint"})
        self.assertEqual(self.lookups, [])  # Grant provisioning follows certificate creation.
        directory = self.proxy_root / "job-a" / "attempts" / "attempt-a" / "owner"
        for name in ("proxy-key.pem", "proxy-cert.pem", "proxy-identity.json"):
            path = directory / name
            self.assertTrue(path.is_file())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertTrue(stat.S_ISSOCK(Path(binding["proxy_endpoint"]).stat().st_mode))
        self.assertNotIn("PRIVATE KEY", json.dumps(binding))
        self.assertNotIn("Bearer", json.dumps(binding))
        client = self.uds_client(binding)
        self.assertEqual(client.get(f"/v2/spaces/{self.sid}/membership").status_code, 503)
        self.register(binding)
        response = client.get(f"/v2/spaces/{self.sid}/membership")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["principal_id"], self.pid)
        response = client.get(self.path + "/content", headers={"Range": "bytes=2-5"})
        self.assertEqual(response.status_code, 206, response.text)
        self.assertEqual(response.content, b"cdef")
        self.assertTrue(all(identity == ("job-a", "attempt-a", "owner") for identity in self.lookups))

    def test_existing_binding_idempotent_and_mismatched_attempt_or_space_rejected(self):
        binding = self.bind()
        self.assertEqual(self.bind(), binding)
        with self.assertRaises(ValueError):
            self.bind(space="foreign-space")
        with self.assertRaises(ValueError):
            self.bind(attempt=dict(self.attempt, epoch=2))
        with self.assertRaises(ValueError):
            self.bind(attempt=dict(self.attempt, job_id="job-b"))
        with self.assertRaises(ValueError):
            self.supervisor.binding(self.job, self.attempt, self.component, self.sid, "foreign-principal")

    def test_cross_job_paths_and_caller_credentials_never_reach_trusted_services(self):
        binding = self.bind()
        self.register(binding)
        client = self.uds_client(binding)
        before = len(self.lookups)
        self.assertEqual(client.get("/v2/spaces/foreign-space/membership").status_code, 404)
        self.assertEqual(client.get(self.path.replace(self.sid, "foreign-space") + "/content").status_code, 404)
        self.assertEqual(client.get(f"/v2/spaces/{self.sid}/membership",
                                    headers={"Authorization": "Bearer copied"}).status_code, 400)
        self.assertEqual(len(self.lookups), before)
        for malicious in ("../foreign", "job-a/foreign", "job-a%2Fforeign"):
            with self.subTest(job_id=malicious), self.assertRaises((ValueError, GatewayError)):
                self.bind(job=dict(self.job, id=malicious), attempt=dict(self.attempt, job_id=malicious))

    def test_ledger_revocation_rechecked_on_every_uds_request(self):
        binding = self.bind()
        self.register(binding)
        client = self.uds_client(binding)
        path = f"/v2/spaces/{self.sid}/membership"
        self.assertEqual(client.get(path).status_code, 200)
        self.service.revoke_workload_grants(self.provisioner, self.sid, {"attempt_id": "attempt-a"}, "revoke-supervised")
        self.assertEqual(client.get(path).status_code, 401)
        self.assertEqual(client.get(self.path + "/content").status_code, 401)

    def test_stop_requires_confirmed_runtime_termination_and_removes_only_own_socket(self):
        first = self.bind()
        participant = {"component_id": "participant-a", "participant_id": "alice"}
        second = self.bind(component=participant)
        with self.assertRaises(ValueError):
            self.supervisor.stop("job-a", "attempt-a", "owner")
        self.assertTrue(Path(first["proxy_endpoint"]).exists())
        self.assertTrue(self.supervisor.stop("job-a", "attempt-a", "owner", termination_confirmed=True))
        self.assertFalse(Path(first["proxy_endpoint"]).exists())
        self.assertTrue(Path(second["proxy_endpoint"]).exists())
        self.assertTrue(self.supervisor.stop("job-a", "attempt-a", "owner", termination_confirmed=True))

    def test_supervisor_restart_reuses_same_certificate_and_live_ledger_binding(self):
        first = self.bind()
        self.register(first)
        self.assertEqual(self.uds_client(first).get(f"/v2/spaces/{self.sid}/membership").status_code, 200)
        key_path = self.proxy_root / "job-a" / "attempts" / "attempt-a" / "owner" / "proxy-key.pem"
        key_bytes = key_path.read_bytes()
        self.supervisor.close()
        restarted = self.new_supervisor()
        second = self.bind(supervisor=restarted)
        self.assertEqual(first, second)
        self.assertEqual(key_path.read_bytes(), key_bytes)
        self.assertEqual(self.uds_client(second).get(f"/v2/spaces/{self.sid}/membership").status_code, 200)

    def test_long_uuid_job_and_attempt_ids_have_working_real_socket(self):
        job = dict(self.job, id=uuid.uuid4().hex)
        attempt = {"id": uuid.uuid4().hex, "job_id": job["id"], "epoch": 1}
        space = self.service.create_space(self.provisioner, {"name": "Long UUID"}, "space-uuid")["id"]
        self.service.enable_managed_space(self.provisioner, space, {"job_id": job["id"]}, "managed-uuid")
        binding = self.bind(job=job, attempt=attempt, space=space)
        material = self.proxy_root / job["id"] / "attempts" / attempt["id"] / "owner" / "proxy-key.pem"
        self.assertGreater(len(str(material).encode()), 107)
        self.assertLessEqual(len(binding["proxy_endpoint"].encode()), 107)
        self.register(binding, job=job, attempt=attempt, space=space)
        response = self.uds_client(binding).get(f"/v2/spaces/{space}/membership")
        self.assertEqual(response.status_code, 200, response.text)

    def test_healthy_live_proxy_is_adopted_and_partial_material_is_not_overwritten(self):
        first = self.bind()
        adopter = self.new_supervisor()
        self.assertEqual(self.bind(supervisor=adopter), first)
        other = {"component_id": "participant-b", "participant_id": "bob"}
        path = self.proxy_root / "job-a" / "attempts" / "attempt-a" / "participant-b"
        path.mkdir(mode=0o700)
        key = path / "proxy-key.pem"
        key.write_text("partial secret")
        key.chmod(0o600)
        with self.assertRaises(ValueError):
            self.bind(component=other)
        self.assertEqual(key.read_text(), "partial secret")

    def control_request(self, binding, operation, *, overrides=None, termination_confirmed=True):
        identity = asdict(ExecutionBinding("job-a", "attempt-a", "owner", self.sid, 1,
                                          binding["certificate_thumbprint"]))
        identity.update(overrides or {})
        request = {"binding": identity, "operation": operation,
                   "termination_confirmed": termination_confirmed}
        control = Path(binding["proxy_endpoint"]).with_name("c")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.connect(str(control))
            connection.sendall(json.dumps(request).encode() + b"\n")
            connection.shutdown(socket.SHUT_WR)
            data = connection.recv(4096)
        return json.loads(data) if data else None

    def test_adopting_controller_close_preserves_owner_proxy_and_confirmed_stop_works(self):
        first = self.bind()
        self.register(first)
        original_client = self.uds_client(first)
        adopter = self.new_supervisor()
        self.assertEqual(self.bind(supervisor=adopter), first)
        adopter.close()
        self.assertEqual(original_client.get(f"/v2/spaces/{self.sid}/membership").status_code, 200)
        # A discarded adoption record cannot claim that a live foreign proxy stopped.
        self.assertFalse(adopter.stop("job-a", "attempt-a", "owner", termination_confirmed=True))
        self.assertEqual(self.bind(supervisor=adopter), first)
        with self.assertRaises(ValueError):
            adopter.stop("job-a", "attempt-a", "owner")
        self.assertTrue(adopter.stop("job-a", "attempt-a", "owner", termination_confirmed=True))
        self.assertFalse(Path(first["proxy_endpoint"]).exists())
        # httpcore's failed connect_unix_socket path leaves its unconnected
        # socket open. Verify transport closure with an explicitly owned socket.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            with self.assertRaises((FileNotFoundError, ConnectionRefusedError)):
                connection.connect(first["proxy_endpoint"])
        # The original owner can finish private control/FD cleanup after remote stop.
        self.assertTrue(self.supervisor.stop("job-a", "attempt-a", "owner", termination_confirmed=True))
        self.assertFalse(Path(first["proxy_endpoint"]).with_name("c").exists())

    def test_private_admin_binding_and_termination_assertion_cannot_be_forged(self):
        binding = self.bind()
        self.register(binding)
        control = Path(binding["proxy_endpoint"]).with_name("c")
        self.assertEqual(stat.S_IMODE(control.stat().st_mode), 0o600)
        self.assertTrue(stat.S_ISSOCK(control.stat().st_mode))
        status = self.control_request(binding, "status")
        self.assertTrue(status["running"])
        self.assertEqual(status["binding"]["certificate_thumbprint"], binding["certificate_thumbprint"])
        for field, value in (("job_id", "job-b"), ("attempt_id", "attempt-b"),
                             ("component_id", "participant-a"), ("space_id", "foreign-space"), ("epoch", 2)):
            with self.subTest(field=field):
                self.assertIsNone(self.control_request(binding, "stop", overrides={field: value}))
        self.assertIsNone(self.control_request(binding, "stop", termination_confirmed=False))
        self.assertTrue(self.control_request(binding, "status")["running"])
        client = self.uds_client(binding)
        before = len(self.lookups)
        self.assertEqual(client.get("/status").status_code, 404)
        self.assertEqual(client.post("/stop", json={"termination_confirmed": True}).status_code, 404)
        self.assertEqual(client.get(f"/v2/spaces/{self.sid}/status").status_code, 404)
        self.assertEqual(len(self.lookups), before)
        self.assertEqual(client.get(f"/v2/spaces/{self.sid}/membership").status_code, 200)

    def test_adopted_stop_removes_only_the_bound_component_and_preserves_other_execution(self):
        first = self.bind()
        self.register(first)
        participant = {"component_id": "participant-a", "participant_id": "alice"}
        second = self.bind(component=participant)
        self.register(second, component=participant)
        participant_client = self.uds_client(second)
        adopter = self.new_supervisor()
        self.assertEqual(self.bind(supervisor=adopter), first)
        self.assertTrue(adopter.stop("job-a", "attempt-a", "owner", termination_confirmed=True))
        self.assertFalse(Path(first["proxy_endpoint"]).exists())
        self.assertTrue(Path(second["proxy_endpoint"]).exists())
        self.assertEqual(participant_client.get(f"/v2/spaces/{self.sid}/membership").status_code, 200)
        self.assertTrue(self.supervisor.stop("job-a", "attempt-a", "owner", termination_confirmed=True))
        self.assertTrue(Path(second["proxy_endpoint"]).with_name("c").exists())

    def test_live_uds_without_authenticated_private_control_is_not_adopted(self):
        first = self.bind()
        self.supervisor.close()
        public = Path(first["proxy_endpoint"])
        public.unlink(missing_ok=True)
        unknown = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(unknown.close)
        unknown.bind(str(public))
        unknown.listen(2)
        candidate = self.new_supervisor()
        with self.assertRaises((ValueError, OSError)):
            self.bind(supervisor=candidate)
        self.assertTrue(public.exists())
        self.assertFalse(candidate.stop("job-a", "attempt-a", "owner", termination_confirmed=True))

    def test_material_identity_is_verified_before_any_live_proxy_adoption(self):
        first = self.bind()
        directory = self.proxy_root / "job-a" / "attempts" / "attempt-a" / "owner"
        metadata = directory / "proxy-identity.json"
        original_metadata = metadata.read_bytes()
        value = json.loads(original_metadata)
        value["job_id"] = "job-b"
        metadata.write_text(json.dumps(value))
        candidate = self.new_supervisor()
        with self.assertRaises(ValueError):
            self.bind(supervisor=candidate)
        metadata.write_bytes(original_metadata)
        certificate = directory / "proxy-cert.pem"
        original_certificate = certificate.read_bytes()
        certificate.write_bytes(Path(self.bundle["other"][2]).read_bytes())
        with self.assertRaises(ValueError):
            self.bind(supervisor=candidate)
        certificate.write_bytes(original_certificate)
        self.assertEqual(self.bind(supervisor=candidate), first)

    def central_supervisor(self, certificate_provider):
        verification_only = WorkloadBroker(replace(self.broker.settings, private_key=None))
        def token_provider(binding, participant_id, audience):
            grant = self.lookup(binding.job_id, binding.attempt_id, binding.component_id)
            if grant is None or not grant["enabled"]:
                raise GatewayError(401, "execution_grant_revoked")
            return self.broker.issue_workload(job_id=binding.job_id, attempt_id=binding.attempt_id,
                component_id=binding.component_id, space_id=binding.space_id, epoch=binding.epoch,
                certificate_thumbprint=binding.certificate_thumbprint, grant_id=grant["grant_id"],
                participant_id=participant_id, audience=audience,
                ttl_seconds=min(300, int(grant["expires_at"] - time.time())))
        def forbidden_local_lookup(*args):
            raise AssertionError("Node should delegate token issuance to the central provider")
        supervisor = ProxySupervisor(self.proxy_root, client_ca_certificate=self.bundle["ca"][2],
            client_ca_key=None, broker=verification_only,
            exchange_endpoint="https://127.0.0.1:" + str(self.exchange_server.server_address[1]),
            gateway_endpoint="https://127.0.0.1:" + str(self.gateway_server.server_address[1]),
            service_ca_file=self.bundle["ca"][2], grant_lookup=forbidden_local_lookup,
            certificate_provider=certificate_provider, token_provider=token_provider)
        self.addCleanup(supervisor.close)
        self.assertIsNone(supervisor.ca_key)
        self.assertIsNone(supervisor.broker._private_key)
        return supervisor

    def issue_csr(self, csr_pem, *, authority=None, public_key=None, ca=False, client_auth=True,
                  not_before=None, not_after=None):
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        self.assertTrue(csr.is_signature_valid)
        issuer = authority or self.bundle["ca"]
        try:
            issuer_ski = issuer[1].extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        except x509.ExtensionNotFound:
            issuer_ski = x509.SubjectKeyIdentifier.from_public_key(issuer[1].public_key())
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(issuer[1].subject)
            .public_key(public_key or csr.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(not_before or now - timedelta(minutes=1))
            .not_valid_after(not_after or now + timedelta(minutes=20))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key or csr.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski),
                           critical=False)
            .add_extension(x509.KeyUsage(digital_signature=not ca, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=ca, crl_sign=ca, encipher_only=None, decipher_only=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client_auth
                                                 else ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(issuer[0], hashes.SHA256()))
        return {"certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
                "certificate_thumbprint": certificate_thumbprint(cert.public_bytes(serialization.Encoding.DER))}

    def test_node_supervisor_uses_central_csr_and_token_providers_without_signing_keys(self):
        requests = []
        def central_provider(fields, csr):
            requests.append((dict(fields), csr))
            directory = self.proxy_root / fields["job_id"] / "attempts" / fields["attempt_id"] / fields["component_id"]
            self.assertEqual(json.loads((directory / "proxy-identity.json").read_text()), fields)
            self.assertEqual(stat.S_IMODE((directory / "proxy-key.pem").stat().st_mode), 0o600)
            self.assertFalse((directory / "proxy-cert.pem").exists())
            return self.issue_csr(csr)
        node = self.central_supervisor(central_provider)
        binding = self.bind(supervisor=node)
        self.register(binding)
        client = self.uds_client(binding)
        self.assertEqual(client.get(f"/v2/spaces/{self.sid}/membership").status_code, 200)
        response = client.get(self.path + "/content", headers={"Range": "bytes=2-5"})
        self.assertEqual(response.status_code, 206, response.text)
        self.assertEqual(response.content, b"cdef")
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0][0], {"job_id": "job-a", "attempt_id": "attempt-a", "component_id": "owner",
                                       "space_id": self.sid, "epoch": 1})
        self.assertNotIn("PRIVATE KEY", requests[0][1])
        self.assertEqual(set(binding), {"certificate_thumbprint", "proxy_endpoint"})
        self.service.revoke_workload_grants(self.provisioner, self.sid, {"attempt_id": "attempt-a"}, "revoke-central")
        self.assertEqual(client.get(f"/v2/spaces/{self.sid}/membership").status_code, 401)

    def test_lost_central_certificate_acknowledgement_retries_same_csr_key_and_certificate(self):
        seen, certificates = [], {}
        def central_provider(fields, csr):
            digest = hashlib.sha256(csr.encode()).hexdigest()
            seen.append(digest)
            if digest not in certificates:
                certificates[digest] = self.issue_csr(csr)
            if len(seen) == 1:
                raise TimeoutError("Synthetic lost issuance acknowledgement")
            return certificates[digest]
        node = self.central_supervisor(central_provider)
        with self.assertRaises(TimeoutError):
            self.bind(supervisor=node)
        directory = self.proxy_root / "job-a" / "attempts" / "attempt-a" / "owner"
        private_before = (directory / "proxy-key.pem").read_bytes()
        metadata_before = (directory / "proxy-identity.json").read_bytes()
        self.assertFalse((directory / "proxy-cert.pem").exists())
        node.close()
        restarted = self.central_supervisor(central_provider)
        binding = self.bind(supervisor=restarted)
        self.assertEqual(seen[0], seen[1])
        self.assertEqual((directory / "proxy-key.pem").read_bytes(), private_before)
        self.assertEqual((directory / "proxy-identity.json").read_bytes(), metadata_before)
        self.assertEqual(binding["certificate_thumbprint"], certificates[seen[0]]["certificate_thumbprint"])
        self.assertEqual((directory / "proxy-cert.pem").read_text(), certificates[seen[0]]["certificate_pem"])
        self.register(binding)
        self.assertEqual(self.uds_client(binding).get(f"/v2/spaces/{self.sid}/membership").status_code, 200)

    def test_central_certificate_replies_cannot_replace_node_key_ca_or_client_usage(self):
        from hf2l_jobs.executor import ExecutionIdentity
        foreign_key, foreign_leaf = self.bundle["foreign"][:2]
        now = datetime.now(timezone.utc)
        foreign_ca = (x509.CertificateBuilder().subject_name(foreign_leaf.subject).issuer_name(foreign_leaf.subject)
            .public_key(foreign_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(foreign_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(foreign_key.public_key()), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
            .sign(foreign_key, hashes.SHA256()))
        for attack in ("wrong-key", "foreign-ca", "ca-certificate", "server-only", "wrong-thumbprint",
                       "excessive-expiry", "future-validity"):
            component = {"component_id": "participant-" + attack, "participant_id": "alice"}
            def provider(fields, csr, attack=attack):
                if attack == "wrong-key":
                    return self.issue_csr(csr, public_key=self.bundle["other"][1].public_key())
                if attack == "foreign-ca":
                    # This certificate is correctly signed, but outside the fixed client CA.
                    return self.issue_csr(csr, authority=(foreign_key, foreign_ca))
                if attack == "ca-certificate":
                    return self.issue_csr(csr, ca=True)
                if attack == "server-only":
                    return self.issue_csr(csr, client_auth=False)
                if attack == "excessive-expiry":
                    return self.issue_csr(csr, not_after=now + timedelta(days=31))
                if attack == "future-validity":
                    return self.issue_csr(csr, not_before=now + timedelta(minutes=5))
                return dict(self.issue_csr(csr), certificate_thumbprint=self.bundle["other"][4])
            node = self.central_supervisor(provider)
            with self.subTest(attack=attack), self.assertRaises(ValueError):
                self.bind(supervisor=node, component=component)
            identity = ExecutionIdentity("job-a", "attempt-a", component["component_id"], 1)
            self.assertFalse(Path(node.endpoint(identity)).exists())
            directory = self.proxy_root / "job-a" / "attempts" / "attempt-a" / component["component_id"]
            self.assertTrue((directory / "proxy-key.pem").is_file())
            self.assertFalse((directory / "proxy-cert.pem").exists())


    def proxy_material_directory(self, identity):
        return self.proxy_root / identity.job_id / "attempts" / identity.attempt_id / identity.component_id

    def assert_purge_complete(self, identity, binding):
        self.assertFalse(self.proxy_material_directory(identity).exists())
        endpoint = Path(binding["proxy_endpoint"])
        self.assertFalse(endpoint.exists())
        self.assertFalse(endpoint.with_name("c").exists())
        tombstone = self.proxy_root / "purge-ledger" / (identity.key + ".json")
        self.assertTrue(tombstone.is_file())
        audit = json.loads(tombstone.read_text())
        for field, value in (
            ("job_id", identity.job_id), ("attempt_id", identity.attempt_id),
            ("component_id", identity.component_id), ("epoch", identity.epoch),
            ("space_id", self.sid), ("certificate_thumbprint", binding["certificate_thumbprint"]),
        ):
            self.assertEqual(audit[field], value)
        self.assertTrue(audit["purged_at"])
        self.assertNotIn("PRIVATE KEY", tombstone.read_text())
        self.assertEqual(stat.S_IMODE(tombstone.stat().st_mode), 0o600)
        return tombstone.read_bytes()

    def test_owner_purge_stops_live_proxy_removes_only_own_material_and_keeps_identity_tombstone(self):
        identity = ExecutionIdentity("job-a", "attempt-a", "owner", 1)
        binding = self.bind()
        self.register(binding)
        sibling_component = {"component_id": "participant-a", "participant_id": "alice"}
        sibling = self.bind(component=sibling_component)
        self.register(sibling, component=sibling_component)
        sibling_client = self.uds_client(sibling)
        self.assertEqual(self.uds_client(binding).get(f"/v2/spaces/{self.sid}/membership").status_code, 200)
        sibling_identity = ExecutionIdentity("job-a", "attempt-a", "participant-a", 1)
        sibling_key = self.proxy_material_directory(sibling_identity) / "proxy-key.pem"
        sibling_bytes = sibling_key.read_bytes()

        self.assertTrue(self.supervisor.purge(identity, termination_confirmed=True))
        audit_bytes = self.assert_purge_complete(identity, binding)
        self.assertTrue(self.supervisor.purge(identity, termination_confirmed=True))
        self.assertEqual(self.assert_purge_complete(identity, binding), audit_bytes)
        self.assertEqual(sibling_key.read_bytes(), sibling_bytes)
        self.assertTrue(Path(sibling["proxy_endpoint"]).exists())
        self.assertEqual(sibling_client.get(f"/v2/spaces/{self.sid}/membership").status_code, 200)
        with self.assertRaises(ValueError):
            self.bind()
        self.assertFalse(self.proxy_material_directory(identity).exists())
        self.assertFalse(Path(binding["proxy_endpoint"]).exists())

    def test_adopted_purge_stops_real_owner_and_is_idempotent_across_supervisors(self):
        identity = ExecutionIdentity("job-a", "attempt-a", "owner", 1)
        binding = self.bind()
        self.register(binding)
        owner_client = self.uds_client(binding)
        self.assertEqual(owner_client.get(f"/v2/spaces/{self.sid}/membership").status_code, 200)
        adopter = self.new_supervisor()
        # Keep a real accepted connection so absence of the public pathname
        # cannot substitute for proof that the owner actually stopped.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as retained_connection:
            retained_connection.settimeout(3)
            retained_connection.connect(binding["proxy_endpoint"])
            probe = http.client.HTTPConnection("execution.local", timeout=3)
            probe.sock = retained_connection
            self.addCleanup(probe.close)
            probe.request("GET", "/status")
            response = probe.getresponse()
            self.assertEqual(response.status, 404)
            response.read()
            # A controller with no local handle must prove the private control
            # identity when an interruption already removed the public pathname.
            Path(binding["proxy_endpoint"]).unlink()
            self.assertEqual(owner_client.get(f"/v2/spaces/{self.sid}/membership").status_code, 200)
            self.assertTrue(adopter.purge(identity, termination_confirmed=True))
            self.assertEqual(retained_connection.recv(1), b"")
        audit_bytes = self.assert_purge_complete(identity, binding)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            with self.assertRaises((FileNotFoundError, ConnectionRefusedError)):
                connection.connect(binding["proxy_endpoint"])
        self.assertTrue(adopter.purge(identity, termination_confirmed=True))
        self.assertTrue(self.supervisor.purge(identity, termination_confirmed=True))
        self.assertEqual(self.assert_purge_complete(identity, binding), audit_bytes)
        with self.assertRaises(ValueError):
            self.bind(supervisor=self.new_supervisor())
        self.assertFalse(self.proxy_material_directory(identity).exists())

    def test_purge_requires_explicit_confirmed_runtime_termination(self):
        identity = ExecutionIdentity("job-a", "attempt-a", "owner", 1)
        binding = self.bind()
        key = self.proxy_material_directory(identity) / "proxy-key.pem"
        key_bytes = key.read_bytes()
        with self.assertRaises(ValueError):
            self.supervisor.purge(identity)
        with self.assertRaises(ValueError):
            self.supervisor.purge(identity, termination_confirmed=False)
        self.assertEqual(key.read_bytes(), key_bytes)
        self.assertTrue(Path(binding["proxy_endpoint"]).exists())
        self.assertFalse((self.proxy_root / "purge-ledger" / (identity.key + ".json")).exists())

    def test_stale_epoch_and_foreign_saved_identity_cannot_purge_current_or_other_job(self):
        identity = ExecutionIdentity("job-a", "attempt-a", "owner", 1)
        binding = self.bind()
        self.register(binding)
        client = self.uds_client(binding)
        other_job = dict(self.job, id="job-b")
        other_attempt = {"id": "attempt-b", "job_id": "job-b", "epoch": 1}
        other_space = self.service.create_space(self.provisioner, {"name": "Other job"}, "space-purge-other")["id"]
        self.service.enable_managed_space(self.provisioner, other_space, {"job_id": "job-b"}, "managed-purge-other")
        other = self.bind(job=other_job, attempt=other_attempt, space=other_space)
        self.register(other, job=other_job, attempt=other_attempt, space=other_space)
        other_client = self.uds_client(other)
        other_identity = ExecutionIdentity("job-b", "attempt-b", "owner", 1)
        other_key = self.proxy_material_directory(other_identity) / "proxy-key.pem"
        other_bytes = other_key.read_bytes()
        metadata = self.proxy_material_directory(identity) / "proxy-identity.json"
        original = metadata.read_bytes()
        current_key = self.proxy_material_directory(identity) / "proxy-key.pem"
        current_bytes = current_key.read_bytes()

        with self.assertRaises(ValueError):
            self.supervisor.purge(ExecutionIdentity("job-a", "attempt-a", "owner", 2), termination_confirmed=True)
        for field, value in (("job_id", "job-b"), ("attempt_id", "attempt-b"), ("component_id", "participant-a")):
            metadata.write_text(json.dumps(dict(json.loads(original), **{field: value})))
            try:
                with self.subTest(field=field), self.assertRaises(ValueError):
                    self.supervisor.purge(identity, termination_confirmed=True)
            finally:
                metadata.write_bytes(original)
        self.assertEqual(current_key.read_bytes(), current_bytes)
        self.assertEqual(other_key.read_bytes(), other_bytes)
        self.assertTrue(Path(binding["proxy_endpoint"]).exists())
        self.assertTrue(Path(other["proxy_endpoint"]).exists())
        self.assertEqual(client.get(f"/v2/spaces/{self.sid}/membership").status_code, 200)
        self.assertEqual(other_client.get(f"/v2/spaces/{other_space}/membership").status_code, 200)
        self.assertFalse((self.proxy_root / "purge-ledger" / (identity.key + ".json")).exists())

    def test_unknown_symlink_and_hardlinked_material_deny_purge_without_unrelated_deletion(self):
        foreign = self.proxy_root / "unrelated-content"
        foreign.write_bytes(b"unrelated material")
        for attack in ("unknown-file", "unknown-directory", "symlink", "hardlink"):
            component = {"component_id": "participant-purge-" + attack, "participant_id": "alice"}
            binding = self.bind(component=component)
            identity = ExecutionIdentity("job-a", "attempt-a", component["component_id"], 1)
            directory = self.proxy_material_directory(identity)
            key = directory / "proxy-key.pem"
            cert = directory / "proxy-cert.pem"
            key_bytes, cert_bytes = key.read_bytes(), cert.read_bytes()
            unexpected = directory / "unrecognized"
            linked_copy = self.proxy_root / ("unrelated-key-" + attack)
            if attack == "unknown-file":
                unexpected.write_bytes(b"keep unknown file")
            elif attack == "unknown-directory":
                unexpected.mkdir(mode=0o700)
                (unexpected / "nested").write_bytes(b"keep nested file")
            elif attack == "symlink":
                cert.unlink()
                cert.symlink_to(foreign)
            else:
                os.link(key, linked_copy)
            with self.subTest(attack=attack), self.assertRaises(ValueError):
                self.supervisor.purge(identity, termination_confirmed=True)
            self.assertEqual(key.read_bytes(), key_bytes)
            self.assertEqual(foreign.read_bytes(), b"unrelated material")
            self.assertTrue((directory / "proxy-identity.json").exists())
            self.assertFalse((self.proxy_root / "purge-ledger" / (identity.key + ".json")).exists())
            if attack == "unknown-file":
                self.assertEqual(unexpected.read_bytes(), b"keep unknown file")
                unexpected.unlink()
            elif attack == "unknown-directory":
                self.assertEqual((unexpected / "nested").read_bytes(), b"keep nested file")
                (unexpected / "nested").unlink()
                unexpected.rmdir()
            elif attack == "symlink":
                self.assertTrue(cert.is_symlink())
                cert.unlink()
                cert.write_bytes(cert_bytes)
                cert.chmod(0o600)
            else:
                self.assertEqual(linked_copy.read_bytes(), key_bytes)
                linked_copy.unlink()
            self.assertTrue(self.supervisor.purge(identity, termination_confirmed=True))
            self.assert_purge_complete(identity, binding)


    def test_purge_base_root_rejects_symlink_ancestor_mode_drift_and_inode_replacement(self):
        actual_parent = Path(self.directory.name) / "real-proxy-parent"
        actual_parent.mkdir(mode=0o700)
        symlink_parent = Path(self.directory.name) / "linked-proxy-parent"
        symlink_parent.symlink_to(actual_parent, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.new_supervisor(root=symlink_parent / "must-not-be-created")
        self.assertEqual(list(actual_parent.iterdir()), [])

        identity = ExecutionIdentity("job-a", "attempt-a", "owner", 1)
        binding = self.bind()
        directory = self.proxy_material_directory(identity)
        certificate = directory / "proxy-cert.pem"
        certificate_bytes = certificate.read_bytes()
        self.proxy_root.chmod(0o755)
        try:
            with self.assertRaises(ValueError):
                self.supervisor.purge(identity, termination_confirmed=True)
            self.assertEqual(certificate.read_bytes(), certificate_bytes)
            self.assertTrue(Path(binding["proxy_endpoint"]).exists())
        finally:
            self.proxy_root.chmod(0o700)

        moved_root = self.proxy_root.with_name("renamed-original-proxies")
        self.proxy_root.rename(moved_root)
        self.proxy_root.mkdir(mode=0o700)
        replacement_marker = self.proxy_root / "unrelated-replacement"
        replacement_marker.write_bytes(b"preserve replacement")
        try:
            with self.assertRaises(ValueError):
                self.supervisor.purge(identity, termination_confirmed=True)
            moved_certificate = moved_root / certificate.relative_to(self.proxy_root)
            moved_socket = moved_root / Path(binding["proxy_endpoint"]).relative_to(self.proxy_root)
            self.assertEqual(moved_certificate.read_bytes(), certificate_bytes)
            self.assertTrue(moved_socket.exists())
            self.assertEqual(replacement_marker.read_bytes(), b"preserve replacement")
            self.assertEqual(list(self.proxy_root.iterdir()), [replacement_marker])
        finally:
            # This is the empty replacement fixture created above, never the
            # root containing the active server or unrelated repository files.
            shutil.rmtree(self.proxy_root)
            moved_root.rename(self.proxy_root)
        self.assertTrue(self.supervisor.purge(identity, termination_confirmed=True))
        self.assert_purge_complete(identity, binding)

    def test_pending_csr_purge_removes_key_and_identity_with_permanent_audit_fence(self):
        requests = []
        def lose_acknowledgement(fields, csr):
            requests.append((dict(fields), csr))
            raise TimeoutError("Synthetic interrupted certificate acknowledgement")
        node = self.central_supervisor(lose_acknowledgement)
        identity = ExecutionIdentity("job-a", "attempt-a", "owner", 1)
        with self.assertRaises(TimeoutError):
            self.bind(supervisor=node)
        directory = self.proxy_material_directory(identity)
        self.assertEqual({path.name for path in directory.iterdir()}, {"proxy-key.pem", "proxy-identity.json"})
        self.assertTrue(node.purge(identity, termination_confirmed=True))
        self.assertFalse(directory.exists())
        self.assertFalse(Path(node.endpoint(identity)).exists())
        tombstone = self.proxy_root / "purge-ledger" / (identity.key + ".json")
        audit_bytes = tombstone.read_bytes()
        audit = json.loads(audit_bytes)
        self.assertEqual({field: audit[field] for field in ("job_id", "attempt_id", "component_id", "epoch")},
            {"job_id": "job-a", "attempt_id": "attempt-a", "component_id": "owner", "epoch": 1})
        self.assertEqual(audit["space_id"], self.sid)
        self.assertIsNone(audit["certificate_thumbprint"])
        self.assertEqual(audit["status"], "purged")
        self.assertTrue(audit["purged_at"])
        self.assertTrue(node.purge(identity, termination_confirmed=True))
        self.assertEqual(tombstone.read_bytes(), audit_bytes)
        with self.assertRaises(ValueError):
            self.bind(supervisor=self.central_supervisor(lose_acknowledgement))
        self.assertEqual(len(requests), 1)
        self.assertFalse(directory.exists())

    def test_interrupted_purge_retries_durable_audit_without_reissuing_private_material(self):
        identity = ExecutionIdentity("job-a", "attempt-a", "owner", 1)
        binding = self.bind()
        directory = self.proxy_material_directory(identity)
        original_key = (directory / "proxy-key.pem").read_bytes()
        real_unlink = os.unlink
        failed = False
        def interrupt_private_key_unlink(path, *args, **kwargs):
            nonlocal failed
            if path == "proxy-key.pem" and "dir_fd" in kwargs and not failed:
                failed = True
                raise OSError("Synthetic interruption after durable purge audit")
            return real_unlink(path, *args, **kwargs)
        with patch("os.unlink", side_effect=interrupt_private_key_unlink):
            with self.assertRaises(OSError):
                self.supervisor.purge(identity, termination_confirmed=True)
        self.assertTrue(failed)
        self.assertFalse(Path(binding["proxy_endpoint"]).exists())
        tombstone = self.proxy_root / "purge-ledger" / (identity.key + ".json")
        audit = json.loads(tombstone.read_text())
        self.assertEqual(audit["status"], "purging")
        self.assertIsNone(audit["purged_at"])
        self.assertEqual(audit["certificate_thumbprint"], binding["certificate_thumbprint"])
        self.assertEqual((directory / "proxy-key.pem").read_bytes(), original_key)
        with self.assertRaises(ValueError):
            self.bind(supervisor=self.new_supervisor())
        self.assertEqual((directory / "proxy-key.pem").read_bytes(), original_key)
        self.assertTrue(self.supervisor.purge(identity, termination_confirmed=True))
        audit_bytes = self.assert_purge_complete(identity, binding)
        self.assertEqual(json.loads(audit_bytes)["status"], "purged")
        self.assertTrue(self.supervisor.purge(identity, termination_confirmed=True))
        self.assertEqual(self.assert_purge_complete(identity, binding), audit_bytes)


    def test_external_credentials_cancellation_is_controlled_on_real_uds_without_downstream_io(self):
        node = self.central_supervisor(lambda fields, csr: self.issue_csr(csr))
        healthy_provider = node.token_provider
        component = {"component_id": "participant-a", "participant_id": "alice"}
        assignment = {"enabled": True}
        credential_calls = []
        internal_node_token = "synthetic-private-node-control-token"
        manager = FastAPI()

        @manager.post("/internal/jobs/v1/participants/{job_id}/{attempt_id}/{component_id}/{epoch}/credentials")
        async def credentials(request: Request, job_id: str, attempt_id: str, component_id: str, epoch: int):
            self.assertEqual((job_id, attempt_id, component_id, epoch),
                             ("job-a", "attempt-a", "participant-a", 1))
            self.assertEqual(request.scope["state"]["verified_certificate_thumbprint"], self.bundle["other"][4])
            self.assertEqual(request.headers["Authorization"], "Bearer " + internal_node_token)
            credential_calls.append((job_id, attempt_id, component_id, epoch))
            if not assignment["enabled"]:
                return JSONResponse({"error": {"code": "participant_assignment_not_found",
                    "details": {"token": internal_node_token, "private_key": "private-provider-secret"}}},
                    status_code=404)
            return {"exchange_token": healthy_provider(execution_binding, "alice", "exchange"),
                    "gateway_token": healthy_provider(execution_binding, "alice", "gateway")}

        manager_server = start_mtls_server(manager, certificate=self.bundle["server"][2],
            key=self.bundle["server"][3], client_ca=self.bundle["ca"][2])
        self.addCleanup(manager_server.server_close)
        self.addCleanup(manager_server.shutdown)
        manager_client = ExternalManagerClient(
            "https://127.0.0.1:" + str(manager_server.server_address[1]),
            ca_file=self.bundle["ca"][2], certificate_file=self.bundle["other"][2],
            key_file=self.bundle["other"][3])
        self.addCleanup(manager_client.close)

        def delegated_credentials(binding, participant_id, audience):
            identity = ExecutionIdentity(binding.job_id, binding.attempt_id, binding.component_id, binding.epoch)
            result = manager_client.request(identity, internal_node_token, "credentials", body={})
            return result["exchange_token" if audience == "exchange" else "gateway_token"]
        node.token_provider = delegated_credentials
        binding = self.bind(supervisor=node, component=component)
        self.register(binding, component=component)
        execution_binding = ExecutionBinding("job-a", "attempt-a", "participant-a", self.sid, 1,
                                             binding["certificate_thumbprint"])
        client = self.uds_client(binding)
        downstream_calls = []
        original_exchange, original_gateway = self.exchange_server.app, self.gateway_server.app
        async def counted_exchange(scope, receive, send):
            if scope["type"] == "http":
                downstream_calls.append(("exchange", scope["method"], scope["path"]))
            await original_exchange(scope, receive, send)
        async def counted_gateway(scope, receive, send):
            if scope["type"] == "http":
                downstream_calls.append(("gateway", scope["method"], scope["path"]))
            await original_gateway(scope, receive, send)

        with patch.object(self.exchange_server, "app", counted_exchange), \
             patch.object(self.gateway_server, "app", counted_gateway):
            self.assertEqual(client.get(f"/v2/spaces/{self.sid}/membership").status_code, 200)
            self.assertEqual(client.head(self.path + "/content").status_code, 200)
            self.assertEqual([entry[0] for entry in downstream_calls], ["exchange", "gateway"])
            downstream_calls.clear()
            before_credentials = len(credential_calls)
            before_storage = len(self.origin_requests)
            self.service.revoke_workload_grants(self.provisioner, self.sid,
                {"attempt_id": "attempt-a"}, "external-provider-cancel")
            assignment["enabled"] = False
            for method, path, body in (
                ("POST", f"/v2/spaces/{self.sid}/records", b'{"metadata":{}}'),
                ("PUT", self.path + "/parts/1", b"part"),
            ):
                response = client.request(method, path, content=body)
                with self.subTest(route=path):
                    self.assertEqual(response.status_code, 403, response.text)
                    self.assertEqual(response.json(), {"error": {"code": "execution_authority_denied"}})
                    returned = response.text + repr(dict(response.headers))
                    for secret in (internal_node_token, "participant_assignment_not_found",
                                   "private-provider-secret", "PRIVATE KEY"):
                        self.assertNotIn(secret, returned)
            self.assertEqual(len(credential_calls), before_credentials + 2)
            self.assertEqual(downstream_calls, [])
            self.assertEqual(len(self.origin_requests), before_storage)


if __name__ == "__main__":
    unittest.main()
