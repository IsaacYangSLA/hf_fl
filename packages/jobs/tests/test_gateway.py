"""Adversarial transfer boundary tests using signed credentials and real mTLS."""
from __future__ import annotations

import asyncio
import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import importlib.util
from pathlib import Path
import ssl
import tempfile
import threading
import time
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
import httpx

from hf2l_jobs.broker import BrokerSettings, WorkloadBroker, stable_workload_subject


def certificate_bundle(directory: Path):
    """Issue two independent test CAs, a server, and three distinct client keys."""
    def issue(name, *, ca=None, server=False):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = datetime.now(timezone.utc)
        builder = (x509.CertificateBuilder().subject_name(subject)
                   .issuer_name(ca[1].subject if ca else subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1))
                   .not_valid_after(now + timedelta(hours=1))
                   .add_extension(x509.BasicConstraints(ca=ca is None, path_length=None), critical=True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                       ca[1].extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
                       if ca else x509.SubjectKeyIdentifier.from_public_key(key.public_key())), critical=False)
                   .add_extension(x509.KeyUsage(digital_signature=ca is not None,
                       content_commitment=False, key_encipherment=bool(ca and server),
                       data_encipherment=False, key_agreement=False, key_cert_sign=ca is None,
                       crl_sign=ca is None, encipher_only=None, decipher_only=None), critical=True))
        if ca:
            usage = ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH
            builder = builder.add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
            if server:
                builder = builder.add_extension(x509.SubjectAlternativeName([
                    x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                    critical=False)
        certificate = builder.sign(ca[0] if ca else key, hashes.SHA256())
        certificate_path = directory / (name + ".pem")
        key_path = directory / (name + ".key")
        certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        key_path.chmod(0o600)
        thumbprint = base64.urlsafe_b64encode(certificate.fingerprint(hashes.SHA256())).decode().rstrip("=")
        return key, certificate, str(certificate_path), str(key_path), thumbprint

    ca = issue("ca")
    foreign_ca = issue("foreign-ca")
    return {"ca": ca, "server": issue("server", ca=ca, server=True),
            "client": issue("client", ca=ca), "other": issue("other", ca=ca),
            "foreign": issue("foreign", ca=foreign_ca)}


class VerifiedPeer:
    """Emulate only trusted TLS scope state for deterministic HTTP tests."""
    def __init__(self, app, thumbprint):
        self.app, self.thumbprint = app, thumbprint

    async def __call__(self, scope, receive, send):
        scope = dict(scope)
        scope["state"] = dict(scope.get("state", {}))
        scope["state"]["verified_certificate_thumbprint"] = self.thumbprint
        await self.app(scope, receive, send)


class RawTransfers:
    """Provider grant fixture; real Exchange grants never reach workload responses."""
    def __init__(self):
        self.url = "https://storage.example.test/bucket/object?signature=private"
        self.size = 8
        self.calls = []
        self.begin_calls, self.finish_calls = [], []
        self.held, self.finished = set(), set()

    def begin_gateway_put(self, principal, sid, rid, aid, number):
        handle = ("private-gateway-put", len(self.begin_calls) + 1, sid, rid, aid, number)
        self.begin_calls.append(handle)
        self.held.add(handle)
        grant = self.grants(sid, rid, aid, principal, [number])["grants"][0]
        return handle, grant

    def finish_gateway_put(self, handle):
        if handle not in self.held:
            raise AssertionError("Cannot finish an unknown or repeated private upload receipt")
        self.finish_calls.append(handle)
        self.held.remove(handle)
        self.finished.add(handle)
        return True

    def grants(self, sid, rid, aid, principal, numbers):
        self.calls.append(("upload", sid, rid, aid, numbers))
        return {"grants": [{"url": self.url, "headers": {"Content-Length": str(self.size)},
                            "number": numbers[0], "size": self.size,
                            "expires_at": time.time() + 60}]}

    def download(self, sid, rid, aid, principal):
        self.calls.append(("download", sid, rid, aid))
        return {"url": self.url, "headers": {}, "size": self.size,
                "sha256": hashlib.sha256(b"abcdefgh").hexdigest(), "expires_at": time.time() + 60}


class GatewayFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public = cls.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def setUp(self):
        from hf2l_exchange.application import Service
        from hf2l_exchange.auth import principal_id
        from hf2l_exchange.config import AuthSettings, DatabaseSettings, Settings, StorageSettings
        from hf2l_exchange.domain import Principal
        from hf2l_exchange.migrations import initialize
        from hf2l_jobs.gateway import ExchangeTransferBackend, GatewaySettings, create_gateway_app

        self.directory = tempfile.TemporaryDirectory(prefix="hf2l-gateway-test-")
        self.addCleanup(self.directory.cleanup)
        self.bundle = certificate_bundle(Path(self.directory.name))
        self.thumbprint = self.bundle["client"][4]
        self.workload_issuer = "https://workloads.example.test"
        provisioner_id = principal_id("https://humans.example.test", "owner")
        self.auth = AuthSettings(issuer="https://humans.example.test", public_key=self.public,
            admin_subject="owner", workload_issuer=self.workload_issuer, workload_public_key=self.public,
            trusted_backend_secret="test-backend-secret-at-least-32-bytes",
            provisioning_principal_ids=(provisioner_id,))
        settings = Settings(database=DatabaseSettings(url="sqlite:///" + self.directory.name + "/exchange.db"),
                            auth=self.auth, storage=StorageSettings(bucket="tests"))
        self.service = Service(settings)
        initialize(self.service.engine)
        self.addCleanup(self.service.engine.dispose)
        self.provisioner = Principal(provisioner_id, "owner", bootstrap_admin=True)
        self.sid = self.service.create_space(self.provisioner, {"name": "Job A"}, "space-a")["id"]
        self.service.enable_managed_space(self.provisioner, self.sid, {"job_id": "job-a"}, "managed-a")
        subject = stable_workload_subject("job-a", "owner")
        self.service.put_member(self.provisioner, self.sid, principal_id(self.workload_issuer, subject),
            {"subject": subject, "roles": ["reader", "contributor", "publisher"], "bindings": {}})
        grant = self.service.create_workload_grant(self.provisioner, self.sid,
            {"subject": subject, "job_id": "job-a", "attempt_id": "attempt-a", "component_id": "owner",
             "epoch": 1, "certificate_thumbprint": self.thumbprint,
             "roles": ["reader", "contributor", "publisher"], "bindings": {},
             "expires_at": time.time() + 120}, "grant-a")
        self.grant_id = grant["grant_id"]
        self.broker = WorkloadBroker(BrokerSettings(workload_issuer=self.workload_issuer,
            exchange_audience="exchange-workload", gateway_audience="hf2l-transfer", node_audience="hf2l-node",
            public_key=self.public, private_key=self.key))
        self.raw = RawTransfers()
        self.backend = ExchangeTransferBackend(self.service, self.raw)
        self.origin_requests = []
        self.origin_handler = self._origin
        self.http = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: self.origin_handler(request)))
        self.addCleanup(lambda: asyncio.run(self.http.aclose()))
        self.gateway_settings = GatewaySettings(auth=self.auth,
            origin_endpoints=("https://storage.example.test",), max_part_bytes=16, chunk_bytes=1024)
        self.app = create_gateway_app(self.gateway_settings, backend=self.backend, http=self.http)
        self.client = TestClient(VerifiedPeer(self.app, self.thumbprint))
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        self.path = f"/transfers/v1/spaces/{self.sid}/records/record-a/attachments/attachment-a"

    def _origin(self, request):
        self.origin_requests.append(request)
        if request.method == "PUT":
            return httpx.Response(200, headers={"ETag": '"part-private"'}, content=b"")
        if request.method == "HEAD":
            return httpx.Response(200, headers={"Content-Length": "8", "Content-Type": "application/octet-stream"})
        if "Range" in request.headers:
            return httpx.Response(206, headers={"Content-Range": "bytes 2-5/8", "Content-Length": "4"}, content=b"cdef")
        return httpx.Response(200, headers={"Content-Length": "8", "Content-Type": "application/octet-stream"},
                              content=b"abcdefgh")

    def authorization(self, **overrides):
        values = {"job_id": "job-a", "attempt_id": "attempt-a", "component_id": "owner", "space_id": self.sid,
                  "grant_id": self.grant_id, "epoch": 1, "certificate_thumbprint": self.thumbprint,
                  "audience": "gateway"}
        values.update(overrides)
        return {"Authorization": "Bearer " + self.broker.issue_workload(**values)}


class GatewayAuthorizationTests(GatewayFixture):
    def test_foreign_space_denied_before_requesting_provider_grant(self):
        path = self.path.replace(self.sid, "foreign-space") + "/content"
        response = self.client.get(path, headers=self.authorization())
        self.assertIn(response.status_code, (403, 404))
        self.assertEqual(self.raw.calls, [])
        self.assertEqual(self.origin_requests, [])

    def test_valid_token_cannot_survive_ledger_revocation(self):
        self.service.revoke_workload_grants(self.provisioner, self.sid, {"attempt_id": "attempt-a"}, "revoke")
        response = self.client.get(self.path + "/content", headers=self.authorization())
        self.assertIn(response.status_code, (401, 403))
        self.assertEqual(self.raw.calls, [])

    def test_epoch_and_attempt_must_match_current_grant(self):
        for overrides in ({"epoch": 2}, {"attempt_id": "attempt-b"}, {"grant_id": "missing"}):
            with self.subTest(overrides=overrides):
                response = self.client.get(self.path + "/content", headers=self.authorization(**overrides))
                self.assertIn(response.status_code, (401, 403))
        self.assertEqual(self.raw.calls, [])

    def test_wrong_certificate_and_exchange_audience_rejected(self):
        for overrides in ({"certificate_thumbprint": self.bundle["other"][4]}, {"audience": "exchange"}):
            with self.subTest(overrides=overrides):
                response = self.client.get(self.path + "/content", headers=self.authorization(**overrides))
                self.assertEqual(response.status_code, 401)
        self.assertEqual(self.origin_requests, [])

    def test_caller_headers_cannot_impersonate_verified_tls_identity(self):
        unverified = TestClient(self.app)
        with unverified:
            headers = self.authorization()
            headers.update({"X-HF2L-TLS-Thumbprint": self.thumbprint})
            response = unverified.get(self.path + "/content", headers=headers)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.raw.calls, [])

    def test_missing_token_pat_and_arbitrary_bearer_denied(self):
        for headers in ({}, {"Authorization": "Bearer hf_copied_pat"}, {"Authorization": "Basic dXNlcjpwYXNz"}):
            with self.subTest(headers=headers):
                response = self.client.get(self.path + "/content", headers=headers)
                self.assertEqual(response.status_code, 401)
        self.assertEqual(self.raw.calls, [])

    def test_url_query_and_connect_are_not_forward_proxy(self):
        attempts = [("GET", self.path + "/content?url=https://evil.example/file"),
                    ("CONNECT", "https://evil.example:443"), ("GET", "/https://evil.example/file")]
        for method, path in attempts:
            with self.subTest(method=method, path=path):
                response = self.client.request(method, path, headers=self.authorization())
                self.assertGreaterEqual(response.status_code, 400)
        self.assertEqual(self.origin_requests, [])

    def test_private_ingress_assertion_binds_exact_target_and_cannot_be_replayed(self):
        from hf2l_exchange.auth import backend_assertion_headers
        path = self.path + "/content"
        headers = self.authorization()
        headers.update(backend_assertion_headers(self.auth.trusted_backend_secret, "HEAD", path,
                                                headers["Authorization"], self.thumbprint))
        with TestClient(self.app) as client:
            self.assertEqual(client.head(path, headers=headers).status_code, 200)
            self.assertEqual(client.get(path, headers=headers).status_code, 401)
            copied = dict(headers, **{"X-HF2L-TLS-Thumbprint": self.bundle["other"][4]})
            self.assertEqual(client.head(path, headers=copied).status_code, 401)
        self.assertEqual(self.origin_requests, [])

    def test_expired_grant_denied_even_when_signed_token_is_current(self):
        from hf2l_exchange.models import WorkloadGrant
        with self.service.sessions.begin() as session:
            session.get(WorkloadGrant, self.grant_id).expires_at = time.time() - 1
        response = self.client.head(self.path + "/content", headers=self.authorization())
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.raw.calls, [])

    def test_revocation_during_grant_resolution_rechecked_before_first_byte(self):
        original = self.raw.download
        def revoke_after_grant(*args):
            grant = original(*args)
            self.service.revoke_workload_grants(self.provisioner, self.sid,
                {"attempt_id": "attempt-a"}, "revoke-during-download")
            return grant
        self.raw.download = revoke_after_grant
        response = self.client.get(self.path + "/content", headers=self.authorization())
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.origin_requests, [])

    def test_actual_gateway_mtls_binds_token_to_authenticated_peer_certificate(self):
        from hf2l_jobs.execution_proxy import start_mtls_server
        server = start_mtls_server(self.app, certificate=self.bundle["server"][2],
            key=self.bundle["server"][3], client_ca=self.bundle["ca"][2])
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        endpoint = "https://127.0.0.1:" + str(server.server_address[1]) + self.path + "/content"
        for certificate, expected in ((self.bundle["client"], 200), (self.bundle["other"], 401)):
            context = ssl.create_default_context(cafile=self.bundle["ca"][2])
            context.load_cert_chain(certificate[2], certificate[3])
            with self.subTest(expected=expected), httpx.Client(verify=context, trust_env=False, timeout=3) as client:
                response = client.head(endpoint, headers=self.authorization())
            self.assertEqual(response.status_code, expected)
        self.assertEqual(self.origin_requests, [])


class GatewayTransferTests(GatewayFixture):
    def test_multipart_put_uses_provider_identity_without_leaking_signed_url(self):
        response = self.client.put(self.path + "/parts/1", headers=self.authorization(), content=b"abcdefgh")
        self.assertEqual(response.status_code, 204, response.text)
        self.assertEqual(len(self.origin_requests), 1)
        request = self.origin_requests[0]
        self.assertEqual(request.method, "PUT")
        self.assertEqual(str(request.url), self.raw.url)
        self.assertEqual(request.content, b"abcdefgh")
        self.assertEqual(request.headers["Content-Length"], "8")
        self.assertNotIn("signature=private", response.text)
        self.assertNotIn("storage.example.test", response.text)
        self.assertNotIn("Authorization", request.headers)
        self.assertEqual(self.raw.finish_calls, self.raw.begin_calls)
        self.assertEqual(self.raw.held, set())

    def test_multipart_length_mismatch_and_part_limit_fail_before_storage(self):
        for body, size in ((b"abc", 8), (b"x" * 17, 17)):
            with self.subTest(body_size=len(body), grant_size=size):
                self.raw.size = size
                response = self.client.put(self.path + "/parts/1", headers=self.authorization(), content=body)
                self.assertIn(response.status_code, (400, 413, 422))
        self.assertEqual(self.origin_requests, [])

    def test_download_range_and_head_keep_object_identity_private(self):
        headers = self.authorization()
        headers["Range"] = "bytes=2-5"
        response = self.client.get(self.path + "/content", headers=headers)
        self.assertEqual(response.status_code, 206, response.text)
        self.assertEqual(response.content, b"cdef")
        self.assertEqual(response.headers["Content-Range"], "bytes 2-5/8")
        self.assertEqual(self.origin_requests[-1].headers["Range"], "bytes=2-5")
        response = self.client.head(self.path + "/content", headers=self.authorization())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"")
        self.assertEqual(response.headers["Content-Length"], "8")
        self.assertNotIn("signature", repr(dict(response.headers)))

    def test_multiple_and_malformed_ranges_rejected(self):
        for value in ("bytes=0-1,3-4", "bytes=-", "items=0-2", "bytes=5-1"):
            with self.subTest(value=value):
                headers = self.authorization()
                headers["Range"] = value
                response = self.client.get(self.path + "/content", headers=headers)
                self.assertIn(response.status_code, (400, 416, 422))
        self.assertEqual(self.origin_requests, [])

    def test_provider_redirects_are_not_followed_or_disclosed(self):
        self.origin_handler = lambda request: httpx.Response(302, headers={"Location": "https://evil.example/copied"})
        response = self.client.get(self.path + "/content", headers=self.authorization())
        self.assertGreaterEqual(response.status_code, 400)
        self.assertNotIn("evil.example", response.text)
        self.assertNotIn("Location", response.headers)

    def test_provider_url_cannot_escape_fixed_storage_origin(self):
        for url in ("https://evil.example/bucket/object", "http://storage.example.test/bucket/object",
                    "https://user:pass@storage.example.test/bucket/object", "https://storage.example.test:8443/bucket/object",
                    "https://storage.example.test/bucket/object#fragment"):
            with self.subTest(url=url):
                self.raw.url = url
                response = self.client.get(self.path + "/content", headers=self.authorization())
                self.assertGreaterEqual(response.status_code, 400)
        self.assertEqual(self.origin_requests, [])

    def test_upload_is_streamed_in_bounded_chunks_instead_of_one_buffer(self):
        from hf2l_jobs.gateway import create_gateway_app
        observed = []
        class StreamingTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(inner, request):
                async for chunk in request.stream:
                    observed.append(chunk)
                return httpx.Response(204)
        stream_http = httpx.AsyncClient(transport=StreamingTransport())
        self.addCleanup(lambda: asyncio.run(stream_http.aclose()))
        self.raw.size = 8192
        settings = replace(self.gateway_settings, max_part_bytes=8192, chunk_bytes=1024)
        app = create_gateway_app(settings, self.backend, http=stream_http)
        payload = b"x" * 8192
        with TestClient(VerifiedPeer(app, self.thumbprint)) as client:
            response = client.put(self.path + "/parts/1", headers=self.authorization(), content=payload)
        self.assertEqual(response.status_code, 204, response.text)
        self.assertEqual(b"".join(observed), payload)
        self.assertGreater(len(observed), 1)
        self.assertTrue(all(len(chunk) <= 1024 for chunk in observed))

    def test_wrong_range_or_length_from_provider_rejected_without_body_disclosure(self):
        attempts = ({"Content-Range": "bytes 1-4/8", "Content-Length": "4"},
                    {"Content-Range": "bytes 2-5/8", "Content-Length": "8"})
        for origin_headers in attempts:
            with self.subTest(origin_headers=origin_headers):
                self.origin_handler = lambda request, values=origin_headers: httpx.Response(206,
                    headers=values, content=b"cdef")
                response = self.client.get(self.path + "/content", headers=dict(self.authorization(), Range="bytes=2-5"))
                self.assertEqual(response.status_code, 502)
                self.assertNotIn("cdef", response.text)

    def test_unsafe_provider_authorization_headers_denied(self):
        original = self.raw.download
        def poisoned(*args):
            return dict(original(*args), headers={"Authorization": "Bearer origin-secret"})
        self.raw.download = poisoned
        response = self.client.get(self.path + "/content", headers=self.authorization())
        self.assertEqual(response.status_code, 502)
        self.assertNotIn("origin-secret", response.text)
        self.assertEqual(self.origin_requests, [])

    def test_multiple_mtls_gateway_requests_reuse_trusted_https_origin_safely(self):
        from hf2l_jobs.execution_proxy import start_mtls_server
        from hf2l_jobs.gateway import create_gateway_app
        observations = []
        class Origin(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(inner, *_):
                pass
            def do_PUT(inner):
                body = inner.rfile.read(int(inner.headers["Content-Length"]))
                observations.append((inner.command, body, inner.headers.get("Authorization")))
                inner.send_response(204)
                inner.send_header("Content-Length", "0")
                inner.send_header("ETag", '"part"')
                inner.end_headers()
            def do_GET(inner):
                selected = inner.headers.get("Range")
                body = b"cdef" if selected else b"abcdefgh"
                observations.append((inner.command, selected, inner.headers.get("Authorization")))
                inner.send_response(206 if selected else 200)
                inner.send_header("Content-Length", str(len(body)))
                if selected:
                    inner.send_header("Content-Range", "bytes 2-5/8")
                inner.end_headers()
                inner.wfile.write(body)
                inner.wfile.flush()
        origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        origin.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.bundle["server"][2], self.bundle["server"][3])
        origin.socket = context.wrap_socket(origin.socket, server_side=True)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        self.addCleanup(origin.server_close)
        self.addCleanup(origin.shutdown)
        origin_endpoint = "https://127.0.0.1:" + str(origin.server_address[1])
        self.raw.url = origin_endpoint + "/bucket/object?signature=private"
        settings = replace(self.gateway_settings, origin_endpoints=(origin_endpoint,), origin_ca_file=self.bundle["ca"][2])
        gateway = create_gateway_app(settings, self.backend)
        server = start_mtls_server(gateway, certificate=self.bundle["server"][2],
            key=self.bundle["server"][3], client_ca=self.bundle["ca"][2])
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        endpoint = "https://127.0.0.1:" + str(server.server_address[1]) + self.path
        trusted = ssl.create_default_context(cafile=self.bundle["ca"][2])
        trusted.load_cert_chain(self.bundle["client"][2], self.bundle["client"][3])
        with httpx.Client(verify=trusted, trust_env=False, timeout=5) as client:
            for _ in range(2):
                response = client.put(endpoint + "/parts/1", headers=self.authorization(), content=b"abcdefgh")
                self.assertEqual(response.status_code, 204, response.text)
                response = client.get(endpoint + "/content", headers=dict(self.authorization(), Range="bytes=2-5"))
                self.assertEqual(response.status_code, 206, response.text)
                self.assertEqual(response.content, b"cdef")
                response = client.get(endpoint + "/content", headers=self.authorization())
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.content, b"abcdefgh")
            self.service.revoke_workload_grants(self.provisioner, self.sid, {"attempt_id": "attempt-a"}, "revoke-live")
            self.assertEqual(client.get(endpoint + "/content", headers=self.authorization()).status_code, 403)
        self.assertEqual(len(observations), 6)
        self.assertTrue(all(authorization is None for _, _, authorization in observations))

    def test_malformed_origin_descriptors_are_denied_before_storage(self):
        original = self.raw.download
        attempts = ({"expires_at": float("nan")}, {"expires_at": float("inf")},
                    {"expires_at": "not-a-time"}, {"expires_at": {}},
                    {"url": "https://storage.example.test:not-a-port/bucket/object"})
        for overrides in attempts:
            with self.subTest(overrides=overrides):
                self.raw.download = lambda *args, values=overrides: dict(original(*args), **values)
                response = self.client.get(self.path + "/content", headers=self.authorization())
                self.assertIn(response.status_code, (409, 502))
        self.assertEqual(self.origin_requests, [])



class GatewayUploadFenceTests(GatewayFixture):
    """Real Exchange mutation ledgers qualified through gateway HTTP requests."""

    def setUp(self):
        super().setUp()
        from hf2l_exchange.auth import Authenticator
        from hf2l_exchange.transfers import TransferService
        fixture_path = Path(__file__).resolve().parents[2] / "exchange" / "tests" / "test_transfers.py"
        specification = importlib.util.spec_from_file_location("_gateway_transfer_store_fixture", fixture_path)
        fixture = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(fixture)
        self.store = fixture.FakeStore()
        self.events, self.finishes, self.provider_entries = [], [], []
        owner = self

        class ObservedTransfers(TransferService):
            def finish_gateway_put(inner, handle):
                owner.finishes.append((handle, tuple(owner.events), tuple(owner.tokens())))
                return super().finish_gateway_put(handle)

        self.transfers = ObservedTransfers(self.service, self.store)
        self.workload = Authenticator(self.auth).authenticate(
            self.authorization(audience="exchange")["Authorization"],
            managed=True, certificate_thumbprint=self.thumbprint)
        self.revision = self.service.register_type(self.provisioner, self.sid, "document",
            {"schema": {"type": "object"}}, "gateway-fence-type")
        self.sequence = 0

    def tokens(self):
        from hf2l_exchange.models import TransferAttempt
        with self.service.sessions() as session:
            return list(session.get(TransferAttempt, self.transfer_attempt_id).mutation_tokens)

    def current_attempt(self):
        from hf2l_exchange.models import TransferAttempt
        with self.service.sessions() as session:
            return session.get(TransferAttempt, self.transfer_attempt_id)

    def prepare(self, content=b"abcdefgh"):
        from hf2l_exchange.storage import UploadedPart
        self.sequence += 1
        self.record = self.service.create_record(self.workload, self.sid, {
            "kind": "document", "schema_revision_id": self.revision["id"], "metadata": {},
            "attachments": [{"path": "upload.bin", "size": len(content),
                             "sha256": hashlib.sha256(content).hexdigest()}],
        }, "gateway-fence-record-" + str(self.sequence))
        self.attachment_id = self.record["attachments"][0]["id"]
        self.transfer_args = self.sid, self.record["id"], self.attachment_id, self.workload
        self.transfer_attempt_id = self.transfers.initiate(*self.transfer_args)["attempt_id"]
        self.store.parts_result = [UploadedPart(1, "owned-part", len(content))]
        self.upload_path = f"/transfers/v1/spaces/{self.sid}/records/{self.record['id']}/attachments/{self.attachment_id}/parts/1"
        return self.upload_path

    def install_gateway(self, scenario="success"):
        from hf2l_jobs.gateway import ExchangeTransferBackend, create_gateway_app
        owner = self

        class ClosedResponse(httpx.AsyncByteStream):
            async def __aiter__(inner):
                if False:
                    yield b""
            async def aclose(inner):
                owner.events.append(("closed", tuple(owner.tokens())))
                if scenario == "close-failure":
                    raise httpx.ReadError("Synthetic ambiguous response close")

        class Provider(httpx.AsyncBaseTransport):
            async def handle_async_request(inner, request):
                owner.provider_entries.append(tuple(owner.tokens()))
                if scenario != "premature-success":
                    body = await request.aread()
                    owner.events.append(("body", body))
                if scenario == "timeout":
                    raise httpx.ReadTimeout("Synthetic provider acknowledgement timeout")
                if scenario == "disconnect":
                    raise httpx.RemoteProtocolError("Synthetic lost provider acknowledgement")
                return httpx.Response(500 if scenario == "non-success" else 204,
                    headers={"Content-Length": "0", "ETag": '"owned-part"'}, stream=ClosedResponse())

        transport_client = httpx.AsyncClient(transport=Provider())
        self.addCleanup(lambda: asyncio.run(transport_client.aclose()))
        self.real_backend = ExchangeTransferBackend(self.service, self.transfers)
        self.fence_app = create_gateway_app(self.gateway_settings, self.real_backend, http=transport_client)
        client = TestClient(VerifiedPeer(self.fence_app, self.thumbprint))
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        return client

    def retire(self):
        self.service.revoke_workload_grants(self.provisioner, self.sid,
            {"attempt_id": "attempt-a"}, "fence-retire-revoke")
        return self.service.retire_managed_space(self.provisioner, self.sid,
            {"job_id": "job-a"}, "fence-retire-space")

    def test_actual_fence_finishes_after_exact_body_and_successful_upstream_close(self):
        path = self.prepare()
        client = self.install_gateway()
        response = client.put(path, content=b"abcdefgh", headers=self.authorization())
        self.assertEqual(response.status_code, 204, response.text)
        self.assertEqual(len(self.provider_entries), 1)
        self.assertEqual(len(self.provider_entries[0]), 1)
        self.assertEqual(len(self.finishes), 1)
        handle, events, marker_at_finish = self.finishes[0]
        self.assertEqual(events[0], ("body", b"abcdefgh"))
        self.assertEqual(events[1][0], "closed")
        self.assertEqual(events[1][1], marker_at_finish)
        self.assertEqual(marker_at_finish, (handle.token,))
        self.assertEqual(self.tokens(), [])
        self.assertNotIn(handle.token, response.text)
        self.assertNotIn(handle.object_key, repr(dict(response.headers)))

    def test_ambiguous_provider_results_leave_real_mutation_receipts_held(self):
        attempts = []
        for scenario in ("timeout", "disconnect", "non-success", "close-failure"):
            path = self.prepare()
            attempts.append(self.transfer_attempt_id)
            client = self.install_gateway(scenario)
            response = client.put(path, content=b"abcdefgh", headers=self.authorization())
            with self.subTest(scenario=scenario):
                self.assertEqual(response.status_code, 503, response.text)
                self.assertEqual(len(self.tokens()), 1)
                self.assertEqual(self.finishes, [])
                self.assertNotIn("gateway-put-", response.text)
        from hf2l_exchange.models import Blob, Space, TransferAttempt
        from hf2l_exchange.worker import tick
        self.assertTrue(self.retire()["cleanup_pending"])
        with self.service.sessions.begin() as session:
            for identity in attempts:
                attempt = session.get(TransferAttempt, identity)
                attempt.grant_expires_at, attempt.next_attempt = 0, 0
                session.get(Blob, attempt.blob_id).grant_expires_at = 0
        self.assertEqual(tick(self.transfers)["cleaned"], 0)
        self.assertEqual(self.store.cleaned, [])
        with self.service.sessions() as session:
            self.assertEqual(session.get(Space, self.sid).reclaiming, 32)
        self.assertTrue(self.service.get_managed_space(self.provisioner, self.sid)["cleanup_pending"])

    def test_premature_success_without_request_eof_cannot_finish_fence(self):
        path = self.prepare()
        response = self.install_gateway("premature-success").put(
            path, content=b"abcdefgh", headers=self.authorization())
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(len(self.tokens()), 1)
        self.assertEqual(self.finishes, [])
        self.assertEqual([event[0] for event in self.events], ["closed"])

    def test_downstream_disconnect_after_begin_does_not_finish_actual_fence(self):
        from starlette.requests import ClientDisconnect
        path = self.prepare()
        self.install_gateway()
        headers = self.authorization()
        receive_messages = iter([
            {"type": "http.request", "body": b"abc", "more_body": True},
            {"type": "http.disconnect"},
        ])
        sent, disconnected = [], []
        async def receive():
            message = next(receive_messages)
            if message["type"] == "http.disconnect":
                disconnected.append(True)
            return message
        async def send(message):
            sent.append(message)
        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "method": "PUT", "scheme": "https", "path": path, "raw_path": path.encode(),
            "query_string": b"", "root_path": "", "client": ("127.0.0.1", 1234),
            "server": ("gateway.local", 443), "headers": [
                (b"authorization", headers["Authorization"].encode()), (b"content-length", b"8"),
            ]}
        async def lost_client():
            try:
                await VerifiedPeer(self.fence_app, self.thumbprint)(scope, receive, send)
            except ClientDisconnect:
                pass
        asyncio.run(lost_client())
        self.assertEqual(disconnected, [True])
        self.assertEqual(len(self.provider_entries), 1)
        self.assertEqual(len(self.provider_entries[0]), 1)
        self.assertEqual(len(self.tokens()), 1)
        self.assertEqual(self.finishes, [])
        starts = [message for message in sent if message["type"] == "http.response.start"]
        self.assertTrue(not starts or starts[0]["status"] >= 400)

    def test_completed_and_malformed_requests_do_not_begin_or_finish_provider_io(self):
        path = self.prepare()
        client = self.install_gateway()
        malformed = (
            {"Content-Length": "3"}, {"Content-Length": "not-an-integer"},
            {"Content-Length": "8", "Transfer-Encoding": "chunked"},
        )
        for extra in malformed:
            with self.subTest(headers=extra):
                response = client.put(path, content=b"abcdefgh", headers=dict(self.authorization(), **extra))
                self.assertIn(response.status_code, (400, 411, 422))
                self.assertEqual(self.tokens(), [])
        from hf2l_exchange.worker import tick
        self.transfers.complete(*self.transfer_args)
        self.assertEqual(tick(self.transfers)["verified"], 1)
        response = client.put(path, content=b"abcdefgh", headers=self.authorization())
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(self.tokens(), [])
        self.assertEqual(self.provider_entries, [])
        self.assertEqual(self.finishes, [])

    def test_fresh_fenced_grant_is_revalidated_before_origin_io(self):
        for changed in ({"size": 7}, {"url": "https://foreign.example.test/object"}):
            path = self.prepare()
            client = self.install_gateway()
            original = self.real_backend.begin_upload
            def changed_fresh(*args, changed=changed):
                receipt, grant = original(*args)
                return receipt, dict(grant, **changed)
            self.real_backend.begin_upload = changed_fresh
            response = client.put(path, content=b"abcdefgh", headers=self.authorization())
            with self.subTest(changed=changed):
                self.assertIn(response.status_code, (502, 503))
                self.assertEqual(len(self.tokens()), 1)
                self.assertEqual(self.provider_entries, [])
                self.assertEqual(self.finishes, [])

    def test_actual_tls_backpressure_retains_retired_space_until_known_ack_after_signed_expiry(self):
        from hf2l_exchange.models import Blob, Space, TransferAttempt, database_time
        from hf2l_exchange.storage import TransferGrant
        from hf2l_exchange.worker import tick
        from hf2l_jobs.execution_proxy import start_mtls_server
        from hf2l_jobs.gateway import ExchangeTransferBackend, create_gateway_app
        content = b"x" * 65537
        path = self.prepare(content)
        object_key = self.current_attempt().object_key
        origin_started, release_origin, release_body = threading.Event(), threading.Event(), threading.Event()
        done, errors, responses, provider_objects = threading.Event(), [], [], {}
        owner = self

        class Origin(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(inner, *_):
                pass
            def do_PUT(inner):
                first = inner.rfile.read(1)
                if first != content[:1]:
                    errors.append(AssertionError("Provider did not receive the admitted writer's byte"))
                origin_started.set()
                if not release_origin.wait(10):
                    errors.append(AssertionError("Provider acknowledgement was never released"))
                    return
                rest = inner.rfile.read(int(inner.headers["Content-Length"]) - 1)
                provider_objects[object_key] = first + rest
                inner.send_response(204)
                inner.send_header("Content-Length", "0")
                inner.send_header("ETag", '"owned-part"')
                inner.end_headers()
                inner.wfile.flush()

        origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        origin.daemon_threads = True
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(self.bundle["server"][2], self.bundle["server"][3])
        origin.socket = server_context.wrap_socket(origin.socket, server_side=True)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        self.addCleanup(origin.server_close)
        self.addCleanup(origin.shutdown)
        origin_endpoint = "https://127.0.0.1:" + str(origin.server_address[1])
        original_grant, original_cleanup = self.store.upload_grant, self.store.cleanup
        def one_second_private_grant(handle, number, size, expires_at, seconds):
            original_grant(handle, number, size, expires_at, seconds)
            return TransferGrant(origin_endpoint + "/private-object?signature=synthetic",
                                 {"Content-Length": str(size)}, expires_at)
        def delete_owned_provider_object(key):
            original_cleanup(key)
            provider_objects.pop(key, None)
        self.store.upload_grant = one_second_private_grant
        self.store.cleanup = delete_owned_provider_object
        self.transfers.settings = replace(self.transfers.settings,
            storage=replace(self.transfers.settings.storage, grant_seconds=1))
        settings = replace(self.gateway_settings, origin_endpoints=(origin_endpoint,),
            origin_ca_file=self.bundle["ca"][2], max_part_bytes=len(content), chunk_bytes=65536,
            timeout_seconds=8)
        gateway = create_gateway_app(settings, ExchangeTransferBackend(self.service, self.transfers))
        edge = start_mtls_server(gateway, certificate=self.bundle["server"][2],
            key=self.bundle["server"][3], client_ca=self.bundle["ca"][2])
        self.addCleanup(edge.server_close)
        self.addCleanup(edge.shutdown)
        endpoint = "https://127.0.0.1:" + str(edge.server_address[1]) + path
        trusted = ssl.create_default_context(cafile=self.bundle["ca"][2])
        trusted.load_cert_chain(self.bundle["client"][2], self.bundle["client"][3])
        def streamed_body():
            yield content[:65536]
            if not release_body.wait(10):
                raise AssertionError("Client stream was never released")
            yield content[65536:]
        def writer():
            try:
                with httpx.Client(verify=trusted, trust_env=False, timeout=8) as client:
                    responses.append(client.put(endpoint, content=streamed_body(),
                        headers=dict(self.authorization(), **{"Content-Length": str(len(content))})))
            except BaseException as error:
                errors.append(error)
            finally:
                done.set()

        # SQLite's clock has whole-second resolution. Start near the beginning
        # of a second so the genuine one-second descriptor admits the request.
        delay = (1.05 - time.time() % 1) % 1
        time.sleep(delay)
        writer_thread = threading.Thread(target=writer, daemon=True)
        writer_thread.start()
        self.addCleanup(writer_thread.join, 5)
        self.addCleanup(release_origin.set)
        self.addCleanup(release_body.set)
        self.assertTrue(origin_started.wait(5), "Actual HTTPS origin did not accept the fenced stream")
        self.assertEqual(errors, [])
        marker = tuple(self.tokens())
        self.assertEqual(len(marker), 1)
        self.assertFalse(done.is_set())
        deadline = time.monotonic() + 4
        while True:
            with self.service.sessions() as session:
                current = session.get(TransferAttempt, self.transfer_attempt_id)
                blob = session.get(Blob, self.attachment_id)
                expired = max(current.grant_expires_at, blob.grant_expires_at) < database_time(session)
            if expired:
                break
            self.assertLess(time.monotonic(), deadline, "One-second private grants did not expire")
            time.sleep(.02)
        self.assertEqual(tuple(self.tokens()), marker)
        self.assertTrue(self.retire()["cleanup_pending"])
        self.assertEqual(tick(self.transfers)["cleaned"], 0)
        self.assertEqual(self.store.cleaned, [])
        with self.service.sessions() as session:
            self.assertEqual(session.get(Space, self.sid).reclaiming, len(content))
            self.assertTrue(session.get(Blob, self.attachment_id).pending_deletion)
        self.assertTrue(self.service.get_managed_space(self.provisioner, self.sid)["cleanup_pending"])
        self.assertFalse(done.is_set())
        release_body.set()
        release_origin.set()
        writer_thread.join(5)
        self.assertFalse(writer_thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(responses[0].status_code, 204, responses[0].text)
        self.assertEqual(provider_objects[object_key], content)
        self.assertEqual(self.tokens(), [])
        self.assertEqual(len(self.finishes), 1)
        self.assertEqual(tick(self.transfers)["cleaned"], 1)
        self.assertEqual(self.store.cleaned, [object_key])
        self.assertEqual(provider_objects, {})
        self.assertFalse(self.service.get_managed_space(self.provisioner, self.sid)["cleanup_pending"])
        with self.service.sessions() as session:
            self.assertEqual(session.get(Space, self.sid).reclaiming, 0)
            self.assertEqual(session.get(Blob, self.attachment_id).state, "cleaned")


class MutualTLSServerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="hf2l-mtls-test-")
        self.addCleanup(self.directory.cleanup)
        self.bundle = certificate_bundle(Path(self.directory.name))

    def test_transport_requires_trusted_client_certificate_and_derives_peer_identity(self):
        from hf2l_jobs.execution_proxy import start_mtls_server
        app = FastAPI()

        @app.get("/peer")
        async def peer(request: Request):
            return {"thumbprint": request.scope.get("state", {}).get("verified_certificate_thumbprint")}

        server = start_mtls_server(app, host="127.0.0.1", port=0,
            certificate=self.bundle["server"][2], key=self.bundle["server"][3], client_ca=self.bundle["ca"][2])
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        endpoint = "https://127.0.0.1:" + str(server.server_address[1]) + "/peer"
        trusted = ssl.create_default_context(cafile=self.bundle["ca"][2])
        trusted.load_cert_chain(self.bundle["client"][2], self.bundle["client"][3])
        with httpx.Client(verify=trusted, trust_env=False, timeout=3) as client:
            response = client.get(endpoint)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["thumbprint"], self.bundle["client"][4])
        for certificate in (None, self.bundle["foreign"]):
            context = ssl.create_default_context(cafile=self.bundle["ca"][2])
            if certificate:
                context.load_cert_chain(certificate[2], certificate[3])
            with self.subTest(certificate=certificate is not None), httpx.Client(
                    verify=context, trust_env=False, timeout=3) as client:
                with self.assertRaises(httpx.TransportError):
                    client.get(endpoint)


if __name__ == "__main__":
    unittest.main()
