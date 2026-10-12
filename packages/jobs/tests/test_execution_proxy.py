"""Closed execution egress rejects cross-job paths and caller credentials."""
from __future__ import annotations

import asyncio
import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient
import httpx
import jwt

from hf2l_jobs.broker import BrokerSettings, WorkloadBroker
from hf2l_jobs.execution_proxy import ExecutionBinding, ProxySettings, create_proxy_app
from hf2l_jobs.domain import Error as ManagerError
from hf2l_jobs.gateway import GatewayError


class ProxyFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public = cls.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="hf2l-proxy-test-")
        self.addCleanup(self.directory.cleanup)
        directory = Path(self.directory.name)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "execution-a")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                    key_encipherment=True, data_encipherment=False, key_agreement=False,
                    key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .sign(self.key, hashes.SHA256()))
        self.cert = directory / "client.pem"
        self.cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.key_path = directory / "client.key"
        self.key_path.write_bytes(self.key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.key_path.chmod(0o600)
        self.thumbprint = base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA256())).decode().rstrip("=")
        self.broker = WorkloadBroker(BrokerSettings(workload_issuer="https://workloads.example.test",
            exchange_audience="exchange-workload", gateway_audience="hf2l-transfer", node_audience="hf2l-node",
            public_key=self.public, private_key=self.key))
        self.binding = ExecutionBinding("job-a", "attempt-a", "owner", "space-a", 1, self.thumbprint)
        self.settings = ProxySettings(exchange_endpoint="https://exchange.example.test",
            gateway_endpoint="https://gateway.example.test", client_certificate=str(self.cert),
            client_key=str(self.key_path), ca_file=str(self.cert), binding=self.binding,
            exchange_token=self.token("exchange"), gateway_token=self.token("gateway"),
            workload_issuer="https://workloads.example.test", workload_public_key=self.public,
            max_control_bytes=128, max_part_bytes=32, max_download_bytes=32)
        self.requests = []
        self.origin_handler = self._origin
        self.http = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: self.origin_handler(request)))
        self.addCleanup(lambda: asyncio.run(self.http.aclose()))
        self.client = self.client_for(self.settings)
        self.control = "/v2/spaces/space-a"
        self.transfer = "/transfers/v1/spaces/space-a/records/record-a/attachments/attachment-a"

    def token(self, audience, **overrides):
        values = {"job_id": "job-a", "attempt_id": "attempt-a", "component_id": "owner", "space_id": "space-a",
                  "grant_id": "grant-a", "epoch": 1, "certificate_thumbprint": self.thumbprint,
                  "audience": audience}
        values.update(overrides)
        return self.broker.issue_workload(**values)

    def client_for(self, settings):
        client = TestClient(create_proxy_app(settings, http=self.http))
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        return client

    def _origin(self, request):
        self.requests.append(request)
        if request.url.host == "gateway.example.test":
            if request.method == "PUT":
                return httpx.Response(204, headers={"ETag": '"part"'})
            return httpx.Response(200, content=b"checkpoint", headers={"Content-Type": "application/octet-stream"})
        return httpx.Response(200, json={"ok": True}, headers={"Set-Cookie": "foreign=secret", "X-Secret": "do-not-forward"})


class ProxyAuthorizationTests(ProxyFixture):
    def test_foreign_spaces_and_privileged_control_operations_denied(self):
        for method, path in (("GET", "/v2/spaces/space-b/records"),
                             ("POST", "/v2/spaces"), ("PUT", self.control + "/members/foreign"),
                             ("POST", self.control + "/workload-grants"),
                             ("PUT", self.control + "/refs/private"), ("GET", "/ready"),
                             ("GET", self.transfer.replace("space-a", "space-b") + "/content")):
            with self.subTest(method=method, path=path):
                response = self.client.request(method, path)
                self.assertEqual(response.status_code, 404, response.text)
        self.assertEqual(self.requests, [])

    def test_url_connect_and_encoded_paths_are_not_forwarded(self):
        for method, path in (("CONNECT", "https://evil.example:443"),
                             ("GET", "/https://evil.example/secret"),
                             ("GET", "/v2/spaces/space-a%2F..%2Fspace-b/records"),
                             ("GET", self.control + "/%2e%2e/space-b/records"),
                             ("GET", self.control + "//records"),
                             ("GET", self.transfer + "/content?url=https://evil.example")):
            with self.subTest(method=method, path=path):
                response = self.client.request(method, path)
                self.assertGreaterEqual(response.status_code, 400)
        self.assertEqual(self.requests, [])

    def test_caller_pat_and_forged_identity_headers_rejected(self):
        headers = ({"Authorization": "Bearer hf_pat"}, {"Proxy-Authorization": "Bearer copied"},
                   {"Cookie": "token=copied"}, {"X-HF2L-TLS-Thumbprint": self.thumbprint},
                   {"X-Forwarded-Client-Cert": self.thumbprint}, {"X-Forwarded-Host": "evil.example"})
        for values in headers:
            with self.subTest(headers=values):
                response = self.client.get(self.control + "/records", headers=values)
                self.assertEqual(response.status_code, 400)
        self.assertEqual(self.requests, [])

    def test_each_credential_binding_must_match_exact_execution(self):
        attacks = ({"job_id": "job-b"}, {"attempt_id": "attempt-b"}, {"component_id": "participant-a"},
                   {"space_id": "space-b"}, {"epoch": 2}, {"certificate_thumbprint": "A" * 43})
        for fields in attacks:
            with self.subTest(fields=fields):
                client = self.client_for(replace(self.settings, exchange_token=self.token("exchange", **fields)))
                response = client.get(self.control + "/records")
                self.assertEqual(response.status_code, 401)
        self.assertEqual(self.requests, [])

    def test_gateway_token_cannot_enter_exchange_or_the_reverse(self):
        for settings, path in ((replace(self.settings, exchange_token=self.token("gateway")), self.control + "/records"),
                               (replace(self.settings, gateway_token=self.token("exchange")), self.transfer + "/content")):
            with self.subTest(path=path):
                response = self.client_for(settings).get(path)
                self.assertEqual(response.status_code, 401)
        self.assertEqual(self.requests, [])

    def test_rotating_token_provider_is_retrieved_on_each_request(self):
        issued = []
        def provider():
            issued.append(len(issued))
            return self.token("exchange", grant_id="grant-" + str(len(issued)))
        client = self.client_for(replace(self.settings, exchange_token=provider))
        self.assertEqual(client.get(self.control + "/records").status_code, 200)
        self.assertEqual(client.get(self.control + "/events").status_code, 200)
        self.assertEqual(len(issued), 2)
        self.assertNotEqual(self.requests[0].headers["Authorization"], self.requests[1].headers["Authorization"])

    def test_boolean_epoch_is_not_equivalent_to_integer_execution_fence(self):
        value = jwt.decode(self.settings.exchange_token, self.public, algorithms=["RS256"],
                           issuer=self.settings.workload_issuer, audience=self.settings.exchange_audience)
        value["epoch"] = True
        token = jwt.encode(value, self.key, algorithm="RS256", headers={"typ": "at+jwt"})
        response = self.client_for(replace(self.settings, exchange_token=token)).get(self.control + "/records")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.requests, [])


    def token_failure_client(self, provider):
        app = create_proxy_app(replace(self.settings, exchange_token=provider, gateway_token=provider), http=self.http)
        received = []
        class CountBodyReceive:
            async def __call__(inner, scope, receive, send):
                if scope["type"] != "http":
                    return await app(scope, receive, send)
                async def observed_receive():
                    received.append(scope["path"])
                    return await receive()
                await app(scope, observed_receive, send)
        client = TestClient(CountBodyReceive())
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        return client, received

    @staticmethod
    def raising_provider(error):
        def provider():
            raise error
        return provider

    def denied_requests(self, client):
        return (
            client.post(self.control + "/records", content=b'{"metadata":{}}'),
            client.put(self.transfer + "/parts/1", content=b"part"),
        )

    def assert_controlled_token_response(self, response, *, status, code):
        self.assertEqual(response.status_code, status, response.text)
        self.assertEqual(response.json(), {"error": {"code": code}})
        returned = response.text + repr(dict(response.headers))
        for secret in ("participant_assignment_not_found", "private-provider-secret", "provider.private.test",
                       self.settings.exchange_token, self.settings.gateway_token):
            self.assertNotIn(secret, returned)

    def test_typed_token_provider_denials_are_controlled_before_body_and_upstream_io(self):
        details = {"token": self.settings.exchange_token, "private_key": "private-provider-secret",
                   "provider_url": "https://provider.private.test/owned?signature=private"}
        with patch.object(self.http, "build_request", wraps=self.http.build_request) as build, \
             patch.object(self.http, "send", wraps=self.http.send) as send:
            for status in (401, 403, 404, 410):
                provider = self.raising_provider(ManagerError(status, "participant_assignment_not_found", details))
                client, received = self.token_failure_client(provider)
                for response in self.denied_requests(client):
                    with self.subTest(provider_status=status, route=response.request.url.path):
                        self.assert_controlled_token_response(response, status=403, code="execution_authority_denied")
                self.assertEqual(received, [])
            build.assert_not_called()
            send.assert_not_called()
        self.assertEqual(self.requests, [])

    def test_token_provider_service_errors_are_bounded_without_detail_disclosure(self):
        cases = ((503, "private_provider_unavailable"), (409, "participant_assignment_not_ready"))
        with patch.object(self.http, "build_request", wraps=self.http.build_request) as build, \
             patch.object(self.http, "send", wraps=self.http.send) as send:
            for status, code in cases:
                provider = self.raising_provider(ManagerError(status, code,
                    {"secret": "private-provider-secret", "token": self.settings.gateway_token}))
                client, received = self.token_failure_client(provider)
                for response in self.denied_requests(client):
                    with self.subTest(provider_status=status, provider_code=code, route=response.request.url.path):
                        self.assert_controlled_token_response(response, status=503, code="execution_service_unavailable")
                        self.assertNotIn(code, response.text)
                self.assertEqual(received, [])
            build.assert_not_called()
            send.assert_not_called()
        self.assertEqual(self.requests, [])

    def test_provider_gateway_error_and_returned_malformed_jwt_keep_existing_mapping(self):
        cases = (
            (self.raising_provider(GatewayError(401, "execution_grant_revoked")), 401, "execution_grant_revoked"),
            (lambda: "not-a-jwt-private-provider-secret", 401, "invalid_execution_credential"),
        )
        with patch.object(self.http, "build_request", wraps=self.http.build_request) as build, \
             patch.object(self.http, "send", wraps=self.http.send) as send:
            for provider, status, code in cases:
                client, received = self.token_failure_client(provider)
                for response in self.denied_requests(client):
                    with self.subTest(code=code, route=response.request.url.path):
                        self.assert_controlled_token_response(response, status=status, code=code)
                self.assertEqual(received, [])
            build.assert_not_called()
            send.assert_not_called()
        self.assertEqual(self.requests, [])

    def test_unexpected_token_provider_errors_remain_visible_and_never_start_io(self):
        failures = (
            ManagerError(422, "unclassified_provider_error"),
            ManagerError(409, "unclassified_provider_conflict"),
            ManagerError(True, "invalid_provider_status"),
            ManagerError(403.0, "invalid_provider_status"),
            RuntimeError("Synthetic unexpected token provider failure"),
            ValueError("Synthetic unexpected token provider value"),
            KeyError("Synthetic unexpected token provider key"),
        )
        with patch.object(self.http, "build_request", wraps=self.http.build_request) as build, \
             patch.object(self.http, "send", wraps=self.http.send) as send:
            for error in failures:
                client, received = self.token_failure_client(self.raising_provider(error))
                for method, path, body in (("POST", self.control + "/records", b'{"metadata":{}}'),
                                           ("PUT", self.transfer + "/parts/1", b"part")):
                    with self.subTest(error=type(error).__name__, route=path), self.assertRaises(type(error)) as caught:
                        client.request(method, path, content=body)
                    self.assertIs(caught.exception, error)
                self.assertEqual(received, [])
            build.assert_not_called()
            send.assert_not_called()
        self.assertEqual(self.requests, [])


class ProxyTransferTests(ProxyFixture):
    def test_fixed_origins_injected_tokens_and_safe_headers(self):
        response = self.client.get(self.control + "/records?limit=2", headers={"Accept": "application/json", "X-Arbitrary": "secret"})
        self.assertEqual(response.status_code, 200, response.text)
        request = self.requests[-1]
        self.assertEqual(str(request.url), "https://exchange.example.test" + self.control + "/records?limit=2")
        self.assertEqual(request.headers["Authorization"], "Bearer " + self.settings.exchange_token)
        self.assertNotIn("X-Arbitrary", request.headers)
        self.assertNotIn("Set-Cookie", response.headers)
        self.assertNotIn("X-Secret", response.headers)
        response = self.client.put(self.transfer + "/parts/1", content=b"part")
        self.assertEqual(response.status_code, 204)
        request = self.requests[-1]
        self.assertEqual(request.url.host, "gateway.example.test")
        self.assertEqual(request.headers["Authorization"], "Bearer " + self.settings.gateway_token)
        self.assertEqual(request.content, b"part")

    def test_control_descriptor_cannot_leak_provider_urls_or_credentials(self):
        for payload in ({"url": "https://origin.example/secret?signature=private"},
                        {"access_key": "secret"}, {"secret_key": "secret"}):
            with self.subTest(payload=payload):
                self.origin_handler = lambda request, payload=payload: httpx.Response(200, json=payload)
                response = self.client.get(self.control + "/records")
                self.assertEqual(response.status_code, 502)
                self.assertNotIn("signature=private", response.text)
                self.assertNotIn("origin.example", response.text)

    def test_bounded_request_and_control_response(self):
        response = self.client.post(self.control + "/records", content=b"x" * 129)
        self.assertEqual(response.status_code, 413)
        response = self.client.put(self.transfer + "/parts/1", content=b"x" * 33)
        self.assertEqual(response.status_code, 413)
        self.assertEqual(self.requests, [])
        self.origin_handler = lambda request: httpx.Response(200, content=b"x" * 129)
        response = self.client.get(self.control + "/records")
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["error"]["code"], "control_response_too_large")

    def test_range_and_head_are_forwarded_to_fixed_gateway(self):
        def handler(request):
            self.requests.append(request)
            return httpx.Response(206, headers={"Content-Range": "bytes 2-5/8", "Content-Length": "4"},
                                  content=b"cdef" if request.method == "GET" else b"")
        self.origin_handler = handler
        for method in ("GET", "HEAD"):
            with self.subTest(method=method):
                response = self.client.request(method, self.transfer + "/content", headers={"Range": "bytes=2-5"})
                self.assertEqual(response.status_code, 206)
                self.assertEqual(response.headers["Content-Range"], "bytes 2-5/8")
                self.assertEqual(response.content, b"cdef" if method == "GET" else b"")
                self.assertEqual(self.requests[-1].headers["Range"], "bytes=2-5")
                self.assertEqual(self.requests[-1].url.host, "gateway.example.test")

    def test_redirect_is_denied_and_sensitive_origin_headers_removed(self):
        self.origin_handler = lambda request: httpx.Response(307, headers={"Location": "https://foreign.example/secret"})
        response = self.client.get(self.control + "/records")
        self.assertEqual(response.status_code, 502)
        self.assertNotIn("Location", response.headers)
        self.assertNotIn("foreign.example", response.text)


class ProxyConfigurationTests(ProxyFixture):
    def test_non_https_and_credentialed_origins_rejected(self):
        for endpoint in ("http://exchange.example.test", "https://user:password@exchange.example.test",
                         "https://exchange.example.test/path", "https://exchange.example.test?url=foreign"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                replace(self.settings, exchange_endpoint=endpoint).validate()

    def test_certificate_binding_does_not_accept_an_unrelated_thumbprint(self):
        with self.assertRaises(ValueError):
            replace(self.settings, binding=replace(self.binding, certificate_thumbprint="A" * 43)).validate()


if __name__ == "__main__":
    unittest.main()
