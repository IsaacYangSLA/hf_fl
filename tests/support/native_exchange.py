"""Real native Go Exchange resources for Python application integration tests.

HF2L_EXCHANGE_GO_BINARY selects an operator-built native executable. Tests own a
SQLite database, signing keys, verified HTTPS listener, background Go worker,
and versioned bucket. Moto supplies only the S3 provider when no external test
storage endpoint is selected; it never implements an HF2L server.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import ipaddress
import logging
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
import uuid

_REQUIRED = ("boto3", "moto", "jwt", "httpx", "cryptography", "hf2l_exchange")
_binary_setting = os.environ.get("HF2L_EXCHANGE_GO_BINARY", "")
_binary = Path(_binary_setting) if _binary_setting else None
exchange_available = bool(_binary and _binary.is_absolute() and _binary.is_file()
                          and os.access(_binary, os.X_OK)
                          and all(importlib.util.find_spec(name) is not None for name in _REQUIRED))
if not exchange_available and os.environ.get("EXCHANGE_REQUIRE_TESTS") == "1":
    raise ImportError("Native Exchange integration requires HF2L_EXCHANGE_GO_BINARY and the SDK/test dependencies")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ExchangeTestCase(unittest.TestCase):
    """Exercise SDK/application behavior against actual Go HTTPS and worker."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import boto3
        from botocore.config import Config
        cls.storage_endpoint = os.environ.get("EXCHANGE_TEST_S3_ENDPOINT")
        cls.moto = None
        if not cls.storage_endpoint:
            from moto.server import ThreadedMotoServer
            logging.getLogger("werkzeug").setLevel(logging.ERROR)
            port = free_port()
            cls.moto = ThreadedMotoServer(ip_address="127.0.0.1", port=port, verbose=False)
            cls.moto.start()
            cls.storage_endpoint = f"http://127.0.0.1:{port}"
        cls.storage_access_key = os.environ.get("EXCHANGE_TEST_S3_ACCESS_KEY", "testing")
        cls.storage_secret_key = os.environ.get("EXCHANGE_TEST_S3_SECRET_KEY", "testing")
        cls.s3 = boto3.client("s3", endpoint_url=cls.storage_endpoint,
            region_name="us-east-1", aws_access_key_id=cls.storage_access_key,
            aws_secret_access_key=cls.storage_secret_key,
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"}))

    @classmethod
    def tearDownClass(cls):
        try:
            if cls.moto is not None:
                cls.moto.stop()
        finally:
            super().tearDownClass()

    def setUp(self):
        super().setUp()
        import httpx
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        self.temp = tempfile.TemporaryDirectory(prefix="hf2l-native-exchange-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()
        os.chmod(self.directory, 0o700)
        self.database_path = self.directory / "exchange.db"
        self.database_url = "sqlite:///" + str(self.database_path)
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.issuer = "https://identity.example.test"
        self.audience = "exchange-test"
        self.bucket = "native-exchange-test-" + uuid.uuid4().hex
        self.s3.create_bucket(Bucket=self.bucket)
        self.addCleanup(self.cleanup_bucket)
        self.s3.put_bucket_versioning(Bucket=self.bucket,
            VersioningConfiguration={"Status": "Enabled"})
        self._certificates()
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith("EXCHANGE_") and k not in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")}
        self.env.update({
            "EXCHANGE_DATABASE_URL": self.database_url,
            "EXCHANGE_ISSUER": self.issuer,
            "EXCHANGE_AUDIENCE": self.audience,
            "EXCHANGE_ADMIN_SUBJECT": "owner",
            "EXCHANGE_JWT_PUBLIC_KEY": self.public_key,
            "EXCHANGE_S3_ENDPOINT": self.storage_endpoint,
            "EXCHANGE_S3_BUCKET": self.bucket,
            "EXCHANGE_S3_REGION": "us-east-1",
            "EXCHANGE_S3_ACCESS_KEY": self.storage_access_key,
            "EXCHANGE_S3_SECRET_KEY": self.storage_secret_key,
            "EXCHANGE_ALLOW_LOCAL_HTTP": "true",
            "EXCHANGE_PART_SIZE": str(5 * 1024 * 1024),
            "EXCHANGE_GRANT_SECONDS": "5",
            "EXCHANGE_WORKER_POLL_SECONDS": "1",
            "EXCHANGE_WORKER_RECOVER_AFTER": "1",
        })
        self.run_native("init-db")
        port = free_port()
        self.endpoint = f"https://127.0.0.1:{port}"
        self.client = httpx.Client(base_url=self.endpoint,
            verify=ssl.create_default_context(cafile=str(self.ca_file)),
            trust_env=False, timeout=30)
        self.addCleanup(self.client.close)
        self.api_process = self.start_native("api", "serve", "--host", "127.0.0.1",
            "--port", str(port), "--tls-cert", str(self.certificate_file),
            "--tls-key", str(self.key_file))
        self.worker_process = self.start_native("worker", "worker")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.api_process.poll() is not None:
                raise RuntimeError("Native Exchange did not start: " + self.native_log("api"))
            try:
                if self.client.get("/ready").status_code == 200:
                    break
            except httpx.TransportError:
                pass
            time.sleep(0.05)
        else:
            raise RuntimeError("Native Exchange readiness timed out: " + self.native_log("api"))
        self.space = self.new_space("integration")
        self.prefix = f"/v2/spaces/{self.space['id']}"
        self.member("alice", ["reader", "contributor"])
        self.member("bob", ["reader", "contributor"])
        self.member("publisher", ["publisher"])
        self.member("administrator", ["admin"])
        self.revision = self.register_type("document")

    def _certificates(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        now = datetime.now(timezone.utc)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "HF2L test authority")])
        ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
            .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(ca_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
        self.ca_file = self.directory / "ca.crt"
        self.certificate_file = self.directory / "server.crt"
        self.key_file = self.directory / "server.key"
        self.ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        self.certificate_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        self.key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        os.chmod(self.ca_file, 0o644)
        os.chmod(self.certificate_file, 0o644)
        os.chmod(self.key_file, 0o600)

    def run_native(self, *args):
        result = subprocess.run([str(_binary), *args], env=self.env, text=True,
                                capture_output=True, timeout=30)
        if result.returncode != 0:
            raise RuntimeError("Native Exchange maintenance failed: " + result.stderr)
        return result

    def worker_once(self):
        return self.run_native("worker", "--once")

    def start_native(self, name, *args):
        log = (self.directory / (name + ".log")).open("w")
        self.addCleanup(log.close)
        process = subprocess.Popen([str(_binary), *args], env=self.env,
            stdout=log, stderr=subprocess.STDOUT)
        self.addCleanup(self.stop_process, process)
        return process

    @staticmethod
    def stop_process(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)

    def native_log(self, name):
        return (self.directory / (name + ".log")).read_text()

    def cleanup_bucket(self):
        for page in self.s3.get_paginator("list_multipart_uploads").paginate(Bucket=self.bucket):
            for upload in page.get("Uploads", []):
                self.s3.abort_multipart_upload(Bucket=self.bucket, Key=upload["Key"], UploadId=upload["UploadId"])
        for page in self.s3.get_paginator("list_object_versions").paginate(Bucket=self.bucket):
            for value in page.get("Versions", []) + page.get("DeleteMarkers", []):
                self.s3.delete_object(Bucket=self.bucket, Key=value["Key"], VersionId=value["VersionId"])
        self.s3.delete_bucket(Bucket=self.bucket)

    def auth(self, subject="owner", **overrides):
        import jwt
        claims = {"iss": self.issuer, "aud": self.audience, "sub": subject,
            "exp": int(time.time()) + 3600, "iat": int(time.time()), "scope": "exchange"}
        claims.update(overrides)
        return {"Authorization": "Bearer " + jwt.encode(claims, self.private_key,
            algorithm="RS256", headers={"typ": "at+jwt"})}

    @staticmethod
    def operation_key(value=None):
        return {"Idempotency-Key": value or uuid.uuid4().hex}

    @staticmethod
    def code(response):
        return response.json().get("error", {}).get("code")

    def request(self, method, path, subject="owner", *, key=None, headers=None, **kwargs):
        auth = self.auth(subject)
        auth.update(headers or {})
        if method.lower() in {"post", "put"}:
            auth.update(self.operation_key(key))
        return self.client.request(method, path, headers=auth, **kwargs)

    def new_space(self, name="test", profile="generic.v1", **limits):
        result = self.request("POST", "/v2/spaces", json={"name": name, "profile": profile, **limits})
        self.assertEqual(result.status_code, 201, result.text)
        return result.json()

    def member(self, subject, roles, bindings=None, space=None):
        from hf2l_exchange.domain import principal_id
        space_id = space or self.space["id"]
        result = self.request("PUT", f"/v2/spaces/{space_id}/members/" + principal_id(self.issuer, subject),
            json={"subject": subject, "roles": roles, "bindings": bindings or {}})
        self.assertEqual(result.status_code, 200, result.text)
        return result.json()

    def register_type(self, kind, schema=None, visibility="shared", publish_roles=None, space=None):
        result = self.request("POST", f"/v2/spaces/{space or self.space['id']}/types/{kind}/revisions", json={
            "schema": schema or {"type": "object"}, "visibility": visibility,
            "publish_roles": publish_roles or ["contributor", "publisher"]})
        self.assertEqual(result.status_code, 201, result.text)
        return result.json()
