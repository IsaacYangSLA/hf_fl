"""Owned real PostgreSQL/S3/HTTPS fixture for the Go managed transfer test.

The parent passes private resource JSON files explicitly. This helper creates
only a unique database schema, versioned bucket, private keys and child HTTPS
server, and removes its owned resources on normal or signalled shutdown.
No manager package is imported. Ready/control files are private, not stdout.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import socket
import ssl
import subprocess
import sys
import time
import uuid
from urllib.parse import quote

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "packages" / "exchange" / "src"))

import boto3
from botocore.config import Config
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import httpx
import jwt
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url

from hf2l_exchange.application import Service
from hf2l_exchange.auth import Authenticator, backend_assertion_headers
from hf2l_exchange.config import AuthSettings, DatabaseSettings, Settings, StorageSettings
from hf2l_exchange.domain import principal_id
from hf2l_exchange.migrations import initialize
from hf2l_exchange.models import Blob, Space, TransferAttempt
from hf2l_exchange.storage import S3BlobStore
from hf2l_exchange.transfers import TransferService
from hf2l_exchange.worker import tick


def private_json(path, value):
    temp = path.with_name("." + path.name + "." + uuid.uuid4().hex)
    with os.fdopen(os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        json.dump(value, stream, separators=(",", ":"), allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def private_file(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(value)


def resource_json(path):
    path = Path(path).resolve(strict=True)
    if path.stat().st_mode & 0o077 or path.stat().st_uid != os.geteuid() or path.stat().st_nlink != 1:
        raise ValueError("Private resource configuration required")
    if path.stat().st_size > 65536:
        raise ValueError("Resource configuration exceeds bound")
    return json.loads(path.read_text())


def native_exchange_binary():
    """Resolve an explicit executable; never fall back after native mode is set."""
    value = os.environ.get("HF2L_EXCHANGE_GO_BINARY")
    if value is None:
        return None
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("Native Exchange binary must be absolute")
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or not info.st_mode & stat.S_IXUSR
            or info.st_mode & 0o022):
        raise ValueError("Native Exchange binary must be a protected regular executable")
    return str(path)


class Fixture:
    issuer = "https://human.integration.example.test"
    workload_issuer = "https://workload.integration.example.test"
    gateway_audience = "hf2l-transfer"

    def __init__(self, runtime, database_config, storage_config):
        self.root = runtime
        self.database_config = database_config
        self.storage_config = storage_config
        self.child = None
        self.service = None
        self.admin = None
        self.s3 = None
        self.bucket_created = False
        self.schema_created = False
        self.receipt_record = None
        self.stop = False
        self.backend_log = None
        self.native_binary = native_exchange_binary()
        self.native_children = []
        self.native_logs = []
        self.native_ready = False
        self.public_endpoint = None
        self.managed_endpoint = None
        self.schema = "go_gateway_" + uuid.uuid4().hex
        self.bucket = "go-gateway-" + uuid.uuid4().hex
        self.secret = uuid.uuid4().hex + uuid.uuid4().hex
        self.owner_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.workload_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def server_command(self, mode, port, *, client_ca=False):
        if self.native_binary:
            command = [self.native_binary, mode, "--host", "127.0.0.1", "--port", str(port),
                       "--tls-cert", str(self.server_cert), "--tls-key", str(self.server_key)]
            if client_ca:
                command.extend(["--client-ca", str(self.ca_file)])
            return command
        factories = {"serve": "hf2l_exchange.api:create_app",
                     "serve-managed": "hf2l_exchange.api:create_managed_app",
                     "serve-gateway-backend": "hf2l_exchange.gateway_api:create_gateway_backend_app"}
        command = [sys.executable, "-m", "uvicorn", factories[mode], "--factory",
                   "--host", "127.0.0.1", "--port", str(port),
                   "--ssl-certfile", str(self.server_cert), "--ssl-keyfile", str(self.server_key),
                   "--no-access-log", "--log-level", "warning"]
        if client_ca:
            command.extend(["--ssl-ca-certs", str(self.ca_file), "--ssl-cert-reqs", "2"])
        return command

    def native_children_alive(self):
        return all(child.poll() is None for child in self.native_children)

    def start_native_services(self, environment):
        for name, mode, client_ca in (("ordinary", "serve", False),
                                      ("managed", "serve-managed", True)):
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            log = os.fdopen(os.open(self.root / (name + ".log"),
                                  os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")
            self.native_logs.append(log)
            child = subprocess.Popen(self.server_command(mode, port, client_ca=client_ca),
                                     env=environment, stdin=subprocess.DEVNULL,
                                     stdout=log, stderr=log)
            self.native_children.append(child)
            endpoint = "https://127.0.0.1:" + str(port)
            context = ssl.create_default_context(cafile=str(self.ca_file))
            if client_ca:
                context.load_cert_chain(str(self.backend_cert), str(self.backend_key))
            with httpx.Client(verify=context, trust_env=False, timeout=2) as client:
                deadline = time.monotonic() + 30
                while True:
                    if child.poll() is not None:
                        raise RuntimeError("Native Exchange API stopped")
                    try:
                        if client.get(endpoint + "/ready").status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    if time.monotonic() > deadline:
                        raise TimeoutError("Native Exchange readiness failed")
                    time.sleep(.05)
            setattr(self, "public_endpoint" if name == "ordinary" else "managed_endpoint", endpoint)
        log = os.fdopen(os.open(self.root / "worker.log",
                              os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")
        self.native_logs.append(log)
        self.native_children.append(subprocess.Popen([self.native_binary, "worker"], env=environment,
                                    stdin=subprocess.DEVNULL, stdout=log, stderr=log))
        self.native_ready = True

    def native_request(self, method, suffix, body=None, *, key=None, managed=False):
        path = "/v2/spaces/" + quote(self.space_id, safe="") + suffix
        authorization = self.owner_authorization
        context = ssl.create_default_context(cafile=str(self.ca_file))
        headers = {}
        endpoint = self.public_endpoint
        if managed:
            now = int(time.time())
            token = jwt.encode({"iss": self.workload_issuer, "aud": "exchange-managed",
                "sub": "component-a", "iat": now - 1, "exp": now + 240, "scope": "exchange",
                "jti": self.grant["grant_id"], "space_id": self.space_id,
                "job_id": "job-integration", "attempt_id": "attempt-integration",
                "component_id": "component-a", "epoch": 1,
                "cnf": {"x5t#S256": self.client_thumbprint}}, self.workload_key,
                algorithm="RS256", headers={"typ": "at+jwt"})
            authorization = "Bearer " + token
            endpoint = self.managed_endpoint
            context.load_cert_chain(str(self.backend_cert), str(self.backend_key))
            headers.update(backend_assertion_headers(self.secret, method, path,
                                                    authorization, self.client_thumbprint))
        headers["Authorization"] = authorization
        if key:
            headers["Idempotency-Key"] = key
        with httpx.Client(verify=context, trust_env=False, timeout=15) as client:
            response = client.request(method, endpoint + path, headers=headers, json=body)
            if not 200 <= response.status_code < 300:
                raise RuntimeError("Native Exchange control request failed: " + str(response.status_code))
            return response.json()

    def runtime_receipt(self):
        if not self.native_binary:
            return {"implementation": "python", "reference_helpers": "fixture setup and oracle"}
        return {"implementation": "go", "binary_sha256": hashlib.sha256(
            Path(self.native_binary).read_bytes()).hexdigest(),
            "reference_helpers": "DDL/S3/retained seed setup and read-only oracle",
            "native_commands": ["serve", "serve-managed", "serve-gateway-backend", "worker"]}

    @staticmethod
    def public(key):
        return key.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def cert(self, name, *, server=False):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(self.ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(self.now - timedelta(minutes=1))
            .not_valid_after(self.now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True,
                 content_commitment=False, data_encipherment=False, key_agreement=False,
                 key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server
                                                 else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False))
        if server:
            builder = builder.add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        certificate = builder.sign(self.ca_key, hashes.SHA256())
        cert_path, key_path = self.root / (name + ".pem"), self.root / (name + ".key")
        private_file(cert_path, certificate.public_bytes(serialization.Encoding.PEM))
        private_file(key_path, key.private_bytes(serialization.Encoding.PEM,
                     serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        thumb = base64.urlsafe_b64encode(hashlib.sha256(
            certificate.public_bytes(serialization.Encoding.DER)).digest()).rstrip(b"=").decode()
        return cert_path, key_path, thumb

    def human_token(self):
        now = int(time.time())
        return jwt.encode({"iss": self.issuer, "aud": "exchange", "sub": "provisioner",
             "iat": now - 1, "exp": now + 3600, "scope": "exchange"}, self.owner_key,
             algorithm="RS256", headers={"typ": "at+jwt"})

    def workload_token(self, *, seconds=240):
        now = int(time.time())
        expiry = now + seconds
        return jwt.encode({"iss": self.workload_issuer, "aud": self.gateway_audience,
             "sub": "component-a", "iat": now - 1, "exp": expiry, "scope": "transfer",
             "jti": self.grant["grant_id"], "space_id": self.space_id, "job_id": "job-integration",
             "attempt_id": "attempt-integration", "component_id": "component-a", "epoch": 1,
             "cnf": {"x5t#S256": self.client_thumbprint}}, self.workload_key,
             algorithm="RS256", headers={"typ": "at+jwt"}), expiry

    def start(self):
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        (self.root / "commands").mkdir(mode=0o700)
        (self.root / "replies").mkdir(mode=0o700)
        self.now = datetime.now(timezone.utc)
        ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Go Gateway Integration CA")])
        self.ca = (x509.CertificateBuilder().subject_name(ca_subject).issuer_name(ca_subject)
            .public_key(self.ca_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(self.now - timedelta(minutes=1)).not_valid_after(self.now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False,
                content_commitment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()), critical=False)
            .sign(self.ca_key, hashes.SHA256()))
        self.ca_file = self.root / "ca.pem"
        private_file(self.ca_file, self.ca.public_bytes(serialization.Encoding.PEM))
        self.server_cert, self.server_key, _ = self.cert("server", server=True)
        self.backend_cert, self.backend_key, self.backend_thumbprint = self.cert("backend-client")
        self.client_cert, self.client_key, self.client_thumbprint = self.cert("workload-client")
        self.foreign_cert, self.foreign_key, _ = self.cert("other-client")
        url = make_url(self.database_config["databases"]["exchange"])
        if url.get_backend_name() not in {"postgres", "postgresql"}:
            raise ValueError("Actual PostgreSQL required")
        url = url.set(drivername="postgresql+psycopg")
        self.admin = create_engine(url)
        with self.admin.begin() as connection:
            connection.execute(text('CREATE SCHEMA "' + self.schema + '"'))
        self.schema_created = True
        database_url = url.update_query_dict({"options": "-csearch_path=" + self.schema}).render_as_string(
            hide_password=False)
        cfg = self.storage_config
        self.s3 = boto3.client("s3", endpoint_url=cfg["endpoint"], region_name=cfg.get("region", "us-east-1"),
            aws_access_key_id=cfg["access_key"], aws_secret_access_key=cfg["secret_key"],
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, proxies={},
                          connect_timeout=3, read_timeout=5, retries={"max_attempts": 1}))
        self.s3.create_bucket(Bucket=self.bucket)
        self.bucket_created = True
        self.s3.put_bucket_versioning(Bucket=self.bucket, VersioningConfiguration={"Status": "Enabled"})
        auth = AuthSettings(issuer=self.issuer, audience="exchange", public_key=self.public(self.owner_key),
            admin_subject="provisioner", workload_issuer=self.workload_issuer,
            workload_audience="exchange-managed", workload_public_key=self.public(self.workload_key),
            trusted_backend_secret=self.secret,
            provisioning_principal_ids=(principal_id(self.issuer, "provisioner"),))
        storage = StorageSettings(endpoint=cfg["endpoint"], bucket=self.bucket,
            access_key=cfg["access_key"], secret_key=cfg["secret_key"],
            region=cfg.get("region", "us-east-1"), prefix="gateway-integration/",
            part_size=5 * 1024 * 1024, allow_local_http=cfg["endpoint"].startswith("http://"))
        self.settings = Settings(database=DatabaseSettings(url=database_url), auth=auth, storage=storage)
        self.service = Service(self.settings)
        initialize(self.service.engine)
        self.storage = S3BlobStore(storage, client=self.s3)
        self.storage.check()
        self.transfers = TransferService(self.service, self.storage)
        self.owner_authorization = "Bearer " + self.human_token()
        self.owner = Authenticator(auth).authenticate(self.owner_authorization)
        self.space_id = self.service.create_space(self.owner, {"name": "Go gateway integration",
                             "quota_bytes": 64 * 1024**2, "principal_quota_bytes": 64 * 1024**2},
                             "fixture-space")["id"]
        component = principal_id(self.workload_issuer, "component-a")
        self.service.put_member(self.owner, self.space_id, component, {"subject": "component-a",
                               "roles": ["reader", "contributor", "publisher"], "bindings": {}})
        self.revision = self.service.register_type(self.owner, self.space_id, "document",
                                  {"schema": {"type": "object"}}, "fixture-type")
        self.service.enable_managed_space(self.owner, self.space_id,
                                         {"job_id": "job-integration"}, "fixture-managed")
        self.grant = self.service.create_workload_grant(self.owner, self.space_id,
            {"subject": "component-a", "job_id": "job-integration", "attempt_id": "attempt-integration",
             "component_id": "component-a", "epoch": 1, "expires_at": int(time.time()) + 3600,
             "certificate_thumbprint": self.client_thumbprint,
             "roles": ["reader", "contributor", "publisher"], "bindings": {}}, "fixture-grant")
        self.token, self.expires = self.workload_token()
        self.workload = Authenticator(replace(auth, workload_audience=self.gateway_audience)).authenticate(
            "Bearer " + self.token, managed=True, certificate_thumbprint=self.client_thumbprint)
        content = bytes(range(256)) * ((5 * 1024 * 1024 + 12345) // 256 + 1)
        content = content[:5 * 1024 * 1024 + 12345]
        self.data = self.root / "content.bin"
        private_file(self.data, content)
        self.digest = hashlib.sha256(content).hexdigest()
        self.record = self.create_upload("fixture-model", len(content), self.digest)
        self.attachment = self.record["attachments"][0]["id"]
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.endpoint = "https://127.0.0.1:" + str(port)
        environment = os.environ.copy()
        for key in tuple(environment):
            if key.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"} or key.startswith("EXCHANGE_"):
                environment.pop(key)
        environment.update({"PYTHONPATH": str(REPO / "packages" / "exchange" / "src"),
            "PYTHONDONTWRITEBYTECODE": "1", "AWS_EC2_METADATA_DISABLED": "true",
            "EXCHANGE_DATABASE_URL": database_url, "EXCHANGE_ISSUER": self.issuer,
            "EXCHANGE_AUDIENCE": "exchange", "EXCHANGE_ADMIN_SUBJECT": "provisioner",
            "EXCHANGE_JWT_PUBLIC_KEY": self.public(self.owner_key),
            "EXCHANGE_WORKLOAD_ISSUER": self.workload_issuer, "EXCHANGE_WORKLOAD_AUDIENCE": "exchange-managed",
            "EXCHANGE_WORKLOAD_PUBLIC_KEY": self.public(self.workload_key),
            "EXCHANGE_TRUSTED_BACKEND_SECRET": self.secret,
            "EXCHANGE_PROVISIONING_PRINCIPAL_IDS": principal_id(self.issuer, "provisioner"),
            "EXCHANGE_DOWNLOAD_BROKER_PRINCIPAL_IDS": principal_id(self.issuer, "provisioner"),
            "EXCHANGE_S3_ENDPOINT": storage.endpoint, "EXCHANGE_S3_BUCKET": storage.bucket,
            "EXCHANGE_S3_ACCESS_KEY": storage.access_key, "EXCHANGE_S3_SECRET_KEY": storage.secret_key,
            "EXCHANGE_S3_REGION": storage.region, "EXCHANGE_S3_PREFIX": storage.prefix,
            "EXCHANGE_PART_SIZE": str(storage.part_size),
            "EXCHANGE_ALLOW_LOCAL_HTTP": "true" if storage.allow_local_http else "false"})
        self.backend_log = os.fdopen(os.open(self.root / "backend.log",
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")
        command = self.server_command("serve-gateway-backend", port, client_ca=True)
        self.child = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL,
                                      stdout=self.backend_log, stderr=self.backend_log)
        context = ssl.create_default_context(cafile=str(self.ca_file))
        context.load_cert_chain(str(self.backend_cert), str(self.backend_key))
        with httpx.Client(verify=context, trust_env=False, timeout=3) as client:
            deadline = time.monotonic() + 30
            while True:
                if self.child.poll() is not None:
                    raise RuntimeError("Private backend process stopped")
                target = "/internal/transfers/v1/storage/check"
                headers = {"Authorization": self.owner_authorization}
                headers.update(backend_assertion_headers(self.secret, "POST", target,
                               self.owner_authorization, self.backend_thumbprint))
                try:
                    result = client.post(self.endpoint + target, headers=headers, json={})
                    if result.status_code == 200 and result.json().get("checked") is True:
                        break
                except httpx.HTTPError:
                    pass
                if time.monotonic() > deadline:
                    raise TimeoutError("Private HTTPS backend readiness failed")
                time.sleep(0.05)
        if self.native_binary:
            self.start_native_services(environment)
        private_json(self.root / "ready.json", {"exchange_runtime": self.runtime_receipt(),
            "backend_endpoint": self.endpoint,
            "ca_file": str(self.ca_file), "server_certificate": str(self.server_cert),
            "server_key": str(self.server_key), "backend_certificate": str(self.backend_cert),
            "backend_key": str(self.backend_key), "backend_thumbprint": self.backend_thumbprint,
            "client_certificate": str(self.client_cert), "client_key": str(self.client_key),
            "client_thumbprint": self.client_thumbprint, "foreign_certificate": str(self.foreign_cert),
            "foreign_key": str(self.foreign_key), "workload_issuer": self.workload_issuer,
            "workload_public_key": self.public(self.workload_key), "gateway_audience": self.gateway_audience,
            "token": self.token, "expires_at": self.expires, "backend_secret": self.secret,
            "provisioner_authorization": self.owner_authorization, "space_id": self.space_id,
            "record_id": self.record["id"], "attachment_id": self.attachment,
            "data_file": str(self.data), "size": len(content), "sha256": self.digest,
            "part_size": storage.part_size, "s3_endpoint": storage.endpoint,
            "s3_bucket": storage.bucket, "s3_prefix": storage.prefix.strip("/"), "s3_region": storage.region,
            "launch": (["go-exchange", "serve-gateway-backend", "--tls-cert", "<owned-server-certificate>",
                       "--tls-key", "<owned-server-key>", "--client-ca", "<owned-client-ca>"]
                       if self.native_binary else
                       ["python", "-m", "uvicorn", "hf2l_exchange.gateway_api:create_gateway_backend_app",
                       "--factory", "--ssl-certfile", "<owned-server-certificate>",
                       "--ssl-keyfile", "<owned-server-key>", "--ssl-ca-certs", "<owned-client-ca>",
                       "--ssl-cert-reqs", "2"])})

    def create_upload(self, key, size, digest):
        if self.native_ready:
            record = self.native_request("POST", "/records", {"kind": "document",
                "schema_revision_id": self.revision["id"], "metadata": {},
                "attachments": [{"path": "model.safetensors", "size": size, "sha256": digest}]},
                key=key, managed=True)
            self.native_request("POST", "/records/" + quote(record["id"], safe="") +
                "/attachments/" + quote(record["attachments"][0]["id"], safe="") + "/upload",
                managed=True)
            return record
        record = self.service.create_record(self.workload, self.space_id, {
            "kind": "document", "schema_revision_id": self.revision["id"], "metadata": {},
            "attachments": [{"path": "model.safetensors", "size": size, "sha256": digest}]}, key)
        self.transfers.initiate(self.space_id, record["id"], record["attachments"][0]["id"], self.workload)
        return record

    def inspect(self):
        with self.service.sessions() as session:
            attempts = session.scalars(select(TransferAttempt)).all()
            space = session.get(Space, self.space_id)
            return {"mutations": sum(len(item.mutation_tokens or []) for item in attempts),
                    "allocated": space.allocated, "reclaiming": space.reclaiming,
                    "attempts": len(attempts)}

    def action(self, name):
        if name == "publish":
            if self.native_ready:
                self.native_request("POST", "/records/" + quote(self.record["id"], safe="") +
                    "/attachments/" + quote(self.attachment, safe="") + "/complete", managed=True)
            else:
                self.transfers.complete(self.space_id, self.record["id"], self.attachment, self.workload)
            for _ in range(600 if self.native_ready else 30):
                if not self.native_ready:
                    tick(self.transfers)
                elif not self.native_children_alive():
                    raise RuntimeError("Native Exchange worker stopped")
                with self.service.sessions() as session:
                    blob = session.get(Blob, self.attachment)
                    if blob.state == "verified":
                        break
                time.sleep(0.05)
            else:
                raise TimeoutError("Object verification failed")
            if self.native_ready:
                published = self.native_request("POST", "/records/" +
                    quote(self.record["id"], safe="") + "/publish", key="fixture-publish", managed=True)
            else:
                published = self.service.publish_record(self.workload, self.space_id,
                                                        self.record["id"], "fixture-publish")
            return {"record_id": published["id"], **self.inspect()}
        if name == "receipt_upload":
            self.receipt_record = self.create_upload("fixture-receipt", 3, hashlib.sha256(b"abc").hexdigest())
            token, expiry = self.workload_token(seconds=4)
            return {"token": token, "expires_at": expiry, "record_id": self.receipt_record["id"],
                    "attachment_id": self.receipt_record["attachments"][0]["id"]}
        if name == "revoke":
            if self.native_ready:
                if self.receipt_record:
                    self.native_request("DELETE", "/records/" + quote(self.receipt_record["id"], safe=""))
                self.native_request("POST", "/workload-grants/revoke",
                    {"attempt_id": "attempt-integration"}, key="fixture-revoke")
            else:
                if self.receipt_record:
                    self.service.withdraw_record(self.owner, self.space_id, self.receipt_record["id"])
                self.service.revoke_workload_grants(self.owner, self.space_id,
                                   {"attempt_id": "attempt-integration"}, "fixture-revoke")
            return self.inspect()
        if name == "inspect":
            return self.inspect()
        if name == "stop":
            self.stop = True
            return {"stopping": True}
        raise ValueError("Unknown fixture action")

    def run(self):
        while not self.stop:
            if self.child.poll() is not None or not self.native_children_alive():
                raise RuntimeError("Private backend or native Exchange process stopped")
            for path in sorted((self.root / "commands").glob("*.json")):
                if not re.fullmatch(r"[a-f0-9]{32}\.json", path.name):
                    raise ValueError("Invalid fixture command file")
                body = resource_json(path)
                path.unlink()
                try:
                    if set(body) != {"action"}:
                        raise ValueError("Invalid fixture command")
                    response = {"ok": True, "result": self.action(body["action"])}
                except Exception as exc:
                    response = {"ok": False, "error": type(exc).__name__}
                private_json(self.root / "replies" / path.name, response)
            time.sleep(0.02)

    def close(self):
        for child in reversed(self.native_children):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
        for log in self.native_logs:
            log.close()
        result = {"server_stopped": self.child is None, "bucket_removed": not self.bucket_created,
                  "schema_removed": not self.schema_created, "errors": []}
        if self.child:
            try:
                self.child.terminate()
                try:
                    self.child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.child.kill()
                    self.child.wait(timeout=5)
                result["server_stopped"] = all(child.poll() is not None
                                               for child in self.native_children)
            except Exception as exc:
                result["errors"].append(type(exc).__name__)
        if self.backend_log:
            self.backend_log.close()
        if self.bucket_created:
            try:
                for page in self.s3.get_paginator("list_multipart_uploads").paginate(Bucket=self.bucket):
                    for upload in page.get("Uploads", []):
                        self.s3.abort_multipart_upload(Bucket=self.bucket, Key=upload["Key"],
                                                      UploadId=upload["UploadId"])
                for page in self.s3.get_paginator("list_object_versions").paginate(Bucket=self.bucket):
                    for item in page.get("Versions", []) + page.get("DeleteMarkers", []):
                        self.s3.delete_object(Bucket=self.bucket, Key=item["Key"], VersionId=item["VersionId"])
                self.s3.delete_bucket(Bucket=self.bucket)
                result["bucket_removed"] = True
            except Exception as exc:
                result["errors"].append(type(exc).__name__)
        if self.service:
            self.service.engine.dispose()
        if self.schema_created:
            try:
                with self.admin.begin() as connection:
                    connection.execute(text('DROP SCHEMA "' + self.schema + '" CASCADE'))
                result["schema_removed"] = True
            except Exception as exc:
                result["errors"].append(type(exc).__name__)
        if self.admin:
            self.admin.dispose()
        if self.s3:
            self.s3.close()
        private_json(self.root / "cleanup.json", result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--database-config", required=True)
    parser.add_argument("--storage-config", required=True)
    args = parser.parse_args()
    root = Path(args.runtime).resolve()
    fixture = Fixture(root, resource_json(args.database_config), resource_json(args.storage_config))
    def stop(*_):
        fixture.stop = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        fixture.start()
        fixture.run()
    except Exception as exc:
        private_json(root / "failure.json", {"error": type(exc).__name__})
        return 1
    finally:
        fixture.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
