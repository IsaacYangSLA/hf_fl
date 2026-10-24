"""Owned native Go HTTPS/PostgreSQL/S3 fixtures; Python is only a client/operator."""
from __future__ import annotations
import contextlib
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import uuid

import boto3
from botocore.config import Config as BotoConfig
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import httpx
import jwt
import psycopg
from psycopg import sql

from hf2l_exchange.client import ExchangeClient
from hf2l_exchange.domain import principal_id
from hf2l_exchange.client_types import ExchangeError


def private_json(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        json.dump(value, target, sort_keys=True, indent=2, allow_nan=False)
    path.chmod(0o600)


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _url(base, schema, reference=False):
    parts = urlsplit(base.replace("postgresql+psycopg://", "postgresql://"))
    query = dict(parse_qsl(parts.query))
    query["options"] = (query.get("options", "") + " -csearch_path=" + schema).strip()
    result = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
    return result.replace("postgresql://", "postgresql+psycopg://", 1) if reference else result


def _key(path):
    value = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.write_bytes(value.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    path.chmod(0o600)
    return value


def _public(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _ca(root, name):
    key = _key(root / (name + ".key"))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256()))
    path = root / (name + ".crt")
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    path.chmod(0o644)
    return key, certificate, path


def _leaf(root, name, ca_key, ca_cert, server):
    import ipaddress
    key_path = root / (name + ".key")
    key = _key(key_path)
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca_cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=True, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True))
    if server:
        builder = builder.add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
    path = root / (name + ".crt")
    path.write_bytes(builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
    path.chmod(0o644)
    return path, key_path


class GoFixture:
    """One explicitly owned schema, versioned bucket, identity and native process set."""

    def __init__(self, config, name="sdk", root=None):
        self.config = dict(config)
        raw_base = Path(config["root"]).expanduser()
        if not raw_base.is_absolute() or raw_base.is_symlink():
            raise ValueError("fixture_root_must_be_absolute_private_directory")
        raw_base.mkdir(mode=0o700, parents=True, exist_ok=True)
        base = raw_base.resolve()
        info = base.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("fixture_root_must_be_owned_and_private")
        self.root = Path(root) if root is not None else base / (name + "-" + uuid.uuid4().hex)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.root.chmod(0o700)
        self.schema = "go_exchange_" + uuid.uuid4().hex
        self.bucket = "go-exchange-" + uuid.uuid4().hex
        self.binary = Path(config["go_binary"]).resolve()
        self.binary_hash = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.processes, self.log_files, self.spaces, self.clients = {}, [], [], []
        self.initialized = self.preserved = self.cleaned = False
        self._schema_created = self._bucket_created = False
        self.owner_subject = "owner"
        self.issuer = "https://identity.example.invalid/native-exchange"
        self.workload_issuer = "https://workloads.example.invalid/native-exchange"
        self.owner_principal = self.principal(self.owner_subject)
        database = load_json(config["database_config"])
        self.storage = load_json(config["storage_config"])
        self.base_database_url = database["databases"][config.get("database_key", "sdk")]
        self.base_database_url = self.base_database_url.replace("postgresql+psycopg://", "postgresql://")
        self.database_url = _url(self.base_database_url, self.schema)
        self.reference_database_url = _url(self.base_database_url, self.schema, True)
        self.s3 = boto3.client("s3", endpoint_url=self.storage["endpoint"],
            aws_access_key_id=self.storage["access_key"], aws_secret_access_key=self.storage["secret_key"],
            region_name=self.storage.get("region", "us-east-1"),
            config=BotoConfig(signature_version="s3v4", connect_timeout=3, read_timeout=20,
                              retries={"mode": "standard", "max_attempts": 3}))
        self.endpoint = "https://localhost:" + str(_port())
        self.managed_endpoint = "https://localhost:" + str(_port())
        self.gateway_endpoint = "https://localhost:" + str(_port())
        self.backend_secret = secrets.token_urlsafe(48)
        self.env = {}

    def principal(self, subject):
        return principal_id(self.issuer, subject)

    def token(self, subject="owner", *, scope="exchange", audience="exchange", lifetime=3600):
        now = int(time.time())
        return jwt.encode({"iss": self.issuer, "aud": audience, "sub": subject, "scope": scope,
                           "iat": now - 1, "exp": now + lifetime},
                          self.human_key, algorithm="RS256", headers={"typ": "at+jwt"})

    def workload_token(self, subject, claims=None, *, audience="exchange-managed", scope="exchange"):
        now = int(time.time())
        body = {"iss": self.workload_issuer, "aud": audience, "sub": subject,
                "scope": scope, "iat": now - 1, "exp": now + 240}
        body.update(claims or {})
        return jwt.encode(body, self.workload_key, algorithm="RS256", headers={"typ": "at+jwt"})

    def _receipt(self):
        private_json(self.root / "fixture.json", {
            "schema": self.schema, "bucket": self.bucket, "binary": str(self.binary),
            "binary_sha256": self.binary_hash, "endpoint": self.endpoint,
            "managed_endpoint": self.managed_endpoint, "gateway_endpoint": self.gateway_endpoint,
            "database_url": self.database_url, "reference_database_url": self.reference_database_url,
            "spaces": self.spaces, "processes": {name: proc.pid for name, proc in self.processes.items()},
            "preserved": self.preserved})
        private_json(self.root / "environment.json", self.env)

    def setup(self, initialize=True, start=True):
        self.human_key = _key(self.root / "human-jwt.key")
        self.workload_key = _key(self.root / "workload-jwt.key")
        ca_key, ca_cert, self.server_ca = _ca(self.root, "service-ca")
        self.server_certificate, self.server_key = _leaf(self.root, "exchange-service", ca_key, ca_cert, True)
        key, cert, self.backend_client_ca = _ca(self.root, "backend-client-ca")
        self.backend_client_certificate, self.backend_client_key = _leaf(
            self.root, "exchange-backend-client", key, cert, False)
        with psycopg.connect(self.base_database_url, autocommit=True) as connection:
            connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(self.schema)))
        self._schema_created = True
        self.s3.create_bucket(Bucket=self.bucket)
        self._bucket_created = True
        self.s3.put_bucket_versioning(Bucket=self.bucket, VersioningConfiguration={"Status": "Enabled"})
        self.env = os.environ.copy()
        self.env.update({
            "EXCHANGE_DATABASE_URL": self.database_url,
            "EXCHANGE_POOL_SIZE": "2", "EXCHANGE_POOL_OVERFLOW": "2",
            "EXCHANGE_POOL_TIMEOUT": "10", "EXCHANGE_POOL_RECYCLE": "1800",
            "EXCHANGE_ISSUER": self.issuer, "EXCHANGE_AUDIENCE": "exchange",
            "EXCHANGE_JWT_PUBLIC_KEY": _public(self.human_key), "EXCHANGE_JWKS_URL": "",
            "EXCHANGE_ADMIN_SUBJECT": self.owner_subject,
            "EXCHANGE_WORKLOAD_ISSUER": self.workload_issuer,
            "EXCHANGE_WORKLOAD_AUDIENCE": "exchange-managed",
            "EXCHANGE_WORKLOAD_PUBLIC_KEY": _public(self.workload_key),
            "EXCHANGE_TRUSTED_BACKEND_SECRET": self.backend_secret,
            "EXCHANGE_PROVISIONING_PRINCIPAL_IDS": self.owner_principal,
            "EXCHANGE_DOWNLOAD_BROKER_PRINCIPAL_IDS": "",
            "EXCHANGE_S3_ENDPOINT": self.storage["endpoint"],
            "EXCHANGE_S3_PUBLIC_ENDPOINT": self.storage["endpoint"],
            "EXCHANGE_S3_BUCKET": self.bucket, "EXCHANGE_S3_PREFIX": "sdk/",
            "EXCHANGE_S3_REGION": self.storage.get("region", "us-east-1"),
            "EXCHANGE_S3_ACCESS_KEY": self.storage["access_key"],
            "EXCHANGE_S3_SECRET_KEY": self.storage["secret_key"],
            "EXCHANGE_S3_SESSION_TOKEN": "", "EXCHANGE_ALLOW_LOCAL_HTTP": "true",
            "EXCHANGE_PART_SIZE": str(5 * 1024 * 1024),
            "EXCHANGE_GRANT_SECONDS": "300", "EXCHANGE_WORKER_POLL_SECONDS": "1"})
        self._receipt()
        if initialize:
            self.run_cli("init-db")
            self.initialized = True
        if start:
            self.start_services()
        return self

    def _assert_binary(self):
        if hashlib.sha256(self.binary.read_bytes()).hexdigest() != self.binary_hash:
            raise RuntimeError("native_binary_identity_changed")

    def run_cli(self, command, *args, timeout=60):
        self._assert_binary()
        result = subprocess.run([str(self.binary), command, *map(str, args)], env=self.env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if result.returncode:
            (self.root / ("cli-" + command + "-failure.log")).write_bytes(
                result.stdout[-16384:] + result.stderr[-16384:])
            raise RuntimeError("native_command_failed:" + command)
        return result

    def _spawn(self, name, command, endpoint=None, private=False):
        self._assert_binary()
        args = [str(self.binary), command]
        if endpoint:
            args += ["--host", "127.0.0.1", "--port", str(urlsplit(endpoint).port),
                     "--tls-cert", str(self.server_certificate), "--tls-key", str(self.server_key)]
            if private:
                args += ["--client-ca", str(self.backend_client_ca)]
        log = (self.root / (name + ".log")).open("ab")
        self.log_files.append(log)
        process = subprocess.Popen(args, env=self.env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        self.processes[name] = process
        self._receipt()
        return process

    def start_services(self):
        if any(proc.poll() is None for proc in self.processes.values()):
            raise RuntimeError("fixture_services_already_running")
        self.processes = {}
        self._spawn("public", "serve", self.endpoint)
        self._spawn("managed", "serve-managed", self.managed_endpoint)
        self._spawn("gateway", "serve-gateway-backend", self.gateway_endpoint, private=True)
        self._spawn("worker", "worker")
        context = ssl.create_default_context(cafile=str(self.server_ca))
        with httpx.Client(verify=context, trust_env=False, timeout=3) as probe, self.backend_http() as backend:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if any(p.poll() is not None for p in self.processes.values()):
                    raise RuntimeError("native_fixture_process_exited")
                try:
                    public = probe.get(self.endpoint + "/ready")
                    managed = probe.get(self.managed_endpoint + "/health")
                    private = backend.get(self.gateway_endpoint + "/")
                    if public.status_code == 200 and managed.status_code == 200 and private.status_code in (404, 405):
                        self._receipt()
                        return
                except httpx.HTTPError:
                    pass
                time.sleep(.1)
        raise RuntimeError("native_fixture_readiness_timeout")

    def stop_services(self):
        for client in self.clients:
            with contextlib.suppress(Exception):
                client.http.close()
                client.transfers.http.close()
        self.clients = []
        for process in self.processes.values():
            if process.poll() is None:
                process.terminate()
        for process in self.processes.values():
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for log in self.log_files:
            log.close()
        self.log_files = []
        self._receipt()

    def restart_services(self):
        self.stop_services()
        self.start_services()

    def client(self, subject="owner"):
        context = ssl.create_default_context(cafile=str(self.server_ca))
        control = httpx.Client(verify=context, trust_env=False, follow_redirects=False, timeout=30)
        transfer = httpx.Client(verify=context, trust_env=False, follow_redirects=False, timeout=60)
        client = ExchangeClient(self.endpoint, lambda: self.token(subject), http=control,
                                transfer=transfer, retries=1, allow_local_http=True)
        self.clients.append(client)
        return client

    def backend_http(self):
        context = ssl.create_default_context(cafile=str(self.server_ca))
        context.load_cert_chain(str(self.backend_client_certificate), str(self.backend_client_key))
        return httpx.Client(verify=context, trust_env=False, follow_redirects=False, timeout=30)

    def track_space(self, sid):
        if sid not in self.spaces:
            self.spaces.append(sid)
            self._receipt()
        return sid

    def query(self, statement, parameters=()):
        with psycopg.connect(self.database_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute(statement, parameters)
                return cursor.fetchall()

    def storage_inventory(self):
        uploads, versions, markers = [], [], []
        for page in self.s3.get_paginator("list_multipart_uploads").paginate(Bucket=self.bucket):
            uploads.extend(page.get("Uploads", []))
        for page in self.s3.get_paginator("list_object_versions").paginate(Bucket=self.bucket):
            versions.extend(page.get("Versions", []))
            markers.extend(page.get("DeleteMarkers", []))
        return {"multipart_uploads": len(uploads), "object_versions": len(versions),
                "delete_markers": len(markers)}

    def cleanup(self, timeout=430):
        """Retire with authenticated APIs and wait for independent physical proof.

        Failure preserves the real namespace, authority and owned process receipts.
        Accepted retirement or elapsed worker leases are never cleanup proof.
        """
        if self.cleaned:
            return
        try:
            populated = False
            if self._schema_created:
                populated = bool(self.query("SELECT 1 FROM information_schema.tables WHERE table_schema=%s",
                                            (self.schema,)))
            if populated and self._bucket_created:
                required = {"public", "managed", "gateway", "worker"}
                if set(self.processes) != required or any(
                        proc.poll() is not None for proc in self.processes.values()):
                    self.stop_services()
                    self.start_services()
                owner = self.client()
                for (space,) in self.query("SELECT id FROM v2_spaces ORDER BY id"):
                    self.track_space(space)
                    try:
                        existing = owner.get_managed_space(space)
                    except ExchangeError as exc:
                        if exc.status != 404 or exc.code != "managed_space_not_found":
                            raise
                        job = "fixture-" + space
                        owner.manage_space(space, job_id=job, idempotency_key="fixture-cleanup-manage")
                    else:
                        job = existing.job_id
                    owner.retire_managed_space(space, job_id=job, idempotency_key="fixture-cleanup-retire")
                deadline = time.monotonic() + timeout
                while True:
                    states = [owner.get_managed_space(space) for space in self.spaces]
                    accounting = self.query("SELECT allocated,reclaiming FROM v2_spaces")
                    inventory = self.storage_inventory()
                    if (not any(state.cleanup_pending for state in states)
                            and all(a == 0 and r == 0 for a, r in accounting)
                            and not any(inventory.values())):
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError("owned_cleanup_deadline")
                    private_json(self.root / "cleanup-progress.json", {
                        "pending_spaces": sum(state.cleanup_pending for state in states),
                        "allocated_bytes": sum(a for a, _ in accounting),
                        "reclaiming_bytes": sum(r for _, r in accounting), **inventory})
                    time.sleep(.25)
            self.stop_services()
            final = self.storage_inventory() if self._bucket_created else {}
            if any(final.values()):
                raise RuntimeError("owned_storage_not_empty")
            if self._bucket_created:
                self.s3.delete_bucket(Bucket=self.bucket)
                self._bucket_created = False
            if self._schema_created:
                with psycopg.connect(self.base_database_url, autocommit=True) as connection:
                    connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(self.schema)))
                self._schema_created = False
            self.cleaned = True
            private_json(self.root / "cleanup.json", {
                "server_stopped": all(p.poll() is not None for p in self.processes.values()),
                "bucket_removed": not self._bucket_created, "schema_removed": not self._schema_created,
                "physical_storage": final, "errors": []})
        except Exception as exc:
            self.preserved = True
            self._receipt()
            private_json(self.root / "cleanup.json", {
                "preserved_for_authenticated_recovery": True,
                "bucket_removed": not self._bucket_created, "schema_removed": not self._schema_created,
                "errors": [type(exc).__name__]})
            raise
