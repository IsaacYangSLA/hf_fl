"""Trusted download broker using only a fixed structured gateway protocol."""
from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any
import time
import httpx

from .gateway import GatewayError, identifier, service_endpoint, tls_context


class GatewayClient:
    def __init__(self, endpoint, token, *, certificate, key, ca_file, max_bytes=1024 ** 4, http=None):
        self.endpoint = service_endpoint(endpoint)
        self.token, self.max_bytes = token, max_bytes
        self.http = http or httpx.AsyncClient(verify=tls_context(ca_file, certificate, key),
                                              trust_env=False, follow_redirects=False, timeout=300)
        self._owned = http is None
        if max_bytes <= 0:
            raise ValueError("Positive broker byte limit is required")

    async def close(self):
        if self._owned:
            await self.http.aclose()

    @asynccontextmanager
    async def download(self, space_id, record_id, attachment_id):
        for value in (space_id, record_id, attachment_id):
            identifier(value)
        target = f"/transfers/v1/spaces/{space_id}/records/{record_id}/attachments/{attachment_id}/content"
        token = self.token() if callable(self.token) else self.token
        async with self.http.stream("GET", self.endpoint + target, headers={"Authorization": "Bearer " + token}) as response:
            if response.status_code != 200:
                raise GatewayError(response.status_code if response.status_code < 500 else 503, "artifact_unavailable")
            try:
                size = int(response.headers["content-length"])
            except (KeyError, ValueError):
                raise GatewayError(502, "invalid_artifact_descriptor") from None
            if not 0 <= size <= self.max_bytes:
                raise GatewayError(413, "artifact_too_large")
            yield response


@dataclass
class ArtifactDownload:
    name: str
    size: int
    content_type: str
    chunks: Any


class ArtifactBroker:
    """Recheck manager ACL before opening a job-bound gateway download.

    resolver(actor,job_id,artifact_id) MUST return only the current authorized
    artifact row, including space_id/record_id/attachment_id/name/size; the
    resolver is the manager application's ACL-checking method. client_for_job
    returns a gateway client with a live job-bound grant, never a human token.
    """

    def __init__(self, resolver, client_for_job):
        self.resolver, self.client_for_job = resolver, client_for_job

    @asynccontextmanager
    async def open_authorized(self, actor, job_id, artifact_id):
        from starlette.concurrency import run_in_threadpool
        metadata = await run_in_threadpool(self.resolver, actor, job_id, artifact_id)
        client = self.client_for_job(job_id)
        async with client.download(metadata["space_id"], metadata["record_id"], metadata["attachment_id"]) as response:
            size = int(response.headers["content-length"])
            if size != metadata["size"]:
                raise GatewayError(409, "artifact_size_mismatch")

            async def chunks():
                count = 0
                async for chunk in response.aiter_bytes(65536):
                    count += len(chunk)
                    if count > size:
                        raise GatewayError(502, "artifact_size_mismatch")
                    yield chunk
                if count != size:
                    raise GatewayError(502, "artifact_size_mismatch")
            name = str(metadata.get("name", "artifact.bin"))
            if any(c in name for c in "/\\\r\n\x00"):
                name = "artifact.bin"
            yield ArtifactDownload(name, size, "application/octet-stream", chunks())


class ManagedArtifactBroker:
    """Fresh manager ACLs plus job-bound, read-only gateway grants or confined local files."""

    def __init__(self, manager, database, exchange, broker, root, *,
                 client_ca_certificate, client_ca_key, gateway_endpoint, service_ca_file,
                 max_bytes=1024 ** 4, executor_root=None, remote_executor=None):
        from pathlib import Path
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        self.manager, self.database, self.exchange, self.broker = manager, database, exchange, broker
        from .resources import private_root
        self.root = private_root(root)
        self.gateway_endpoint = service_endpoint(gateway_endpoint)
        self.service_ca_file, self.max_bytes = service_ca_file, max_bytes
        self.executor_root = Path(executor_root).absolute() if executor_root is not None else None
        self.remote_executor = remote_executor
        self.ca_certificate = x509.load_pem_x509_certificate(Path(client_ca_certificate).read_bytes())
        self.ca_key = serialization.load_pem_private_key(Path(client_ca_key).read_bytes(), password=None)
        if self.ca_certificate.public_key().public_numbers() != self.ca_key.public_key().public_numbers():
            raise ValueError("Artifact broker certificate authority key mismatch")
        if not self.ca_certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("Artifact broker certificate authority must be a CA")

    @staticmethod
    def attempt_id(job_id):
        import hashlib
        return "artifact-" + hashlib.sha256(job_id.encode()).hexdigest()[:40]

    def _resource(self, job_id, resource_id):
        from .models import ProvisioningResource
        with self.database.transaction(immediate=False) as session:
            resource = session.get(ProvisioningResource, resource_id)
            if (resource is None or resource.job_id != job_id or resource.deleted_at is not None
                    or resource.state in {"deleted", "cleanup_pending"} or not resource.external_id):
                raise GatewayError(404, "artifact_unavailable")
            ownership = resource.ownership_json
            if ownership.get("job_id") != job_id:
                raise GatewayError(404, "artifact_unavailable")
            return resource.external_id, dict(resource.details_json), resource.kind, dict(ownership)

    def _space_owned(self, job_id, space_id):
        from sqlalchemy import select
        from .models import ProvisioningResource
        with self.database.transaction(immediate=False) as session:
            resource = session.scalar(select(ProvisioningResource).where(
                ProvisioningResource.job_id == job_id, ProvisioningResource.kind == "exchange_space",
                ProvisioningResource.external_id == space_id, ProvisioningResource.deleted_at.is_(None)))
            if resource is None or resource.state in {"deleted", "cleanup_pending"} or resource.ownership_json.get("job_id") != job_id:
                raise GatewayError(404, "artifact_unavailable")

    def _certificate(self, job_id, request_id):
        import os
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        current = self.root
        for name in (".artifact-broker", identifier(job_id), identifier(request_id)):
            current = current / name
            if current.is_symlink():
                raise GatewayError(503, "unsafe_broker_storage")
            current.mkdir(mode=0o700, exist_ok=True)
        now = datetime.now(timezone.utc)
        expiry = min(now + timedelta(seconds=300), self.ca_certificate.not_valid_after_utc)
        if expiry <= now + timedelta(seconds=30):
            raise GatewayError(503, "broker_certificate_authority_expired")
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        try:
            issuer_identifier = self.ca_certificate.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier).value
        except x509.ExtensionNotFound:
            issuer_identifier = x509.SubjectKeyIdentifier.from_public_key(
                self.ca_certificate.public_key())
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hf2l-artifact-broker")]))
                .issuer_name(self.ca_certificate.subject).public_key(private.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(seconds=30))
                .not_valid_after(expiry)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                    private.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    issuer_identifier), critical=False)
                .add_extension(x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .sign(self.ca_key, hashes.SHA256()))
        certificate, key = current / "cert.pem", current / "key.pem"
        for path, content in (
                (certificate, cert.public_bytes(serialization.Encoding.PEM)),
                (key, private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(content)
        from .gateway import certificate_thumbprint
        return current, str(certificate), str(key), certificate_thumbprint(cert.public_bytes(serialization.Encoding.DER)), expiry.timestamp()

    def _grant(self, job_id, space_id, request_id, thumbprint, expiry):
        from .broker import stable_workload_subject, stable_workload_principal
        from .resources import ResourceLedger
        self._space_owned(job_id, space_id)
        component = "download-broker"
        subject = stable_workload_subject(job_id, component)
        principal = stable_workload_principal(self.broker.settings.workload_issuer, job_id, component)
        self.exchange.set_member(space_id, principal, ["reader"], subject=subject, bindings={})
        body = {"subject": subject, "job_id": job_id, "attempt_id": self.attempt_id(job_id),
                "component_id": component, "epoch": 1, "certificate_thumbprint": thumbprint,
                "expires_at": expiry, "roles": ["reader"], "bindings": {}}
        grant = self.exchange.request("POST", self.exchange.path(space_id, "/workload-grants"),
                                      body=body, headers={"Idempotency-Key": "artifact-" + request_id})
        if grant.get("principal_id") != principal or grant.get("job_id") != job_id or grant.get("space_id") != space_id:
            raise GatewayError(503, "invalid_broker_grant")
        ResourceLedger(self.database).own(job_id=job_id, attempt_id=None, component_id=component,
            kind="workload_grant", external_id=grant["grant_id"], details=dict(grant), retained=True)
        return grant

    def revoke(self, job_id):
        from sqlalchemy import select
        from .models import ProvisioningResource
        with self.database.transaction(immediate=False) as session:
            resource = session.scalar(select(ProvisioningResource).where(
                ProvisioningResource.job_id == job_id, ProvisioningResource.kind == "exchange_space",
                ProvisioningResource.deleted_at.is_(None)))
            if resource is None:
                return True
            space_id = resource.external_id
        result = self.exchange.request("POST", self.exchange.path(space_id, "/workload-grants/revoke"),
            body={"attempt_id": self.attempt_id(job_id)}, headers={"Idempotency-Key": "artifact-revoke-" + job_id})
        return result.get("attempt_id") == self.attempt_id(job_id) and bool(result.get("revoked_at"))

    @asynccontextmanager
    async def _exchange_download(self, metadata, locator, job_id):
        import uuid
        from starlette.concurrency import run_in_threadpool
        request_id = uuid.uuid4().hex
        directory, cert, key, thumbprint, expiry = await run_in_threadpool(self._certificate, job_id, request_id)
        client = None
        try:
            grant = await run_in_threadpool(self._grant, job_id, locator["space_id"], request_id, thumbprint, expiry)
            def token():
                remaining = int(expiry - time.time())
                if remaining < 1:
                    raise GatewayError(401, "broker_grant_expired")
                return self.broker.issue_workload(job_id=job_id, attempt_id=self.attempt_id(job_id),
                    component_id="download-broker", space_id=locator["space_id"], grant_id=grant["grant_id"],
                    epoch=1, certificate_thumbprint=thumbprint, audience="gateway", ttl_seconds=min(300, remaining))
            client = GatewayClient(self.gateway_endpoint, token, certificate=cert, key=key,
                                   ca_file=self.service_ca_file, max_bytes=self.max_bytes)
            async with client.download(locator["space_id"], locator["record_id"], locator["attachment_id"]) as response:
                expected = metadata["size_bytes"]
                if int(response.headers["content-length"]) != expected or response.headers.get("x-content-sha256") != metadata["sha256"]:
                    raise GatewayError(409, "artifact_descriptor_mismatch")
                async def chunks():
                    import hashlib
                    digest, count = hashlib.sha256(), 0
                    async for chunk in response.aiter_bytes(65536):
                        count += len(chunk)
                        if count > expected:
                            raise GatewayError(502, "artifact_descriptor_mismatch")
                        digest.update(chunk)
                        yield chunk
                    if count != expected or digest.hexdigest() != metadata["sha256"]:
                        raise GatewayError(502, "artifact_integrity_failed")
                yield chunks()
        finally:
            if client:
                await client.close()
            # Keys belong to this broker invocation and are never retained in a job volume.
            from pathlib import Path
            Path(cert).unlink(missing_ok=True)
            Path(key).unlink(missing_ok=True)
            directory.rmdir()

    @asynccontextmanager
    async def _local_download(self, metadata, locator, job_id):
        import hashlib
        import os
        import stat
        from pathlib import Path
        from starlette.concurrency import run_in_threadpool
        from .collection import SafeCollector, CollectionError
        directory, details, kind, ownership = await run_in_threadpool(self._resource, job_id, locator["resource_id"])
        expected_root = self.root / job_id
        root = Path(directory).absolute()
        if kind == "retained_artifact_root":
            from .executor import ExecutionIdentity
            try:
                identity = ExecutionIdentity(job_id, ownership["attempt_id"], ownership["component_id"], ownership["epoch"])
            except (KeyError, ValueError, RuntimeError):
                raise GatewayError(404, "artifact_unavailable") from None
            allowed = ({self.executor_root / identity.key / "retained" / name for name in ("state", "runtime")}
                       if self.executor_root is not None else set())
            canonical_log_root = self.executor_root / identity.key / "retained" if self.executor_root is not None else None
            prefixed_component_file = locator["relative_path"].startswith(("state/", "runtime/"))
            if root not in allowed and not (root == canonical_log_root and prefixed_component_file):
                raise GatewayError(404, "artifact_unavailable")
        elif (root != expected_root and expected_root not in root.parents) or kind not in {
                "artifact_directory", "component_state", "component_volume", "source", "source_snapshot", "source_directory", "owned_directory"}:
            raise GatewayError(404, "artifact_unavailable")
        collector, descriptor, parent = None, -1, -1
        try:
            collector = SafeCollector(root, max_file_bytes=max(1, metadata["size_bytes"]),
                                       max_total_bytes=max(1, metadata["size_bytes"]))
            parts = collector._parts(locator["relative_path"])
            parent = os.dup(collector._root_fd)
            for part in parts[:-1]:
                next_fd = collector._directory(part, parent)
                os.close(parent)
                parent = next_fd
            descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            before = os.fstat(descriptor)
            collector._validate_file(before)
            if before.st_size != metadata["size_bytes"]:
                raise GatewayError(409, "artifact_descriptor_mismatch")
            async def chunks():
                count, digest = 0, hashlib.sha256()
                while True:
                    chunk = await run_in_threadpool(os.read, descriptor, 65536)
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > before.st_size:
                        raise GatewayError(502, "artifact_changed")
                    digest.update(chunk)
                    yield chunk
                after = os.fstat(descriptor)
                if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                        after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or (
                        count != before.st_size or digest.hexdigest() != metadata["sha256"]):
                    raise GatewayError(502, "artifact_changed")
            yield chunks()
        except (OSError, CollectionError):
            raise GatewayError(404, "artifact_unavailable") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if parent >= 0:
                os.close(parent)
            if collector:
                collector.close()



    @asynccontextmanager
    async def _remote_download(self, metadata, locator, job_id):
        import hashlib
        from urllib.parse import urlsplit
        from starlette.concurrency import run_in_threadpool
        from .executor import ExecutionIdentity
        directory, details, kind, ownership = await run_in_threadpool(self._resource, job_id, locator["resource_id"])
        try:
            identity = ExecutionIdentity(job_id, ownership["attempt_id"], ownership["component_id"], ownership["epoch"])
            parsed = urlsplit(directory)
        except (KeyError, ValueError, RuntimeError):
            raise GatewayError(404, "artifact_unavailable") from None
        if (kind != "retained_artifact_root" or parsed.scheme != "hf2l-node" or not parsed.netloc
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path != "/" + identity.key or self.remote_executor is None
                or details.get("node_id") != parsed.netloc):
            raise GatewayError(404, "artifact_unavailable")
        # Route resolution is trusted deployment inventory and assignment history,
        # never a host or URL chosen from an artifact locator.
        route = await run_in_threadpool(self.remote_executor.route, identity, None)
        node_id = route.get("node_id") if isinstance(route, dict) else getattr(route, "node_id", None)
        if node_id != parsed.netloc:
            raise GatewayError(404, "artifact_unavailable")
        if metadata["size_bytes"] > 64 * 1024 * 1024:
            raise GatewayError(413, "remote_artifact_too_large")
        content = await run_in_threadpool(self.remote_executor.read_artifact, identity,
                                         locator["relative_path"], max_bytes=max(1, metadata["size_bytes"]))
        if len(content) != metadata["size_bytes"] or hashlib.sha256(content).hexdigest() != metadata["sha256"]:
            raise GatewayError(409, "artifact_integrity_failed")
        async def chunks():
            for offset in range(0, len(content), 65536):
                yield content[offset:offset + 65536]
        yield chunks()

    @asynccontextmanager
    async def open_authorized(self, actor, job_id, artifact_id):
        from starlette.concurrency import run_in_threadpool
        from .domain import ArtifactLocator
        metadata = await run_in_threadpool(self.manager.artifact_storage, actor, job_id, artifact_id)
        if type(metadata.get("size_bytes")) is not int or not 0 <= metadata["size_bytes"] <= self.max_bytes:
            raise GatewayError(413, "artifact_too_large")
        try:
            parsed = ArtifactLocator.model_validate(metadata["locator"])
            locator = parsed.model_dump(exclude_none=True)
        except (ValueError, KeyError):
            raise GatewayError(404, "artifact_unavailable") from None
        if locator["kind"] == "exchange":
            context = self._exchange_download(metadata, locator, job_id)
        else:
            directory, _, _, _ = await run_in_threadpool(self._resource, job_id, locator["resource_id"])
            context = (self._remote_download(metadata, locator, job_id) if directory.startswith("hf2l-node://")
                       else self._local_download(metadata, locator, job_id))
        name = str(metadata.get("name", "artifact.bin"))
        if any(c in name for c in "/\\\r\n\x00"):
            name = "artifact.bin"
        async with context as chunks:
            yield ArtifactDownload(name, metadata["size_bytes"], "application/octet-stream", chunks)
