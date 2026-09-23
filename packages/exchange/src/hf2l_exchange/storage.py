"""Typed blob storage port and versioned S3 multipart implementation.

Provider locators are private server values. This module has no persistence or
HTTP framework dependency; application code sees normalized storage failures.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from math import ceil
from typing import Mapping, Protocol
from urllib.parse import parse_qs, urlsplit
from datetime import datetime, timezone
import uuid
import threading


@dataclass(frozen=True)
class UploadHandle:
    id: str
    key: str


@dataclass(frozen=True)
class UploadedPart:
    number: int
    etag: str
    size: int


@dataclass(frozen=True)
class StoredObject:
    key: str
    version: str


@dataclass(frozen=True)
class Verification:
    size: int
    sha256: str


@dataclass(frozen=True)
class TransferGrant:
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    expires_at: float = 0


class StorageFailure(RuntimeError):
    """Provider-independent failure safe to persist and return to callers."""

    def __init__(self, code: str, retryable: bool = False, uncertain: bool = False):
        self.code, self.retryable, self.uncertain = code, retryable, uncertain
        super().__init__(code)


class BlobStore(Protocol):
    protocol: str
    def check(self) -> None: ...
    def start(self, key: str) -> UploadHandle: ...
    def parts(self, handle: UploadHandle) -> list[UploadedPart]: ...
    def upload_grant(self, handle: UploadHandle, number: int, size: int,
                     expires_at: float, seconds: int) -> TransferGrant: ...
    def complete(self, handle: UploadHandle, size: int, part_size: int) -> StoredObject: ...
    def verify(self, stored: StoredObject, size: int, digest: str) -> Verification: ...
    def download_grant(self, stored: StoredObject, expires_at: float, seconds: int) -> TransferGrant: ...
    def cleanup(self, key: str) -> None: ...


def part_size_for(number: int, size: int, part_size: int) -> int:
    count = max(1, ceil(size / part_size))
    if not 1 <= number <= count:
        raise StorageFailure("invalid_part_number")
    return min(part_size, size - (number - 1) * part_size)


def _normalize(exc: Exception) -> StorageFailure:
    # botocore is an optional server dependency, imported only when used.
    from botocore.exceptions import ClientError
    if isinstance(exc, StorageFailure):
        return exc
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {}).get("Code", "")
        if error in {"NoSuchKey", "NoSuchUpload", "NoSuchVersion", "404", "NotFound"}:
            return StorageFailure("storage_missing")
        if error in {"AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch", "403"}:
            return StorageFailure("storage_misconfigured", retryable=True)
        if error in {"InvalidPart", "InvalidPartOrder", "EntityTooSmall"}:
            return StorageFailure("invalid_parts")
    return StorageFailure("storage_unavailable", retryable=True, uncertain=True)


def _provider_operation(fn):
    def normalized(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except StorageFailure:
            raise
        except Exception as exc:
            raise _normalize(exc) from exc
    normalized.__name__ = fn.__name__
    return normalized


class S3BlobStore:
    """S3 multipart-v1: opaque server keys and exact version downloads."""

    protocol = "s3-multipart-v1"

    def __init__(self, settings, client=None, signer=None):
        self.settings, self.bucket = settings, settings.bucket
        self._client, self._signer = client, signer
        self._client_lock = threading.RLock()

    def _make_client(self, endpoint):
        import boto3
        from botocore.config import Config
        options = {"region_name": self.settings.region,
                   "config": Config(signature_version="s3v4", connect_timeout=3, read_timeout=30,
                                    retries={"mode": "standard", "max_attempts": 3})}
        if self.settings.access_key:
            options.update(aws_access_key_id=self.settings.access_key,
                           aws_secret_access_key=self.settings.secret_key,
                           aws_session_token=getattr(self.settings, "session_token", "") or None)
        return boto3.session.Session().client("s3", endpoint_url=endpoint or None, **options)

    @property
    def client(self):
        with self._client_lock:
            if self._client is None:
                self._client = self._make_client(self.settings.endpoint)
            return self._client

    @property
    def signer(self):
        with self._client_lock:
            if self._signer is None:
                self._signer = (self._make_client(self.settings.public_endpoint)
                                if self.settings.public_endpoint else self.client)
            return self._signer

    @staticmethod
    def _version(result) -> str:
        version = result.get("VersionId")
        if not version or version == "null":
            raise StorageFailure("storage_misconfigured", retryable=True)
        return version

    def _grant(self, operation, params, method, expires_at, seconds, headers=None):
        url = self.signer.generate_presigned_url(operation, Params=params, ExpiresIn=seconds, HttpMethod=method)
        parsed = urlsplit(url)
        local = parsed.hostname in {"localhost", "127.0.0.1", "::1", "testserver"}
        if parsed.scheme != "https" and not (parsed.scheme == "http" and local and self.settings.allow_local_http):
            raise StorageFailure("insecure_storage_grant")
        query = parse_qs(parsed.query)
        # SigV4 uses the signer's wall clock; persist the actual signed expiry.
        if "X-Amz-Date" in query and "X-Amz-Expires" in query:
            signed_at = datetime.strptime(query["X-Amz-Date"][0], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
            expires_at = signed_at.timestamp() + int(query["X-Amz-Expires"][0])
        return TransferGrant(url, headers or {}, expires_at)

    @_provider_operation
    def check(self) -> None:
        if self.client.get_bucket_versioning(Bucket=self.bucket).get("Status") != "Enabled":
            raise StorageFailure("storage_misconfigured", retryable=True)
        # A missing-object HEAD probes permission to distinguish absence from denial.
        self._recover_object("readiness/" + uuid.uuid4().hex)

    @_provider_operation
    def start(self, key: str) -> UploadHandle:
        result = self.client.create_multipart_upload(Bucket=self.bucket, Key=key)
        return UploadHandle(result["UploadId"], key)

    @_provider_operation
    def parts(self, handle: UploadHandle) -> list[UploadedPart]:
        parts = []
        for page in self.client.get_paginator("list_parts").paginate(
                Bucket=self.bucket, Key=handle.key, UploadId=handle.id):
            parts.extend(UploadedPart(int(p["PartNumber"]), p["ETag"], int(p["Size"]))
                         for p in page.get("Parts", []))
        return sorted(parts, key=lambda p: p.number)

    @_provider_operation
    def upload_grant(self, handle: UploadHandle, number: int, size: int,
                     expires_at: float, seconds: int) -> TransferGrant:
        return self._grant("upload_part", {"Bucket": self.bucket, "Key": handle.key,
            "UploadId": handle.id, "PartNumber": number, "ContentLength": size}, "PUT",
            expires_at, seconds, {"Content-Length": str(size)})

    def _recover_object(self, key):
        from botocore.exceptions import ClientError
        try:
            result = self.client.head_object(Bucket=self.bucket, Key=key)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in {"404", "NoSuchKey", "NotFound"}:
                return None
            raise
        return StoredObject(key, self._version(result))

    @_provider_operation
    def complete(self, handle: UploadHandle, size: int, part_size: int) -> StoredObject:
        existing = self._recover_object(handle.key)
        if existing is not None:
            return existing  # lost completion response at this attempt's private key
        parts = self.parts(handle)
        if len(parts) != max(1, ceil(size / part_size)) or any(
                p.number != n or p.size != part_size_for(n, size, part_size)
                for n, p in enumerate(parts, 1)):
            raise StorageFailure("invalid_parts")
        result = self.client.complete_multipart_upload(Bucket=self.bucket, Key=handle.key,
            UploadId=handle.id, MultipartUpload={"Parts": [
                {"PartNumber": p.number, "ETag": p.etag} for p in parts]})
        return StoredObject(handle.key, self._version(result))

    @_provider_operation
    def verify(self, stored: StoredObject, size: int, digest: str) -> Verification:
        response = self.client.get_object(Bucket=self.bucket, Key=stored.key, VersionId=stored.version)
        actual_size, actual_digest = 0, sha256()
        with response["Body"] as body:
            for chunk in iter(lambda: body.read(1024 * 1024), b""):
                actual_size += len(chunk)
                actual_digest.update(chunk)
        actual = Verification(actual_size, actual_digest.hexdigest())
        if actual.size != size or actual.sha256 != digest:
            raise StorageFailure("verification_failed")
        return actual

    @_provider_operation
    def download_grant(self, stored: StoredObject, expires_at: float, seconds: int) -> TransferGrant:
        return self._grant("get_object", {"Bucket": self.bucket, "Key": stored.key,
            "VersionId": stored.version}, "GET", expires_at, seconds)

    def _abort_confirm(self, key, upload_id):
        try:
            self.client.abort_multipart_upload(Bucket=self.bucket, Key=key, UploadId=upload_id)
        except Exception as exc:
            failure = _normalize(exc)
            if failure.code != "storage_missing":
                raise failure from exc
        # Abort alone does not prove that concurrent UploadPart requests released
        # their parts. Require ListParts to confirm the upload no longer exists.
        try:
            self.client.list_parts(Bucket=self.bucket, Key=key, UploadId=upload_id)
        except Exception as exc:
            failure = _normalize(exc)
            if failure.code == "storage_missing":
                return
            raise failure from exc
        raise StorageFailure("cleanup_incomplete", retryable=True)

    @_provider_operation
    def cleanup(self, key: str) -> None:
        for page in self.client.get_paginator("list_multipart_uploads").paginate(Bucket=self.bucket, Prefix=key):
            for item in page.get("Uploads", []):
                if item["Key"] == key:
                    self._abort_confirm(key, item["UploadId"])
        for page in self.client.get_paginator("list_object_versions").paginate(Bucket=self.bucket, Prefix=key):
            for item in page.get("Versions", []) + page.get("DeleteMarkers", []):
                if item["Key"] == key:
                    self.client.delete_object(Bucket=self.bucket, Key=key, VersionId=item["VersionId"])
