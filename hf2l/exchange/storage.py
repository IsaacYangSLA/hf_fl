"""Version-pinned S3 multipart storage. No client chooses storage locators."""
import hashlib
import math
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


class StorageMisconfigured(RuntimeError):
    """The storage provider cannot supply the required immutable version contract."""


class S3BlobStore:
    def __init__(self, settings, client=None):
        self.settings = settings
        self.bucket = settings.bucket
        self.client = client or boto3.client(
            "s3", endpoint_url=settings.s3_endpoint, region_name=settings.region,
            config=Config(signature_version="s3v4", connect_timeout=3, read_timeout=30,
                          retries={"mode": "standard", "max_attempts": 4}),
        )
        self.signer = boto3.client(
            "s3", endpoint_url=settings.s3_public_endpoint, region_name=settings.region,
            config=Config(signature_version="s3v4"),
        ) if settings.s3_public_endpoint else self.client

    def check(self):
        if self.client.get_bucket_versioning(Bucket=self.bucket).get("Status") != "Enabled":
            raise StorageMisconfigured("Exchange bucket versioning must be enabled")
        # Read-only permission probe: ListBucket is needed to distinguish missing keys from denied access.
        self.recover_version("health/missing-" + uuid.uuid4().hex)

    def start(self, key):
        return self.client.create_multipart_upload(Bucket=self.bucket, Key=key)["UploadId"]

    def pending_uploads(self, key):
        for page in self.client.get_paginator("list_multipart_uploads").paginate(Bucket=self.bucket, Prefix=key):
            for item in page.get("Uploads", []):
                if item["Key"] == key:
                    yield item["UploadId"]

    def recover_start(self, key):
        # No grant is issued before initiation is durably committed. Restart with a fresh attempt-owned MPU;
        # never adopt a stale attempt's MPU that its delayed owner may still abort.
        for upload_id in self.pending_uploads(key):
            self.client.abort_multipart_upload(Bucket=self.bucket, Key=key, UploadId=upload_id)
        return self.start(key)

    def parts(self, blob):
        result = []
        for page in self.client.get_paginator("list_parts").paginate(
            Bucket=self.bucket, Key=blob.key, UploadId=blob.upload_id
        ):
            result.extend(page.get("Parts", []))
        return result

    def authorize(self, blob, numbers):
        count = max(1, math.ceil(blob.size / blob.part_bytes))
        result = []
        for number in numbers:
            if not 1 <= number <= count:
                raise ValueError("Invalid part number")
            size = min(blob.part_bytes, blob.size - (number - 1) * blob.part_bytes)
            url = self.signer.generate_presigned_url("upload_part", Params={
                "Bucket": self.bucket, "Key": blob.key, "UploadId": blob.upload_id,
                "PartNumber": number, "ContentLength": size,
            }, ExpiresIn=self.settings.grant_seconds, HttpMethod="PUT")
            result.append({"part_number": number, "size_bytes": size, "url": url,
                           "headers": {"Content-Length": str(size)}})
        return result

    def recover_version(self, key):
        try:
            result = self.client.head_object(Bucket=self.bucket, Key=key)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("404", "NoSuchKey", "NotFound"):
                return None
            raise
        version = result.get("VersionId")
        if not version or version == "null":
            raise StorageMisconfigured("Storage did not supply an immutable version ID")
        return version

    def complete(self, blob):
        # A lost successful completion response is reconciled at a service-owned key.
        existing = self.recover_version(blob.key)
        if existing:
            return existing
        parts = self.parts(blob)
        count = max(1, math.ceil(blob.size / blob.part_bytes))
        if len(parts) != count:
            raise ValueError("Missing upload parts")
        for index, part in enumerate(parts, 1):
            expected = min(blob.part_bytes, blob.size - (index - 1) * blob.part_bytes)
            if part["PartNumber"] != index or part["Size"] != expected:
                raise ValueError("Part size or number does not match reservation")
        result = self.client.complete_multipart_upload(
            Bucket=self.bucket, Key=blob.key, UploadId=blob.upload_id,
            MultipartUpload={"Parts": [{"PartNumber": p["PartNumber"], "ETag": p["ETag"]} for p in parts]},
        )
        version = result.get("VersionId")
        if not version or version == "null":
            raise StorageMisconfigured("Storage did not supply an immutable version ID")
        return version

    def verify(self, blob):
        response = self.client.get_object(Bucket=self.bucket, Key=blob.key, VersionId=blob.version)
        digest, size = hashlib.sha256(), 0
        with response["Body"] as body:
            for chunk in iter(lambda: body.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
        if size != blob.size or digest.hexdigest() != blob.sha256:
            raise ValueError("Blob size or SHA-256 mismatch")
        return digest.hexdigest()

    def download(self, blob):
        return self.signer.generate_presigned_url("get_object", Params={
            "Bucket": self.bucket, "Key": blob.key, "VersionId": blob.version,
        }, ExpiresIn=self.settings.grant_seconds, HttpMethod="GET")

    def abort(self, blob):
        if blob.upload_id:
            try:
                self.client.abort_multipart_upload(Bucket=self.bucket, Key=blob.key, UploadId=blob.upload_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchUpload":
                    raise

    def delete(self, blob):
        if blob.version:
            self.client.delete_object(Bucket=self.bucket, Key=blob.key, VersionId=blob.version)

    def cleanup(self, blob):
        for upload_id in self.pending_uploads(blob.key):
            self.client.abort_multipart_upload(Bucket=self.bucket, Key=blob.key, UploadId=upload_id)
        for page in self.client.get_paginator("list_object_versions").paginate(Bucket=self.bucket, Prefix=blob.key):
            for item in page.get("Versions", []) + page.get("DeleteMarkers", []):
                if item["Key"] == blob.key:
                    self.client.delete_object(Bucket=self.bucket, Key=blob.key, VersionId=item["VersionId"])
