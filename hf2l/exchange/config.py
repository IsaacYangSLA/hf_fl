"""Explicit deployment configuration; no anonymous or shared-token auth mode."""
from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database_url: str
    issuer: str
    audience: str
    bucket: str
    admin_subject: str
    jwks_url: str = ""
    public_key: str = ""
    s3_endpoint: str | None = None
    region: str = "us-east-1"
    grant_seconds: int = 300
    upload_seconds: int = 86400
    part_bytes: int = 64 * 1024 * 1024
    max_body_bytes: int = 1024 * 1024
    worker_interval: float = 5.0
    worker_batch: int = 256
    worker_concurrency: int = 4
    worker_lease_seconds: int = 3600
    # Blobs left in initiating/completing are recovered only after the API had time to finish its own transition.
    worker_recover_after: int = 30

    def __post_init__(self):
        if not all((self.database_url, self.issuer, self.audience, self.bucket, self.admin_subject)):
            raise ValueError("Database, issuer, audience, bucket and bootstrap admin subject are required")
        if bool(self.jwks_url) == bool(self.public_key):
            raise ValueError("Configure exactly one trusted JWKS URL or PEM public key")
        if self.jwks_url and not self.jwks_url.startswith("https://"):
            raise ValueError("JWKS URL must use HTTPS")
        if not 5 * 1024 * 1024 <= self.part_bytes <= 5 * 1024**3:
            raise ValueError("Invalid multipart part size")
        if not 60 <= self.grant_seconds <= 3600 or not 600 <= self.upload_seconds <= 7 * 86400:
            raise ValueError("Invalid grant or upload window")
        if self.worker_interval <= 0 or not 1 <= self.worker_batch <= 10000 or not 1 <= self.worker_concurrency <= 64:
            raise ValueError("Invalid worker interval, batch or concurrency")

    @classmethod
    def from_env(cls):
        def required(name):
            return os.environ["EXCHANGE_" + name]

        def optional(name, default, convert):
            value = os.environ.get("EXCHANGE_" + name)
            return convert(value) if value else default
        key_path = os.environ.get("EXCHANGE_PUBLIC_KEY_FILE")
        return cls(
            database_url=required("DATABASE_URL"), issuer=required("ISSUER"),
            audience=required("AUDIENCE"), bucket=required("S3_BUCKET"),
            admin_subject=required("ADMIN_SUBJECT"),
            jwks_url=os.environ.get("EXCHANGE_JWKS_URL", ""),
            public_key=Path(key_path).read_text() if key_path else "",
            s3_endpoint=os.environ.get("EXCHANGE_S3_ENDPOINT"),
            region=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
            grant_seconds=optional("GRANT_SECONDS", 300, int),
            upload_seconds=optional("UPLOAD_SECONDS", 86400, int),
            part_bytes=optional("PART_BYTES", 64 * 1024 * 1024, int),
            max_body_bytes=optional("MAX_BODY_BYTES", 1024 * 1024, int),
            worker_interval=optional("WORKER_INTERVAL", 5.0, float),
            worker_batch=optional("WORKER_BATCH", 256, int),
            worker_concurrency=optional("WORKER_CONCURRENCY", 4, int),
            worker_lease_seconds=optional("WORKER_LEASE_SECONDS", 3600, int),
            worker_recover_after=optional("WORKER_RECOVER_AFTER", 30, int),
        )
