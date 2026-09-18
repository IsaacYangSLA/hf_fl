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

    def __post_init__(self):
        if not all((self.database_url, self.issuer, self.audience, self.bucket, self.admin_subject)):
            raise ValueError("Database, issuer, audience, bucket and bootstrap admin subject are required")
        if bool(self.jwks_url) == bool(self.public_key):
            raise ValueError("Configure exactly one trusted JWKS URL or PEM public key")
        if self.jwks_url and not self.jwks_url.startswith("https://"):
            raise ValueError("JWKS URL must use HTTPS")
        if not 5 * 1024 * 1024 <= self.part_bytes <= 5 * 1024**3:
            raise ValueError("Invalid multipart part size")

    @classmethod
    def from_env(cls):
        def required(name):
            return os.environ["EXCHANGE_" + name]
        key_path = os.environ.get("EXCHANGE_PUBLIC_KEY_FILE")
        return cls(
            database_url=required("DATABASE_URL"), issuer=required("ISSUER"),
            audience=required("AUDIENCE"), bucket=required("S3_BUCKET"),
            admin_subject=required("ADMIN_SUBJECT"),
            jwks_url=os.environ.get("EXCHANGE_JWKS_URL", ""),
            public_key=Path(key_path).read_text() if key_path else "",
            s3_endpoint=os.environ.get("EXCHANGE_S3_ENDPOINT"),
            region=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        )
