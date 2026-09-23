"""Component-specific configuration; database tools need no identity or S3 secrets."""
from dataclasses import dataclass, field
import ipaddress
import os
from urllib.parse import urlsplit


def require_tls(url: str, allow_local_http: bool = False) -> str:
    parts = urlsplit(url)
    if parts.username or parts.password or not parts.hostname or parts.fragment:
        raise ValueError("URL must have a host and contain no credentials or fragment")
    if parts.scheme == "https":
        return url
    local = parts.hostname in {"localhost", "testserver"}
    try:
        local = local or ipaddress.ip_address(parts.hostname).is_loopback
    except ValueError:
        pass
    if parts.scheme == "http" and allow_local_http and local:
        return url
    raise ValueError("HTTPS is required; allow_local_http only permits loopback development endpoints")


def _env(name, default=""):
    return os.getenv("EXCHANGE_" + name, default)


def _bool(name, default=False):
    value = _env(name, "true" if default else "false").lower()
    if value not in {"true", "false", "1", "0"}:
        raise ValueError("EXCHANGE_" + name + " must be true or false")
    return value in {"true", "1"}


def _positive(value, name, allow_zero=False):
    if value < (0 if allow_zero else 1):
        raise ValueError(name + " must be " + ("nonnegative" if allow_zero else "positive"))


@dataclass(frozen=True)
class DatabaseSettings:
    url: str = "sqlite:///exchange-v2.db"
    pool_size: int = 5
    pool_overflow: int = 10
    pool_timeout: float = 30
    pool_recycle: int = 1800

    def validate(self):
        if not self.url.startswith(("sqlite:", "postgresql:" , "postgresql+psycopg:")):
            raise ValueError("Database must be SQLite or PostgreSQL")
        for key in ("pool_size", "pool_timeout", "pool_recycle"):
            _positive(getattr(self, key), key)
        _positive(self.pool_overflow, "pool_overflow", True)
        return self

    @classmethod
    def from_env(cls):
        return cls(url=_env("DATABASE_URL", cls.url), pool_size=int(_env("POOL_SIZE", "5")),
                   pool_overflow=int(_env("POOL_OVERFLOW", "10")), pool_timeout=float(_env("POOL_TIMEOUT", "30")),
                   pool_recycle=int(_env("POOL_RECYCLE", "1800"))).validate()


@dataclass(frozen=True)
class AuthSettings:
    issuer: str = ""
    audience: str = "exchange"
    public_key: str = ""
    jwks_url: str = ""
    admin_subject: str = ""
    jwks_timeout: float = 5
    jwks_cache_seconds: int = 300
    allow_local_http: bool = False

    def validate(self):
        if not self.issuer or not self.audience or bool(self.public_key) == bool(self.jwks_url):
            raise ValueError("Authentication requires issuer, audience and exactly one public key or JWKS URL")
        require_tls(self.issuer, self.allow_local_http)
        if self.jwks_url:
            require_tls(self.jwks_url, self.allow_local_http)
        _positive(self.jwks_timeout, "jwks_timeout")
        _positive(self.jwks_cache_seconds, "jwks_cache_seconds")
        return self

    @classmethod
    def from_env(cls):
        return cls(issuer=_env("ISSUER"), audience=_env("AUDIENCE", "exchange"),
                   public_key=_env("JWT_PUBLIC_KEY"), jwks_url=_env("JWKS_URL"),
                   admin_subject=_env("ADMIN_SUBJECT"), jwks_timeout=float(_env("JWKS_TIMEOUT", "5")),
                   jwks_cache_seconds=int(_env("JWKS_CACHE_SECONDS", "300")),
                   allow_local_http=_bool("ALLOW_LOCAL_HTTP")).validate()


@dataclass(frozen=True)
class StorageSettings:
    endpoint: str = ""
    public_endpoint: str = ""
    bucket: str = ""
    region: str = "us-east-1"
    access_key: str = ""
    secret_key: str = ""
    prefix: str = "exchange-v2/"
    grant_seconds: int = 300
    part_size: int = 8388608
    allow_local_http: bool = False

    def validate(self):
        if not self.bucket:
            raise ValueError("Storage bucket is required")
        for endpoint in (self.endpoint, self.public_endpoint):
            if endpoint:
                require_tls(endpoint, self.allow_local_http)
        if bool(self.access_key) != bool(self.secret_key):
            raise ValueError("Storage access key and secret key must be supplied together")
        if len(self.prefix.encode("utf-8")) > 800 or self.prefix.startswith("/") or ".." in self.prefix.split("/"):
            raise ValueError("Storage prefix must be a relative path")
        if not 1 <= self.grant_seconds <= 3600:
            raise ValueError("grant_seconds must be between 1 and 3600")
        if not 5242880 <= self.part_size <= 5368709120:
            raise ValueError("part_size must satisfy S3 multipart limits")
        return self

    @classmethod
    def from_env(cls):
        return cls(endpoint=_env("S3_ENDPOINT"), public_endpoint=_env("S3_PUBLIC_ENDPOINT"),
                   bucket=_env("S3_BUCKET"), region=_env("S3_REGION", "us-east-1"),
                   access_key=_env("S3_ACCESS_KEY", os.getenv("AWS_ACCESS_KEY_ID", "")),
                   secret_key=_env("S3_SECRET_KEY", os.getenv("AWS_SECRET_ACCESS_KEY", "")),
                   prefix=_env("S3_PREFIX", "exchange-v2/"), grant_seconds=int(_env("GRANT_SECONDS", "300")),
                   part_size=int(_env("PART_SIZE", "8388608")),
                   allow_local_http=_bool("ALLOW_LOCAL_HTTP")).validate()


@dataclass(frozen=True)
class WorkerSettings:
    lease_seconds: int = 300
    failure_seconds: int = 86400
    poll_seconds: float = 1
    verify_concurrency: int = 2
    cleanup_concurrency: int = 2
    batch_size: int = 32
    recover_after: int = 30
    operation_retention_seconds: int = 864000
    event_retention_seconds: int = 2592000

    def validate(self):
        for name in self.__dataclass_fields__:
            _positive(getattr(self, name), name)
        if self.failure_seconds < self.lease_seconds:
            raise ValueError("failure_seconds must cover a worker lease")
        return self

    @classmethod
    def from_env(cls):
        values = {name: (float if name == "poll_seconds" else int)(_env("WORKER_" + name.upper(), str(f.default)))
                  for name, f in cls.__dataclass_fields__.items()}
        # Retention knobs retain concise names used by operators.
        for name in ("operation_retention_seconds", "event_retention_seconds"):
            values[name] = int(_env(name.upper(), str(values[name])))
        return cls(**values).validate()


@dataclass(frozen=True)
class Settings:
    database: DatabaseSettings = field(default_factory=DatabaseSettings)
    auth: AuthSettings = field(default_factory=AuthSettings)
    storage: StorageSettings = field(default_factory=StorageSettings)
    worker: WorkerSettings = field(default_factory=WorkerSettings)
    allow_local_http: bool = False
    docs_enabled: bool = False
    max_body_bytes: int = 1048576
    draft_seconds: int = 86400
    coordination_seconds: int = 300

    def validate(self, component="server"):
        self.database.validate()
        if component == "server":
            self.auth.validate()
        if component in {"server", "worker"}:
            self.storage.validate()
            self.worker.validate()
            if self.worker.operation_retention_seconds <= self.draft_seconds + self.storage.grant_seconds + 86400:
                raise ValueError("Operation retention must exceed draft lifetime, grants, and one day of retries")
        for name in ("max_body_bytes", "draft_seconds", "coordination_seconds"):
            _positive(getattr(self, name), name)
        if self.draft_seconds > 604800 or self.coordination_seconds > 3600:
            raise ValueError("Draft lifetime is bounded to seven days and coordination lease to one hour")
        return self

    @classmethod
    def from_env(cls, component="server"):
        return cls(database=DatabaseSettings.from_env(),
                   auth=AuthSettings.from_env() if component == "server" else AuthSettings(),
                   storage=StorageSettings.from_env() if component != "database" else StorageSettings(),
                   worker=WorkerSettings.from_env(), allow_local_http=_bool("ALLOW_LOCAL_HTTP"),
                   docs_enabled=_bool("DOCS_ENABLED"), max_body_bytes=int(_env("MAX_BODY_BYTES", "1048576")),
                   draft_seconds=int(_env("DRAFT_SECONDS", "86400")),
                   coordination_seconds=int(_env("COORDINATION_SECONDS", "300"))).validate(component)
