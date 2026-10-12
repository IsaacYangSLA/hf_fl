"""Validated manager configuration; credentials are server-only."""
from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import urlsplit


def require_tls(url: str, allow_local_http: bool = False) -> str:
    parts = urlsplit(url)
    if not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ValueError("URL requires a host without credentials or fragments")
    if parts.scheme == "https":
        return url
    local = parts.hostname in {"localhost", "testserver"}
    try:
        local = local or ipaddress.ip_address(parts.hostname).is_loopback
    except ValueError:
        pass
    if parts.scheme == "http" and allow_local_http and local:
        return url
    raise ValueError("HTTPS is required; development HTTP is limited to loopback")


def origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc.lower()}"


def _env(name: str, default: str = "") -> str:
    values = [os.environ[prefix + name] for prefix in ("JOBS_", "HF2L_JOBS_") if prefix + name in os.environ]
    if len(set(values)) > 1:
        raise ValueError(f"Conflicting JOBS_{name} and HF2L_JOBS_{name}")
    return values[0] if values else default


def _bool(name: str, default: bool = False) -> bool:
    value = _env(name, str(default)).lower()
    if value not in {"true", "false", "1", "0"}:
        raise ValueError(f"JOBS_{name} must be true or false")
    return value in {"true", "1"}


def _file(name: str) -> str:
    path = _env(name)
    return Path(path).read_text(encoding="utf-8") if path else ""


@dataclass(frozen=True)
class OIDCSettings:
    issuer: str = ""
    client_id: str = ""
    client_secret: str = field(default="", repr=False)
    redirect_uri: str = ""
    audience: str = "hf2l-jobs"
    introspection_url: str = ""
    jwks_url: str = ""
    public_key: str = ""
    endpoint_origins: tuple[str, ...] = ()
    timeout_seconds: float = 5.0
    jwks_cache_seconds: int = 300
    allow_local_http: bool = False

    def validate(self):
        for name in ("issuer", "client_id", "redirect_uri", "audience"):
            if not getattr(self, name):
                raise ValueError(f"OIDC {name} is required")
        require_tls(self.issuer, self.allow_local_http)
        if urlsplit(self.issuer).query:
            raise ValueError("OIDC issuer cannot contain a query")
        require_tls(self.redirect_uri, self.allow_local_http)
        callback = urlsplit(self.redirect_uri)
        if callback.query or callback.fragment:
            raise ValueError("OIDC redirect URI cannot contain a query or fragment")
        for endpoint in (self.introspection_url, self.jwks_url):
            if endpoint:
                self.validate_endpoint(endpoint)
        for allowed in self.endpoint_origins:
            require_tls(allowed, self.allow_local_http)
            if origin(allowed) != allowed or urlsplit(allowed).path:
                raise ValueError("OIDC endpoint origins must be exact HTTPS origins")
        if bool(self.public_key) and bool(self.jwks_url):
            raise ValueError("Configure a public key or fixed JWKS URL, not both")
        if not 0 < self.timeout_seconds <= 30 or not 1 <= self.jwks_cache_seconds <= 300:
            raise ValueError("OIDC timeout/cache are bounded to 30/300 seconds")
        return self

    def validate_endpoint(self, endpoint: str) -> str:
        require_tls(endpoint, self.allow_local_http)
        if origin(endpoint) not in {origin(self.issuer), *self.endpoint_origins}:
            raise ValueError("OIDC endpoint origin is not explicitly trusted")
        return endpoint


@dataclass(frozen=True)
class _DatabaseCompatibility:
    url: str


@dataclass(frozen=True)
class Settings:
    database_url: str = "postgresql+psycopg://localhost/hf2l_jobs"
    cursor_secret: str = field(default="", repr=False)
    session_secret: str = field(default="", repr=False)
    oidc: OIDCSettings = field(default_factory=OIDCSettings)
    platform_operator_ids: tuple[str, ...] = ()
    broker: Any = field(default=None, repr=False)
    max_body_bytes: int = 1_048_576
    docs_enabled: bool = False
    extra: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @property
    def database(self):
        return _DatabaseCompatibility(self.database_url)

    @property
    def cookie_name(self):
        return "__Host-hf2l_jobs"

    @property
    def login_cookie_name(self):
        return "__Host-hf2l_jobs_login"

    def validate(self, component: str = "server"):
        if not self.database_url.startswith(("postgresql:", "postgresql+psycopg:", "sqlite:")):
            raise ValueError("Manager database must be PostgreSQL or SQLite (tests)")
        if not 1024 <= self.max_body_bytes <= 8_388_608:
            raise ValueError("Manager request size must be between 1KiB and 8MiB")
        if component == "server":
            self.oidc.validate()
            for key in ("cursor_secret", "session_secret"):
                if len(getattr(self, key).encode("utf-8")) < 32:
                    raise ValueError(f"{key} must contain at least 32 bytes")
            if self.cursor_secret == self.session_secret:
                raise ValueError("Cursor and session signing secrets must be distinct")
        if self.broker is not None:
            self.broker.validate()
        if not isinstance(self.extra, Mapping):
            raise ValueError("Operational configuration must be a mapping")
        return self

    @classmethod
    def from_env(cls, component: str = "server"):
        allow_http = _bool("ALLOW_LOCAL_HTTP")
        oidc = OIDCSettings(
            issuer=_env("OIDC_ISSUER"), client_id=_env("OIDC_CLIENT_ID"),
            client_secret=_file("OIDC_CLIENT_SECRET_FILE") or _env("OIDC_CLIENT_SECRET"),
            redirect_uri=_env("OIDC_REDIRECT_URI"), audience=_env("AUDIENCE", "hf2l-jobs"),
            introspection_url=_env("OIDC_INTROSPECTION_URL"), jwks_url=_env("OIDC_JWKS_URL"),
            public_key=_file("OIDC_PUBLIC_KEY_FILE"), endpoint_origins=tuple(filter(None, _env("OIDC_ENDPOINT_ORIGINS").split(","))),
            timeout_seconds=float(_env("OIDC_TIMEOUT_SECONDS", "5")),
            jwks_cache_seconds=int(_env("OIDC_JWKS_CACHE_SECONDS", "300")), allow_local_http=allow_http,
        )
        broker = None
        if _env("WORKLOAD_ISSUER"):
            from .broker import BrokerSettings
            broker = BrokerSettings(
                workload_issuer=_env("WORKLOAD_ISSUER"),
                exchange_audience=_env("WORKLOAD_EXCHANGE_AUDIENCE", "exchange-managed"),
                gateway_audience=_env("WORKLOAD_GATEWAY_AUDIENCE", "hf2l-transfer"),
                node_audience=_env("NODE_AUDIENCE", "hf2l-nodes"),
                private_key=_file("WORKLOAD_PRIVATE_KEY_FILE") or None,
                public_key=_file("WORKLOAD_PUBLIC_KEY_FILE"),
                key_id=_env("WORKLOAD_KEY_ID"),
            )
        config_path = _env("OPERATIONAL_CONFIG_FILE") or _env("CONFIG")
        extra = {}
        if config_path:
            extra = json.loads(Path(config_path).read_text(encoding="utf-8"))
            allowed = {"executor", "node", "provisioner", "service", "gateway", "proxy", "retention", "boundaries", "controller", "secrets", "nodes", "participants"}
            if not isinstance(extra, dict) or set(extra) - allowed:
                raise ValueError("Unknown operational configuration section")
        return cls(
            database_url=_env("DATABASE_URL", cls.database_url), cursor_secret=_file("CURSOR_SECRET_FILE") or _env("CURSOR_SECRET"),
            session_secret=_file("SESSION_SECRET_FILE") or _env("SESSION_SECRET"),
            oidc=oidc, platform_operator_ids=tuple(filter(None, _env("PLATFORM_OPERATOR_IDS").split(","))),
            broker=broker, max_body_bytes=int(_env("MAX_BODY_BYTES", "1048576")),
            docs_enabled=_bool("DOCS_ENABLED"), extra=MappingProxyType(extra),
        ).validate(component)
