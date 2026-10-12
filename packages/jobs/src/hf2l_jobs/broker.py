"""Fixed-key, certificate-bound credentials for isolated execution.

This module never discovers token issuers or keys and never reads TLS identity
from HTTP headers. The caller supplies peer identity from its trusted TLS adapter.
Only the trusted control plane may construct a broker with a signing key.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Callable, Mapping

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_THUMBPRINT = re.compile(r"^[A-Za-z0-9_-]{43}$")
NODE_SCOPES = frozenset({
    "acknowledge", "heartbeat", "progress", "logs", "stopped", "collect",
    "reserve", "start", "inspect", "stop", "release", "renew", "assignment", "purge",
})
_RESOURCE_KEYS = frozenset({"cpu_millicores", "memory_bytes", "disk_bytes", "gpu_uuids"})


class BrokerError(ValueError):
    """Safe authentication/signing error with an HTTP-independent status."""

    def __init__(self, code="invalid_access_token", status=401):
        super().__init__(code)
        self.code = code
        self.status = status


def principal_id(issuer: str, subject: str) -> str:
    """Match Exchange's fixed-issuer stable principal derivation."""
    return hashlib.sha256(
        json.dumps([issuer, subject], separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def stable_workload_subject(job_id: str, component_id: str,
                            participant_id: str | None = None) -> str:
    """Attempt rotation cannot change creator or participant identity."""
    _identifier(job_id)
    _identifier(component_id)
    if participant_id is not None:
        _identifier(participant_id)
    identity = json.dumps([job_id, component_id, participant_id], separators=(",", ":"))
    return "job:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()


def stable_workload_principal(issuer: str, job_id: str, component_id: str,
                              participant_id: str | None = None) -> str:
    return principal_id(issuer, stable_workload_subject(job_id, component_id, participant_id))


def _identifier(value):
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise BrokerError("invalid_credential_binding", 422)
    return value


def _thumbprint(value):
    if not isinstance(value, str) or not _THUMBPRINT.fullmatch(value):
        raise BrokerError("invalid_certificate_binding", 422)
    # A SHA-256 thumbprint is canonical unpadded base64url of exactly 32 bytes.
    import base64
    decoded = base64.urlsafe_b64decode(value + "=")
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise BrokerError("invalid_certificate_binding", 422)
    return value


def _epoch(value):
    if type(value) is not int or value < 1 or value > (1 << 63) - 1:
        raise BrokerError("invalid_credential_epoch", 422)
    return value


def _resource_limits(value):
    if not isinstance(value, Mapping) or set(value) - _RESOURCE_KEYS:
        raise BrokerError("invalid_node_resources", 422)
    result = {}
    for key, item in value.items():
        if key == "gpu_uuids":
            if not isinstance(item, (list, tuple)) or len(item) > 1024:
                raise BrokerError("invalid_node_resources", 422)
            if any(not isinstance(gpu, str) or not _IDENTIFIER.fullmatch(gpu) for gpu in item):
                raise BrokerError("invalid_node_resources", 422)
            if len(set(item)) != len(item):
                raise BrokerError("invalid_node_resources", 422)
            result[key] = tuple(item)
        else:
            if type(item) is not int or item < 1 or item > (1 << 50):
                raise BrokerError("invalid_node_resources", 422)
            result[key] = item
    return MappingProxyType(result)


@dataclass(frozen=True)
class BrokerSettings:
    workload_issuer: str
    exchange_audience: str
    gateway_audience: str
    node_audience: str
    public_key: object = field(repr=False)
    private_key: object | None = field(default=None, repr=False)
    key_id: str = ""
    max_ttl_seconds: int = 300

    def validate(self):
        values = (self.workload_issuer, self.exchange_audience,
                  self.gateway_audience, self.node_audience)
        if any(not isinstance(value, str) or not value or len(value) > 2048
               or any(ord(char) < 33 for char in value) for value in values):
            raise ValueError("Broker issuer and audiences must be fixed nonempty strings")
        if len({self.exchange_audience, self.gateway_audience, self.node_audience}) != 3:
            raise ValueError("Exchange, gateway and node audiences must be distinct")
        if type(self.max_ttl_seconds) is not int or not 1 <= self.max_ttl_seconds <= 300:
            raise ValueError("Credential lifetime cannot exceed 300 seconds")
        if not isinstance(self.key_id, str) or (self.key_id and not _IDENTIFIER.fullmatch(self.key_id)):
            raise ValueError("Invalid broker key identifier")


@dataclass(frozen=True)
class WorkloadPrincipal:
    id: str
    subject: str
    job_id: str
    attempt_id: str
    component_id: str
    space_id: str
    grant_id: str
    epoch: int
    certificate_thumbprint: str
    audience: str
    issued_at: int
    expires_at: int
    participant_id: str | None = None


@dataclass(frozen=True)
class NodePrincipal:
    id: str
    subject: str
    node_id: str
    pool_id: str
    job_id: str
    attempt_id: str
    component_id: str
    grant_id: str
    epoch: int
    certificate_thumbprint: str
    scopes: frozenset[str]
    resources: Mapping[str, object]
    issued_at: int
    expires_at: int


@dataclass(frozen=True)
class PlatformNodePrincipal:
    """Registered node identity for platform qualification, without a job grant."""

    id: str
    subject: str
    node_id: str
    pool_id: str
    registration_id: str
    certificate_thumbprint: str
    scopes: frozenset[str]
    expires_at: int


class WorkloadBroker:
    def __init__(self, settings: BrokerSettings, *, clock: Callable[[], float] = time.time,
                 node_grant_validator: Callable[[NodePrincipal], bool] | None = None,
                 node_registration_validator: Callable[[PlatformNodePrincipal], bool] | None = None):
        settings.validate()
        self.settings = settings
        self.clock = clock
        self.node_grant_validator = node_grant_validator
        self.node_registration_validator = node_registration_validator
        self._public_key = self._load_key(settings.public_key, private=False)
        self._private_key = (self._load_key(settings.private_key, private=True)
                             if settings.private_key is not None else None)
        if self._private_key is not None:
            if self._private_key.public_key().public_numbers() != self._public_key.public_numbers():
                raise ValueError("Broker signing and verification keys must match")

    @staticmethod
    def _load_key(value, *, private):
        try:
            if isinstance(value, str):
                value = value.encode("utf-8")
            if isinstance(value, bytes):
                value = (serialization.load_pem_private_key(value, password=None) if private
                         else serialization.load_pem_public_key(value))
            expected = rsa.RSAPrivateKey if private else rsa.RSAPublicKey
            if not isinstance(value, expected) or value.key_size < 2048:
                raise ValueError()
            return value
        except (ValueError, TypeError):
            raise ValueError("Broker requires an RSA key of at least 2048 bits") from None

    def _base_claims(self, subject, audience, grant_id, certificate_thumbprint, ttl_seconds):
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= self.settings.max_ttl_seconds:
            raise BrokerError("invalid_credential_lifetime", 422)
        now = int(self.clock())
        return {
            "iss": self.settings.workload_issuer, "aud": audience, "sub": subject,
            "iat": now, "nbf": now, "exp": now + ttl_seconds,
            "jti": _identifier(grant_id), "grant_id": grant_id,
            "cnf": {"x5t#S256": _thumbprint(certificate_thumbprint)},
        }

    def _sign(self, claims):
        if self._private_key is None:
            raise BrokerError("signing_key_unavailable", 503)
        headers = {"typ": "at+jwt"}
        if self.settings.key_id:
            headers["kid"] = self.settings.key_id
        return jwt.encode(claims, self._private_key, algorithm="RS256", headers=headers)

    def issue_workload(self, *, job_id, attempt_id, component_id, space_id, grant_id,
                       epoch, certificate_thumbprint, participant_id=None,
                       ttl_seconds=300, audience="exchange"):
        if audience not in {"exchange", "gateway"}:
            raise BrokerError("invalid_workload_audience", 422)
        fixed_audience = (self.settings.exchange_audience if audience == "exchange"
                          else self.settings.gateway_audience)
        claims = self._base_claims(
            stable_workload_subject(job_id, component_id, participant_id),
            fixed_audience, grant_id, certificate_thumbprint, ttl_seconds)
        claims.update({
            "token_use": "workload", "scope": "exchange" if audience == "exchange" else "transfer",
            "job_id": _identifier(job_id), "attempt_id": _identifier(attempt_id),
            "component_id": _identifier(component_id), "space_id": _identifier(space_id),
            "epoch": _epoch(epoch),
        })
        if participant_id is not None:
            claims["participant_id"] = _identifier(participant_id)
        return self._sign(claims)

    def issue_node(self, *, node_id, pool_id, job_id, attempt_id, component_id,
                   grant_id, epoch, certificate_thumbprint, scopes, resources=None,
                   ttl_seconds=300):
        if not isinstance(scopes, (list, tuple, set, frozenset)):
            raise BrokerError("invalid_node_scopes", 422)
        if not scopes or any(not isinstance(scope, str) or scope not in NODE_SCOPES for scope in scopes):
            raise BrokerError("invalid_node_scopes", 422)
        scopes = sorted(set(scopes))
        limits = _resource_limits({} if resources is None else resources)
        if set(scopes) & {"reserve", "start", "renew"}:
            if not {"cpu_millicores", "memory_bytes", "disk_bytes"} <= set(limits):
                raise BrokerError("invalid_node_resources", 422)
        claims = self._base_claims("node:" + _identifier(node_id), self.settings.node_audience,
                                   grant_id, certificate_thumbprint, ttl_seconds)
        claims.update({
            "token_use": "node", "scope": " ".join(scopes),
            "node_id": node_id, "pool_id": _identifier(pool_id),
            "job_id": _identifier(job_id), "attempt_id": _identifier(attempt_id),
            "component_id": _identifier(component_id), "epoch": _epoch(epoch),
            "resources": dict(limits),
        })
        return self._sign(claims)

    def issue_node_platform(self, *, node_id, pool_id, registration_id,
                            certificate_thumbprint, ttl_seconds=300):
        """Issue a qualification credential bound to an operator registration.

        The trusted TLS adapter supplies the registered manager certificate
        thumbprint. Job grants and resource reservations are not platform claims.
        """
        node_id = _identifier(node_id)
        registration_id = _identifier(registration_id)
        claims = self._base_claims(
            "node-platform:" + node_id, self.settings.node_audience,
            registration_id, certificate_thumbprint, ttl_seconds)
        claims.pop("grant_id")
        claims.update({
            "token_use": "node_platform", "scope": "qualify",
            "node_id": node_id, "pool_id": _identifier(pool_id),
            "registration_id": registration_id,
        })
        return self._sign(claims)

    issue_platform_node = issue_node_platform

    def _decode(self, authorization, audience, verified_peer_thumbprint, *, job_bound=True):
        try:
            if not isinstance(authorization, str) or len(authorization) > 16384:
                raise ValueError()
            scheme, token = authorization.split(" ", 1)
            if scheme.lower() != "bearer" or not token or any(char.isspace() for char in token):
                raise ValueError()
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or header.get("typ") != "at+jwt":
                raise ValueError()
            if set(header) - {"alg", "typ", "kid"}:
                raise ValueError()
            if self.settings.key_id and header.get("kid") != self.settings.key_id:
                raise ValueError()
            claims = jwt.decode(
                token, self._public_key, algorithms=["RS256"], audience=audience,
                issuer=self.settings.workload_issuer,
                options={"require": ["iss", "aud", "sub", "iat", "nbf", "exp", "jti", "cnf"],
                         "strict_aud": True, "verify_exp": False,
                         "verify_iat": False, "verify_nbf": False})
            if not isinstance(claims["aud"], str) or claims["aud"] != audience:
                raise ValueError()
            if not isinstance(claims["sub"], str) or not claims["sub"] or len(claims["sub"]) > 256:
                raise ValueError()
            if any(type(claims[key]) is not int for key in ("iat", "nbf", "exp")):
                raise ValueError()
            now = self.clock()
            if claims["nbf"] != claims["iat"] or claims["iat"] > now:
                raise ValueError()
            if not claims["iat"] < claims["exp"] <= claims["iat"] + self.settings.max_ttl_seconds:
                raise ValueError()
            if claims["exp"] <= now:
                raise ValueError()
            _identifier(claims["jti"])
            if claims.get("grant_id", claims["jti"]) != claims["jti"]:
                raise ValueError()
            cnf = claims["cnf"]
            if not isinstance(cnf, dict) or set(cnf) != {"x5t#S256"}:
                raise ValueError()
            claimed = _thumbprint(cnf["x5t#S256"])
            verified = _thumbprint(verified_peer_thumbprint)
            if not hmac.compare_digest(claimed, verified):
                raise ValueError()
            if job_bound:
                for name in ("job_id", "attempt_id", "component_id"):
                    _identifier(claims[name])
                _epoch(claims["epoch"])
            return claims
        except (jwt.PyJWTError, ValueError, TypeError, KeyError, AttributeError):
            raise BrokerError() from None

    def authenticate_workload(self, authorization, *, verified_peer_thumbprint, audience="exchange"):
        """Validate identity only; the receiving service must also check its current grant ledger."""
        if audience not in {"exchange", "gateway"}:
            raise BrokerError()
        fixed = (self.settings.exchange_audience if audience == "exchange"
                 else self.settings.gateway_audience)
        claims = self._decode(authorization, fixed, verified_peer_thumbprint)
        try:
            if claims.get("token_use") != "workload":
                raise ValueError()
            if claims.get("scope") != ("exchange" if audience == "exchange" else "transfer"):
                raise ValueError()
            _identifier(claims["space_id"])
            participant = claims.get("participant_id")
            if participant is not None:
                _identifier(participant)
            subject = stable_workload_subject(claims["job_id"], claims["component_id"], participant)
            if claims["sub"] != subject:
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            raise BrokerError() from None
        return WorkloadPrincipal(
            principal_id(self.settings.workload_issuer, subject), subject, claims["job_id"],
            claims["attempt_id"], claims["component_id"], claims["space_id"], claims["jti"],
            claims["epoch"], claims["cnf"]["x5t#S256"], fixed, claims["iat"], claims["exp"], participant)

    def authenticate_node(self, authorization, *, verified_peer_thumbprint, grant_validator=None):
        claims = self._decode(authorization, self.settings.node_audience, verified_peer_thumbprint)
        try:
            if claims.get("token_use") != "node":
                raise ValueError()
            node_id, pool_id = _identifier(claims["node_id"]), _identifier(claims["pool_id"])
            if claims["sub"] != "node:" + node_id:
                raise ValueError()
            raw_scope = claims["scope"]
            if not isinstance(raw_scope, str):
                raise ValueError()
            parts = raw_scope.split(" ")
            if not parts or any(scope not in NODE_SCOPES for scope in parts) or len(set(parts)) != len(parts):
                raise ValueError()
            limits = _resource_limits(claims["resources"])
            if set(parts) & {"reserve", "start", "renew"}:
                if not {"cpu_millicores", "memory_bytes", "disk_bytes"} <= set(limits):
                    raise ValueError()
            principal = NodePrincipal(
                principal_id(self.settings.workload_issuer, claims["sub"]), claims["sub"],
                node_id, pool_id, claims["job_id"], claims["attempt_id"], claims["component_id"],
                claims["jti"], claims["epoch"], claims["cnf"]["x5t#S256"], frozenset(parts),
                limits, claims["iat"], claims["exp"])
        except (ValueError, KeyError, TypeError):
            raise BrokerError() from None
        validator = grant_validator or self.node_grant_validator
        if validator is None:
            raise BrokerError("node_grant_unavailable", 503)
        try:
            valid = validator(principal)
        except Exception:
            raise BrokerError("node_grant_unavailable", 503) from None
        if valid is not True:
            raise BrokerError()
        return principal


    def authenticate_node_platform(self, authorization, *, verified_peer_thumbprint,
                                   registration_validator=None):
        """Require a valid signature, registered manager TLS peer and current registration."""
        claims = self._decode(
            authorization, self.settings.node_audience, verified_peer_thumbprint,
            job_bound=False)
        try:
            allowed = {
                "iss", "aud", "sub", "iat", "nbf", "exp", "jti", "cnf",
                "token_use", "scope", "node_id", "pool_id", "registration_id",
            }
            if set(claims) != allowed:
                raise ValueError()
            if claims["token_use"] != "node_platform" or claims["scope"] != "qualify":
                raise ValueError()
            node_id = _identifier(claims["node_id"])
            pool_id = _identifier(claims["pool_id"])
            registration_id = _identifier(claims["registration_id"])
            subject = "node-platform:" + node_id
            if claims["sub"] != subject or claims["jti"] != registration_id:
                raise ValueError()
            principal = PlatformNodePrincipal(
                principal_id(self.settings.workload_issuer, subject), subject,
                node_id, pool_id, registration_id, claims["cnf"]["x5t#S256"],
                frozenset({"qualify"}), claims["exp"])
        except (ValueError, KeyError, TypeError):
            raise BrokerError() from None
        validator = (registration_validator if registration_validator is not None
                     else self.node_registration_validator)
        if validator is None:
            raise BrokerError("node_registration_unavailable", 503)
        try:
            valid = validator(principal)
        except Exception:
            raise BrokerError("node_registration_unavailable", 503) from None
        if valid is not True:
            raise BrokerError()
        return principal

    authenticate_platform_node = authenticate_node_platform


class NodeAuthenticator:
    """Verification-only adapter; current grant verification is mandatory."""

    def __init__(self, settings, *, grant_validator=None, clock=time.time):
        self.broker = WorkloadBroker(settings, clock=clock, node_grant_validator=grant_validator)

    def authenticate(self, authorization, *, verified_peer_thumbprint):
        return self.broker.authenticate_node(
            authorization, verified_peer_thumbprint=verified_peer_thumbprint)
