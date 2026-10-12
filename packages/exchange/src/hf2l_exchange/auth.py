"""Fixed-issuer access-token validation independent of HTTP frameworks."""
import hashlib
import hmac
import re
import json
import threading
import time
import jwt
from .domain import Error, Principal, WorkloadIdentity, principal_id


_THUMBPRINT = re.compile(r"^[A-Za-z0-9_-]{43}$")


def backend_assertion_headers(secret, method, target, authorization, certificate_thumbprint, timestamp=None):
    """Authenticate verified TLS metadata over the private backend channel.

    Only a trusted TLS terminator may hold this secret. The signature covers the
    complete authorization value and request target, preventing certificate/token
    substitution. Public ingress never consumes these assertions.
    """
    stamp = str(int(time.time()) if timestamp is None else timestamp)
    message = json.dumps([method.upper(), target, authorization, certificate_thumbprint, stamp],
                         separators=(",", ":")).encode()
    signature = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    return {"X-HF2L-Backend-Timestamp": stamp, "X-HF2L-TLS-Thumbprint": certificate_thumbprint,
            "X-HF2L-Backend-Signature": signature}


def verified_backend_thumbprint(settings, method, target, authorization, headers):
    """Return a TLS identity only after authenticating the trusted backend."""
    try:
        values = {str(k).lower(): str(v) for k, v in headers.items()}
        stamp = values["x-hf2l-backend-timestamp"]
        thumbprint = values["x-hf2l-tls-thumbprint"]
        signature = values["x-hf2l-backend-signature"]
        if not settings.workloads_enabled or not _THUMBPRINT.fullmatch(thumbprint):
            raise ValueError()
        if not stamp.isdigit() or abs(time.time() - int(stamp)) > 30:
            raise ValueError()
        expected = backend_assertion_headers(settings.trusted_backend_secret, method, target,
                                             authorization, thumbprint, stamp)
        if not hmac.compare_digest(signature, expected["X-HF2L-Backend-Signature"]):
            raise ValueError()
    except (ValueError, KeyError, TypeError, OverflowError):
        raise Error(401, "invalid_backend_assertion") from None
    return thumbprint


class Authenticator:
    def __init__(self, settings):
        settings.validate()
        self.settings = settings
        self.jwks = jwt.PyJWKClient(settings.jwks_url, timeout=settings.jwks_timeout,
                                    lifespan=settings.jwks_cache_seconds) if settings.jwks_url else None
        self.key_lock = threading.Lock()
        self.retry_after = 0.0

    def signing_key(self, token):
        if not self.jwks:
            return self.settings.public_key
        if time.monotonic() < self.retry_after or not self.key_lock.acquire(timeout=self.settings.jwks_timeout):
            raise jwt.PyJWKClientConnectionError("Key service temporarily unavailable")
        try:
            if time.monotonic() < self.retry_after:
                raise jwt.PyJWKClientConnectionError("Key service temporarily unavailable")
            try:
                return self.jwks.get_signing_key_from_jwt(token).key
            except jwt.PyJWKClientConnectionError:
                self.retry_after = time.monotonic() + 3
                raise
        finally:
            self.key_lock.release()

    def authenticate(self, authorization: str, *, managed=False, certificate_thumbprint="") -> Principal:
        try:
            scheme, token = authorization.split(" ", 1)
            if scheme.lower() != "bearer" or not token:
                raise ValueError()
            header = jwt.get_unverified_header(token)
            if header.get("typ") != "at+jwt" or header.get("alg") != "RS256":
                raise ValueError()
            unverified = jwt.decode(token, options={"verify_signature": False})
            if unverified.get("iss") == self.settings.workload_issuer and self.settings.workloads_enabled:
                if not managed or not _THUMBPRINT.fullmatch(certificate_thumbprint):
                    raise ValueError()
                return self._authenticate_workload(token, certificate_thumbprint)
            key = self.signing_key(token)
            claims = jwt.decode(token, key, algorithms=["RS256"], audience=self.settings.audience,
                                issuer=self.settings.issuer, options={"require": ["exp", "iat", "iss", "aud", "sub"]})
            subject = claims["sub"]
            if not isinstance(subject, str) or not subject or len(subject) > 256:
                raise ValueError()
            if "exchange" not in str(claims.get("scope", "")).split():
                raise ValueError()
        except jwt.PyJWKClientConnectionError:
            raise Error(503, "identity_provider_unavailable", headers={"Retry-After": "3"}) from None
        except (ValueError, AttributeError, TypeError, KeyError, OverflowError, jwt.PyJWTError):
            raise Error(401, "invalid_access_token", headers={"WWW-Authenticate": "Bearer"}) from None
        return Principal(principal_id(self.settings.issuer, subject), subject,
                         bool(self.settings.admin_subject) and subject == self.settings.admin_subject)


    def _authenticate_workload(self, token, certificate_thumbprint):
        claims = jwt.decode(token, self.settings.workload_public_key, algorithms=["RS256"],
                            issuer=self.settings.workload_issuer, audience=self.settings.workload_audience,
                            options={"require": ["exp", "iat", "iss", "aud", "sub", "jti", "space_id",
                                                 "job_id", "attempt_id", "component_id", "epoch", "cnf"]})
        for field, limit in (("sub", 256), ("jti", 64), ("space_id", 64), ("job_id", 128),
                             ("attempt_id", 128), ("component_id", 128)):
            if not isinstance(claims[field], str) or not 1 <= len(claims[field]) <= limit:
                raise ValueError()
        if type(claims["epoch"]) is not int or not 1 <= claims["epoch"] <= 2**63 - 1:
            raise ValueError()
        if any(type(claims[key]) not in {int, float} for key in ("exp", "iat")):
            raise ValueError()
        if not 0 < claims["exp"] - claims["iat"] <= 300:
            raise ValueError()
        cnf = claims["cnf"]
        if not isinstance(cnf, dict) or set(cnf) != {"x5t#S256"}:
            raise ValueError()
        if not hmac.compare_digest(str(cnf["x5t#S256"]), certificate_thumbprint):
            raise ValueError()
        if claims.get("grant_id", claims["jti"]) != claims["jti"]:
            raise ValueError()
        identity = WorkloadIdentity(claims["jti"], claims["space_id"], claims["job_id"],
                                    claims["attempt_id"], claims["component_id"], claims["epoch"],
                                    certificate_thumbprint, float(claims["exp"]))
        return Principal(principal_id(self.settings.workload_issuer, claims["sub"]), claims["sub"],
                         workload=identity)
