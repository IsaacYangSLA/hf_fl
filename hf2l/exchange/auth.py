"""JWT authentication with a fixed issuer, audience, algorithm and key source."""
from dataclasses import dataclass
import hashlib
import json
import threading
import time

import jwt
from fastapi import HTTPException


def principal_id(issuer: str, subject: str) -> str:
    return hashlib.sha256(json.dumps([issuer, subject], separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class Principal:
    id: str
    subject: str
    bootstrap_admin: bool


class Authenticator:
    def __init__(self, settings):
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

    def authenticate(self, authorization: str) -> Principal:
        try:
            scheme, token = authorization.split(" ", 1)
            if scheme.lower() != "bearer" or not token:
                raise ValueError()
            header = jwt.get_unverified_header(token)
            if header.get("typ") != "at+jwt" or header.get("alg") != "RS256":
                raise ValueError()
            key = self.signing_key(token)
            claims = jwt.decode(token, key, algorithms=["RS256"],
                                audience=self.settings.audience, issuer=self.settings.issuer,
                                options={"require": ["exp", "iat", "iss", "aud", "sub"]})
            subject = claims["sub"]
            if not isinstance(subject, str) or not subject:
                raise ValueError()
            if "exchange" not in str(claims.get("scope", "")).split():
                raise ValueError()
        except jwt.PyJWKClientConnectionError:
            raise HTTPException(503, "identity_provider_unavailable", headers={"Retry-After": "3"}) from None
        except (ValueError, jwt.PyJWTError):
            raise HTTPException(401, "invalid_access_token", headers={"WWW-Authenticate": "Bearer"})
        return Principal(principal_id(self.settings.issuer, subject), subject,
                         subject == self.settings.admin_subject)
