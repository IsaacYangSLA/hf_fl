"""JWT authentication with a fixed issuer, audience, algorithm and key source."""
from dataclasses import dataclass
import hashlib
import json

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
        self.jwks = jwt.PyJWKClient(settings.jwks_url) if settings.jwks_url else None

    def authenticate(self, authorization: str) -> Principal:
        try:
            scheme, token = authorization.split(" ", 1)
            if scheme.lower() != "bearer" or not token:
                raise ValueError()
            if jwt.get_unverified_header(token).get("typ") != "at+jwt":
                raise ValueError()
            key = self.jwks.get_signing_key_from_jwt(token).key if self.jwks else self.settings.public_key
            claims = jwt.decode(token, key, algorithms=["RS256"],
                                audience=self.settings.audience, issuer=self.settings.issuer,
                                options={"require": ["exp", "iat", "iss", "aud", "sub"]})
            subject = claims["sub"]
            if not isinstance(subject, str) or not subject:
                raise ValueError()
            if "exchange" not in str(claims.get("scope", "")).split():
                raise ValueError()
        except (ValueError, jwt.PyJWTError):
            raise HTTPException(401, "invalid_access_token", headers={"WWW-Authenticate": "Bearer"})
        return Principal(principal_id(self.settings.issuer, subject), subject,
                         subject == self.settings.admin_subject)
