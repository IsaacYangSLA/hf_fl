"""Fixed-issuer OIDC authorization-code/PKCE and JWT verification."""
from __future__ import annotations

import base64
import hashlib
import hmac
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .config import OIDCSettings

LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


class ProviderError(Exception):
    def __init__(self, status: int, code: str):
        self.status = status
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Identity:
    issuer: str
    subject: str
    access_token: str = ""
    provider_sid: str | None = None


def _half_hash(value: str) -> str:
    digest = hashlib.sha256(value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")


class OIDCProvider:
    """Never chooses an issuer, endpoint or verification algorithm from a token."""

    def __init__(self, settings: OIDCSettings, client: httpx.Client | None = None):
        self.settings = settings.validate()
        if settings.public_key:
            try:
                key = serialization.load_pem_public_key(settings.public_key.encode("utf-8"))
                if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
                    raise ValueError()
            except (TypeError, ValueError):
                raise ValueError("OIDC verification requires an RSA key of at least 2048 bits") from None
        self.client = client or httpx.Client(timeout=settings.timeout_seconds, follow_redirects=False)
        self._discovery = None
        self._keys: dict[str, object] = {}
        self._keys_until = 0.0
        self._keys_lock = threading.Lock()
        self._last_refresh = 0.0

    def _request(self, method: str, url: str, **kwargs) -> dict:
        try:
            self.settings.validate_endpoint(url)
            response = self.client.request(method, url, timeout=self.settings.timeout_seconds,
                                           follow_redirects=False, **kwargs)
            if response.status_code != 200:
                raise ProviderError(503, "identity_provider_unavailable")
            if len(response.content) > 1_048_576:
                raise ProviderError(503, "identity_provider_invalid_response")
            data = response.json()
            if not isinstance(data, dict):
                raise ProviderError(503, "identity_provider_invalid_response")
            return data
        except ProviderError:
            raise
        except (httpx.HTTPError, ValueError, TypeError):
            raise ProviderError(503, "identity_provider_unavailable") from None

    def discovery(self) -> dict:
        if self._discovery is None:
            data = self._request("GET", self.settings.issuer.rstrip("/") + "/.well-known/openid-configuration")
            if data.get("issuer") != self.settings.issuer:
                raise ProviderError(503, "identity_provider_issuer_mismatch")
            for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                if not isinstance(data.get(key), str):
                    raise ProviderError(503, "identity_provider_invalid_response")
                try:
                    self.settings.validate_endpoint(data[key])
                except ValueError:
                    raise ProviderError(503, "identity_provider_endpoint_rejected") from None
            if "S256" not in data.get("code_challenge_methods_supported", []):
                raise ProviderError(503, "identity_provider_pkce_required")
            if "RS256" not in data.get("id_token_signing_alg_values_supported", []):
                raise ProviderError(503, "identity_provider_algorithm_rejected")
            endpoint = data.get("introspection_endpoint")
            if endpoint:
                try:
                    self.settings.validate_endpoint(endpoint)
                except ValueError:
                    raise ProviderError(503, "identity_provider_endpoint_rejected") from None
            self._discovery = data
        return self._discovery

    def authorization_url(self, state: str, nonce: str, code_challenge: str) -> str:
        endpoint = self.discovery()["authorization_endpoint"]
        return endpoint + ("&" if "?" in endpoint else "?") + urlencode({
            "response_type": "code", "response_mode": "query",
            "client_id": self.settings.client_id, "redirect_uri": self.settings.redirect_uri,
            "scope": "openid", "state": state, "nonce": nonce,
            "code_challenge": code_challenge, "code_challenge_method": "S256",
            "prompt": "login",
        })

    def _signing_key(self, token: str):
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or any(key in header for key in ("jku", "x5u", "jwk")):
            raise jwt.InvalidTokenError("Disallowed token key or algorithm")
        if self.settings.public_key:
            return self.settings.public_key
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid or len(kid) > 256:
            raise jwt.InvalidTokenError("Missing key identifier")
        now = time.monotonic()
        with self._keys_lock:
            if now < self._keys_until and kid in self._keys:
                return self._keys[kid]
            # Unknown keys cannot cause an unbounded series of network lookups.
            if now < self._keys_until and now - self._last_refresh < 2:
                raise jwt.InvalidTokenError("Unknown key identifier")
            data = self._request("GET", self.settings.jwks_url or self.discovery()["jwks_uri"])
            keys = data.get("keys")
            if not isinstance(keys, list) or len(keys) > 100:
                raise ProviderError(503, "identity_provider_invalid_jwks")
            parsed = {}
            try:
                for value in keys:
                    if not isinstance(value, dict) or value.get("kty") != "RSA":
                        continue
                    if value.get("use", "sig") != "sig" or value.get("alg", "RS256") != "RS256":
                        continue
                    if "d" in value:
                        raise ValueError("Private JWKS key")
                    key_id = value.get("kid")
                    if not isinstance(key_id, str) or not key_id or key_id in parsed:
                        raise ValueError("Invalid or duplicate JWKS key")
                    key = jwt.PyJWK.from_dict(value, algorithm="RS256").key
                    if key.key_size < 2048:
                        raise ValueError("Weak JWKS key")
                    parsed[key_id] = key
            except (ValueError, jwt.PyJWTError):
                raise ProviderError(503, "identity_provider_invalid_jwks") from None
            self._keys = parsed
            self._last_refresh = now
            self._keys_until = now + self.settings.jwks_cache_seconds
            if kid not in parsed:
                raise jwt.InvalidTokenError("Unknown key identifier")
            return parsed[kid]

    def _decode(self, token: str, audience: str, required=()):
        if not isinstance(token, str) or not token or len(token) > 65_536:
            raise ProviderError(401, "invalid_access_token")
        try:
            claims = jwt.decode(token, self._signing_key(token), algorithms=["RS256"],
                                issuer=self.settings.issuer, audience=audience,
                                options={"require": ["iss", "sub", "aud", "iat", "exp", *required]})
            subject = claims["sub"]
            if not isinstance(subject, str) or not subject or len(subject) > 256:
                raise ValueError()
            if type(claims["iat"]) not in (int, float) or type(claims["exp"]) not in (int, float):
                raise ValueError()
            if claims["exp"] <= claims["iat"]:
                raise ValueError()
            return claims
        except ProviderError:
            raise
        except (ValueError, TypeError, OverflowError, jwt.PyJWTError):
            raise ProviderError(401, "invalid_access_token") from None

    def exchange_code(self, code: str, verifier: str, nonce: str) -> Identity:
        if not isinstance(code, str) or not 1 <= len(code) <= 8192:
            raise ProviderError(401, "invalid_authorization_response")
        data = {"grant_type": "authorization_code", "code": code, "code_verifier": verifier,
                "redirect_uri": self.settings.redirect_uri, "client_id": self.settings.client_id}
        auth = httpx.BasicAuth(self.settings.client_id, self.settings.client_secret) if self.settings.client_secret else None
        result = self._request("POST", self.discovery()["token_endpoint"], data=data, auth=auth)
        token = result.get("id_token")
        access_token = result.get("access_token", "")
        if not isinstance(access_token, str) or len(access_token) > 65_536:
            raise ProviderError(401, "invalid_authorization_response")
        claims = self._decode(token, self.settings.client_id, required=("nonce",))
        if not isinstance(claims.get("nonce"), str) or not claims["nonce"].isascii() or not hmac.compare_digest(claims["nonce"], nonce):
            raise ProviderError(401, "invalid_oidc_nonce")
        audiences = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
        if (len(audiences) > 1 or "azp" in claims) and claims.get("azp") != self.settings.client_id:
            raise ProviderError(401, "invalid_oidc_authorized_party")
        for key, value in (("at_hash", access_token), ("c_hash", code)):
            if key in claims:
                try:
                    if not value or not hmac.compare_digest(claims[key], _half_hash(value)):
                        raise ValueError()
                except (ValueError, TypeError, UnicodeError):
                    raise ProviderError(401, "invalid_oidc_token_hash") from None
        sid = claims.get("sid")
        if sid is not None and (not isinstance(sid, str) or not sid or len(sid) > 256):
            raise ProviderError(401, "invalid_oidc_session")
        return Identity(self.settings.issuer, claims["sub"], access_token, sid)

    def online_check(self, access_token: str, subject: str) -> bool:
        endpoint = self.settings.introspection_url or self.discovery().get("introspection_endpoint")
        if not endpoint:
            raise ProviderError(401, "fresh_authorization_required")
        if not access_token:
            raise ProviderError(401, "fresh_authorization_required")
        data = {"token": access_token, "client_id": self.settings.client_id}
        auth = httpx.BasicAuth(self.settings.client_id, self.settings.client_secret) if self.settings.client_secret else None
        result = self._request("POST", endpoint, data=data, auth=auth)
        if result.get("active") is not True:
            return False
        if result.get("sub") != subject or result.get("iss", self.settings.issuer) != self.settings.issuer:
            return False
        # Provider introspection responses may bind an opaque token using client_id,
        # an audience, or both. At least one verified client binding is required.
        audience = result.get("aud", [])
        audiences = audience if isinstance(audience, list) else [audience]
        clients = {self.settings.client_id, self.settings.audience}
        bound = result.get("client_id") == self.settings.client_id or bool(clients.intersection(audiences))
        if not bound:
            return False
        expires = result.get("exp")
        if expires is not None and (type(expires) not in (int, float) or expires <= time.time()):
            return False
        return True

    def authenticate_access_token(self, token: str) -> Identity:
        try:
            if jwt.get_unverified_header(token).get("typ") != "at+jwt":
                raise ValueError()
        except (ValueError, TypeError, OverflowError, jwt.PyJWTError):
            raise ProviderError(401, "invalid_access_token") from None
        claims = self._decode(token, self.settings.audience)
        scope = claims.get("scope")
        if not isinstance(scope, str) or "jobs" not in scope.split():
            raise ProviderError(401, "invalid_access_scope")
        endpoint = self.settings.introspection_url or self.discovery().get("introspection_endpoint")
        if endpoint:
            if not self.online_check(token, claims["sub"]):
                raise ProviderError(401, "identity_revoked")
        elif time.time() - claims["iat"] >= 900:
            raise ProviderError(401, "fresh_authorization_required")
        return Identity(self.settings.issuer, claims["sub"])

    def logout_identity(self, token: str) -> tuple[str | None, str | None, str]:
        try:
            claims = jwt.decode(token, self._signing_key(token), algorithms=["RS256"],
                                issuer=self.settings.issuer, audience=self.settings.client_id,
                                options={"require": ["iss", "aud", "iat", "jti", "events"]})
            if type(claims["iat"]) not in (int, float) or time.time() - claims["iat"] > 300:
                raise ValueError()
            if "nonce" in claims or claims.get("events") != {LOGOUT_EVENT: {}}:
                raise ValueError()
            sub, sid, jti = claims.get("sub"), claims.get("sid"), claims["jti"]
            if not sub and not sid:
                raise ValueError()
            for value in (sub, sid, jti):
                if value is not None and (not isinstance(value, str) or not value or len(value) > 256):
                    raise ValueError()
            return sub, sid, jti
        except ProviderError:
            raise
        except (ValueError, TypeError, OverflowError, jwt.PyJWTError):
            raise ProviderError(401, "invalid_logout_token") from None
