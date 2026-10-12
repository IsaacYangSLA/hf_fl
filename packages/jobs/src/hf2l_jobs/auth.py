"""Human server sessions and separate internal node authentication."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import String, Text, delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column

from .config import Settings, origin
from .domain import Error, utcnow
from .models import AuthSession, Base, UTCDateTime
from .oidc import OIDCProvider, ProviderError

SESSION_IDLE = timedelta(minutes=30)
SESSION_ABSOLUTE = timedelta(hours=8)
IDENTITY_RECHECK = timedelta(minutes=15)
LOGIN_LIFETIME = timedelta(minutes=10)
_COOKIE = re.compile(r"^[A-Za-z0-9_-]{40,128}$")


class AuthError(Error):
    def __init__(self, status: int, code: str, headers: dict | None = None):
        self.status = status
        self.code = code
        self.headers = headers or ({"WWW-Authenticate": "Bearer"} if status == 401 else {})
        super().__init__(status, code)


def principal_id(issuer: str, subject: str) -> str:
    return hashlib.sha256(json.dumps([issuer, subject], separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class Principal:
    id: str
    issuer: str
    subject: str
    platform_operator: bool = False

    @property
    def principal_id(self):
        return self.id

    @property
    def display_name(self):
        return self.subject


@dataclass(frozen=True)
class LoginStart:
    authorization_url: str
    state_cookie: str


@dataclass(frozen=True)
class SessionIssue:
    session_token: str
    csrf_token: str
    principal: Principal


class LoginAttempt(Base):
    __tablename__ = "auth_login_attempts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    cookie_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    verifier: Mapped[str] = mapped_column(Text, nullable=False)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[object] = mapped_column(UTCDateTime, nullable=False, index=True)
    used_at: Mapped[object | None] = mapped_column(UTCDateTime, nullable=True)


class LogoutReplay(Base):
    __tablename__ = "auth_logout_replays"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[object] = mapped_column(UTCDateTime, nullable=False, index=True)


class AuthService:
    def __init__(self, session_factory, settings: Settings, oidc_provider: OIDCProvider | None = None,
                 node_grant_validator=None, clock=utcnow):
        self.sessions = session_factory
        self.settings = settings.validate()
        self.provider = oidc_provider or OIDCProvider(settings.oidc)
        self.node_grant_validator = node_grant_validator
        self.clock = clock
        self._cleanup_after = None

    def _principal(self, issuer: str, subject: str) -> Principal:
        identifier = principal_id(issuer, subject)
        return Principal(identifier, issuer, subject, identifier in self.settings.platform_operator_ids)

    def _provider(self, method, *args):
        try:
            return method(*args)
        except ProviderError as error:
            raise AuthError(error.status, error.code, {"Retry-After": "3"} if error.status == 503 else None) from None

    @staticmethod
    def _token_hash(token: str) -> str:
        if not isinstance(token, str) or not _COOKIE.fullmatch(token):
            raise AuthError(401, "invalid_session")
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    def _csrf(self, session_token: str) -> str:
        self._token_hash(session_token)
        return hmac.new(self.settings.session_secret.encode("utf-8"),
                        b"hf2l-jobs-csrf:" + session_token.encode("ascii"), hashlib.sha256).hexdigest()

    def prune_expired(self) -> dict[str, int]:
        """Remove only expired authentication records, preserving job history."""
        now = self.clock()
        with self.sessions.begin() as session:
            removed = {
                "sessions": session.execute(delete(AuthSession).where(AuthSession.expires_at <= now)).rowcount,
                "login_attempts": session.execute(delete(LoginAttempt).where(LoginAttempt.expires_at <= now)).rowcount,
                "logout_replays": session.execute(delete(LogoutReplay).where(LogoutReplay.expires_at <= now)).rowcount,
            }
        self._cleanup_after = now + timedelta(minutes=1)
        return removed

    def begin_login(self) -> LoginStart:
        if self._cleanup_after is None or self.clock() >= self._cleanup_after:
            self.prune_expired()
        state = secrets.token_urlsafe(32)
        cookie = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        nonce = secrets.token_urlsafe(32)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        url = self._provider(self.provider.authorization_url, state, nonce, challenge)
        with self.sessions.begin() as session:
            session.add(LoginAttempt(id=self._token_hash(state), cookie_hash=self._token_hash(cookie),
                                     verifier=verifier, nonce=nonce, expires_at=self.clock() + LOGIN_LIFETIME))
        return LoginStart(url, cookie)

    def finish_login(self, code: str, state: str, state_cookie: str) -> SessionIssue:
        state_hash = self._token_hash(state)
        cookie_hash = self._token_hash(state_cookie)
        now = self.clock()
        with self.sessions.begin() as session:
            attempt = session.get(LoginAttempt, state_hash)
            if attempt is None or attempt.used_at is not None or now >= attempt.expires_at or not hmac.compare_digest(attempt.cookie_hash, cookie_hash):
                raise AuthError(401, "invalid_authorization_state")
            verifier, nonce = attempt.verifier, attempt.nonce
            updated = session.execute(update(LoginAttempt).where(
                LoginAttempt.id == state_hash, LoginAttempt.used_at.is_(None), LoginAttempt.expires_at > now
            ).values(used_at=now, verifier="", nonce=""))
            if updated.rowcount != 1:
                raise AuthError(401, "invalid_authorization_state")
        identity = self._provider(self.provider.exchange_code, code, verifier, nonce)
        principal = self._principal(identity.issuer, identity.subject)
        token = secrets.token_urlsafe(32)
        csrf = self._csrf(token)
        with self.sessions.begin() as session:
            session.add(AuthSession(
                id=self._token_hash(token), principal_id=principal.id, issuer=identity.issuer,
                subject=identity.subject, csrf_hash=hashlib.sha256(csrf.encode("ascii")).hexdigest(),
                access_token=identity.access_token or None, provider_sid=identity.provider_sid,
                created_at=now, last_seen_at=now, checked_at=now,
                expires_at=now + SESSION_IDLE, absolute_expires_at=now + SESSION_ABSOLUTE,
            ))
        return SessionIssue(token, csrf, principal)

    def authenticate_session(self, token: str, touch: bool = True) -> Principal:
        identifier = self._token_hash(token)
        now = self.clock()
        with self.sessions.begin() as session:
            row = session.execute(select(AuthSession).where(AuthSession.id == identifier).with_for_update()).scalar_one_or_none()
            if row is None or row.revoked_at is not None:
                raise AuthError(401, "invalid_session")
            absolute = row.absolute_expires_at or row.created_at + SESSION_ABSOLUTE
            if now >= row.expires_at or now >= absolute or now - row.last_seen_at >= SESSION_IDLE:
                raise AuthError(401, "session_expired")
            if row.issuer != self.settings.oidc.issuer or row.principal_id != principal_id(row.issuer, row.subject):
                raise AuthError(401, "invalid_session")
            if now - row.checked_at >= IDENTITY_RECHECK:
                active = self._provider(self.provider.online_check, row.access_token or "", row.subject)
                if not active:
                    # Commit revocation even though the request will be rejected.
                    row.revoked_at = now
                    row.access_token = None
                    session.flush()
                    invalid = True
                else:
                    row.checked_at = now
                    invalid = False
            else:
                invalid = False
            if not invalid and touch:
                row.last_seen_at = now
                row.expires_at = min(now + SESSION_IDLE, absolute)
            principal = self._principal(row.issuer, row.subject)
        if invalid:
            raise AuthError(401, "identity_revoked")
        return principal

    def authenticate_request(self, authorization: str = "", session_token: str = "", touch: bool = True) -> Principal:
        if authorization:
            if session_token:
                raise AuthError(401, "ambiguous_authentication")
            try:
                scheme, token = authorization.split(" ", 1)
                if scheme.lower() != "bearer" or not token or " " in token:
                    raise ValueError()
                identity = self._provider(self.provider.authenticate_access_token, token)
                return self._principal(identity.issuer, identity.subject)
            except (ValueError, AttributeError):
                raise AuthError(401, "invalid_access_token") from None
        if not session_token:
            raise AuthError(401, "authentication_required")
        return self.authenticate_session(session_token, touch=touch)

    def session_info(self, token: str) -> dict:
        principal = self.authenticate_session(token)
        return {"authenticated": True, "principal": {"principal_id": principal.id, "display_name": principal.display_name},
                "csrf_token": self._csrf(token), "permissions": ["platform_operator"] if principal.platform_operator else [],
                "login_url": "/auth/login"}

    def require_csrf(self, session_token: str, csrf_token: str, origin: str = "") -> None:
        expected = self._csrf(session_token)
        if not isinstance(csrf_token, str) or not re.fullmatch(r"[0-9a-f]{64}", csrf_token) or not hmac.compare_digest(csrf_token, expected):
            raise AuthError(403, "csrf_invalid")
        if origin != self._application_origin():
            raise AuthError(403, "csrf_origin_invalid")
        with self.sessions() as session:
            row = session.get(AuthSession, self._token_hash(session_token))
            if row is None or row.revoked_at is not None:
                raise AuthError(401, "invalid_session")
            if not hmac.compare_digest(row.csrf_hash, hashlib.sha256(expected.encode("ascii")).hexdigest()):
                raise AuthError(403, "csrf_invalid")

    def _application_origin(self):
        return origin(self.settings.oidc.redirect_uri)

    def logout(self, session_token: str, csrf_token: str, origin: str = "") -> None:
        self.require_csrf(session_token, csrf_token, origin)
        with self.sessions.begin() as session:
            row = session.get(AuthSession, self._token_hash(session_token))
            if row is not None:
                row.revoked_at = self.clock()
                row.access_token = None

    def revoke_subject(self, issuer: str, subject: str) -> int:
        with self.sessions.begin() as session:
            result = session.execute(update(AuthSession).where(
                AuthSession.issuer == issuer, AuthSession.subject == subject, AuthSession.revoked_at.is_(None)
            ).values(revoked_at=self.clock(), access_token=None))
            return result.rowcount

    def backchannel_logout(self, logout_token: str) -> None:
        subject, sid, jti = self._provider(self.provider.logout_identity, logout_token)
        now = self.clock()
        replay = hashlib.sha256(json.dumps([self.settings.oidc.issuer, jti], separators=(",", ":")).encode()).hexdigest()
        try:
            with self.sessions.begin() as session:
                session.add(LogoutReplay(id=replay, expires_at=now + timedelta(minutes=5)))
                session.flush()
                statement = update(AuthSession).where(
                    AuthSession.issuer == self.settings.oidc.issuer, AuthSession.revoked_at.is_(None)
                )
                if subject:
                    statement = statement.where(AuthSession.subject == subject)
                if sid:
                    statement = statement.where(AuthSession.provider_sid == sid)
                if not subject and not sid:
                    raise AuthError(401, "invalid_logout_token")
                session.execute(statement.values(revoked_at=now, access_token=None))
        except IntegrityError:
            raise AuthError(401, "logout_token_replayed") from None

    def authenticate_node(self, authorization: str, peer_thumbprint: str):
        if self.settings.broker is None:
            raise AuthError(503, "node_authentication_unconfigured")
        from .broker import BrokerError, WorkloadBroker
        try:
            return WorkloadBroker(self.settings.broker, node_grant_validator=self.node_grant_validator).authenticate_node(
                authorization, verified_peer_thumbprint=peer_thumbprint)
        except BrokerError as error:
            raise AuthError(error.status, error.code) from None
