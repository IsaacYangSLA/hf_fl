"""OIDC/PKCE, hashed session and browser security contracts."""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import time
import tempfile
from pathlib import Path
import unittest
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from hf2l_jobs.auth import AuthError, AuthService, LoginAttempt, principal_id
from hf2l_jobs.config import OIDCSettings, Settings
from hf2l_jobs.database import create_database
from hf2l_jobs.models import AuthSession
from hf2l_jobs.oidc import LOGOUT_EVENT, OIDCProvider, ProviderError


class IssuerFixture:
    issuer = "https://identity.example.test"

    def __init__(self, key):
        self.key = key
        self.active = True
        self.offline = False
        self.introspection = True
        self.subject = "alice"
        self.nonce = ""
        self.challenge = ""
        self.overrides = {}
        self.headers = {"kid": "test-key"}
        self.requests = []
        self.discovery_overrides = {}

    def id_token(self, **changes):
        now = time.time()
        claims = {"iss": self.issuer, "sub": self.subject, "aud": "dashboard",
                  "iat": now, "exp": now + 600, "nonce": self.nonce, "sid": "provider-session"}
        claims.update(self.overrides)
        claims.update(changes)
        return jwt.encode(claims, self.key, algorithm="RS256", headers=self.headers)

    def access_token(self, **changes):
        now = time.time()
        claims = {"iss": self.issuer, "sub": self.subject, "aud": "hf2l-jobs",
                  "iat": now, "exp": now + 600, "scope": "jobs"}
        claims.update(changes)
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "test-key", "typ": "at+jwt"})

    def handle(self, request):
        self.requests.append(request)
        if self.offline:
            raise httpx.ConnectError("synthetic issuer outage")
        if request.url.path.endswith("openid-configuration"):
            data = {"issuer": self.issuer, "authorization_endpoint": self.issuer + "/authorize",
                    "token_endpoint": self.issuer + "/token", "jwks_uri": self.issuer + "/jwks",
                    "code_challenge_methods_supported": ["S256"], "id_token_signing_alg_values_supported": ["RS256"]}
            if self.introspection:
                data["introspection_endpoint"] = self.issuer + "/introspect"
            data.update(self.discovery_overrides)
            return httpx.Response(200, json=data)
        if request.url.path == "/jwks":
            jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
            jwk.update(kid="test-key", use="sig", alg="RS256")
            return httpx.Response(200, json={"keys": [jwk]})
        if request.url.path == "/token":
            body = parse_qs(request.content.decode())
            verifier = body["code_verifier"][0]
            actual = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            if actual != self.challenge or body.get("redirect_uri") != ["https://jobs.example.test/auth/callback"]:
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"id_token": self.id_token(), "access_token": "opaque-access"})
        if request.url.path == "/introspect":
            return httpx.Response(200, json={"active": self.active, "sub": self.subject, "client_id": "dashboard", "exp": time.time() + 600})
        return httpx.Response(404)


class AuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.fixture = IssuerFixture(self.key)
        self.oidc = OIDCSettings(issuer=self.fixture.issuer, client_id="dashboard",
                                 redirect_uri="https://jobs.example.test/auth/callback")
        self.settings = Settings(database_url="sqlite://", cursor_secret="c" * 32,
                                 session_secret="s" * 32, oidc=self.oidc)
        self.provider = OIDCProvider(self.oidc, httpx.Client(transport=httpx.MockTransport(self.fixture.handle)))
        self.db = create_database("sqlite://")
        self.now = datetime.now(timezone.utc)
        self.auth = AuthService(self.db.session_factory, self.settings, self.provider, clock=lambda: self.now)
        self.addCleanup(self.db.close)
        self.addCleanup(self.provider.client.close)

    def start(self):
        start = self.auth.begin_login()
        values = parse_qs(urlsplit(start.authorization_url).query)
        self.fixture.nonce = values["nonce"][0]
        self.fixture.challenge = values["code_challenge"][0]
        return start, values["state"][0]

    def login(self):
        start, state = self.start()
        return self.auth.finish_login("test-code", state, start.state_cookie)

    def test_authorization_code_uses_pkce_nonce_and_exact_redirect(self):
        start, state = self.start()
        values = parse_qs(urlsplit(start.authorization_url).query)
        self.assertEqual(values["response_type"], ["code"])
        self.assertEqual(values["code_challenge_method"], ["S256"])
        self.assertEqual(values["redirect_uri"], ["https://jobs.example.test/auth/callback"])
        self.assertNotIn("client_secret", start.authorization_url)
        issued = self.auth.finish_login("test-code", state, start.state_cookie)
        self.assertEqual(issued.principal.id, principal_id(self.fixture.issuer, "alice"))
        self.assertEqual(self.auth.authenticate_session(issued.session_token), issued.principal)

    def test_session_database_stores_only_cookie_digest(self):
        issued = self.login()
        with self.db.sessions() as session:
            row = session.get(AuthSession, hashlib.sha256(issued.session_token.encode()).hexdigest())
            self.assertIsNotNone(row)
            self.assertNotEqual(row.id, issued.session_token)
            self.assertNotEqual(row.csrf_hash, issued.csrf_token)
            attempt = session.query(LoginAttempt).one()
            self.assertEqual(attempt.verifier, "")
            self.assertEqual(attempt.nonce, "")

    def test_authorization_state_is_bound_to_login_cookie(self):
        start, state = self.start()
        with self.assertRaises(AuthError) as error:
            self.auth.finish_login("test-code", state, "x" * 43)
        self.assertEqual(error.exception.code, "invalid_authorization_state")
        self.assertFalse(any(request.url.path == "/token" for request in self.fixture.requests))

    def test_state_is_one_time_and_expired_state_never_exchanges_code(self):
        start, state = self.start()
        self.auth.finish_login("test-code", state, start.state_cookie)
        with self.assertRaises(AuthError):
            self.auth.finish_login("test-code", state, start.state_cookie)
        start, state = self.start()
        self.now += timedelta(minutes=11)
        calls = len(self.fixture.requests)
        with self.assertRaises(AuthError):
            self.auth.finish_login("test-code", state, start.state_cookie)
        self.assertEqual(len(self.fixture.requests), calls)

    def test_nonce_mismatch_rejected_after_code_exchange(self):
        self.fixture.overrides["nonce"] = "wrong"
        with self.assertRaises(AuthError) as error:
            self.login()
        self.assertEqual(error.exception.code, "invalid_oidc_nonce")

    def test_wrong_issuer_audience_or_authorized_party_rejected(self):
        for changes in ({"iss": "https://attacker.example"}, {"aud": "foreign-client"},
                        {"aud": ["dashboard", "foreign"], "azp": "foreign"},
                        {"azp": "foreign"}, {"at_hash": "forged"}, {"c_hash": "forged"}):
            with self.subTest(changes=changes):
                self.fixture.overrides = changes
                with self.assertRaises(AuthError):
                    self.login()

    def test_key_url_from_token_is_never_fetched(self):
        self.fixture.headers["jku"] = "https://attacker.example/keys"
        with self.assertRaises(AuthError):
            self.login()
        self.assertTrue(all(request.url.host == "identity.example.test" for request in self.fixture.requests))

    def test_signature_algorithm_and_expiry_rejected(self):
        with self.assertRaises(ProviderError):
            self.provider.authenticate_access_token(jwt.encode({"iss": self.fixture.issuer, "sub": "alice", "aud": "hf2l-jobs",
                                                                 "iat": time.time(), "exp": time.time() + 600, "scope": "jobs"},
                                                                "not-an-rsa-key-" * 4, algorithm="HS256", headers={"typ": "at+jwt"}))
        with self.assertRaises(ProviderError):
            self.provider.authenticate_access_token(self.fixture.access_token(iat=time.time() - 700, exp=time.time() - 1))

    def test_jwks_keys_cached_without_per_request_network_fetch(self):
        self.login()
        self.auth.authenticate_request(authorization="Bearer " + self.fixture.access_token())
        self.auth.authenticate_request(authorization="Bearer " + self.fixture.access_token())
        self.assertEqual(sum(request.url.path == "/jwks" for request in self.fixture.requests), 1)

    def test_fixed_discovery_issuer_and_endpoint_allowlist(self):
        for changes in ({"issuer": "https://attacker.example"},
                        {"jwks_uri": "https://attacker.example/jwks"},
                        {"token_endpoint": "http://169.254.169.254/token"},
                        {"code_challenge_methods_supported": ["plain"]}):
            with self.subTest(changes=changes):
                self.fixture.discovery_overrides = changes
                provider = OIDCProvider(self.oidc, self.provider.client)
                with self.assertRaises(ProviderError):
                    provider.discovery()

    def test_idle_session_expires_at_thirty_minutes(self):
        issued = self.login()
        self.now += timedelta(minutes=30)
        with self.assertRaises(AuthError) as error:
            self.auth.authenticate_session(issued.session_token)
        self.assertEqual(error.exception.code, "session_expired")

    def test_absolute_expiry_does_not_extend_with_activity(self):
        issued = self.login()
        for _ in range(47):
            self.now += timedelta(minutes=10)
            self.auth.authenticate_session(issued.session_token)
        self.now += timedelta(minutes=10)
        with self.assertRaises(AuthError) as error:
            self.auth.authenticate_session(issued.session_token)
        self.assertEqual(error.exception.code, "session_expired")

    def test_identity_online_rechecked_at_fifteen_minutes(self):
        issued = self.login()
        self.now += timedelta(minutes=14)
        self.auth.authenticate_session(issued.session_token)
        self.assertFalse(any(request.url.path == "/introspect" for request in self.fixture.requests))
        self.now += timedelta(minutes=1)
        self.auth.authenticate_session(issued.session_token)
        self.assertEqual(sum(request.url.path == "/introspect" for request in self.fixture.requests), 1)

    def test_disabled_identity_revokes_session_and_fails_closed(self):
        issued = self.login()
        self.now += timedelta(minutes=15)
        self.fixture.active = False
        with self.assertRaises(AuthError) as error:
            self.auth.authenticate_session(issued.session_token)
        self.assertEqual(error.exception.code, "identity_revoked")
        self.fixture.active = True
        with self.assertRaises(AuthError):
            self.auth.authenticate_session(issued.session_token)

    def test_provider_outage_fails_closed_without_extending_session(self):
        issued = self.login()
        self.now += timedelta(minutes=15)
        self.fixture.offline = True
        with self.assertRaises(AuthError) as error:
            self.auth.authenticate_session(issued.session_token)
        self.assertEqual(error.exception.status, 503)
        with self.db.sessions() as session:
            row = session.query(AuthSession).one()
            self.assertEqual(row.last_seen_at, self.now - timedelta(minutes=15))

    def test_missing_online_check_requires_fresh_authorization(self):
        self.fixture.introspection = False
        issued = self.login()
        self.now += timedelta(minutes=15)
        with self.assertRaises(AuthError) as error:
            self.auth.authenticate_session(issued.session_token)
        self.assertEqual(error.exception.code, "fresh_authorization_required")

    def test_csrf_bound_to_session_and_same_origin(self):
        first, second = self.login(), self.login()
        self.auth.require_csrf(first.session_token, first.csrf_token, origin="https://jobs.example.test")
        for token, csrf, value in ((first.session_token, "", ""), (first.session_token, second.csrf_token, ""),
                                   (first.session_token, first.csrf_token, "https://evil.example"),
                                   (first.session_token, first.csrf_token, ""),
                                   (first.session_token, first.csrf_token, "null")):
            with self.subTest(value=value):
                with self.assertRaises(AuthError):
                    self.auth.require_csrf(token, csrf, origin=value)

    def test_session_info_has_csrf_but_no_access_or_session_tokens(self):
        issued = self.login()
        info = self.auth.session_info(issued.session_token)
        self.assertEqual(info["csrf_token"], issued.csrf_token)
        self.assertEqual(info["principal"]["principal_id"], issued.principal.id)
        self.assertNotIn(issued.session_token, json.dumps(info))
        self.assertNotIn("opaque-access", json.dumps(info))

    def test_logout_requires_csrf_and_revokes_existing_session(self):
        issued = self.login()
        with self.assertRaises(AuthError):
            self.auth.logout(issued.session_token, "")
        self.auth.logout(issued.session_token, issued.csrf_token, origin="https://jobs.example.test")
        with self.assertRaises(AuthError):
            self.auth.authenticate_session(issued.session_token)

    def test_platform_operator_is_explicit_config_not_token_claim(self):
        token = self.fixture.access_token(platform_operator=True, roles=["admin"], admin=True)
        self.assertFalse(self.auth.authenticate_request(authorization="Bearer " + token).platform_operator)
        settings = dataclasses.replace(self.settings, platform_operator_ids=(principal_id(self.fixture.issuer, "alice"),))
        auth = AuthService(self.db.sessions, settings, self.provider)
        self.assertTrue(auth.authenticate_request(authorization="Bearer " + token).platform_operator)

    def test_bearer_scope_audience_issuer_and_malformed_tokens_rejected(self):
        for token in ("garbage", self.fixture.access_token(scope="exchange"),
                      self.fixture.access_token(aud="exchange"), self.fixture.access_token(iss="https://evil.example")):
            with self.subTest(token=token[:12]):
                with self.assertRaises(AuthError):
                    self.auth.authenticate_request(authorization="Bearer " + token)

    def test_ambiguous_session_and_bearer_and_missing_auth_rejected(self):
        issued = self.login()
        with self.assertRaises(AuthError):
            self.auth.authenticate_request(authorization="Bearer " + self.fixture.access_token(), session_token=issued.session_token)
        with self.assertRaises(AuthError):
            self.auth.authenticate_request()

    def test_backchannel_logout_subject_and_sid_revoke_and_replay_rejected(self):
        issued = self.login()
        now = time.time()
        claims = {"iss": self.fixture.issuer, "aud": "dashboard", "iat": now, "jti": "logout-1",
                  "sid": "provider-session", "events": {LOGOUT_EVENT: {}}}
        token = jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "test-key"})
        self.auth.backchannel_logout(token)
        with self.assertRaises(AuthError):
            self.auth.authenticate_session(issued.session_token)
        with self.assertRaises(AuthError) as error:
            self.auth.backchannel_logout(token)
        self.assertEqual(error.exception.code, "logout_token_replayed")

    def test_forged_backchannel_nonce_events_or_issuer_rejected(self):
        self.login()
        now = time.time()
        original = {"iss": self.fixture.issuer, "sub": "alice", "aud": "dashboard", "iat": now,
                    "jti": "logout-2", "events": {LOGOUT_EVENT: {}}}
        for changes in ({"nonce": "login"}, {"events": {}}, {"iss": "https://evil.example"}, {"iat": now - 301}):
            with self.subTest(changes=changes):
                token = jwt.encode({**original, **changes}, self.key, algorithm="RS256", headers={"kid": "test-key"})
                with self.assertRaises(AuthError):
                    self.auth.backchannel_logout(token)

    def test_non_ascii_csrf_and_nonce_fail_cleanly(self):
        issued = self.login()
        with self.assertRaises(AuthError) as error:
            self.auth.require_csrf(issued.session_token, "é" * 64)
        self.assertEqual(error.exception.status, 403)
        self.fixture.overrides["nonce"] = "é" * 43
        with self.assertRaises(AuthError) as error:
            self.login()
        self.assertEqual(error.exception.code, "invalid_oidc_nonce")

    def test_expired_authentication_records_pruned_without_active_session_loss(self):
        first = self.login()
        self.now += timedelta(minutes=16)
        second = self.login()
        self.now += timedelta(minutes=15)
        removed = self.auth.prune_expired()
        self.assertEqual(removed["sessions"], 1)
        self.assertEqual(removed["login_attempts"], 1)
        with self.assertRaises(AuthError):
            self.auth.authenticate_session(first.session_token)
        self.assertEqual(self.auth.authenticate_session(second.session_token).subject, "alice")

    def test_node_auth_unconfigured_fails_closed(self):
        with self.assertRaises(AuthError) as error:
            self.auth.authenticate_node("Bearer anything", "verified-thumb")
        self.assertEqual(error.exception.status, 503)


class ConfigTests(unittest.TestCase):
    def test_server_secrets_are_distinct_bounded_and_hidden(self):
        oidc = OIDCSettings(issuer="https://identity.example.test", client_id="client",
                            client_secret="private-oidc-secret", redirect_uri="https://jobs.example.test/auth/callback")
        settings = Settings(cursor_secret="c" * 32, session_secret="s" * 32, oidc=oidc)
        settings.validate()
        self.assertNotIn("s" * 32, repr(settings))
        self.assertNotIn("private-oidc-secret", repr(settings))
        with self.assertRaises(ValueError):
            dataclasses.replace(settings, session_secret="short").validate()
        with self.assertRaises(ValueError):
            dataclasses.replace(settings, session_secret=settings.cursor_secret).validate()

    def test_tls_allowlist_rejects_remote_http_credentials_and_origin_widening(self):
        for issuer in ("http://identity.example.test", "https://user:pass@identity.example.test"):
            with self.assertRaises(ValueError):
                OIDCSettings(issuer=issuer, client_id="client", redirect_uri="https://jobs.example.test/auth/callback",
                             allow_local_http=True).validate()
        with self.assertRaises(ValueError):
            OIDCSettings(issuer="https://identity.example.test", client_id="client",
                         redirect_uri="https://jobs.example.test/auth/callback", jwks_url="https://foreign.example/jwks").validate()

    def test_env_operational_file_accepts_nodes_and_participants_sections(self):
        with tempfile.TemporaryDirectory(prefix="hf2l-auth-config-") as directory:
            path = Path(directory) / "operational.json"
            data = {"nodes": {"endpoints": []}, "participants": {"external_enabled": True}}
            path.write_text(json.dumps(data), encoding="utf-8")
            with patch.dict("os.environ", {"JOBS_DATABASE_URL": "sqlite://", "JOBS_OPERATIONAL_CONFIG_FILE": str(path)}, clear=True):
                settings = Settings.from_env("database")
                self.assertEqual(dict(settings.extra), data)
                path.write_text(json.dumps({"unapproved_section": {}}), encoding="utf-8")
                with self.assertRaises(ValueError):
                    Settings.from_env("database")

    def test_env_types_alias_conflicts_and_unknown_config_sections_rejected(self):
        with patch.dict("os.environ", {"JOBS_DOCS_ENABLED": "yes"}, clear=True):
            with self.assertRaises(ValueError):
                Settings.from_env("database")
        with patch.dict("os.environ", {"JOBS_DATABASE_URL": "sqlite://", "HF2L_JOBS_DATABASE_URL": "sqlite:///other"}, clear=True):
            with self.assertRaises(ValueError):
                Settings.from_env("database")
        with patch.dict("os.environ", {"JOBS_DATABASE_URL": "sqlite://"}, clear=True):
            self.assertEqual(Settings.from_env("database").database.url, "sqlite://")


if __name__ == "__main__":
    unittest.main()
