"""Registration-bound platform credentials cannot authorize job execution."""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import unittest

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from hf2l_jobs.broker import (
    BrokerError, BrokerSettings, PlatformNodePrincipal, WorkloadBroker, principal_id,
)


class PlatformBrokerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.thumb = base64.urlsafe_b64encode(
            hashlib.sha256(b"registered manager certificate").digest()).decode().rstrip("=")
        cls.other_thumb = base64.urlsafe_b64encode(
            hashlib.sha256(b"unregistered certificate").digest()).decode().rstrip("=")

    def setUp(self):
        self.now = 1_000_000
        self.settings = BrokerSettings(
            "https://workloads.example.test", "exchange-managed", "hf2l-transfer",
            "hf2l-nodes", self.private.public_key(), self.private, key_id="broker-key")
        self.registration = {
            "node_id": "node-a", "pool_id": "pool-a", "registration_id": "registration-1",
            "certificate_thumbprint": self.thumb, "enabled": True, "expires_at": self.now + 1000,
        }
        self.broker = WorkloadBroker(
            self.settings, clock=lambda: self.now,
            node_registration_validator=self.current_registration)

    def current_registration(self, principal):
        return (self.registration["enabled"] and self.registration["expires_at"] > self.now
                and all(getattr(principal, name) == self.registration[name] for name in
                        ("node_id", "pool_id", "registration_id", "certificate_thumbprint")))

    def token(self, **changes):
        values = dict(node_id="node-a", pool_id="pool-a", registration_id="registration-1",
                      certificate_thumbprint=self.thumb)
        values.update(changes)
        return self.broker.issue_node_platform(**values)

    def authenticate(self, token, **changes):
        changes.setdefault("verified_peer_thumbprint", self.thumb)
        return self.broker.authenticate_node_platform("Bearer " + token, **changes)

    def claims(self, token):
        return jwt.decode(token, options={"verify_signature": False})

    def sign(self, claims, *, key=None, headers=None):
        return jwt.encode(claims, key or self.private, algorithm="RS256",
                          headers=headers or {"typ": "at+jwt", "kid": "broker-key"})

    def changed(self, token, **changes):
        claims = self.claims(token)
        claims.update(changes)
        return self.sign(claims)

    def test_signed_platform_identity_and_exact_minimal_claims(self):
        token = self.token()
        claims = self.claims(token)
        self.assertEqual(set(claims), {
            "iss", "aud", "sub", "iat", "nbf", "exp", "jti", "cnf", "token_use",
            "scope", "node_id", "pool_id", "registration_id",
        })
        self.assertEqual(claims["token_use"], "node_platform")
        self.assertEqual(claims["scope"], "qualify")
        self.assertEqual(claims["jti"], "registration-1")
        self.assertEqual(claims["aud"], self.settings.node_audience)
        principal = self.authenticate(token)
        self.assertIsInstance(principal, PlatformNodePrincipal)
        self.assertEqual(principal.subject, "node-platform:node-a")
        self.assertEqual(principal.id, principal_id(self.settings.workload_issuer, principal.subject))
        self.assertEqual(principal.scopes, frozenset({"qualify"}))
        self.assertEqual(principal.expires_at, self.now + 300)
        self.assertEqual(principal.certificate_thumbprint, self.thumb)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            principal.pool_id = "pool-b"

    def test_aliases_and_verification_only_broker(self):
        verifier = WorkloadBroker(
            dataclasses.replace(self.settings, private_key=None),
            clock=lambda: self.now, node_registration_validator=self.current_registration)
        token = self.broker.issue_platform_node(
            node_id="node-a", pool_id="pool-a", registration_id="registration-1",
            certificate_thumbprint=self.thumb)
        principal = verifier.authenticate_platform_node(
            "Bearer " + token, verified_peer_thumbprint=self.thumb)
        self.assertEqual(principal.registration_id, "registration-1")
        with self.assertRaises(BrokerError) as failure:
            verifier.issue_platform_node(
                node_id="node-a", pool_id="pool-a", registration_id="registration-1",
                certificate_thumbprint=self.thumb)
        self.assertEqual(failure.exception.status, 503)

    def test_registration_validator_is_mandatory(self):
        verifier = WorkloadBroker(self.settings, clock=lambda: self.now)
        with self.assertRaises(BrokerError) as failure:
            verifier.authenticate_node_platform(
                "Bearer " + self.token(), verified_peer_thumbprint=self.thumb)
        self.assertEqual(failure.exception.code, "node_registration_unavailable")
        self.assertEqual(failure.exception.status, 503)
        principal = verifier.authenticate_node_platform(
            "Bearer " + self.token(), verified_peer_thumbprint=self.thumb,
            registration_validator=self.current_registration)
        self.assertEqual(principal.registration_id, "registration-1")

    def test_registration_expiration_revocation_and_rotation_are_current(self):
        token = self.token()
        self.authenticate(token)
        for field, value in (
            ("enabled", False), ("expires_at", self.now), ("registration_id", "registration-2"),
            ("pool_id", "pool-b"), ("node_id", "node-b"),
            ("certificate_thumbprint", self.other_thumb),
        ):
            previous = self.registration[field]
            self.registration[field] = value
            with self.subTest(field=field), self.assertRaises(BrokerError):
                self.authenticate(token)
            self.registration[field] = previous

    def test_callback_errors_and_non_boolean_results_fail_closed(self):
        def broken(_):
            raise RuntimeError("operator registration storage unavailable")
        with self.assertRaises(BrokerError) as failure:
            self.authenticate(self.token(), registration_validator=broken)
        self.assertEqual(failure.exception.status, 503)
        for result in (False, None, 1, "yes", {}, []):
            with self.subTest(result=result), self.assertRaises(BrokerError):
                self.authenticate(self.token(), registration_validator=lambda _: result)

    def test_token_requires_the_registered_tls_certificate(self):
        token = self.token()
        for peer in (self.other_thumb, None, "", self.thumb + "=", "forwarded-header"):
            with self.subTest(peer=peer), self.assertRaises(BrokerError):
                self.authenticate(token, verified_peer_thumbprint=peer)
        copied = self.token(certificate_thumbprint=self.other_thumb)
        with self.assertRaises(BrokerError):
            self.authenticate(copied, verified_peer_thumbprint=self.other_thumb)

    def test_platform_token_and_job_tokens_are_not_interchangeable(self):
        token = self.token()
        for audience in ("exchange", "gateway"):
            with self.subTest(audience=audience), self.assertRaises(BrokerError):
                self.broker.authenticate_workload(
                    "Bearer " + token, verified_peer_thumbprint=self.thumb, audience=audience)
        with self.assertRaises(BrokerError):
            self.broker.authenticate_node(
                "Bearer " + token, verified_peer_thumbprint=self.thumb,
                grant_validator=lambda _: True)
        workload = self.broker.issue_workload(
            job_id="job-a", attempt_id="attempt-1", component_id="owner", space_id="space-a",
            grant_id="grant-1", epoch=1, certificate_thumbprint=self.thumb)
        node = self.broker.issue_node(
            node_id="node-a", pool_id="pool-a", job_id="job-a", attempt_id="attempt-1",
            component_id="owner", grant_id="grant-1", epoch=1,
            certificate_thumbprint=self.thumb, scopes=["inspect"])
        for other in (workload, node):
            with self.subTest(token_use=self.claims(other)["token_use"]), self.assertRaises(BrokerError):
                self.authenticate(other, registration_validator=lambda _: True)

    def test_injected_job_claims_and_resources_are_rejected(self):
        token = self.token()
        for name, value in (
            ("job_id", "job-a"), ("attempt_id", "attempt-1"), ("component_id", "owner"),
            ("epoch", 1), ("grant_id", "registration-1"), ("space_id", "space-a"),
            ("participant_id", "alice"), ("resources", {}),
        ):
            with self.subTest(name=name), self.assertRaises(BrokerError):
                self.authenticate(self.changed(token, **{name: value}))

    def test_only_platform_kind_and_qualification_scope_are_accepted(self):
        token = self.token()
        for changes in (
            {"token_use": "node"}, {"token_use": "workload"}, {"token_use": ""},
            {"scope": "qualify reserve"}, {"scope": "inspect"}, {"scope": ["qualify"]},
            {"scope": ""}, {"scope": "qualify qualify"},
        ):
            with self.subTest(changes=changes), self.assertRaises(BrokerError):
                self.authenticate(self.changed(token, **changes))

    def test_registration_subject_and_identifiers_are_bound(self):
        token = self.token()
        for changes in (
            {"registration_id": "registration-2"}, {"jti": "registration-2"},
            {"registration_id": "../escape"}, {"node_id": "node/b"}, {"pool_id": []},
            {"sub": "node:node-a"}, {"sub": "node-platform:node-b"},
            {"node_id": "node-b"}, {"pool_id": "pool-b"},
        ):
            with self.subTest(changes=changes), self.assertRaises(BrokerError):
                self.authenticate(self.changed(token, **changes))

    def test_required_claims_cannot_be_removed(self):
        token = self.token()
        for name in self.claims(token):
            claims = self.claims(token)
            claims.pop(name)
            with self.subTest(name=name), self.assertRaises(BrokerError):
                self.authenticate(self.sign(claims))

    def test_lifetime_and_exact_expiration(self):
        for lifetime in (0, -1, 301, True, 1.0):
            with self.subTest(lifetime=lifetime), self.assertRaises(BrokerError):
                self.token(ttl_seconds=lifetime)
        token = self.token(ttl_seconds=1)
        self.authenticate(token)
        self.now += 1
        with self.assertRaises(BrokerError):
            self.authenticate(token)
        self.now -= 1
        for changes in (
            {"exp": self.now + 301}, {"exp": self.now}, {"exp": float(self.now + 300)},
            {"iat": True}, {"nbf": self.now - 1},
            {"iat": self.now + 1, "nbf": self.now + 1},
        ):
            with self.subTest(changes=changes), self.assertRaises(BrokerError):
                self.authenticate(self.changed(self.token(), **changes))

    def test_fixed_issuer_audience_signature_and_header_checks_apply(self):
        token = self.token()
        for changes in (
            {"iss": "https://untrusted.test"}, {"aud": "exchange-managed"},
            {"aud": ["hf2l-nodes", "other"]}, {"cnf": {}},
            {"cnf": {"x5t#S256": self.thumb, "jwk": {}}},
        ):
            with self.subTest(changes=changes), self.assertRaises(BrokerError):
                self.authenticate(self.changed(token, **changes))
        with self.assertRaises(BrokerError):
            self.authenticate(self.sign(self.claims(token), key=self.other_private))
        for headers in (
            {"typ": "at+jwt", "kid": "wrong-key"},
            {"typ": "JWT", "kid": "broker-key"},
            {"typ": "at+jwt", "kid": "broker-key", "jku": "https://untrusted.test"},
        ):
            with self.subTest(headers=headers), self.assertRaises(BrokerError):
                self.authenticate(self.sign(self.claims(token), headers=headers))
        for algorithm, key in (("none", None), ("HS256", b"untrusted-key-with-32-bytes-123456")):
            forged = jwt.encode(self.claims(token), key, algorithm=algorithm,
                                headers={"typ": "at+jwt"})
            with self.subTest(algorithm=algorithm), self.assertRaises(BrokerError):
                self.authenticate(forged)

    def test_invalid_issue_bindings_rejected(self):
        for changes in (
            {"node_id": "../node"}, {"pool_id": ""}, {"registration_id": []},
            {"certificate_thumbprint": self.thumb + "="},
        ):
            with self.subTest(changes=changes), self.assertRaises(BrokerError):
                self.token(**changes)


if __name__ == "__main__":
    unittest.main()
