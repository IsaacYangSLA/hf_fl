"""Broker security contracts without network discovery or real credentials."""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import unittest

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from hf2l_jobs.broker import (
    BrokerError, BrokerSettings, NodeAuthenticator, WorkloadBroker,
    principal_id, stable_workload_principal, stable_workload_subject,
)


class BrokerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.thumb = base64.urlsafe_b64encode(hashlib.sha256(b"execution A").digest()).decode().rstrip("=")
        cls.other_thumb = base64.urlsafe_b64encode(hashlib.sha256(b"execution B").digest()).decode().rstrip("=")

    def setUp(self):
        self.now = 1_000_000
        self.settings = BrokerSettings(
            "https://workloads.example.test", "exchange-managed", "hf2l-transfer", "hf2l-nodes",
            self.private.public_key(), self.private, key_id="broker-key")
        self.broker = WorkloadBroker(self.settings, clock=lambda: self.now)

    def workload(self, **changes):
        fields = dict(job_id="job-a", attempt_id="attempt-1", component_id="owner",
                      space_id="space-a", grant_id="grant-1", epoch=1,
                      certificate_thumbprint=self.thumb)
        fields.update(changes)
        return self.broker.issue_workload(**fields)

    def node(self, **changes):
        fields = dict(node_id="node-a", pool_id="pool-a", job_id="job-a",
                      attempt_id="attempt-1", component_id="owner", grant_id="grant-node",
                      epoch=1, certificate_thumbprint=self.thumb, scopes=["heartbeat", "progress"],
                      resources={"cpu_millicores": 1000, "memory_bytes": 1024, "disk_bytes": 2048})
        fields.update(changes)
        return self.broker.issue_node(**fields)

    def verify(self, token, **options):
        options.setdefault("verified_peer_thumbprint", self.thumb)
        return self.broker.authenticate_workload("Bearer " + token, **options)

    def tamper(self, token, *, headers=None, signing_key=None, **changes):
        claims = jwt.decode(token, options={"verify_signature": False})
        claims.update(changes)
        return jwt.encode(claims, signing_key or self.private, algorithm="RS256",
                          headers=headers or {"typ": "at+jwt", "kid": "broker-key"})

    def test_workload_claims_and_stable_principal(self):
        first = self.verify(self.workload())
        second = self.verify(self.workload(attempt_id="attempt-2", grant_id="grant-2", epoch=2))
        self.assertEqual(first.id, second.id)
        self.assertEqual(first.subject, second.subject)
        self.assertNotEqual(first.grant_id, second.grant_id)
        self.assertEqual(first.expires_at - first.issued_at, 300)
        self.assertEqual(first.space_id, "space-a")
        expected = hashlib.sha256(json.dumps(
            [self.settings.workload_issuer, first.subject], separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(first.id, expected)
        self.assertEqual(first.id, stable_workload_principal(self.settings.workload_issuer, "job-a", "owner"))
        self.assertEqual(first.subject, stable_workload_subject("job-a", "owner"))

    def test_distinct_jobs_components_participants_never_share_principal(self):
        values = {
            self.verify(self.workload()).id,
            self.verify(self.workload(job_id="job-b")).id,
            self.verify(self.workload(component_id="participant")).id,
            self.verify(self.workload(component_id="participant", participant_id="alice")).id,
            self.verify(self.workload(component_id="participant", participant_id="bob")).id,
        }
        self.assertEqual(len(values), 5)

    def test_exchange_and_gateway_tokens_are_not_interchangeable(self):
        gateway = self.workload(audience="gateway")
        self.assertEqual(self.verify(gateway, audience="gateway").audience, "hf2l-transfer")
        with self.assertRaises(BrokerError):
            self.verify(gateway)
        with self.assertRaises(BrokerError):
            self.verify(self.workload(), audience="gateway")
        for audience in ("https://attacker.invalid", "node", "", None):
            with self.subTest(audience=audience), self.assertRaises(BrokerError):
                self.workload(audience=audience)

    def test_copied_token_requires_own_execution_certificate(self):
        token = self.workload()
        for thumbprint in (self.other_thumb, None, "", "forwarded-header", self.thumb + "="):
            with self.subTest(thumbprint=thumbprint), self.assertRaises(BrokerError):
                self.verify(token, verified_peer_thumbprint=thumbprint)

    def test_all_security_bindings_are_validated(self):
        token = self.workload()
        invalid = [
            {"iss": "https://attacker.invalid"},
            {"aud": "human-api"}, {"aud": ["exchange-managed", "human-api"]},
            {"sub": "human-user"}, {"scope": "exchange admin"},
            {"job_id": "../other-job"}, {"attempt_id": ""}, {"component_id": []},
            {"space_id": "space/b"}, {"grant_id": "other-grant"},
            {"epoch": True}, {"epoch": 0}, {"epoch": -1},
            {"participant_id": "injected"}, {"token_use": "node"},
            {"cnf": {}}, {"cnf": {"x5t#S256": self.thumb, "jwk": {}}},
            {"cnf": {"x5t#S256": self.other_thumb}},
        ]
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(BrokerError):
                self.verify(self.tamper(token, **changes))

    def test_required_claims_cannot_be_removed(self):
        token = self.workload()
        for name in ("iss", "aud", "sub", "iat", "nbf", "exp", "jti", "cnf",
                     "job_id", "attempt_id", "component_id", "space_id", "epoch"):
            claims = jwt.decode(token, options={"verify_signature": False})
            claims.pop(name)
            forged = jwt.encode(claims, self.private, algorithm="RS256",
                                headers={"typ": "at+jwt", "kid": "broker-key"})
            with self.subTest(name=name), self.assertRaises(BrokerError):
                self.verify(forged)

    def test_forged_signatures_and_key_discovery_headers_rejected(self):
        token = self.workload()
        with self.assertRaises(BrokerError):
            self.verify(self.tamper(token, signing_key=self.other_private))
        for headers in (
            {"typ": "at+jwt", "kid": "wrong-key"},
            {"typ": "JWT", "kid": "broker-key"},
            {"typ": "at+jwt", "kid": "broker-key", "jku": "https://attacker.invalid"},
            {"typ": "at+jwt", "kid": "broker-key", "jwk": {}},
            {"typ": "at+jwt", "kid": "broker-key", "x5u": "https://attacker.invalid"},
        ):
            with self.subTest(headers=headers), self.assertRaises(BrokerError):
                self.verify(self.tamper(token, headers=headers))
        claims = jwt.decode(token, options={"verify_signature": False})
        for algorithm, key in (("HS256", b"synthetic-attacker-key-with-32-bytes"), ("none", None)):
            forged = jwt.encode(claims, key, algorithm=algorithm, headers={"typ": "at+jwt"})
            with self.subTest(algorithm=algorithm), self.assertRaises(BrokerError):
                self.verify(forged)

    def test_maximum_lifetime_and_exact_expiration(self):
        for lifetime in (0, 301, -1, True, 1.0):
            with self.subTest(lifetime=lifetime), self.assertRaises(BrokerError):
                self.workload(ttl_seconds=lifetime)
        token = self.workload(ttl_seconds=1)
        self.verify(token)
        self.now += 1
        with self.assertRaises(BrokerError):
            self.verify(token)
        self.now -= 1
        for changes in ({"exp": self.now + 301}, {"exp": self.now},
                        {"iat": True}, {"nbf": self.now - 1},
                        {"iat": self.now + 1, "nbf": self.now + 1},
                        {"exp": float(self.now + 300)}):
            with self.subTest(changes=changes), self.assertRaises(BrokerError):
                self.verify(self.tamper(self.workload(), **changes))

    def test_node_requires_current_durable_grant(self):
        token = self.node()
        with self.assertRaises(BrokerError) as missing:
            self.broker.authenticate_node("Bearer " + token, verified_peer_thumbprint=self.thumb)
        self.assertEqual(missing.exception.status, 503)
        active = {"grant-node": (1, "attempt-1")}
        def validator(principal):
            return active.get(principal.grant_id) == (principal.epoch, principal.attempt_id)
        principal = self.broker.authenticate_node(
            "Bearer " + token, verified_peer_thumbprint=self.thumb, grant_validator=validator)
        self.assertEqual(principal.node_id, "node-a")
        self.assertEqual(principal.pool_id, "pool-a")
        self.assertEqual(principal.scopes, frozenset({"heartbeat", "progress"}))
        self.assertEqual(principal.resources["cpu_millicores"], 1000)
        with self.assertRaises(TypeError):
            principal.resources["cpu_millicores"] = 2000
        active.clear()
        with self.assertRaises(BrokerError):
            self.broker.authenticate_node("Bearer " + token, verified_peer_thumbprint=self.thumb,
                                          grant_validator=validator)

    def test_node_validator_failure_does_not_allow_access(self):
        token = self.node()
        def broken(_):
            raise RuntimeError("database unavailable")
        with self.assertRaises(BrokerError) as failure:
            self.broker.authenticate_node("Bearer " + token, verified_peer_thumbprint=self.thumb,
                                          grant_validator=broken)
        self.assertEqual(failure.exception.status, 503)
        for result in (None, 1, "yes", {}):
            with self.subTest(result=result), self.assertRaises(BrokerError):
                self.broker.authenticate_node("Bearer " + token, verified_peer_thumbprint=self.thumb,
                                              grant_validator=lambda _: result)

    def test_node_authenticator_fixed_audience_and_certificate(self):
        verify_settings = dataclasses.replace(self.settings, private_key=None)
        authenticator = NodeAuthenticator(verify_settings, grant_validator=lambda _: True,
                                          clock=lambda: self.now)
        principal = authenticator.authenticate("Bearer " + self.node(),
                                               verified_peer_thumbprint=self.thumb)
        self.assertEqual(principal.subject, "node:node-a")
        self.assertEqual(principal.id, principal_id(self.settings.workload_issuer, principal.subject))
        for token, thumb in ((self.workload(), self.thumb), (self.node(), self.other_thumb)):
            with self.subTest(thumb=thumb), self.assertRaises(BrokerError):
                authenticator.authenticate("Bearer " + token, verified_peer_thumbprint=thumb)
        with self.assertRaises(BrokerError):
            self.verify(self.node())

    def test_external_assignment_scope_remains_job_node_certificate_bound(self):
        token = self.node(scopes=["assignment"], pool_id="external", resources={})
        principal = self.broker.authenticate_node(
            "Bearer " + token, verified_peer_thumbprint=self.thumb,
            grant_validator=lambda value: value.node_id == "node-a" and value.job_id == "job-a")
        self.assertEqual(principal.scopes, frozenset({"assignment"}))
        self.assertEqual(principal.pool_id, "external")
        self.assertEqual(dict(principal.resources), {})
        with self.assertRaises(BrokerError):
            self.node(scopes=["assignment", "reserve"], resources={})
        with self.assertRaises(BrokerError):
            self.broker.authenticate_node(
                "Bearer " + token, verified_peer_thumbprint=self.other_thumb,
                grant_validator=lambda _: True)

    def test_node_scopes_and_resources_are_narrow(self):
        for scopes in ([], ["admin"], ["exchange"], ["jobs:read"], "heartbeat", [True]):
            with self.subTest(scopes=scopes), self.assertRaises(BrokerError):
                self.node(scopes=scopes)
        for resources in ({"host_path": "/etc"}, {"cpu_millicores": True}, {"memory_bytes": 0},
                          {"disk_bytes": -1}, {"gpu_uuids": ["GPU-a", "GPU-a"]}, [], ""):
            with self.subTest(resources=resources), self.assertRaises(BrokerError):
                self.node(resources=resources)
        for scope in ("reserve", "start", "renew"):
            with self.subTest(scope=scope), self.assertRaises(BrokerError):
                self.node(scopes=[scope], resources={})
        token = self.node(scopes=["reserve", "start", "stop", "renew"],
                          resources={"cpu_millicores": 1000, "memory_bytes": 1024, "disk_bytes": 2048, "gpu_uuids": ["GPU-a"]})
        principal = self.broker.authenticate_node(
            "Bearer " + token, verified_peer_thumbprint=self.thumb, grant_validator=lambda _: True)
        self.assertEqual(principal.resources["gpu_uuids"], ("GPU-a",))
        for changes in ({"scope": "heartbeat heartbeat"}, {"scope": "admin"},
                        {"node_id": "node-b"}, {"pool_id": "../pool"},
                        {"resources": {"cpu_millicores": "1000"}}, {"token_use": "workload"}):
            with self.subTest(changes=changes), self.assertRaises(BrokerError):
                self.broker.authenticate_node(
                    "Bearer " + self.tamper(self.node(), **changes),
                    verified_peer_thumbprint=self.thumb, grant_validator=lambda _: True)

    def test_authorization_envelope_rejects_malformed_input(self):
        token = self.workload()
        for authorization in (None, "", token, "Basic " + token, "Bearer  " + token,
                              "Bearer " + token + " ", "Bearer " + "a" * 16384):
            with self.subTest(authorization=str(authorization)[:20]), self.assertRaises(BrokerError):
                self.broker.authenticate_workload(
                    authorization, verified_peer_thumbprint=self.thumb)

    def test_verification_only_instances_cannot_mint(self):
        broker = WorkloadBroker(dataclasses.replace(self.settings, private_key=None), clock=lambda: self.now)
        with self.assertRaises(BrokerError) as missing:
            broker.issue_workload(job_id="j", attempt_id="a", component_id="c", space_id="s",
                                  grant_id="g", epoch=1, certificate_thumbprint=self.thumb)
        self.assertEqual(missing.exception.code, "signing_key_unavailable")

    def test_settings_reject_key_confusion_and_overbroad_audiences(self):
        for changes in ({"exchange_audience": "hf2l-transfer"}, {"max_ttl_seconds": 301},
                        {"max_ttl_seconds": True}, {"workload_issuer": ""}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                WorkloadBroker(dataclasses.replace(self.settings, **changes))
        weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        for changes in ({"public_key": weak.public_key()}, {"public_key": b"not-a-key"},
                        {"private_key": self.other_private}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                WorkloadBroker(dataclasses.replace(self.settings, **changes))

    def test_pem_keys_and_safe_settings_representation(self):
        private_pem = self.private.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        public_pem = self.private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        settings = dataclasses.replace(self.settings, private_key=private_pem, public_key=public_pem)
        broker = WorkloadBroker(settings, clock=lambda: self.now)
        self.assertNotIn("PRIVATE KEY", repr(settings))
        self.assertNotIn("PUBLIC KEY", repr(settings))
        self.assertEqual(broker.authenticate_workload(
            "Bearer " + self.workload(), verified_peer_thumbprint=self.thumb).job_id, "job-a")


if __name__ == "__main__":
    unittest.main()
