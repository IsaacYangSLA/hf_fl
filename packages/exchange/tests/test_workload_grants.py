"""Adversarial managed identity tests independent of model execution and S3."""
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select, text

from hf2l_exchange.application import Service
from hf2l_exchange.auth import (Authenticator, backend_assertion_headers, principal_id,
                                verified_backend_thumbprint)
from hf2l_exchange.config import AuthSettings, DatabaseSettings, Settings, StorageSettings
from hf2l_exchange.domain import Error, Principal
from hf2l_exchange.migrations import (SCHEMA_REVISION, SQLITE_BASELINE, _event_sequence,
                                      check, initialize, migrate)
from hf2l_exchange.models import (Blob, Event, ManagedSpace, Member, Record, SchemaRevision,
                                  Space, TransferAttempt, WorkloadGrant, WorkloadRevocation, database)


class SignedIdentityFixture(unittest.TestCase):
    legacy_issuer = "https://humans.example.test"
    workload_issuer = "https://workloads.example.test"
    thumbprint = "a" * 43

    @classmethod
    def setUpClass(cls):
        cls.legacy_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.workload_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.legacy_public = cls.legacy_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        cls.workload_public = cls.workload_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def legacy_settings(self):
        return AuthSettings(issuer=self.legacy_issuer, public_key=self.legacy_public,
                            admin_subject="owner")

    def token(self, *, workload=False, **overrides):
        now = int(time.time())
        claims = {"iss": self.workload_issuer if workload else self.legacy_issuer,
                  "aud": "exchange", "sub": "component-a" if workload else "owner",
                  "iat": now - 1, "exp": now + 60, "scope": "exchange"}
        claims.update(overrides)
        key = self.workload_key if workload else self.legacy_key
        return "Bearer " + jwt.encode(claims, key, algorithm="RS256", headers={"typ": "at+jwt"})


class LegacyAuthenticationCompatibilityTests(SignedIdentityFixture):
    def test_legacy_authority_remains_issuer_bound_without_workload_configuration(self):
        principal = Authenticator(self.legacy_settings()).authenticate(self.token())
        self.assertEqual(principal.id, principal_id(self.legacy_issuer, "owner"))
        self.assertTrue(principal.bootstrap_admin)

    def test_workload_signature_cannot_enter_disabled_legacy_authenticator(self):
        with self.assertRaises(Error) as caught:
            Authenticator(self.legacy_settings()).authenticate(self.token(workload=True))
        self.assertEqual(caught.exception.status, 401)

    def test_job_named_claims_do_not_expand_legacy_authority(self):
        principal = Authenticator(self.legacy_settings()).authenticate(
            self.token(sub="reader", job_id="job-a", space_id="foreign", roles=["admin"]))
        self.assertEqual(principal.id, principal_id(self.legacy_issuer, "reader"))
        self.assertFalse(principal.bootstrap_admin)


class ManagedSignedIdentityFixture(SignedIdentityFixture):
    backend_secret = "fixture-terminator-secret-32-characters"

    def managed_settings(self):
        return replace(self.legacy_settings(), workload_issuer=self.workload_issuer,
                       workload_public_key=self.workload_public,
                       trusted_backend_secret=self.backend_secret,
                       provisioning_principal_ids=(principal_id(self.legacy_issuer, "owner"),),
                       download_broker_principal_ids=(principal_id(self.legacy_issuer, "broker"),))

    def workload_token(self, **overrides):
        values = {"aud": "exchange-workload", "jti": "grant-a", "space_id": "space-a",
                  "job_id": "job-a", "attempt_id": "attempt-a", "component_id": "component-a",
                  "epoch": 1, "cnf": {"x5t#S256": self.thumbprint}}
        values.update(overrides)
        return self.token(workload=True, **values)

    def workload_principal(self, **overrides):
        return Authenticator(self.managed_settings()).authenticate(
            self.workload_token(**overrides), managed=True, certificate_thumbprint=self.thumbprint)


class ManagedAuthenticationTests(ManagedSignedIdentityFixture):
    def test_valid_workload_is_separate_from_human_admin_identity(self):
        principal = self.workload_principal(sub="owner")
        self.assertEqual(principal.id, principal_id(self.workload_issuer, "owner"))
        self.assertNotEqual(principal.id, principal_id(self.legacy_issuer, "owner"))
        self.assertFalse(principal.bootstrap_admin)
        self.assertEqual(principal.workload.job_id, "job-a")
        self.assertEqual(principal.workload.grant_id, "grant-a")
        self.assertEqual(principal.workload.certificate_thumbprint, self.thumbprint)

    def test_public_ingress_rejects_even_a_valid_certificate_bound_workload(self):
        with self.assertRaises(Error) as caught:
            Authenticator(self.managed_settings()).authenticate(
                self.workload_token(), certificate_thumbprint=self.thumbprint)
        self.assertEqual(caught.exception.status, 401)

    def test_copied_token_fails_another_execution_certificate(self):
        for presented in ("", "b" * 43, "invalid-format"):
            with self.subTest(certificate=presented), self.assertRaises(Error) as caught:
                Authenticator(self.managed_settings()).authenticate(
                    self.workload_token(), managed=True, certificate_thumbprint=presented)
            self.assertEqual(caught.exception.status, 401)

    def test_workload_claims_are_strict_and_lifetime_is_bounded(self):
        now = int(time.time())
        attacks = ({"epoch": True}, {"epoch": 0}, {"job_id": ""}, {"jti": ""},
                   {"space_id": "x" * 65}, {"grant_id": "different"},
                   {"cnf": {"x5t#S256": self.thumbprint, "jwk": {}}},
                   {"cnf": {"x5t#S256": "b" * 43}}, {"cnf": {}},
                   {"iat": now - 1, "exp": now + 301}, {"exp": str(now + 60)},
                   {"iat": now - 60, "exp": now - 1}, {"aud": "exchange"},
                   {"component_id": ["component-a"]})
        for claims in attacks:
            with self.subTest(claims=claims), self.assertRaises(Error) as caught:
                self.workload_principal(**claims)
            self.assertEqual(caught.exception.status, 401)

    def test_claimed_issuer_cannot_cross_the_fixed_signing_keys(self):
        auth = Authenticator(self.managed_settings())
        for authorization in (self.workload_token(iss=self.legacy_issuer),
                              self.token(iss=self.workload_issuer, aud="exchange-workload")):
            with self.subTest(token=authorization[-16:]), self.assertRaises(Error) as caught:
                auth.authenticate(authorization, managed=True, certificate_thumbprint=self.thumbprint)
            self.assertEqual(caught.exception.status, 401)

    def test_enabled_workload_support_preserves_human_authentication(self):
        principal = Authenticator(self.managed_settings()).authenticate(self.token(sub="reader"))
        self.assertEqual(principal.id, principal_id(self.legacy_issuer, "reader"))
        self.assertIsNone(principal.workload)


class BackendCertificateAssertionTests(ManagedSignedIdentityFixture):
    def test_signed_backend_assertion_binds_method_target_token_and_certificate(self):
        authorization = self.workload_token()
        headers = backend_assertion_headers(self.backend_secret, "GET", "/v2/spaces/space-a?limit=1",
                                             authorization, self.thumbprint)
        self.assertEqual(verified_backend_thumbprint(self.managed_settings(), "GET",
                                                    "/v2/spaces/space-a?limit=1", authorization, headers),
                         self.thumbprint)
        attempts = [("POST", "/v2/spaces/space-a?limit=1", authorization, headers),
                    ("GET", "/v2/spaces/space-b?limit=1", authorization, headers),
                    ("GET", "/v2/spaces/space-a?limit=2", authorization, headers),
                    ("GET", "/v2/spaces/space-a?limit=1", self.workload_token(jti="grant-b"), headers),
                    ("GET", "/v2/spaces/space-a?limit=1", authorization,
                     dict(headers, **{"X-HF2L-TLS-Thumbprint": "b" * 43}))]
        for method, target, token, values in attempts:
            with self.subTest(method=method, target=target), self.assertRaises(Error) as caught:
                verified_backend_thumbprint(self.managed_settings(), method, target, token, values)
            self.assertEqual(caught.exception.code, "invalid_backend_assertion")

    def test_unsigned_certificate_headers_and_stale_assertions_cannot_spoof_tls(self):
        authorization = self.workload_token()
        attempts = ({"X-HF2L-TLS-Thumbprint": self.thumbprint},
                    {"X-Forwarded-Client-Cert": self.thumbprint},
                    backend_assertion_headers(self.backend_secret, "GET", "/ready", authorization,
                                              self.thumbprint, timestamp=int(time.time()) - 31),
                    backend_assertion_headers("attacker-secret", "GET", "/ready", authorization,
                                              self.thumbprint))
        for headers in attempts:
            with self.subTest(headers=headers), self.assertRaises(Error) as caught:
                verified_backend_thumbprint(self.managed_settings(), "GET", "/ready", authorization, headers)
            self.assertEqual(caught.exception.status, 401)


class ManagedAuthenticationConfigurationTests(ManagedSignedIdentityFixture):
    def test_partial_workload_configuration_fails_closed(self):
        settings = self.managed_settings()
        attacks = (replace(settings, workload_public_key=""),
                   replace(settings, workload_issuer=self.legacy_issuer),
                   replace(settings, trusted_backend_secret="too-short"),
                   replace(settings, provisioning_principal_ids=()),
                   replace(settings, provisioning_principal_ids=("owner",)),
                   replace(self.legacy_settings(), download_broker_principal_ids=("a" * 64,)))
        for config in attacks:
            with self.subTest(config=config.workload_issuer), self.assertRaises(ValueError):
                config.validate()


class WorkloadGrantMigrationTests(unittest.TestCase):
    def test_frozen_0002_upgrade_preserves_unmanaged_space_and_membership(self):
        engine, sessions = database("sqlite:///:memory:")
        self.addCleanup(engine.dispose)
        with engine.begin() as connection:
            for statement in SQLITE_BASELINE:
                connection.exec_driver_sql(statement)
            _event_sequence(connection)
            connection.exec_driver_sql("CREATE TABLE v2_schema_ledger (revision VARCHAR(64) NOT NULL PRIMARY KEY)")
            connection.exec_driver_sql("INSERT INTO v2_schema_ledger VALUES ('0002_event_sequence')")
            connection.execute(text("""INSERT INTO v2_spaces
                (id,name,profile,generation,quota_bytes,principal_quota_bytes,allocated,reclaiming,
                 quota_records,record_count,quota_metadata_bytes,metadata_bytes,event_floor)
                VALUES ('legacy','Existing','generic.v1',1,1000,1000,0,0,10,0,1000,0,0)"""))
            connection.execute(text("""INSERT INTO v2_members
                (space_id,principal_id,subject,roles,bindings)
                VALUES ('legacy','reader','Reader','["reader"]','{}')"""))
        self.assertNotIn("v2_workload_grants", inspect(engine).get_table_names())
        self.assertNotEqual(SCHEMA_REVISION, "0002_event_sequence")
        self.assertEqual(migrate(engine), SCHEMA_REVISION)
        self.assertEqual(initialize(engine), SCHEMA_REVISION)
        self.assertEqual(check(engine), SCHEMA_REVISION)
        service = Service(Settings(), engine=engine, sessions=sessions)
        self.assertEqual(service.get_space(Principal("reader", "Reader"), "legacy")["name"], "Existing")
        with sessions() as session:
            self.assertEqual(session.get(Member, ("legacy", "reader")).roles, ["reader"])
            self.assertIsNone(session.get(ManagedSpace, "legacy"))
            self.assertEqual(session.scalars(select(WorkloadGrant)).all(), [])


class ManagedSpaceFixture(ManagedSignedIdentityFixture):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="exchange-workload-grants-")
        self.addCleanup(temporary.cleanup)
        self.settings = Settings(
            database=DatabaseSettings(url="sqlite:///" + str(Path(temporary.name) / "exchange.db")),
            auth=self.managed_settings(), storage=StorageSettings(bucket="fixture-bucket"),
            allow_local_http=True)
        self.service = Service(self.settings)
        self.addCleanup(self.service.engine.dispose)
        initialize(self.service.engine)
        self.owner = Authenticator(self.settings.auth).authenticate(self.token())
        self.human = Authenticator(self.settings.auth).authenticate(self.token(sub="human-admin"))
        self.broker = Authenticator(self.settings.auth).authenticate(self.token(sub="broker"))
        self.space = self.service.create_space(self.owner, {"name": "job-a"}, "space-a")
        self.space_id = self.space["id"]
        self.component_id = principal_id(self.workload_issuer, "component-a")
        for principal in (Principal(self.component_id, "component-a"), self.human, self.broker):
            self.service.put_member(self.owner, self.space_id, principal.id,
                {"subject": principal.subject, "roles": ["reader", "contributor", "publisher", "admin"],
                 "bindings": {"participant": "alice"} if principal.id == self.component_id else {}})
        self.revision = self.service.register_type(self.owner, self.space_id, "document",
                                                   {"schema": {"type": "object"}}, "type")
        self.service.enable_managed_space(self.owner, self.space_id, {"job_id": "job-a"}, "managed-a")
        self.body = {"subject": "component-a", "job_id": "job-a", "attempt_id": "attempt-a",
                     "component_id": "component-a", "epoch": 1, "expires_at": int(time.time()) + 3600,
                     "certificate_thumbprint": self.thumbprint, "roles": ["reader", "contributor"],
                     "bindings": {"participant": "alice"}}
        self.grant = self.service.create_workload_grant(self.owner, self.space_id, self.body, "grant-a")
        self.workload = self.principal_for(self.grant)

    def principal_for(self, grant):
        return self.workload_principal(sub=grant["subject"], jti=grant["grant_id"], space_id=grant["space_id"],
            job_id=grant["job_id"], attempt_id=grant["attempt_id"], component_id=grant["component_id"],
            epoch=grant["epoch"])

    def create_document(self, principal=None, key="record-a"):
        return self.service.create_record(principal or self.workload, self.space_id,
            {"kind": "document", "schema_revision_id": self.revision["id"], "metadata": {}}, key)

    def assert_error(self, status, code, function, *args, **kwargs):
        with self.assertRaises(Error) as caught:
            function(*args, **kwargs)
        self.assertEqual((caught.exception.status, caught.exception.code), (status, code))


class WorkloadGrantAuthorizationTests(ManagedSpaceFixture):
    def test_roles_are_intersected_without_mutating_persisted_membership(self):
        self.assertEqual(self.service.get_membership(self.workload, self.space_id)["roles"],
                         ["contributor", "reader"])
        self.assertEqual(self.service.verify_workload_grant(self.workload, self.space_id)["effective_roles"],
                         ["contributor", "reader"])
        self.assert_error(403, "role_required", self.service.update_space_limits,
                          self.workload, self.space_id, {"quota_bytes": 100})
        self.create_document()
        with self.service.sessions() as session:
            self.assertEqual(session.get(Member, (self.space_id, self.component_id)).roles,
                             ["admin", "contributor", "publisher", "reader"])

    def test_current_member_roles_restrict_an_existing_grant_immediately(self):
        self.service.put_member(self.owner, self.space_id, self.component_id,
            {"subject": "component-a", "roles": ["reader"], "bindings": {"participant": "alice"}})
        self.assertEqual(self.service.get_membership(self.workload, self.space_id)["roles"], ["reader"])
        self.assert_error(403, "role_required", self.create_document)
        self.service.put_member(self.owner, self.space_id, self.component_id,
            {"subject": "component-a", "roles": [], "bindings": {"participant": "alice"}})
        self.assert_error(404, "space_not_found", self.service.get_space, self.workload, self.space_id)

    def test_current_participant_binding_must_equal_the_grant(self):
        self.service.put_member(self.owner, self.space_id, self.component_id,
            {"subject": "component-a", "roles": ["reader", "contributor"], "bindings": {"participant": "bob"}})
        self.assert_error(403, "workload_grant_invalid", self.service.get_space, self.workload, self.space_id)

    def test_accidental_membership_in_foreign_space_does_not_expand_authority(self):
        foreign = self.service.create_space(self.owner, {"name": "job-b"}, "space-b")["id"]
        self.service.put_member(self.owner, foreign, self.component_id,
            {"subject": "component-a", "roles": ["reader", "contributor", "admin"],
             "bindings": {"participant": "alice"}})
        self.service.enable_managed_space(self.owner, foreign, {"job_id": "job-b"}, "managed-b")
        self.assert_error(404, "space_not_found", self.service.get_space, self.workload, foreign)
        foreign_identity = replace(self.workload.workload, space_id=foreign, job_id="job-b")
        self.assert_error(403, "workload_grant_invalid", self.service.get_space,
                          replace(self.workload, workload=foreign_identity), foreign)

    def test_every_opaque_execution_binding_and_ledger_identity_must_match(self):
        attacks = ({"grant_id": "unknown"}, {"job_id": "job-b"}, {"attempt_id": "attempt-b"},
                   {"component_id": "component-b"}, {"epoch": 2},
                   {"certificate_thumbprint": "b" * 43}, {"expires_at": time.time() - 1})
        for binding in attacks:
            with self.subTest(binding=binding):
                principal = replace(self.workload, workload=replace(self.workload.workload, **binding))
                self.assert_error(403, "workload_grant_invalid", self.service.get_space, principal, self.space_id)
        self.assert_error(403, "workload_grant_invalid", self.service.get_space,
                          replace(self.workload, subject="impostor"), self.space_id)

    def test_expired_ledger_is_rejected_even_when_the_jwt_is_fresh(self):
        with self.service.sessions.begin() as session:
            session.get(WorkloadGrant, self.grant["grant_id"]).expires_at = time.time() - 1
        self.assert_error(403, "workload_grant_invalid", self.service.get_space, self.workload, self.space_id)

    def test_ordinary_human_members_cannot_bypass_managed_authentication(self):
        self.assert_error(404, "space_not_found", self.service.get_space, self.human, self.space_id)
        self.assert_error(404, "space_not_found", self.create_document, self.human)

    def test_download_broker_is_read_only_even_with_accidental_admin_membership(self):
        self.assertEqual(self.service.get_space(self.broker, self.space_id)["id"], self.space_id)
        self.assertEqual(self.service.get_membership(self.broker, self.space_id)["roles"], ["reader"])
        self.assert_error(403, "role_required", self.service.update_space_limits,
                          self.broker, self.space_id, {"quota_bytes": 100})
        self.assert_error(403, "role_required", self.create_document, self.broker)

    def test_only_trusted_provisioner_can_manage_grants_or_space_bindings(self):
        operations = [(self.service.enable_managed_space, {"job_id": "job-a"}, "enable"),
                      (self.service.create_workload_grant, self.body, "grant"),
                      (self.service.revoke_workload_grants, {"attempt_id": "attempt-a"}, "revoke")]
        for principal in (self.human, self.broker, self.workload):
            for function, body, key in operations:
                with self.subTest(subject=principal.subject, operation=function.__name__):
                    self.assert_error(403, "provisioning_principal_required", function,
                                      principal, self.space_id, body, key)
            self.assert_error(403, "provisioning_principal_required", self.service.get_workload_grant,
                              principal, self.space_id, self.grant["grant_id"])

    def test_grant_creation_retries_are_idempotent_and_body_changes_conflict(self):
        self.assertEqual(self.service.create_workload_grant(self.owner, self.space_id, self.body, "grant-a"), self.grant)
        self.assert_error(409, "idempotency_conflict", self.service.create_workload_grant,
                          self.owner, self.space_id, dict(self.body, roles=["reader"]), "grant-a")
        with self.service.sessions() as session:
            self.assertEqual(len(session.scalars(select(WorkloadGrant)).all()), 1)

    def test_new_attempt_requires_explicit_revocation_even_after_old_expiry(self):
        successor = dict(self.body, attempt_id="attempt-b", epoch=2)
        self.assert_error(409, "previous_attempt_not_revoked", self.service.create_workload_grant,
                          self.owner, self.space_id, successor, "grant-b")
        with self.service.sessions.begin() as session:
            session.get(WorkloadGrant, self.grant["grant_id"]).expires_at = time.time() - 1
        self.assert_error(409, "previous_attempt_not_revoked", self.service.create_workload_grant,
                          self.owner, self.space_id, successor, "grant-b")

    def test_takeover_preserves_creator_identity_but_invalidates_old_attempt(self):
        record = self.create_document()
        revoked = self.service.revoke_workload_grants(self.owner, self.space_id,
                                                      {"attempt_id": "attempt-a"}, "revoke-a")
        self.assertEqual(revoked["revoked"], 1)
        self.assertEqual(self.service.revoke_workload_grants(self.owner, self.space_id,
                         {"attempt_id": "attempt-a"}, "revoke-a"), revoked)
        self.assert_error(403, "workload_grant_invalid", self.service.get_space, self.workload, self.space_id)
        successor = self.service.create_workload_grant(self.owner, self.space_id,
                        dict(self.body, attempt_id="attempt-b", epoch=2), "grant-b")
        new_principal = self.principal_for(successor)
        self.assertEqual(successor["principal_id"], self.grant["principal_id"])
        self.assertEqual(new_principal.id, self.workload.id)
        recovered = self.service.get_record(new_principal, self.space_id, record["id"])
        self.assertEqual(recovered["creator"], self.component_id)
        self.assertEqual(recovered["creator_bindings"], {"participant": "alice"})

    def test_revoked_attempt_cannot_be_reopened_by_stale_provisioning(self):
        self.service.revoke_workload_grants(self.owner, self.space_id, {"attempt_id": "attempt-a"}, "revoke-a")
        self.assert_error(409, "attempt_already_revoked", self.service.create_workload_grant,
                          self.owner, self.space_id, self.body, "late-grant-a")
        self.assert_error(409, "stale_workload_epoch", self.service.create_workload_grant,
                          self.owner, self.space_id, dict(self.body, attempt_id="attempt-b"), "grant-b")

    def test_revoking_empty_attempt_blocks_late_grants(self):
        revoked = self.service.revoke_workload_grants(self.owner, self.space_id,
                                                      {"attempt_id": "never-started"}, "cancel-empty")
        self.assertEqual(revoked["revoked"], 0)
        self.assert_error(409, "attempt_already_revoked", self.service.create_workload_grant,
                          self.owner, self.space_id, dict(self.body, attempt_id="never-started", epoch=2), "late-empty")

    def test_grant_roles_and_bindings_cannot_exceed_membership(self):
        self.assert_error(403, "workload_membership_required", self.service.create_workload_grant,
                          self.owner, self.space_id, dict(self.body, bindings={"participant": "bob"}), "binding")
        self.service.put_member(self.owner, self.space_id, self.component_id,
            {"subject": "component-a", "roles": ["reader"], "bindings": {"participant": "alice"}})
        self.assert_error(403, "workload_membership_required", self.service.create_workload_grant,
                          self.owner, self.space_id, self.body, "roles")

    def test_ledger_grants_cover_multi_day_jobs_while_jwts_remain_short_lived(self):
        multi_day = self.service.create_workload_grant(self.owner, self.space_id,
                    dict(self.body, expires_at=int(time.time()) + 2 * 86400), "multi-day")
        self.assertGreater(multi_day["expires_at"] - time.time(), 86400)
        self.assertEqual(self.service.verify_workload_grant(self.principal_for(multi_day), self.space_id)["grant_id"],
                         multi_day["grant_id"])
        self.assert_error(422, "invalid_grant_expiry", self.service.create_workload_grant,
                          self.owner, self.space_id, dict(self.body, expires_at=int(time.time()) + 31 * 86400),
                          "too-long")

    def test_managed_space_job_binding_cannot_change_or_be_shared(self):
        self.assert_error(409, "managed_space_binding_immutable", self.service.enable_managed_space,
                          self.owner, self.space_id, {"job_id": "job-b"}, "rebind")
        foreign = self.service.create_space(self.owner, {"name": "other"}, "other-space")["id"]
        self.assert_error(409, "managed_job_space_conflict", self.service.enable_managed_space,
                          self.owner, foreign, {"job_id": "job-a"}, "reuse-job")

    def test_workload_principal_cannot_bootstrap_new_spaces(self):
        self.assert_error(403, "bootstrap_admin_required", self.service.create_space,
                          replace(self.workload, bootstrap_admin=True), {"name": "escape"}, "foreign")

    def test_grant_input_validation_rejects_bad_epochs_expiry_and_thumbprints(self):
        attacks = (({"epoch": True}, "invalid_workload_epoch"),
                   ({"epoch": 0}, "invalid_workload_epoch"),
                   ({"expires_at": float("nan")}, "invalid_grant_expiry"),
                   ({"expires_at": time.time() - 1}, "invalid_grant_expiry"),
                   ({"expires_at": time.time() + 31 * 86400}, "invalid_grant_expiry"),
                   ({"certificate_thumbprint": "bad"}, "invalid_certificate_thumbprint"))
        for index, (patch, code) in enumerate(attacks):
            with self.subTest(patch=patch):
                self.assert_error(422, code, self.service.create_workload_grant, self.owner,
                                  self.space_id, dict(self.body, **patch), "bad-" + str(index))


class ManagedWorkloadHTTPTests(ManagedSpaceFixture):
    def setUp(self):
        super().setUp()
        from hf2l_exchange.api import create_app
        self.prefix = "/v2/spaces/" + self.space_id
        transfers = Mock()
        self.public = TestClient(create_app(self.settings, service=self.service, transfers=transfers))
        self.internal = TestClient(create_app(self.settings, service=self.service, transfers=transfers,
                                               managed_ingress=True))
        self.public.__enter__()
        self.internal.__enter__()
        self.addCleanup(self.public.__exit__, None, None, None)
        self.addCleanup(self.internal.__exit__, None, None, None)

    def execution_authorization(self):
        return self.workload_token(jti=self.grant["grant_id"], space_id=self.space_id)

    def assertion(self, method, target, authorization=None, certificate=None):
        authorization = authorization or self.execution_authorization()
        result = {"Authorization": authorization}
        result.update(backend_assertion_headers(self.backend_secret, method, target, authorization,
                                               certificate or self.thumbprint))
        return result

    def assert_response(self, response, status, code=None):
        self.assertEqual(response.status_code, status, response.text)
        if code is not None:
            self.assertEqual(response.json()["error"]["code"], code)

    def test_public_listener_cannot_accept_signed_or_spoofed_certificate_metadata(self):
        path = self.prefix
        for headers in (self.assertion("GET", path),
                        {"Authorization": self.execution_authorization(),
                         "X-Forwarded-Client-Cert": self.thumbprint,
                         "X-HF2L-TLS-Thumbprint": self.thumbprint}):
            with self.subTest(headers=sorted(headers)):
                self.assert_response(self.public.get(path, headers=headers), 401, "invalid_access_token")

    def test_internal_listener_requires_authenticated_backend_then_matching_tls_binding(self):
        self.assert_response(self.internal.get(self.prefix,
                             headers={"Authorization": self.execution_authorization(),
                                      "X-HF2L-TLS-Thumbprint": self.thumbprint}), 401, "invalid_backend_assertion")
        self.assert_response(self.internal.get(self.prefix,
                             headers=self.assertion("GET", self.prefix, certificate="b" * 43)),
                             401, "invalid_access_token")
        self.assert_response(self.internal.get(self.prefix,
                             headers=self.assertion("GET", self.prefix)), 200)

    def test_duplicate_tls_assertion_headers_are_rejected_before_authentication(self):
        for name in ("X-HF2L-TLS-Thumbprint", "X-HF2L-Backend-Signature", "X-HF2L-Backend-Timestamp"):
            headers = self.assertion("GET", self.prefix)
            duplicate = list(headers.items()) + [(name.lower(), headers[name])]
            with self.subTest(name=name):
                self.assert_response(self.internal.get(self.prefix, headers=duplicate),
                                     401, "invalid_backend_assertion")

    def test_backend_assertion_binds_actual_query_string(self):
        target = self.prefix + "/membership?limit=1"
        self.assert_response(self.internal.get(target, headers=self.assertion("GET", target)), 200)
        self.assert_response(self.internal.get(self.prefix + "/membership?limit=2",
                             headers=self.assertion("GET", target)), 401, "invalid_backend_assertion")

    def test_human_admin_cannot_bypass_managed_space_even_on_private_listener(self):
        authorization = self.token(sub="human-admin")
        self.assert_response(self.public.get(self.prefix, headers={"Authorization": authorization}),
                             404, "space_not_found")
        self.assert_response(self.internal.get(self.prefix,
                             headers=self.assertion("GET", self.prefix, authorization)), 404, "space_not_found")

    def test_provisioning_routes_enforce_current_trusted_principal(self):
        target = self.prefix + "/workload-grants"
        body = dict(self.body, roles=["reader"])
        headers = {"Authorization": self.token(), "Idempotency-Key": "http-grant"}
        created = self.public.post(target, headers=headers, json=body)
        self.assert_response(created, 201)
        self.assert_response(self.public.post(target, headers=headers, json=body), 201)
        self.assertEqual(created.json()["grant_id"], self.public.post(target, headers=headers, json=body).json()["grant_id"])
        self.assert_response(self.public.post(target,
                             headers={"Authorization": self.token(sub="human-admin"), "Idempotency-Key": "human-grant"},
                             json=body), 403, "provisioning_principal_required")
        self.assert_response(self.internal.post(target,
                             headers=dict(self.assertion("POST", target), **{"Idempotency-Key": "workload-grant"}),
                             json=body), 403, "provisioning_principal_required")

    def test_revocation_blocks_current_workload_requests_immediately(self):
        verify = self.prefix + "/workload-grants/verify"
        self.assert_response(self.internal.post(verify, headers=self.assertion("POST", verify), json={}), 200)
        revoke = self.public.post(self.prefix + "/workload-grants/revoke",
                    headers={"Authorization": self.token(), "Idempotency-Key": "http-revoke"},
                    json={"attempt_id": "attempt-a"})
        self.assert_response(revoke, 200)
        self.assertEqual(revoke.json()["revoked"], 1)
        self.assert_response(self.internal.post(verify, headers=self.assertion("POST", verify), json={}),
                             403, "workload_grant_invalid")

    def test_unmanaged_human_api_behavior_remains_available(self):
        space = self.service.create_space(self.owner, {"name": "unmanaged"}, "unmanaged")["id"]
        self.service.put_member(self.owner, space, self.human.id,
                                {"subject": "human-admin", "roles": ["reader"], "bindings": {}})
        result = self.public.get("/v2/spaces/" + space,
                                 headers={"Authorization": self.token(sub="human-admin")})
        self.assert_response(result, 200)
        self.assertEqual(result.json()["id"], space)


class ManagedSpaceRetirementTests(ManagedSpaceFixture):
    def revoke_attempt(self):
        return self.service.revoke_workload_grants(self.owner, self.space_id,
                                                  {"attempt_id": "attempt-a"}, "retirement-revoke")

    def retire(self, key="retire-a"):
        return self.service.retire_managed_space(self.owner, self.space_id, {"job_id": "job-a"}, key)

    def test_retirement_requires_matching_job_and_trusted_provisioner(self):
        for principal in (self.human, self.broker, self.workload):
            with self.subTest(subject=principal.subject):
                self.assert_error(403, "provisioning_principal_required", self.service.retire_managed_space,
                                  principal, self.space_id, {"job_id": "job-a"}, "retire")
        self.assert_error(409, "managed_space_binding_required", self.service.retire_managed_space,
                          self.owner, self.space_id, {"job_id": "job-b"}, "wrong-job")
        with self.service.sessions() as session:
            self.assertIsNone(session.get(ManagedSpace, self.space_id).retired_at)
            self.assertTrue(session.get(WorkloadGrant, self.grant["grant_id"]).enabled)

    def test_trusted_provisioner_still_requires_current_space_admin_role(self):
        self.service.put_member(self.owner, self.space_id, self.owner.id,
                                {"subject": "owner", "roles": ["reader"], "bindings": {}})
        self.assert_error(403, "role_required", self.retire)

    def test_retirement_requires_explicit_revocation_even_after_grant_expiry(self):
        self.assert_error(409, "workload_revocation_required", self.retire)
        with self.service.sessions.begin() as session:
            session.get(WorkloadGrant, self.grant["grant_id"]).expires_at = time.time() - 1
        self.assert_error(409, "workload_revocation_required", self.retire)
        self.revoke_attempt()
        self.assertEqual(self.retire()["status"], "retired")

    def test_retirement_is_idempotent_and_retains_the_ownership_ledger(self):
        draft = self.create_document(key="draft")
        published = self.create_document(key="published")
        self.service.publish_record(self.workload, self.space_id, published["id"], "publish")
        tables_before = set(inspect(self.service.engine).get_table_names())
        revoked = self.revoke_attempt()
        result = self.retire()
        self.assertEqual(self.revoke_attempt(), revoked)
        self.assertEqual(self.retire(), result)
        self.assertEqual(self.retire("second-retirement")["retired_at"], result["retired_at"])
        self.assertEqual(result["status"], "retired")
        self.assertFalse(result["cleanup_pending"])
        self.assertTrue(result["provenance_retained"])
        self.assertEqual(set(inspect(self.service.engine).get_table_names()), tables_before)
        with self.service.sessions() as session:
            self.assertIsNotNone(session.get(Space, self.space_id))
            self.assertIsNotNone(session.get(ManagedSpace, self.space_id))
            self.assertIsNotNone(session.get(Member, (self.space_id, self.component_id)))
            self.assertIsNotNone(session.get(SchemaRevision, self.revision["id"]))
            self.assertIsNotNone(session.get(WorkloadRevocation, (self.space_id, "attempt-a")))
            self.assertFalse(session.get(WorkloadGrant, self.grant["grant_id"]).enabled)
            self.assertEqual(session.get(Record, draft["id"]).state, "cancelled")
            self.assertEqual(session.get(Record, published["id"]).state, "withdrawn")
            retirement_events = session.scalars(select(Event).where(
                Event.space_id == self.space_id, Event.type == "space.managed_retired")).all()
            self.assertEqual(len(retirement_events), 1)

    def test_retired_space_fences_grants_membership_publications_and_purge(self):
        record = self.create_document()
        self.revoke_attempt()
        self.retire()
        operations = (
            (self.service.create_workload_grant,
             (self.owner, self.space_id, dict(self.body, attempt_id="attempt-b", epoch=2), "future-grant")),
            (self.service.enable_managed_space, (self.owner, self.space_id, {"job_id": "job-a"}, "reenable")),
            (self.service.put_member, (self.owner, self.space_id, self.component_id,
                {"subject": "component-a", "roles": ["reader"], "bindings": {"participant": "alice"}})),
            (self.service.publish_record, (self.owner, self.space_id, record["id"], "late-publish")),
            (self.service.update_space_limits, (self.owner, self.space_id, {"quota_bytes": 100})),
            (self.service.purge_record, (self.owner, self.space_id, record["id"])),
        )
        for function, arguments in operations:
            with self.subTest(operation=function.__name__):
                self.assert_error(409, "managed_space_retired", function, *arguments)
        self.assert_error(409, "managed_space_retired", self.create_document, self.owner, "late-record")

    def test_retired_space_preserves_read_authorization_and_hides_status_from_foreign_members(self):
        foreign = self.service.create_space(self.owner, {"name": "foreign"}, "foreign")["id"]
        self.service.put_member(self.owner, foreign, self.component_id,
            {"subject": "component-a", "roles": ["reader", "contributor"], "bindings": {"participant": "alice"}})
        self.service.enable_managed_space(self.owner, foreign, {"job_id": "foreign-job"}, "foreign-managed")
        self.service.retire_managed_space(self.owner, foreign, {"job_id": "foreign-job"}, "retire-foreign")
        self.assert_error(404, "space_not_found", self.service.get_managed_space, self.workload, foreign)
        self.assert_error(404, "space_not_found", self.service.update_space_limits,
                          self.workload, foreign, {"quota_bytes": 100})
        self.revoke_attempt()
        self.retire()
        self.assert_error(404, "space_not_found", self.service.get_managed_space, self.workload, self.space_id)
        self.assert_error(404, "space_not_found", self.service.get_managed_space, self.human, self.space_id)
        self.assert_error(404, "space_not_found", self.create_document, self.human)
        self.assertEqual(self.service.get_managed_space(self.owner, self.space_id)["status"], "retired")
        self.assertEqual(self.service.get_managed_space(self.broker, self.space_id)["status"], "retired")

    def test_retirement_does_not_change_another_space_or_unmanaged_job(self):
        foreign = self.service.create_space(self.owner, {"name": "unmanaged"}, "unmanaged")["id"]
        original = self.service.get_space(self.owner, foreign)
        self.revoke_attempt()
        self.retire()
        self.assertEqual(self.service.get_space(self.owner, foreign), original)
        self.service.put_member(self.owner, foreign, self.human.id,
                                {"subject": "human-admin", "roles": ["reader"], "bindings": {}})
        self.assertEqual(self.service.get_space(self.human, foreign)["id"], foreign)
        self.assert_error(409, "managed_space_binding_required", self.service.retire_managed_space,
                          self.owner, foreign, {"job_id": "job-a"}, "unmanaged-retire")

    def test_retirement_tracks_pending_blob_cleanup_until_worker_confirmation(self):
        from hf2l_exchange.storage import UploadHandle
        from hf2l_exchange.transfers import TransferService
        from hf2l_exchange.worker import tick
        record = self.service.create_record(self.workload, self.space_id,
            {"kind": "document", "schema_revision_id": self.revision["id"], "metadata": {},
             "attachments": [{"path": "weights.bin", "size": 3, "sha256": sha256(b"abc").hexdigest()}]},
            "with-blob")
        attachment = record["attachments"][0]
        storage = Mock()
        storage.start.side_effect = lambda key: UploadHandle("owned-upload", key)
        transfers = TransferService(self.service, storage)
        initiated = transfers.initiate(self.space_id, record["id"], attachment["id"], self.workload)
        self.revoke_attempt()
        result = self.retire()
        self.assertTrue(result["cleanup_pending"])
        self.assertTrue(self.service.get_managed_space(self.owner, self.space_id)["cleanup_pending"])
        with self.service.sessions() as session:
            attempt = session.get(TransferAttempt, initiated["attempt_id"])
            self.assertEqual(attempt.state, "cleanup")
            owned_key = attempt.object_key
            self.assertEqual(session.get(Space, self.space_id).reclaiming, 3)
        self.assertEqual(tick(transfers)["cleaned"], 1)
        storage.cleanup.assert_called_once_with(owned_key)
        state = self.service.get_managed_space(self.owner, self.space_id)
        self.assertFalse(state["cleanup_pending"])
        with self.service.sessions() as session:
            self.assertEqual(session.get(Blob, attachment["id"]).state, "cleaned")
            self.assertEqual(session.get(Space, self.space_id).reclaiming, 0)
            self.assertIsNotNone(session.get(Record, record["id"]))
            self.assertIsNotNone(session.get(WorkloadRevocation, (self.space_id, "attempt-a")))

    def test_http_retirement_requires_revocation_and_returns_preserved_status(self):
        from hf2l_exchange.api import create_app
        app = create_app(self.settings, service=self.service, transfers=Mock())
        target = "/v2/spaces/" + self.space_id + "/managed/retire"
        headers = {"Authorization": self.token(), "Idempotency-Key": "http-retire"}
        with TestClient(app) as client:
            response = client.post(target, json={"job_id": "job-a"}, headers=headers)
            self.assertEqual(response.status_code, 409, response.text)
            self.assertEqual(response.json()["error"]["code"], "workload_revocation_required")
            self.revoke_attempt()
            response = client.post(target, json={"job_id": "job-a"}, headers=headers)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["status"], "retired")
            duplicate = client.post(target, json={"job_id": "job-a"}, headers=headers)
            self.assertEqual(duplicate.json(), response.json())
            current = client.get(target.removesuffix("/retire"), headers={"Authorization": self.token()})
            self.assertEqual(current.status_code, 200, current.text)
            self.assertTrue(current.json()["provenance_retained"])

    def test_http_retirement_route_excludes_nonprovisioners_and_wrong_job_bindings(self):
        from hf2l_exchange.api import create_app
        app = create_app(self.settings, service=self.service, transfers=Mock())
        target = "/v2/spaces/" + self.space_id + "/managed/retire"
        with TestClient(app) as client:
            for subject in ("human-admin", "broker"):
                response = client.post(target, json={"job_id": "job-a"},
                    headers={"Authorization": self.token(sub=subject), "Idempotency-Key": "forbidden"})
                self.assertEqual(response.status_code, 403, response.text)
                self.assertEqual(response.json()["error"]["code"], "provisioning_principal_required")
            response = client.post(target, json={"job_id": "job-b"},
                headers={"Authorization": self.token(), "Idempotency-Key": "foreign-job"})
            self.assertEqual(response.status_code, 409, response.text)
            self.assertEqual(response.json()["error"]["code"], "managed_space_binding_required")


if __name__ == "__main__":
    unittest.main()
