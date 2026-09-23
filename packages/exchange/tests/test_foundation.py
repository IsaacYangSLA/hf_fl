"""Foundation invariants, tested without HTTP routes or an ML installation."""
import json
import time
import unittest
from unittest.mock import patch
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import event, inspect, text
from sqlalchemy.exc import IntegrityError, OperationalError
from hf2l_exchange.auth import Authenticator, principal_id
from hf2l_exchange.config import AuthSettings, DatabaseSettings, Settings, StorageSettings, require_tls
from hf2l_exchange.domain import Error, Principal
from hf2l_exchange.migrations import EXPECTED_COLUMNS, SCHEMA_REVISION, check, check_revision, initialize
from hf2l_exchange.models import Blob, TransferAttempt, Base, Coordination, CoordinationInput, Member, Record, Reference, SchemaRevision, Space, database, database_time
from hf2l_exchange.profiles import get_profile
from hf2l_exchange.schemas import MAX_ATTACHMENTS, metadata_size, schema_digest, validate_metadata, validate_path, validate_schema


class SchemaTests(unittest.TestCase):
    def test_generic_schema_and_immutable_digest(self):
        schema = {"type": "object", "properties": {"label": {"type": "string"}}, "required": ["label"]}
        validate_schema(schema)
        self.assertGreater(validate_metadata({"label": "hello"}, schema), 0)
        self.assertEqual(schema_digest(schema), schema_digest(dict(reversed(list(schema.items())))))
        with self.assertRaisesRegex(Error, "metadata_schema_mismatch"):
            validate_metadata({"label": 42}, schema)
        self.assertEqual(MAX_ATTACHMENTS, 256)

    def test_metadata_depth_size_and_json_numbers(self):
        value = {}
        for _ in range(17):
            value = {"nested": value}
        with self.assertRaisesRegex(Error, "metadata_too_deep"):
            metadata_size(value)
        for value in ({"value": float("nan")}, {1: "value"}):
            with self.assertRaises(Error):
                metadata_size(value)
        with self.assertRaisesRegex(Error, "metadata_too_large"):
            metadata_size({"value": "x" * 65536})

    def test_schema_references_are_local_bounded_and_never_fetch(self):
        schema = {"type": "object", "$defs": {"item": {"type": "string"}},
                  "properties": {"name": {"$ref": "#/$defs/item"}}}
        validate_schema(schema)
        validate_metadata({"name": "x"}, schema)
        for reference in ("https://example.com/schema", "#", "#/$defs/missing"):
            with self.assertRaises(Error):
                validate_schema({"type": "object", "properties": {"name": {"$ref": reference}}})
        with self.assertRaises(Error):
            validate_metadata({}, {"type": "object", "$ref": "https://example.invalid/schema"})
        with self.assertRaises(Error):
            validate_schema({"type": "object", "$defs": {"item": {"$ref": "#/$defs/item"}}})

    def test_local_reference_can_address_array(self):
        schema = {"type": "object", "allOf": [{"properties": {"x": {"type": "string"}}}],
                  "properties": {"nested": {"$ref": "#/allOf/0"}}}
        validate_schema(schema)
        validate_metadata({"nested": {"x": "ok"}}, schema)

    def test_paths_are_safe_relative_names(self):
        self.assertEqual(validate_path("models/weights.bin"), "models/weights.bin")
        for path in ("/abs", "../escape", "a/../b", "a//b", "./a", "a\\b", "C:/drive", "a\x00b", ""):
            with self.subTest(path=path), self.assertRaises(Error):
                validate_path(path)


class ConfigurationTests(unittest.TestCase):
    def test_transport_security_and_development_exception(self):
        self.assertEqual(require_tls("https://service.example"), "https://service.example")
        self.assertEqual(require_tls("http://127.0.0.1:9000", True), "http://127.0.0.1:9000")
        for url in ("http://service.example", "http://10.1.2.3", "https://user:secret@example.com", "file:///tmp/x"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                require_tls(url, True)
        with self.assertRaises(ValueError):
            require_tls("http://localhost")

    def test_database_command_configuration_has_no_external_dependencies(self):
        with patch.dict("os.environ", {}, clear=True):
            config = Settings.from_env(component="database")
        self.assertIsInstance(config.database, DatabaseSettings)
        self.assertEqual(config.auth.issuer, "")
        self.assertEqual(config.storage.bucket, "")

    def test_invalid_settings_rejected(self):
        with self.assertRaises(ValueError):
            StorageSettings(bucket="bucket", endpoint="http://object.example").validate()
        with self.assertRaises(ValueError):
            StorageSettings(bucket="bucket", part_size=1).validate()
        with self.assertRaises(ValueError):
            AuthSettings(issuer="https://issuer", public_key="key", jwks_url="https://issuer/keys").validate()
        with self.assertRaises(ValueError):
            Settings(draft_seconds=9999999).validate(component="database")


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.engine, self.sessions = database("sqlite:///:memory:")

    def tearDown(self):
        self.engine.dispose()

    def test_frozen_baseline_matches_mapping_and_replays_idempotently(self):
        self.assertEqual(initialize(self.engine), SCHEMA_REVISION)
        self.assertEqual(initialize(self.engine), SCHEMA_REVISION)
        self.assertEqual(check(self.engine), SCHEMA_REVISION)
        self.assertEqual({name: tuple(table.c.keys()) for name, table in Base.metadata.tables.items()}, EXPECTED_COLUMNS)
        with self.sessions.begin() as session:
            self.assertLess(abs(database_time(session) - time.time()), 1)

    def test_readiness_never_initializes(self):
        with self.assertRaisesRegex(Error, "database_not_initialized"):
            check(self.engine)
        self.assertEqual(inspect(self.engine).get_table_names(), [])

    def test_request_revision_check_avoids_catalog_queries(self):
        initialize(self.engine)
        statements = []
        def observe(connection, cursor, statement, parameters, context, executemany):
            statements.append(statement)
        event.listen(self.engine, "before_cursor_execute", observe)
        try:
            self.assertEqual(check_revision(self.engine), SCHEMA_REVISION)
        finally:
            event.remove(self.engine, "before_cursor_execute", observe)
        selects = [statement for statement in statements if statement.lstrip().upper().startswith("SELECT")]
        self.assertEqual(selects, ["SELECT revision FROM v2_schema_ledger ORDER BY revision"])
        self.assertFalse(any("PRAGMA" in statement.upper() for statement in statements))

    def test_request_revision_check_fails_closed_without_initializing(self):
        with self.assertRaises(Error) as caught:
            check_revision(self.engine)
        self.assertEqual(caught.exception.status, 503)
        self.assertEqual(caught.exception.code, "database_not_initialized")
        self.assertEqual(inspect(self.engine).get_table_names(), [])
        initialize(self.engine)
        with self.engine.begin() as connection:
            connection.execute(text("DELETE FROM v2_schema_ledger"))
        with self.assertRaisesRegex(Error, "database_revision_incompatible"):
            check_revision(self.engine)
        with self.engine.begin() as connection:
            connection.execute(text("INSERT INTO v2_schema_ledger(revision) VALUES ('future')"))
        with self.assertRaisesRegex(Error, "database_revision_incompatible"):
            check_revision(self.engine)

    def test_request_revision_check_rejects_extra_history_and_database_outage(self):
        initialize(self.engine)
        with self.engine.begin() as connection:
            connection.execute(text("INSERT INTO v2_schema_ledger(revision) VALUES ('future')"))
        with self.assertRaisesRegex(Error, "database_revision_incompatible"):
            check_revision(self.engine)
        with patch.object(self.engine, "connect", side_effect=OperationalError("connect", {}, OSError("offline"))):
            with self.assertRaises(Error) as caught:
                check_revision(self.engine)
        self.assertEqual(caught.exception.status, 503)
        self.assertEqual(caught.exception.code, "database_unavailable")

    def test_legacy_database_is_rejected(self):
        with self.engine.begin() as connection:
            connection.execute(text("CREATE TABLE exchange_spaces (id TEXT)"))
        with self.assertRaisesRegex(Error, "fresh database"):
            initialize(self.engine)

    def test_unknown_revision_and_partial_schema_are_rejected(self):
        initialize(self.engine)
        with self.engine.begin() as connection:
            connection.execute(text("UPDATE v2_schema_ledger SET revision='future'"))
        with self.assertRaisesRegex(Error, "database_revision_incompatible"):
            check(self.engine)

    def test_unversioned_partial_schema_is_not_adopted(self):
        with self.engine.begin() as connection:
            connection.execute(text("CREATE TABLE v2_spaces (id TEXT)"))
        with self.assertRaisesRegex(Error, "partial unversioned"):
            initialize(self.engine)

    def test_provider_mutation_markers_survive_worker_lease_expiry(self):
        initialize(self.engine)
        with self.sessions.begin() as session:
            session.add(Space(id="space", name="Space"))
            session.flush()
            session.add(SchemaRevision(id="type", space_id="space", kind="document", revision=1, schema={"type": "object"}))
            session.flush()
            session.add(Record(id="record", space_id="space", kind="document", schema_revision_id="type", creator="owner", expires_at=time.time()+60))
            session.flush()
            session.add(Blob(id="blob", space_id="space", record_id="record", path="file", size=10, sha256="a"*64, expires_at=time.time()+60))
            session.flush()
            session.add(TransferAttempt(id="attempt", blob_id="blob", object_key="unique", token="lease", lease_until=0,
                                        mutation_tokens=["first", "second"]))
        with self.sessions.begin() as session:
            attempt = session.get(TransferAttempt, "attempt")
            self.assertEqual(attempt.mutation_tokens, ["first", "second"])
            self.assertEqual(attempt.lease_until, 0)
            attempt.mutation_tokens = [token for token in attempt.mutation_tokens if token != "first"]
        with self.sessions() as session:
            self.assertEqual(session.get(TransferAttempt, "attempt").mutation_tokens, ["second"])

    def test_cross_space_record_and_coordination_links_are_rejected(self):
        initialize(self.engine)
        with self.sessions.begin() as session:
            session.add_all([Space(id="a", name="A"), Space(id="b", name="B")])
            session.flush()
            session.add_all([SchemaRevision(id="ta", space_id="a", kind="doc", revision=1, schema={"type": "object"}),
                             SchemaRevision(id="tb", space_id="b", kind="doc", revision=1, schema={"type": "object"})])
            session.flush()
            session.add(Record(id="ra", space_id="a", kind="doc", schema_revision_id="ta", creator="p", expires_at=time.time()+60))
        with self.assertRaises(IntegrityError), self.sessions.begin() as session:
            session.add(Record(id="bad", space_id="b", kind="doc", schema_revision_id="ta", creator="p", expires_at=time.time()+60))
        with self.assertRaises(IntegrityError), self.sessions.begin() as session:
            session.add(Reference(space_id="b", name="main", record_id="ra"))


class ProfileTests(unittest.TestCase):
    def test_generic_profile_needs_no_ml_fields(self):
        profile = get_profile("generic.v1")
        profile.validate_type("document", {"type": "object"})
        profile.validate_record("document", {"title": "x"}, {})
        profile.validate_reference("main", {"id": "doc", "kind": "document", "metadata": {}})
        with self.assertRaisesRegex(Error, "unknown_profile"):
            get_profile("user.import.module")

    def test_fedavg_attribution_and_sample_count(self):
        profile = get_profile("fedavg.v1")
        profile.validate_record("training.update", {"base_record_id": "base", "sample_count": 1}, {"participant": "alice"})
        for metadata, bindings in [({"base_record_id": "base", "sample_count": True}, {"participant": "alice"}),
                                   ({"base_record_id": "base", "sample_count": 1}, {})]:
            with self.assertRaises(Error):
                profile.validate_record("training.update", metadata, bindings)

    def test_profile_hooks_keep_generic_core_free_of_ml_policy(self):
        generic, fedavg = get_profile("generic.v1"), get_profile("fedavg.v1")
        self.assertIsNone(generic.selection_spec("main", "base"))
        self.assertEqual(fedavg.selection_spec("main", "base")["minimum"], 2)
        self.assertEqual(fedavg.policy_defaults("model.global")["publish_roles"], ["publisher"])
        generic.validate_bindings({"participant": "repeat"}, [{"participant": "repeat"}])
        with self.assertRaisesRegex(Error, "participant_already_bound"):
            fedavg.validate_bindings({"participant": "repeat"}, [{"participant": "repeat"}])
        with self.assertRaisesRegex(Error, "profile_policy_conflict"):
            fedavg.validate_policy("model.global", ["contributor"], "shared")
        fedavg.validate_reference("documents", {"kind": "document"})

    def test_profile_schema_rejects_indirect_mandatory_field_constraints(self):
        profile = get_profile("fedavg.v1")
        for schema in ({"type": "object", "allOf": [{"not": {"required": ["sample_count"]}}]},
                       {"type": "object", "properties": {"sample_count": {"type": "integer", "maximum": 0}}},
                       {"type": "object", "additionalProperties": {"type": "boolean"}}):
            with self.assertRaises(Error) as caught:
                profile.validate_type("training.update", schema)
            self.assertEqual(caught.exception.code, "profile_schema_conflict")
        profile.validate_type("document", {"type": "object", "allOf": []})

    def test_completion_can_use_valid_subset_of_frozen_inputs(self):
        profile = get_profile("fedavg.v1")
        frozen = [{"id": name, "kind": "training.update", "creator_bindings": {"participant": name},
                   "metadata": {"base_record_id": "base"}} for name in ("a", "b", "malformed")]
        result = {"kind": "model.global", "metadata": {"base_record_id": "base", "inputs": ["a", "b"]}}
        used = profile.completion_inputs(result, frozen)
        self.assertEqual([item["id"] for item in used], ["a", "b"])
        profile.validate_reference("main", result, used, "base")
        for ids in (["a"], ["a", "outside"], ["a", "a"]):
            with self.assertRaises(Error):
                profile.completion_inputs({"metadata": {"inputs": ids}}, frozen)

    def test_newest_selection_and_protected_publication(self):
        profile = get_profile("fedavg.v1")
        def update(id, participant, when):
            return {"id": id, "kind": "training.update", "published_at": when,
                    "metadata": {"base_record_id": "base"}, "creator_bindings": {"participant": participant}}
        inputs = [update("old", "a", 1), update("new", "a", 2), update("second", "b", 1)]
        selected = profile.select_inputs(inputs, "base")
        self.assertEqual([item["id"] for item in selected], ["new", "second"])
        result = {"id": "result", "kind": "model.global", "metadata": {"base_record_id": "base", "inputs": ["new", "second"]}}
        profile.validate_reference("main", result, selected, "base")
        with self.assertRaisesRegex(Error, "coordination_required"):
            profile.validate_reference("main", result, [], "base")
        with self.assertRaisesRegex(Error, "invalid_round_inputs"):
            profile.validate_reference("main", result, selected, "different")


class AuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public = cls.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def token(self, **overrides):
        claims = {"iss": "https://issuer.example", "aud": "exchange", "sub": "owner", "iat": time.time()-1,
                  "exp": time.time()+60, "scope": "exchange"}
        claims.update(overrides)
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"typ": "at+jwt"})

    def test_principal_is_issuer_bound_and_bootstrap_explicit(self):
        auth = Authenticator(AuthSettings(issuer="https://issuer.example", public_key=self.public, admin_subject="owner"))
        result = auth.authenticate("Bearer " + self.token())
        self.assertTrue(result.bootstrap_admin)
        self.assertEqual(result.id, principal_id("https://issuer.example", "owner"))
        self.assertNotEqual(result.id, principal_id("https://other.example", "owner"))
        with self.assertRaises(Error) as caught:
            auth.authenticate("Bearer " + self.token(aud="other"))
        self.assertEqual(caught.exception.status, 401)

    def test_jwks_outage_is_retryable_and_cooldown_prevents_storm(self):
        auth = Authenticator(AuthSettings(issuer="https://issuer.example", jwks_url="https://issuer.example/keys"))
        with patch.object(auth.jwks, "get_signing_key_from_jwt", side_effect=jwt.PyJWKClientConnectionError("offline")) as fetch:
            for _ in range(2):
                with self.assertRaises(Error) as caught:
                    auth.authenticate("Bearer " + self.token())
                self.assertEqual(caught.exception.status, 503)
                self.assertEqual(caught.exception.headers, {"Retry-After": "3"})
            self.assertEqual(fetch.call_count, 1)
