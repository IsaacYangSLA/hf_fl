"""Project administration recovery and identity boundaries."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from hf2l_exchange.client_types import ExchangeError, MemberDescriptor, RecordDescriptor, ReferenceSnapshot, SpaceDescriptor
from hf2l_exchange.domain import principal_id

SPEC = importlib.util.spec_from_file_location("first_federation_project", Path(__file__).parents[1] / "project.py")
project = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(project)

ENDPOINT = "https://exchange.example.org"
ISSUER = "https://auth.example.org/realms/hf2l"
RECEIPT = {"issuer": ISSUER, "client_id": "hf2l-cli", "accounts": {
    name: {"username": name, "subject": name + "-actual-subject",
           "principal_id": principal_id(ISSUER, name + "-actual-subject")}
    for name in ("bootstrap-admin", "owner", "alice", "bob")
}}


class FakeExchange:
    def __init__(self):
        self.creates = []
        self.types = {}
        self.people = {}
        self.fail_create = False
        self.fail_type = None
        self.space = SpaceDescriptor("opaque-space", "first-federation", "fedavg.v1")
        self.reference = ReferenceSnapshot("main", "immutable-base", "1")
        self.record = RecordDescriptor("immutable-base", "opaque-space", "model.global", "type-global",
            {"hf2l_files": {"fedavg_round.json": {"round": 0}}, "password": "must-not-export"},
            "published", 1, True, "owner")
        self.on_create = lambda: None

    def create_space(self, name, *, profile, idempotency_key):
        self.on_create()
        self.creates.append(idempotency_key)
        if self.fail_create:
            self.fail_create = False
            raise ExchangeError(503, "ambiguous_create")
        return self.space

    def get_space(self, sid):
        assert sid == self.space.id
        return self.space

    def register_type(self, sid, kind, schema, *, publish_roles, visibility, idempotency_key):
        self.types.setdefault(idempotency_key, (kind, schema, publish_roles, visibility))
        if kind == self.fail_type:
            self.fail_type = None
            raise ExchangeError(503, "ambiguous_type")
        return SimpleNamespace(id=kind)

    def set_member(self, sid, principal, roles, *, subject=None, bindings=None):
        value = MemberDescriptor(principal, tuple(roles), subject, bindings or {})
        self.people[principal] = value
        return value

    def members(self, sid):
        return tuple(self.people.values())

    def get_membership(self, sid):
        return self.people[RECEIPT["accounts"]["owner"]["principal_id"]]

    def resolve(self, sid, name):
        return self.reference

    def get_record(self, sid, rid):
        return self.record


class ProjectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "project.json"
        self.client = FakeExchange()

    def create(self, **kwargs):
        return project.create_project(self.client, self.path, name=kwargs.get("name", "first-federation"),
                                      receipt=kwargs.get("receipt", RECEIPT), owner="owner", endpoint=ENDPOINT)

    def enroll(self, user="alice", participant="alice"):
        return project.enroll(self.client, self.path, receipt=RECEIPT, user=user,
                              participant=participant, endpoint=ENDPOINT)

    def test_creation_saves_intent_before_first_network_call(self):
        def before():
            state = project.read_json(self.path)
            self.assertIn("operation_key", state)
            self.assertNotIn("space_id", state)
        self.client.on_create = before
        state = self.create()
        self.assertTrue(state["completed"])
        self.assertEqual(state["space_id"], "opaque-space")
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_ambiguous_create_reuses_original_operation_identity(self):
        self.client.fail_create = True
        with self.assertRaises(ExchangeError):
            self.create()
        state = self.create()
        self.assertEqual(len(self.client.creates), 2)
        self.assertEqual(self.client.creates[0], self.client.creates[1])
        self.assertEqual(state["space_id"], self.client.space.id)

    def test_partial_setup_retains_space_and_reuses_type_keys(self):
        self.client.fail_type = "training.update"
        with self.assertRaises(ExchangeError):
            self.create()
        self.assertEqual(project.read_json(self.path)["space_id"], self.client.space.id)
        self.create()
        self.assertEqual(len(self.client.creates), 1)
        self.assertEqual(len(self.client.types), 2)
        policies = {item[0]: (item[2], item[3]) for item in self.client.types.values()}
        self.assertEqual(policies["model.global"], (["publisher"], "shared"))
        self.assertEqual(policies["training.update"], (["contributor"], "private"))

    def test_repeated_complete_setup_does_not_restore_modified_membership(self):
        self.create()
        self.client.people.clear()
        self.create()
        self.assertFalse(self.client.people)
        self.assertEqual(len(self.client.creates), 1)

    def test_different_create_intent_is_rejected_before_network(self):
        self.create()
        with self.assertRaisesRegex(ValueError, "intent differs"):
            self.create(name="another-project")
        self.assertEqual(len(self.client.creates), 1)

    def test_owner_receives_all_explicit_required_roles(self):
        self.create()
        owner = self.client.people[RECEIPT["accounts"]["owner"]["principal_id"]]
        self.assertEqual(set(owner.roles), {"admin", "publisher", "reader"})
        self.assertFalse(owner.bindings)

    def test_participant_identity_is_derived_from_actual_trusted_subject(self):
        self.create()
        result = self.enroll()
        self.assertEqual(result["principal"], principal_id(ISSUER, "alice-actual-subject"))
        self.assertEqual(result["subject"], "alice-actual-subject")
        self.assertEqual(set(result["roles"]), {"reader", "contributor"})
        self.assertEqual(result["bindings"], {"participant": "alice"})

    def test_receipt_inconsistent_hash_is_rejected(self):
        receipt = json.loads(json.dumps(RECEIPT))
        receipt["accounts"]["owner"]["principal_id"] = "untrusted"
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.create(receipt=receipt)
        self.assertFalse(self.client.creates)

    def test_rejects_foreign_issuer_and_reused_participant(self):
        self.create()
        self.enroll()
        with self.assertRaisesRegex(ValueError, "already assigned"):
            self.enroll("bob", "alice")
        with self.assertRaisesRegex(ValueError, "different participant"):
            self.enroll("alice", "another-alice")
        foreign = json.loads(json.dumps(RECEIPT))
        foreign["issuer"] = "https://foreign.example.org/realms/hf2l"
        for name, account in foreign["accounts"].items():
            account["principal_id"] = principal_id(foreign["issuer"], account["subject"])
        with self.assertRaisesRegex(ValueError, "issuer differs"):
            project.enroll(self.client, self.path, receipt=foreign, user="bob",
                           participant="bob", endpoint=ENDPOINT)

    def test_owner_cannot_be_replaced_with_contributor_membership(self):
        self.create()
        with self.assertRaisesRegex(ValueError, "distinct accounts"):
            self.enroll("owner", "owner")

    def test_invitation_exports_allowlist_and_exact_immutable_base(self):
        self.create()
        self.enroll()
        state = project.read_json(self.path)
        state["refresh_token"] = "must-not-export"
        state["private_key"] = "must-not-export"
        value = project.invitation(self.client, state, participant="alice", source_revision="a" * 40)
        self.assertEqual(set(value), {"schema_version", "endpoint", "issuer", "client_id", "space_id",
            "participant", "base_revision", "source_round", "source_revision", "model_agreement"})
        self.assertEqual(value["base_revision"], "immutable-base")
        self.assertEqual(value["source_round"], 0)
        self.assertNotIn("must-not-export", json.dumps(value))

    def test_invitation_rejects_revoked_or_rebound_membership(self):
        self.create()
        self.enroll()
        self.client.people[RECEIPT["accounts"]["alice"]["principal_id"]] = MemberDescriptor(
            RECEIPT["accounts"]["alice"]["principal_id"], ("reader",), bindings={"participant": "alice"})
        with self.assertRaisesRegex(ValueError, "revoked or rebound"):
            project.invitation(self.client, project.read_json(self.path), participant="alice", source_revision="a" * 40)

    def test_invitation_requires_exact_source_revision(self):
        self.create()
        self.enroll()
        with self.assertRaisesRegex(ValueError, "40-character"):
            project.invitation(self.client, project.read_json(self.path), participant="alice", source_revision="main")

    def test_authenticated_endpoint_must_match_saved_state(self):
        self.create()
        with self.assertRaisesRegex(ValueError, "endpoint differs"):
            project.load_state(self.path, "https://different.example.org")

    def test_inspect_returns_current_reference_and_authorized_record(self):
        state = self.create()
        result = project.inspect_project(self.client, state)
        self.assertEqual(result["reference"]["record_id"], "immutable-base")
        self.assertEqual(result["record"]["id"], "immutable-base")

    def test_inspect_handles_uninitialized_project_only(self):
        state = self.create()
        self.client.resolve = lambda *_: (_ for _ in ()).throw(ExchangeError(404, "reference_not_found"))
        self.assertIsNone(project.inspect_project(self.client, state)["reference"])
        self.client.resolve = lambda *_: (_ for _ in ()).throw(ExchangeError(403, "forbidden"))
        with self.assertRaises(ExchangeError):
            project.inspect_project(self.client, state)

    def test_state_writer_rejects_symlink(self):
        target = self.path.with_name("target")
        target.write_text("unchanged")
        self.path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            project.write_json(self.path, {})
        self.assertEqual(target.read_text(), "unchanged")


if __name__ == "__main__":
    unittest.main()
