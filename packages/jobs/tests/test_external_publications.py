"""External client lost-ack recovery requires exact stopped execution receipts."""
from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
import unittest

from sqlalchemy import update

import test_publications as managed_fixtures
from hf2l_exchange.client_types import ExchangeError
from hf2l_jobs.domain import JobSpec
from hf2l_jobs.executor import ExecutionIdentity
from hf2l_jobs.models import Attempt, Job, ProvisioningOperation, ProvisioningResource
from hf2l_jobs.provisioning import Provisioner
from hf2l_jobs.publications import AuthoritativePublicationObserver
from hf2l_jobs.workflow import publication_intent_fingerprint


class ExternalPublicationTests(unittest.TestCase):
    def setUp(self):
        fixture = self.fixture = managed_fixtures.PublicationTests(
            methodName="test_accepted_initial_publication_lost_ack_matches_hashes_and_identity")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        payload = fixture.spec.to_dict()
        payload["participants"] = [{"participant_id": "alice", "dataset_binding": "alice-local", "mode": "external"}]
        self.spec = JobSpec.model_validate(payload)
        self.cid = Provisioner.external_component("alice")
        self.identity = ExecutionIdentity("external-job", "external-attempt", self.cid, 1)
        self.stop_id = "external-stop-receipt"
        self.resource_id = "external-execution-receipt"
        with fixture.db.transaction() as session:
            self.job = Job(id=self.identity.job_id, project_id="project", creator_id="human",
                           name="External job", spec_json=self.spec.to_dict(), spec_hash=self.spec.digest,
                           target_round=1)
            session.add(self.job)
            session.flush()
            self.attempt = Attempt(id=self.identity.attempt_id, job_id=self.job.id,
                                   number=1, epoch=1, revocation_confirmed=True)
            session.add(self.attempt)
            session.flush()
            for suffix, component, operation in (
                    ("owner-start", "owner", "start"), ("revoke", "owner", "revoke"),
                    ("owner-stop", "owner", "stop"), (self.stop_id, self.cid, "stop")):
                session.add(ProvisioningOperation(id="external-" + suffix if suffix != self.stop_id else suffix,
                    job_id=self.job.id, attempt_id=self.attempt.id, component_id=component,
                    operation=operation, idempotency_key="external-" + suffix,
                    state="confirmed", desired_json={}, observed_json={}))
            session.add(ProvisioningResource(
                id=self.resource_id, job_id=self.job.id, attempt_id=self.attempt.id,
                component_id=self.cid, kind="external_execution", external_id=self.identity.key,
                state="ready", retained=True,
                ownership_json={"job_id": self.job.id, "attempt_id": self.attempt.id, "component_id": self.cid},
                details_json={"node_id": "external-node", "node_certificate_thumbprint": "b" * 43,
                              "participant_id": "alice", "dataset_binding": "alice-local",
                              "spec_digest": self.spec.digest, "epoch": 1, "source_manifest": {},
                              "termination_confirmed": True, "termination_operation_id": self.stop_id}))
        (fixture.root / "initialization.json").unlink()
        (fixture.root / "progress.json").write_text(json.dumps({
            "job_id": self.job.id, "component_id": "owner", "phase": "completed"}))
        self.global_record = SimpleNamespace(
            id="global-target", space_id="space", creator="owner-principal", creator_bindings={},
            kind="model.global", state="published", attachments=(),
            metadata={"hf2l_files": {"fedavg_round.json": {"round": 1}}})
        self.submission = {"participant": "alice", "base_revision": "global-base",
                           "round": 0, "num_examples": 8,
                           "checkpoint_files_sha256": {"weights.safetensors": "b" * 64}}
        self.intent = {"repo_id": "space", "participant": "alice", "base_revision": "global-base",
                       "submission_revision": "client-output", "submitted_at": "2026-10-09T22:00:00Z",
                       "checkpoint_files_sha256": {"weights.safetensors": "b" * 64}}
        self.client_record = SimpleNamespace(
            id="client-record", space_id="space", creator="alice-principal",
            creator_bindings={"participant": "alice"}, kind="training.update", state="published",
            metadata={"base_record_id": "global-base", "hf2l_files": {"fedavg_submission.json": self.submission}},
            attachments=(SimpleNamespace(path="weights.safetensors", sha256="b" * 64),))
        directory = "listener/jobs/" + hashlib.sha256(b"global-base").hexdigest() + "/work"
        self.upload_path = directory + "/trained_model.exchange-upload.json"
        self.files = {
            "progress.json": self.encode({"job_id": self.job.id, "attempt_id": self.attempt.id,
                                         "component_id": self.cid, "epoch": 1, "participant_id": "alice",
                                         "role": "client", "phase": "failed"}),
            "listener/state.json": self.encode({"active": "global-base", "jobs": {
                "global-base": {"revision": "global-base", "source_round": 0, "status": "uncertain"}}}),
            directory + "/client-publication-intent.json": self.encode(self.intent),
            self.upload_path: self.encode({"key": "external-client-upload", "record_id": "client-record"}),
            directory + "/trained_model/fedavg_submission.json": self.encode(self.submission),
        }
        self.calls = []
        test = self
        class Exchange:
            def path(self, space, suffix):
                return "/v2/spaces/" + space + suffix
            def request(self, method, path):
                return {"record_id": "global-target"}
            def get_record(self, space, record_id):
                records = {"global-target": test.global_record, "client-record": test.client_record}
                if record_id not in records:
                    raise ExchangeError(404, "record_not_found")
                return records[record_id]
        self.exchange = Exchange()
        self.observer = self.make_observer()

    @staticmethod
    def encode(document):
        return json.dumps(document, sort_keys=True).encode()

    def read_external(self, identity, path, *, max_bytes):
        self.calls.append((identity, path, max_bytes))
        self.assertEqual(identity, self.identity)
        self.assertLessEqual(max_bytes, 1024 * 1024)
        self.assertFalse(path.startswith("/"))
        return self.files.get(path)

    def make_observer(self, reader="default"):
        return AuthoritativePublicationObserver(
            self.fixture.db, self.exchange,
            state_roots=lambda job, attempt: {"owner": self.fixture.root},
            principal=lambda job_id, component_id, participant_id:
                "alice-principal" if component_id == self.cid and participant_id == "alice" else "owner-principal",
            external_state_reader=self.read_external if reader == "default" else reader)

    def update_details(self, **changes):
        with self.fixture.db.transaction() as session:
            resource = session.get(ProvisioningResource, self.resource_id)
            original = dict(resource.details_json)
            # Explicit UPDATE preserves JSON type differences (True versus 1)
            # that Python equality would hide from ORM dirty comparison.
            session.execute(update(ProvisioningResource).where(
                ProvisioningResource.id == self.resource_id).values(details_json={**original, **changes}))
        return original

    def observe(self):
        return self.observer(self.job, self.attempt, "space")

    def test_unstopped_external_blocks_resolution_even_when_main_reached_target(self):
        self.update_details(termination_confirmed=False)
        result = self.observe()
        self.assertFalse(result.known, result.evidence)
        self.assertEqual(result.status, "unknown")
        self.assertEqual(self.calls, [])

    def test_missing_external_reader_or_stop_receipt_cannot_be_replaced_by_main(self):
        self.assertFalse(self.make_observer(reader=None)(self.job, self.attempt, "space").known)
        self.update_details(termination_operation_id=None)
        self.assertFalse(self.observe().known)

    def test_exact_published_external_client_receipt_produces_stable_component_directive(self):
        result = self.observe()
        self.assertTrue(result.known, result.evidence)
        self.assertEqual(result.current_round, 1)
        proof = result.evidence["directives"][self.cid][0]
        self.assertEqual(proof["role"], "client")
        self.assertEqual(proof["action"], "confirmed")
        self.assertEqual(proof["record_id"], "client-record")
        self.assertEqual(proof["old_attempt_id"], self.attempt.id)
        self.assertEqual(proof["old_epoch"], 1)
        self.assertEqual(proof["termination_operation_id"], self.stop_id)
        self.assertEqual(proof["intent_sha256"], publication_intent_fingerprint("client", self.intent))
        self.assertTrue(self.calls)
        with self.fixture.db.transaction(immediate=False) as session:
            saved = session.get(Attempt, self.attempt.id).details_json["reconciliation_directives"]
        self.assertEqual(saved[self.cid][0], proof)

    def test_old_epoch_foreign_spec_and_wrong_participant_execution_are_rejected(self):
        for changes in ({"epoch": 2}, {"epoch": True}, {"spec_digest": "f" * 64}, {"participant_id": "bob"},
                        {"dataset_binding": "foreign-dataset"}):
            with self.subTest(changes=changes):
                old = self.update_details(**changes)
                self.assertFalse(self.observe().known)
                self.update_details(**old)
        with self.fixture.db.transaction() as session:
            resource = session.get(ProvisioningResource, self.resource_id)
            resource.ownership_json = {**resource.ownership_json, "job_id": "foreign-job"}
        self.assertFalse(self.observe().known)

    def test_foreign_principal_hash_base_and_participant_server_receipts_are_rejected(self):
        for field in ("creator", "hash", "base", "participant"):
            old_creator, old_attachments = self.client_record.creator, self.client_record.attachments
            old_metadata, old_binding = self.client_record.metadata, self.client_record.creator_bindings
            with self.subTest(field=field):
                if field == "creator":
                    self.client_record.creator = "foreign-principal"
                elif field == "hash":
                    self.client_record.attachments = (SimpleNamespace(path="weights.safetensors", sha256="c" * 64),)
                elif field == "base":
                    self.client_record.metadata = {**old_metadata, "base_record_id": "foreign-base"}
                else:
                    self.client_record.creator_bindings = {"participant": "bob"}
                self.assertFalse(self.observe().known)
            self.client_record.creator, self.client_record.attachments = old_creator, old_attachments
            self.client_record.metadata, self.client_record.creator_bindings = old_metadata, old_binding

    def test_missing_creation_receipt_and_unavailable_or_oversized_node_state_remain_unknown(self):
        for document in ({"key": "lost-create"}, {"key": "saved", "record_id": "missing-record"}):
            with self.subTest(document=document):
                self.files[self.upload_path] = self.encode(document)
                self.assertFalse(self.observe().known)
        self.files[self.upload_path] = self.encode({"key": "external-client-upload", "record_id": "client-record"})
        def unavailable(*args, **kwargs):
            raise RuntimeError("external node unreachable")
        def oversized(identity, path, *, max_bytes):
            return b"x" * (max_bytes + 1)
        for reader in (unavailable, oversized):
            with self.subTest(reader=reader.__name__):
                result = self.make_observer(reader)(self.job, self.attempt, "space")
                self.assertFalse(result.known)


if __name__ == "__main__":
    unittest.main()
