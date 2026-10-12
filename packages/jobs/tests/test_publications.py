"""Lost-ack publication resolution against immutable server receipts and fences."""
from datetime import timedelta
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from hf2l_jobs.database import create_database
from hf2l_jobs.domain import JobSpec, utcnow
from hf2l_jobs.models import Project, Job, Attempt, ProvisioningOperation
from hf2l_jobs.publications import AuthoritativePublicationObserver
from hf2l_exchange.client_types import ExchangeError


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.db = create_database("sqlite://")
        self.addCleanup(self.db.close)
        self.spec = JobSpec.model_validate({"project_id": "project", "name": "Job", "source_id": "source",
            "source_commit": "a" * 40, "runtime_image": "runtime", "plugin": "plugin", "components": [{
                "component_id": "owner", "role": "owner", "resources": {"pool_id": "pool", "cpu_millicores": 100,
                    "memory_bytes": 64 * 1024**2, "disk_bytes": 64 * 1024**2}}],
            "target_round": 1, "max_duration_seconds": 600})
        with self.db.transaction() as session:
            session.add(Project(id="project", name="Project"))
            session.flush()
            self.job = Job(id="job", project_id="project", creator_id="human", name="Job", spec_json=self.spec.to_dict(),
                           spec_hash=self.spec.digest, target_round=1)
            session.add(self.job)
            session.flush()
            self.attempt = Attempt(id="attempt", job_id="job", number=1, epoch=1, revocation_confirmed=True)
            session.add(self.attempt)
            session.flush()
            for op in ("start", "revoke", "stop"):
                session.add(ProvisioningOperation(id=op, job_id="job", attempt_id="attempt", component_id="owner",
                    operation=op, idempotency_key=op, state="confirmed", desired_json={}, observed_json={}))
        self.document = {"round": 0, "checkpoint_files_sha256": {"weights.safetensors": "a" * 64}}
        data = json.dumps(self.document, sort_keys=True).encode()
        self.manifest_sha = hashlib.sha256(data).hexdigest()
        (self.root / "initial-model").mkdir()
        (self.root / "initial-model/fedavg_round.json").write_bytes(data)
        (self.root / "initialization.json").write_text(json.dumps({
            "phase": "uncertain", "binding": {"job_id": "job"}, "manifest_sha256": self.manifest_sha,
            "checkpoint_files_sha256": {"weights.safetensors": "a" * 64}}))
        (self.root / "initial-model.exchange-upload.json").write_text(json.dumps({"key": "upload-key", "record_id": "record"}))
        (self.root / "progress.json").write_text(json.dumps({"job_id": "job", "component_id": "owner", "phase": "failed"}))
        self.record = SimpleNamespace(id="record", space_id="space", creator="principal", creator_bindings={},
            kind="model.global", state="published", metadata={"hf2l_files": {"fedavg_round.json": self.document}},
            attachments=(SimpleNamespace(path="weights.safetensors", sha256="a" * 64),))
        self.main_id = "record"
        fixture = self
        class Exchange:
            def path(self, space, suffix):
                return "/v2/spaces/" + space + suffix
            def request(self, method, path):
                if fixture.main_id is None:
                    raise ExchangeError(404, "reference_not_found")
                return {"record_id": fixture.main_id}
            def get_record(self, space, record_id):
                if record_id != fixture.record.id:
                    raise ExchangeError(404, "record_not_found")
                return fixture.record
        self.observer = AuthoritativePublicationObserver(self.db, Exchange(),
                state_roots=lambda job, attempt: {"owner": self.root},
                principal=lambda job_id, component_id, participant_id: "principal")

    def test_accepted_initial_publication_lost_ack_matches_hashes_and_identity(self):
        result = self.observer(self.job, self.attempt, "space")
        self.assertTrue(result.known, result.evidence)
        self.assertEqual(result.status, "confirmed")
        self.assertEqual(result.current_round, 0)
        with self.db.transaction(immediate=False) as session:
            directives = session.get(Attempt, "attempt").details_json["reconciliation_directives"]
        proof = directives["owner"][0]
        self.assertEqual(proof["record_id"], "record")
        self.assertEqual(proof["revocation_operation_id"], "revoke")
        self.assertEqual(proof["termination_operation_id"], "stop")
        self.assertEqual(proof["action"], "confirmed")

    def test_exact_draft_after_revocation_and_stop_proves_nonpublication(self):
        self.main_id = None
        self.record.state = "draft"
        result = self.observer(self.job, self.attempt, "space")
        self.assertTrue(result.known, result.evidence)
        self.assertEqual(result.evidence["directives"]["owner"][0]["action"], "absent")

    def test_foreign_principal_or_hash_cannot_authorize_replay(self):
        for kind in ("creator", "hash", "manifest"):
            with self.subTest(kind=kind):
                old_creator, old_attachment, old_doc = self.record.creator, self.record.attachments, self.record.metadata
                if kind == "creator":
                    self.record.creator = "foreign"
                elif kind == "hash":
                    self.record.attachments = (SimpleNamespace(path="weights.safetensors", sha256="b" * 64),)
                else:
                    self.record.metadata = {"hf2l_files": {"fedavg_round.json": {"round": 0}}}
                self.assertFalse(self.observer(self.job, self.attempt, "space").known)
                self.record.creator, self.record.attachments, self.record.metadata = old_creator, old_attachment, old_doc

    def test_missing_creation_receipt_or_record_is_never_absence(self):
        for payload in ({"key": "lost-create"}, {"key": "saved", "record_id": "missing"}):
            (self.root / "initial-model.exchange-upload.json").write_text(json.dumps(payload))
            self.assertFalse(self.observer(self.job, self.attempt, "space").known)

    def test_current_round_does_not_bypass_unconfirmed_intent(self):
        self.record.state = "draft"
        self.assertFalse(self.observer(self.job, self.attempt, "space").known)

    def test_user_claim_does_not_replace_server_proof(self):
        self.attempt.details_json = {"reconciliation_evidence": {"publication_id": "record", "outcome": "published"}}
        self.record.creator = "foreign"
        self.assertFalse(self.observer(self.job, self.attempt, "space").known)

    def test_revocation_must_be_durably_confirmed(self):
        with self.db.transaction() as session:
            session.get(Attempt, "attempt").revocation_confirmed = False
        self.assertFalse(self.observer(self.job, self.attempt, "space").known)

    def test_remote_bounded_reader_uses_exact_execution_identity(self):
        from hf2l_jobs.collection import SafeCollector, CollectionError
        calls = []
        def read_state(identity, path, *, max_bytes):
            calls.append((identity, path, max_bytes))
            with SafeCollector(self.root) as collector:
                try:
                    return collector.read(path, max_bytes=max_bytes)
                except CollectionError as error:
                    if isinstance(error.__cause__, FileNotFoundError):
                        return None
                    raise
        observer = AuthoritativePublicationObserver(self.db, self.observer.exchange,
            principal=self.observer.principal, state_reader=read_state)
        result = observer(self.job, self.attempt, "space")
        self.assertTrue(result.known, result.evidence)
        self.assertEqual(result.evidence["directives"]["owner"][0]["record_id"], "record")
        self.assertTrue(calls)
        for identity, path, bound in calls:
            self.assertEqual((identity.job_id, identity.attempt_id, identity.component_id, identity.epoch),
                             ("job", "attempt", "owner", 1))
            self.assertLessEqual(bound, 1024 * 1024)
            self.assertFalse(path.startswith("/"))

    def test_remote_transport_failure_and_oversized_reply_are_unknown(self):
        def unavailable(identity, path, *, max_bytes):
            raise RuntimeError("Node receipt is unavailable")
        def oversized(identity, path, *, max_bytes):
            return b"x" * (max_bytes + 1)
        for reader in (unavailable, oversized):
            with self.subTest(reader=reader.__name__):
                observer = AuthoritativePublicationObserver(self.db, self.observer.exchange,
                    principal=self.observer.principal, state_reader=reader)
                self.assertFalse(observer(self.job, self.attempt, "space").known)

    def test_remote_reader_rejects_paths_before_contacting_node(self):
        from hf2l_jobs.executor import ExecutionIdentity
        from hf2l_jobs.publications import _RemoteState, PublicationEvidenceError
        calls = []
        reader = _RemoteState(lambda *args, **kwargs: calls.append(args),
                              ExecutionIdentity("job", "attempt", "owner", 1))
        for path in ("../foreign.json", "/host/file.json", "a//b.json", "a/./b.json",
                     "a\\b.json", "a\nfile.json"):
            with self.subTest(path=path), self.assertRaises(PublicationEvidenceError):
                reader.read(path)
        self.assertEqual(calls, [])

    def test_no_start_operation_is_authoritative_absence(self):
        with self.db.transaction() as session:
            session.delete(session.get(ProvisioningOperation, "start"))
        result = self.observer(self.job, self.attempt, None)
        self.assertTrue(result.known)
        self.assertEqual(result.status, "absent")


if __name__ == "__main__":
    unittest.main()
