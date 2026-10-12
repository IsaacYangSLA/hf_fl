"""Storage is released only for immutable, fully confirmed node purge receipts."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from hf2l_jobs.database import create_database
from hf2l_jobs.domain import JobSpec, utcnow
from hf2l_jobs.executor import ExecutionIdentity
from hf2l_jobs.models import Project, Job, Attempt, Allocation, Pool
from hf2l_jobs.provisioning import Provisioner
from hf2l_jobs.resources import OwnedDirectories
from hf2l_jobs.retention import RetentionService
from hf2l_jobs.source import RegistryCatalog, SourceRegistry


class AuxiliaryReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "jobs"
        self.database = create_database("sqlite://")
        self.addCleanup(self.database.close)
        self.spec = JobSpec.model_validate({"project_id": "project", "name": "Job", "source_id": "source",
            "source_commit": "a" * 40, "runtime_image": "runtime", "plugin": "plugin",
            "target_round": 1, "max_duration_seconds": 600, "components": [{"component_id": "owner",
            "role": "owner", "resources": {"pool_id": "pool", "cpu_millicores": 100,
                                          "memory_bytes": 64 * 1024**2, "disk_bytes": 64 * 1024**2}}]})
        with self.database.transaction() as session:
            session.add(Project(id="project", name="Project"))
            session.add(Pool(id="pool", name="Pool", node_id="node", disk_bytes=128 * 1024**2))
            session.flush()
            self.job = Job(id="job", project_id="project", creator_id="human", name="Job",
                spec_json=self.spec.to_dict(), spec_hash=self.spec.digest, state="FAILED", target_round=1,
                current_attempt=1, epoch=1)
            session.add(self.job)
            session.flush()
            session.add(Attempt(id="attempt", job_id="job", number=1, epoch=1,
                                revocation_confirmed=True, termination_confirmed=True))
            session.flush()
            session.add(Allocation(id="allocation", job_id="job", attempt_id="attempt", component_id="owner",
                pool_id="pool", cpu_millicores=100, memory_bytes=64 * 1024**2, disk_bytes=64 * 1024**2,
                epoch=1, state="RELEASED", released_at=utcnow(), acknowledged=True,
                termination_confirmed=True, details_json={"node_id": "node", "storage_deleted": True}))
        self.provisioner = Provisioner(self.database, None, RegistryCatalog(SourceRegistry(), {}), self.root,
                                       workload_issuer="https://issuer.example.invalid")
        self.job_root = OwnedDirectories(self.root).ensure_job("job", self.spec.digest)
        self.resource_id = self.provisioner.ledger.own(job_id="job", attempt_id="attempt", component_id="owner",
            kind="remote_auxiliary", external_id="hf2l-node-inputs://node/job/owner", retained=True,
            details={"node_id": "node", "pool_id": "pool", "spec_digest": self.spec.digest})
        RetentionService(self.database).reserve_resource(self.resource_id, "job", 4 * 1024**2)
        identity = ExecutionIdentity("job", "attempt", "owner", 1)
        self.receipt = {"job_id": "job", "attempt_id": "attempt", "component_id": "owner", "epoch": 1,
            "node_id": "node", "pool_id": "pool", "spec_digest": self.spec.digest,
            "purpose": "managed_node_purge", "operation_id": "purge-" + identity.key}
        for name in ("confirmed", "termination_confirmed", "source_deleted", "config_deleted", "build_deleted",
                     "private_credentials_deleted", "private_secrets_deleted", "retained_deleted", "auxiliary_deleted"):
            self.receipt[name] = True

    def assert_held(self):
        row = self.provisioner.ledger.resources("job", kind="remote_auxiliary")[0]
        self.assertNotEqual(row["state"], "deleted")
        self.assertTrue(self.job_root.exists())
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.get(Project, "project").retained_bytes, 4 * 1024**2)

    def test_boolean_or_missing_receipt_never_releases_storage(self):
        for callback in (None, lambda *args: True, lambda *args: {}, lambda *args: {self.resource_id: [None]}):
            self.provisioner.remote_auxiliary_cleanup = callback
            self.assertFalse(self.provisioner.purge_job(self.job))
            self.assert_held()

    def test_foreign_or_incomplete_receipts_never_release_storage(self):
        changes = (("node_id", "foreign"), ("component_id", "foreign"), ("epoch", 2), ("epoch", True),
                   ("spec_digest", "b" * 64), ("operation_id", "foreign"), ("purpose", "unrelated"),
                   ("auxiliary_deleted", False), ("private_credentials_deleted", False))
        for field, value in changes:
            with self.subTest(field=field):
                receipt = {**self.receipt, field: value}
                self.provisioner.remote_auxiliary_cleanup = lambda *args: {self.resource_id: [receipt]}
                self.assertFalse(self.provisioner.purge_job(self.job))
                self.assert_held()

    def test_exact_confirmed_receipt_releases_once_and_preserves_unowned_dataset(self):
        dataset = Path(self.temporary.name) / "operator-dataset.npz"
        dataset.write_bytes(b"unowned participant data")
        self.provisioner.remote_auxiliary_cleanup = lambda *args: {self.resource_id: [self.receipt]}
        self.assertTrue(self.provisioner.purge_job(self.job))
        self.assertTrue(self.provisioner.purge_job(self.job))
        self.assertEqual(dataset.read_bytes(), b"unowned participant data")
        row = self.provisioner.ledger.resources("job", kind="remote_auxiliary")[0]
        self.assertEqual(row["state"], "deleted")
        self.assertEqual(row["details"]["purge_receipts"], [self.receipt])
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.get(Project, "project").retained_bytes, 0)

    def test_reassigned_pool_keeps_each_nodes_historical_identity(self):
        with self.database.transaction() as session:
            session.add(Attempt(id="new-attempt", job_id="job", number=2, epoch=2,
                                revocation_confirmed=True, termination_confirmed=True))
            session.flush()
            session.add(Allocation(id="new-allocation", job_id="job", attempt_id="new-attempt",
                component_id="owner", pool_id="pool", cpu_millicores=100, memory_bytes=64 * 1024**2,
                disk_bytes=64 * 1024**2, epoch=2, state="RELEASED", released_at=utcnow(),
                acknowledged=True, termination_confirmed=True, details_json={"node_id": "new-node", "storage_deleted": True}))
        second_id = self.provisioner.ledger.own(job_id="job", attempt_id="new-attempt", component_id="owner",
            kind="remote_auxiliary", external_id="hf2l-node-inputs://new-node/job/owner", retained=True,
            details={"node_id": "new-node", "pool_id": "pool", "spec_digest": self.spec.digest})
        RetentionService(self.database).reserve_resource(second_id, "job", 4 * 1024**2)
        new_receipt = {**self.receipt, "attempt_id": "new-attempt", "epoch": 2, "node_id": "new-node",
            "operation_id": "purge-" + ExecutionIdentity("job", "new-attempt", "owner", 2).key}
        self.provisioner.remote_auxiliary_cleanup = lambda *args: {
            self.resource_id: [self.receipt], second_id: [new_receipt]}
        self.assertTrue(self.provisioner.purge_job(self.job))
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.get(Project, "project").retained_bytes, 0)

    def test_missing_historical_node_affinity_preserves_charge(self):
        with self.database.transaction() as session:
            allocation = session.get(Allocation, "allocation")
            allocation.details_json = {"storage_deleted": True}
        self.provisioner.remote_auxiliary_cleanup = lambda *args: {self.resource_id: [self.receipt]}
        self.assertFalse(self.provisioner.purge_job(self.job))
        self.assert_held()

    def test_each_historical_execution_needs_its_own_node_receipt(self):
        with self.database.transaction() as session:
            session.add(Attempt(id="older-attempt", job_id="job", number=2, epoch=2,
                                revocation_confirmed=True, termination_confirmed=True))
            session.flush()
            session.add(Allocation(id="older-allocation", job_id="job", attempt_id="older-attempt",
                component_id="owner", pool_id="pool", cpu_millicores=100, memory_bytes=64 * 1024**2,
                disk_bytes=64 * 1024**2, epoch=2, state="RELEASED", released_at=utcnow(),
                acknowledged=True, termination_confirmed=True, details_json={"node_id": "node", "storage_deleted": True}))
        self.provisioner.remote_auxiliary_cleanup = lambda *args: {self.resource_id: [self.receipt]}
        self.assertFalse(self.provisioner.purge_job(self.job))
        self.assert_held()
        second = {**self.receipt, "attempt_id": "older-attempt", "epoch": 2,
            "operation_id": "purge-" + ExecutionIdentity("job", "older-attempt", "owner", 2).key}
        self.provisioner.remote_auxiliary_cleanup = lambda *args: {self.resource_id: [self.receipt, second]}
        self.assertTrue(self.provisioner.purge_job(self.job))


if __name__ == "__main__":
    unittest.main()
