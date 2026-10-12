"""Foundation regressions: immutable inputs and database-enforced ownership."""
from __future__ import annotations

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.schema import CreateTable

from hf2l_jobs.database import create_database
from hf2l_jobs.domain import ArtifactLocator, JobSpec, canonical_json, new_id, spec_hash, utcnow
from hf2l_jobs.migrations import CURRENT_REVISION, REVISIONS, SchemaError, check_schema, migrate
from hf2l_jobs.models import Allocation, Artifact, Attempt, Base, LogChunk, GpuAllocation, Job, JobMember, Pool, Project, SchemaRevision


def specification(**changes):
    value = dict(project_id="project", name="Training", source_id="approved-source",
                 source_commit="a" * 40, runtime_image="approved-cpu-runtime", plugin="example.plugin:Trainer",
                 components=[dict(component_id="owner", role="owner", resources=dict(
                     pool_id="cpu", cpu_millicores=1000, memory_bytes=1024, disk_bytes=2048))],
                 target_round=3, max_duration_seconds=3600)
    value.update(changes)
    return value


class JobSpecTests(unittest.TestCase):
    def test_canonical_spec_hash_and_json_roundtrip(self):
        spec = JobSpec.model_validate(specification(options={"epochs": 2, "config": {"lr": 0.1}}))
        recovered = JobSpec.model_validate(json.loads(spec.model_dump_json()))
        self.assertEqual(spec.digest, recovered.digest)
        self.assertEqual(canonical_json({"b": 1, "a": 2}), canonical_json({"a": 2, "b": 1}))
        self.assertNotEqual(spec.digest, JobSpec.model_validate(specification(target_round=4)).digest)

    def test_nested_options_and_defaults_are_immutable(self):
        supplied = {"layers": [{"size": 10}]}
        spec = JobSpec.model_validate(specification(options=supplied))
        supplied["layers"][0]["size"] = 99
        self.assertEqual(spec.options["layers"][0]["size"], 10)
        with self.assertRaises(TypeError):
            spec.options["layers"][0]["size"] = 20
        with self.assertRaises(ValidationError):
            spec.target_round = 5
        with self.assertRaises(TypeError):
            JobSpec.model_validate(specification()).options["lr"] = 1
        with self.assertRaises(TypeError):
            JobSpec.model_validate(specification()).secret_refs["db"] = "secret"

    def test_numeric_fields_reject_boolean_and_out_of_range(self):
        for field in ("target_round", "max_duration_seconds"):
            for value in (True, 0, -1, 1.5):
                with self.subTest(field=field, value=value), self.assertRaises(ValidationError):
                    JobSpec.model_validate(specification(**{field: value}))
        for field in ("cpu_millicores", "memory_bytes", "disk_bytes", "gpu_count"):
            value = specification()
            value["components"][0]["resources"][field] = True
            with self.subTest(field=field), self.assertRaises(ValidationError):
                JobSpec.model_validate(value)

    def test_forbidden_execution_and_secret_options_at_all_depths(self):
        for key in ("command", "mounts", "executor_flags", "api_key", "apiKey", "APIKEY", "accessToken", "password", "Authorization", "private-key"):
            with self.subTest(key=key), self.assertRaises(ValidationError):
                JobSpec.model_validate(specification(options={"config": [{key: "private-value"}]}))
        with self.assertRaises(ValidationError):
            JobSpec.model_validate(specification(command="cat /host"))

    def test_input_rejects_urls_paths_mutable_refs_and_nonfinite_options(self):
        for field, values in {
            "source_id": ("https://evil.invalid/repo", "../repo", "/tmp/repo"),
            "source_commit": ("main", "a" * 39, "g" * 40),
            "runtime_image": ("repo/image:latest", "https://example.invalid/image"),
            "plugin": ("../../exploit", "foo;exec", ".relative"),
            "name": ("\nname", "   "),
        }.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValidationError):
                    JobSpec.model_validate(specification(**{field: value}))
        for value in (float("nan"), float("inf"), object()):
            with self.assertRaises(ValidationError):
                JobSpec.model_validate(specification(options={"lr": value}))

    def test_secret_reference_only_accepts_opaque_approved_ids(self):
        spec = JobSpec.model_validate(specification(secret_refs={"training_key": "project-key-1"}))
        self.assertEqual(spec.to_dict()["secret_refs"], {"training_key": "project-key-1"})
        for value in ("file:///etc/shadow", "/var/secrets/key", "vault://host/key"):
            with self.assertRaises(ValidationError):
                JobSpec.model_validate(specification(secret_refs={"training_key": value}))

    def test_owner_and_managed_participant_bindings_are_reciprocal(self):
        value = specification(participants=[dict(participant_id="alice", dataset_binding="local-dataset", mode="managed", component_id="alice-worker")])
        value["components"].append(dict(component_id="alice-worker", role="participant", participant_id="alice", resources=dict(pool_id="node-alice", cpu_millicores=1000, memory_bytes=1024, disk_bytes=1024)))
        self.assertEqual(len(JobSpec.model_validate(value).components), 2)
        value["components"][1]["participant_id"] = "bob"
        with self.assertRaises(ValidationError):
            JobSpec.model_validate(value)
        value = specification()
        value["components"].append(dict(value["components"][0]))
        with self.assertRaises(ValidationError):
            JobSpec.model_validate(value)
        value["components"] = []
        with self.assertRaises(ValidationError):
            JobSpec.model_validate(value)

    def test_gpu_whole_count_requires_fixed_profile(self):
        for count, profile in ((1, None), (0, "gpu-qualified")):
            value = specification()
            value["components"][0]["resources"].update(gpu_count=count, gpu_profile=profile)
            with self.assertRaises(ValidationError):
                JobSpec.model_validate(value)
        value["components"][0]["resources"].update(gpu_count=1, gpu_profile="gpu-qualified")
        self.assertEqual(JobSpec.model_validate(value).components[0].resources.gpu_count, 1)

    def test_options_size_and_depth_bounded(self):
        with self.assertRaises(ValidationError):
            JobSpec.model_validate(specification(options={"x": "a" * 8193}))
        with self.assertRaises(ValidationError):
            JobSpec.model_validate(specification(options={str(i): "a" * 8000 for i in range(10)}))
        nested = {}
        for _ in range(10):
            nested = {"x": nested}
        with self.assertRaises(ValidationError):
            JobSpec.model_validate(specification(options=nested))


    def test_trusted_artifact_locators_are_structured_and_confined(self):
        self.assertEqual(ArtifactLocator.model_validate(dict(kind="local", resource_id="owned", relative_path="checkpoints/model.bin")).to_dict(),
                         dict(kind="local", resource_id="owned", relative_path="checkpoints/model.bin"))
        self.assertEqual(ArtifactLocator.model_validate(dict(kind="exchange", space_id="s", record_id="r", attachment_id="a")).kind, "exchange")
        for locator in (
            dict(kind="local", resource_id="owned", relative_path="../foreign/model"),
            dict(kind="local", resource_id="owned", relative_path="/etc/shadow"),
            dict(kind="local", resource_id="owned", relative_path="a//b"),
            dict(kind="local", resource_id="owned", relative_path="a/./b"),
            dict(kind="local", resource_id="owned", relative_path="a\\b"),
            dict(kind="exchange", space_id="s", record_id="r"),
            dict(kind="exchange", space_id="s", record_id="r", attachment_id="a", resource_id="foreign"),
            dict(kind="exchange", space_id="s", record_id="r", attachment_id="a", url="https://evil.invalid"),
        ):
            with self.subTest(locator=locator), self.assertRaises(ValidationError):
                ArtifactLocator.model_validate(locator)

    def test_ids_are_opaque_unique_uuid_hex(self):
        values = {new_id() for _ in range(100)}
        self.assertEqual(len(values), 100)
        self.assertTrue(all(len(value) == 32 and int(value, 16) >= 0 for value in values))


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.database = create_database("sqlite://")
        self.addCleanup(self.database.close)
        self.spec = JobSpec.model_validate(specification())
        self.job_id, self.attempt_id = new_id(), new_id()
        with self.database.transaction() as session:
            session.add(Project(id="project", name="Project"))
            session.flush()
            session.add(Job(id=self.job_id, project_id="project", creator_id="human", name="Training", spec_json=self.spec.to_dict(), spec_hash=self.spec.digest, target_round=3))
            session.add(Pool(id="cpu", name="CPU", node_id="node", cpu_millicores=8000, memory_bytes=8192, disk_bytes=8192))
            session.add(Pool(id="other", name="Other", node_id="node", cpu_millicores=8000, memory_bytes=8192, disk_bytes=8192))
            session.flush()
            session.add(Attempt(id=self.attempt_id, job_id=self.job_id, number=1, epoch=1))

    def allocation(self, component="owner", pool="cpu"):
        return Allocation(id=new_id(), job_id=self.job_id, attempt_id=self.attempt_id,
                          component_id=component, pool_id=pool, cpu_millicores=1000,
                          memory_bytes=1024, disk_bytes=2048, epoch=1)

    def test_migration_is_explicit_idempotent_and_schema_checked(self):
        self.assertEqual(check_schema(self.database.engine), CURRENT_REVISION)
        self.assertEqual(migrate(self.database.engine), CURRENT_REVISION)
        with self.database.transaction() as session:
            self.assertEqual(len(session.scalars(select(SchemaRevision)).all()), len(REVISIONS))

    def test_schema_rejects_unknown_revision(self):
        with self.database.transaction() as session:
            row = session.get(SchemaRevision, CURRENT_REVISION)
            row.revision = "future-incompatible"
        with self.assertRaises(SchemaError):
            check_schema(self.database.engine)
        with self.assertRaises(SchemaError):
            migrate(self.database.engine)

    def test_schema_missing_table_is_not_silently_created_on_current_revision(self):
        with self.database.engine.begin() as connection:
            connection.exec_driver_sql("DROP TABLE jm_log_chunks")
        with self.assertRaises(SchemaError):
            migrate(self.database.engine)

    def test_schema_missing_column_is_detected(self):
        with self.database.engine.begin() as connection:
            connection.exec_driver_sql("ALTER TABLE jm_pools DROP COLUMN details_json")
        with self.assertRaises(SchemaError):
            self.database.check_schema()
        with self.assertRaises(SchemaError):
            self.database.migrate()

    def test_timestamp_roundtrip_is_aware_utc(self):
        value = datetime(2026, 10, 9, 11, 0, tzinfo=timezone(timedelta(hours=5)))
        with self.database.transaction() as session:
            session.get(Job, self.job_id).updated_at = value
        with self.database.transaction() as session:
            loaded = session.get(Job, self.job_id).updated_at
            self.assertEqual(loaded, value.astimezone(timezone.utc))
            self.assertEqual(loaded.utcoffset(), timedelta(0))
        with self.assertRaises(StatementError):
            with self.database.transaction() as session:
                session.get(Job, self.job_id).updated_at = datetime(2026, 10, 9)

    def test_foreign_memberships_and_invalid_roles_rejected(self):
        with self.assertRaises(IntegrityError):
            with self.database.transaction() as session:
                session.add(JobMember(job_id="f" * 32, principal_id="human", role="admin"))
        with self.assertRaises(IntegrityError):
            with self.database.transaction() as session:
                session.add(JobMember(job_id=self.job_id, principal_id="human", role="god-mode"))

    def test_job_specification_cannot_be_modified(self):
        for field, value in (("spec_json", {}), ("spec_hash", "0" * 64), ("target_round", 4), ("creator_id", "other")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                with self.database.transaction() as session:
                    setattr(session.get(Job, self.job_id), field, value)
        with self.database.transaction() as session:
            self.assertEqual(session.get(Job, self.job_id).spec_hash, self.spec.digest)

    def test_unique_live_allocation_does_not_block_confirmed_release(self):
        first = self.allocation()
        with self.database.transaction() as session:
            session.add(first)
        with self.assertRaises(IntegrityError):
            with self.database.transaction() as session:
                session.add(self.allocation())
        with self.database.transaction() as session:
            allocation = session.get(Allocation, first.id)
            allocation.state = "RELEASED"
            allocation.released_at = utcnow()
        with self.database.transaction() as session:
            session.add(self.allocation())

    def test_successor_cannot_overlap_predecessor_component(self):
        predecessor = self.allocation()
        next_attempt_id = new_id()
        with self.database.transaction() as session:
            session.add(predecessor)
            session.add(Attempt(id=next_attempt_id, job_id=self.job_id, number=2, epoch=2))
        successor = self.allocation()
        successor.attempt_id = next_attempt_id
        successor.epoch = 2
        with self.assertRaises(IntegrityError):
            with self.database.transaction() as session:
                session.add(successor)

    def test_whole_gpu_unique_across_different_pools_and_reusable_after_release(self):
        first, second = self.allocation(), self.allocation(component="other", pool="other")
        with self.database.transaction() as session:
            session.add_all([first, second])
            session.flush()
            session.add(GpuAllocation(allocation_id=first.id, pool_id="cpu", gpu_uuid="GPU-physical"))
        with self.assertRaises(IntegrityError):
            with self.database.transaction() as session:
                session.add(GpuAllocation(allocation_id=second.id, pool_id="other", gpu_uuid="GPU-physical"))
        with self.database.transaction() as session:
            row = session.scalar(select(GpuAllocation).where(GpuAllocation.gpu_uuid == "GPU-physical"))
            row.released_at = utcnow()
        with self.database.transaction() as session:
            session.add(GpuAllocation(allocation_id=second.id, pool_id="other", gpu_uuid="GPU-physical"))


    def _legacy_schema(self):
        # Reproduce the released v1 absence of trusted locators, log charges and
        # session expiry index while preserving the other constraints and data.
        log_ddl = str(CreateTable(LogChunk.__table__).compile(dialect=self.database.engine.dialect))
        log_ddl = "\n".join(line for line in log_ddl.splitlines() if "charged_bytes BIGINT" not in line)
        log_ddl = log_ddl.replace(" AND charged_bytes >= 0", "")
        with self.database.engine.begin() as connection:
            connection.exec_driver_sql("ALTER TABLE jm_artifacts DROP COLUMN locator_json")
            connection.exec_driver_sql("DROP TABLE jm_log_chunks")
            connection.exec_driver_sql(log_ddl)
            connection.exec_driver_sql("DROP INDEX ix_jm_sessions_expiry")
            connection.exec_driver_sql("DROP TABLE jm_admin_audit")
            connection.execute(text("DELETE FROM jm_schema_revisions WHERE revision<>:revision"), {"revision": REVISIONS[0]})
            connection.execute(text("INSERT INTO jm_log_chunks(id, job_id, component, sequence, data, created_at) VALUES (:id,:job,:component,1,:data,:time)"),
                               {"id": new_id(), "job": self.job_id, "component": "owner", "data": "historic log", "time": utcnow().isoformat()})

    def test_existing_v1_upgrade_preserves_history_and_fails_closed_legacy_locator(self):
        artifact_id = new_id()
        with self.database.transaction() as session:
            session.add(Artifact(id=artifact_id, job_id=self.job_id, kind="model", name="model.bin", size_bytes=123,
                                 sha256="f" * 64, storage_key="opaque-old-key"))
        self._legacy_schema()
        with self.assertRaises(SchemaError):
            self.database.check_schema()
        self.assertEqual(self.database.migrate(), CURRENT_REVISION)
        with self.database.transaction() as session:
            artifact = session.get(Artifact, artifact_id)
            self.assertIsNone(artifact.locator_json)
            self.assertEqual(artifact.storage_key, "opaque-old-key")
            row = session.scalar(select(LogChunk).where(LogChunk.job_id == self.job_id))
            self.assertEqual(row.data, "historic log")
            self.assertEqual(row.charged_bytes, 0)
            self.assertEqual(set(session.scalars(select(SchemaRevision.revision))), set(REVISIONS))
        with self.assertRaises(IntegrityError):
            with self.database.transaction() as session:
                session.scalar(select(LogChunk).where(LogChunk.job_id == self.job_id)).charged_bytes = -1

    def test_upgrade_columns_and_revision_roll_back_as_one_transaction(self):
        self._legacy_schema()
        from hf2l_jobs import migrations
        original = migrations._verify_tables
        def fail_after_upgrade(connection, tables, *, legacy=False):
            original(connection, tables, legacy=legacy)
            if not legacy:
                raise RuntimeError("interrupted upgrade verification")
        with patch.object(migrations, "_verify_tables", side_effect=fail_after_upgrade):
            with self.assertRaises(RuntimeError):
                self.database.migrate()
        self.assertNotIn("locator_json", {item["name"] for item in inspect(self.database.engine).get_columns("jm_artifacts")})
        self.assertNotIn("charged_bytes", {item["name"] for item in inspect(self.database.engine).get_columns("jm_log_chunks")})
        with self.database.transaction() as session:
            self.assertEqual(set(session.scalars(select(SchemaRevision.revision))), {REVISIONS[0]})
        self.assertEqual(self.database.migrate(), CURRENT_REVISION)

    def test_trusted_locator_persistence_and_invalid_location_rejection(self):
        locator = dict(kind="local", resource_id="owned-resource", relative_path="results/model.bin")
        artifact_id = new_id()
        with self.database.transaction() as session:
            session.add(Artifact(id=artifact_id, job_id=self.job_id, kind="model", name="model.bin", size_bytes=123,
                                 sha256="f" * 64, storage_key="opaque", locator_json=locator))
        with self.database.transaction() as session:
            self.assertEqual(session.get(Artifact, artifact_id).locator_json, locator)
        with self.assertRaises(ValidationError):
            with self.database.transaction() as session:
                session.get(Artifact, artifact_id).locator_json = dict(kind="local", resource_id="owned", relative_path="../foreign")

    def test_failed_transaction_does_not_leave_partial_resources(self):
        with self.assertRaises(RuntimeError):
            with self.database.transaction() as session:
                session.add(self.allocation())
                session.flush()
                raise RuntimeError("provisioning interrupted")
        with self.database.transaction() as session:
            self.assertEqual(session.scalars(select(Allocation)).all(), [])


class MigrationFailureTests(unittest.TestCase):
    def test_absent_schema_is_detected_without_initialization(self):
        database = create_database("sqlite://", initialize=False)
        self.addCleanup(database.close)
        with self.assertRaises(SchemaError):
            database.check_schema()
        self.assertEqual(inspect(database.engine).get_table_names(), [])

    def test_migration_ddl_and_revision_roll_back_together(self):
        database = create_database("sqlite://", initialize=False)
        self.addCleanup(database.close)
        def interrupted(connection):
            connection.exec_driver_sql("CREATE TABLE jm_interrupted (id INTEGER)")
            raise RuntimeError("mid-migration crash")
        with patch.object(Base.metadata, "create_all", side_effect=interrupted):
            with self.assertRaises(RuntimeError):
                migrate(database.engine)
        self.assertEqual(inspect(database.engine).get_table_names(), [])
        self.assertEqual(migrate(database.engine), CURRENT_REVISION)

    def test_unversioned_partial_schema_requires_recovery(self):
        database = create_database("sqlite://", initialize=False)
        self.addCleanup(database.close)
        with database.engine.begin() as connection:
            connection.exec_driver_sql("CREATE TABLE jm_jobs (id TEXT)")
        with self.assertRaises(SchemaError):
            migrate(database.engine)
        self.assertEqual(inspect(database.engine).get_table_names(), ["jm_jobs"])

    def test_unrelated_existing_tables_are_preserved(self):
        database = create_database("sqlite://", initialize=False)
        self.addCleanup(database.close)
        with database.engine.begin() as connection:
            connection.exec_driver_sql("CREATE TABLE unrelated_data (value TEXT)")
            connection.exec_driver_sql("INSERT INTO unrelated_data VALUES (\"preserved\")")
        migrate(database.engine)
        with database.engine.connect() as connection:
            self.assertEqual(connection.scalar(text("SELECT value FROM unrelated_data")), "preserved")

    def test_competing_initial_migrations_do_not_duplicate_revision(self):
        with tempfile.TemporaryDirectory(prefix="hf2l-jobs-migrate-") as directory:
            url = "sqlite:///" + str(Path(directory) / "manager.db")
            def initialize():
                database = create_database(url)
                try:
                    return database.check_schema()
                finally:
                    database.close()
            with ThreadPoolExecutor(max_workers=2) as workers:
                self.assertEqual(list(workers.map(lambda _: initialize(), range(2))), [CURRENT_REVISION, CURRENT_REVISION])


if __name__ == "__main__":
    unittest.main()
