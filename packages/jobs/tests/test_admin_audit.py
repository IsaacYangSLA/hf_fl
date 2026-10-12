"""Durable administrative history and additive migration regressions."""
from __future__ import annotations

import hashlib
import json
import os
import unittest
from uuid import uuid4
from unittest.mock import patch

from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.engine import make_url

from hf2l_jobs.admin_audit import record_admin_audit, sanitize_policy_metadata
from hf2l_jobs.database import create_database
from hf2l_jobs.migrations import CURRENT_REVISION, REVISIONS, SchemaError
from hf2l_jobs.models import AdministrativeAudit, Project, SchemaRevision


class AdministrativeAuditTests(unittest.TestCase):
    def setUp(self):
        self.database = create_database("sqlite://")
        self.addCleanup(self.database.close)

    def test_authorized_change_and_audit_commit_together_without_credential_contents(self):
        with self.database.transaction() as session:
            project = Project(id="project", name="Before", retention_days=90)
            session.add(project)
            session.flush()
            project.name = "After"
            row = record_admin_audit(
                session, actor_id="unix:1000", operation="project.update",
                resource_type="project", resource_id=project.id,
                before={"name": "Before", "retention_days": 90},
                after={"name": project.name, "retention_days": 30, "version": 2,
                       "quotas": {"disk_bytes": 123, "password": "should-not-persist"},
                       "private_key": "synthetic-private-key", "access_token": "synthetic-token",
                       "source": {"contents": "synthetic-source"}, "host_path": "/etc/shadow"},
            )
        with self.database.transaction() as session:
            self.assertEqual(session.get(Project, "project").name, "After")
            saved = session.get(AdministrativeAudit, row.id)
            self.assertEqual(saved.before_json, {"name": "Before", "retention_days": 90})
            self.assertEqual(saved.after_json, {"name": "After", "retention_days": 30, "version": 2, "quotas": {"disk_bytes": 123}})
            self.assertIsNotNone(saved.created_at.tzinfo)
            self.assertNotIn("synthetic", json.dumps(saved.after_json))

    def test_failed_policy_transaction_rolls_back_audit_and_policy(self):
        with self.database.transaction() as session:
            session.add(Project(id="project", name="Before"))
        with self.assertRaises(RuntimeError):
            with self.database.transaction() as session:
                project = session.get(Project, "project")
                project.name = "After"
                record_admin_audit(session, actor_id="unix:1000", operation="project.update",
                                   resource_type="project", resource_id=project.id,
                                   before={"name": "Before"}, after={"name": "After"})
                session.flush()
                raise RuntimeError("simulated crash")
        with self.database.transaction() as session:
            self.assertEqual(session.get(Project, "project").name, "Before")
            self.assertEqual(session.scalars(select(AdministrativeAudit)).all(), [])

    def test_record_is_deep_copied_and_survives_resource_deletion(self):
        snapshot = {"name": "CPU", "gpu_uuids": ["GPU-first"], "quotas": {"disk_bytes": 100}}
        with self.database.transaction() as session:
            session.add(Project(id="project", name="Project"))
            row = record_admin_audit(session, actor_id="human", operation="project.create",
                                     resource_type="project", resource_id="project", after=snapshot)
            snapshot["gpu_uuids"].append("GPU-second")
            snapshot["quotas"]["disk_bytes"] = 999
        with self.database.transaction() as session:
            session.delete(session.get(Project, "project"))
        with self.database.transaction() as session:
            saved = session.get(AdministrativeAudit, row.id)
            self.assertEqual(saved.after_json["gpu_uuids"], ["GPU-first"])
            self.assertEqual(saved.after_json["quotas"]["disk_bytes"], 100)

    def test_audit_history_is_append_only(self):
        with self.database.transaction() as session:
            row = record_admin_audit(session, actor_id="human", operation="pool.update",
                                     resource_type="pool", resource_id="pool", after={"healthy": False})
        for operation in ("update", "delete"):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                with self.database.transaction() as session:
                    saved = session.get(AdministrativeAudit, row.id)
                    if operation == "update":
                        saved.after_json = {"healthy": True}
                    else:
                        session.delete(saved)
        with self.database.transaction() as session:
            self.assertEqual(session.get(AdministrativeAudit, row.id).after_json, {"healthy": False})

    def test_direct_model_insertion_also_sanitizes_metadata(self):
        with self.database.transaction() as session:
            row = AdministrativeAudit(actor_id="human", operation="pool.update", resource_type="pool",
                                      resource_id="pool", after_json={"healthy": True, "ca_key": "synthetic"})
            session.add(row)
        self.assertEqual(row.after_json, {"healthy": True})

    def test_large_policy_lists_have_bounded_exact_hash_summary(self):
        profiles = ["profile-" + str(index) for index in range(1024)]
        expected = hashlib.sha256(json.dumps(profiles, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        result = sanitize_policy_metadata({"sandbox_profiles": profiles})
        self.assertEqual(result, {"sandbox_profiles": {"count": 1024, "sha256": expected}})
        with self.database.transaction() as session:
            row = record_admin_audit(session, actor_id="human", operation="pool.update",
                                     resource_type="pool", resource_id="pool", after={"sandbox_profiles": profiles})
        self.assertEqual(row.after_json, result)

    def test_invalid_policy_types_or_credentials_never_enter_history(self):
        invalid = [
            {"name": "Bearer synthetic-token"},
            {"name": "-----BEGIN PRIVATE KEY-----"},
            {"name": "a" * 201}, {"name": "line\nbreak"},
            {"disk_bytes": True}, {"disk_bytes": -1}, {"disk_bytes": 1.2},
            {"disk_bytes": 1 << 63}, {"healthy": 1},
            {"gpu_uuids": ["id"] * 1025}, {"quotas": {"disk_bytes": False}},
        ]
        for after in invalid:
            with self.subTest(after=after), self.assertRaises(ValueError):
                with self.database.transaction() as session:
                    record_admin_audit(session, actor_id="human", operation="pool.update",
                                       resource_type="pool", resource_id="pool", after=after)
        with self.database.transaction() as session:
            self.assertEqual(session.scalars(select(AdministrativeAudit)).all(), [])

    def test_actor_operation_and_resource_identity_are_bounded(self):
        for changes in ({"actor_id": ""}, {"actor_id": "a" * 257}, {"actor_id": "Basic synthetic"},
                        {"operation": "pool\nupdate"}, {"operation": "x" * 65},
                        {"resource_type": "unsafe space"}, {"resource_id": ""}):
            values = dict(actor_id="human", operation="pool.update", resource_type="pool", resource_id="pool")
            values.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                with self.database.transaction() as session:
                    record_admin_audit(session, **values, after={"healthy": True})


class AuditMigrationTests(unittest.TestCase):
    def database_for_test(self):
        return create_database("sqlite://")

    def setUp(self):
        self.database = self.database_for_test()
        self.addCleanup(self.database.close)
        with self.database.transaction() as session:
            session.add(Project(id="project", name="Historic", retention_days=90, retained_bytes=456))
        with self.database.engine.begin() as connection:
            self.original_revisions = dict(connection.execute(
                text("SELECT revision, applied_at FROM jm_schema_revisions WHERE revision != :current"),
                {"current": CURRENT_REVISION}).all())
            connection.exec_driver_sql("DROP TABLE jm_admin_audit")
            connection.execute(text("DELETE FROM jm_schema_revisions WHERE revision=:current"), {"current": CURRENT_REVISION})

    def test_v2_upgrade_preserves_policy_history_and_prior_revision_timestamps(self):
        with self.assertRaises(SchemaError):
            self.database.check_schema()
        self.assertEqual(self.database.migrate(), CURRENT_REVISION)
        self.assertEqual(self.database.migrate(), CURRENT_REVISION)
        with self.database.transaction() as session:
            project = session.get(Project, "project")
            self.assertEqual((project.name, project.retention_days, project.retained_bytes), ("Historic", 90, 456))
            self.assertEqual(set(session.scalars(select(SchemaRevision.revision))), set(REVISIONS))
            self.assertEqual(session.scalars(select(AdministrativeAudit)).all(), [])
        with self.database.engine.connect() as connection:
            revisions = dict(connection.execute(text(
                "SELECT revision, applied_at FROM jm_schema_revisions WHERE revision != :current"),
                {"current": CURRENT_REVISION}).all())
            self.assertEqual(revisions, self.original_revisions)

    def test_interrupted_v3_upgrade_rolls_back_table_indexes_and_revision(self):
        from hf2l_jobs import migrations
        original = migrations._upgrade_administrative_audit
        def interrupted(connection):
            original(connection)
            raise RuntimeError("interrupted additive migration")
        with patch.object(migrations, "_upgrade_administrative_audit", side_effect=interrupted):
            with self.assertRaises(RuntimeError):
                self.database.migrate()
        self.assertNotIn("jm_admin_audit", inspect(self.database.engine).get_table_names())
        with self.database.transaction() as session:
            self.assertEqual(set(session.scalars(select(SchemaRevision.revision))), set(REVISIONS[:2]))
            self.assertEqual(session.get(Project, "project").retained_bytes, 456)
        self.assertEqual(self.database.migrate(), CURRENT_REVISION)

    def test_out_of_order_revision_or_partial_unversioned_audit_is_rejected(self):
        with self.database.engine.begin() as connection:
            connection.exec_driver_sql("CREATE TABLE jm_admin_audit (id TEXT)")
        with self.assertRaises(SchemaError):
            self.database.migrate()
        with self.database.engine.begin() as connection:
            connection.exec_driver_sql("DROP TABLE jm_admin_audit")
            connection.execute(text("DELETE FROM jm_schema_revisions WHERE revision=:first"), {"first": REVISIONS[0]})
        with self.assertRaises(SchemaError):
            self.database.migrate()

    def test_missing_current_audit_index_fails_schema_check_without_silent_repair(self):
        self.database.migrate()
        with self.database.engine.begin() as connection:
            connection.exec_driver_sql("DROP INDEX ix_jm_admin_audit_actor")
        with self.assertRaises(SchemaError):
            self.database.check_schema()
        with self.assertRaises(SchemaError):
            self.database.migrate()


@unittest.skipUnless(os.environ.get("JOBS_TEST_DATABASE_URL"), "JOBS_TEST_DATABASE_URL is not configured")
class PostgreSQLAuditMigrationTests(AuditMigrationTests):
    """Exercise production transactional DDL only in an owned random schema."""
    def database_for_test(self):
        supplied = make_url(os.environ["JOBS_TEST_DATABASE_URL"])
        if supplied.get_backend_name() != "postgresql":
            self.fail("JOBS_TEST_DATABASE_URL must select PostgreSQL")
        schema = "jm_audit_" + uuid4().hex
        admin = create_engine(supplied, pool_pre_ping=True)
        self.addCleanup(admin.dispose)
        with admin.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        def drop_owned_schema():
            with admin.begin() as connection:
                connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        self.addCleanup(drop_owned_schema)
        options = f"-csearch_path={schema} -clock_timeout=10000 -cstatement_timeout=20000"
        url = supplied.update_query_dict({"options": options}).render_as_string(hide_password=False)
        return create_database(url, isolation_level="READ COMMITTED")


if __name__ == "__main__":
    unittest.main()
