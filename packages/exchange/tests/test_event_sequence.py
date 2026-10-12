"""Event cursors survive SQLite retention and upgrades from the frozen baseline."""
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sqlalchemy import delete, inspect, select, text, update
from sqlalchemy.exc import IntegrityError

from hf2l_exchange.application import Service
from hf2l_exchange.config import AuthSettings, DatabaseSettings, Settings, WorkerSettings
from hf2l_exchange.domain import Error, Principal
from hf2l_exchange import migrations
from hf2l_exchange.models import Base, Event, Space, database
from hf2l_exchange.worker import prune


class EventSequenceTests(unittest.TestCase):
    def setUp(self):
        self.engine, self.sessions = database("sqlite:///:memory:")
        self.addCleanup(self.engine.dispose)
        self.settings = Settings(database=DatabaseSettings(url="sqlite:///:memory:"),
                                 auth=AuthSettings(admin_subject="owner"),
                                 worker=WorkerSettings(event_retention_seconds=1))
        self.service = Service(self.settings, engine=self.engine, sessions=self.sessions)
        self.owner = Principal("owner", "owner", True)

    def baseline(self):
        # Replay exactly the released baseline, independent of the current ORM.
        with self.engine.begin() as connection:
            for statement in migrations.SQLITE_BASELINE:
                connection.exec_driver_sql(statement)
            connection.exec_driver_sql("CREATE TABLE v2_schema_ledger (revision VARCHAR(64) PRIMARY KEY)")
            connection.execute(text("INSERT INTO v2_schema_ledger (revision) VALUES (:revision)"),
                               {"revision": migrations.BASELINE_REVISION})

    def assert_retention_keeps_cursors(self):
        space_id = self.service.create_space(self.owner, {"name": "events"}, "space")["id"]
        cursor = self.service.events(self.owner, space_id)["next_cursor"]
        transfers = SimpleNamespace(settings=self.settings, sessions=self.sessions)
        for quota in (200000, 300000):
            with self.sessions.begin() as session:
                session.execute(update(Event).values(created_at=0))
            prune(transfers, 100)
            with self.sessions.begin() as session:
                self.assertEqual(list(session.scalars(select(Event.id))), [])
                self.assertEqual(session.get(Space, space_id).event_floor, cursor)
            self.service.update_space_limits(self.owner, space_id, {"quota_records": quota})
            page = self.service.events(self.owner, space_id, after=cursor)
            self.assertEqual([item["type"] for item in page["items"]], ["space.limits_updated"])
            self.assertGreater(page["next_cursor"], cursor)
            cursor = page["next_cursor"]

    def test_initialized_schema_preserves_cursors_after_every_event_is_pruned(self):
        migrations.initialize(self.engine)
        self.assert_retention_keeps_cursors()

    def test_orm_created_schema_preserves_cursors_after_every_event_is_pruned(self):
        Base.metadata.create_all(self.engine)
        self.assert_retention_keeps_cursors()

    def test_upgrade_preserves_rows_indexes_foreign_keys_and_all_space_floors(self):
        self.baseline()
        with self.sessions.begin() as session:
            session.add_all([Space(id="a", name="A", event_floor=120),
                             Space(id="b", name="B", event_floor=175)])
            session.flush()
            session.add_all([
                Event(id=7, space_id="a", record_id="removed-record", type="record.withdrawn",
                      principal_id="system", payload={"state": "withdrawn", "kind": "document"}, created_at=1),
                Event(id=80, space_id="b", type="space.created", principal_id="owner", payload={}, created_at=2),
            ])
        with self.engine.connect() as connection:
            before = list(connection.exec_driver_sql("SELECT * FROM v2_events ORDER BY id"))
        self.assertEqual(migrations.migrate(self.engine), migrations.SCHEMA_REVISION)
        self.assertEqual(migrations.check(self.engine), migrations.SCHEMA_REVISION)
        self.assertEqual(migrations.check_revision(self.engine), migrations.SCHEMA_REVISION)
        with self.engine.connect() as connection:
            self.assertEqual(list(connection.exec_driver_sql("SELECT * FROM v2_events ORDER BY id")), before)
            self.assertEqual(connection.exec_driver_sql(
                "SELECT seq FROM sqlite_sequence WHERE name = 'v2_events'").scalar_one(), 175)
            self.assertEqual(connection.exec_driver_sql("PRAGMA foreign_key_check").all(), [])
        indexes = {index["name"]: index["column_names"] for index in inspect(self.engine).get_indexes("v2_events")}
        self.assertEqual(indexes, {"ix_v2_events_retention": ["created_at", "id"],
                                   "ix_v2_events_space_cursor": ["space_id", "id"]})
        with self.assertRaises(IntegrityError), self.sessions.begin() as session:
            session.add(Event(space_id="missing", type="space.created", principal_id="owner"))
        with self.sessions.begin() as session:
            next_event = Event(space_id="a", type="space.created", principal_id="owner")
            session.add(next_event)
            session.flush()
            self.assertGreater(next_event.id, 175)

    def test_upgrade_seeds_sequence_when_retention_already_removed_every_event(self):
        self.baseline()
        with self.sessions.begin() as session:
            session.add(Space(id="a", name="A", event_floor=400))
        with self.assertRaisesRegex(Error, "database_revision_incompatible"):
            migrations.initialize(self.engine)
        with self.assertRaisesRegex(Error, "database_revision_incompatible"):
            migrations.check_revision(self.engine)
        self.assertEqual(migrations.migrate(self.engine), migrations.SCHEMA_REVISION)
        self.assertEqual(migrations.migrate(self.engine), migrations.SCHEMA_REVISION)
        with self.sessions.begin() as session:
            first = Event(space_id="a", type="space.created", principal_id="owner")
            session.add(first)
            session.flush()
            self.assertGreater(first.id, 400)
            first_id = first.id
        with self.sessions.begin() as session:
            session.execute(delete(Event))
            following = Event(space_id="a", type="space.created", principal_id="owner")
            session.add(following)
            session.flush()
            self.assertGreater(following.id, first_id)

    def test_upgrade_also_seeds_sequence_above_retained_event_ids(self):
        self.baseline()
        with self.sessions.begin() as session:
            session.add(Space(id="a", name="A", event_floor=50))
            session.flush()
            session.add(Event(id=800, space_id="a", type="space.created", principal_id="owner"))
        migrations.migrate(self.engine)
        with self.sessions.begin() as session:
            following = Event(space_id="a", type="space.created", principal_id="owner")
            session.add(following)
            session.flush()
            self.assertGreater(following.id, 800)

    def test_failed_upgrade_rolls_back_data_ddl_and_ledger(self):
        self.baseline()
        with self.sessions.begin() as session:
            session.add(Space(id="a", name="A", event_floor=20))
            session.flush()
            session.add(Event(id=5, space_id="a", type="space.created", principal_id="owner"))

        def interrupted(connection):
            migrations._event_sequence(connection)
            raise RuntimeError("interrupted migration")

        with patch.object(migrations, "MIGRATIONS", ((migrations.SCHEMA_REVISION, interrupted),)):
            with self.assertRaisesRegex(RuntimeError, "interrupted migration"):
                migrations.migrate(self.engine)
        with self.engine.connect() as connection:
            self.assertEqual(connection.exec_driver_sql("SELECT revision FROM v2_schema_ledger").scalar_one(),
                             migrations.BASELINE_REVISION)
            self.assertEqual(connection.exec_driver_sql("SELECT id FROM v2_events").scalar_one(), 5)
            ddl = connection.exec_driver_sql("SELECT sql FROM sqlite_master WHERE name = 'v2_events'").scalar_one()
            self.assertNotIn("AUTOINCREMENT", ddl)
        self.assertNotIn("v2_events_0002", inspect(self.engine).get_table_names())
        self.assertEqual(migrations.migrate(self.engine), migrations.SCHEMA_REVISION)

    def test_migrate_rejects_unknown_or_multiple_ledger_rows_without_changing_schema(self):
        self.baseline()
        for revision in ("future", migrations.BASELINE_REVISION):
            with self.subTest(revision=revision):
                with self.engine.begin() as connection:
                    connection.exec_driver_sql("DELETE FROM v2_schema_ledger")
                    connection.execute(text("INSERT INTO v2_schema_ledger (revision) VALUES (:revision)"),
                                       {"revision": revision})
                    if revision == migrations.BASELINE_REVISION:
                        connection.exec_driver_sql("INSERT INTO v2_schema_ledger (revision) VALUES ('future')")
                with self.assertRaisesRegex(Error, "database_revision_incompatible"):
                    migrations.migrate(self.engine)
                with self.engine.connect() as connection:
                    ddl = connection.exec_driver_sql("SELECT sql FROM sqlite_master WHERE name = 'v2_events'").scalar_one()
                    self.assertNotIn("AUTOINCREMENT", ddl)


if __name__ == "__main__":
    unittest.main()
