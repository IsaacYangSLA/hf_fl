"""PostgreSQL external stop/event regression tests, with no ML execution.

JOBS_TEST_DATABASE_URL selects an expendable PostgreSQL fixture. Every test
creates only its own UUID schema, uses READ COMMITTED and independent pools,
and drops that schema after closing its owned connections. Failure reports
contain exception types and domain codes, never DSNs, SQL, or parameters.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import os
import queue
import threading
import unittest
from types import SimpleNamespace
from uuid import uuid4

from sqlalchemy import create_engine, event, select, text
from sqlalchemy.engine import make_url

from hf2l_jobs import models
from hf2l_jobs.application import Manager
from hf2l_jobs.controller import Controller
from hf2l_jobs.database import create_database
from hf2l_jobs.domain import Error
from hf2l_jobs.participants import ExternalParticipantService
from hf2l_jobs.source import RegistryCatalog
from test_participants import ExternalParticipantFixture


@unittest.skipUnless(os.environ.get("JOBS_TEST_DATABASE_URL"), "JOBS_TEST_DATABASE_URL is not configured")
class PostgreSQLParticipantStopTests(ExternalParticipantFixture):
    def setUp(self):
        try:
            supplied = make_url(os.environ["JOBS_TEST_DATABASE_URL"])
            if supplied.get_backend_name() != "postgresql":
                raise ValueError("A PostgreSQL fixture is required")
            self.schema = "jm_participant_stop_" + uuid4().hex
            self.admin = create_engine(supplied, pool_pre_ping=True, hide_parameters=True)
            self.addCleanup(self.admin.dispose)
            with self.admin.begin() as connection:
                connection.execute(text(f'CREATE SCHEMA "{self.schema}"'))
            self.addCleanup(self.drop_owned_schema)
            options = f"-csearch_path={self.schema} -clock_timeout=10000 -cstatement_timeout=20000"
            self.pg_url = supplied.update_query_dict({"options": options}).render_as_string(hide_password=False)
            super().setUp()
            self.enrollments = {name: self.enroll(name, key="pg-" + name) for name in ("alice", "bob")}
            self.activate()
            self.actors, self.documents = {}, {}
            for name, enrollment in self.enrollments.items():
                self.actors[name], self.documents[name] = self.node_actor(enrollment)
        except Exception as error:
            raise AssertionError("PostgreSQL participant fixture setup failed: " + type(error).__name__) from None

    def fixture_database(self, ignored_url):
        self.database_url = self.pg_url
        return create_database(self.pg_url, isolation_level="READ COMMITTED", hide_parameters=True)

    def drop_owned_schema(self):
        try:
            with self.admin.begin() as connection:
                connection.execute(text(f'DROP SCHEMA IF EXISTS "{self.schema}" CASCADE'))
        except Exception as error:
            raise AssertionError("Owned PostgreSQL schema cleanup failed: " + type(error).__name__) from None

    def service_for(self, database, manager=None):
        manager = manager or Manager(database, b"fixture-pagination-secret-32-bytes", clock=lambda: self.now)
        provisioner = SimpleNamespace(root=self.provisioner.root, exchange=self.exchange,
            registry=RegistryCatalog.from_database(database), _space_id=self.provisioner._space_id)
        return ExternalParticipantService(manager, provisioner, self.broker, [self.node])

    def snapshot(self, name):
        try:
            with self.database.transaction(immediate=False) as session:
                resource = session.get(models.ProvisioningResource, self.enrollments[name]["id"])
                historical = session.get(models.ProvisioningResource, resource.details_json["external_execution_id"])
                return dict(resource.details_json), dict(historical.details_json)
        except Exception as error:
            raise AssertionError("PostgreSQL receipt read failed: " + type(error).__name__) from None

    def events(self):
        try:
            with self.database.transaction(immediate=False) as session:
                events = list(session.scalars(select(models.Event).where(
                    models.Event.job_id == self.job["id"]).order_by(models.Event.sequence)))
                return [(item.id, item.sequence, item.kind, dict(item.data_json)) for item in events]
        except Exception as error:
            raise AssertionError("PostgreSQL event read failed: " + type(error).__name__) from None

    def race(self, requests, *, controller_event=False, attention=False):
        """All writers face a held real Job lock before trying their events."""
        count = len(requests) + int(controller_event)
        ready = queue.Queue()
        action, bootstrap = threading.Event(), threading.Event()
        job_queries = [threading.Event() for _ in range(count)]
        dispatch_waiting = [threading.Event() for _ in requests]
        entered_emit = threading.Event()

        def worker(index, request):
            database = None
            try:
                database = create_database(self.pg_url, initialize=False, isolation_level="READ COMMITTED",
                    hide_parameters=True, pool_size=1, max_overflow=0)
                with database.transaction(immediate=False) as session:
                    isolation = session.scalar(text("SHOW transaction_isolation"))
                    backend = session.scalar(text("SELECT pg_backend_pid()"))
                ready.put({"stage": "ready", "index": index, "backend": backend, "isolation": isolation})
                def query_started(connection, cursor, statement, parameters, context, executemany):
                    if action.is_set() and statement.lstrip().startswith("SELECT") and "jm_jobs" in statement:
                        job_queries[index].set()
                event.listen(database.engine, "before_cursor_execute", query_started)
                manager = Manager(database, b"fixture-pagination-secret-32-bytes", clock=lambda: self.now)
                real_emit = manager._emit
                def emit(*args, **kwargs):
                    entered_emit.set()
                    return real_emit(*args, **kwargs)
                manager._emit = emit
                if request is None:
                    if not action.wait(timeout=10):
                        raise TimeoutError("Controller start gate")
                    Controller(database, object(), object(), clock=lambda: self.now)._authoritative_round(self.job["id"], 1)
                    return {"stage": "result", "result": "controller"}
                name, never_started = request
                service = self.service_for(database, manager)
                if attention:
                    def fail_dispatch(node_id, document):
                        dispatch_waiting[index].set()
                        if not action.wait(timeout=10):
                            raise TimeoutError("Dispatch failure gate")
                        raise RuntimeError("Deterministic private node unavailable")
                    service.node_dispatch = fail_dispatch
                    if not bootstrap.wait(timeout=10):
                        raise TimeoutError("Bootstrap start gate")
                    result = service._dispatch_one(self.enrollments[name]["id"])
                else:
                    if not action.wait(timeout=10):
                        raise TimeoutError("Stop start gate")
                    result = service.confirm_stopped(self.actors[name], never_started=never_started)
                return {"stage": "result", "result": result, "never_started": never_started}
            except Error as error:
                return {"stage": "refused", "status": error.status, "code": error.code}
            except Exception as error:
                ready.put({"stage": "failed", "type": type(error).__name__})
                return {"stage": "failed", "type": type(error).__name__}
            finally:
                if database is not None:
                    database.close()

        with ThreadPoolExecutor(max_workers=count) as workers:
            futures = [workers.submit(worker, index, request) for index, request in enumerate(requests)]
            if controller_event:
                futures.append(workers.submit(worker, count - 1, None))
            try:
                arrivals = [ready.get(timeout=15) for _ in range(count)]
                self.assertTrue(all(item["stage"] == "ready" for item in arrivals), arrivals)
                self.assertEqual({item["isolation"] for item in arrivals}, {"read committed"})
                self.assertEqual(len({item["backend"] for item in arrivals}), count)
                if attention:
                    bootstrap.set()
                    self.assertTrue(all(gate.wait(timeout=10) for gate in dispatch_waiting),
                                    "The real dispatch callbacks did not reach their failure gate")
                with self.database.transaction() as session:
                    session.scalar(select(models.Job).where(models.Job.id == self.job["id"]).with_for_update())
                    action.set()
                    self.assertTrue(all(gate.wait(timeout=10) for gate in job_queries),
                                    "Writers did not reach the held Job row")
                    self.assertFalse(entered_emit.wait(timeout=0.2),
                        "A participant event writer entered _emit without owning the held Job lock")
            except AssertionError:
                raise
            except Exception as error:
                raise AssertionError("PostgreSQL race coordination failed: " + type(error).__name__) from None
            finally:
                action.set()
                bootstrap.set()
            results = [future.result(timeout=15) for future in futures]
        self.assertFalse(any(item["stage"] == "failed" for item in results), results)
        return results

    def assert_contiguous_new_events(self, before, kinds):
        after = self.events()
        self.assertEqual([sequence for _, sequence, _, _ in after], list(range(1, len(after) + 1)))
        self.assertEqual(after[:len(before)], before)
        self.assertCountEqual([kind for _, _, kind, _ in after[len(before):]], kinds)

    def test_concurrent_alice_bob_stops_and_controller_event_have_unique_sequences(self):
        before = self.events()
        results = self.race([("alice", False), ("bob", False)], controller_event=True)
        self.assertTrue(all(item["stage"] == "result" for item in results), results)
        self.assert_contiguous_new_events(before, ["participant.stopped", "participant.stopped", "round_confirmed"])
        for name in ("alice", "bob"):
            enrollment, historical = self.snapshot(name)
            self.assertEqual(enrollment["status"], "stopped")
            self.assertIs(enrollment["termination_confirmed"], True)
            self.assertIs(historical["termination_confirmed"], True)

    def test_two_connections_replaying_exact_stop_emit_one_event_and_keep_receipt(self):
        before = self.events()
        results = self.race([("alice", True), ("alice", True)])
        self.assertTrue(all(item.get("result") == {"accepted": True} for item in results), results)
        self.assert_contiguous_new_events(before, ["participant.stopped"])
        stopped = self.snapshot("alice")
        self.now += timedelta(seconds=30)
        self.assertEqual(self.service.confirm_stopped(self.actors["alice"], never_started=True), {"accepted": True})
        self.assertEqual(self.snapshot("alice"), stopped)
        self.assert_contiguous_new_events(before, ["participant.stopped"])

    def test_conflicting_concurrent_stop_receipts_have_one_immutable_winner(self):
        before = self.events()
        results = self.race([("alice", False), ("alice", True)])
        winners = [item for item in results if item["stage"] == "result"]
        refused = [item for item in results if item["stage"] == "refused"]
        self.assertEqual(len(winners), 1)
        self.assertEqual(refused, [{"stage": "refused", "status": 409, "code": "external_stop_receipt_immutable"}])
        self.assert_contiguous_new_events(before, ["participant.stopped"])
        enrollment, historical = self.snapshot("alice")
        self.assertIs(enrollment["never_started"], winners[0]["never_started"])
        self.assertIs(historical["never_started"], winners[0]["never_started"])

    def test_concurrent_attention_and_controller_events_share_the_same_job_lock(self):
        before = self.events()
        results = self.race([("alice", False), ("bob", False)], controller_event=True, attention=True)
        self.assertEqual([item.get("result") for item in results[:2]], [False, False])
        self.assert_contiguous_new_events(before, ["participant.attention", "participant.attention", "round_confirmed"])
        for name in ("alice", "bob"):
            enrollment, _ = self.snapshot(name)
            self.assertEqual(enrollment["last_dispatch_error"], "external_node_dispatch_failed")

    def test_writer_refreshes_preloaded_enrollment_after_another_connection_stops(self):
        try:
            with self.database.transaction(immediate=False) as stale:
                cached = stale.get(models.ProvisioningResource, self.enrollments["alice"]["id"])
                self.assertFalse(cached.details_json["termination_confirmed"])
                other = create_database(self.pg_url, initialize=False, isolation_level="READ COMMITTED", hide_parameters=True)
                try:
                    self.service_for(other).confirm_stopped(self.actors["alice"], never_started=True)
                finally:
                    other.close()
                refreshed, *_ = self.service._node_record(stale, self.actors["alice"], write=True)
                self.assertIs(refreshed, cached)
                self.assertEqual(refreshed.details_json["status"], "stopped")
                self.assertIs(refreshed.details_json["never_started"], True)
        except AssertionError:
            raise
        except Exception as error:
            raise AssertionError("PostgreSQL identity map refresh failed: " + type(error).__name__) from None

    def test_bootstrap_waiting_on_stop_commit_preserves_receipt_and_stop_only_scope(self):
        stop_written, continue_stop, bootstrap_query = threading.Event(), threading.Event(), threading.Event()
        def stop_worker():
            database = create_database(self.pg_url, initialize=False, isolation_level="READ COMMITTED", hide_parameters=True)
            try:
                manager = Manager(database, b"fixture-pagination-secret-32-bytes", clock=lambda: self.now)
                real_emit = manager._emit
                def emit(*args, **kwargs):
                    result = real_emit(*args, **kwargs)
                    stop_written.set()
                    if not continue_stop.wait(timeout=10):
                        raise TimeoutError("Stop commit gate")
                    return result
                manager._emit = emit
                return self.service_for(database, manager).confirm_stopped(self.actors["alice"], never_started=True)
            except Exception as error:
                return {"failure_type": type(error).__name__}
            finally:
                database.close()
        def bootstrap_worker():
            database = create_database(self.pg_url, initialize=False, isolation_level="READ COMMITTED", hide_parameters=True)
            try:
                def before_query(connection, cursor, statement, parameters, context, executemany):
                    if statement.lstrip().startswith("SELECT") and "jm_jobs" in statement:
                        bootstrap_query.set()
                event.listen(database.engine, "before_cursor_execute", before_query)
                result = self.service_for(database).bootstrap_credentials(self.enrollments["alice"]["id"])
                return {"operation": result["operation"]}
            except Exception as error:
                return {"failure_type": type(error).__name__}
            finally:
                database.close()
        with ThreadPoolExecutor(max_workers=2) as workers:
            stopping = workers.submit(stop_worker)
            try:
                self.assertTrue(stop_written.wait(timeout=10))
                bootstrapping = workers.submit(bootstrap_worker)
                self.assertTrue(bootstrap_query.wait(timeout=10))
                self.assertFalse(bootstrapping.done())
            finally:
                continue_stop.set()
            self.assertEqual(stopping.result(timeout=15), {"accepted": True})
            self.assertEqual(bootstrapping.result(timeout=15), {"operation": "stop"})
        enrollment, historical = self.snapshot("alice")
        self.assertEqual(enrollment["status"], "stopped")
        self.assertIs(enrollment["never_started"], True)
        self.assertIs(historical["never_started"], True)

    def test_dispatch_success_waiting_on_uncommitted_stop_preserves_exact_receipt(self):
        callback_entered, stop_written, continue_stop, dispatch_job_query = (
            threading.Event() for _ in range(4))
        accepted_receipt = []
        def stop_worker():
            database = None
            try:
                if not callback_entered.wait(timeout=10):
                    raise TimeoutError("Dispatcher callback gate")
                database = create_database(self.pg_url, initialize=False, isolation_level="READ COMMITTED", hide_parameters=True)
                manager = Manager(database, b"fixture-pagination-secret-32-bytes", clock=lambda: self.now)
                real_emit = manager._emit
                def emit(session, *args, **kwargs):
                    result = real_emit(session, *args, **kwargs)
                    resource = session.get(models.ProvisioningResource, self.enrollments["alice"]["id"])
                    history = session.get(models.ProvisioningResource, resource.details_json["external_execution_id"])
                    accepted_receipt.append((dict(resource.details_json), dict(history.details_json)))
                    stop_written.set()
                    if not continue_stop.wait(timeout=10):
                        raise TimeoutError("Stop commit gate")
                    return result
                manager._emit = emit
                return self.service_for(database, manager).confirm_stopped(self.actors["alice"], never_started=True)
            except Exception as error:
                return {"failure_type": type(error).__name__}
            finally:
                if database is not None:
                    database.close()
        def dispatch_worker():
            database = None
            try:
                database = create_database(self.pg_url, initialize=False, isolation_level="READ COMMITTED", hide_parameters=True)
                def before_query(connection, cursor, statement, parameters, context, executemany):
                    if stop_written.is_set() and statement.lstrip().startswith("SELECT") and "jm_jobs" in statement:
                        dispatch_job_query.set()
                event.listen(database.engine, "before_cursor_execute", before_query)
                service = self.service_for(database)
                def callback(node_id, document):
                    callback_entered.set()
                    if not stop_written.wait(timeout=10):
                        raise TimeoutError("Uncommitted callback stop gate")
                    return {"accepted": True}
                service.node_dispatch = callback
                return service._dispatch_one(self.enrollments["alice"]["id"])
            except Exception as error:
                return {"failure_type": type(error).__name__}
            finally:
                if database is not None:
                    database.close()
        before = self.events()
        with ThreadPoolExecutor(max_workers=2) as workers:
            stopping = workers.submit(stop_worker)
            dispatching = workers.submit(dispatch_worker)
            try:
                self.assertTrue(stop_written.wait(timeout=10))
                self.assertTrue(dispatch_job_query.wait(timeout=10),
                    "Dispatch success must take the Job lock before reloading enrollment")
                self.assertFalse(dispatching.done(), "Success receipt escaped the uncommitted stop writer")
            finally:
                continue_stop.set()
            self.assertEqual(stopping.result(timeout=15), {"accepted": True})
            self.assertIs(dispatching.result(timeout=15), True)
        self.assertEqual(self.snapshot("alice"), accepted_receipt[0])
        self.assert_contiguous_new_events(before, ["participant.stopped"])


if __name__ == "__main__":
    unittest.main()
