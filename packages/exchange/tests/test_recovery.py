"""Actual process-exit recovery and concurrent publication using shared services.

The child exits after a provider side effect and before its DB result commit.
Tests advance the persisted lease deadline instead of sleeping for a lease period.
"""
from __future__ import annotations

from hashlib import sha256
import multiprocessing
import os
import unittest

import httpx
from sqlalchemy import event, select

from hf2l_exchange.models import Blob, Space, TransferAttempt, database_time
from support import ExchangeTestCase


def process_command(settings, authorization, action, arguments, output, barrier=None):
    """Spawn-safe entrypoint: no inherited sessions, engines or storage clients."""
    from hf2l_exchange.application import Service
    from hf2l_exchange.auth import Authenticator
    from hf2l_exchange.domain import ExchangeError
    from hf2l_exchange.storage import S3BlobStore
    from hf2l_exchange.transfers import TransferService
    from hf2l_exchange.worker import tick

    service = Service(settings)
    try:
        principal = Authenticator(settings.auth).authenticate(authorization)
        if barrier is not None and not barrier.wait(timeout=20):
            raise RuntimeError("concurrent test barrier timed out")
        if action == "reference":
            result = service.put_reference(principal, *arguments)
        elif action == "acquire":
            result = service.acquire(principal, *arguments)
        else:
            storage = S3BlobStore(settings.storage)
            transfers = TransferService(service, storage)
            if action in {"crash-initiation", "crash-completion"}:
                operation = "start" if action == "crash-initiation" else "complete"
                original = getattr(storage, operation)

                def create_then_exit(*args, **kwargs):
                    original(*args, **kwargs)
                    os._exit(23)

                setattr(storage, operation, create_then_exit)
                method = transfers.initiate if action == "crash-initiation" else transfers.complete
                method(*arguments, principal)
                raise AssertionError("injected crash was not reached")
            if action != "tick":
                raise AssertionError("unknown child command")
            result = [tick(transfers) for _ in range(3)]
        output.send(("ok", result))
    except ExchangeError as exc:
        output.send(("error", exc.status, exc.code))
    except Exception as exc:
        output.send(("exception", type(exc).__name__, str(exc)))
    finally:
        service.engine.dispose()
        output.close()


class ProcessRecoveryTests(ExchangeTestCase):
    def spawn_command(self, action, arguments, subject="publisher", barrier=None):
        context = multiprocessing.get_context("spawn")
        receive, send = context.Pipe(duplex=False)
        process = context.Process(target=process_command,
            args=(self.settings, self.auth(subject)["Authorization"], action, arguments, send, barrier))
        process.start()
        send.close()

        def stop_child():
            if process.is_alive():
                process.terminate()
            process.join(timeout=10)
            receive.close()

        self.addCleanup(stop_child)
        return process, receive

    def result(self, child):
        process, receive = child
        self.assertTrue(receive.poll(30), "child did not return within 30 seconds")
        result = receive.recv()
        process.join(timeout=10)
        self.assertEqual(process.exitcode, 0, result)
        self.assertNotEqual(result[0], "exception", result)
        return result

    def expire_attempt_lease(self, record):
        with self.service.sessions.begin() as session:
            attempt = session.scalar(select(TransferAttempt).where(
                TransferAttempt.blob_id == record["attachments"][0]["id"]))
            attempt.lease_until = 0
            attempt.next_attempt = 0
            return attempt.id, attempt.object_key

    def declaration(self, content):
        return {"path": "ordinary.bin", "size": len(content), "sha256": sha256(content).hexdigest()}

    def begin_upload(self, content):
        record = self.create(attachments=[self.declaration(content)]).json()
        path = self.prefix + f"/records/{record['id']}/attachments/{record['attachments'][0]['id']}"
        begun = self.request("POST", path + "/upload", "alice")
        self.assertEqual(begun.status_code, 200, begun.text)
        grants = self.request("POST", path + "/grants", "alice", json={"numbers": [1]})
        self.assertEqual(grants.status_code, 200, grants.text)
        grant = grants.json()["grants"][0]
        self.assertEqual(httpx.put(grant["url"], headers=grant["headers"], content=content, timeout=30).status_code, 200)
        return record, path

    def test_concurrent_process_reference_updates_have_exactly_one_winner(self):
        base = self.ready("publisher")
        reference = self.reference(base).json()
        contenders = [self.ready("publisher", metadata={"candidate": n}) for n in range(2)]
        barrier = multiprocessing.get_context("spawn").Event()
        children = [self.spawn_command("reference", (self.space["id"], "main", {"record_id": record["id"]},
                        reference["token"], "writer-" + str(n)), barrier=barrier)
                    for n, record in enumerate(contenders)]
        barrier.set()
        results = [self.result(child) for child in children]
        self.assertEqual(sum(result[0] == "ok" for result in results), 1, results)
        loser = next(result for result in results if result[0] != "ok")
        self.assertEqual(loser, ("error", 412, "reference_version_mismatch"))
        current = self.request("GET", self.prefix + "/refs/main", "bob").json()
        self.assertEqual(int(current["token"]), int(reference["token"]) + 1)
        winner = next(result[1] for result in results if result[0] == "ok")
        self.assertEqual(current, winner)

    def test_new_process_recovers_lost_acquisition_response_by_persisted_key(self):
        base = self.ready("publisher")
        reference = self.reference(base).json()
        source = self.ready("alice")
        body = {"reference": "main", "expected_token": reference["token"], "input_record_ids": [source["id"]]}
        arguments = (self.space["id"], body, "durable-acquisition-key")
        first = self.result(self.spawn_command("acquire", arguments))
        self.assertEqual(first[0], "ok", first)
        # A second entirely new process has only the durable key and request.
        replay = self.result(self.spawn_command("acquire", arguments))
        self.assertEqual(replay, first)
        other = self.result(self.spawn_command("acquire", (self.space["id"], body, "another-job")))
        self.assertEqual(other, ("error", 409, "acquisition_busy"))

    def test_worker_restart_recovers_provider_completion_after_process_exit(self):
        content = b"completed bytes whose HTTP response was lost"
        record, path = self.begin_upload(content)
        arguments = (self.space["id"], record["id"], record["attachments"][0]["id"])
        process, _ = self.spawn_command("crash-completion", arguments, subject="alice")
        process.join(timeout=30)
        self.assertEqual(process.exitcode, 23)
        attempt_id, key = self.expire_attempt_lease(record)
        stored = self.s3.get_object(Bucket=self.bucket, Key=key)
        self.assertEqual(stored["Body"].read(), content)
        stored["Body"].close()
        self.assertEqual(self.result(self.spawn_command("tick", ()))[0], "ok")
        with self.service.sessions.begin() as session:
            attempt = session.get(TransferAttempt, attempt_id)
            self.assertEqual(attempt.state, "completing")
            self.assertTrue(attempt.mutation_tokens)
            self.assertEqual(session.get(Blob, record["attachments"][0]["id"]).state, "completing")
        self.apply_quiescent_repair(attempt_id, "recover_completion")
        self.assertEqual(self.result(self.spawn_command("tick", ()))[0], "ok")
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(TransferAttempt, attempt_id).state, "verified")
            blob = session.get(Blob, record["attachments"][0]["id"])
            self.assertEqual(blob.verified_sha256, sha256(content).hexdigest())
            self.assertEqual(blob.object_version, stored["VersionId"])
        published = self.request("POST", self.prefix + f"/records/{record['id']}/publish", "alice")
        self.assertEqual(published.status_code, 200, published.text)
        grant = self.request("GET", path + "/download", "bob").json()
        self.assertEqual(httpx.get(grant["url"], timeout=30).content, content)

    def test_worker_restart_uses_new_key_after_lost_initiation_and_reclaims_only_old_key(self):
        content = b"resumed on a new attempt"
        record = self.create(attachments=[self.declaration(content)]).json()
        arguments = (self.space["id"], record["id"], record["attachments"][0]["id"])
        process, _ = self.spawn_command("crash-initiation", arguments, subject="alice")
        process.join(timeout=30)
        self.assertEqual(process.exitcode, 23)
        old_id, old_key = self.expire_attempt_lease(record)
        before = self.s3.list_multipart_uploads(Bucket=self.bucket).get("Uploads", [])
        self.assertEqual([upload["Key"] for upload in before], [old_key])
        self.assertEqual(self.result(self.spawn_command("tick", ()))[0], "ok")
        with self.service.sessions.begin() as session:
            old = session.get(TransferAttempt, old_id)
            self.assertEqual(old.state, "cleanup")
            self.assertTrue(old.mutation_tokens)
            self.assertIsNone(session.scalar(select(TransferAttempt).where(
                TransferAttempt.blob_id == old.blob_id, TransferAttempt.id != old_id)))
        # Neither worker recovery nor a client retry may reserve another object
        # key while the first provider mutation has an unknown outcome.
        path = self.prefix + f"/records/{record['id']}/attachments/{record['attachments'][0]['id']}"
        blocked = self.request("POST", path + "/upload", "alice")
        self.assertEqual(blocked.status_code, 409, blocked.text)
        self.apply_quiescent_repair(old_id, "schedule_cleanup")
        self.assertEqual(self.result(self.spawn_command("tick", ()))[0], "ok")
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(TransferAttempt, old_id).state, "cleaned")
        self.assertEqual(self.s3.list_multipart_uploads(Bucket=self.bucket).get("Uploads", []), [])
        finished = self.upload(record, content)
        self.assertEqual(finished["attachments"][0]["state"], "verified")
        with self.service.sessions.begin() as session:
            successor = session.scalar(select(TransferAttempt).where(
                TransferAttempt.blob_id == record["attachments"][0]["id"], TransferAttempt.id != old_id))
            self.assertEqual(successor.state, "verified")
            self.assertNotEqual(successor.object_key, old_key)

    def test_cancelled_crash_keeps_physical_quota_until_operator_repair_and_cleanup(self):
        content = b"uncertain storage reservation"
        with self.service.sessions.begin() as session:
            session.get(Space, self.space["id"]).quota_bytes = len(content)
        record = self.create(attachments=[self.declaration(content)]).json()
        arguments = (self.space["id"], record["id"], record["attachments"][0]["id"])
        process, _ = self.spawn_command("crash-initiation", arguments, subject="alice")
        process.join(timeout=30)
        self.assertEqual(process.exitcode, 23)
        attempt_id, _ = self.expire_attempt_lease(record)
        self.assert_quiescent_repair_then_cleanup(record, attempt_id)
        self.assertEqual(self.create(attachments=[self.declaration(content)]).status_code, 201)

    def apply_quiescent_repair(self, attempt_id, action):
        from hf2l_exchange.domain import ExchangeError
        from hf2l_exchange.transfers import repair_mutations

        with self.service.sessions.begin() as session:
            retained = list(session.get(TransferAttempt, attempt_id).mutation_tokens)
        self.assertTrue(retained)
        preview = repair_mutations(self.service, [attempt_id])
        self.assertEqual(preview["attempts"][0]["action"], action)
        self.assertTrue(preview["attempts"][0]["repairable"])
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(TransferAttempt, attempt_id).mutation_tokens, retained)
        for assertions in ({}, {"writers_stopped": True}, {"provider_quiesced": True}):
            with self.assertRaises(ExchangeError) as denied:
                repair_mutations(self.service, [attempt_id], execute=True, **assertions)
            self.assertEqual(denied.exception.code, "storage_quiescence_required")
        # No writer is running and the fixture knows the synchronous provider
        # request completed before its child called os._exit.
        repair_mutations(self.service, [attempt_id], execute=True,
                         writers_stopped=True, provider_quiesced=True)
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(TransferAttempt, attempt_id).mutation_tokens, [])

    def assert_quiescent_repair_then_cleanup(self, record, uncertain_attempt_id):
        """Process death cannot establish that the provider has stopped mutating."""
        from hf2l_exchange.transfers import repair_mutations
        route = self.prefix + f"/records/{record['id']}"
        self.assertEqual(self.request("DELETE", route, "alice").status_code, 200)
        attachment_id = record["attachments"][0]["id"]
        declared_size = record["attachments"][0]["size"]
        # Advance only persisted grant deadlines; these tests no longer use the
        # previously issued grants. Mutation markers remain unresolved.
        with self.service.sessions.begin() as session:
            blob = session.get(Blob, attachment_id)
            blob.grant_expires_at = blob.expires_at = 0
            for attempt in session.scalars(select(TransferAttempt).where(TransferAttempt.blob_id == attachment_id)):
                attempt.grant_expires_at = 0
                attempt.next_attempt = 0
                attempt.lease_until = 0
        self.assertEqual(self.result(self.spawn_command("tick", ()))[0], "ok")
        with self.service.sessions.begin() as session:
            attempt = session.get(TransferAttempt, uncertain_attempt_id)
            retained_markers = list(attempt.mutation_tokens)
            self.assertTrue(retained_markers)
            self.assertNotEqual(attempt.state, "cleaned")
            self.assertEqual(session.get(Space, self.space["id"]).reclaiming, declared_size)
            self.assertTrue(session.get(Blob, attachment_id).pending_deletion)
        denied = self.create(attachments=[{name: record["attachments"][0][name] for name in ("path", "size", "sha256")}])
        self.assertEqual(self.code(denied), "blob_quota_exceeded")
        # A repair preview cannot clear markers or reduce the retained charge.
        repair_mutations(self.service, [uncertain_attempt_id])
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(TransferAttempt, uncertain_attempt_id).mutation_tokens, retained_markers)
            self.assertEqual(session.get(Space, self.space["id"]).reclaiming, declared_size)
        # Both assertions are true in this fixture: the crash process exited,
        # and its synchronous provider request completed before os._exit.
        repair_mutations(self.service, [uncertain_attempt_id], execute=True,
                         writers_stopped=True, provider_quiesced=True)
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(TransferAttempt, uncertain_attempt_id).mutation_tokens, [])
            self.assertEqual(session.get(Space, self.space["id"]).reclaiming, declared_size)
        self.assertEqual(self.result(self.spawn_command("tick", ()))[0], "ok")
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(Space, self.space["id"]).reclaiming, 0)
            self.assertEqual(session.get(Blob, attachment_id).state, "cleaned")

    def test_postgresql_retry_waits_for_space_lock_and_preserves_successor_lease(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Event
        from hf2l_exchange.storage import StorageFailure

        if self.service.engine.dialect.name != "postgresql":
            self.skipTest("Requires PostgreSQL row-lock concurrency")
        record, _ = self.begin_upload(b"retry fence")
        with self.service.sessions.begin() as session:
            old = session.scalar(select(TransferAttempt).where(
                TransferAttempt.blob_id == record["attachments"][0]["id"]))
            old.state = "verifying"
            old.token = "old-operation"
            old.lease_until = database_time(session) + 300
            session.flush()
            session.expunge(old)
        waiting = Event()

        def observe_lock(connection, cursor, statement, parameters, context, executemany):
            if "v2_spaces" in statement and "FOR UPDATE" in statement.upper():
                waiting.set()

        pool = ThreadPoolExecutor(max_workers=1)
        listener_added = False
        try:
            with self.service.sessions.begin() as session:
                session.scalar(select(Space).where(Space.id == self.space["id"]).with_for_update())
                event.listen(self.service.engine, "before_cursor_execute", observe_lock)
                listener_added = True
                pending = pool.submit(self.transfers._retry, old, StorageFailure("old-timeout", retryable=True))
                self.assertTrue(waiting.wait(timeout=10), "Retry did not acquire the space lock before reading ownership")
                current = session.get(TransferAttempt, old.id)
                current.token = "successor-operation"
                current.lease_until = database_time(session) + 300
                current.retry_count = 7
                current.last_error = "successor-state"
                current.next_attempt = 12345
            pending.result(timeout=10)
        finally:
            pool.shutdown(wait=True)
            if listener_added:
                event.remove(self.service.engine, "before_cursor_execute", observe_lock)
        with self.service.sessions.begin() as session:
            current = session.get(TransferAttempt, old.id)
            self.assertEqual(current.token, "successor-operation")
            self.assertEqual(current.retry_count, 7)
            self.assertEqual(current.last_error, "successor-state")
            self.assertEqual(current.next_attempt, 12345)


if __name__ == "__main__":
    unittest.main()
