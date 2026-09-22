"""Regression coverage for the exchange review: real transfer paths and controlled interleavings."""
import hashlib
import json
import os
from pathlib import Path
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import test_exchange as fixtures

if fixtures.EXCHANGE_AVAILABLE:
    import httpx
    import jwt
    from sqlalchemy import event, select, text
    from sqlalchemy.exc import IntegrityError
    from hf2l.exchange.auth import Authenticator, principal_id
    from hf2l.exchange.client import ExchangeError
    from hf2l.exchange.config import Settings
    from hf2l.exchange.leases import heartbeat
    from hf2l.exchange.models import Blob, Claim, Event, Member, Operation, Record, Ref, Space, database_time
    from hf2l.exchange.worker import acquire, commit, release_lease, tick, prune
    from hf2l.exchange.storage import StorageMisconfigured, S3BlobStore
    from hf2l.exchange.api import create_app
    from hf2l.exchange.migrations import initialize, migrate
    from hf2l.backends.base import ResolvedReference
    from hf2l.backends.exchange import ExchangeStore
    from hf2l.hub_helpers import ROUND_FILE, write_json


@unittest.skipUnless(fixtures.EXCHANGE_AVAILABLE, "install exchange test dependencies")
class HardeningTests(unittest.TestCase):
    def test_expired_worker_cannot_commit_or_release_successor(self):
        record = self.create(data=b"lease").json()
        blob_id = self.upload(record, b"lease")
        old, state = acquire(self.service, blob_id)
        with self.service.sessions.begin() as session:
            session.get(Blob, blob_id).worker_lease_until = 1
        new, _ = acquire(self.service, blob_id)
        self.assertFalse(commit(self.service, old, state, "verified", old.sha256))
        release_lease(self.service, old)
        with self.service.sessions.begin() as session:
            row = session.get(Blob, blob_id)
            self.assertEqual(row.worker_token, new.worker_token)
            self.assertIsNotNone(row.worker_lease_until)
        self.assertTrue(commit(self.service, new, state, "verified", new.sha256))

    def test_renewal_and_active_lease_do_not_starve_other_blobs(self):
        self.service.settings = replace(self.settings, worker_lease_seconds=3)
        first = self.create(data=b"first").json()
        first_id = self.upload(first, b"first")
        owner, _ = acquire(self.service, first_id)
        second = self.create("bob", data=b"second").json()
        second_id = self.upload(second, b"second", "bob")
        with heartbeat(self.service, owner):
            self.assertEqual(tick(self.service, batch=1)["verified"], 1)
            time.sleep(3.2)
            self.assertIsNone(acquire(self.service, first_id))
        release_lease(self.service, owner)
        self.assertEqual(tick(self.service)["verified"], 1)

    def test_missing_version_is_terminal_and_cleanup_releases_physical_budget(self):
        record = self.create(data=b"gone").json()
        blob_id = self.upload(record, b"gone")
        with self.service.sessions.begin() as session:
            blob = session.get(Blob, blob_id)
            self.s3.delete_object(Bucket=self.settings.bucket, Key=blob.key, VersionId=blob.version)
            session.get(Record, record["id"]).expires_at = 1
        self.assertEqual(tick(self.service)["failed"], 1)
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(Record, record["id"]).state, "failed")
            self.assertEqual((session.get(Space, self.space).allocated, session.get(Space, self.space).reclaiming), (0, 4))
            session.get(Blob, blob_id).expires_at = 1
        self.assertEqual(tick(self.service)["cleaned"], 1)
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(Space, self.space).reclaiming, 0)

    def test_cancelled_and_expired_multipart_uploads_are_actually_aborted(self):
        for cancel in (True, False):
            record = self.create(data=b"pending").json()
            blob_id = record["attachments"][0]["id"]
            self.client.post(self.prefix + f"/records/{record['id']}/blobs/{blob_id}/uploads", headers=self.auth("alice"))
            with self.service.sessions.begin() as session:
                blob = session.get(Blob, blob_id)
                key, upload_id = blob.key, blob.upload_id
                session.get(Record, record["id"]).expires_at = 1
            self.assertIn(upload_id, list(self.storage.pending_uploads(key)))
            if cancel:
                self.client.delete(self.prefix + f"/records/{record['id']}", headers=self.auth("alice"))
            with self.service.sessions.begin() as session:
                session.get(Blob, blob_id).expires_at = 1
            self.assertEqual(tick(self.service)["cleaned"], 1)
            self.assertEqual(list(self.storage.pending_uploads(key)), [])
            remaining = self.s3.list_object_versions(Bucket=self.settings.bucket, Prefix=key)
            self.assertFalse(remaining.get("Versions") or remaining.get("DeleteMarkers"))

    def test_only_one_http_completion_attempt_enters_storage(self):
        record = self.create(data=b"data").json()
        blob_id = record["attachments"][0]["id"]
        route = self.prefix + f"/uploads/{blob_id}:complete"
        original = self.storage.complete
        competing = []
        def nested(blob):
            competing.append(self.client.post(route, headers=self.auth("alice")))
            return original(blob)
        with patch.object(self.storage, "complete", side_effect=nested) as finish:
            self.upload(record, b"data")
        self.assertEqual(finish.call_count, 1)
        self.assertEqual((competing[0].status_code, competing[0].json()["state"]), (202, "completing"))
        self.assertEqual(tick(self.service)["verified"], 1)

    def test_losing_initiation_aborts_only_its_own_upload(self):
        record = self.create(data=b"data").json()
        blob_id = record["attachments"][0]["id"]
        original = self.storage.start
        ids = []
        def cancelled(key):
            provider_id = original(key)
            ids.append(provider_id)
            self.client.delete(self.prefix + f"/records/{record['id']}", headers=self.auth("alice"))
            return provider_id
        with patch.object(self.storage, "start", side_effect=cancelled):
            response = self.client.post(self.prefix + f"/records/{record['id']}/blobs/{blob_id}/uploads", headers=self.auth("alice"))
        self.assertEqual(self.code(response), "upload_cancelled")
        with self.service.sessions.begin() as session:
            blob = session.get(Blob, blob_id)
        self.assertNotIn(ids[0], list(self.storage.pending_uploads(blob.key)))
        # A recovery worker that loses its CAS must also abort its newly-created, unadopted MPU.
        second = self.create(data=b"other").json()
        second_id = second["attachments"][0]["id"]
        with self.service.sessions.begin() as session:
            row = session.get(Blob, second_id)
            row.state, row.updated_at = "initiating", time.time() - 60
        def lose(key):
            orphan = original(key)
            successor = original(key)
            ids.extend([orphan, successor])
            with self.service.sessions.begin() as session:
                current = session.get(Blob, second_id)
                current.state, current.upload_id, current.worker_token = "uploading", successor, "successor"
            return orphan
        with patch.object(self.storage, "recover_start", side_effect=lose):
            tick(self.service)
        with self.service.sessions.begin() as session:
            key = session.get(Blob, second_id).key
        self.assertEqual(list(self.storage.pending_uploads(key)), [ids[-1]])

    def test_resume_already_failed_blob_cancels_poisoned_state(self):
        path = Path(self.temp.name) / "data"
        path.write_bytes(b"payload")
        state = Path(self.temp.name) / "state.json"
        def fail(request):
            raise httpx.ConnectError("interrupted", request=request)
        sdk = self.sdk("alice", httpx.Client(transport=httpx.MockTransport(fail)))
        with self.assertRaises(ExchangeError):
            sdk.put_record(self.space, kind="message", metadata={}, files={"data": path}, state_path=state)
        record_id = json.loads(state.read_text())["record_id"]
        record = sdk.get_record(self.space, record_id)
        with self.service.sessions.begin() as session:
            session.get(Blob, record["attachments"][0]["id"]).state = "failed"
        with self.assertRaises(ExchangeError) as exc:
            sdk.put_record(self.space, kind="message", metadata={}, files={"data": path}, state_path=state)
        self.assertEqual(exc.exception.code, "blob_verification_failed")
        self.assertFalse(state.exists())
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(Record, record_id).state, "cancelled")
            self.assertEqual(session.get(Space, self.space).allocated, 0)

    def test_resume_does_not_resend_confirmed_parts(self):
        self.background_worker()
        path = Path(self.temp.name) / "parts.bin"
        path.write_bytes(b"x" * (2 * self.settings.part_bytes + 7))
        state = Path(self.temp.name) / "resume.json"
        sent, failures = [], [3]
        def transfer(request):
            if request.method == "PUT":
                number = int(parse_qs(request.url.query.decode())["partNumber"][0])
                sent.append(number)
                if number == 2 and failures[0]:
                    failures[0] -= 1
                    raise httpx.ConnectError("interrupted", request=request)
        sdk = self.sdk("alice", httpx.Client(event_hooks={"request": [transfer]}))
        with self.assertRaises(ExchangeError):
            sdk.put_record(self.space, kind="message", metadata={}, files={"parts.bin": path}, state_path=state)
        self.assertEqual(sent.count(1), 1)
        record = sdk.put_record(self.space, kind="message", metadata={"retried": True}, files={"parts.bin": path}, state_path=state)
        self.assertEqual((record["state"], sent.count(1), sent.count(2), sent.count(3)), ("ready", 1, 4, 1))

    def test_parts_authorization_and_completion_errors(self):
        data = b"good"
        record = self.create(data=data).json()
        blob_id = record["attachments"][0]["id"]
        self.client.post(self.prefix + f"/records/{record['id']}/blobs/{blob_id}/uploads", headers=self.auth("alice"))
        route = self.prefix + f"/uploads/{blob_id}"
        for number in (0, 2):
            denied = self.client.post(route + "/parts:authorize", headers=self.auth("alice"), json={"part_numbers": [number]})
            self.assertEqual((denied.status_code, self.code(denied)), (422, "invalid_part_number"))
        self.assertEqual(self.code(self.client.post(route + ":complete", headers=self.auth("alice"))), "upload_parts_incomplete_or_invalid")
        grant = self.client.post(route + "/parts:authorize", headers=self.auth("alice"), json={"part_numbers": [1]}).json()["parts"][0]
        # Use service credentials only to inject an invalid part that a length-bound grant cannot produce.
        with self.service.sessions.begin() as session:
            blob = session.get(Blob, blob_id)
        self.s3.upload_part(Bucket=self.settings.bucket, Key=blob.key, UploadId=blob.upload_id, PartNumber=1, Body=b"bad")
        self.assertEqual(self.code(self.client.post(route + ":complete", headers=self.auth("alice"))), "upload_parts_incomplete_or_invalid")
        with httpx.Client() as transfer:
            self.assertEqual(transfer.put(grant["url"], content=data, headers=grant["headers"]).status_code, 200)
        status = self.client.get(route, headers=self.auth("alice")).json()
        self.assertEqual(status["parts"], [{"part_number": 1, "size_bytes": 4}])
        self.assertEqual(self.client.post(route + ":complete", headers=self.auth("alice")).status_code, 202)
        self.assertEqual(tick(self.service)["verified"], 1)

    def test_storage_misconfiguration_preserves_completion_for_recovery(self):
        record = self.create(data=b"data").json()
        original = self.storage.complete
        def misconfigured(blob):
            original(blob)
            raise StorageMisconfigured("immutable versions unavailable")
        blob_id = record["attachments"][0]["id"]
        self.client.post(self.prefix + f"/records/{record['id']}/blobs/{blob_id}/uploads", headers=self.auth("alice"))
        with self.service.sessions.begin() as session:
            blob = session.get(Blob, blob_id)
        self.s3.upload_part(Bucket=self.settings.bucket, Key=blob.key, UploadId=blob.upload_id, PartNumber=1, Body=b"data")
        with patch.object(self.storage, "complete", side_effect=misconfigured):
            response = self.client.post(self.prefix + f"/uploads/{blob_id}:complete", headers=self.auth("alice"))
        self.assertEqual((response.status_code, self.code(response)), (503, "storage_misconfigured"))
        self.assertEqual(response.headers["Retry-After"], "3")
        with self.service.sessions.begin() as session:
            blob = session.get(Blob, blob_id)
            self.assertEqual(blob.state, "completing")
        self.assertEqual(tick(self.service)["recovered"], 1)
        self.assertEqual(tick(self.service)["verified"], 1)

    def test_claim_keys_distinguish_jobs_and_renewal_is_fenced(self):
        base = self.ready()
        self.ref(base)
        for subject in ("alice", "bob"):
            self.ready(subject, "training.update", base["id"])
        first = self.claim(key="job-one", lease_seconds=60).json()
        replay = self.claim(key="job-one", lease_seconds=60).json()
        self.assertEqual((first["id"], first["fence"]), (replay["id"], replay["fence"]))
        self.assertEqual(self.code(self.claim(key="job-two")), "claim_busy")
        self.assertEqual(self.code(self.claim(key="job-one", minimum=99)), "idempotency_key_reused")
        route = self.prefix + f"/claims/{first['id']}"
        renewal = self.client.post(route + ":renew", headers=self.headers, json={"fence": first["fence"], "lease_seconds": 120})
        self.assertEqual(renewal.status_code, 200)
        self.assertGreater(renewal.json()["lease_until"], first["lease_until"])
        self.assertEqual(self.code(self.client.post(route + ":renew", headers=self.headers, json={"fence": 99})), "claim_not_active")
        self.member("carol", ["coordinator"])
        self.assertEqual(self.code(self.client.post(route + ":renew", headers=self.auth("carol"), json={"fence": 1})), "claim_held_by_other")
        with self.service.sessions.begin() as session:
            session.get(Claim, first["id"]).lease_until = 1
        self.assertEqual(self.code(self.client.post(route + ":renew", headers=self.headers, json={"fence": 1})), "claim_not_active")
        self.assertEqual(self.code(self.claim(key="job-one", lease_seconds=60)), "claim_not_active")
        self.assertGreater(self.claim(key="replacement").json()["fence"], first["fence"])

    def test_adapter_recovers_lost_claim_response_with_persisted_key(self):
        base = self.ready()
        self.ref(base)
        for subject in ("alice", "bob"):
            self.ready(subject, "training.update", base["id"])
        owner = self.store("owner")
        owner.resolve_reference(self.space)
        directory = Path(self.temp.name) / "round"
        directory.mkdir()
        original = owner.client.acquire_claim
        received = []
        def lose(*args, **kwargs):
            received.append(original(*args, **kwargs))
            raise ExchangeError(503, "connection_failed")
        with patch.object(owner.client, "acquire_claim", side_effect=lose):
            with self.assertRaises(ExchangeError):
                owner.claim_submissions(self.space, state_dir=directory)
        saved = json.loads((directory / "exchange-claim.json").read_text())
        self.assertIn("acquisition_key", saved)
        restarted = self.store("owner")
        restarted.resolve_reference(self.space)
        restarted.claim_submissions(self.space, state_dir=directory)
        self.assertEqual(restarted.claim["id"], received[0]["id"])
        self.assertEqual(restarted.claim["fence"], received[0]["fence"])

    def test_profile_compositions_and_metadata_patch_validation(self):
        rules = self.client.get(self.prefix, headers=self.headers).json()["rules"]
        bad = json.loads(json.dumps(rules))
        bad["model.global"]["metadata_schema"] = {"allOf": [{"type": "object", "additionalProperties": False}]}
        self.assertEqual(self.code(self.set_rules(bad)), "profile_kind_incompatible")
        bad["model.global"]["metadata_schema"] = {"properties": {"hf2l_files": {"type": "object", "maxProperties": 0}}}
        self.assertEqual(self.code(self.set_rules(bad)), "profile_kind_incompatible")
        bad = json.loads(json.dumps(rules))
        bad["message"]["metadata_schema"] = {"type": "nonsense"}
        self.assertEqual(self.code(self.set_rules(bad)), "invalid_metadata_schema")
        rules["message"]["metadata_schema"] = {"type": "object", "required": ["count"], "properties": {"count": {"type": "integer"}}}
        self.assertEqual(self.set_rules(rules).status_code, 200)
        record = self.create(metadata={"count": 1}).json()
        route = self.prefix + "/records/" + record["id"]
        stale = self.client.patch(route, headers={**self.auth("alice"), "If-Match": '"99"'}, json={"metadata": {"count": 2}})
        self.assertEqual(self.code(stale), "record_changed")
        invalid = self.client.patch(route, headers={**self.auth("alice"), "If-Match": '"1"'}, json={"metadata": {"count": "bad"}})
        self.assertEqual(self.code(invalid), "metadata_schema_mismatch")
        good = self.client.patch(route, headers={**self.auth("alice"), "If-Match": '"1"'}, json={"metadata": {"count": 2}})
        self.assertEqual(good.json()["generation"], 2)
        self.assertEqual(self.client.post(route + ":publish", headers=self.auth("alice")).status_code, 200)

    def test_authentication_algorithms_issuer_type_and_jwks_outage(self):
        for headers in (self.auth("alice", iss="https://wrong.test"), self.auth("alice", aud="wrong"), self.auth("alice", exp=1)):
            response = self.client.get(self.prefix + "/me", headers=headers)
            self.assertEqual((response.status_code, self.code(response), response.headers["WWW-Authenticate"]), (401, "invalid_access_token", "Bearer"))
        claims = {"iss": self.settings.issuer, "aud": self.settings.audience, "sub": "alice", "iat": int(time.time()),
                  "exp": int(time.time()) + 60, "scope": "exchange"}
        for algorithm, key, typ in (("HS256", "symmetric-key-that-is-not-an-rsa-key", "at+jwt"), ("RS256", self.private_key, "JWT")):
            token = jwt.encode(claims, key, algorithm=algorithm, headers={"typ": typ})
            response = self.client.get(self.prefix + "/me", headers={"Authorization": "Bearer " + token})
            self.assertEqual(self.code(response), "invalid_access_token")
        jwks = Mock()
        jwks.get_signing_key_from_jwt.return_value = SimpleNamespace(key=self.private_key.public_key())
        with patch.object(self.service.auth, "jwks", jwks):
            self.assertEqual(self.client.get(self.prefix + "/me", headers=self.auth("alice")).status_code, 200)
            jwks.get_signing_key_from_jwt.side_effect = jwt.PyJWKClientConnectionError("unavailable")
            unavailable = self.client.get(self.prefix + "/me", headers=self.auth("alice"))
            self.assertEqual((unavailable.status_code, self.code(unavailable)), (503, "identity_provider_unavailable"))
            self.assertEqual(unavailable.headers["Retry-After"], "3")

    def test_authorization_matrix_and_database_cross_space_constraint(self):
        self.member("reader", ["reader"])
        self.member("admin", ["admin"])
        base = self.ready()
        record = self.create("alice", "training.update", base["id"], data=b"secret").json()
        blob_id = self.upload(record, b"secret")
        tick(self.service)
        route = self.prefix + "/records/" + record["id"]
        self.assertEqual(self.client.post(route + ":publish", headers=self.auth("alice")).status_code, 200)
        download = route + f"/blobs/{blob_id}:download"
        for identity in ("reader", "admin", "bob"):
            self.assertEqual(self.code(self.client.get(route, headers=self.auth(identity))), "record_not_found")
            self.assertEqual(self.code(self.client.post(download, headers=self.auth(identity))), "record_not_found")
        self.assertEqual(self.code(self.create("reader")), "record_kind_not_allowed")
        self.assertEqual(self.client.get(self.prefix + "/records", headers=self.auth("admin")).json()["items"], [])
        self.assertEqual(self.client.post(download, headers=self.headers).status_code, 200)
        other = self.client.post("/v1/spaces", headers={**self.headers, "Idempotency-Key": "second-space"}, json={"name": "other", "tenant": "label"}).json()["id"]
        cross = self.client.post(f"/v1/spaces/{other}/records/{record['id']}/blobs/{blob_id}:download", headers=self.headers)
        self.assertEqual(self.code(cross), "record_not_found")
        self.assertEqual(self.code(self.client.get(f"/v1/spaces/{other}/uploads/{blob_id}", headers=self.headers)), "upload_not_found")
        with self.assertRaises(IntegrityError), self.service.sessions.begin() as session:
            session.add(Ref(space_id=other, name="invalid", record_id=record["id"]))
            session.flush()
        self.member("alice", [])
        self.assertEqual(self.code(self.client.post(download, headers=self.auth("alice"))), "space_not_found")

    def test_event_visibility_paging_and_retention_floor(self):
        base = self.ready()
        private = self.ready("alice", "training.update", base["id"])
        public = [self.ready("alice", "message") for _ in range(3)]
        def collect(subject):
            cursor, found = 0, []
            for _ in range(10):
                page = self.client.get(self.prefix + "/events", params={"cursor": cursor, "limit": 1}, headers=self.auth(subject)).json()
                found.extend(row["record_id"] for row in page["items"])
                if page["next_cursor"] == cursor:
                    return found
                cursor = page["next_cursor"]
            self.fail("event cursor did not finish")
        self.assertNotIn(private["id"], collect("bob"))
        self.assertIn(private["id"], collect("owner"))
        self.assertTrue(set(r["id"] for r in public) <= set(collect("bob")))
        with self.service.sessions.begin() as session:
            for row in session.scalars(select(Event)):
                row.created_at = 1
            for row in session.scalars(select(Operation)):
                row.created_at = 1
        prune(self.service, 1000)
        response = self.client.get(self.prefix + "/events?cursor=1", headers=self.headers)
        self.assertEqual((response.status_code, self.code(response)), (410, "event_cursor_expired"))
        with self.service.sessions.begin() as session:
            self.assertEqual(session.query(Operation).count(), 0)

    def test_read_queries_are_batched_and_postgres_reads_do_not_wait_for_writer(self):
        for _ in range(8):
            self.ready("alice", "message")
        queries = []
        def observe(conn, cursor, statement, parameters, context, many):
            queries.append(statement)
        event.listen(self.service.engine, "before_cursor_execute", observe)
        try:
            response = self.client.get(self.prefix + "/records", headers=self.headers)
        finally:
            event.remove(self.service.engine, "before_cursor_execute", observe)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(sum("FROM exchange_blobs" in query for query in queries), 1)
        self.assertFalse(any("FOR UPDATE" in query for query in queries))
        if self.service.engine.dialect.name == "postgresql":
            done = threading.Event()
            with self.service.sessions.begin() as session:
                session.scalar(select(Space).where(Space.id == self.space).with_for_update())
                thread = threading.Thread(target=lambda: (self.client.get(self.prefix + "/me", headers=self.headers), done.set()))
                thread.start()
                try:
                    self.assertTrue(done.wait(3), "GET /me blocked on the writer's space lock")
                finally:
                    # Transaction exit releases the lock even when the regression assertion fails.
                    pass
            thread.join(5)

    def test_tag_failure_reports_published_revision_and_explicit_reference(self):
        base = self.ready()
        self.ref(base)
        owner = self.store("owner")
        reference = ResolvedReference(base["id"], 1)
        folder = Path(self.temp.name) / "aggregate"
        folder.mkdir()
        original = owner.client.set_ref
        def racing(space, name, record, **kwargs):
            if name == "round-1":
                raise ExchangeError(412, "reference_changed")
            return original(space, name, record, **kwargs)
        with patch.object(owner.client, "set_ref", side_effect=racing):
            result = owner.publish_aggregate(self.space, folder, [], expected_base=base["id"], next_round=1,
                                             tag="round-1", reference=reference)
        self.assertFalse(result.tag_created)
        self.assertIn(result.revision, result.warnings[0])
        self.assertEqual(owner.client.resolve(self.space)["record_id"], result.revision)
        owner.client.set_ref(self.space, "existing", result.revision)
        with patch.object(owner, "_publish") as upload, self.assertRaisesRegex(ValueError, "Tag already exists"):
            owner.publish_aggregate(self.space, folder, [], expected_base=result.revision, next_round=2,
                                    tag="existing", reference=ResolvedReference(result.revision, 2))
        upload.assert_not_called()

    def test_separate_verification_budget_and_initialization_wait(self):
        path = Path(self.temp.name) / "data"
        path.write_bytes(b"payload")
        sdk = self.sdk("alice")
        original_upload = sdk._upload
        def slow(space, record_id, attachment, path, deadline):
            time.sleep(0.03)  # Longer than the verification-only budget; transfers have their own budget.
            original_upload(space, record_id, attachment, path, deadline)
        original_request = sdk.request
        pending = [True]
        def request(method, route, **kwargs):
            if route.endswith("/uploads") and pending[0]:
                pending[0] = False
                raise ExchangeError(409, "upload_initialization_pending")
            if route.endswith(":publish"):
                tick(self.service)
            return original_request(method, route, **kwargs)
        with patch.object(sdk, "_upload", side_effect=slow), patch.object(sdk, "request", side_effect=request):
            record = sdk.put_record(self.space, kind="message", metadata={}, files={"data": path}, wait_seconds=0.01)
        self.assertEqual(record["state"], "ready")
        self.assertFalse(pending[0])

    def test_interrupted_download_preserves_partial_and_integrity_failure_removes_it(self):
        data = b"x" * (2 * 1024 * 1024)
        record = self.create(data=data).json()
        blob_id = self.upload(record, data)
        tick(self.service)
        self.client.post(self.prefix + f"/records/{record['id']}:publish", headers=self.auth("alice"))
        calls = []
        class Broken(httpx.SyncByteStream):
            def __iter__(self):
                yield data[:1024 * 1024]
                raise httpx.ReadError("interrupted")
        def interrupt(request):
            calls.append(request.headers.get("Range"))
            if len(calls) == 1:
                return httpx.Response(200, stream=Broken())
            raise httpx.ConnectError("unavailable", request=request)
        sdk = self.sdk("alice", httpx.Client(transport=httpx.MockTransport(interrupt)))
        target = Path(self.temp.name) / "download.bin"
        attachment = record["attachments"][0]
        partial = target.with_name(target.name + "." + blob_id + ".part")
        with self.assertRaises(ExchangeError) as exc:
            sdk.download_attachment(self.space, record["id"], attachment, target)
        self.assertEqual(exc.exception.code, "download_incomplete")
        self.assertEqual(partial.stat().st_size, 1024 * 1024)
        self.assertEqual(calls[1:], ["bytes=1048576-", "bytes=1048576-"])
        self.sdk("alice").download_attachment(self.space, record["id"], attachment, target)
        self.assertEqual(target.read_bytes(), data)
        target.unlink()
        partial.write_bytes(b"z" * len(data))
        with self.assertRaises(ExchangeError) as exc:
            self.sdk("alice").download_attachment(self.space, record["id"], attachment, target)
        self.assertEqual(exc.exception.code, "download_integrity_failed")
        self.assertFalse(partial.exists())

    def test_tls_readiness_docs_and_required_headers(self):
        for url in ("http://storage.example", "http://127.0.0.1:9000"):
            with self.assertRaises(ValueError):
                replace(self.settings, s3_endpoint=url, allow_local_http=False)
        with self.assertRaises(ValueError):
            replace(self.settings, s3_endpoint="http://storage.example", allow_local_http=True)
        sdk = self.sdk("alice")
        grant = {"url": "http://storage.example/file"}
        with patch.object(sdk, "request", return_value=grant), patch.object(sdk.transfer, "stream") as transfer:
            with self.assertRaises(ValueError):
                sdk.download_attachment(self.space, "rec", {"id": "blob", "size_bytes": 1, "sha256": "0" * 64}, Path(self.temp.name) / "file")
        transfer.assert_not_called()
        self.assertEqual(self.client.get("/docs").status_code, 404)
        self.assertEqual(self.client.get("/openapi.json").status_code, 404)
        with patch.object(self.storage, "check", side_effect=StorageMisconfigured("versioning off")):
            self.assertEqual(self.client.get("/health").status_code, 200)
            response = self.client.get("/ready")
            self.assertEqual((response.status_code, self.code(response)), (503, "storage_misconfigured"))
        with fixtures.TestClient(create_app(replace(self.settings, docs_enabled=True), self.storage)) as client:
            schema = client.get("/openapi.json").json()
            for path in ("/v1/spaces", "/v1/spaces/{space_id}/claims", "/v1/spaces/{space_id}/records"):
                header = next(p for p in schema["paths"][path]["post"]["parameters"] if p["name"] == "idempotency-key")
                self.assertTrue(header["required"])
                self.assertEqual((header["schema"]["minLength"], header["schema"]["maxLength"]), (1, 128))
        configured = S3BlobStore(replace(self.settings, s3_public_endpoint="https://download.example"), self.s3)
        # Signing uses the public endpoint, while service-side operations keep their internal client.
        fake = SimpleNamespace(key="spaces/x/blobs/y", upload_id="u", size=3, part_bytes=self.settings.part_bytes)
        self.assertEqual(urlsplit(configured.authorize(fake, [1])[0]["url"]).hostname, "download.example")
        self.assertIs(configured.client, self.s3)

    def test_environment_configuration_and_bounded_worker_backoff(self):
        from hf2l.exchange.cli import main
        pem = Path(self.temp.name) / "public.pem"
        pem.write_text(self.settings.public_key)
        env = {"EXCHANGE_DATABASE_URL": self.settings.database_url, "EXCHANGE_ISSUER": self.settings.issuer,
               "EXCHANGE_AUDIENCE": "exchange", "EXCHANGE_S3_BUCKET": self.settings.bucket, "EXCHANGE_ADMIN_SUBJECT": "owner",
               "EXCHANGE_PUBLIC_KEY_FILE": str(pem), "EXCHANGE_ALLOW_LOCAL_HTTP": "true", "EXCHANGE_S3_ENDPOINT": self.endpoint,
               "EXCHANGE_POOL_SIZE": "7", "EXCHANGE_POOL_OVERFLOW": "2", "EXCHANGE_POOL_TIMEOUT": "2.5",
               "EXCHANGE_JWKS_TIMEOUT": "1.5", "EXCHANGE_DOCS_ENABLED": "false", "EXCHANGE_WORKER_CONCURRENCY": "2"}
        with patch.dict(os.environ, env, clear=True):
            settings = Settings.from_env()
            self.assertEqual((settings.pool_size, settings.pool_overflow, settings.pool_timeout, settings.jwks_timeout), (7, 2, 2.5, 1.5))
            self.assertFalse(settings.docs_enabled)
            with patch.dict(os.environ, {"EXCHANGE_DOCS_ENABLED": "typo"}):
                with self.assertRaises(ValueError):
                    Settings.from_env()
        waits = []
        def sleep(seconds):
            waits.append(seconds)
            if len(waits) == 1030:
                raise KeyboardInterrupt()
        with patch("sys.argv", ["exchange", "worker"]), patch("hf2l.exchange.config.Settings.from_env", return_value=self.settings), \
             patch("hf2l.exchange.api.Service", return_value=self.service), patch("hf2l.exchange.worker.tick", side_effect=RuntimeError()), \
             patch("hf2l.exchange.cli.log"), patch("hf2l.exchange.cli.time.sleep", side_effect=sleep):
            with self.assertRaises(KeyboardInterrupt):
                main()
        self.assertEqual(max(waits), 300)

    def test_explicit_v1_migration_is_repeatable_and_accounts_existing_garbage(self):
        record = self.create(data=b"old").json()
        self.client.delete(self.prefix + "/records/" + record["id"], headers=self.auth("alice"))
        with self.service.engine.begin() as connection:
            connection.execute(text("DROP INDEX ix_exchange_operations_created_at"))
            for table, column in (("exchange_spaces", "reclaiming"), ("exchange_spaces", "event_floor"),
                                  ("exchange_blobs", "worker_token"), ("exchange_members", "subject"),
                                  ("exchange_operations", "created_at")):
                connection.execute(text(f"ALTER TABLE {table} DROP COLUMN {column}"))
        with self.assertRaisesRegex(ValueError, "migrate-db"):
            initialize(self.service.engine)
        migrate(self.service.engine)
        migrate(self.service.engine)
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(Space, self.space).reclaiming, 3)
            self.assertIsNone(session.get(Blob, record["attachments"][0]["id"]).worker_token)
            self.assertGreater(session.scalar(select(Operation.created_at).limit(1)), 0)


# Share fixture setup and helpers without inheriting/re-running every test in ExchangeTests.
for _name, _method in fixtures.ExchangeTests.__dict__.items():
    if not _name.startswith("test_") and not _name.startswith("__"):
        setattr(HardeningTests, _name, _method)
