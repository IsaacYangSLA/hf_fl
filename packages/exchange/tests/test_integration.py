"""End-to-end exchange contracts against real HTTP blob transfers.

Moto runs by default. EXCHANGE_TEST_S3_ENDPOINT exercises the same contracts
against the configured provider; its version/signature evidence is distinct.
"""
from __future__ import annotations

from hashlib import sha256
from types import SimpleNamespace
import time
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import httpx

from hf2l_exchange.storage import S3BlobStore, StorageFailure, StoredObject
from support import ExchangeTestCase, ResourceTestCase


class S3ConformanceTests(ResourceTestCase):
    def setUp(self):
        super().setUp()
        self.storage = S3BlobStore(SimpleNamespace(
            bucket=self.bucket, endpoint=self.endpoint, public_endpoint=None,
            region="us-east-1", allow_local_http=True), client=self.s3)

    def test_multipart_grants_resume_completion_and_immutable_download(self):
        """An overwritten key must not change the record's immutable bytes."""
        self.storage.check()
        size = 5 * 1024 * 1024
        content = b"a" * size + b"remaining payload"
        digest = sha256(content).hexdigest()
        handle = self.storage.start("attempts/first/blob")
        for number, part in enumerate((content[:size], content[size:]), 1):
            grant = self.storage.upload_grant(handle, number, len(part), time.time() + 300, 300)
            self.assertNotIn("Authorization", grant.headers)
            response = httpx.put(grant.url, headers=grant.headers, content=part, timeout=30)
            self.assertEqual(response.status_code, 200, response.text)
            confirmed = self.storage.parts(handle)
            self.assertEqual([p.number for p in confirmed], list(range(1, number + 1)))
        stored = self.storage.complete(handle, len(content), size)
        # Retrying after the provider completed but the response was lost returns
        # the exact object identity, even though the upload handle no longer exists.
        self.assertEqual(self.storage.complete(handle, len(content), size), stored)
        verified = self.storage.verify(stored, len(content), digest)
        self.assertEqual((verified.size, verified.sha256), (len(content), digest))
        self.s3.put_object(Bucket=self.bucket, Key=stored.key, Body=b"new untrusted version")
        grant = self.storage.download_grant(stored, time.time() + 300, 300)
        response = httpx.get(grant.url, timeout=30)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.content, content)
        self.assertIn(stored.version, parse_qs(urlsplit(grant.url).query).get("versionId", []))

    def test_cleanup_is_scoped_to_attempt_and_verification_rejects_bad_digest(self):
        first = self.storage.start("attempts/old")
        successor = self.storage.start("attempts/old-successor")
        self.s3.upload_part(Bucket=self.bucket, Key=first.key, UploadId=first.id, PartNumber=1, Body=b"data")
        stored = self.storage.complete(first, 4, 5 * 1024 * 1024)
        with self.assertRaises(StorageFailure) as mismatch:
            self.storage.verify(stored, 4, sha256(b"evil").hexdigest())
        self.assertEqual(mismatch.exception.code, "verification_failed")
        self.storage.cleanup(first.key)
        self.storage.cleanup(first.key)
        self.assertEqual(self.storage.parts(successor), [])
        with self.assertRaises(StorageFailure) as missing:
            self.storage.verify(stored, 4, sha256(b"data").hexdigest())
        self.assertEqual(missing.exception.code, "storage_missing")

    def test_live_provider_rejects_modified_download_signature(self):
        if not self.live_storage:
            self.skipTest("Moto does not enforce S3 presigned signatures")
        result = self.s3.put_object(Bucket=self.bucket, Key="signature/check", Body=b"protected")
        grant = self.storage.download_grant(
            StoredObject("signature/check", result["VersionId"]), time.time() + 300, 300)
        parsed = urlsplit(grant.url)
        query = parse_qs(parsed.query)
        # Signature Version 4 is required by the storage adapter.
        self.assertIn("X-Amz-Signature", query)
        query["X-Amz-Signature"] = ["0" * 64]
        tampered = urlunsplit(parsed._replace(query=urlencode(query, doseq=True)))
        response = httpx.get(tampered, timeout=30)
        self.assertEqual(response.status_code, 403, response.text)


class GenericExchangeIntegrationTests(ExchangeTestCase):
    def test_arbitrary_document_types_filenames_and_named_references(self):
        content = b"a" * (5 * 1024 * 1024) + b"generic document payload"
        descriptor = {"path": "round.json", "size": len(content), "sha256": sha256(content).hexdigest()}
        created = self.create(metadata={"title": "Manual", "hf2l_files": "ordinary application data"},
                              attachments=[descriptor])
        self.assertEqual(created.status_code, 201, created.text)
        record = self.upload(created.json(), content)
        published = self.request("POST", self.prefix + f"/records/{record['id']}/publish", "alice")
        self.assertEqual(published.status_code, 200, published.text)
        pointer = self.reference(published.json(), name="manual-latest")
        self.assertEqual(pointer.status_code, 200, pointer.text)
        resolved = self.request("GET", self.prefix + "/refs/manual-latest", "bob")
        self.assertEqual(resolved.json()["record_id"], record["id"])
        download = self.request("GET", self.prefix +
            f"/records/{record['id']}/attachments/{record['attachments'][0]['id']}/download", "bob")
        self.assertEqual(download.status_code, 200, download.text)
        self.assertEqual(httpx.get(download.json()["url"], timeout=30).content, content)
        self.assertEqual([t["kind"] for t in self.request("GET", self.prefix + "/types").json()["items"]], ["document"])

    def test_schema_revision_is_immutable_and_draft_keeps_original_revision(self):
        first = self.register_type("contract", {"type": "object", "required": ["title"],
            "properties": {"title": {"type": "string"}}, "additionalProperties": False})
        draft = self.create(kind="contract", revision=first, metadata={"title": "v1"}).json()
        second = self.register_type("contract", {"type": "object", "required": ["title", "category"],
            "properties": {"title": {"type": "string"}, "category": {"type": "string"}}})
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(second["revision"], first["revision"] + 1)
        published = self.request("POST", self.prefix + f"/records/{draft['id']}/publish", "alice")
        self.assertEqual(published.status_code, 200, published.text)
        self.assertEqual(published.json()["schema_revision_id"], first["id"])
        rejected = self.create(kind="contract", revision=second, metadata={"title": "v2"})
        self.assertEqual(self.code(rejected), "metadata_schema_mismatch")
        old_revision = self.request("GET", self.prefix + f"/types/contract/revisions/{first['revision']}")
        self.assertEqual(old_revision.status_code, 200, old_revision.text)
        self.assertEqual(old_revision.json()["schema"], first["schema"])
        immutable = self.request("PATCH", self.prefix + f"/records/{draft['id']}", "alice",
            headers={"If-Match": published.headers.get("ETag", '\"2\"')}, json={"metadata": {"title": "edited"}})
        self.assertEqual(immutable.status_code, 409, immutable.text)

    def test_roles_visibility_revocation_and_cross_space(self):
        private_type = self.register_type("private-document", visibility="private")
        private = self.ready("alice", kind="private-document", revision=private_type)
        shared = self.ready("alice", metadata={"visibility": "shared"})
        for subject in ("bob", "administrator"):
            self.assertEqual(self.request("GET", self.prefix + f"/records/{private['id']}", subject).status_code, 404)
        self.assertEqual(self.request("GET", self.prefix + f"/records/{private['id']}", "publisher").status_code, 200)
        # Administration alone must not confer content access, even for shared records.
        self.assertEqual(self.request("GET", self.prefix + f"/records/{shared['id']}", "administrator").status_code, 404)
        listing = self.request("GET", self.prefix + "/records", "bob").json()["items"]
        self.assertEqual([record["id"] for record in listing], [shared["id"]])
        feed = self.request("GET", self.prefix + "/events", "bob").json()["items"]
        self.assertNotIn(private["id"], [event.get("record_id") for event in feed])
        hidden_ref = self.reference(private)
        self.assertEqual(hidden_ref.status_code, 409, hidden_ref.text)
        other = self.new_space("other")
        cross = self.request("GET", f"/v2/spaces/{other['id']}/records/{shared['id']}")
        self.assertEqual(cross.status_code, 404)
        self.member("alice", [])
        self.assertEqual(self.request("GET", self.prefix + f"/records/{private['id']}", "alice").status_code, 404)
        self.assertEqual(self.request("GET", self.prefix + "/events", "alice").status_code, 404)
        self.assertEqual(self.create("alice").status_code, 404)
        # Administrative cleanup remains permitted without content-reading rights.
        cancelled = self.request("DELETE", self.prefix + f"/records/{private['id']}", "administrator")
        self.assertEqual(cancelled.status_code, 200, cancelled.text)
        self.assertEqual(set(cancelled.json()), {"id", "state"})

    def test_current_policy_rechecked_at_publication_without_retargeting_schema(self):
        draft = self.create().json()
        restricted = self.request("PUT", self.prefix + "/policies/document",
            json={"publish_roles": ["publisher"], "visibility": "private"})
        self.assertEqual(restricted.status_code, 200, restricted.text)
        denied = self.request("POST", self.prefix + f"/records/{draft['id']}/publish", "alice")
        self.assertEqual(denied.status_code, 403, denied.text)
        self.member("alice", ["publisher"])
        published = self.request("POST", self.prefix + f"/records/{draft['id']}/publish", "alice")
        self.assertEqual(published.status_code, 200, published.text)
        self.assertFalse(published.json()["shared"])
        self.assertEqual(published.json()["schema_revision_id"], draft["schema_revision_id"])

    def test_coordination_keys_freeze_inputs_fence_stale_attempts_and_replay_completion(self):
        from hf2l_exchange.models import Coordination
        base = self.ready("publisher")
        reference = self.reference(base).json()
        source = self.ready("alice")
        key = "same-job-retry"
        first = self.acquire(reference, [source], key=key)
        self.assertEqual(first.status_code, 201, first.text)
        first = first.json()
        replay = self.acquire(reference, [source], key=key)
        self.assertEqual(replay.json()["id"], first["id"])
        other_job = self.acquire(reference, [source], key="same-principal-other-job")
        self.assertEqual(self.code(other_job), "acquisition_busy")
        cannot_withdraw = self.request("DELETE", self.prefix + f"/records/{source['id']}", "alice")
        self.assertEqual(self.code(cannot_withdraw), "record_in_active_acquisition")
        result = self.ready("publisher", metadata={"derived_from": source["id"]})
        with self.service.sessions.begin() as session:
            session.get(Coordination, first["id"]).lease_until = 0
        second = self.acquire(reference, [source], key="takeover").json()
        self.assertGreater(second["fence"], first["fence"])
        stale = self.complete(first, result)
        self.assertEqual(self.code(stale), "acquisition_not_active")
        completed = self.complete(second, result, key="result-response-lost")
        self.assertEqual(completed.status_code, 200, completed.text)
        self.assertEqual(completed.json()["state"], "completed")
        repeated = self.complete(second, result, key="fresh-completion-retry")
        self.assertEqual(repeated.json(), completed.json())
        updated = self.request("GET", self.prefix + "/refs/main", "bob").json()
        self.assertEqual(updated["record_id"], result["id"])
        self.assertEqual(int(updated["token"]), int(reference["token"]) + 1)
        outdated = self.reference(base, token=reference["token"])
        self.assertEqual(outdated.status_code, 412, outdated.text)

    def test_metadata_and_count_budgets_include_cancelled_until_explicit_purge(self):
        limited = self.new_space("count-limited", quota_records=1, quota_metadata_bytes=32)
        revision = self.register_type("item", space=limited["id"])
        self.member("alice", ["contributor"], space=limited["id"])
        created = self.create(kind="item", revision=revision, space=limited["id"], metadata={"x": 1})
        self.assertEqual(created.status_code, 201, created.text)
        record = created.json()
        self.assertEqual(self.code(self.create(kind="item", revision=revision, space=limited["id"])), "metadata_quota_exceeded")
        route = f"/v2/spaces/{limited['id']}/records/{record['id']}"
        self.assertEqual(self.request("DELETE", route, "alice").status_code, 200)
        self.assertEqual(self.code(self.create(kind="item", revision=revision, space=limited["id"])), "metadata_quota_exceeded")
        self.assertEqual(self.request("POST", route + "/purge", "alice").status_code, 403)
        purge = self.request("POST", route + "/purge")
        self.assertEqual(purge.status_code, 200, purge.text)
        self.assertEqual(self.create(kind="item", revision=revision, space=limited["id"]).status_code, 201)
        bytes_limited = self.new_space("bytes-limited", quota_records=10, quota_metadata_bytes=10)
        revision = self.register_type("item", space=bytes_limited["id"])
        too_large = self.create("owner", kind="item", revision=revision, space=bytes_limited["id"], metadata={"long": "value"})
        self.assertEqual(self.code(too_large), "metadata_quota_exceeded")
        status = self.request("GET", f"/v2/spaces/{bytes_limited['id']}").json()
        self.assertEqual((status["record_count"], status["metadata_bytes"]), (0, 0))
        self.member("administrator", ["admin"], space=bytes_limited["id"])
        self.member("bob", ["reader"], space=bytes_limited["id"])
        limit_path = f"/v2/spaces/{bytes_limited['id']}"
        self.assertEqual(self.request("PATCH", limit_path, "bob", json={"quota_metadata_bytes": 64}).status_code, 403)
        raised = self.request("PATCH", limit_path, "administrator", json={"quota_metadata_bytes": 64})
        self.assertEqual(raised.status_code, 200, raised.text)
        self.assertEqual(raised.json()["quota_metadata_bytes"], 64)
        admitted = self.create("owner", kind="item", revision=revision, space=bytes_limited["id"], metadata={"long": "value"})
        self.assertEqual(admitted.status_code, 201, admitted.text)
        shrink = self.request("PATCH", limit_path, "administrator", json={"quota_metadata_bytes": 1})
        self.assertEqual(self.code(shrink), "quota_below_current_usage")

    def test_withdrawal_tombstones_survive_purge_and_respect_current_authorization(self):
        shared = self.ready("alice", metadata={"secret": "never include content in a deletion event"})
        private_type = self.register_type("private-note", visibility="private")
        private = self.ready("alice", kind="private-note", revision=private_type, metadata={"secret": "private value"})
        draft = self.create("alice", metadata={"secret": "unpublished draft"}).json()
        for record in (shared, private, draft):
            response = self.request("DELETE", self.prefix + f"/records/{record['id']}", "alice")
            self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.request("GET", self.prefix + f"/records/{shared['id']}", "bob").status_code, 404)
        page = self.request("GET", self.prefix + "/events", "bob")
        self.assertEqual(page.status_code, 200, page.text)
        before = page.json()["items"]
        self.assertEqual([event["record_id"] for event in before], [shared["id"]])
        self.assertEqual(before[0]["payload"], {"state": "withdrawn"})
        self.assertNotIn("secret", str(before))
        for record in (shared, private, draft):
            purge = self.request("POST", self.prefix + f"/records/{record['id']}/purge", "administrator")
            self.assertEqual(purge.status_code, 200, purge.text)
        after = self.request("GET", self.prefix + "/events", "bob").json()["items"]
        self.assertEqual(after, before)
        self.request("PUT", self.prefix + "/policies/document",
                     json={"publish_roles": ["contributor", "publisher"], "visibility": "private"})
        self.assertEqual(self.request("GET", self.prefix + "/events", "bob").json()["items"], [])
        publisher_feed = self.request("GET", self.prefix + "/events", "publisher").json()["items"]
        self.assertEqual({event["record_id"] for event in publisher_feed}, {shared["id"], private["id"]})
        self.assertTrue(all(event["payload"] == {"state": "withdrawn"} for event in publisher_feed))
        self.member("bob", [])
        self.assertEqual(self.request("GET", self.prefix + "/events", "bob").status_code, 404)

    def test_feed_pagination_filters_before_limit_and_expired_cursor_is_explicit(self):
        from hf2l_exchange.models import Event, Space
        from hf2l_exchange.worker import prune
        hidden_revision = self.register_type("hidden", visibility="private")
        for _ in range(3):
            self.ready("alice", kind="hidden", revision=hidden_revision)
        visible = self.ready("alice")
        page = self.request("GET", self.prefix + "/events?limit=1", "bob")
        self.assertEqual(page.status_code, 200, page.text)
        self.assertEqual(page.json()["items"][0]["record_id"], visible["id"])
        with self.service.sessions.begin() as session:
            for event in session.query(Event).filter(Event.space_id == self.space["id"]).all():
                event.created_at = 1
        prune(self.transfers, 1000)
        expired = self.request("GET", self.prefix + "/events?after=0", "bob")
        self.assertEqual(expired.status_code, 410, expired.text)
        self.assertEqual(self.code(expired), "event_cursor_expired")
        with self.service.sessions.begin() as session:
            floor = session.get(Space, self.space["id"]).event_floor
        self.assertGreater(floor, 0)
        reconciled = self.request("GET", self.prefix + "/records", "bob")
        self.assertIn(visible["id"], [record["id"] for record in reconciled.json()["items"]])
        self.assertEqual(self.request("GET", self.prefix + f"/events?after={floor}", "bob").status_code, 200)


    def test_typed_sdk_upload_download_pagination_and_coordination(self):
        from itertools import islice
        from hf2l_exchange.auth import principal_id
        from hf2l_exchange.client import ExchangeClient
        from hf2l_exchange.worker import tick

        def sdk(subject):
            client = ExchangeClient("http://127.0.0.1", self.auth(subject)["Authorization"].split(" ", 1)[1],
                http=self.client, allow_local_http=True, sleep=lambda _: tick(self.transfers))
            self.addCleanup(client.close)
            return client

        alice, bob, publisher = sdk("alice"), sdk("bob"), sdk("publisher")
        source = self.directory / "source.bin"
        content = b"a" * (5 * 1024 * 1024) + b"last SDK part"
        source.write_bytes(content)
        record = alice.put_record(self.space["id"], kind="document", schema_revision_id=self.revision["id"],
            metadata={"purpose": "non-ML SDK example"}, files={"submission.json": source},
            state_path=self.directory / "upload-state.json", upload_seconds=30, verification_seconds=30)
        self.assertEqual(record.state, "published")
        repeated = alice.put_record(self.space["id"], kind="document", schema_revision_id=self.revision["id"],
            metadata={"purpose": "non-ML SDK example"}, files={"submission.json": source},
            state_path=self.directory / "upload-state.json", upload_seconds=30, verification_seconds=30)
        self.assertEqual(repeated.id, record.id)
        downloaded = bob.download_attachment(self.space["id"], record.id, record.attachments[0], self.directory / "result.bin")
        self.assertEqual(downloaded.read_bytes(), content)
        self.assertEqual(alice.get_membership(self.space["id"]).principal, principal_id(self.issuer, "alice"))
        self.ready("alice")
        self.ready("bob")
        records = list(islice(bob.records(self.space["id"], limit=1), 4))
        self.assertEqual(len(records), 3)
        self.assertEqual(len({item.id for item in records}), 3)
        page, cursor = bob.events(self.space["id"], limit=1)
        next_page, _ = bob.events(self.space["id"], cursor=cursor, limit=1)
        self.assertTrue(page)
        self.assertTrue(next_page)
        self.assertGreater(next_page[0].id, page[0].id)
        reference = publisher.set_ref(self.space["id"], "documents", record.id)
        acquired = publisher.acquire(self.space["id"], reference=reference, input_ids=[record.id],
            state_path=self.directory / "coordination.json")
        result = publisher.put_record(self.space["id"], kind="document", schema_revision_id=self.revision["id"],
            metadata={"summary": "document processed"})
        completed = publisher.complete(self.space["id"], acquired, result.id)
        self.assertEqual(completed.state, "completed")
        self.assertEqual(publisher.resolve(self.space["id"], "documents").record_id, result.id)


    def test_document_example_is_executable_and_recovers_completed_run(self):
        from contextlib import redirect_stdout
        from importlib.util import module_from_spec, spec_from_file_location
        from io import StringIO
        from pathlib import Path
        from unittest.mock import patch
        from hf2l_exchange.client import ExchangeClient
        from hf2l_exchange.worker import tick

        script = Path(__file__).resolve().parents[3] / "examples" / "generic_exchange.py"
        spec = spec_from_file_location("generic_exchange_example", script)
        example = module_from_spec(spec)
        spec.loader.exec_module(example)
        original = self.directory / "report.txt"
        original.write_text("general information exchange", encoding="utf-8")
        work = self.directory / "example-run"

        def connected_client(endpoint, token, **kwargs):
            return ExchangeClient(endpoint, token, http=self.client,
                                  sleep=lambda _: tick(self.transfers), **kwargs)

        arguments = [str(script), "--endpoint", "http://127.0.0.1", "--input", str(original),
                     "--work-dir", str(work), "--allow-local-http"]
        with patch.object(example, "ExchangeClient", connected_client), \
                patch("sys.argv", arguments), \
                patch.dict("os.environ", {"EXCHANGE_TOKEN": self.auth("owner")["Authorization"].split(" ", 1)[1]}):
            first = StringIO()
            with redirect_stdout(first):
                example.main()
            self.assertEqual((work / "processed.txt").read_text(), "GENERAL INFORMATION EXCHANGE")
            self.assertIn("Completed record:", first.getvalue())
            replay = StringIO()
            with redirect_stdout(replay):
                example.main()
            first_id = first.getvalue().split("Completed record: ")[-1].strip()
            self.assertEqual(replay.getvalue().strip(), "Completed record: " + first_id)


if __name__ == "__main__":
    unittest.main()
