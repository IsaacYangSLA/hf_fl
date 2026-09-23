"""SDK recovery and credential-boundary checks using real httpx transports."""
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import httpx

from hf2l_exchange.client import ExchangeClient, ExchangeError
from hf2l_exchange.client_state import StateRepository
from hf2l_exchange.client_types import AttachmentDescriptor, CoordinationHandle, RecordDescriptor, ReferenceSnapshot
from hf2l_exchange.transfer_client import TransferManager, require_tls


def record(**changes):
    value = {"id": "record", "space_id": "space", "kind": "document", "schema_revision_id": "schema",
             "metadata": {"title": "Hello"}, "state": "draft", "version": 1, "shared": True,
             "creator": "alice", "creator_bindings": {}, "attachments": []}
    value.update(changes)
    return value


def handle(**changes):
    value = {"id": "attempt", "reference": "latest", "expected_token": "7", "holder": "alice",
             "fence": 2, "state": "active", "lease_until": time.time() + 60,
             "input_record_ids": ["record"], "result_record_id": None}
    value.update(changes)
    return value


class SDKTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)

    def client(self, handler, *, transfer_handler=None, **options):
        http = httpx.Client(transport=httpx.MockTransport(handler))
        transfer = httpx.Client(transport=httpx.MockTransport(transfer_handler or handler))
        self.addCleanup(http.close)
        self.addCleanup(transfer.close)
        return ExchangeClient("https://api.example", "api-secret", http=http, transfer=transfer,
                              sleep=lambda _: None, **options)

    def test_tls_and_safe_destinations(self):
        for url in ("http://remote.example", "http://localhost", "https://user:pass@example.com", "https://example.com/#secret"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                require_tls(url)
        require_tls("http://127.0.0.1:1234", allow_local_http=True)
        with self.assertRaises(ValueError):
            require_tls("http://192.168.1.2", allow_local_http=True)
        for name in ("../file", "/etc/passwd", "a//b", "a\\b"):
            with self.assertRaises(ValueError):
                ExchangeClient.safe_destination(self.root, name)

    def test_auth_refresh_retry_after_and_error_decode(self):
        seen, delays = [], []
        def handler(request):
            seen.append(request.headers["Authorization"])
            if len(seen) == 1:
                return httpx.Response(401, json={"error": {"code": "token_expired"}})
            if len(seen) == 2:
                return httpx.Response(503, headers={"Retry-After": "0.25"})
            return httpx.Response(200, json={"id": "space", "name": "Documents"})
        client = self.client(handler)
        tokens = iter(("old", "new", "new"))
        client.token, client.sleep = lambda: next(tokens), delays.append
        self.assertEqual(client.get_space("space").name, "Documents")
        self.assertEqual(seen, ["Bearer old", "Bearer new", "Bearer new"])
        self.assertEqual(delays, [0.25])

    def test_type_registration_preserves_profile_defaults_and_explicit_values(self):
        bodies = []
        def control(request):
            body = json.loads(request.content)
            bodies.append(body)
            if body.get("publish_roles") == []:
                return httpx.Response(422, json={"error": {"code": "invalid_publish_roles"}})
            return httpx.Response(201, json={"id": "schema", "kind": "document", "schema": body["schema"]})
        client = self.client(control)
        schema = {"type": "object"}
        client.register_type("space", "document", schema)
        self.assertEqual(bodies[-1], {"schema": schema})
        client.register_type("space", "document", schema, publish_roles=["publisher"], visibility="private")
        self.assertEqual(bodies[-1], {"schema": schema, "publish_roles": ["publisher"], "visibility": "private"})
        with self.assertRaisesRegex(ExchangeError, "invalid_publish_roles"):
            client.register_type("space", "document", schema, publish_roles=[])
        self.assertEqual(bodies[-1]["publish_roles"], [])

    def test_sdk_fedavg_registration_defaults_and_quota_update_through_api(self):
        try:
            from fastapi.testclient import TestClient
            from hf2l_exchange.api import create_app
            from hf2l_exchange.application import Service
            from hf2l_exchange.config import DatabaseSettings, Settings
            from hf2l_exchange.domain import Principal
            from hf2l_exchange.models import KindPolicy
            from hf2l_exchange.migrations import initialize
        except ImportError:
            self.skipTest("Server dependencies are optional for the standalone SDK")
        from types import SimpleNamespace
        settings = Settings(database=DatabaseSettings(url="sqlite:///" + str(self.root / "sdk.db")))
        service = Service(settings)
        self.addCleanup(service.engine.dispose)
        initialize(service.engine)
        authenticator = SimpleNamespace(authenticate=lambda _: Principal("root", "root", True))
        app = create_app(settings, service=service, transfers=object(), authenticator=authenticator)
        with TestClient(app, base_url="https://api.example") as http:
            client = ExchangeClient("https://api.example", "test", http=http)
            self.addCleanup(client.close)
            space = client.create_space("training", profile="fedavg.v1")
            for kind in ("training.update", "model.global"):
                revision = client.register_type(space.id, kind, {"type": "object"})
                self.assertEqual(revision.kind, kind)
            with service.sessions() as session:
                training = session.get(KindPolicy, (space.id, "training.update"))
                global_model = session.get(KindPolicy, (space.id, "model.global"))
                self.assertEqual((training.publish_roles, training.visibility), (["contributor"], "private"))
                self.assertEqual((global_model.publish_roles, global_model.visibility), (["publisher"], "shared"))
            changed = client.update_space_limits(space.id, quota_records=42, principal_quota_bytes=1234)
            self.assertEqual(changed.quota_records, 42)
            self.assertEqual(changed.principal_quota_bytes, 1234)
            self.assertGreater(changed.generation, space.generation)
            with self.assertRaises(ExchangeError) as rejected:
                client.register_type(space.id, "training.update", {"type": "object"}, publish_roles=[])
            self.assertEqual(rejected.exception.status, 422)

    def test_lost_create_response_reuses_durable_operation_key(self):
        state_path = self.root / "upload.json"
        keys, creates = [], []
        def handler(request):
            if request.method == "POST" and request.url.path.endswith("/records"):
                keys.append(request.headers["Idempotency-Key"])
                creates.append(json.loads(request.content))
                self.assertTrue(state_path.exists())
                if len(keys) == 1:
                    raise httpx.ReadError("response lost", request=request)
                return httpx.Response(201, json=record())
            return httpx.Response(200, json=record(state="published") if request.url.path.endswith("/publish") else record())
        client = self.client(handler, retries=1)
        with self.assertRaises(ExchangeError):
            client.put_record("space", kind="document", schema_revision_id="schema", metadata={"title": "Hello"}, state_path=state_path)
        result = client.put_record("space", kind="document", schema_revision_id="schema", metadata={"title": "Hello"}, state_path=state_path)
        self.assertIsInstance(result, RecordDescriptor)
        self.assertEqual(result.state, "published")
        self.assertEqual(keys[0], keys[1])
        self.assertEqual(creates[0], creates[1])
        self.assertEqual(state_path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("api-secret", state_path.read_text())

    def test_failed_draft_reclaims_and_forgets_recovery_state(self):
        calls = []
        def handler(request):
            calls.append(request.method)
            if request.method == "DELETE":
                return httpx.Response(204)
            return httpx.Response(200, json=record(state="failed") if request.method == "GET" else record())
        state = self.root / "state.json"
        with self.assertRaisesRegex(ExchangeError, "blob_verification_failed"):
            self.client(handler).put_record("space", kind="document", schema_revision_id="schema",
                                           metadata={"title": "Hello"}, state_path=state)
        self.assertIn("DELETE", calls)
        self.assertFalse(state.exists())

    def test_state_mismatch_preserves_existing_operation(self):
        repository = StateRepository(self.root / "state.json")
        state = repository.begin("record", ["space", "schema-1"])
        with self.assertRaisesRegex(ExchangeError, "operation_state_mismatch"):
            repository.begin("record", ["space", "schema-2"])
        self.assertEqual(repository.load(), state)

    def test_multipart_resume_skips_confirmed_parts_and_separates_credentials(self):
        content = b"abcdefghijkl"
        source = self.root / "source"
        source.write_bytes(content)
        attachment = AttachmentDescriptor("blob", "source", len(content), hashlib.sha256(content).hexdigest(), "uploading")
        sent = []
        def control(request):
            self.assertEqual(request.headers["Authorization"], "Bearer api-secret")
            suffix = request.url.path.rsplit("/", 1)[-1]
            if suffix == "upload":
                data = {"state": "uploading", "protocol": "s3-multipart-v1", "part_size": 4}
            elif suffix == "parts":
                data = {"parts": [{"number": 1, "size": 4, "etag": "a"}, {"number": 3, "size": 4, "etag": "c"}]}
            elif suffix == "grants":
                number = json.loads(request.content)["numbers"][0]
                data = {"grants": [{"number": number, "size": 4, "url": f"https://blobs.example/{number}", "headers": {}}]}
            else:
                data = {"state": "verifying"}
            return httpx.Response(200, json=data)
        def transfer(request):
            self.assertNotIn("Authorization", request.headers)
            sent.append((request.url.path, request.content))
            return httpx.Response(200)
        client = self.client(control, transfer_handler=transfer)
        client.transfers.upload("space", "record", attachment, source, deadline=time.monotonic() + 10)
        self.assertEqual(sent, [("/2", b"efgh")])

    def test_transfer_rejects_credentials_in_grant(self):
        with self.assertRaises(ValueError):
            TransferManager._headers({"headers": {"Authorization": "Bearer api-secret"}})
        with httpx.Client(headers={"Authorization": "secret"}) as http:
            with self.assertRaises(ValueError):
                TransferManager(None, None, http=http)

    def test_transfer_rejects_inherited_or_mutated_auth_and_cookies(self):
        for options in ({"auth": ("user", "secret")}, {"cookies": {"session": "secret"}}):
            with httpx.Client(**options) as http, self.assertRaises(ValueError):
                TransferManager(None, None, http=http)
        with httpx.Client() as http:
            manager = TransferManager(None, None, http=http)
            http.cookies.set("session", "server-cookie")
            with self.assertRaises(ValueError):
                manager._check_client()

    def test_late_successful_upload_does_not_complete(self):
        clock = [0.0]
        calls = []
        source = self.root / "source"
        source.write_bytes(b"data")
        attachment = AttachmentDescriptor("blob", "source", 4, hashlib.sha256(b"data").hexdigest(), "uploading")
        def control(request):
            name = request.url.path.rsplit("/", 1)[-1]
            calls.append(name)
            self.assertLessEqual(request.extensions["timeout"]["read"], 1)
            if name == "upload":
                result = {"state": "uploading", "protocol": "s3-multipart-v1", "part_size": 4}
            elif name == "parts":
                result = {"parts": []}
            else:
                result = {"grants": [{"number": 1, "size": 4, "url": "https://blobs.example/part", "headers": {}}]}
            return httpx.Response(200, json=result)
        def transfer(request):
            self.assertLessEqual(request.extensions["timeout"]["read"], 1)
            clock[0] = 2
            return httpx.Response(200)
        client = self.client(control, transfer_handler=transfer)
        with patch("hf2l_exchange.client.time.monotonic", side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(ExchangeError, "transfer_deadline_exceeded"):
                client.transfers.upload("space", "record", attachment, source, deadline=1)
        self.assertNotIn("complete", calls)

    def test_control_retry_sleep_is_limited_by_transfer_budget(self):
        clock, sleeps = [0.0], []
        client = self.client(lambda _: httpx.Response(503, headers={"Retry-After": "60"}))
        def sleep(seconds):
            sleeps.append(seconds)
            clock[0] += seconds
        client.sleep = sleep
        with patch("hf2l_exchange.client.time.monotonic", side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(ExchangeError, "request_deadline_exceeded"):
                client.request("GET", "/v2/spaces/space", deadline=1)
        self.assertEqual(sleeps, [1])

    def test_download_resumes_verified_range_and_checks_digest(self):
        content = b"document content"
        attachment = AttachmentDescriptor("blob", "doc.txt", len(content), hashlib.sha256(content).hexdigest(), "verified")
        output = self.root / "doc.txt"
        suffix = hashlib.sha256(b"blob").hexdigest()[:24]
        partial = output.with_name(output.name + "." + suffix + ".part")
        partial.write_bytes(content[:5])
        def control(request):
            return httpx.Response(200, json={"url": "https://blobs.example/exact-version", "headers": {},
                                           "size": len(content), "sha256": attachment.sha256})
        def transfer(request):
            self.assertNotIn("Authorization", request.headers)
            self.assertEqual(request.headers["Range"], "bytes=5-")
            return httpx.Response(206, content=content[5:], headers={"Content-Range": f"bytes 5-{len(content)-1}/{len(content)}"})
        result = self.client(control, transfer_handler=transfer).download_attachment("space", "record", attachment, output)
        self.assertEqual(result.read_bytes(), content)
        self.assertFalse(partial.exists())

    def test_incomplete_download_keeps_partial_for_next_invocation(self):
        content = b"document content"
        attachment = AttachmentDescriptor("blob", "doc.txt", len(content), hashlib.sha256(content).hexdigest(), "verified")
        def control(request):
            return httpx.Response(200, json={"url": "https://blobs.example/object", "headers": {},
                                           "size": len(content), "sha256": attachment.sha256})
        def transfer(request):
            return httpx.Response(200, content=content[:3])
        output = self.root / "doc.txt"
        with self.assertRaisesRegex(ExchangeError, "download_incomplete"):
            self.client(control, transfer_handler=transfer, retries=1).download_attachment("space", "record", attachment, output)
        self.assertEqual(next(self.root.glob("*.part")).read_bytes(), content[:3])
        self.assertFalse(output.exists())

    def test_acquisition_lost_response_and_complete_typed_outcome(self):
        keys = []
        def control(request):
            if request.url.path.endswith("/complete"):
                return httpx.Response(200, json=handle(state="completed", result_record_id="result"))
            keys.append(request.headers["Idempotency-Key"])
            if len(keys) == 1:
                raise httpx.ReadError("response lost", request=request)
            return httpx.Response(200, json=handle())
        client = self.client(control, retries=1)
        state = self.root / "acquire.json"
        snapshot = ReferenceSnapshot("latest", "record", "7")
        with self.assertRaises(ExchangeError):
            client.acquire("space", reference=snapshot, input_ids=["record"], state_path=state)
        acquisition = client.acquire("space", reference=snapshot, input_ids=["record"], state_path=state)
        self.assertEqual(keys[0], keys[1])
        self.assertEqual(acquisition.input_ids, ("record",))
        outcome = client.complete("space", acquisition, "result")
        self.assertIsInstance(outcome, CoordinationHandle)
        self.assertEqual(outcome.result_record_id, "result")

    def test_pagination_uses_after_and_typed_membership(self):
        paths = []
        def control(request):
            paths.append(str(request.url))
            if request.url.path.endswith("/membership"):
                return httpx.Response(200, json={"principal_id": "alice", "roles": ["publisher"], "bindings": {"team": "docs"}})
            if request.url.path.endswith("/events"):
                self.assertEqual(request.url.params["after"], "8")
                return httpx.Response(200, json={"items": [], "next_cursor": 10})
            if "after" not in request.url.params:
                return httpx.Response(200, json={"items": [record(state="published")], "next_cursor": "record"})
            self.assertEqual(request.url.params["after"], "record")
            return httpx.Response(200, json={"items": [], "next_cursor": None})
        client = self.client(control)
        self.assertEqual(len(list(client.records("space"))), 1)
        self.assertEqual(client.events("space", cursor=8), ((), 10))
        self.assertEqual(client.get_membership("space").principal_id, "alice")


if __name__ == "__main__":
    unittest.main()
