"""Managed SDK compartments, resumable streams, and backward compatible controls."""
from copy import deepcopy
import hashlib
from http.server import BaseHTTPRequestHandler
import json
from pathlib import Path
import tempfile
import socketserver
import threading
import time
import unittest
from unittest.mock import patch

import httpx

from hf2l_exchange.client import ExchangeClient
from hf2l_exchange.client_types import AttachmentDescriptor, ExchangeError, WorkloadGrantDescriptor


def descriptor(method="GET", part_number=None, **changes):
    operation = {"space_id": "space", "record_id": "record", "attachment_id": "blob", "method": method}
    if part_number is not None:
        operation["part_number"] = part_number
    return {"protocol": "hf2l-managed-v1", "operation": operation, "headers": {}, **changes}


class ManagedSDKTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.content = b"abcdefghijkl"
        self.file = self.root / "source"
        self.file.write_bytes(self.content)
        self.attachment = AttachmentDescriptor("blob", "source", len(self.content),
                                              hashlib.sha256(self.content).hexdigest(), "uploading")

    def client(self, handler, *, data=None, **options):
        control = httpx.Client(transport=httpx.MockTransport(handler))
        transfer = httpx.Client(transport=httpx.MockTransport(data or handler))
        self.addCleanup(control.close)
        self.addCleanup(transfer.close)
        return ExchangeClient.for_execution("/run/hf2l/proxy.sock", space="space",
            http=control, transfer=transfer, sleep=lambda _: None, **options)

    def upload_control(self, request, grants=None, present=()):
        self.assertEqual(request.url.host, "proxy")
        self.assertNotIn("Authorization", request.headers)
        suffix = request.url.path.rsplit("/", 1)[-1]
        if suffix == "upload":
            value = {"protocol": "hf2l-managed-v1", "state": "uploading", "part_size": 4}
        elif suffix == "parts":
            value = {"parts": [{"number": number, "size": 4} for number in present]}
        elif suffix == "grants":
            number = json.loads(request.content)["numbers"][0]
            value = {"grants": [grants or descriptor("PUT", number, number=number, size=4)]}
        else:
            value = {"protocol": "hf2l-managed-v1", "state": "verifying"}
        return httpx.Response(200, json=value)

    def test_managed_control_requires_explicit_bound_socket_and_no_credentials(self):
        with self.assertRaises(ValueError):
            ExchangeClient("https://example.test", None)
        for endpoint, token, socket, space in (
                ("https://attacker.test", None, "/run/proxy.sock", "space"),
                ("http://proxy", "human-token", "/run/proxy.sock", "space"),
                ("http://proxy", None, "relative.sock", "space"),
                ("http://proxy", None, "/run/proxy.sock", "../space")):
            with self.subTest(endpoint=endpoint, space=space), self.assertRaises(ValueError):
                ExchangeClient(endpoint, token, managed_proxy_uds=socket, managed_space=space)
        socket = self.root / "proxy.sock"
        socket.symlink_to(self.root / "other")
        with self.assertRaises(ValueError):
            ExchangeClient.for_execution(socket, space="space")

    def test_real_unix_socket_transport_ignores_environment_proxy_and_streams_parts(self):
        seen = []
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def do_GET(self):
                seen.append((self.command, self.path, dict(self.headers), b""))
                encoded = json.dumps({"id": "space", "name": "managed"}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def do_PUT(self):
                content = self.rfile.read(int(self.headers["Content-Length"]))
                seen.append((self.command, self.path, dict(self.headers), content))
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
        class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True
        socket = self.root / "proxy.sock"
        server = Server(str(socket), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with patch.dict("os.environ", {"HTTP_PROXY": "http://unreachable.invalid:1", "ALL_PROXY": "http://unreachable.invalid:1"}):
            with ExchangeClient.for_execution(socket, space="space") as client:
                self.assertEqual(client.get_space("space").name, "managed")
                grant = descriptor("PUT", 1, number=1, size=4)
                url = client.transfers._operation_url(grant, "space", "record", "blob", "PUT", 1)
                response = client.transfers.http.put(url, headers={"Content-Length": "4"},
                    content=client.transfers._chunks(self.file, 0, 4), auth=None, follow_redirects=False)
                self.assertEqual(response.status_code, 204)
        self.assertEqual(seen[1][3], b"abcd")
        for _, path, headers, _ in seen:
            self.assertNotIn("Authorization", headers)
            self.assertNotIn("Transfer-Encoding", headers)
            self.assertTrue(path.startswith(("/v2/spaces/space", "/transfers/v1/spaces/space")))

    def test_control_rejects_foreign_space_traversal_urls_and_auth(self):
        seen = []
        client = self.client(lambda request: (seen.append(request), httpx.Response(200, json={}))[1])
        for path in ("/v2/spaces/foreign", "/v2/spaces/space/../foreign",
                     "/v2/spaces/space/%2e%2e/foreign", "/v2/spaces/space?host=attacker",
                     "https://attacker.test/v2/spaces/space", "/v2/spaces/space/%5cforeign"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                client.request("GET", path)
        with self.assertRaises(ValueError):
            client.request("GET", "/v2/spaces/space", headers={"Authorization": "Bearer human"})
        self.assertEqual(seen, [])

    def test_control_rejects_inherited_and_mutated_authentication(self):
        for kwargs in ({"headers": {"Authorization": "human"}}, {"auth": ("a", "b")},
                       {"cookies": {"session": "human"}}):
            with httpx.Client(**kwargs) as http, self.assertRaises(ValueError):
                ExchangeClient.for_execution("/run/proxy.sock", space="space", http=http)
        client = self.client(lambda _: httpx.Response(200, json={}))
        client.http.cookies.set("session", "cookie")
        with self.assertRaises(ValueError):
            client.request("GET", "/v2/spaces/space")

    def test_control_rechecks_cookies_between_retries(self):
        calls = []
        def handler(request):
            calls.append(request)
            return httpx.Response(503, headers={"Set-Cookie": "session=foreign"})
        client = self.client(handler)
        with self.assertRaises(ValueError):
            client.request("GET", "/v2/spaces/space")
        self.assertEqual(len(calls), 1)

    def test_multipart_stream_resume_keeps_tokens_out_of_data_requests(self):
        sent = []
        def data(request):
            self.assertEqual(request.url.host, "proxy")
            self.assertNotIn("Authorization", request.headers)
            self.assertNotIn("Cookie", request.headers)
            self.assertEqual(request.headers["Content-Length"], "4")
            sent.append((request.url.path, request.read()))
            return httpx.Response(200)
        client = self.client(lambda r: self.upload_control(r, present=(1, 3)), data=data)
        client.transfers.upload("space", "record", self.attachment, self.file, deadline=time.monotonic() + 5)
        self.assertEqual(sent, [("/transfers/v1/spaces/space/records/record/attachments/blob/parts/2", b"efgh")])

    def test_foreign_and_redirect_descriptors_never_send_bytes(self):
        valid = descriptor("PUT", 1, number=1, size=4)
        bad = []
        for key in ("space_id", "record_id", "attachment_id", "method"):
            value = deepcopy(valid)
            value["operation"][key] = "foreign"
            bad.append(value)
        value = deepcopy(valid)
        value["operation"]["part_number"] = True
        bad.append(value)
        bad += [{**valid, "url": "https://origin.test/signed-secret"},
                {**valid, "headers": {"Authorization": "Bearer stolen"}},
                {**valid, "protocol": "s3-multipart-v1"}]
        for value in bad:
            with self.subTest(value=value):
                sent = []
                client = self.client(lambda r: self.upload_control(r, grants=value),
                                     data=lambda r: (sent.append(r), httpx.Response(200))[1])
                with self.assertRaises(ExchangeError):
                    client.transfers.upload("space", "record", self.attachment, self.file, deadline=time.monotonic() + 5)
                self.assertEqual(sent, [])

    def test_managed_upload_rejects_http_redirect_without_following(self):
        seen = []
        def data(request):
            seen.append(str(request.url))
            return httpx.Response(307, headers={"Location": "https://foreign.test/stolen"})
        client = self.client(self.upload_control, data=data)
        with self.assertRaises(ExchangeError) as raised:
            client.transfers.upload("space", "record", self.attachment, self.file, deadline=time.monotonic() + 5)
        self.assertEqual(raised.exception.status, 307)
        self.assertEqual(len(seen), 1)
        self.assertIn("http://proxy/transfers/", seen[0])

    def test_upload_denied_grant_is_not_retried_or_completed(self):
        controls, calls = [], []
        def control(request):
            controls.append(request.url.path.rsplit("/", 1)[-1])
            return self.upload_control(request)
        def data(request):
            calls.append(request)
            return httpx.Response(403, json={"error": {"code": "workload_grant_revoked"}})
        client = self.client(control, data=data)
        with self.assertRaisesRegex(ExchangeError, "workload_grant_revoked"):
            client.transfers.upload("space", "record", self.attachment, self.file, deadline=time.monotonic() + 5)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("complete", controls)

    def test_upload_resends_one_part_after_lost_reply(self):
        sent = []
        def data(request):
            sent.append(request.read())
            if len(sent) == 1:
                raise httpx.ReadError("lost reply", request=request)
            return httpx.Response(200)
        client = self.client(lambda r: self.upload_control(r, present=(2, 3)), data=data)
        client.transfers.upload("space", "record", self.attachment, self.file, deadline=time.monotonic() + 5)
        self.assertEqual(sent, [b"abcd", b"abcd"])

    def partial(self, output):
        identity = hashlib.sha256(b"space/record/blob").hexdigest()[:24]
        return output.with_name(output.name + "." + identity + ".part")

    def download_control(self, _):
        return httpx.Response(200, json=descriptor(size=len(self.content), sha256=self.attachment.sha256))

    def test_download_checks_head_and_resumes_range(self):
        output = self.root / "download"
        self.partial(output).write_bytes(self.content[:5])
        seen = []
        def data(request):
            self.assertNotIn("Authorization", request.headers)
            seen.append(request.method)
            if request.method == "HEAD":
                return httpx.Response(200, headers={"Content-Length": str(len(self.content)),
                                                   "X-Content-SHA256": self.attachment.sha256})
            self.assertEqual(request.headers["Range"], "bytes=5-")
            return httpx.Response(206, content=self.content[5:],
                                  headers={"Content-Range": "bytes 5-11/12"})
        client = self.client(self.download_control, data=data)
        client.download_attachment("space", "record", self.attachment, output)
        self.assertEqual(output.read_bytes(), self.content)
        self.assertEqual(seen, ["HEAD", "GET"])
        self.assertFalse(self.partial(output).exists())

    def test_head_denial_prevents_download(self):
        calls = []
        def data(request):
            calls.append(request.method)
            return httpx.Response(403, json={"error": {"code": "workload_certificate_mismatch"}})
        client = self.client(self.download_control, data=data)
        with self.assertRaisesRegex(ExchangeError, "workload_certificate_mismatch"):
            client.download_attachment("space", "record", self.attachment, self.root / "download")
        self.assertEqual(calls, ["HEAD"])

    def test_download_rejects_redirect_origin_and_range_mismatch(self):
        origin = descriptor(size=12, sha256=self.attachment.sha256, url="https://origin.test/object")
        client = self.client(lambda _: httpx.Response(200, json=origin),
                             data=lambda _: self.fail("Origin descriptor must not send a request"))
        with self.assertRaisesRegex(ExchangeError, "invalid_transfer_descriptor"):
            client.download_attachment("space", "record", self.attachment, self.root / "origin")
        for status in (302, 206):
            output = self.root / str(status)
            self.partial(output).write_bytes(self.content[:5])
            def data(request):
                if request.method == "HEAD":
                    return httpx.Response(200, headers={"Content-Length": "12"})
                return httpx.Response(status, headers={"Location": "https://foreign.test",
                                                      "Content-Range": "bytes 0-11/12"}, content=self.content)
            with self.subTest(status=status), self.assertRaises(ExchangeError):
                self.client(self.download_control, data=data).download_attachment("space", "record", self.attachment, output)
            self.assertFalse(output.exists())

    def test_download_integrity_failure_removes_poisoned_partial(self):
        output = self.root / "download"
        def data(request):
            if request.method == "HEAD":
                return httpx.Response(200, headers={"Content-Length": "12"})
            return httpx.Response(200, content=b"x" * 12)
        with self.assertRaisesRegex(ExchangeError, "download_integrity_failed"):
            self.client(self.download_control, data=data).download_attachment("space", "record", self.attachment, output)
        self.assertFalse(output.exists())
        self.assertFalse(self.partial(output).exists())


class WorkloadGrantSDKTests(unittest.TestCase):
    def test_managed_retirement_state_is_typed_and_idempotent(self):
        calls = []
        def handler(request):
            calls.append((request.method, request.url.path))
            result = {"space_id": "space", "job_id": "job", "managed": True, "status": "retired",
                      "retired_at": 5, "cleanup_pending": True, "provenance_retained": True}
            if request.method == "POST":
                self.assertEqual(request.headers["Idempotency-Key"], "retire-key")
                self.assertEqual(json.loads(request.content), {"job_id": "job"})
            return httpx.Response(200, json=result)
        with httpx.Client(transport=httpx.MockTransport(handler)) as http:
            with ExchangeClient("https://exchange.test", "provisioner", http=http) as client:
                state = client.retire_managed_space("space", job_id="job", idempotency_key="retire-key")
                self.assertEqual((state.status, state.retired_at), ("retired", 5))
                self.assertTrue(state.cleanup_pending)
                self.assertTrue(client.get_managed_space("space").provenance_retained)
        self.assertEqual(calls, [("POST", "/v2/spaces/space/managed/retire"),
                                 ("GET", "/v2/spaces/space/managed")])

    def test_additive_admin_calls_are_typed_and_use_durable_keys(self):
        grant = {"grant_id": "grant", "principal_id": "owner", "subject": "stable-subject",
                 "space_id": "space", "job_id": "job", "attempt_id": "attempt", "component_id": "owner",
                 "epoch": 2, "expires_at": 500.0, "certificate_thumbprint": "a" * 43,
                 "roles": ["publisher"], "bindings": {}, "enabled": True, "created_at": 1,
                 "revoked_at": None, "effective_roles": ["publisher"]}
        calls = []
        def handler(request):
            calls.append((request.method, request.url.path, json.loads(request.content) if request.content else None))
            self.assertEqual(request.headers["Authorization"], "Bearer provisioner")
            if request.url.path.endswith("/managed"):
                self.assertEqual(request.headers["Idempotency-Key"], "manage-key")
                result = {"space_id": "space", "job_id": "job", "managed": True}
            elif request.url.path.endswith("/revoke"):
                self.assertEqual(request.headers["Idempotency-Key"], "revoke-key")
                result = {"attempt_id": "attempt", "revoked": 1, "revoked_at": 2}
            else:
                result = grant
            return httpx.Response(200, json=result)
        with httpx.Client(transport=httpx.MockTransport(handler)) as http:
            with ExchangeClient("https://exchange.test", "provisioner", http=http) as client:
                managed = client.manage_space("space", job_id="job", idempotency_key="manage-key")
                self.assertEqual(managed.job_id, "job")
                created = client.create_workload_grant("space", subject="stable-subject", job_id="job",
                    attempt_id="attempt", component_id="owner", epoch=2, expires_at=500,
                    certificate_thumbprint="a" * 43, roles=["publisher"], idempotency_key="grant-key")
                self.assertIsInstance(created, WorkloadGrantDescriptor)
                self.assertEqual(created.roles, ("publisher",))
                self.assertEqual(client.get_workload_grant("space", "grant").grant_id, "grant")
                self.assertEqual(client.verify_workload_grant("space").effective_roles, ("publisher",))
                self.assertEqual(client.revoke_workload_grants("space", attempt_id="attempt",
                    idempotency_key="revoke-key")["revoked"], 1)
        self.assertEqual(len(calls), 5)
        self.assertEqual(calls[1][2]["bindings"], {})
        self.assertNotIn("provisioner", json.dumps(created.to_dict()))


if __name__ == "__main__":
    unittest.main()
