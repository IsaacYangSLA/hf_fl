"""Focused client/export tests: failed downloads cannot become valid exports."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import httpx
from tools.jobs_client import API, JobsClient, JobsClientError, atomic_json, manager_origin
from tools.export_jobs import export_job, opaque_id, sanitize


MANAGER = "https://jobs.example.test:9443"


class JobExportTests(unittest.TestCase):
    def client(self, handler, **kwargs):
        return JobsClient(kwargs.pop("base_url", MANAGER), transport=httpx.MockTransport(handler), **kwargs)

    def test_generic_https_origins_are_normalized(self):
        for origin, expected in (
                ("https://jobs.example.test:9443", "https://jobs.example.test:9443"),
                ("https://JOBS.EXAMPLE.TEST:443/", "https://jobs.example.test"),
                ("https://192.0.2.12:9443", "https://192.0.2.12:9443"),
                ("https://[2001:db8::12]:9443", "https://[2001:db8::12]:9443"),
                ("https://localhost", "https://localhost"),
                ("https://münchen.example", "https://xn--mnchen-3ya.example")):
            with self.subTest(origin=origin):
                self.assertEqual(manager_origin(origin), expected)
                requests = []
                with self.client(lambda request: (
                        requests.append(request) or httpx.Response(200)),
                        base_url=origin, session_cookie="private-session") as client:
                    client.request("GET", "/jobs")
                self.assertEqual(str(requests[0].url), expected + "/jobs")
                self.assertEqual(requests[0].headers["cookie"],
                                 "__Host-hf2l_jobs=private-session")

    def test_invalid_origins_rejected_before_credentials_are_loaded(self):
        for origin in (
                None, "", "http://jobs.example", "ftp://jobs.example", "//jobs.example",
                "https://", "https://user:password@jobs.example", "https://@jobs.example",
                "https://jobs.example/api", "https://jobs.example?token=private",
                "https://jobs.example?", "https://jobs.example#fragment",
                "https://jobs.example#", "https://jobs.example:0",
                "https://jobs.example:65536", "https://jobs.example:notaport",
                "https://jobs.example:", "https://[invalid]", "https://bad_host",
                "https://-bad.example", "https://bad..example", "https://jobs.example\\other",
                "https://jobs.example\n", " https://jobs.example", "https://jobs.example%2fother"):
            with self.subTest(origin=origin), patch("tools.jobs_client.private_json") as load:
                with self.assertRaises(JobsClientError):
                    JobsClient(origin, session_file="/never-read")
                load.assert_not_called()

    def test_foreign_origin_session_file_refused_before_requests(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "session.json"
            atomic_json(target, {"base_url": "https://other.example.test",
                                 "session_cookie": "private-session"})
            requests = []
            with self.assertRaises(JobsClientError):
                self.client(lambda request: (
                    requests.append(request) or httpx.Response(200)), session_file=target)
            self.assertEqual(requests, [])

    def test_invalid_session_document_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "session.json"
            atomic_json(target, ["not", "a", "session"])
            with self.assertRaises(JobsClientError):
                self.client(lambda request: httpx.Response(200), session_file=target)

    def test_tls_requires_certificates_and_hostname_with_system_roots(self):
        import ssl
        with patch("tools.jobs_client.httpx.Client") as create:
            with JobsClient(MANAGER):
                pass
        context = create.call_args.kwargs["verify"]
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertTrue(context.verify_flags & ssl.VERIFY_X509_STRICT)
        self.assertFalse(create.call_args.kwargs["follow_redirects"])
        self.assertFalse(create.call_args.kwargs["trust_env"])

    def test_export_cli_requires_explicit_origin_and_output(self):
        from tools.export_jobs import main
        for arguments in (
                ["--session-file", "/unused", "--output", "/unused-output"],
                ["--session-file", "/unused", "--manager-url", MANAGER]):
            with self.subTest(arguments=arguments), patch("sys.stderr"), patch(
                    "tools.export_jobs.JobsClient") as create:
                with self.assertRaises(SystemExit) as error:
                    main(arguments)
                self.assertEqual(error.exception.code, 2)
                create.assert_not_called()

    def test_export_cli_forwards_ca_origin_output_and_job(self):
        from tools.export_jobs import main
        from unittest.mock import MagicMock
        client = MagicMock()
        client.__enter__.return_value = client
        client.get_json.return_value = {"state": "SUCCEEDED"}
        with patch("tools.export_jobs.JobsClient", return_value=client) as create, patch(
                "tools.export_jobs.export_job", return_value={"complete": True}) as export, patch(
                "builtins.print"):
            result = main(["--session-file", "/private-session", "--manager-url", MANAGER,
                           "--ca-file", "/trust/organization-ca.pem", "--output", "/private-exports",
                           "--job-id", "opaque-job"])
        self.assertEqual(result, 0)
        create.assert_called_once_with(MANAGER, ca_file=Path("/trust/organization-ca.pem"),
                                       session_file=Path("/private-session"))
        export.assert_called_once_with(client, "opaque-job", Path("/private-exports"))

    def test_export_cli_uses_system_trust_by_default(self):
        from tools.export_jobs import main
        from unittest.mock import MagicMock
        client = MagicMock()
        client.__enter__.return_value = client
        client.iter_pages.return_value = []
        with patch("tools.export_jobs.JobsClient", return_value=client) as create, patch(
                "builtins.print"):
            result = main(["--session-file", "/private-session", "--manager-url", MANAGER,
                           "--output", "/private-exports"])
        self.assertEqual(result, 0)
        self.assertIsNone(create.call_args.kwargs["ca_file"])

    def test_cursor_follows_signed_value_and_filters(self):
        requests = []
        def handle(request):
            requests.append(dict(request.url.params))
            if "cursor" not in request.url.params:
                return httpx.Response(200, json={"items": [{"id": "first"}], "next_cursor": "signed+/?cursor"})
            return httpx.Response(200, json={"items": [{"id": "second"}], "next_cursor": None})
        with self.client(handle) as client:
            values = list(client.iter_pages(API + "/jobs", params={"view": "history"}))
        self.assertEqual([item["id"] for item in values], ["first", "second"])
        self.assertEqual(requests[1], {"view": "history", "limit": "100", "cursor": "signed+/?cursor"})

    def test_cursor_loop_refused(self):
        with self.client(lambda req: httpx.Response(200, json={"items": [], "next_cursor": "repeated"})) as client:
            with self.assertRaises(JobsClientError):
                list(client.iter_pages(API + "/jobs"))

    def test_download_checks_hash_before_replacing_existing_file(self):
        content = b"real checkpoint bytes"
        digest = hashlib.sha256(content).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "artifact"
            destination.write_bytes(b"previous verified checkpoint")
            def handle(req):
                return httpx.Response(200, headers={"Content-Length": str(len(content))},
                                      stream=httpx.ByteStream(content))
            with self.client(handle) as client:
                with self.assertRaises(JobsClientError):
                    client.stream_download("/download", destination, expected_size=len(content),
                                           expected_sha256="0" * 64)
                self.assertEqual(destination.read_bytes(), b"previous verified checkpoint")
                self.assertEqual(list(Path(temporary).glob(".download-*")), [])
                verified = client.stream_download("/download", destination, expected_size=len(content),
                                                  expected_sha256=digest)
            self.assertEqual(destination.read_bytes(), content)
            self.assertEqual(verified["sha256"], digest)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_short_or_oversize_download_leaves_no_file(self):
        for content in (b"a", b"oversized"):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary) / "artifact"
                with self.client(lambda req: httpx.Response(200, stream=httpx.ByteStream(content))) as client:
                    with self.assertRaises(JobsClientError):
                        client.stream_download("/download", target, expected_size=2,
                                               expected_sha256=hashlib.sha256(b"ok").hexdigest())
                self.assertFalse(target.exists())
                self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_origin_cookie_csrf_and_redirect_constraints(self):
        requests = []
        def handle(request):
            requests.append(request)
            return httpx.Response(303, headers={"Location": "https://foreign.invalid/"})
        with self.client(handle, session_cookie="private-session", csrf_token="csrf") as client:
            response = client.request("POST", "/mutation", json={}, check=False)
            self.assertEqual(response.status_code, 303)
            self.assertEqual(len(requests), 1)
            self.assertEqual(requests[0].headers["cookie"], "__Host-hf2l_jobs=private-session")
            self.assertEqual(requests[0].headers["origin"], "https://jobs.example.test:9443")
            self.assertEqual(requests[0].headers["x-csrf-token"], "csrf")
            for unsafe in ("//foreign.invalid/path", "https://foreign.invalid/", "/\\foreign.invalid"):
                with self.assertRaises(JobsClientError):
                    client.request("GET", unsafe)
        with self.assertRaises(JobsClientError):
            self.client(handle, base_url="http://jobs.example.test:9443")

    def test_private_session_file_modes_and_origin(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "session.json"
            atomic_json(target, {"base_url": "https://jobs.example.test:9443", "session_cookie": "cookie"})
            def handle(req):
                return httpx.Response(200, json={"authenticated": True, "csrf_token": "live-csrf"})
            with self.client(handle, session_file=target) as client:
                self.assertEqual(client.csrf_token, "live-csrf")
            target.chmod(0o644)
            with self.assertRaises(JobsClientError):
                self.client(handle, session_file=target)

    def test_export_metadata_sanitized_and_artifact_names_never_used_as_paths(self):
        payload = b"checkpoint"
        digest = hashlib.sha256(payload).hexdigest()
        artifact = {"id": "artifact-1", "kind": "checkpoint", "name": "../../escape.pt",
                    "download_available": True, "size_bytes": len(payload), "sha256": digest}
        def handle(req):
            path = req.url.path
            if path.endswith("/download"):
                return httpx.Response(200, stream=httpx.ByteStream(payload))
            if path.endswith("/artifacts/artifact-1"):
                return httpx.Response(200, json=artifact)
            if path.endswith("/artifacts"):
                return httpx.Response(200, json={"items": [artifact], "next_cursor": None})
            if path.endswith("/events") or path.endswith("/logs"):
                return httpx.Response(200, json={"items": [{"data": "token=private /etc/application/secrets/key"}],
                                               "next_cursor": None})
            if path.endswith("/attempts"):
                return httpx.Response(200, json={"items": []})
            return httpx.Response(200, json={"id": "job-1", "state": "SUCCEEDED",
                "spec": {"source_commit": "f" * 40, "secret_refs": ["private"],
                         "options": {"password": "private", "host_path": "/var/lib/application/private"}}})
        with tempfile.TemporaryDirectory() as temporary, self.client(handle) as client:
            manifest = export_job(client, "job-1", Path(temporary))
            root = Path(temporary) / "job-1"
            self.assertEqual((root / "artifacts" / "artifact-1").read_bytes(), payload)
            self.assertFalse((Path(temporary) / "escape.pt").exists())
            self.assertTrue(manifest["complete"])
            rendered = (root / "job.json").read_text() + (root / "logs.json").read_text()
            self.assertNotIn("private", rendered)
            self.assertNotIn("/etc/application", rendered)
            self.assertNotIn("secret_refs", rendered)

    def test_failed_refresh_removes_stale_success_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "job-1"
            root.mkdir(mode=0o700)
            (root / "manifest.json").write_text('{"complete":true}')
            def handle(req):
                if req.url.path.endswith("/attempts"):
                    return httpx.Response(503)
                return httpx.Response(200, json={"id": "job-1", "state": "SUCCEEDED"})
            with self.client(handle) as client, self.assertRaises(JobsClientError):
                export_job(client, "job-1", Path(temporary))
            self.assertFalse((root / "manifest.json").exists())

    def test_active_snapshot_is_never_a_complete_export(self):
        def handle(req):
            if req.url.path.endswith("/job-active"):
                return httpx.Response(200, json={"id": "job-active", "state": "RUNNING"})
            return httpx.Response(200, json={"items": [], "next_cursor": None})
        with tempfile.TemporaryDirectory() as temporary, self.client(handle) as client:
            manifest = export_job(client, "job-active", Path(temporary))
            self.assertFalse(manifest["complete"])
            self.assertEqual(manifest["job_state"], "RUNNING")

    def test_include_active_cli_enumerates_all_view(self):
        from tools.export_jobs import main
        from unittest.mock import MagicMock
        client = MagicMock()
        client.__enter__.return_value = client
        client.iter_pages.return_value = []
        with patch("tools.export_jobs.JobsClient", return_value=client), patch("builtins.print"):
            self.assertEqual(main(["--session-file", "/unused", "--manager-url", MANAGER, "--output", "/unused-output", "--include-active"]), 0)
        client.iter_pages.assert_called_once_with(API + "/jobs", params={"view": "all"})

    def test_expired_logs_make_terminal_export_incomplete(self):
        def handle(req):
            if req.url.path.endswith("/job-1"):
                return httpx.Response(200, json={"id": "job-1", "state": "SUCCEEDED"})
            if req.url.path.endswith("/logs"):
                return httpx.Response(200, json={"items": [
                    {"id": "expired-log", "expired": True, "data": ""}], "next_cursor": None})
            return httpx.Response(200, json={"items": [], "next_cursor": None})
        with tempfile.TemporaryDirectory() as temporary, self.client(handle) as client:
            manifest = export_job(client, "job-1", Path(temporary))
            self.assertFalse(manifest["complete"])
            self.assertEqual(manifest["unavailable_log_ids"], ["expired-log"])

    def test_credentials_cannot_be_published_as_ordinary_output(self):
        from tools.export_jobs import CredentialGuard, SensitiveArtifact
        samples = (b"-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----",
                   b'{"client_secret": "private"}',
                   b'{"cookies": [{"name": "__Host-hf2l_jobs", "value": "private"}]}',
                   b"eyJabcdef.abcdefghi.abcdefghijk")
        for payload in samples:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary) / "opaque-artifact"
                with self.client(lambda req: httpx.Response(
                        200, stream=httpx.ByteStream(payload))) as client:
                    with self.assertRaises(SensitiveArtifact):
                        client.stream_download("/download", target,
                            expected_size=len(payload), expected_sha256=hashlib.sha256(payload).hexdigest(),
                            content_guard=CredentialGuard())
                self.assertFalse(target.exists())
                self.assertEqual(list(Path(temporary).iterdir()), [])
        guard = CredentialGuard()
        guard.feed(b"-----BEGIN PRI")
        with self.assertRaises(SensitiveArtifact):
            guard.feed(b"VATE KEY-----")

    def test_credential_filenames_excluded_without_download(self):
        artifact = {"id": "artifact-private", "kind": "output", "name": "owner/workload-key.pem",
                    "download_available": True}
        def handle(req):
            if req.url.path.endswith("/job-1"):
                return httpx.Response(200, json={"id": "job-1", "state": "SUCCEEDED"})
            if req.url.path.endswith("/artifacts"):
                return httpx.Response(200, json={"items": [artifact], "next_cursor": None})
            if req.url.path.endswith("/download"):
                self.fail("Credential-named artifact must never be downloaded")
            return httpx.Response(200, json={"items": [], "next_cursor": None})
        with tempfile.TemporaryDirectory() as temporary, self.client(handle) as client:
            manifest = export_job(client, "job-1", Path(temporary))
            self.assertEqual(manifest["excluded_artifact_ids"], ["artifact-private"])
            self.assertEqual(manifest["files"], [])

    def test_linked_output_and_invalid_ids_refused(self):
        for value in ("../escape", "/abs", ".", "..", "id/other", "bad\x00id"):
            with self.assertRaises(JobsClientError):
                opaque_id(value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "linked").symlink_to(root)
            with self.client(lambda req: httpx.Response(200, json={"id": "job-1"})) as client:
                with self.assertRaises(JobsClientError):
                    export_job(client, "job-1", root / "linked")

    def test_sanitizes_private_key_and_jwt(self):
        raw = "-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY----- eyJabc.def.ghi"
        safe = sanitize({"value": raw, "client_secret": "private", "session_token": "private"})
        self.assertNotIn("private", safe["value"].replace("[private key omitted]", ""))
        self.assertNotIn("eyJ", safe["value"])
        self.assertEqual(set(safe), {"value"})
        self.assertEqual(sanitize('embedded {"client_secret":"private"}'),
                         "[credential-containing text omitted]")


if __name__ == "__main__":
    unittest.main()
