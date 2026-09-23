"""HTTP contract boundaries independent of application and storage internals."""
from __future__ import annotations

import asyncio
import io
import json
import os
from contextlib import redirect_stdout, redirect_stderr
import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from hf2l_exchange.api import RequestBoundary, create_app
from hf2l_exchange.domain import ExchangeError, Principal
from hf2l_exchange.storage import StorageFailure


class HTTPBoundaryTests(unittest.TestCase):
    def setUp(self):
        revision = patch("hf2l_exchange.migrations.check_revision")
        revision.start()
        self.addCleanup(revision.stop)
        self.settings = SimpleNamespace(docs_enabled=False, max_body_bytes=4096, allow_local_http=True)
        self.service, self.transfers, self.auth = Mock(), Mock(), Mock()
        self.person = Principal("principal", "alice")
        self.auth.authenticate.return_value = self.person
        self.app = create_app(self.settings, self.service, self.transfers, self.auth)
        self.client = TestClient(self.app, raise_server_exceptions=False)
        self.addCleanup(self.client.close)
        self.headers = {"Authorization": "Bearer sample", "Idempotency-Key": "operation"}

    def test_creation_required_key_and_thin_command_translation(self):
        self.service.create_space.return_value = {"id": "space"}
        result = self.client.post("/v2/spaces", json={"name": "Documents"}, headers=self.headers)
        self.assertEqual(result.status_code, 201, result.text)
        principal, body, key = self.service.create_space.call_args.args
        self.assertEqual(principal, self.person)
        self.assertEqual((body["name"], body["profile"], key), ("Documents", "generic.v1", "operation"))
        self.service.create_space.reset_mock()
        result = self.client.post("/v2/spaces", json={"name": "Documents"})
        self.assertEqual(result.status_code, 422)
        self.service.create_space.assert_not_called()

    def test_error_contract_and_request_identity(self):
        self.service.get_space.side_effect = ExchangeError(403, "forbidden", "Access denied")
        result = self.client.get("/v2/spaces/a", headers={"X-Request-ID": "client.operation-1"})
        self.assertEqual(result.status_code, 403)
        self.assertEqual(result.headers["x-request-id"], "client.operation-1")
        self.assertEqual(result.json(), {"error": {"code": "forbidden", "detail": "Access denied",
                                                  "request_id": "client.operation-1"}})
        self.auth.authenticate.side_effect = ExchangeError(401, "invalid_access_token", headers={"WWW-Authenticate": "Bearer"})
        result = self.client.get("/v2/spaces/a")
        self.assertEqual(result.status_code, 401)
        self.assertEqual(result.headers["www-authenticate"], "Bearer")

    def test_exception_messages_and_validation_inputs_are_not_disclosed(self):
        secret = "password=never-return-me"
        self.service.get_space.side_effect = RuntimeError(secret)
        with self.assertLogs("hf2l_exchange.http", level="ERROR") as logs:
            result = self.client.get("/v2/spaces/a")
        self.assertEqual(result.status_code, 500)
        self.assertIn("x-request-id", result.headers)
        self.assertNotIn(secret, result.text + str(logs.output))
        result = self.client.post("/v2/spaces", json={"name": "ok", "unknown": secret}, headers=self.headers)
        self.assertEqual(result.status_code, 422)
        self.assertNotIn(secret, result.text)

    def test_cas_headers_and_returned_etags(self):
        self.service.put_reference.return_value = {"name": "main", "record_id": "r", "token": "8"}
        body = {"record_id": "r"}
        path = "/v2/spaces/s/refs/main"
        result = self.client.put(path, json=body, headers=self.headers)
        self.assertEqual(result.status_code, 428)
        self.service.put_reference.assert_not_called()
        result = self.client.put(path, json=body, headers=self.headers | {"If-Match": '"7"'})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.headers["etag"], '"8"')
        self.assertEqual(self.service.put_reference.call_args.args[-2:], ("7", "operation"))
        result = self.client.put(path, json=body, headers=self.headers | {"If-None-Match": "*"})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.service.put_reference.call_args.args[-2], "*")
        for headers in ({"If-Match": 'W/"7"'}, {"If-Match": '"7", "8"'},
                        {"If-Match": '"7"', "If-None-Match": "*"}):
            self.assertEqual(self.client.put(path, json=body, headers=self.headers | headers).status_code, 400)
        self.service.patch_record.return_value = {"id": "r", "version": 4}
        result = self.client.patch("/v2/spaces/s/records/r", json={"metadata": {"title": "new"}},
                                   headers=self.headers | {"If-Match": '"3"'})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.headers["etag"], '"4"')
        self.assertEqual(self.service.patch_record.call_args.args[-1], 3)

    def test_schema_alias_and_acquisition_wire_shape(self):
        self.service.register_type.return_value = {"id": "t", "kind": "document", "revision": 1}
        result = self.client.post("/v2/spaces/s/types/document/revisions",
                                  json={"schema": {"type": "object"}}, headers=self.headers)
        self.assertEqual(result.status_code, 201)
        self.assertIn("schema", self.service.register_type.call_args.args[-2])
        self.assertNotIn("schema_document", self.service.register_type.call_args.args[-2])
        self.service.acquire.return_value = {"id": "a", "fence": 1}
        result = self.client.post("/v2/spaces/s/acquisitions", headers=self.headers,
                                  json={"reference": "latest", "expected_token": "3", "input_record_ids": ["r"]})
        self.assertEqual(result.status_code, 201)
        self.service.complete.return_value = {"id": "a", "state": "completed"}
        result = self.client.post("/v2/spaces/s/acquisitions/a/complete", headers=self.headers,
                                  json={"fence": 1, "result_record_id": "result"})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.service.complete.call_args.args[-2], {"fence": 1, "result_record_id": "result"})

    def test_transfer_and_storage_error_translation(self):
        path = "/v2/spaces/s/records/r/attachments/a"
        self.transfers.grants.return_value = {"grants": [{"number": 1, "url": "https://storage.test"}]}
        result = self.client.post(path + "/grants", json={"numbers": [1]}, headers=self.headers)
        self.assertEqual(result.status_code, 200)
        self.transfers.grants.assert_called_once_with("s", "r", "a", self.person, [1])
        self.transfers.complete.side_effect = StorageFailure("storage_unavailable", retryable=True)
        result = self.client.post(path + "/complete", headers=self.headers)
        self.assertEqual(result.status_code, 503)
        self.assertEqual(result.headers["retry-after"], "3")
        self.transfers.complete.side_effect = StorageFailure("invalid_parts")
        self.assertEqual(self.client.post(path + "/complete", headers=self.headers).status_code, 409)

    def test_readiness_does_not_initialize_schema_and_liveness_is_independent(self):
        self.assertEqual(self.client.get("/health").json(), {"status": "alive"})
        self.transfers.storage.check.assert_not_called()
        with patch("hf2l_exchange.migrations.check") as check:
            self.assertEqual(self.client.get("/ready").status_code, 200)
            check.assert_called_once_with(self.service.engine)
            check.side_effect = RuntimeError("credentials-secret")
            self.transfers.storage.check.reset_mock()
            result = self.client.get("/ready")
            self.assertEqual(result.status_code, 503)
            self.assertEqual(result.headers["retry-after"], "3")
            self.assertNotIn("credentials-secret", result.text)
            self.transfers.storage.check.assert_not_called()
            self.assertEqual(self.client.get("/health").status_code, 200)

    def test_docs_disabled_and_https_required_outside_explicit_local_mode(self):
        self.assertEqual(self.client.get("/docs").status_code, 404)
        self.assertEqual(self.client.get("/openapi.json").status_code, 404)
        self.settings.allow_local_http = False
        secure = create_app(self.settings, self.service, self.transfers, self.auth)
        with TestClient(secure, raise_server_exceptions=False) as client:
            self.assertEqual(client.get("/health").status_code, 426)
            self.assertEqual(client.get("https://testserver/health").status_code, 200)
        self.settings.allow_local_http = True
        self.settings.docs_enabled = True
        with TestClient(create_app(self.settings, self.service, self.transfers, self.auth)) as client:
            document = client.get("/openapi.json")
            self.assertEqual(document.status_code, 200)
            self.assertIn("/v2/spaces", document.json()["paths"])

    def test_declared_and_streamed_body_limit(self):
        result = self.client.post("/v2/spaces", content=b"x" * 4097, headers=self.headers)
        self.assertEqual(result.status_code, 413)
        self.service.create_space.assert_not_called()

        async def streamed():
            invoked = False
            output = []
            parts = iter([{"type": "http.request", "body": b"123", "more_body": True},
                          {"type": "http.request", "body": b"456", "more_body": False}])
            async def app(scope, receive, send):
                nonlocal invoked
                invoked = True
            async def receive():
                return next(parts)
            async def send(message):
                output.append(message)
            middleware = RequestBoundary(app, max_body_bytes=5, allow_local_http=False)
            await middleware({"type": "http", "scheme": "https", "method": "POST", "headers": []}, receive, send)
            self.assertFalse(invoked)
            self.assertEqual(output[0]["status"], 413)
        asyncio.run(streamed())


class HTTPApplicationContractTests(unittest.TestCase):
    """Real service and revision ledger; no external identity/storage required."""

    def setUp(self):
        from hf2l_exchange.application import Service
        from hf2l_exchange.config import AuthSettings, DatabaseSettings, Settings
        from hf2l_exchange.migrations import initialize
        temporary = tempfile.TemporaryDirectory(prefix="exchange-http-contract-")
        self.addCleanup(temporary.cleanup)
        settings = Settings(database=DatabaseSettings(url="sqlite:///" + str(Path(temporary.name) / "test.db")),
                            auth=AuthSettings(admin_subject="owner"), allow_local_http=True)
        self.service = Service(settings)
        self.addCleanup(self.service.engine.dispose)
        initialize(self.service.engine)
        self.auth, self.transfers = Mock(), Mock()
        self.auth.authenticate.return_value = Principal("owner", "owner", True)
        self.app = create_app(settings, self.service, self.transfers, self.auth)
        self.client = TestClient(self.app, raise_server_exceptions=False)
        self.addCleanup(self.client.close)
        self.headers = {"Authorization": "Bearer test", "Idempotency-Key": "space"}

    def test_type_registration_preserves_profile_defaults(self):
        response = self.client.post("/v2/spaces", json={"name": "FedAvg", "profile": "fedavg.v1"}, headers=self.headers)
        self.assertEqual(response.status_code, 201, response.text)
        space = response.json()["id"]
        for kind, role, visibility in (("training.update", "contributor", "private"),
                                       ("model.global", "publisher", "shared")):
            response = self.client.post(f"/v2/spaces/{space}/types/{kind}/revisions",
                                        json={"schema": {"type": "object"}}, headers=self.headers)
            self.assertEqual(response.status_code, 201, response.text)
            from hf2l_exchange.models import KindPolicy
            with self.service.read_sessions() as session:
                policy = session.get(KindPolicy, (space, kind))
                self.assertEqual((policy.publish_roles, policy.visibility), ([role], visibility))
        response = self.client.post(f"/v2/spaces/{space}/types/model.global/revisions",
                                    json={"schema": {"type": "object"}, "publish_roles": ["contributor"]},
                                    headers=self.headers | {"Idempotency-Key": "invalid-policy"})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["error"]["code"], "profile_policy_conflict")

    def test_space_principal_quota_and_numeric_bounds(self):
        response = self.client.post("/v2/spaces", json={"name": "Documents", "principal_quota_bytes": 1024},
                                    headers=self.headers)
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["principal_quota_bytes"], 1024)
        for value in (0, -1, 2**63):
            for field in ("quota_bytes", "principal_quota_bytes", "quota_metadata_bytes", "quota_records"):
                response = self.client.post("/v2/spaces", json={"name": "Invalid", field: value}, headers=self.headers)
                self.assertEqual(response.status_code, 422, (field, value, response.text))

    def test_administrative_quota_updates_enforce_current_usage_and_membership(self):
        response = self.client.post("/v2/spaces", json={"name": "Documents", "quota_records": 1}, headers=self.headers)
        self.assertEqual(response.status_code, 201, response.text)
        space = response.json()["id"]
        prefix = f"/v2/spaces/{space}"
        response = self.client.post(prefix + "/types/document/revisions", json={"schema": {"type": "object"}}, headers=self.headers)
        self.assertEqual(response.status_code, 201, response.text)
        revision = response.json()["id"]
        response = self.client.post(prefix + "/records", json={"kind": "document", "schema_revision_id": revision,
                                    "metadata": {"title": "pending"}, "attachments": [{"path": "file", "size": 100,
                                    "sha256": "0" * 64}]}, headers=self.headers)
        self.assertEqual(response.status_code, 201, response.text)
        response = self.client.patch(prefix, json={"quota_records": 2}, headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["quota_records"], 2)
        for field, value in (("quota_bytes", 99), ("principal_quota_bytes", 99), ("quota_metadata_bytes", 1)):
            response = self.client.patch(prefix, json={field: value}, headers=self.headers)
            self.assertEqual(response.status_code, 409, (field, response.text))
        self.assertEqual(self.client.patch(prefix, json={"quota_records": 0}, headers=self.headers).status_code, 422)
        self.assertEqual(self.client.patch(prefix, json={"profile": "fedavg.v1"}, headers=self.headers).status_code, 422)
        owner = self.auth.authenticate.return_value
        self.service.put_member(owner, space, "reader", {"subject": "reader", "roles": ["reader"]})
        self.auth.authenticate.return_value = Principal("reader", "reader")
        self.assertEqual(self.client.patch(prefix, json={"quota_records": 3}, headers=self.headers).status_code, 403)
        self.assertEqual(self.client.get(prefix + "/members", headers=self.headers).status_code, 403)
        response = self.client.get(prefix + "/membership", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"principal_id": "reader", "subject": "reader", "roles": ["reader"], "bindings": {}})

    def test_unknown_database_revision_blocks_reads_and_mutations_without_initializing(self):
        from sqlalchemy import text
        from hf2l_exchange.migrations import LEDGER
        response = self.client.post("/v2/spaces", json={"name": "Documents"}, headers=self.headers)
        self.assertEqual(response.status_code, 201, response.text)
        space = response.json()["id"]
        with self.service.sessions.begin() as session:
            session.execute(text("UPDATE " + LEDGER + " SET revision='future'"))
        with patch("hf2l_exchange.migrations.initialize") as initialize:
            for method, path, body in (("GET", f"/v2/spaces/{space}", None),
                                       ("POST", "/v2/spaces", {"name": "Unsafe"})):
                response = self.client.request(method, path, json=body, headers=self.headers)
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.json()["error"]["code"], "database_revision_incompatible")
                self.assertEqual(response.headers["retry-after"], "3")
            self.assertEqual(self.client.get("/ready").status_code, 503)
            self.assertEqual(self.client.get("/health").status_code, 200)
            initialize.assert_not_called()
        with self.service.read_sessions() as session:
            self.assertEqual(session.execute(text("SELECT revision FROM " + LEDGER)).scalar_one(), "future")

    def test_offline_repair_cli_keeps_pending_quota_until_worker_reclamation(self):
        from hf2l_exchange.cli import main
        from hf2l_exchange.models import Space, TransferAttempt
        response = self.client.post("/v2/spaces", json={"name": "Repair"}, headers=self.headers)
        self.assertEqual(response.status_code, 201, response.text)
        space = response.json()["id"]
        prefix = f"/v2/spaces/{space}"
        response = self.client.post(prefix + "/types/document/revisions", json={"schema": {"type": "object"}}, headers=self.headers)
        revision = response.json()["id"]
        response = self.client.post(prefix + "/records", json={"kind": "document", "schema_revision_id": revision,
                                    "metadata": {}, "attachments": [{"path": "file", "size": 100, "sha256": "0" * 64}]},
                                    headers=self.headers)
        self.assertEqual(response.status_code, 201, response.text)
        record = response.json()
        with self.service.sessions.begin() as session:
            session.add(TransferAttempt(id="orphan", blob_id=record["attachments"][0]["id"],
                                        object_key="private-storage-locator", mutation_tokens=["private-mutation-token"],
                                        lease_until=0))
        self.assertEqual(self.client.delete(prefix + "/records/" + record["id"], headers=self.headers).status_code, 200)
        with patch.dict(os.environ, {"EXCHANGE_DATABASE_URL": self.service.settings.database.url}), \
             patch("hf2l_exchange.cli.logging.basicConfig"):
            for apply in (False, True):
                output = io.StringIO()
                arguments = ["repair-transfers", "--attempt", "orphan"]
                if apply:
                    arguments.extend(["--apply", "--writers-stopped", "--provider-quiesced"])
                with redirect_stdout(output):
                    self.assertEqual(main(arguments), 0)
                result = json.loads(output.getvalue())
                self.assertIs(result["dry_run"], not apply)
                self.assertNotIn("private-storage-locator", output.getvalue())
                self.assertNotIn("private-mutation-token", output.getvalue())
                with self.service.read_sessions() as session:
                    self.assertEqual(session.get(Space, space).reclaiming, 100)
                    attempt = session.get(TransferAttempt, "orphan")
                    self.assertEqual(attempt.state, "cleanup")
                    self.assertEqual(attempt.mutation_tokens, [] if apply else ["private-mutation-token"])

    def test_database_outage_is_retryable_and_discloses_no_connection_parameters(self):
        with patch("hf2l_exchange.migrations.check_revision", side_effect=RuntimeError("password=private")):
            response = self.client.post("/v2/spaces", json={"name": "Documents"}, headers=self.headers)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"]["code"], "database_unavailable")
        self.assertNotIn("password", response.text)
        self.assertEqual(self.client.get("/health").status_code, 200)


class CLICompositionTests(unittest.TestCase):
    def setUp(self):
        quiet = patch("hf2l_exchange.cli.logging.basicConfig")
        quiet.start()
        self.addCleanup(quiet.stop)

    def test_database_command_needs_only_database_configuration(self):
        from hf2l_exchange.cli import main
        with patch("hf2l_exchange.config.DatabaseSettings.from_env") as config, \
             patch("hf2l_exchange.models.database") as database, \
             patch("hf2l_exchange.migrations.check") as check, \
             patch("hf2l_exchange.config.Settings.from_env") as whole_settings:
            engine = Mock()
            database.return_value = engine, Mock()
            self.assertEqual(main(["check-db"]), 0)
            config.assert_called_once_with()
            check.assert_called_once_with(engine)
            engine.dispose.assert_called_once_with()
            whole_settings.assert_not_called()

    def test_storage_check_needs_no_database_or_identity_configuration(self):
        from hf2l_exchange.cli import main
        with patch("hf2l_exchange.config.StorageSettings.from_env") as config, \
             patch("hf2l_exchange.storage.S3BlobStore") as storage, \
             patch("hf2l_exchange.config.Settings.from_env") as whole_settings:
            self.assertEqual(main(["check-storage"]), 0)
            config.assert_called_once_with()
            storage.assert_called_once_with(config.return_value)
            storage.return_value.check.assert_called_once_with()
            whole_settings.assert_not_called()

    def test_worker_once_reports_failure_without_authentication_or_leaking_error(self):
        from hf2l_exchange.cli import main
        with patch("hf2l_exchange.config.Settings.from_env") as config, \
             patch("hf2l_exchange.application.Service") as service, \
             patch("hf2l_exchange.storage.S3BlobStore"), \
             patch("hf2l_exchange.transfers.TransferService"), \
             patch("hf2l_exchange.worker.tick", side_effect=RuntimeError("secret-password")), \
             self.assertLogs("hf2l_exchange.worker", level="ERROR") as logs:
            self.assertEqual(main(["worker", "--once"]), 1)
            config.assert_called_once_with(component="worker")
            service.return_value.engine.dispose.assert_called_once_with()
            self.assertNotIn("secret-password", str(logs.output))

    def test_repair_inventory_is_read_only_and_needs_only_database_configuration(self):
        from hf2l_exchange.cli import main
        output = io.StringIO()
        with patch("hf2l_exchange.config.DatabaseSettings.from_env") as config, \
             patch("hf2l_exchange.config.AuthSettings.from_env") as auth, \
             patch("hf2l_exchange.config.StorageSettings.from_env") as storage, \
             patch("hf2l_exchange.application.Service") as service, \
             patch("hf2l_exchange.migrations.check") as check, \
             patch("hf2l_exchange.transfers.inspect_mutations", return_value={"items": [], "truncated": False}) as inspect, \
             patch("hf2l_exchange.transfers.repair_mutations") as repair, redirect_stdout(output):
            self.assertEqual(main(["repair-transfers"]), 0)
            config.assert_called_once_with()
            auth.assert_not_called()
            storage.assert_not_called()
            check.assert_called_once_with(service.return_value.engine)
            inspect.assert_called_once_with(service.return_value)
            repair.assert_not_called()
            service.return_value.engine.dispose.assert_called_once_with()
        self.assertEqual(json.loads(output.getvalue()), {"items": [], "truncated": False, "dry_run": True})

    def test_repair_apply_requires_explicit_selection_and_both_assertions(self):
        from hf2l_exchange.cli import main
        invalid = (["--apply"], ["--apply", "--attempt", "a"],
                   ["--apply", "--attempt", "a", "--writers-stopped"],
                   ["--apply", "--attempt", "a", "--provider-quiesced"],
                   ["--apply", "--writers-stopped", "--provider-quiesced"])
        with patch("hf2l_exchange.application.Service") as service:
            for arguments in invalid:
                with self.assertRaises(SystemExit) as failure, redirect_stderr(io.StringIO()):
                    main(["repair-transfers", *arguments])
                self.assertEqual(failure.exception.code, 2)
            service.assert_not_called()

    def test_repair_selection_is_bounded_and_application_is_explicit(self):
        from hf2l_exchange.cli import main
        for arguments in (["--attempt", "a", "--attempt", "a"],
                          [word for i in range(101) for word in ("--attempt", str(i))]):
            with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                main(["repair-transfers", *arguments])
        for execute in (False, True):
            arguments = ["repair-transfers", "--attempt", "a", "--attempt", "b"]
            if execute:
                arguments += ["--apply", "--writers-stopped", "--provider-quiesced"]
            output = io.StringIO()
            with patch("hf2l_exchange.config.DatabaseSettings.from_env"), \
                 patch("hf2l_exchange.application.Service") as service, \
                 patch("hf2l_exchange.migrations.check"), \
                 patch("hf2l_exchange.transfers.inspect_mutations") as inspect, \
                 patch("hf2l_exchange.transfers.repair_mutations", return_value={"items": []}) as repair, \
                 redirect_stdout(output):
                self.assertEqual(main(arguments), 0)
                repair.assert_called_once_with(service.return_value, ["a", "b"], execute=execute,
                                               writers_stopped=execute, provider_quiesced=execute)
                inspect.assert_not_called()
            self.assertIs(json.loads(output.getvalue())["dry_run"], not execute)

    def test_serve_uses_import_factory_for_multiple_processes(self):
        from hf2l_exchange.cli import main
        with patch("uvicorn.run") as run:
            self.assertEqual(main(["serve", "--workers", "3"]), 0)
            self.assertEqual(run.call_args.args, ("hf2l_exchange.api:create_app",))
            self.assertTrue(run.call_args.kwargs["factory"])
            self.assertEqual(run.call_args.kwargs["workers"], 3)


if __name__ == "__main__":
    unittest.main()
