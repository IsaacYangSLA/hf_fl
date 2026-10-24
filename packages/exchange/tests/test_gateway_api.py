"""Private gateway HTTP adapter: real JWTs, SQL grant checks and mutation fences."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
import time
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from fastapi.testclient import TestClient
from sqlalchemy import select

from hf2l_exchange.api import create_app
from hf2l_exchange.auth import backend_assertion_headers
from hf2l_exchange.gateway_api import BASE, MAX_BODY_BYTES, create_gateway_backend_app
from hf2l_exchange.models import Blob, Space, TransferAttempt
from hf2l_exchange.storage import S3BlobStore, StorageFailure
from hf2l_exchange.transfers import TransferService
from hf2l_exchange.worker import tick
from test_transfers import FakeStore
from test_workload_grants import ManagedSpaceFixture


class GatewayBackendTests(ManagedSpaceFixture):
    def setUp(self):
        super().setUp()
        self.settings = replace(self.settings, allow_local_http=False)
        self.storage = FakeStore()
        self.transfers = TransferService(self.service, self.storage)
        self.record = self.new_record("gateway-record")
        self.attachment = self.record["attachments"][0]["id"]
        self.args = self.space_id, self.record["id"], self.attachment, self.workload
        self.transfers.initiate(*self.args)
        self.authorization = self.gateway_token()
        self.app = create_gateway_backend_app(self.settings, self.service, self.transfers)
        self.client = self.client_for(self.app)
        self.part = (BASE + "/spaces/" + self.space_id + "/records/" + self.record["id"]
                     + "/attachments/" + self.attachment + "/parts/1")

    def client_for(self, app, origin="https://backend.example.test"):
        client = TestClient(app, base_url=origin, raise_server_exceptions=False)
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        return client

    def new_record(self, key):
        return self.service.create_record(self.workload, self.space_id, {
            "kind": "document", "schema_revision_id": self.revision["id"], "metadata": {},
            "attachments": [{"path": "model.safetensors", "size": 3,
                             "sha256": hashlib.sha256(b"abc").hexdigest()}]}, key)

    def gateway_token(self, **overrides):
        fields = {"aud": "hf2l-transfer", "scope": "transfer", "jti": self.grant["grant_id"],
                  "space_id": self.space_id, "job_id": "job-a", "attempt_id": "attempt-a",
                  "component_id": "component-a", "epoch": 1}
        fields.update(overrides)
        return self.workload_token(**fields)

    def headers(self, path, *, authorization=None, thumbprint=None, stamp=None):
        authorization = authorization or self.authorization
        headers = {"Authorization": authorization}
        headers.update(backend_assertion_headers(self.backend_secret, "POST", path,
            authorization, thumbprint or self.thumbprint, timestamp=stamp))
        return headers

    def post(self, path, *, body=None, authorization=None, thumbprint=None, client=None):
        return (client or self.client).post(path, json=body,
            headers=self.headers(path, authorization=authorization, thumbprint=thumbprint))

    def begin(self, **kwargs):
        response = self.post(self.part + "/begin", **kwargs)
        self.assertEqual(response.status_code, 200, response.text)
        value = response.json()
        self.assertEqual(set(value), {"receipt", "grant"})
        self.assertEqual(value["grant"]["size"], 3)
        self.assertEqual(value["grant"]["number"], 1)
        self.assertIn("url", value["grant"])
        return value["receipt"]

    def markers(self, attachment=None):
        with self.service.sessions() as session:
            attempt = session.scalar(select(TransferAttempt).where(
                TransferAttempt.blob_id == (attachment or self.attachment)))
            return list(attempt.mutation_tokens)

    def test_private_authorization_and_origin_grants_use_existing_checks(self):
        path = BASE + "/spaces/" + self.space_id + "/authorize"
        authorized = self.post(path)
        self.assertEqual(authorized.status_code, 200, authorized.text)
        self.assertEqual(authorized.json()["grant_id"], self.grant["grant_id"])
        response = self.post(self.part + "/grant", body={})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["url"], "https://storage.example.test/put")
        self.assertEqual(self.markers(), [])

    def test_begin_persists_exact_fence_before_returning_receipt(self):
        receipt = self.begin()
        markers = self.markers()
        self.assertEqual(len(markers), 1)
        payload = json.loads(base64.urlsafe_b64decode(receipt.split(".")[0] + "==="))
        self.assertEqual(payload["put"]["token"], markers[0])
        self.assertEqual(payload["put"]["record_id"], self.record["id"])
        self.assertEqual(payload["owner"]["certificate_thumbprint"], self.thumbprint)
        self.assertEqual(payload["authorization_sha256"],
                         hashlib.sha256(self.authorization.encode()).hexdigest())
        self.assertNotIn(self.authorization, json.dumps(payload))
        self.assertNotIn(self.authorization.removeprefix("Bearer "), json.dumps(payload))

    def test_receipt_survives_backend_restart_and_replay_cannot_settle_new_marker(self):
        old = self.begin()
        restarted = self.client_for(create_gateway_backend_app(self.settings, self.service, self.transfers))
        result = self.post(BASE + "/settle", body={"receipt": old}, client=restarted)
        self.assertEqual(result.json(), {"settled": True})
        newer = self.begin()
        markers = self.markers()
        replay = self.post(BASE + "/settle", body={"receipt": old})
        self.assertEqual(replay.json(), {"settled": False})
        self.assertEqual(self.markers(), markers)
        self.assertEqual(self.post(BASE + "/settle", body={"receipt": newer}).json(), {"settled": True})

    def test_exact_old_receipt_does_not_remove_another_upload_marker(self):
        old = self.begin()
        other = self.new_record("another-upload")
        attachment = other["attachments"][0]["id"]
        self.transfers.initiate(self.space_id, other["id"], attachment, self.workload)
        path = (BASE + "/spaces/" + self.space_id + "/records/" + other["id"]
                + "/attachments/" + attachment + "/parts/1/begin")
        response = self.post(path)
        self.assertEqual(response.status_code, 200, response.text)
        other_markers = self.markers(attachment)
        self.assertEqual(self.post(BASE + "/settle", body={"receipt": old}).json(), {"settled": True})
        self.assertEqual(self.markers(), [])
        self.assertEqual(self.markers(attachment), other_markers)

    def test_settlement_after_token_expiry_and_grant_revocation_is_allowed(self):
        receipt = self.begin()
        self.service.revoke_workload_grants(self.owner, self.space_id,
                                           {"attempt_id": "attempt-a"}, "gateway-revoke")
        with patch("jwt.api_jwt.datetime") as clock:
            clock.now.return_value = datetime.now(timezone.utc) + timedelta(minutes=10)
            denied = self.post(BASE + "/spaces/" + self.space_id + "/authorize")
            self.assertEqual(denied.status_code, 401, denied.text)
            response = self.post(BASE + "/settle", body={"receipt": receipt})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), {"settled": True})
        self.assertEqual(self.markers(), [])

    def test_revoked_grants_cannot_authorize_or_mint_any_new_origin_descriptor(self):
        self.service.revoke_workload_grants(self.owner, self.space_id,
                                           {"attempt_id": "attempt-a"}, "gateway-revoke")
        with patch.object(self.storage, "upload_grant",
                          side_effect=AssertionError("must not sign")) as signer:
            for path in (BASE + "/spaces/" + self.space_id + "/authorize",
                         self.part + "/grant", self.part + "/begin"):
                result = self.post(path)
                self.assertIn(result.status_code, (403, 404), result.text)
            signer.assert_not_called()
        self.assertEqual(self.markers(), [])

    def test_tampered_receipt_or_owner_cannot_settle(self):
        receipt = self.begin()
        encoded, signature = receipt.split(".")
        payload = json.loads(base64.urlsafe_b64decode(encoded + "==="))
        payload["put"]["part_number"] = 2
        tampered = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode() + "." + signature
        for value in (tampered, receipt[:-1] + ("0" if receipt[-1] != "0" else "1"),
                      "not-a-receipt", "", 1, None):
            with self.subTest(value_type=type(value).__name__):
                response = self.post(BASE + "/settle", body={"receipt": value})
                self.assertEqual(response.status_code, 401, response.text)
                self.assertEqual(len(self.markers()), 1)
        replacement = self.gateway_token(nonce="different-token")
        for authorization, thumb in ((replacement, self.thumbprint), (self.authorization, "b" * 43)):
            result = self.post(BASE + "/settle", body={"receipt": receipt},
                               authorization=authorization, thumbprint=thumb)
            self.assertEqual(result.status_code, 401, result.text)
        self.assertEqual(len(self.markers()), 1)

    def test_unknown_or_extra_body_fields_are_rejected_without_a_fence(self):
        for body in ({"principal": "admin"}, {"receipt": "wrong"}, [], None, True):
            result = self.client.post(self.part + "/begin", content=json.dumps(body),
                headers={**self.headers(self.part + "/begin"), "Content-Type": "application/json"})
            self.assertEqual(result.status_code, 422, result.text)
        for content in ('{"x":1,"x":2}', '{"x":NaN}', "{", '{"receipt":"x","receipt":"y"}'):
            response = self.client.post(BASE + "/settle", content=content,
                headers={**self.headers(BASE + "/settle"), "Content-Type": "application/json"})
            self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(self.markers(), [])

    def test_unsigned_stale_duplicate_or_substituted_assertions_are_rejected(self):
        path = self.part + "/grant"
        for headers in ({"Authorization": self.authorization},
                        self.headers(path, stamp=int(time.time()) - 31),
                        self.headers(self.part + "/begin"),
                        {**self.headers(path), "X-HF2L-TLS-Thumbprint": "b" * 43}):
            result = self.client.post(path, headers=headers)
            self.assertEqual(result.status_code, 401, result.text)
        duplicate = list(self.headers(path).items()) + [("Authorization", self.authorization)]
        self.assertEqual(self.client.post(path, headers=duplicate).status_code, 401)
        duplicate = list(self.headers(path).items()) + [("X-HF2L-TLS-Thumbprint", self.thumbprint)]
        self.assertEqual(self.client.post(path, headers=duplicate).status_code, 401)
        self.assertEqual(self.markers(), [])

    def test_query_percent_encoding_cookies_and_wrong_space_are_denied(self):
        path = self.part + "/grant"
        response = self.client.post(path + "?unexpected=1", headers=self.headers(path + "?unexpected=1"))
        self.assertEqual(response.status_code, 400, response.text)
        encoded = path.replace("/spaces/", "/%73paces/")
        response = self.client.post(encoded, headers=self.headers(path))
        self.assertEqual(response.status_code, 400, response.text)
        for name in ("Cookie", "Proxy-Authorization", "X-Forwarded-Client-Cert"):
            response = self.client.post(path, headers={**self.headers(path), name: "untrusted"})
            self.assertEqual(response.status_code, 400, response.text)
        foreign = path.replace(self.space_id, "foreign")
        response = self.client.post(foreign, headers=self.headers(foreign))
        self.assertEqual(response.status_code, 404, response.text)
        self.assertEqual(self.markers(), [])

    def test_only_transfer_scope_audience_and_bound_certificate_are_accepted(self):
        path = self.part + "/grant"
        for authorization, thumb in (
                (self.gateway_token(scope="exchange"), self.thumbprint),
                (self.gateway_token(aud="exchange-workload"), self.thumbprint),
                (self.gateway_token(aud=["hf2l-transfer"]), self.thumbprint),
                (self.authorization, "b" * 43),
                (self.token(), self.thumbprint)):
            result = self.post(path, authorization=authorization, thumbprint=thumb)
            self.assertEqual(result.status_code, 401, result.text)
        self.assertEqual(self.markers(), [])

    def test_lost_signing_outcome_keeps_durable_mutation_and_sanitizes_errors(self):
        self.storage.on_grant = lambda: (_ for _ in ()).throw(StorageFailure("storage_unavailable", True))
        result = self.post(self.part + "/begin")
        self.assertEqual(result.status_code, 503, result.text)
        self.assertNotIn("receipt", result.json())
        self.assertEqual(len(self.markers()), 1)

    def test_download_origin_descriptor_requires_published_verified_record(self):
        path = (BASE + "/spaces/" + self.space_id + "/records/" + self.record["id"]
                + "/attachments/" + self.attachment + "/download")
        self.assertEqual(self.post(path).status_code, 409)
        self.transfers.complete(*self.args)
        self.assertEqual(tick(self.transfers)["verified"], 1)
        self.service.publish_record(self.workload, self.space_id, self.record["id"], "gateway-publish")
        result = self.post(path)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()["url"], "https://storage.example.test/get")
        self.assertEqual(result.json()["sha256"], hashlib.sha256(b"abc").hexdigest())
        self.assertEqual(result.json()["size"], 3)

    def test_https_limits_and_sanitized_internal_errors(self):
        local = self.client_for(self.app, "http://127.0.0.1")
        result = self.post(self.part + "/grant", client=local)
        self.assertEqual(result.status_code, 426, result.text)
        huge = self.client.post(BASE + "/settle", content="x" * (MAX_BODY_BYTES + 1),
                                headers=self.headers(BASE + "/settle"))
        self.assertEqual(huge.status_code, 413)
        with patch.object(self.transfers, "grants", side_effect=RuntimeError("secret-origin-value")):
            with self.assertLogs("hf2l_exchange.gateway_backend", level="ERROR") as logs:
                result = self.post(self.part + "/grant")
        self.assertEqual(result.status_code, 500)
        self.assertNotIn("secret-origin-value", result.text + " ".join(logs.output))
        self.assertEqual(result.json()["error"]["request_id"], result.headers["X-Request-ID"])

    def test_public_exchange_factory_never_exposes_private_origin_routes(self):
        public = self.client_for(create_app(self.settings, self.service, self.transfers))
        result = self.post(self.part + "/grant", client=public)
        self.assertEqual(result.status_code, 404)
        self.assertEqual(self.client.get("/docs").status_code, 404)
        self.assertEqual(self.client.get("/openapi.json").status_code, 404)

    def test_private_backend_requires_managed_identity_and_separate_audience(self):
        with self.assertRaises(ValueError):
            create_gateway_backend_app(replace(self.settings, auth=self.legacy_settings()),
                                       self.service, self.transfers)
        with self.assertRaises(ValueError):
            create_gateway_backend_app(self.settings, self.service, self.transfers,
                                       gateway_audience=self.settings.auth.workload_audience)

    def storage_client(self):
        client = Mock()
        client.get_bucket_versioning.return_value = {"Status": "Enabled"}
        client.head_object.side_effect = ClientError({"Error": {"Code": "404"}}, "HeadObject")
        return client

    def test_storage_check_qualifies_fixed_actual_s3_backend_and_discloses_no_credentials(self):
        client = self.storage_client()
        self.transfers.storage = S3BlobStore(self.settings.storage, client=client)
        response = self.post(BASE + "/storage/check", authorization=self.token())
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), {"endpoint": "", "bucket": "fixture-bucket",
            "prefix": "exchange-v2", "region": "us-east-1", "protocol": "s3-multipart-v1",
            "versioning": "Enabled", "checked": True})
        client.get_bucket_versioning.assert_called_once_with(Bucket="fixture-bucket")
        self.assertEqual(client.head_object.call_count, 1)
        self.assertNotIn("secret", response.text.lower())

    def test_storage_check_requires_explicit_provisioner_not_workload_or_unlisted_human(self):
        client = self.storage_client()
        self.transfers.storage = S3BlobStore(self.settings.storage, client=client)
        for token, status in ((self.token(sub="human-admin"), 403), (self.authorization, 401)):
            result = self.post(BASE + "/storage/check", authorization=token)
            self.assertEqual(result.status_code, status, result.text)
        result = self.post(BASE + "/storage/check", authorization=self.token(),
                           body={"endpoint": "https://attacker.example.test"})
        self.assertEqual(result.status_code, 422, result.text)
        client.get_bucket_versioning.assert_not_called()

    def test_storage_check_refuses_unversioned_or_mismatched_backend(self):
        client = self.storage_client()
        self.transfers.storage = S3BlobStore(self.settings.storage, client=client)
        client.get_bucket_versioning.return_value = {"Status": "Suspended"}
        result = self.post(BASE + "/storage/check", authorization=self.token())
        self.assertEqual(result.status_code, 503, result.text)
        self.assertFalse(result.json().get("checked", False))
        mismatched = replace(self.settings.storage, bucket="another-bucket")
        self.transfers.storage = S3BlobStore(mismatched, client=client)
        client.reset_mock()
        result = self.post(BASE + "/storage/check", authorization=self.token())
        self.assertEqual(result.status_code, 503, result.text)
        self.assertEqual(result.json()["error"]["code"], "storage_backend_mismatch")
        client.get_bucket_versioning.assert_not_called()

    def test_settlement_key_rotation_fails_closed(self):
        receipt = self.begin()
        rotated = replace(self.settings, auth=replace(self.settings.auth,
                           trusted_backend_secret="new-private-backend-secret-at-least-32-bytes"))
        client = self.client_for(create_gateway_backend_app(rotated, self.service, self.transfers))
        path = BASE + "/settle"
        headers = {"Authorization": self.authorization}
        headers.update(backend_assertion_headers(rotated.auth.trusted_backend_secret, "POST",
                                                path, self.authorization, self.thumbprint))
        result = client.post(path, json={"receipt": receipt}, headers=headers)
        self.assertEqual(result.status_code, 401, result.text)
        self.assertEqual(len(self.markers()), 1)

    def test_settlement_rearms_only_owned_cleanup_and_keeps_storage_charged(self):
        receipt = self.begin()
        self.service.withdraw_record(self.workload, self.space_id, self.record["id"])
        self.service.revoke_workload_grants(self.owner, self.space_id,
                                           {"attempt_id": "attempt-a"}, "cleanup-revoke")
        with self.service.sessions() as session:
            attempt = session.scalar(select(TransferAttempt).where(
                TransferAttempt.blob_id == self.attachment))
            self.assertEqual(attempt.state, "cleanup")
            self.assertEqual(len(attempt.mutation_tokens), 1)
            self.assertEqual(session.get(Space, self.space_id).reclaiming, 3)
        response = self.post(BASE + "/settle", body={"receipt": receipt})
        self.assertEqual(response.json(), {"settled": True})
        with self.service.sessions() as session:
            attempt = session.scalar(select(TransferAttempt).where(
                TransferAttempt.blob_id == self.attachment))
            self.assertEqual(attempt.state, "cleanup")
            self.assertEqual(attempt.mutation_tokens, [])
            self.assertTrue(session.get(Blob, self.attachment).pending_deletion)
            self.assertEqual(session.get(Space, self.space_id).reclaiming, 3)
        self.assertEqual(self.storage.cleaned, [])
