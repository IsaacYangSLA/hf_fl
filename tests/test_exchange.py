"""Control-plane, SDK and FedAvg integration tests using real JWT signatures and an emulated S3 server."""
import hashlib
import json
import logging
import os
import socket
import tempfile
import time
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from pathlib import Path

try:
    import boto3
    import httpx
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from fastapi.testclient import TestClient
    from moto.server import ThreadedMotoServer
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url

    from hf2l.backends.exchange import INLINE_METADATA_BUDGET, ROUND_FULL_FILE, ExchangeStore
    from hf2l.exchange.api import create_app
    from hf2l.exchange.auth import principal_id
    from hf2l.exchange.client import ExchangeClient, ExchangeError
    from hf2l.exchange.config import Settings
    from hf2l.exchange.models import Base, Blob, Claim, Event, Member, Record, Space
    from hf2l.exchange.protocol import METADATA_LIMIT_BYTES, metadata_size
    from hf2l.exchange.storage import S3BlobStore
    from hf2l.exchange.worker import tick
    from hf2l.hub_helpers import ROUND_FILE, SUBMISSION_FILE, write_json
    EXCHANGE_AVAILABLE = True
except ModuleNotFoundError:
    if os.environ.get("EXCHANGE_REQUIRE_TESTS") == "1":
        raise
    EXCHANGE_AVAILABLE = False


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@unittest.skipUnless(EXCHANGE_AVAILABLE, "install hf2l[service,exchange,exchange-test]")
class ExchangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.live = bool(os.environ.get("EXCHANGE_TEST_S3_ENDPOINT"))
        cls.endpoint = os.environ.get("EXCHANGE_TEST_S3_ENDPOINT")
        if not cls.live:
            # A real HTTP server (not mock_aws) so the SDK's presigned PUT/GET transfers are exercised.
            port = free_port()
            logging.getLogger("werkzeug").setLevel(logging.ERROR)
            cls.moto = ThreadedMotoServer(ip_address="127.0.0.1", port=port, verbose=False)
            cls.moto.start()
            cls.endpoint = f"http://127.0.0.1:{port}"
            for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
                os.environ.setdefault(name, "testing")
            os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

    @classmethod
    def tearDownClass(cls):
        if not cls.live:
            cls.moto.stop()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        database_url = f"sqlite:///{self.temp.name}/exchange.db"
        if os.environ.get("EXCHANGE_TEST_DATABASE_URL"):
            url = make_url(os.environ["EXCHANGE_TEST_DATABASE_URL"])
            schema = "hf2ltest_" + uuid.uuid4().hex
            admin_engine = create_engine(url)
            with admin_engine.begin() as connection:
                connection.execute(text(f'CREATE SCHEMA "{schema}"'))
            def cleanup_schema():
                with admin_engine.begin() as connection:
                    connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
                admin_engine.dispose()
            self.addCleanup(cleanup_schema)
            database_url = url.update_query_dict({"options": "-csearch_path=" + schema}).render_as_string(hide_password=False)
        self.settings = Settings(database_url=database_url,
                                 issuer="https://issuer.test", audience="exchange", bucket="hf2l-test-" + uuid.uuid4().hex,
                                 s3_endpoint=self.endpoint, allow_local_http=True, admin_subject="owner", public_key=public,
                                 part_bytes=5 * 1024 * 1024, worker_recover_after=0)
        self.s3 = boto3.client("s3", region_name="us-east-1", endpoint_url=self.endpoint)
        self.s3.create_bucket(Bucket=self.settings.bucket)
        def cleanup_bucket():
            for page in self.s3.get_paginator("list_object_versions").paginate(Bucket=self.settings.bucket):
                for item in page.get("Versions", []) + page.get("DeleteMarkers", []):
                    self.s3.delete_object(Bucket=self.settings.bucket, Key=item["Key"], VersionId=item["VersionId"])
            for page in self.s3.get_paginator("list_multipart_uploads").paginate(Bucket=self.settings.bucket):
                for item in page.get("Uploads", []):
                    self.s3.abort_multipart_upload(Bucket=self.settings.bucket, Key=item["Key"], UploadId=item["UploadId"])
            self.s3.delete_bucket(Bucket=self.settings.bucket)
        self.addCleanup(cleanup_bucket)
        self.s3.put_bucket_versioning(Bucket=self.settings.bucket, VersioningConfiguration={"Status": "Enabled"})
        self.storage = S3BlobStore(self.settings, self.s3)
        self.app = create_app(self.settings, self.storage)
        self.service = self.app.state.service
        Base.metadata.create_all(self.service.engine)
        self.client = TestClient(self.app)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        self.headers = self.auth("owner")
        response = self.client.post("/v1/spaces", headers={**self.headers, "Idempotency-Key": "space"},
                                    json={"name": "test", "tenant": "tenant-1"})
        self.assertEqual(response.status_code, 201, response.text)
        self.space = response.json()["id"]
        self.prefix = f"/v1/spaces/{self.space}"
        for subject in ("alice", "bob"):
            self.member(subject, ["contributor", "reader"], subject)

    def auth(self, subject, **claims):
        token = jwt.encode({"iss": self.settings.issuer, "aud": "exchange", "sub": subject,
                            "exp": int(time.time()) + 3600, "iat": int(time.time()), "scope": "exchange", **claims},
                           self.private_key, algorithm="RS256", headers={"typ": "at+jwt"})
        return {"Authorization": "Bearer " + token}

    def member(self, subject, roles, participant=None):
        result = self.client.put(self.prefix + "/members/" + principal_id(self.settings.issuer, subject),
                                 headers=self.headers, json={"subject": subject, "roles": roles, "participant": participant})
        self.assertEqual(result.status_code, 200, result.text)

    @staticmethod
    def code(response):
        return response.json().get("code")

    def create(self, subject="alice", kind="message", base=None, data=None, metadata=None, key=None, attachments=None):
        if attachments is None:
            attachments = [] if data is None else [{"name": "model.bin", "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}]
        return self.client.post(self.prefix + "/records", headers={**self.auth(subject), "Idempotency-Key": key or uuid.uuid4().hex},
                                json={"kind": kind, "base_record_id": base, "metadata": metadata or {}, "attachments": attachments})

    def ready(self, subject="owner", kind="model.global", base=None, metadata=None):
        result = self.create(subject, kind, base, metadata=metadata)
        self.assertEqual(result.status_code, 201, result.text)
        record = result.json()
        response = self.client.post(self.prefix + f"/records/{record['id']}:publish", headers=self.auth(subject))
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def ref(self, record, expected=None, key=None, subject="owner"):
        headers = {**self.auth(subject), "Idempotency-Key": key or uuid.uuid4().hex}
        headers["If-Match" if expected else "If-None-Match"] = f'"{expected}"' if expected else "*"
        return self.client.put(self.prefix + "/refs/main", headers=headers, json={"record_id": record["id"]})

    def upload(self, record, data, subject="alice"):
        identifier = record["attachments"][0]["id"]
        response = self.client.post(self.prefix + f"/records/{record['id']}/blobs/{identifier}/uploads", headers=self.auth(subject))
        self.assertEqual(response.status_code, 200, response.text)
        with self.service.sessions.begin() as session:
            blob = session.get(Blob, identifier)
        for offset in range(0, max(len(data), 1), blob.part_bytes):
            self.s3.upload_part(Bucket=self.settings.bucket, Key=blob.key, UploadId=blob.upload_id,
                                PartNumber=offset // blob.part_bytes + 1, Body=data[offset:offset + blob.part_bytes])
        response = self.client.post(self.prefix + f"/uploads/{identifier}:complete", headers=self.auth(subject))
        self.assertEqual(response.status_code, 202, response.text)
        return identifier

    def claim(self, subject="owner", key=None, **body):
        return self.client.post(self.prefix + "/claims", headers={**self.auth(subject), "Idempotency-Key": key or uuid.uuid4().hex}, json=body)

    def sdk(self, subject, transfer=None):
        def check_storage_request(request):
            self.assertNotIn("authorization", request.headers)
        transfer = transfer or httpx.Client(event_hooks={"request": [check_storage_request]}, timeout=30)
        self.addCleanup(transfer.close)
        return ExchangeClient("http://testserver", self.auth(subject)["Authorization"].split(" ", 1)[1],
                              http=self.client, transfer=transfer, allow_local_http=True)

    def store(self, subject, transfer=None):
        return ExchangeStore(None, None, client=self.sdk(subject, transfer), wait_seconds=60)

    def test_authentication_and_cross_space_isolation(self):
        for headers in ({}, self.auth("alice", aud="other"), self.auth("alice", exp=1), self.auth("alice", scope="")):
            result = self.client.get(self.prefix + "/records", headers=headers)
            self.assertEqual(result.status_code, 401)
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        forged_token = jwt.encode({"iss": self.settings.issuer, "aud": "exchange", "sub": "owner", "exp": int(time.time()) + 60,
                                   "iat": int(time.time()), "scope": "exchange"}, other_key, algorithm="RS256", headers={"typ": "at+jwt"})
        self.assertEqual(self.client.get(self.prefix + "/me", headers={"Authorization": "Bearer " + forged_token}).status_code, 401)
        self.assertEqual(self.client.get(self.prefix + "/records", headers=self.auth("stranger")).status_code, 404)
        forged = self.client.post(self.prefix + "/records", headers={**self.auth("alice"), "Idempotency-Key": "bad"},
                                  json={"kind": "message", "created_by": "owner"})
        self.assertEqual(forged.status_code, 422)
        self.assertEqual(self.create(kind="model.global").status_code, 403)
        other = self.client.post("/v1/spaces", headers={**self.headers, "Idempotency-Key": "other"},
                                 json={"name": "other", "tenant": "tenant-2"}).json()["id"]
        record = self.ready("alice", "message")
        self.assertEqual(self.client.get(f"/v1/spaces/{other}/records/{record['id']}", headers=self.headers).status_code, 404)

    def test_metadata_roundtrip_visibility_and_immutability(self):
        draft = self.create().json()
        self.assertEqual(self.client.get(self.prefix + f"/records/{draft['id']}", headers=self.headers).status_code, 404)
        record = self.ready("alice", "message", metadata={"hello": "world"})
        response = self.client.get(self.prefix + f"/records/{record['id']}", headers=self.auth("bob"))
        self.assertEqual(response.json()["metadata"], {"hello": "world"})
        changed = self.client.patch(self.prefix + f"/records/{record['id']}", headers={**self.auth("alice"), "If-Match": '"2"'}, json={"metadata": {}})
        self.assertEqual(self.code(changed), "record_immutable")
        base = self.ready()
        private = self.ready("alice", "training.update", base["id"])
        self.assertEqual(self.client.get(self.prefix + f"/records/{private['id']}", headers=self.auth("bob")).status_code, 404)
        visible = self.client.get(self.prefix + "/records", headers=self.auth("bob")).json()["items"]
        self.assertNotIn(private["id"], [r["id"] for r in visible])

    def test_idempotency_quota_and_cancellation(self):
        first = self.create(data=b"abc", key="same")
        second = self.create(data=b"abc", key="same")
        self.assertEqual(first.json()["id"], second.json()["id"])
        self.assertEqual(self.code(self.create(data=b"abcd", key="same")), "idempotency_key_reused")
        space = self.client.get(self.prefix, headers=self.headers)
        self.assertEqual(space.json()["allocated_bytes"], 3)
        self.assertEqual(self.client.patch(self.prefix, headers=self.headers, json={"quota_bytes": 3}).status_code, 412)
        patched = self.client.patch(self.prefix, headers={**self.headers, "If-Match": space.headers["ETag"]}, json={"quota_bytes": 3})
        self.assertEqual(patched.status_code, 200, patched.text)
        self.assertEqual(self.client.patch(self.prefix, headers={**self.auth("alice"), "If-Match": patched.headers["ETag"]},
                                           json={"quota_bytes": 5}).status_code, 403)
        self.assertEqual(self.code(self.create(data=b"a")), "space_quota_exceeded")
        self.client.delete(self.prefix + "/records/" + first.json()["id"], headers=self.auth("alice"))
        self.assertEqual(self.code(self.create(data=b"abc")), "space_quota_exceeded")
        with self.service.sessions.begin() as session:
            session.get(Blob, first.json()["attachments"][0]["id"]).expires_at = 1
        tick(self.service)
        self.assertEqual(self.create(data=b"abc").status_code, 201)

    def test_principal_quota_admin_cancel_and_revocation_release(self):
        space = self.client.get(self.prefix, headers=self.headers)
        self.client.patch(self.prefix, headers={**self.headers, "If-Match": space.headers["ETag"]},
                          json={"quota_bytes": 100, "principal_quota_bytes": 10})
        hog = self.create(data=b"x" * 11)
        self.assertEqual(self.code(hog), "principal_quota_exceeded")
        draft = self.create(data=b"x" * 10)
        self.assertEqual(draft.status_code, 201, draft.text)
        self.assertEqual(self.code(self.create(data=b"y")), "principal_quota_exceeded")
        self.assertEqual(self.create("bob", data=b"y").status_code, 201)
        # The admin can see and release another member's reservation; a coordinator-only member cannot.
        self.member("carol", ["coordinator"])
        self.assertEqual(self.client.delete(self.prefix + f"/records/{draft.json()['id']}", headers=self.auth("carol")).status_code, 404)
        cancelled = self.client.delete(self.prefix + f"/records/{draft.json()['id']}", headers=self.headers)
        self.assertEqual(cancelled.json(), {"state": "cancelled"})
        self.assertEqual(self.client.get(self.prefix, headers=self.headers).json()["allocated_bytes"], 1)
        self.member("bob", [])
        self.assertEqual(self.client.get(self.prefix, headers=self.headers).json()["allocated_bytes"], 0)

    def test_ready_record_withdrawal_protects_references_and_lineage(self):
        base = self.ready()
        self.assertEqual(self.ref(base).status_code, 200)
        self.assertEqual(self.code(self.client.delete(self.prefix + f"/records/{base['id']}", headers=self.headers)), "record_referenced")
        update = self.ready("alice", "training.update", base["id"])
        note = self.ready("alice", "message")
        self.assertEqual(self.code(self.client.delete(self.prefix + f"/records/{note['id']}", headers=self.auth("bob"))), "not_record_owner")
        self.assertEqual(self.client.delete(self.prefix + f"/records/{note['id']}", headers=self.auth("alice")).json(), {"state": "withdrawn"})
        self.assertEqual(self.client.get(self.prefix + f"/records/{note['id']}", headers=self.auth("bob")).status_code, 404)
        second = self.ready("bob", "training.update", base["id"])
        claim = self.claim().json()
        self.assertEqual(self.code(self.client.delete(self.prefix + f"/records/{update['id']}", headers=self.auth("alice"))), "record_claimed")
        self.client.post(self.prefix + f"/claims/{claim['id']}:abandon", headers=self.headers, json={"fence": claim["fence"]})
        self.assertEqual(self.client.delete(self.prefix + f"/records/{update['id']}", headers=self.auth("alice")).json(), {"state": "withdrawn"})
        self.assertEqual(self.code(self.claim()), "insufficient_submissions")
        self.assertEqual(self.client.get(self.prefix + f"/records/{second['id']}", headers=self.auth("bob")).status_code, 200)

    def test_multipart_verification_and_pinned_download(self):
        data = b"a" * (5 * 1024 * 1024) + b"last part"
        record = self.create(data=data).json()
        self.assertEqual(self.code(self.client.post(self.prefix + f"/records/{record['id']}:publish", headers=self.auth("alice"))), "blobs_not_verified")
        blob_id = self.upload(record, data)
        self.assertEqual(tick(self.service)["verified"], 1)
        result = self.client.post(self.prefix + f"/records/{record['id']}:publish", headers=self.auth("alice"))
        self.assertEqual(result.status_code, 200, result.text)
        with self.service.sessions.begin() as session:
            blob = session.get(Blob, blob_id)
        self.s3.put_object(Bucket=self.settings.bucket, Key=blob.key, Body=b"overwrite")
        original = self.s3.get_object(Bucket=self.settings.bucket, Key=blob.key, VersionId=blob.version)["Body"].read()
        self.assertEqual(original, data)
        grant = self.client.post(self.prefix + f"/records/{record['id']}/blobs/{blob_id}:download", headers=self.auth("bob"))
        self.assertEqual(grant.status_code, 200, grant.text)
        self.assertIn("versionId=" + blob.version, grant.json()["url"])
        self.assertEqual(self.code(self.client.delete(self.prefix + f"/uploads/{blob_id}", headers=self.auth("alice"))), "record_not_uploadable")

    def test_digest_failure_and_revoked_membership(self):
        record = self.create(data=b"abc").json()
        blob_id = self.upload(record, b"bad")
        self.assertEqual(tick(self.service)["failed"], 1)
        self.assertEqual(self.client.post(self.prefix + f"/records/{record['id']}:publish", headers=self.auth("alice")).status_code, 409)
        self.member("alice", [])
        self.assertEqual(self.client.post(self.prefix + f"/uploads/{blob_id}/parts:authorize", headers=self.auth("alice"), json={"part_numbers": [1]}).status_code, 404)

    def test_reference_cas_lineage_and_duplicate_retry(self):
        note = self.ready("alice", "message")
        self.assertEqual(self.code(self.ref(note)), "aggregate_kind_mismatch")
        base = self.ready()
        self.assertEqual(self.ref(base).status_code, 200)
        first, second = self.ready(base=base["id"]), self.ready(base=base["id"])
        self.assertEqual(self.ref(first, 1, key="publish").status_code, 200)
        self.assertEqual(self.ref(first, 1, key="publish").status_code, 200)
        self.assertEqual(self.code(self.ref(second, 1)), "reference_changed")
        self.assertEqual(self.code(self.ref(second, 2)), "aggregate_base_mismatch")
        baseless = self.ready()
        self.assertEqual(self.code(self.ref(baseless, 2)), "aggregate_base_mismatch")
        # main only ever names a global model, even when the target builds on the current main; other refs are free.
        configured = self.ready("owner", "configuration", base=first["id"])
        self.assertEqual(self.code(self.ref(configured, 2)), "aggregate_kind_mismatch")
        tagged = self.client.put(self.prefix + "/refs/latest-config", headers={**self.headers, "Idempotency-Key": "cfg", "If-None-Match": "*"},
                                 json={"record_id": configured["id"]})
        self.assertEqual(tagged.status_code, 200, tagged.text)
        self.assertEqual(self.client.get(self.prefix + "/refs/main", headers=self.headers).json(), {"record_id": first["id"], "generation": 2})
        self.assertEqual(self.ref(second, 2, subject="alice").status_code, 403)

    def test_worker_recovers_completion_and_cleans_expired_object(self):
        record = self.create(data=b"hello").json()
        blob_id = self.upload(record, b"hello")
        with self.service.sessions.begin() as session:
            blob = session.get(Blob, blob_id)
            blob.state, blob.version, blob.updated_at = "completing", None, time.time() - 60
        self.assertEqual(tick(self.service)["recovered"], 1)
        self.assertEqual(tick(self.service)["verified"], 1)
        with self.service.sessions.begin() as session:
            session.get(Record, record["id"]).expires_at = 1
            session.get(Blob, blob_id).expires_at = 1
        self.assertEqual(tick(self.service)["cleaned"], 1)
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(Space, self.space).allocated, 0)
        versions = self.s3.list_object_versions(Bucket=self.settings.bucket).get("Versions", [])
        self.assertEqual(versions, [])

    def test_worker_does_not_expire_drafts_while_verifying(self):
        record = self.create(data=b"hello").json()
        self.upload(record, b"hello")
        with self.service.sessions.begin() as session:
            session.get(Record, record["id"]).expires_at = 1
        counts = tick(self.service, concurrency=1)
        self.assertEqual((counts["expired"], counts["verified"]), (0, 1))
        result = self.client.post(self.prefix + f"/records/{record['id']}:publish", headers=self.auth("alice"))
        self.assertEqual(result.status_code, 200, result.text)

    def test_worker_leases_blobs_and_cleanup_backlog_cannot_starve_verification(self):
        # 256 zero-byte reservations from a cancelled record used to fill the entire worker batch.
        empty = hashlib.sha256(b"").hexdigest()
        hog = self.create(attachments=[{"name": f"shard-{n}", "size_bytes": 0, "sha256": empty} for n in range(256)])
        self.assertEqual(hog.status_code, 201, hog.text)
        self.client.delete(self.prefix + f"/records/{hog.json()['id']}", headers=self.auth("alice"))
        record = self.create("bob", data=b"real").json()
        self.upload(record, b"real", "bob")
        calls = []
        original = self.storage.verify
        def slow_verify(blob):
            calls.append(blob.id)
            time.sleep(0.5)
            return original(blob)
        with patch.object(self.storage, "verify", side_effect=slow_verify):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: tick(self.service), range(2)))
        self.assertEqual(sum(r["verified"] for r in results), 1)
        self.assertEqual(len(calls), 1)

    def test_claim_freezes_inputs_and_fences_stale_worker(self):
        base = self.ready()
        self.ref(base)
        updates = [self.ready(p, "training.update", base["id"]) for p in ("alice", "bob")]
        response = self.claim()
        self.assertEqual(response.status_code, 200, response.text)
        claim = response.json()
        self.assertEqual(set(claim["inputs"]), {r["id"] for r in updates})
        self.member("carol", ["coordinator"])
        self.assertEqual(self.code(self.claim("carol")), "claim_busy")
        with self.service.sessions.begin() as session:
            session.get(Claim, claim["id"]).lease_until = 1
        replacement = self.claim().json()
        result = self.ready(base=base["id"], metadata={"input_record_ids": claim["inputs"]})
        route = self.prefix + f"/claims/{claim['id']}:publish"
        self.assertEqual(self.code(self.client.post(route, headers=self.headers, json={"record_id": result["id"], "fence": claim["fence"]})), "claim_fence_changed")
        self.assertEqual(self.code(self.ref(result, 1)), "active_claim_requires_fenced_publication")
        stranger = self.ready(base=base["id"], metadata={"input_record_ids": [updates[0]["id"], "rec_other"]})
        self.assertEqual(self.code(self.client.post(route, headers=self.headers, json={"record_id": stranger["id"], "fence": replacement["fence"]})), "claim_inputs_mismatch")
        self.assertEqual(self.client.post(route, headers=self.headers, json={"record_id": result["id"], "fence": replacement["fence"]}).status_code, 200)
        self.assertEqual(self.client.post(route, headers=self.headers, json={"record_id": result["id"], "fence": replacement["fence"]}).status_code, 200)
        self.assertEqual(self.code(self.client.post(route, headers=self.headers, json={"record_id": stranger["id"], "fence": replacement["fence"]})), "claim_completed")

    def test_claim_abandon_newest_per_participant_and_subset_publication(self):
        base = self.ready()
        self.ref(base)
        old = self.ready("alice", "training.update", base["id"])
        new = self.ready("alice", "training.update", base["id"])
        bob = self.ready("bob", "training.update", base["id"])
        self.member("carol", ["coordinator", "reader"])
        claim = self.claim().json()
        self.assertEqual((set(claim["inputs"]), claim["superseded"]), ({new["id"], bob["id"]}, [old["id"]]))
        self.assertEqual(self.code(self.client.get(self.prefix + f"/claims/{claim['id']}", headers=self.auth("carol"))), "claim_held_by_other")
        self.assertEqual(self.code(self.client.post(self.prefix + f"/claims/{claim['id']}:abandon", headers=self.auth("carol"), json={})), "claim_held_by_other")
        self.assertEqual(self.code(self.client.post(self.prefix + f"/claims/{claim['id']}:abandon", headers=self.headers, json={"fence": 9})), "claim_fence_changed")
        abandoned = self.client.post(self.prefix + f"/claims/{claim['id']}:abandon", headers=self.headers, json={"fence": claim["fence"]})
        self.assertEqual(abandoned.json()["state"], "abandoned")
        # After abandonment main is free again, and a coordinator may choose explicit inputs.
        explicit = self.claim("carol", inputs=[old["id"], bob["id"]])
        self.assertEqual(explicit.status_code, 200, explicit.text)
        # Another acquisition, even by the same identity, cannot share this run's fence.
        repeated = self.claim("carol", inputs=[old["id"], new["id"]])
        self.assertEqual((repeated.status_code, self.code(repeated)), (409, "claim_busy"))
        self.assertEqual(self.code(self.claim()), "claim_busy")
        # The admin can abandon another holder's claim without knowing its fence.
        self.assertEqual(self.client.post(self.prefix + f"/claims/{explicit.json()['id']}:abandon", headers=self.headers, json={}).status_code, 200)
        self.assertEqual(self.code(self.claim("carol", inputs=[old["id"], "rec_missing"])), "claim_inputs_invalid")
        explicit = self.claim("carol", inputs=[old["id"], bob["id"]])
        subset = self.ready(base=base["id"], metadata={"input_record_ids": [bob["id"]]})
        route = self.prefix + f"/claims/{explicit.json()['id']}:publish"
        self.assertEqual(self.code(self.client.post(route, headers=self.headers, json={"record_id": subset["id"], "fence": 1})), "claim_held_by_other")
        result = self.client.post(route, headers=self.auth("carol"), json={"record_id": subset["id"], "fence": 1})
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(self.client.get(self.prefix + "/refs/main", headers=self.headers).json()["record_id"], subset["id"])
        # An expired claim no longer blocks a plain fenced-by-generation publication.
        with self.service.sessions.begin() as session:
            session.get(Claim, explicit.json()["id"]).result_id = None
            session.get(Claim, explicit.json()["id"]).lease_until = 1
        following = self.ready(base=subset["id"])
        self.assertEqual(self.ref(following, 2).status_code, 200)

    def test_claim_is_idempotent_for_holder_listable_and_persisted_by_adapter(self):
        base = self.ready()
        self.ref(base)
        for participant in ("alice", "bob"):
            self.ready(participant, "training.update", base["id"])
        self.member("carol", ["coordinator", "reader"])
        self.member("dave", ["admin"])
        claim = self.claim(key="same-acquisition").json()
        again = self.claim(key="same-acquisition")
        self.assertEqual(again.status_code, 200, again.text)
        self.assertEqual((again.json()["id"], again.json()["fence"]), (claim["id"], claim["fence"]))
        busy = self.claim("carol")
        self.assertEqual((busy.status_code, self.code(busy), busy.json()["claim_id"]), (409, "claim_busy", claim["id"]))
        self.assertEqual(busy.json()["lease_until"], claim["lease_until"])
        with self.assertRaises(ExchangeError) as refused:
            self.sdk("carol").acquire_claim(self.space, lease_seconds=60)
        self.assertEqual(refused.exception.details["claim_id"], claim["id"])
        listing = self.client.get(self.prefix + "/claims", headers=self.auth("carol"))
        self.assertEqual([(c["id"], c["holder"], c["workflow"]) for c in listing.json()["items"]], [(claim["id"], claim["holder"], "fedavg")])
        self.assertEqual(self.client.get(self.prefix + "/claims", headers=self.auth("dave")).status_code, 200)
        self.assertEqual(self.client.get(self.prefix + "/claims", headers=self.auth("alice")).status_code, 403)
        self.assertEqual(self.client.get(self.prefix + "/claims", params={"base_record_id": "rec_other"}, headers=self.headers).json()["items"], [])
        self.assertEqual(self.sdk("carol").claims(self.space, workflow="other"), [])
        self.assertEqual([c["id"] for c in self.sdk("carol").claims(self.space, workflow="fedavg", base_record_id=base["id"])], [claim["id"]])
        # An expired lease without a result leaves the active listing but stays visible with active=false.
        with self.service.sessions.begin() as session:
            session.get(Claim, claim["id"]).lease_until = 1
        self.assertEqual(self.sdk("carol").claims(self.space), [])
        self.assertEqual([c["id"] for c in self.sdk("carol").claims(self.space, active=False)], [claim["id"]])
        with self.service.sessions.begin() as session:
            session.get(Claim, claim["id"]).lease_until = claim["lease_until"]
        result = self.ready(base=base["id"], metadata={"input_record_ids": claim["inputs"]})
        published = self.client.post(self.prefix + f"/claims/{claim['id']}:publish", headers=self.headers, json={"record_id": result["id"], "fence": claim["fence"]})
        self.assertEqual(published.status_code, 200, published.text)
        self.assertEqual(self.sdk("owner").claims(self.space), [])
        self.assertEqual([c["result_record_id"] for c in self.sdk("owner").claims(self.space, active=False)], [result["id"]])
        # The adapter persists the held claim in the round's output directory and clears it once released.
        for participant in ("alice", "bob"):
            self.ready(participant, "training.update", result["id"])
        root = Path(self.temp.name) / "round"
        root.mkdir()
        owner = self.store("owner")
        owner.resolve_revision(self.space, "main")
        candidates = owner.claim_submissions(self.space, state_dir=root)
        saved = json.loads((root / "exchange-claim.json").read_text())
        self.assertEqual((saved["space"], saved["claim_id"], saved["fence"]), (self.space, owner.claim["id"], owner.claim["fence"]))
        self.assertEqual(len(candidates), 2)
        # A restarted coordinator pointed at the same directory resumes the persisted claim by ID, without acquiring.
        resumed = self.store("owner")
        resumed.resolve_revision(self.space, "main")
        with patch.object(resumed.client, "request", wraps=resumed.client.request) as spy:
            resumed.claim_submissions(self.space, state_dir=root)
        self.assertEqual(resumed.claim["id"], saved["claim_id"])
        self.assertEqual([c.args for c in spy.call_args_list if "/claims" in c.args[1]],
                         [("GET", f"{self.prefix}/claims/{saved['claim_id']}")])
        # An abandon that never reaches the server keeps the persisted ID for a manual abandon.
        with patch.object(resumed.client, "request", side_effect=ExchangeError(503, "connection_failed")):
            with self.assertRaises(ExchangeError):
                resumed.abandon_claim(self.space)
        self.assertTrue((root / "exchange-claim.json").exists())
        self.assertEqual([c["id"] for c in self.sdk("owner").claims(self.space)], [saved["claim_id"]])
        # Once the persisted claim is no longer active an explicit --claim-id still fails, but a stale state file
        # is discarded in favour of a fresh acquisition, which here re-acquires the expired claim with a new fence.
        with self.service.sessions.begin() as session:
            session.get(Claim, saved["claim_id"]).lease_until = 1
        fresh = self.store("owner")
        fresh.resolve_revision(self.space, "main")
        with self.assertRaises(ExchangeError) as stale:
            fresh.claim_submissions(self.space, claim_id=saved["claim_id"], state_dir=root)
        self.assertEqual(stale.exception.code, "claim_not_active")
        self.assertTrue((root / "exchange-claim.json").exists())
        fresh.claim_submissions(self.space, state_dir=root)
        rewritten = json.loads((root / "exchange-claim.json").read_text())
        self.assertEqual((rewritten["claim_id"], rewritten["fence"], fresh.claim["fence"]), (saved["claim_id"], 2, 2))
        fresh.abandon_claim(self.space)
        self.assertFalse((root / "exchange-claim.json").exists())
        self.assertEqual(self.sdk("owner").claims(self.space), [])

    def test_participant_rebinding_invalidates_drafts_and_stale_updates(self):
        base = self.ready()
        self.ref(base)
        self.member("erin", ["contributor", "reader"], "erin")
        alice_update = self.ready("alice", "training.update", base["id"])
        bob_update = self.ready("bob", "training.update", base["id"])
        erin_update = self.ready("erin", "training.update", base["id"])
        # A ready update whose creator was rebound is skipped by automatic freezing and refused as an explicit input.
        self.member("alice", ["contributor", "reader"], "alice-2")
        claim = self.claim()
        self.assertEqual(claim.status_code, 200, claim.text)
        self.assertEqual((set(claim.json()["inputs"]), claim.json()["skipped"]), ({bob_update["id"], erin_update["id"]}, [alice_update["id"]]))
        self.client.post(self.prefix + f"/claims/{claim.json()['id']}:abandon", headers=self.headers, json={"fence": claim.json()["fence"]})
        blocked = self.claim(inputs=[alice_update["id"], bob_update["id"]])
        self.assertEqual((blocked.status_code, self.code(blocked), blocked.json()["record_id"]), (409, "participant_binding_changed", alice_update["id"]))
        # A REST revocation that keeps the participant string (roles []) also drops the member's ready update.
        self.member("bob", [], "bob")
        revoked = self.claim()
        self.assertEqual((self.code(revoked), set(revoked.json()["skipped"])),
                         ("insufficient_submissions", {alice_update["id"], bob_update["id"]}))
        blocked = self.claim(inputs=[bob_update["id"], erin_update["id"]])
        self.assertEqual((blocked.status_code, self.code(blocked), blocked.json()["record_id"]), (409, "participant_binding_changed", bob_update["id"]))
        self.member("bob", ["contributor", "reader"], "bob")
        # Too few attributable updates fail the acquisition and name the ones that were skipped.
        self.member("erin", ["contributor", "reader"], None)
        short = self.claim()
        self.assertEqual((self.code(short), set(short.json()["skipped"])), ("insufficient_submissions", {alice_update["id"], erin_update["id"]}))
        self.member("alice", ["contributor", "reader"], "alice")
        self.member("erin", ["contributor", "reader"], "erin")
        # A rebinding after freezing is caught at publication, and re-acquiring the expired claim drops the update.
        claim = self.claim().json()
        self.assertEqual(set(claim["inputs"]), {alice_update["id"], bob_update["id"], erin_update["id"]})
        self.member("alice", ["contributor", "reader"], "alice-2")
        result = self.ready(base=base["id"], metadata={"input_record_ids": claim["inputs"]})
        route = self.prefix + f"/claims/{claim['id']}:publish"
        stale = self.client.post(route, headers=self.headers, json={"record_id": result["id"], "fence": claim["fence"]})
        self.assertEqual((stale.status_code, self.code(stale), stale.json()["record_id"]), (409, "participant_binding_changed", alice_update["id"]))
        with self.service.sessions.begin() as session:
            session.get(Claim, claim["id"]).lease_until = 1
        reacquired = self.claim().json()
        self.assertEqual((reacquired["fence"], set(reacquired["inputs"]), reacquired["skipped"]),
                         (2, {bob_update["id"], erin_update["id"]}, [alice_update["id"]]))
        self.assertEqual(self.code(self.client.post(route, headers=self.headers, json={"record_id": result["id"], "fence": 2})), "claim_inputs_mismatch")
        subset = self.ready(base=base["id"], metadata={"input_record_ids": reacquired["inputs"]})
        self.assertEqual(self.client.post(route, headers=self.headers, json={"record_id": subset["id"], "fence": 2}).status_code, 200)
        # Rebinding or clearing the binding during the draft window cancels only the member's participant-bound
        # drafts and releases their quota; other kinds and a first-time binding leave drafts alone.
        self.member("alice", ["contributor", "reader"], "alice")
        draft = self.create("alice", "training.update", base["id"], data=b"abc").json()
        note = self.create("alice", "message", data=b"xy").json()
        self.member("alice", ["contributor", "reader"], "alice-2")
        states = {r: self.client.get(self.prefix + f"/records/{r}", headers=self.auth("alice")).json()["state"] for r in (draft["id"], note["id"])}
        self.assertEqual(states, {draft["id"]: "cancelled", note["id"]: "draft"})
        self.assertEqual(self.client.get(self.prefix, headers=self.headers).json()["allocated_bytes"], 2)
        checkpoint = self.create("owner", "model.global", subset["id"], data=b"ckpt").json()
        self.member("owner", ["admin", "coordinator", "reader"], "owner-site")
        self.assertEqual(self.client.get(self.prefix + f"/records/{checkpoint['id']}", headers=self.headers).json()["state"], "draft")
        draft = self.create("bob", "training.update", base["id"]).json()
        self.member("bob", ["contributor", "reader"], None)
        self.assertEqual(self.code(self.client.post(self.prefix + f"/records/{draft['id']}:publish", headers=self.auth("bob"))), "record_expired")
        self.assertEqual(self.code(self.create("bob", "training.update", base["id"])), "participant_and_base_required")
        # A role change that keeps the binding leaves drafts alone.
        bound_draft = self.create("alice", "training.update", base["id"]).json()
        self.member("alice", ["contributor", "reader", "coordinator"], "alice-2")
        states = {r: self.client.get(self.prefix + f"/records/{r}", headers=self.auth("alice")).json()["state"] for r in (bound_draft["id"], note["id"])}
        self.assertEqual(states, {bound_draft["id"]: "draft", note["id"]: "draft"})
        # Publish itself re-validates the binding even if the membership row changed without cancellation.
        self.member("bob", ["contributor", "reader"], "bob")
        draft = self.create("bob", "training.update", base["id"]).json()
        bob_id = principal_id(self.settings.issuer, "bob")
        with self.service.sessions.begin() as session:
            session.get(Member, (self.space, bob_id)).participant = "bob-2"
        stale = self.client.post(self.prefix + f"/records/{draft['id']}:publish", headers=self.auth("bob"))
        self.assertEqual((stale.status_code, self.code(stale)), (409, "participant_binding_changed"))
        with self.service.sessions.begin() as session:
            session.get(Member, (self.space, bob_id)).participant = "bob"
        self.assertEqual(self.client.post(self.prefix + f"/records/{draft['id']}:publish", headers=self.auth("bob")).status_code, 200)

    def test_abort_upload_only_before_completion_and_upload_id_cleared(self):
        record = self.create(data=b"abc").json()
        blob_id = record["attachments"][0]["id"]
        route = self.prefix + f"/uploads/{blob_id}"
        self.upload(record, b"abc")
        with self.service.sessions.begin() as session:
            blob = session.get(Blob, blob_id)
            self.assertEqual((blob.state, blob.upload_id), ("verifying", None))
        self.assertEqual(self.code(self.client.delete(route, headers=self.auth("alice"))), "upload_already_completed")
        # A completion whose response was lost is protected from a stale abort until the worker settles it.
        with self.service.sessions.begin() as session:
            blob = session.get(Blob, blob_id)
            blob.state, blob.version, blob.upload_id, blob.updated_at = "completing", None, "stale-upload", time.time() - 60
        self.assertEqual(self.code(self.client.delete(route, headers=self.auth("alice"))), "upload_completing")
        self.assertEqual(tick(self.service)["recovered"], 1)
        with self.service.sessions.begin() as session:
            self.assertIsNone(session.get(Blob, blob_id).upload_id)
        self.assertEqual(tick(self.service)["verified"], 1)
        self.assertEqual(self.code(self.client.delete(route, headers=self.auth("alice"))), "upload_already_completed")
        self.assertEqual(self.client.post(self.prefix + f"/records/{record['id']}:publish", headers=self.auth("alice")).status_code, 200)
        # Unfinished uploads can still be aborted, idempotently; the record then needs a new attempt.
        other = self.create("bob", data=b"xyz").json()
        other_route = self.prefix + f"/uploads/{other['attachments'][0]['id']}"
        self.assertEqual(self.client.delete(other_route, headers=self.auth("bob")).json(), {"state": "aborted"})
        self.assertEqual(self.client.delete(other_route, headers=self.auth("bob")).json(), {"state": "aborted"})
        self.assertEqual(self.code(self.client.post(self.prefix + f"/records/{other['id']}:publish", headers=self.auth("bob"))), "blobs_not_verified")
        # A transfer the worker already failed is terminal: it cannot be turned into an abort either.
        failed = self.create("bob", data=b"nope").json()
        with self.service.sessions.begin() as session:
            session.get(Blob, failed["attachments"][0]["id"]).state = "failed"
        refused = self.client.delete(self.prefix + f"/uploads/{failed['attachments'][0]['id']}", headers=self.auth("bob"))
        self.assertEqual((refused.status_code, self.code(refused)), (409, "upload_not_open"))

    def test_bootstrap_admin_break_glass_and_last_admin_guard(self):
        owner_id, carol_id = (principal_id(self.settings.issuer, s) for s in ("owner", "carol"))
        self.member("carol", ["admin"])
        # Another admin can revoke the bootstrap admin; the space then has one admin left.
        revoked = self.client.put(self.prefix + f"/members/{owner_id}", headers=self.auth("carol"), json={"subject": "owner", "roles": [], "participant": None})
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertEqual(self.client.get(self.prefix + "/me", headers=self.headers).status_code, 404)
        self.assertEqual(self.client.get(self.prefix + "/records", headers=self.headers).status_code, 404)
        # Nobody can remove or demote the last admin, not even the bootstrap admin from outside the space.
        demoted = self.client.put(self.prefix + f"/members/{carol_id}", headers=self.headers, json={"subject": "carol", "roles": ["reader"], "participant": None})
        self.assertEqual((demoted.status_code, self.code(demoted)), (409, "last_admin"))
        self.assertEqual(self.code(self.client.put(self.prefix + f"/members/{carol_id}", headers=self.auth("carol"),
                                                   json={"subject": "carol", "roles": [], "participant": None})), "cannot_remove_own_admin_role")
        # Break-glass: only the configured bootstrap admin can inspect and repair membership without being a member.
        members = self.client.get(self.prefix + "/members", headers=self.headers)
        self.assertEqual(members.status_code, 200, members.text)
        self.assertEqual({m["principal_id"]: m["roles"] for m in members.json()["items"]}[carol_id], ["admin"])
        self.assertEqual(self.client.get(self.prefix + "/members", headers=self.auth("alice")).status_code, 403)
        self.assertEqual(self.client.get(self.prefix + "/members", headers=self.auth("stranger")).status_code, 404)
        # The revoked bootstrap admin holds no admin role, so re-adding itself with lesser roles is no self-demotion,
        # and break-glass keeps applying while it is a member without the admin role.
        reader = self.client.put(self.prefix + f"/members/{owner_id}", headers=self.headers,
                                 json={"subject": "owner", "roles": ["reader"], "participant": None})
        self.assertEqual(reader.status_code, 200, reader.text)
        self.assertEqual(self.client.get(self.prefix + "/me", headers=self.headers).json()["roles"], ["reader"])
        self.assertEqual(self.client.get(self.prefix + "/members", headers=self.headers).status_code, 200)
        restored = self.client.put(self.prefix + f"/members/{owner_id}", headers=self.headers,
                                   json={"subject": "owner", "roles": ["admin", "coordinator", "reader"], "participant": None})
        self.assertEqual(restored.status_code, 200, restored.text)
        self.assertEqual(self.client.get(self.prefix + "/me", headers=self.headers).json()["roles"], ["admin", "coordinator", "reader"])
        # Each break-glass use that commits is audited; the refused demotion rolled back with its event.
        def grants():
            with self.service.sessions.begin() as session:
                return session.query(Event).filter_by(space_id=self.space, kind="member.bootstrap_grant").count()
        self.assertEqual(grants(), 4)
        # Regular admins (including the restored bootstrap admin) list members without break-glass.
        self.assertEqual(self.client.get(self.prefix + "/members", headers=self.auth("carol")).status_code, 200)
        self.assertEqual(self.client.get(self.prefix + "/members", headers=self.headers).status_code, 200)
        self.assertEqual(self.client.put(self.prefix + f"/members/{carol_id}", headers=self.headers,
                                         json={"subject": "carol", "roles": ["reader"], "participant": None}).status_code, 200)
        self.assertEqual(self.code(self.client.put(self.prefix + f"/members/{owner_id}", headers=self.headers,
                                                   json={"subject": "owner", "roles": ["reader"], "participant": None})), "cannot_remove_own_admin_role")
        self.assertEqual(grants(), 4)

    def test_concurrent_identical_space_creation_replays_one_result(self):
        body = {"name": "shared", "tenant": "tenant-3"}
        headers = {**self.headers, "Idempotency-Key": "shared-key"}
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(lambda _: self.client.post("/v1/spaces", headers=headers, json=body), range(2)))
        self.assertEqual([r.status_code for r in responses], [201, 201])
        self.assertEqual(len({r.json()["id"] for r in responses}), 1)
        # Force the race SQLite serializes away: the lookup misses although the key was committed meanwhile.
        original = self.service.stored_operation
        misses = {"remaining": 1}
        def racing_lookup(session, identifier):
            if misses["remaining"]:
                misses["remaining"] -= 1
                return None
            return original(session, identifier)
        with patch.object(self.service, "stored_operation", side_effect=racing_lookup):
            replayed = self.client.post("/v1/spaces", headers=headers, json=body)
        self.assertEqual((replayed.status_code, replayed.json()["id"]), (201, responses[0].json()["id"]), replayed.text)
        self.assertEqual(misses["remaining"], 0)
        with self.service.sessions.begin() as session:
            self.assertEqual(session.query(Space).count(), 2)
        self.assertEqual(self.code(self.client.post("/v1/spaces", headers=headers, json={"name": "other", "tenant": "tenant-3"})), "idempotency_key_reused")

    def test_pagination_and_event_visibility(self):
        for n in range(3):
            self.ready("alice", "message", metadata={"n": n})
        response = self.client.get(self.prefix + "/records?limit=2", headers=self.auth("bob")).json()
        self.assertEqual(len(response["items"]), 2)
        next_page = self.client.get(self.prefix + "/records", params={"cursor": response["next_cursor"]}, headers=self.auth("bob")).json()
        self.assertEqual(len(next_page["items"]), 1)
        self.assertEqual(len(self.client.get(self.prefix + "/events", headers=self.auth("bob")).json()["items"]), 3)
        base = self.ready()
        self.ready("alice", "training.update", base["id"])
        events = self.client.get(self.prefix + "/events", headers=self.auth("bob")).json()["items"]
        self.assertEqual(len(events), 4)

    def test_request_limits_safe_paths_and_missing_base(self):
        large = self.create(metadata={"large": "x" * METADATA_LIMIT_BYTES})
        self.assertEqual((large.status_code, self.code(large), large.json()["limit"]), (422, "metadata_too_large", METADATA_LIMIT_BYTES))
        self.assertGreater(large.json()["size"], METADATA_LIMIT_BYTES)
        # The SDK refuses oversized metadata before any draft exists, with the same code and a readable message.
        sdk = self.sdk("alice")
        with patch.object(sdk, "request", wraps=sdk.request) as spy, self.assertRaises(ExchangeError) as refused:
            sdk.put_record(self.space, kind="message", metadata={"large": "x" * METADATA_LIMIT_BYTES})
        spy.assert_not_called()
        self.assertEqual((refused.exception.code, refused.exception.details["limit"]), ("metadata_too_large", METADATA_LIMIT_BYTES))
        self.assertIn(f"at most {METADATA_LIMIT_BYTES}", str(refused.exception))
        response = self.client.post(self.prefix + "/records", headers=self.auth("alice"), content=b"x" * (1024 * 1024 + 1))
        self.assertEqual(response.status_code, 413)
        self.assertTrue(response.headers.get("X-Request-ID"))
        body = {"kind": "message", "attachments": [{"name": "../escape", "size_bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}]}
        self.assertEqual(self.client.post(self.prefix + "/records", headers={**self.auth("alice"), "Idempotency-Key": "escape"}, json=body).status_code, 422)
        empty = hashlib.sha256(b"").hexdigest()
        collision = self.create(attachments=[{"name": "a", "size_bytes": 0, "sha256": empty}, {"name": "a/b", "size_bytes": 0, "sha256": empty}])
        self.assertEqual(self.code(collision), "attachment_name_collides_with_directory")
        self.assertEqual(self.create(base="rec_nonexistent").status_code, 404)

    def set_rules(self, rules, subject="owner"):
        space = self.client.get(self.prefix, headers=self.headers)
        return self.client.patch(self.prefix, headers={**self.auth(subject), "If-Match": space.headers["ETag"]}, json={"rules": rules})

    def test_rule_changes_apply_to_existing_records_and_keep_the_profile(self):
        base = self.ready()
        update = self.ready("alice", "training.update", base["id"])
        route = self.prefix + f"/records/{update['id']}"
        self.assertEqual(self.client.get(route, headers=self.auth("bob")).status_code, 404)
        rules = self.client.get(self.prefix, headers=self.headers).json()["rules"]
        rules["training.update"]["shared"] = True
        self.assertEqual(self.set_rules(rules).status_code, 200)
        # A changed shared flag applies to the records that already exist, not only to future ones.
        self.assertEqual(self.client.get(route, headers=self.auth("bob")).status_code, 200)
        listed = self.client.get(self.prefix + "/records", params={"kind": "training.update"}, headers=self.auth("bob")).json()["items"]
        self.assertEqual([r["id"] for r in listed], [update["id"]])
        with self.service.sessions.begin() as session:
            events = [e.data for e in session.query(Event).filter_by(space_id=self.space, kind="space.rules_changed")]
        self.assertEqual(events, [{"added": [], "removed": [], "shared_changed": ["training.update"]}])
        rules["training.update"]["shared"] = False
        self.assertEqual(self.set_rules(rules).status_code, 200)
        self.assertEqual(self.client.get(route, headers=self.auth("bob")).status_code, 404)
        self.assertEqual(self.client.get(self.prefix + "/records", params={"kind": "training.update"}, headers=self.auth("bob")).json()["items"], [])
        # Custom rules may add kinds but cannot drop the FedAvg profile kinds or make main unresolvable.
        refused = self.set_rules({k: v for k, v in rules.items() if k != "model.global"})
        self.assertEqual((refused.status_code, self.code(refused), refused.json()["kind"]), (422, "profile_kind_required", "model.global"))
        private_global = json.loads(json.dumps(rules))
        private_global["model.global"]["shared"] = False
        refused = self.set_rules(private_global)
        self.assertEqual((self.code(refused), refused.json()["reason"]), ("profile_kind_incompatible", "must_be_shared"))
        closed = json.loads(json.dumps(rules))
        closed["model.global"]["metadata_schema"] = {"type": "object", "additionalProperties": False, "properties": {"round": {"type": "integer"}}}
        self.assertEqual(self.code(self.set_rules(closed)), "profile_kind_incompatible")
        closed["model.global"]["metadata_schema"]["properties"]["input_record_ids"] = {"type": "array"}
        closed["model.global"]["metadata_schema"]["properties"]["hf2l_files"] = {"type": "object"}
        closed["telemetry"] = {"creators": ["contributor"], "shared": True, "metadata_schema": {}}
        self.assertEqual(self.set_rules(closed).status_code, 200)
        created = self.client.post("/v1/spaces", headers={**self.headers, "Idempotency-Key": "no-profile"},
                                   json={"name": "partial", "tenant": "tenant-9", "rules": {"message": rules["message"], "model.global": rules["model.global"]}})
        self.assertEqual((created.status_code, self.code(created), created.json()["kind"]), (422, "profile_kind_required", "training.update"))

    def test_metadata_schema_references_are_local_only_and_never_fetched(self):
        rules = self.client.get(self.prefix, headers=self.headers).json()["rules"]
        def with_schema(schema):
            return {**rules, "message": {**rules["message"], "metadata_schema": schema}}
        local = {"$schema": "https://json-schema.org/draft/2020-12/schema", "description": "no remote $ref in here",
                 "$defs": {"count": {"type": "integer"}}, "type": "object", "properties": {"n": {"$ref": "#/$defs/count"}},
                 "examples": [{"$ref": "https://example.com/data-not-a-reference"}]}
        self.assertEqual(self.set_rules(with_schema(local)).status_code, 200)
        self.assertEqual(self.code(self.create(metadata={"n": "x"})), "metadata_schema_mismatch")
        self.assertEqual(self.create(metadata={"n": 1}).status_code, 201)
        remote = ({"$ref": "https://attacker.example/s.json"}, {"$dynamicRef": "https://attacker.example/s.json"},
                  {"$id": "https://attacker.example/root", "type": "object"}, {"properties": {"x": {"$recursiveRef": "other.json"}}})
        for schema in remote:
            refused = self.set_rules(with_schema(schema))
            self.assertEqual((refused.status_code, self.code(refused), refused.json()["kind"]), (422, "external_schema_references_not_supported", "message"), schema)
        created = self.client.post("/v1/spaces", headers={**self.headers, "Idempotency-Key": "remote"},
                                   json={"name": "remote", "tenant": "tenant-9", "rules": with_schema(remote[1])})
        self.assertEqual(self.code(created), "external_schema_references_not_supported")
        # A rule that bypassed validation, or names a missing local target, yields 422 for its records: no 500, no fetch.
        for broken in (remote[1], {"$ref": "#/$defs/missing"}):
            with self.service.sessions.begin() as session:
                session.get(Space, self.space).rules = with_schema(broken)
            with patch("urllib.request.urlopen") as fetch:
                response = self.create(metadata={"n": 1})
            fetch.assert_not_called()
            self.assertEqual((response.status_code, self.code(response)), (422, "metadata_schema_unresolvable"), broken)

    def test_reserved_and_colliding_attachment_names(self):
        empty = hashlib.sha256(b"").hexdigest()
        def attempt(names, metadata=None):
            return self.create(attachments=[{"name": n, "size_bytes": 0, "sha256": empty} for n in names], metadata=metadata)
        for names, metadata in (([SUBMISSION_FILE], None), (["FedAvg_Round.json/part-1"], None),
                                (["notes/a"], {"hf2l_files": {"notes": {}}}), (["Notes"], {"hf2l_files": {"notes": {}}})):
            refused = attempt(names, metadata)
            self.assertEqual((refused.status_code, self.code(refused), refused.json()["name"]), (422, "attachment_name_reserved", names[0]), names)
        self.assertEqual(self.code(attempt(["Model.bin", "model.bin"])), "duplicate_attachment_name")
        self.assertEqual(self.code(attempt(["a", "A/b"])), "attachment_name_collides_with_directory")
        draft = attempt(["model.bin"])
        self.assertEqual(draft.status_code, 201, draft.text)
        shadowing = self.client.patch(self.prefix + f"/records/{draft.json()['id']}", headers={**self.auth("alice"), "If-Match": '"1"'},
                                      json={"metadata": {"hf2l_files": {"model.bin": {}}}})
        self.assertEqual(self.code(shadowing), "attachment_name_reserved")
        # The adapter never produces such names either.
        folder = Path(self.temp.name) / "upload"
        folder.mkdir()
        (folder / "Fedavg_Submission.json").write_bytes(b"{}")
        with self.assertRaises(ValueError):
            self.store("alice").publish_submission(self.space, folder, ["Fedavg_Submission.json"], participant="alice",
                                                   source_round=0, base_revision="rec_x", submission_revision=None)
        # A record accepted before this validation is refused by the adapter with a ValueError naming the record,
        # instead of a filesystem error, so the owner's skip logic applies; manifest-only reads touch no attachment.
        base = self.ready()
        manifest = {"participant": "alice", "base_revision": base["id"]}
        record = self.create("alice", "training.update", base["id"], data=b"weights", metadata={"hf2l_files": {SUBMISSION_FILE: manifest}}).json()
        self.upload(record, b"weights")
        self.assertEqual(tick(self.service)["verified"], 1)
        self.assertEqual(self.client.post(self.prefix + f"/records/{record['id']}:publish", headers=self.auth("alice")).status_code, 200)
        owner = self.store("owner")
        target = Path(self.temp.name) / "manifest-only"
        owner.download_snapshot(self.space, record["id"], target, allow_patterns=SUBMISSION_FILE)
        self.assertEqual(sorted(p.name for p in target.iterdir()), [SUBMISSION_FILE])
        with patch.object(owner.client, "download_attachment", side_effect=FileExistsError("model.bin")):
            with self.assertRaises(ValueError) as failed:
                owner.download_snapshot(self.space, record["id"], Path(self.temp.name) / "full")
        self.assertIn(record["id"], str(failed.exception))
        with self.service.sessions.begin() as session:
            session.get(Blob, record["attachments"][0]["id"]).name = SUBMISSION_FILE
        with self.assertRaises(ValueError) as shadowed:
            owner.download_snapshot(self.space, record["id"], Path(self.temp.name) / "shadowed", allow_patterns=SUBMISSION_FILE)
        self.assertIn(record["id"], str(shadowed.exception))
        self.assertFalse((Path(self.temp.name) / "shadowed").exists())
        with self.assertRaises(ValueError):
            ExchangeStore._check_layout({"id": "rec_old", "attachments": [{"name": "a"}, {"name": "A/b"}]}, {})

    def test_large_round_manifest_is_bounded_inline_with_complete_attachment(self):
        errors = self.background_worker()
        root = Path(self.temp.name)
        owner = self.store("owner")
        initial = root / "initial"
        initial.mkdir()
        write_json(initial / "config.json", {"model_type": "test"})
        first = {"schema_version": 2, "backend": "exchange", "round": 0}
        write_json(initial / ROUND_FILE, first)
        base = owner.initialize_repository(self.space, initial, private=True).revision
        # A manifest that fits stays inline unchanged and adds no attachment.
        initial_record = owner.client.get_record(self.space, base)
        self.assertEqual(([a["name"] for a in initial_record["attachments"]], initial_record["metadata"]["hf2l_files"][ROUND_FILE]), (["config.json"], first))
        owner.resolve_revision(self.space, "main")
        aggregate = root / "aggregate"
        aggregate.mkdir()
        write_json(aggregate / "config.json", {"model_type": "test"})
        submissions = [{"participant": f"site-{n}", "author": "a" * 64, "submission_revision": f"rec_{n:032x}", "resolved_revision": f"rec_{n:032x}",
                        "num_examples": n + 1, "coefficient": 1 / 40, "training": {"loss_curve": list(range(500)), "epochs": 3, "note": "n" * 300}}
                       for n in range(40)]
        full = {"schema_version": 2, "backend": "exchange", "round": 1, "base_revision": base, "checkpoint_files": ["config.json"],
                "evaluation": {"accuracy": 0.9, "confusion": [[1, 2], [3, 4]]}, "submissions": submissions}
        write_json(aggregate / ROUND_FILE, full)
        self.assertGreater(metadata_size({"hf2l_files": {ROUND_FILE: full}}), METADATA_LIMIT_BYTES)
        revision = owner.publish_aggregate(self.space, aggregate, ["config.json", ROUND_FILE], expected_base=base, next_round=1, tag=None).revision
        record = owner.client.get_record(self.space, revision)
        self.assertLessEqual(metadata_size(record["metadata"]), INLINE_METADATA_BUDGET)
        inline = record["metadata"]["hf2l_files"][ROUND_FILE]
        self.assertEqual((inline["round"], inline["base_revision"], inline["complete_manifest"], inline["evaluation"]), (1, base, ROUND_FULL_FILE, {"accuracy": 0.9}))
        self.assertEqual([s["participant"] for s in inline["submissions"]], [s["participant"] for s in submissions])
        self.assertEqual({k: inline["submissions"][3][k] for k in ("resolved_revision", "num_examples", "coefficient")},
                         {"resolved_revision": submissions[3]["resolved_revision"], "num_examples": 4, "coefficient": 1 / 40})
        self.assertEqual((inline["submissions"][3]["training"]["epochs"], "loss_curve" in inline["submissions"][3]["training"]), (3, False))
        self.assertEqual([a["name"] for a in record["attachments"]], ["config.json", ROUND_FULL_FILE])
        # Readers of the round record keep working: metadata-only reads see the bounded copy, full reads get both.
        only = root / "manifest-only"
        owner.download_snapshot(self.space, revision, only, allow_patterns=ROUND_FILE)
        self.assertEqual((sorted(p.name for p in only.iterdir()), json.loads((only / ROUND_FILE).read_text())["round"]), ([ROUND_FILE], 1))
        target = root / "download"
        owner.download_snapshot(self.space, revision, target)
        self.assertEqual((json.loads((target / ROUND_FULL_FILE).read_text()), json.loads((target / ROUND_FILE).read_text())), (full, inline))
        self.assertEqual(owner.resolve_revision(self.space, "main"), revision)
        self.assertEqual(errors, [])

    def test_worker_recovers_lost_initiation(self):
        record = self.create(data=b"hello").json()
        with self.service.sessions.begin() as session:
            blob = session.get(Blob, record["attachments"][0]["id"])
            blob.state, blob.updated_at = "initiating", time.time() - 60
            provider_id = self.storage.start(blob.key)
        self.assertEqual(tick(self.service)["recovered"], 1)
        with self.service.sessions.begin() as session:
            self.assertNotEqual(session.get(Blob, blob.id).upload_id, provider_id)
        self.assertNotIn(provider_id, list(self.storage.pending_uploads(blob.key)))

    def test_storage_and_database_errors_are_logged_json_with_request_id(self):
        from botocore.exceptions import ClientError
        from sqlalchemy.exc import OperationalError
        record = self.create(data=b"abc").json()
        blob_id = record["attachments"][0]["id"]
        denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "CreateMultipartUpload")
        with patch.object(self.storage, "start", side_effect=denied), self.assertLogs("hf2l.exchange.api", level="ERROR") as logs:
            response = self.client.post(self.prefix + f"/records/{record['id']}/blobs/{blob_id}/uploads", headers=self.auth("alice"))
        self.assertEqual((response.status_code, self.code(response)), (503, "storage_unavailable"))
        self.assertIn("AccessDenied", logs.output[0])
        with patch.object(self.service, "read_sessions") as sessions:
            sessions.begin.side_effect = OperationalError("select", {}, Exception("db down"))
            with self.assertLogs("hf2l.exchange.api", level="ERROR") as logs:
                response = self.client.get(self.prefix + "/me", headers=self.auth("alice"))
        self.assertEqual((response.status_code, self.code(response)), (503, "database_unavailable"))
        self.assertEqual(response.headers["X-Request-ID"], response.json()["request_id"])
        self.assertIn("database_unavailable", logs.output[0])
        # The interrupted initialization is repaired by the worker and the SDK waits for it instead of failing.
        self.assertEqual(tick(self.service)["recovered"], 1)

    @unittest.skipUnless(os.environ.get("EXCHANGE_TEST_S3_ENDPOINT"), "requires live signature enforcement")
    def test_storage_rejects_tampered_and_expired_grants(self):
        record = self.create(data=b"abc").json()
        identifier = record["attachments"][0]["id"]
        self.client.post(self.prefix + f"/records/{record['id']}/blobs/{identifier}/uploads", headers=self.auth("alice"))
        response = self.client.post(self.prefix + f"/uploads/{identifier}/parts:authorize", headers=self.auth("alice"), json={"part_numbers": [1]})
        self.assertEqual(response.status_code, 200, response.text)
        grant = response.json()["parts"][0]
        with httpx.Client(timeout=15) as transport:
            tampered = grant["url"].replace("partNumber=1", "partNumber=2")
            self.assertEqual(transport.put(tampered, content=b"abc", headers=grant["headers"]).status_code, 403)
            with self.service.sessions.begin() as session:
                blob = session.get(Blob, identifier)
            url = self.storage.client.generate_presigned_url("upload_part", Params={"Bucket": self.settings.bucket,
                "Key": blob.key, "UploadId": blob.upload_id, "PartNumber": 1}, ExpiresIn=1, HttpMethod="PUT")
            time.sleep(2)
            self.assertEqual(transport.put(url, content=b"abc").status_code, 403)

    def test_concurrent_publishers_only_one_advances_reference(self):
        base = self.ready()
        self.ref(base)
        candidates = [self.ready(base=base["id"]) for _ in range(2)]
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda record: self.ref(record, 1).status_code, candidates))
        self.assertEqual(sorted(results), [200, 412])

    def background_worker(self):
        stop = threading.Event()
        errors = []
        def work():
            while not stop.wait(0.05):
                try:
                    tick(self.service)
                except Exception as exc:
                    logging.getLogger("tests").exception("background worker tick failed")
                    errors.append(exc)
        worker = threading.Thread(target=work, daemon=True)
        worker.start()
        def stop_worker():
            stop.set()
            worker.join(timeout=10)
        self.addCleanup(stop_worker)
        return errors

    def test_sdk_resumes_after_transport_failure_and_releases_poisoned_drafts(self):
        errors = self.background_worker()
        root = Path(self.temp.name)
        payload = root / "payload.bin"
        payload.write_bytes(os.urandom(5 * 1024 * 1024 + 17))
        state = root / "upload.json"
        failures = {"remaining": 3}
        def flaky(request):
            if request.method == "PUT" and failures["remaining"]:
                failures["remaining"] -= 1
                raise httpx.ConnectError("simulated", request=request)
        transfer = httpx.Client(event_hooks={"request": [flaky]}, timeout=30)
        sdk = self.sdk("alice", transfer)
        with self.assertRaises(ExchangeError) as failed:
            sdk.put_record(self.space, kind="message", metadata={"attempt": 1, "at": "t0"}, files={"payload.bin": payload}, state_path=state)
        self.assertEqual(failed.exception.code, "blob_transfer_failed")
        self.assertTrue(state.exists())
        first_id = json.loads(state.read_text())["record_id"]
        puts_before = failures["remaining"]
        # The retry carries refreshed volatile metadata yet resumes the same draft and re-sends only missing parts.
        record = sdk.put_record(self.space, kind="message", metadata={"attempt": 2, "at": "t1"}, files={"payload.bin": payload}, state_path=state, wait_seconds=60)
        self.assertEqual((record["id"], record["state"], record["metadata"]), (first_id, "ready", {"attempt": 2, "at": "t1"}))
        self.assertFalse(state.exists())
        self.assertEqual(puts_before, 0)
        ready = [r["id"] for r in sdk.records(self.space, kind="message", state="ready")]
        self.assertEqual(ready, [first_id])
        target = root / "download" / "payload.bin"
        partial = target.with_name(target.name + "." + record["attachments"][0]["id"] + ".part")
        partial.parent.mkdir()
        partial.write_bytes(payload.read_bytes()[:1024 * 1024])
        sdk.download_attachment(self.space, record["id"], record["attachments"][0], target)
        self.assertEqual(target.read_bytes(), payload.read_bytes())
        # A draft whose blob fails verification is cancelled so the reservation is released for the retry.
        wrong = root / "wrong.bin"
        wrong.write_bytes(b"declared")
        digest = hashlib.sha256(b"declared").hexdigest()
        with patch("hf2l.exchange.client.sha256", return_value=digest):
            wrong.write_bytes(b"actual!!")
            with self.assertRaises(ExchangeError) as poisoned:
                sdk.put_record(self.space, kind="message", metadata={}, files={"wrong.bin": wrong}, state_path=root / "wrong.json", wait_seconds=60)
        self.assertEqual(poisoned.exception.code, "blob_verification_failed")
        self.assertFalse((root / "wrong.json").exists())
        self.assertEqual(self.client.get(self.prefix, headers=self.headers).json()["allocated_bytes"], payload.stat().st_size)
        self.assertEqual(errors, [])

    def test_client_sdk_and_fedavg_end_to_end(self):
        import torch
        from safetensors.torch import load_file, save_file
        from hf2l.client_steps import download_client_round, upload_client_update
        from hf2l.hub_helpers import artifact_hashes
        from hf2l.owner_fedavg import main

        errors = self.background_worker()
        owner = self.store("owner")
        root = Path(self.temp.name)
        initial = root / "initial"
        initial.mkdir()
        write_json(initial / "config.json", {"model_type": "test"})
        save_file({"weight": torch.tensor([0.0])}, initial / "model.safetensors")
        write_json(initial / ROUND_FILE, {"schema_version": 2, "backend": "exchange", "round": 0,
                                          "checkpoint_files_sha256": artifact_hashes(initial, ["config.json", "model.safetensors"])})
        base = owner.initialize_repository(self.space, initial, private=True).revision
        self.member("carol", ["contributor", "reader"], "carol")

        def train(subject, value, count):
            participant = self.store(subject)
            folder = root / subject
            download_client_round(participant, self.space, base, folder)
            trained = folder / "trained_model"
            trained.mkdir()
            write_json(trained / "config.json", {"model_type": "test"})
            save_file({"weight": torch.tensor([value])}, trained / "model.safetensors")
            upload_client_update(participant, folder, trained, subject, count)
            return participant, folder, trained

        train("alice", 1.0, 1)
        bob, bob_folder, bob_trained = train("bob", 3.0, 3)
        # A repeated upload from the same work directory after success is a new, superseding record.
        upload_client_update(bob, bob_folder, bob_trained, "bob", 3)
        # A malformed record and then an incompatible checkpoint from carol must not wedge the round.
        carol = self.store("carol")
        carol.client.put_record(self.space, kind="training.update", metadata={"hf2l_files": {"notes.json": {}}}, base_record_id=base)
        bad = root / "carol-bad"
        bad.mkdir()
        write_json(bad / "config.json", {"model_type": "test"})
        save_file({"weight": torch.tensor([5.0, 5.0])}, bad / "model.safetensors")
        write_json(bad / SUBMISSION_FILE, {"schema_version": 2, "backend": "exchange", "repo_id": self.space, "participant": "carol",
                                           "base_revision": base, "source_round": 0, "num_examples": 1, "training": {},
                                           "checkpoint_files_sha256": artifact_hashes(bad, ["config.json", "model.safetensors"])})
        incompatible = carol.publish_submission(self.space, bad, ["config.json", "model.safetensors", SUBMISSION_FILE], participant="carol",
                                                source_round=0, base_revision=base, submission_revision=None).revision
        # A record accepted before attachment names were validated carries a complete manifest as an attachment that
        # shadows its incomplete inline copy. The owner must skip it rather than read the attachment's claims.
        self.member("dave", ["contributor", "reader"], "dave")
        dave = self.store("dave")
        inline_manifest = {"schema_version": 2, "backend": "exchange", "repo_id": self.space, "participant": "dave",
                           "base_revision": base, "source_round": 0, "training": {}}
        shadow = root / "dave-shadow.json"
        write_json(shadow, {**inline_manifest, "num_examples": 999999})
        shadowing = dave.client.put_record(self.space, kind="training.update", metadata={"hf2l_files": {SUBMISSION_FILE: inline_manifest}},
                                           files={"weights.bin": shadow}, base_record_id=base, wait_seconds=60)
        with self.service.sessions.begin() as session:
            session.get(Blob, shadowing["attachments"][0]["id"]).name = SUBMISSION_FILE

        readiness = root / "readiness"
        args = ["owner_fedavg", "--backend", "exchange", "--repo-id", self.space,
                "--discover-submissions", "--check-only", "--output-dir", str(readiness)]
        with patch("sys.argv", args), patch("hf2l.owner_fedavg.make_store", return_value=owner):
            main()
        self.assertEqual(json.loads((readiness / "readiness.json").read_text())["eligible_count"], 3)

        # The frozen claim includes carol's incompatible checkpoint; the failed round must release its claim.
        args = ["owner_fedavg", "--backend", "exchange", "--repo-id", self.space,
                "--claim-submissions", "--output-dir", str(root / "failed"), "--publish"]
        with patch("sys.argv", args), patch("hf2l.owner_fedavg.make_store", return_value=owner):
            with self.assertRaises(SystemExit):
                main()
        with self.service.sessions.begin() as session:
            self.assertEqual(session.query(Claim).count(), 0)

        # Carol withdraws the incompatible update; the next claim freezes her malformed one, which is skipped.
        self.assertEqual(carol.client.cancel_record(self.space, incompatible), {"state": "withdrawn"})
        owner = self.store("owner")
        args = ["owner_fedavg", "--backend", "exchange", "--repo-id", self.space, "--claim-submissions",
                "--output-dir", str(root / "average"), "--publish", "--tag", "round-1"]
        with patch("sys.argv", args), patch("hf2l.owner_fedavg.make_store", return_value=owner):
            main()
        result = load_file(root / "average/aggregated_model/model.safetensors")["weight"]
        torch.testing.assert_close(result, torch.tensor([2.5]))
        latest = owner.resolve_revision(self.space, "main")
        self.assertNotEqual(latest, base)
        published = owner.client.get_record(self.space, latest)
        self.assertEqual(published["metadata"]["hf2l_files"][ROUND_FILE]["round"], 1)
        updates = list(owner.client.records(self.space, kind="training.update", state="ready", base_record_id=base))
        newest_bob = max((r for r in updates if r["participant"] == "bob"), key=lambda r: r["created_at"])["id"]
        alice_id = next(r["id"] for r in updates if r["participant"] == "alice")
        self.assertEqual(set(published["metadata"]["input_record_ids"]), {alice_id, newest_bob})
        self.assertEqual(owner.client.resolve(self.space, "round-1")["record_id"], latest)
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
