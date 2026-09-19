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

    from hf2l.backends.exchange import ExchangeStore
    from hf2l.exchange.api import create_app
    from hf2l.exchange.auth import principal_id
    from hf2l.exchange.client import ExchangeClient, ExchangeError
    from hf2l.exchange.config import Settings
    from hf2l.exchange.models import Base, Blob, Claim, Record, Space
    from hf2l.exchange.storage import S3BlobStore
    from hf2l.exchange.worker import tick
    EXCHANGE_AVAILABLE = True
except ModuleNotFoundError:
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
                                 s3_endpoint=self.endpoint, admin_subject="owner", public_key=public,
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

    def claim(self, subject="owner", **body):
        return self.client.post(self.prefix + "/claims", headers=self.auth(subject), json=body)

    def sdk(self, subject, transfer=None):
        def check_storage_request(request):
            self.assertNotIn("authorization", request.headers)
        transfer = transfer or httpx.Client(event_hooks={"request": [check_storage_request]}, timeout=30)
        self.addCleanup(transfer.close)
        return ExchangeClient("http://testserver", self.auth(subject)["Authorization"].split(" ", 1)[1],
                              http=self.client, transfer=transfer)

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
        base = self.ready()
        self.assertEqual(self.ref(base).status_code, 200)
        first, second = self.ready(base=base["id"]), self.ready(base=base["id"])
        self.assertEqual(self.ref(first, 1, key="publish").status_code, 200)
        self.assertEqual(self.ref(first, 1, key="publish").status_code, 200)
        self.assertEqual(self.code(self.ref(second, 1)), "reference_changed")
        self.assertEqual(self.code(self.ref(second, 2)), "aggregate_base_mismatch")
        baseless = self.ready("owner", "configuration")
        self.assertEqual(self.code(self.ref(baseless, 2)), "aggregate_base_mismatch")
        self.assertEqual(self.ref(second, 2, subject="alice").status_code, 403)

    def test_worker_recovers_lost_completion_and_expired_uploads(self):
        record = self.create(data=b"hello").json()
        blob_id = self.upload(record, b"hello")
        with self.service.sessions.begin() as session:
            blob = session.get(Blob, blob_id)
            blob.state, blob.version, blob.updated_at = "completing", None, 0
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
        self.assertEqual(self.code(self.claim()), "claim_busy")
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
        self.assertEqual(self.code(self.claim("carol", inputs=[old["id"], new["id"]])), "claim_busy")
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

    def test_request_limits_safe_paths_and_foreign_keys(self):
        self.assertEqual(self.create(metadata={"large": "x" * 65536}).status_code, 422)
        response = self.client.post(self.prefix + "/records", headers=self.auth("alice"), content=b"x" * (1024 * 1024 + 1))
        self.assertEqual(response.status_code, 413)
        self.assertTrue(response.headers.get("X-Request-ID"))
        body = {"kind": "message", "attachments": [{"name": "../escape", "size_bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}]}
        self.assertEqual(self.client.post(self.prefix + "/records", headers={**self.auth("alice"), "Idempotency-Key": "escape"}, json=body).status_code, 422)
        empty = hashlib.sha256(b"").hexdigest()
        collision = self.create(attachments=[{"name": "a", "size_bytes": 0, "sha256": empty}, {"name": "a/b", "size_bytes": 0, "sha256": empty}])
        self.assertEqual(self.code(collision), "attachment_name_collides_with_directory")
        self.assertEqual(self.create(base="rec_nonexistent").status_code, 404)

    def test_worker_recovers_lost_initiation(self):
        record = self.create(data=b"hello").json()
        with self.service.sessions.begin() as session:
            blob = session.get(Blob, record["attachments"][0]["id"])
            blob.state, blob.updated_at = "initiating", 0
            provider_id = self.storage.start(blob.key)
        self.assertEqual(tick(self.service)["recovered"], 1)
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(Blob, blob.id).upload_id, provider_id)

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
        with patch.object(self.service, "sessions") as sessions:
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
        from hf2l.hub_helpers import ROUND_FILE, SUBMISSION_FILE, artifact_hashes, write_json
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
