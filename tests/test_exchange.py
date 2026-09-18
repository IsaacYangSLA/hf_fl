"""Control-plane integration tests using real JWT signatures and emulated S3."""
import hashlib
import json
import os
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
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from fastapi.testclient import TestClient
    from moto import mock_aws
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url

    from hf2l.exchange.api import create_app
    from hf2l.exchange.auth import principal_id
    from hf2l.exchange.config import Settings
    from hf2l.exchange.models import Base, Blob, Claim, Record, Space
    from hf2l.exchange.storage import S3BlobStore
    from hf2l.exchange.worker import tick
    EXCHANGE_AVAILABLE = True
except ModuleNotFoundError:
    EXCHANGE_AVAILABLE = False


@unittest.skipUnless(EXCHANGE_AVAILABLE, "install hf2l[service,exchange,exchange-test]")

class ExchangeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        live_endpoint = os.environ.get("EXCHANGE_TEST_S3_ENDPOINT")
        if not live_endpoint:
            self.aws = mock_aws()
            self.aws.start()
            self.addCleanup(self.aws.stop)
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
                                 s3_endpoint=live_endpoint,
                                 admin_subject="owner", public_key=public, part_bytes=5 * 1024 * 1024)
        self.s3 = boto3.client("s3", region_name="us-east-1", endpoint_url=live_endpoint)
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

    def create(self, subject="alice", kind="message", base=None, data=None, metadata=None, key=None):
        attachments = [] if data is None else [{"name": "model.bin", "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}]
        return self.client.post(self.prefix + "/records", headers={**self.auth(subject), "Idempotency-Key": key or str(time.time_ns())},
                                json={"kind": kind, "base_record_id": base, "metadata": metadata or {}, "attachments": attachments})

    def ready(self, subject="owner", kind="model.global", base=None, metadata=None):
        result = self.create(subject, kind, base, metadata=metadata)
        self.assertEqual(result.status_code, 201, result.text)
        record = result.json()
        response = self.client.post(self.prefix + f"/records/{record['id']}:publish", headers=self.auth(subject))
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def ref(self, record, expected=None, key=None, subject="owner"):
        headers = {**self.auth(subject), "Idempotency-Key": key or str(time.time_ns())}
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

    def test_authentication_and_cross_space_isolation(self):
        for headers in ({}, self.auth("alice", aud="other"), self.auth("alice", exp=1), self.auth("alice", scope="")):
            result = self.client.get(self.prefix + "/records", headers=headers)
            self.assertEqual(result.status_code, 401)
        self.assertEqual(self.client.get(self.prefix + "/records", headers=self.auth("stranger")).status_code, 404)
        forged = self.client.post(self.prefix + "/records", headers={**self.auth("alice"), "Idempotency-Key": "bad"},
                                  json={"kind": "message", "created_by": "owner"})
        self.assertEqual(forged.status_code, 422)
        self.assertEqual(self.create(kind="model.global").status_code, 403)

    def test_metadata_roundtrip_visibility_and_immutability(self):
        draft = self.create().json()
        self.assertEqual(self.client.get(self.prefix + f"/records/{draft['id']}", headers=self.headers).status_code, 404)
        record = self.ready("alice", "message", metadata={"hello": "world"})
        response = self.client.get(self.prefix + f"/records/{record['id']}", headers=self.auth("bob"))
        self.assertEqual(response.json()["metadata"], {"hello": "world"})
        changed = self.client.patch(self.prefix + f"/records/{record['id']}", headers={**self.auth("alice"), "If-Match": '"2"'}, json={"metadata": {}})
        self.assertEqual(changed.status_code, 409)
        base = self.ready()
        private = self.ready("alice", "training.update", base["id"])
        self.assertEqual(self.client.get(self.prefix + f"/records/{private['id']}", headers=self.auth("bob")).status_code, 404)
        visible = self.client.get(self.prefix + "/records", headers=self.auth("bob")).json()["items"]
        self.assertNotIn(private["id"], [r["id"] for r in visible])

    def test_idempotency_quota_and_cancellation(self):
        first = self.create(data=b"abc", key="same")
        second = self.create(data=b"abc", key="same")
        self.assertEqual(first.json()["id"], second.json()["id"])
        self.assertEqual(self.create(data=b"abcd", key="same").status_code, 409)
        with self.service.sessions.begin() as session:
            space = session.get(Space, self.space)
            self.assertEqual(space.allocated, 3)
            space.quota = 3
        self.assertEqual(self.create(data=b"a").status_code, 429)
        self.client.delete(self.prefix + "/records/" + first.json()["id"], headers=self.auth("alice"))
        self.assertEqual(self.create(data=b"abc").status_code, 201)

    def test_multipart_verification_and_pinned_download(self):
        data = b"a" * (5 * 1024 * 1024) + b"last part"
        record = self.create(data=data).json()
        self.assertEqual(self.client.post(self.prefix + f"/records/{record['id']}:publish", headers=self.auth("alice")).status_code, 409)
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

    def test_digest_failure_and_revoked_membership(self):
        record = self.create(data=b"abc").json()
        blob_id = self.upload(record, b"bad")
        self.assertEqual(tick(self.service)["failed"], 1)
        self.assertEqual(self.client.post(self.prefix + f"/records/{record['id']}:publish", headers=self.auth("alice")).status_code, 409)
        self.member("alice", [])
        self.assertEqual(self.client.post(self.prefix + f"/uploads/{blob_id}/parts:authorize", headers=self.auth("alice"), json={"part_numbers": [1]}).status_code, 404)

    def test_reference_cas_and_duplicate_retry(self):
        base = self.ready()
        self.assertEqual(self.ref(base).status_code, 200)
        first, second = self.ready(base=base["id"]), self.ready(base=base["id"])
        self.assertEqual(self.ref(first, 1, key="publish").status_code, 200)
        self.assertEqual(self.ref(first, 1, key="publish").status_code, 200)
        self.assertEqual(self.ref(second, 1).status_code, 412)
        self.assertEqual(self.ref(second, 2, subject="alice").status_code, 403)

    def test_worker_recovers_lost_completion_and_expired_uploads(self):
        record = self.create(data=b"hello").json()
        blob_id = self.upload(record, b"hello")
        with self.service.sessions.begin() as session:
            blob = session.get(Blob, blob_id)
            blob.state, blob.version = "completing", None
        self.assertEqual(tick(self.service)["recovered"], 1)
        self.assertEqual(tick(self.service)["verified"], 1)
        with self.service.sessions.begin() as session:
            session.get(Record, record["id"]).expires_at = 1
            session.get(Blob, blob_id).expires_at = 1
        self.assertEqual(tick(self.service)["cleaned"], 1)
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(Space, self.space).allocated, 0)

    def test_claim_freezes_inputs_and_fences_stale_worker(self):
        base = self.ready()
        self.ref(base)
        updates = [self.ready(p, "training.update", base["id"]) for p in ("alice", "bob")]
        response = self.client.post(self.prefix + "/claims", headers=self.headers, json={})
        self.assertEqual(response.status_code, 200, response.text)
        claim = response.json()
        self.assertEqual(set(claim["inputs"]), {r["id"] for r in updates})
        self.assertEqual(self.client.post(self.prefix + "/claims", headers=self.headers, json={}).status_code, 409)
        with self.service.sessions.begin() as session:
            session.get(Claim, claim["id"]).lease_until = 1
        replacement = self.client.post(self.prefix + "/claims", headers=self.headers, json={}).json()
        result = self.ready(base=base["id"], metadata={"input_record_ids": claim["inputs"]})
        route = self.prefix + f"/claims/{claim['id']}:publish"
        self.assertEqual(self.client.post(route, headers=self.headers, json={"record_id": result["id"], "fence": claim["fence"]}).status_code, 412)
        self.assertEqual(self.ref(result, 1).status_code, 409)
        self.assertEqual(self.client.post(route, headers=self.headers, json={"record_id": result["id"], "fence": replacement["fence"]}).status_code, 200)

    def test_pagination_and_event_visibility(self):
        for n in range(3):
            self.ready("alice", "message", metadata={"n": n})
        response = self.client.get(self.prefix + "/records?limit=2", headers=self.auth("bob")).json()
        self.assertEqual(len(response["items"]), 2)
        next_page = self.client.get(self.prefix + "/records", params={"cursor": response["next_cursor"]}, headers=self.auth("bob")).json()
        self.assertEqual(len(next_page["items"]), 1)
        self.assertEqual(len(self.client.get(self.prefix + "/events", headers=self.auth("bob")).json()["items"]), 3)

    def test_request_limits_safe_paths_and_foreign_keys(self):
        self.assertEqual(self.create(metadata={"large": "x" * 65536}).status_code, 422)
        response = self.client.post(self.prefix + "/records", headers=self.auth("alice"), content=b"x" * (1024 * 1024 + 1))
        self.assertEqual(response.status_code, 413)
        body = {"kind": "message", "attachments": [{"name": "../escape", "size_bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}]}
        self.assertEqual(self.client.post(self.prefix + "/records", headers={**self.auth("alice"), "Idempotency-Key": "escape"}, json=body).status_code, 422)
        self.assertEqual(self.create(base="rec_nonexistent").status_code, 404)

    def test_worker_recovers_lost_initiation(self):
        record = self.create(data=b"hello").json()
        with self.service.sessions.begin() as session:
            blob = session.get(Blob, record["attachments"][0]["id"])
            blob.state = "initiating"
            provider_id = self.storage.start(blob.key)
        self.assertEqual(tick(self.service)["recovered"], 1)
        with self.service.sessions.begin() as session:
            self.assertEqual(session.get(Blob, blob.id).upload_id, provider_id)

    @unittest.skipUnless(os.environ.get("EXCHANGE_TEST_S3_ENDPOINT"), "requires live signature enforcement")
    def test_storage_rejects_tampered_and_expired_grants(self):
        import httpx
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

    @unittest.skipUnless(os.environ.get("EXCHANGE_TEST_S3_ENDPOINT"), "requires live local S3 endpoint")
    def test_client_sdk_and_fedavg_end_to_end(self):
        import httpx
        import torch
        from safetensors.torch import save_file
        from hf2l.backends.exchange import ExchangeStore
        from hf2l.client_steps import download_client_round, upload_client_update
        from hf2l.exchange.client import ExchangeClient
        from hf2l.hub_helpers import ROUND_FILE, artifact_hashes, write_json
        from hf2l.owner_fedavg import main

        stop = threading.Event()
        errors = []
        def work():
            while not stop.wait(0.05):
                try:
                    tick(self.service)
                except Exception as exc:
                    errors.append(exc)
        worker = threading.Thread(target=work, daemon=True)
        worker.start()
        def stop_worker():
            stop.set()
            worker.join(timeout=10)
        self.addCleanup(stop_worker)
        def store(subject):
            def check_storage_request(request):
                self.assertNotIn("authorization", request.headers)
            transfer = httpx.Client(event_hooks={"request": [check_storage_request]}, timeout=30)
            self.addCleanup(transfer.close)
            sdk = ExchangeClient("http://testserver", self.auth(subject)["Authorization"].split(" ", 1)[1],
                                 http=self.client, transfer=transfer)
            return ExchangeStore(None, None, client=sdk)
        owner = store("owner")
        root = Path(self.temp.name)
        initial = root / "initial"
        initial.mkdir()
        write_json(initial / "config.json", {"model_type": "test"})
        save_file({"weight": torch.tensor([0.0])}, initial / "model.safetensors")
        write_json(initial / ROUND_FILE, {"schema_version": 2, "backend": "exchange", "round": 0,
                                          "checkpoint_files_sha256": artifact_hashes(initial, ["config.json", "model.safetensors"])})
        base = owner.initialize_repository(self.space, initial, private=True).revision
        for subject, value, count in (("alice", 1.0, 1), ("bob", 3.0, 3)):
            participant = store(subject)
            folder = root / subject
            download_client_round(participant, self.space, base, folder)
            trained = folder / "trained_model"
            trained.mkdir()
            write_json(trained / "config.json", {"model_type": "test"})
            save_file({"weight": torch.tensor([value])}, trained / "model.safetensors")
            upload_client_update(participant, folder, trained, subject, count)
        args = ["owner_fedavg", "--backend", "exchange", "--repo-id", self.space,
                "--claim-submissions", "--output-dir", str(root / "average"), "--publish"]
        with patch("sys.argv", args), patch("hf2l.owner_fedavg.make_store", return_value=owner):
            main()
        from safetensors.torch import load_file
        result = load_file(root / "average/aggregated_model/model.safetensors")["weight"]
        torch.testing.assert_close(result, torch.tensor([2.5]))
        latest = owner.resolve_revision(self.space, "main")
        self.assertNotEqual(latest, base)
        self.assertEqual(owner.client.get_record(self.space, latest)["metadata"]["hf2l_files"][ROUND_FILE]["round"], 1)
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
