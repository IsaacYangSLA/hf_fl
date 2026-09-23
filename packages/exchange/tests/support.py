"""Isolated database, identity and real HTTP object-storage test resources.

EXCHANGE_TEST_DATABASE_URL / EXCHANGE_TEST_S3_ENDPOINT select live services.
Each test owns a PostgreSQL schema and versioned bucket; no shared data is reset.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
import socket
import tempfile
import time
import unittest
import uuid

import boto3
import jwt
from botocore.config import Config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from moto.server import ThreadedMotoServer
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ResourceTestCase(unittest.TestCase):
    """Use real JWTs and HTTP grants against Moto or the configured provider."""

    @classmethod
    def setUpClass(cls):
        cls.endpoint = os.environ.get("EXCHANGE_TEST_S3_ENDPOINT")
        cls.live_storage = bool(cls.endpoint)
        if not cls.endpoint:
            logging.getLogger("werkzeug").setLevel(logging.ERROR)
            port = free_port()
            cls.moto = ThreadedMotoServer(ip_address="127.0.0.1", port=port, verbose=False)
            cls.moto.start()
            cls.endpoint = f"http://127.0.0.1:{port}"
        os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
        os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
        os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

    @classmethod
    def tearDownClass(cls):
        if not cls.live_storage:
            cls.moto.stop()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="exchange-v2-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.database_url = "sqlite:///" + str(self.directory / "exchange.db")
        live_database = os.environ.get("EXCHANGE_TEST_DATABASE_URL")
        if live_database:
            url = make_url(live_database)
            self.database_schema = "exchangev2_" + uuid.uuid4().hex
            admin = create_engine(url)
            with admin.begin() as connection:
                connection.execute(text(f'CREATE SCHEMA "{self.database_schema}"'))

            def cleanup_schema():
                try:
                    with admin.begin() as connection:
                        connection.execute(text(f'DROP SCHEMA "{self.database_schema}" CASCADE'))
                finally:
                    admin.dispose()

            self.addCleanup(cleanup_schema)
            self.database_url = url.update_query_dict(
                {"options": "-csearch_path=" + self.database_schema}
            ).render_as_string(hide_password=False)
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        self.issuer = "https://identity.example.test"
        self.audience = "exchange-test"
        self.bucket = "exchange-v2-test-" + uuid.uuid4().hex
        self.s3 = boto3.client("s3", region_name="us-east-1", endpoint_url=self.endpoint,
                               config=Config(signature_version="s3v4"))
        self.s3.create_bucket(Bucket=self.bucket)
        self.addCleanup(self.cleanup_bucket)
        self.s3.put_bucket_versioning(
            Bucket=self.bucket, VersioningConfiguration={"Status": "Enabled"}
        )

    def cleanup_bucket(self):
        for page in self.s3.get_paginator("list_multipart_uploads").paginate(Bucket=self.bucket):
            for upload in page.get("Uploads", []):
                self.s3.abort_multipart_upload(
                    Bucket=self.bucket, Key=upload["Key"], UploadId=upload["UploadId"]
                )
        for page in self.s3.get_paginator("list_object_versions").paginate(Bucket=self.bucket):
            for version in page.get("Versions", []) + page.get("DeleteMarkers", []):
                self.s3.delete_object(
                    Bucket=self.bucket, Key=version["Key"], VersionId=version["VersionId"]
                )
        self.s3.delete_bucket(Bucket=self.bucket)

    def auth(self, subject="owner", **overrides):
        claims = {"iss": self.issuer, "aud": self.audience, "sub": subject,
                  "exp": int(time.time()) + 3600, "iat": int(time.time()), "scope": "exchange"}
        claims.update(overrides)
        token = jwt.encode(claims, self.private_key, algorithm="RS256", headers={"typ": "at+jwt"})
        return {"Authorization": "Bearer " + token}

    @staticmethod
    def operation_key(value=None):
        return {"Idempotency-Key": value or uuid.uuid4().hex}


class ExchangeTestCase(ResourceTestCase):
    """Full API/application/storage fixture with ordinary generic-space members."""

    def setUp(self):
        super().setUp()
        from fastapi.testclient import TestClient
        from hf2l_exchange.api import create_app
        from hf2l_exchange.application import Service
        from hf2l_exchange.config import AuthSettings, DatabaseSettings, Settings, StorageSettings, WorkerSettings
        from hf2l_exchange.migrations import initialize
        from hf2l_exchange.storage import S3BlobStore
        from hf2l_exchange.transfers import TransferService

        self.settings = Settings(
            database=DatabaseSettings(url=self.database_url),
            auth=AuthSettings(issuer=self.issuer, audience=self.audience,
                              admin_subject="owner", public_key=self.public_key),
            storage=StorageSettings(endpoint=self.endpoint, bucket=self.bucket,
                                    part_size=5 * 1024 * 1024, allow_local_http=True),
            worker=WorkerSettings(recover_after=1), allow_local_http=True)
        self.service = Service(self.settings)
        self.addCleanup(self.service.engine.dispose)
        initialize(self.service.engine)
        self.storage = S3BlobStore(self.settings.storage, client=self.s3)
        self.transfers = TransferService(self.service, self.storage)
        self.app = create_app(self.settings, service=self.service, transfers=self.transfers)
        self.client = TestClient(self.app)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        self.space = self.new_space("integration")
        self.prefix = f"/v2/spaces/{self.space['id']}"
        self.member("alice", ["reader", "contributor"])
        self.member("bob", ["reader", "contributor"])
        self.member("publisher", ["publisher"])
        self.member("administrator", ["admin"])
        self.revision = self.register_type("document")

    @staticmethod
    def code(response):
        return response.json().get("error", {}).get("code")

    def request(self, method, path, subject="owner", *, key=None, headers=None, **kwargs):
        auth = self.auth(subject)
        auth.update(headers or {})
        if method.lower() in {"post", "put"}:
            auth.update(self.operation_key(key))
        return self.client.request(method, path, headers=auth, **kwargs)

    def new_space(self, name="test", profile="generic.v1", **limits):
        result = self.request("POST", "/v2/spaces", json={"name": name, "profile": profile, **limits})
        self.assertEqual(result.status_code, 201, result.text)
        return result.json()

    def member(self, subject, roles, bindings=None, space=None):
        from hf2l_exchange.auth import principal_id
        space_id = space or self.space["id"]
        result = self.request("PUT", f"/v2/spaces/{space_id}/members/" + principal_id(self.issuer, subject),
                              json={"subject": subject, "roles": roles, "bindings": bindings or {}})
        self.assertEqual(result.status_code, 200, result.text)
        return result.json()

    def register_type(self, kind, schema=None, visibility="shared", publish_roles=None, space=None):
        prefix = f"/v2/spaces/{space or self.space['id']}"
        result = self.request("POST", prefix + f"/types/{kind}/revisions", json={
            "schema": schema or {"type": "object"}, "visibility": visibility,
            "publish_roles": publish_roles or ["contributor", "publisher"]})
        self.assertEqual(result.status_code, 201, result.text)
        return result.json()

    def create(self, subject="alice", kind="document", revision=None, metadata=None, attachments=None, key=None, space=None):
        return self.request("POST", f"/v2/spaces/{space or self.space['id']}/records", subject, key=key,
            json={"kind": kind, "schema_revision_id": (revision or self.revision)["id"],
                  "metadata": metadata or {}, "attachments": attachments or []})

    def ready(self, subject="alice", **kwargs):
        result = self.create(subject, **kwargs)
        self.assertEqual(result.status_code, 201, result.text)
        record = result.json()
        response = self.request("POST", f"/v2/spaces/{record['space_id']}/records/{record['id']}/publish", subject)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def reference(self, record, name="main", token="*", subject="publisher", key=None):
        header = {"If-None-Match": "*"} if token == "*" else {"If-Match": f'"{token}"'}
        return self.request("PUT", self.prefix + f"/refs/{name}", subject, key=key,
                            headers=header, json={"record_id": record["id"]})

    def acquire(self, reference, inputs=(), subject="publisher", key=None):
        return self.request("POST", self.prefix + "/acquisitions", subject, key=key,
            json={"reference": reference["name"], "expected_token": reference["token"],
                  "input_record_ids": [record["id"] if isinstance(record, dict) else record for record in inputs]})

    def complete(self, acquisition, result, subject="publisher", key=None):
        return self.request("POST", self.prefix + f"/acquisitions/{acquisition['id']}/complete", subject, key=key,
                            json={"fence": acquisition["fence"], "result_record_id": result["id"]})

    def upload(self, record, content, subject="alice", attachment_index=0):
        import httpx
        from hf2l_exchange.worker import tick
        descriptor = record["attachments"][attachment_index]
        route = self.prefix + f"/records/{record['id']}/attachments/{descriptor['id']}"
        initiated = self.request("POST", route + "/upload", subject)
        self.assertEqual(initiated.status_code, 200, initiated.text)
        size = initiated.json()["part_size"]
        count = max(1, (len(content) + size - 1) // size)
        grants = self.request("POST", route + "/grants", subject,
                              json={"numbers": list(range(1, count + 1))})
        self.assertEqual(grants.status_code, 200, grants.text)
        for grant in grants.json()["grants"]:
            offset = (grant["number"] - 1) * size
            response = httpx.put(grant["url"], headers=grant["headers"], content=content[offset:offset + size], timeout=30)
            self.assertEqual(response.status_code, 200, response.text)
        completed = self.request("POST", route + "/complete", subject)
        self.assertEqual(completed.status_code, 202, completed.text)
        for _ in range(3):
            tick(self.transfers)
        refreshed = self.request("GET", self.prefix + f"/records/{record['id']}", subject)
        self.assertEqual(refreshed.status_code, 200, refreshed.text)
        self.assertEqual(refreshed.json()["attachments"][attachment_index]["state"], "verified")
        return refreshed.json()
