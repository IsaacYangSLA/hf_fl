"""Credential selection and refresh for internal S3 calls and public grants."""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import boto3
import botocore.session
from botocore.credentials import CredentialProvider, DeferredRefreshableCredentials

from hf2l_exchange.config import StorageSettings
from hf2l_exchange.storage import S3BlobStore


class StorageCredentialTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="exchange-credentials-")
        self.addCleanup(directory.cleanup)
        environment = {
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_CONFIG_FILE": str(Path(directory.name) / "no-config"),
            "AWS_SHARED_CREDENTIALS_FILE": str(Path(directory.name) / "no-credentials"),
            "EXCHANGE_S3_BUCKET": "credential-tests",
            "EXCHANGE_S3_ENDPOINT": "https://internal.example.test",
            "EXCHANGE_S3_PUBLIC_ENDPOINT": "https://public.example.test",
        }
        self.environment = patch.dict(os.environ, environment, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def sign(self, client):
        url = client.generate_presigned_url(
            "get_object", Params={"Bucket": "credential-tests", "Key": "test", "VersionId": "version"},
            ExpiresIn=60,
        )
        return parse_qs(urlsplit(url).query)

    def assert_credentials(self, storage, access_key, token):
        for name, client in (("internal", storage.client), ("public", storage.signer)):
            with self.subTest(client=name):
                query = self.sign(client)
                self.assertEqual(query["X-Amz-Credential"][0].split("/")[0], access_key)
                self.assertEqual(query.get("X-Amz-Security-Token"), [token] if token else None)

    def test_ambient_temporary_credentials_keep_token_for_both_clients(self):
        os.environ.update(AWS_ACCESS_KEY_ID="ambient-key", AWS_SECRET_ACCESS_KEY="ambient-secret",
                          AWS_SESSION_TOKEN="ambient/token+value=")
        settings = StorageSettings.from_env()
        self.assertEqual((settings.access_key, settings.secret_key, settings.session_token), ("", "", ""))
        storage = S3BlobStore(settings)
        self.assert_credentials(storage, "ambient-key", "ambient/token+value=")
        self.assertEqual(storage.client.meta.endpoint_url, "https://internal.example.test")
        self.assertEqual(storage.signer.meta.endpoint_url, "https://public.example.test")

    def test_explicit_temporary_credentials_override_ambient_credentials(self):
        os.environ.update(AWS_ACCESS_KEY_ID="ambient-key", AWS_SECRET_ACCESS_KEY="ambient-secret",
                          AWS_SESSION_TOKEN="ambient-token", EXCHANGE_S3_ACCESS_KEY="explicit-key",
                          EXCHANGE_S3_SECRET_KEY="explicit-secret", EXCHANGE_S3_SESSION_TOKEN="explicit-token")
        self.assert_credentials(S3BlobStore(StorageSettings.from_env()), "explicit-key", "explicit-token")

    def test_explicit_permanent_credentials_do_not_inherit_ambient_token(self):
        os.environ.update(AWS_ACCESS_KEY_ID="ambient-key", AWS_SECRET_ACCESS_KEY="ambient-secret",
                          AWS_SESSION_TOKEN="ambient-token", EXCHANGE_S3_ACCESS_KEY="explicit-key",
                          EXCHANGE_S3_SECRET_KEY="explicit-secret")
        self.assert_credentials(S3BlobStore(StorageSettings.from_env()), "explicit-key", None)

    def test_partial_explicit_credentials_never_mix_with_ambient_credentials(self):
        os.environ.update(AWS_ACCESS_KEY_ID="ambient-key", AWS_SECRET_ACCESS_KEY="ambient-secret",
                          AWS_SESSION_TOKEN="ambient-token")
        for overrides in ({"S3_ACCESS_KEY": "explicit-key"}, {"S3_SECRET_KEY": "explicit-secret"},
                          {"S3_SESSION_TOKEN": "explicit-token"},
                          {"S3_ACCESS_KEY": "explicit-key", "S3_SESSION_TOKEN": "explicit-token"},
                          {"S3_SECRET_KEY": "explicit-secret", "S3_SESSION_TOKEN": "explicit-token"}):
            with self.subTest(overrides=tuple(overrides)), patch.dict(
                    os.environ, {"EXCHANGE_" + key: value for key, value in overrides.items()}):
                with self.assertRaises(ValueError):
                    StorageSettings.from_env()

    def test_direct_settings_reject_partial_credentials(self):
        for values in ({"access_key": "key"}, {"secret_key": "secret"}, {"session_token": "token"}):
            with self.subTest(fields=tuple(values)), self.assertRaises(ValueError):
                StorageSettings(bucket="bucket", **values).validate()

    def test_provider_credentials_refresh_for_existing_internal_and_public_clients(self):
        # Model an instance/task role provider. Both clients must retain its
        # refreshable credential object instead of copying a frozen key pair.
        clock = [datetime.now(timezone.utc)]
        sessions, calls = [], []

        class Provider(CredentialProvider):
            METHOD = "test-role"

            def __init__(self, prefix):
                self.prefix, self.generation = prefix, 0

            def refresh(self):
                self.generation += 1
                calls.append((self.prefix, self.generation))
                return {"access_key": self.prefix + "-key-" + str(self.generation),
                        "secret_key": "role-secret", "token": self.prefix + "-token-" + str(self.generation),
                        "expiry_time": (clock[0] + timedelta(hours=1)).isoformat()}

            def load(self):
                return DeferredRefreshableCredentials(
                    refresh_using=self.refresh, method=self.METHOD, time_fetcher=lambda: clock[0])

        for name in ("internal", "public"):
            session = botocore.session.get_session()
            session.get_component("credential_provider").insert_before("env", Provider(name))
            sessions.append(boto3.session.Session(botocore_session=session))
        storage = S3BlobStore(StorageSettings.from_env())
        with patch("boto3.session.Session", side_effect=sessions):
            clients = (("internal", storage.client), ("public", storage.signer))
        for generation in (1, 2):
            for name, client in clients:
                with self.subTest(client=name, generation=generation):
                    query = self.sign(client)
                    self.assertEqual(query["X-Amz-Credential"][0].split("/")[0],
                                     name + "-key-" + str(generation))
                    self.assertEqual(query["X-Amz-Security-Token"], [name + "-token-" + str(generation)])
            clock[0] += timedelta(hours=2)
        self.assertEqual(calls, [("internal", 1), ("public", 1), ("internal", 2), ("public", 2)])


if __name__ == "__main__":
    unittest.main()
