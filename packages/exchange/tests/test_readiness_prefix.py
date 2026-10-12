"""S3 readiness must work with credentials scoped to the transfer prefix."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from botocore.exceptions import ClientError

from hf2l_exchange.config import StorageSettings
from hf2l_exchange.storage import S3BlobStore, StorageFailure


class PrefixScopedS3:
    """Model GetObject permission and missing-object HEAD within a key prefix."""

    def __init__(self, prefix, *, versioning="Enabled", deny_objects=False):
        self.prefix = prefix
        self.versioning = versioning
        self.deny_objects = deny_objects
        self.head_keys = []

    def get_bucket_versioning(self, *, Bucket):
        return {"Status": self.versioning}

    def head_object(self, *, Bucket, Key):
        self.head_keys.append(Key)
        if self.deny_objects or not Key.startswith(self.prefix):
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "HeadObject")
        raise ClientError({"Error": {"Code": "404"}}, "HeadObject")


class ReadinessPrefixTests(unittest.TestCase):
    def test_readiness_uses_transfer_prefix_for_scoped_credentials(self):
        client = PrefixScopedS3("exchange-v2/")
        # The bucket-root probe used by the old implementation is denied.
        with self.assertRaises(ClientError):
            client.head_object(Bucket="bucket", Key="readiness/root-probe")
        storage = S3BlobStore(StorageSettings(bucket="bucket"), client=client)
        storage.check()
        self.assertEqual(len(client.head_keys), 2)
        self.assertRegex(client.head_keys[-1], r"^exchange-v2/readiness/[0-9a-f]{32}$")

    def test_empty_and_trailing_slash_prefixes_match_transfer_normalization(self):
        for prefix, expected in (("", "readiness/probe"),
                                 ("project", "project/readiness/probe"),
                                 ("project/", "project/readiness/probe"),
                                 ("project/nested///", "project/nested/readiness/probe")):
            with self.subTest(prefix=prefix):
                normalized = prefix.strip("/")
                client = PrefixScopedS3(normalized + "/" if normalized else "")
                storage = S3BlobStore(StorageSettings(bucket="bucket", prefix=prefix), client=client)
                with patch("hf2l_exchange.storage.uuid.uuid4") as random_id:
                    random_id.return_value.hex = "probe"
                    storage.check()
                self.assertEqual(client.head_keys, [expected])

    def test_object_access_denial_remains_readiness_failure(self):
        client = PrefixScopedS3("exchange-v2/", deny_objects=True)
        storage = S3BlobStore(StorageSettings(bucket="bucket"), client=client)
        with self.assertRaises(StorageFailure) as raised:
            storage.check()
        self.assertEqual(raised.exception.code, "storage_misconfigured")
        self.assertTrue(raised.exception.retryable)

    def test_disabled_versioning_fails_before_object_probe(self):
        client = PrefixScopedS3("exchange-v2/", versioning="Suspended")
        storage = S3BlobStore(StorageSettings(bucket="bucket"), client=client)
        with self.assertRaises(StorageFailure) as raised:
            storage.check()
        self.assertEqual(raised.exception.code, "storage_misconfigured")
        self.assertEqual(client.head_keys, [])


if __name__ == "__main__":
    unittest.main()
