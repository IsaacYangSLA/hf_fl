"""Live regressions for the optional patched provider; isolated versioned buckets.

Use the project's .venv with boto3 and EXCHANGE_TEST_S3_ENDPOINT configured.
The endpoint must run with strict (nonrecursive) bucket deletion enabled.
"""
from concurrent.futures import ThreadPoolExecutor
import os
import unittest
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


class ProviderRegressionTests(unittest.TestCase):
    def setUp(self):
        endpoint = os.environ.get("EXCHANGE_TEST_S3_ENDPOINT")
        if not endpoint:
            self.fail("EXCHANGE_TEST_S3_ENDPOINT is required; use an isolated provider")
        self.s3 = boto3.client("s3", endpoint_url=endpoint,
                              region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
                              config=Config(signature_version="s3v4"))
        self.bucket = "hf2l-provider-regression-" + uuid.uuid4().hex
        self.s3.create_bucket(Bucket=self.bucket)
        self.addCleanup(self.cleanup_bucket)
        self.s3.put_bucket_versioning(Bucket=self.bucket, VersioningConfiguration={"Status": "Enabled"})

    def cleanup_bucket(self):
        for page in self.s3.get_paginator("list_multipart_uploads").paginate(Bucket=self.bucket):
            for item in page.get("Uploads", []):
                self.s3.abort_multipart_upload(Bucket=self.bucket, Key=item["Key"], UploadId=item["UploadId"])
        for page in self.s3.get_paginator("list_object_versions").paginate(Bucket=self.bucket):
            for item in page.get("Versions", []) + page.get("DeleteMarkers", []):
                self.s3.delete_object(Bucket=self.bucket, Key=item["Key"], VersionId=item["VersionId"])
        self.s3.delete_bucket(Bucket=self.bucket)
        self.s3.close()

    def start(self, key="nested/attempt/blob"):
        return {"Bucket": self.bucket, "Key": key,
                "UploadId": self.s3.create_multipart_upload(Bucket=self.bucket, Key=key)["UploadId"]}

    def upload(self, upload, body, number=1):
        return self.s3.upload_part(**upload, PartNumber=number, Body=body)["ETag"]

    def listed(self, upload):
        return [part for page in self.s3.get_paginator("list_parts").paginate(**upload)
                for part in page.get("Parts", [])]

    def complete(self, upload, etag, expected):
        result = self.s3.complete_multipart_upload(**upload,
            MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": etag}]})
        self.assertNotIn(result.get("VersionId"), (None, "null", ""))
        response = self.s3.get_object(Bucket=self.bucket, Key=upload["Key"], VersionId=result["VersionId"])
        with response["Body"] as body:
            self.assertEqual(body.read(), expected)
        return result

    def assert_not_empty(self):
        with self.assertRaises(ClientError) as caught:
            self.s3.delete_bucket(Bucket=self.bucket)
        self.assertEqual(caught.exception.response["Error"]["Code"], "BucketNotEmpty")

    def test_repeated_parts_replace_bytes_and_sizes(self):
        for before, after in ((b"good", b"good"), (b"bad", b"good"), (b"evil", b"good"),
                              (b"good", b""), (b"", b"good")):
            with self.subTest(before=before, after=after):
                upload = self.start("nested/repeated/" + uuid.uuid4().hex)
                self.upload(upload, before)
                etag = self.upload(upload, after)
                parts = self.listed(upload)
                self.assertEqual([(p["PartNumber"], p["Size"], p["ETag"]) for p in parts], [(1, len(after), etag)])
                self.complete(upload, etag, after)

    def test_overwritten_etag_cannot_complete(self):
        upload = self.start()
        old = self.upload(upload, b"evil")
        latest = self.upload(upload, b"good")
        with self.assertRaises(ClientError) as caught:
            self.s3.complete_multipart_upload(**upload,
                MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": old}]})
        self.assertEqual(caught.exception.response["Error"]["Code"], "InvalidPart")
        self.complete(upload, latest, b"good")

    def test_list_parts_paginates_logical_parts(self):
        upload = self.start()
        for number in (1, 2, 3):
            self.upload(upload, b"old", number)
            self.upload(upload, b"new", number)
        marker, numbers = 0, []
        for _ in range(4):
            response = self.s3.list_parts(**upload, MaxParts=1, PartNumberMarker=marker)
            numbers.extend(p["PartNumber"] for p in response.get("Parts", []))
            if not response["IsTruncated"]:
                break
            self.assertGreater(response["NextPartNumberMarker"], marker)
            marker = response["NextPartNumberMarker"]
        self.assertEqual(numbers, [1, 2, 3])

    def test_duplicate_completion_numbers_do_not_delete_selected_bytes(self):
        upload = self.start()
        etag = self.upload(upload, b"good")
        with self.assertRaises(ClientError) as caught:
            self.s3.complete_multipart_upload(**upload, MultipartUpload={"Parts": [
                {"PartNumber": 1, "ETag": etag}, {"PartNumber": 1, "ETag": etag}]})
        self.assertEqual(caught.exception.response["Error"]["Code"], "InvalidPartOrder")
        self.complete(upload, etag, b"good")

    def test_upload_part_copy_uses_same_replacement_order(self):
        for before, copied, after in ((b"old", b"new", None), (b"old", b"", None),
                                       (b"", b"copied", b"uploaded")):
            with self.subTest(before=before, copied=copied, after=after):
                source = self.s3.put_object(Bucket=self.bucket, Key="copy-source", Body=copied)
                upload = self.start("copy/" + uuid.uuid4().hex)
                self.upload(upload, before)
                response = self.s3.upload_part_copy(**upload, PartNumber=1, CopySource={
                    "Bucket": self.bucket, "Key": "copy-source", "VersionId": source["VersionId"]})
                etag = '"' + response["CopyPartResult"]["ETag"].strip('"') + '"'
                expected = copied
                if after is not None:
                    etag, expected = self.upload(upload, after), after
                parts = self.listed(upload)
                self.assertEqual([(p["PartNumber"], p["Size"], p["ETag"]) for p in parts], [(1, len(expected), etag)])
                self.complete(upload, etag, expected)

    def test_concurrent_part_writes_keep_selected_bytes_intact(self):
        upload = self.start()
        contents = [str(number).encode().ljust(64 * 1024, b"x") for number in range(12)]
        with ThreadPoolExecutor(max_workers=4) as pool:
            etags = list(pool.map(lambda body: self.upload(upload, body), contents))
        parts = self.listed(upload)
        self.assertEqual(len(parts), 1)
        chosen = parts[0]["ETag"]
        self.assertIn(chosen, etags)
        self.complete(upload, chosen, contents[etags.index(chosen)])

    def test_strict_delete_preserves_empty_active_upload(self):
        self.start()
        self.assert_not_empty()

    def test_strict_delete_preserves_noncurrent_versions_and_delete_markers(self):
        version = self.s3.put_object(Bucket=self.bucket, Key="nested/key", Body=b"history")
        marker = self.s3.delete_object(Bucket=self.bucket, Key="nested/key")
        self.assert_not_empty()
        self.s3.delete_object(Bucket=self.bucket, Key="nested/key", VersionId=version["VersionId"])
        self.assert_not_empty()
        self.s3.delete_object(Bucket=self.bucket, Key="nested/key", VersionId=marker["VersionId"])
        # Cleanup verifies that the remaining empty prefix really can be deleted.

    def test_strict_delete_preserves_directory_marker(self):
        self.s3.put_object(Bucket=self.bucket, Key="directory/", Body=b"")
        self.assert_not_empty()


if __name__ == "__main__":
    unittest.main(verbosity=2)
