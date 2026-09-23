"""Multipart replacement contracts against the configured HTTP S3 provider.

These regressions run against Moto by default and unchanged against a live
provider through EXCHANGE_TEST_S3_ENDPOINT. In particular, retrying UploadPart
must replace a part rather than leave duplicate part numbers behind.
"""
from __future__ import annotations

from hashlib import sha256
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx

from hf2l_exchange.client import ExchangeClient
from hf2l_exchange.storage import S3BlobStore
from hf2l_exchange.worker import tick
from support import ExchangeTestCase, ResourceTestCase


PART_SIZE = 5 * 1024 * 1024


class MultipartReplacementConformanceTests(ResourceTestCase):
    def setUp(self):
        super().setUp()
        self.storage = S3BlobStore(SimpleNamespace(
            bucket=self.bucket, endpoint=self.endpoint, public_endpoint=None,
            region="us-east-1", allow_local_http=True), client=self.s3)
        self.http = httpx.Client(timeout=30)
        self.addCleanup(self.http.close)

    def put(self, grant, content):
        response = self.http.put(grant.url, headers=grant.headers, content=content)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.headers.get("ETag"), "UploadPart must return its ETag")
        return response.headers["ETag"]

    def check_replacement(self, previous, *, inject_wrong_size=False):
        # Replacing a middle part after a later part already exists also checks
        # that completion preserves order, lengths, and the unaffected parts.
        parts = (b"first" * (PART_SIZE // 5), b"b" * PART_SIZE, b"last part")
        content = b"".join(parts)
        handle = self.storage.start("attempts/multipart-replacement")
        grants = [self.storage.upload_grant(handle, number, len(part), time.time() + 300, 300)
                  for number, part in enumerate(parts, 1)]
        etags = {1: self.put(grants[0], parts[0])}
        if inject_wrong_size:
            # A grant binds Content-Length. Inject malformed preexisting state
            # using the service credential, then repair it with the real grant.
            self.s3.upload_part(Bucket=self.bucket, Key=handle.key, UploadId=handle.id,
                                PartNumber=2, Body=previous)
        else:
            self.put(grants[1], previous)
        etags[3] = self.put(grants[2], parts[2])
        before = self.storage.parts(handle)
        self.assertEqual([(part.number, part.size) for part in before],
                         [(1, PART_SIZE), (2, len(previous)), (3, len(parts[2]))])

        # Reuse the same signed URL, as happens after a response is lost.
        etags[2] = self.put(grants[1], parts[1])
        current = self.storage.parts(handle)
        self.assertEqual([part.number for part in current], [1, 2, 3],
                         "UploadPart replacement must leave one entry per number")
        self.assertEqual([part.size for part in current], [len(part) for part in parts])
        self.assertEqual([part.etag for part in current], [etags[number] for number in (1, 2, 3)])

        stored = self.storage.complete(handle, len(content), PART_SIZE)
        self.assertTrue(stored.version)
        self.assertNotEqual(stored.version, "null")
        verified = self.storage.verify(stored, len(content), sha256(content).hexdigest())
        self.assertEqual((verified.size, verified.sha256), (len(content), sha256(content).hexdigest()))

        # An exact-version grant must still return the repaired multipart bytes
        # when the key's newest version has since changed.
        newer = self.s3.put_object(Bucket=self.bucket, Key=stored.key, Body=b"new version")
        self.assertNotEqual(newer["VersionId"], stored.version)
        grant = self.storage.download_grant(stored, time.time() + 300, 300)
        self.assertEqual(parse_qs(urlsplit(grant.url).query).get("versionId"), [stored.version])
        downloaded = self.http.get(grant.url, headers=grant.headers)
        self.assertEqual(downloaded.status_code, 200, downloaded.text)
        self.assertEqual(downloaded.content, content)
        self.assertEqual(sha256(downloaded.content).hexdigest(), sha256(content).hexdigest())

    def test_identical_signed_middle_part_retry_replaces_previous_part(self):
        self.check_replacement(b"b" * PART_SIZE)

    def test_different_same_size_middle_part_replaces_previous_bytes(self):
        self.check_replacement(b"old!!" * (PART_SIZE // 5))

    def test_wrong_size_middle_part_can_be_corrected(self):
        self.check_replacement(b"bad", inject_wrong_size=True)


class SDKMultipartRetryConformanceTests(ExchangeTestCase):
    def test_lost_successful_middle_part_response_retries_and_publishes(self):
        content = b"a" * PART_SIZE + b"b" * PART_SIZE + b"last part"
        source = self.directory / "source.bin"
        source.write_bytes(content)
        accepted = []
        listed_parts = []
        lost = False

        def lose_middle_response(response):
            nonlocal lost
            request = response.request
            if request.method != "PUT":
                return
            number = int(request.url.params["partNumber"])
            response.read()
            self.assertEqual(response.status_code, 200, response.text)
            self.assertNotIn("Authorization", request.headers)
            accepted.append((number, response.headers["ETag"]))
            if number == 2 and not lost:
                lost = True
                response.close()
                raise httpx.ReadError("response lost after successful UploadPart", request=request)

        complete = self.storage.complete

        def observe_completion(handle, size, part_size):
            listed_parts.append(self.storage.parts(handle))
            return complete(handle, size, part_size)

        with httpx.Client(event_hooks={"response": [lose_middle_response]}) as transfer:
            token = self.auth("alice")["Authorization"].split(" ", 1)[1]
            with ExchangeClient("http://127.0.0.1", token, http=self.client,
                                transfer=transfer, allow_local_http=True,
                                sleep=lambda _: tick(self.transfers)) as sdk:
                with patch.object(self.storage, "complete", side_effect=observe_completion):
                    record = sdk.put_record(
                        self.space["id"], kind="document", schema_revision_id=self.revision["id"],
                        metadata={}, files={"blob.bin": source}, state_path=self.directory / "state.json",
                        upload_seconds=60, verification_seconds=30)
                self.assertTrue(lost, "The real provider must accept the part before response loss")
                self.assertEqual([number for number, _ in accepted], [1, 2, 2, 3])
                self.assertEqual(len(listed_parts), 1)
                self.assertEqual([part.number for part in listed_parts[0]], [1, 2, 3])
                self.assertEqual([part.size for part in listed_parts[0]], [PART_SIZE, PART_SIZE, 9])
                latest_etags = dict(accepted)
                self.assertEqual([part.etag for part in listed_parts[0]],
                                 [latest_etags[number] for number in (1, 2, 3)])
                self.assertEqual(record.state, "published")
                self.assertEqual(record.attachments[0].state, "verified")
                self.assertEqual(record.attachments[0].sha256, sha256(content).hexdigest())
                downloaded = sdk.download_attachment(
                    self.space["id"], record.id, record.attachments[0], self.directory / "download.bin")
                self.assertEqual(downloaded.read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
