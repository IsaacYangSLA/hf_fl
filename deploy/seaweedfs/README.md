# SeaweedFS provider compatibility build

Unmodified SeaweedFS 4.47 returns duplicate multipart part numbers after a retry,
which Exchange correctly rejects as `invalid_parts`. Its strict DeleteBucket
check also mistakes empty implicit prefixes for stored objects. This optional
source build applies [the provider patch](seaweedfs-4.47-exchange.patch) while
keeping Exchange's generic S3 adapter and integrity checks unchanged. This is a
local compatibility build, not an upstream release or a production HA validation.

## Build

From the repository root:

```bash
docker build -t hf2l-seaweedfs:4.47-exchange1 deploy/seaweedfs
```

The Dockerfile pins SeaweedFS commit
`c5073360007d28385a33426a42ac3e4ec504c5a3`, verifies its source archive SHA-256,
and pins both builder and runtime images by digest. It runs the patch's Go
regression tests before compiling the binary. The patch tests are included in
the patch itself and can also run in a patched source checkout:

```bash
go test ./weed/s3api -run '^TestHF2L' -count=1 -v
```

The resulting binary identifies itself with `c50733600-hf2l1`. Retain the built
image digest alongside deployment records; a floating `4.47` upstream tag does
not include this fix. The build needs Internet access to the pinned source,
container registries, and Go's module proxy/checksum database.

## What changes

Multipart parts retain immutable provider files. Successful writes record a
private nanosecond timestamp, including empty parts and UploadPartCopy. A process-local monotonic sequence
prevents wall-clock adjustments from reordering writes within the gateway. ListParts and completion
use the same latest entry for each part number, instead of UUID filename order.
The list scans physical pages before applying S3 part-number pagination, so
retries cannot duplicate or skip logical parts. Completion rejects an overwritten
part's stale ETag. Conflicting entries with indistinguishable timestamps fail
closed. Exact version downloads and final size/SHA-256 verification remain in
Exchange.

Strict bucket deletion recursively checks prefixes and internal directories. It
preserves ordinary files, explicit directory objects, noncurrent versions,
delete markers, and active multipart uploads. Only a namespace containing empty
implicit directories qualifies as empty. Listing errors fail closed.

Drain or abort existing multipart uploads before switching a running deployment
to this build. Existing uploads lack the new ordering metadata; their internal
chunk timestamps provide a compatibility fallback but cannot prove all possible
historical ordering, especially across clocks. Use this compatibility build with **one S3 gateway only**. Its process-local
sequence does not establish write order across gateways, and clock synchronization
does not make that ordering safe. Multiple gateways need a durable provider
sequencer and additional tests. After a clock rollback across a gateway restart,
abort outstanding multipart uploads before resuming writes. Functional validation
on one provider node does not establish HA behavior.

## Run and validate

Use the same authenticated S3 configuration, versioned bucket, service endpoint,
and public endpoint settings described in [the Exchange runbook](../../docs/EXCHANGE_V3.md).
Do not enable anonymous access. For strict S3 bucket deletion, add
`-s3.allowDeleteBucketNotEmpty=false` to `weed server` and retain
`-s3.autoCreateBucket=false`. Existing data directories must not be shared by
simultaneously running provider versions.

Run the Exchange tests against an isolated provider and database using the
runbook's `EXCHANGE_TEST_S3_ENDPOINT` and `EXCHANGE_TEST_DATABASE_URL` settings.
The validation must cover identical retries, different-size and same-size part
replacement, lost successful PUT responses, part pagination, stale ETag
rejection, exact-version reads, and strict empty-bucket deletion. Keep test
credentials and disposable buckets separate from deployment data.

## Upstream source evidence

- [4.47 part naming](https://github.com/seaweedfs/seaweedfs/blob/c5073360007d28385a33426a42ac3e4ec504c5a3/weed/s3api/s3api_object_handlers_multipart.go#L543)
- [4.47 part listing and completion](https://github.com/seaweedfs/seaweedfs/blob/c5073360007d28385a33426a42ac3e4ec504c5a3/weed/s3api/filer_multipart.go)
- [4.47 strict bucket emptiness check](https://github.com/seaweedfs/seaweedfs/blob/c5073360007d28385a33426a42ac3e4ec504c5a3/weed/s3api/s3api_bucket_handlers.go#L548)
- [AWS repeated UploadPart semantics](https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html)

This repository does not publish or deploy the image automatically. The patch
should be replaced by an upstream release only after the same conformance
checks pass; an upstream fix has not been confirmed.

The runtime image retains upstream components and includes the SeaweedFS Apache
license, a modification notice, this README, and the exact source patch under
`/usr/share/doc/seaweedfs/`. The pinned upstream source has no root NOTICE file.

Run this bundle's provider-specific live regressions against an isolated strict
endpoint with disposable credentials in the AWS environment variables:

```bash
EXCHANGE_TEST_S3_ENDPOINT=http://127.0.0.1:18334 \
  .venv/bin/python deploy/seaweedfs/test_provider.py
```

These tests create uniquely named buckets, delete only their own objects and
uploads, and require strict bucket deletion; they intentionally fail against an
unpatched provider.
