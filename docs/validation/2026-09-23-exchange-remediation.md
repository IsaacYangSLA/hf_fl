# Exchange remediation — 2026-09-23

This follow-up addresses the three application defects and the SeaweedFS
compatibility failures identified by the [remote validation](2026-09-23-exchange-remote.md).
Validation covered the working tree based on `60e4bf8`, before committing the
changes. Existing documentation/diagram work and the untracked `claude` file
were preserved during remediation.

## Application fixes

| Finding | Implemented behavior | Regression evidence |
|---|---|---|
| B2: temporary AWS credentials lose their token | Ambient credentials stay in boto3's provider chain. Explicit Exchange credentials accept `EXCHANGE_S3_SESSION_TOKEN`; incomplete overrides are rejected without mixing ambient credentials. Both S3 clients/signers retain tokens. | Six credential tests cover both signers, explicit/ambient precedence, invalid combinations, and refreshable role credentials. The original B2 reproducer passes. |
| B3: same-state acquisition retry gets stuck | The runner saves claim ownership and starts renewal before fetching input descriptors. Confirmed abandoned/expired claims permit a durable new key; uncertain responses, active claims, completed publication evidence, and explicitly selected claims retain their identity. Older key-only run-state files also recover. | Twelve authenticated SDK/API tests cover metadata failure followed by successful weighted publication, lost acquire/abandon/completion responses, active replay, terminal reconciliation, and explicit claim protection. |
| B8: cancellation moves cleanup into verification slots | Transfer acquisition checks the expected work category transactionally before changing state or taking a lease. Changed selections are skipped and handled by the appropriate pool on a later tick. | Seven worker tests cover cancellation before/after acquisition, wrong-pool dispatch, stale leases, competing workers, and initiation recovery. The original B8 reproducer passes. |

Completed or uncertain publications still require reconciliation; the fix does
not silently reaggregate them. An explicitly supplied claim ID is never replaced.
Older third-party adapters using the compatibility `claim_submissions` path
retain their prior behavior; persistence before input reads is implemented for
the current Exchange adapter through the separate `acquire_claim` operation.

Worker ticks still wait for both selected batches before selecting another
batch. The fix prevents cleanup from entering verification slots; it does not
introduce an independently scheduled continuous worker loop.

Four new S3 conformance tests exercise repeated identical parts, same-size
replacement, corrected-length replacement, and a lost successful middle-part
response followed by the SDK's normal retry. They retain strict part ordering,
latest ETag, final size/hash, and exact-version download assertions.

## SeaweedFS provider fix

The generic Exchange S3 adapter continues to require valid, unique multipart
parts. Unmodified SeaweedFS 4.47 remains incompatible with that retry contract.
An optional [pinned provider build](../../deploy/seaweedfs/README.md) carries the
provider-side fixes; deploying the application changes alone does not patch an
existing SeaweedFS server.

The build pins upstream source, verifies the archive checksum, and pins its Go
builder and runtime image. Its patch keeps immutable physical part files while
making ListParts and completion agree on the latest logical part. It also fixes
strict empty-bucket checks without ignoring stored versions, delete markers,
directory objects, or active multipart uploads. The recipe includes provider
regression tests and documents its single-gateway validation boundary.

The documented Dockerfile built successfully on the remote host. The resulting
`hf2l-seaweedfs:4.47-exchange1` image has local image ID
`sha256:fb501794dcfe78b50815184cc1759fc1a747088057a3abe01bc5fc1bbc5b1496`.
Its provider binary is byte-identical to the candidate used for the application
and HTTP tests: SHA-256
`4880c7d2c2a830af95f725c6fa59e5b561dc13e15df4cb38aef063360568a769`.
The image includes the upstream license, a modification notice, the matching
patch, and its operating limitations. Build commands, hashes, and comparisons
are retained in `seaweedfs-build/build-manifest.json` and the build logs under
the evidence directory below.

## Completed application verification

All commands used the relevant project `.venv`. Remote tests ran in
`ubuntu@k8s:~/wksp/hf_fl` against isolated loopback services and unique test
schemas/buckets. Existing host services were preserved.

| Configuration | Result |
|---|---|
| Local standalone Exchange, SQLite/Moto | 137 run, 135 passed, 2 expected skips |
| Local application/legacy suite, SQLite/Moto | 259 run, 258 passed, 1 expected skip |
| Remote standalone Exchange, PostgreSQL/MinIO | 137 passed, no skips |
| Remote application/legacy suite, PostgreSQL/MinIO | 260 passed, no skips |
| Remote separate API/worker HTTP harness, PostgreSQL/MinIO | 16 grouped checks passed, including a 20 MiB multipart file and process restarts |
| Remote standalone Exchange, PostgreSQL/patched SeaweedFS | 137 passed, no skips |
| Remote application/legacy suite, PostgreSQL/patched SeaweedFS | 260 passed, no skips |
| Remote separate API/worker HTTP harness, PostgreSQL/patched SeaweedFS | 16 grouped checks passed |
| Patched SeaweedFS provider HTTP regressions | 9 passed, including copy-part replacement, stale ETags, concurrent writes, logical pagination, and strict deletion |
| Full patched upstream `go test ./weed/s3api` | 834 top-level tests passed, 5 existing manual/integration tests skipped; includes 12 new patch regressions |
| Original B2/B8 reproducer on remote host | 2 passed |

The SQLite/Moto skips cover live provider signatures and PostgreSQL row locking.
Counts are the test runner's reported totals for each configuration. These rows
include overlapping tests and are not unique coverage totals. The full project
environment passes `pip check`. After the optional-dependency guard was finalized,
all twelve acquisition-recovery tests passed again locally and remotely; a
minimal-environment check confirmed twelve skips, while required-test mode fails
explicitly if those dependencies are missing.

The generated Exchange environment and error contracts were regenerated, and
the contract consistency tests pass. The [FedAvg sequence](../diagrams/fedavg-round.mmd)
and its SVG/[offline HTML](../diagrams/call-sequences.html) were updated to show
ownership persistence before metadata reads. Rendering and browser checks pass;
the other two SVGs remain byte-identical. Local HTTP fixtures require loopback
access; an initial restricted-sandbox run was stopped and rerun with that access.
FastAPI/Starlette deprecation warnings are separate from failures.

Both live providers passed the new multipart replacement/response-loss tests.
The SeaweedFS candidate used strict bucket deletion
(`-s3.allowDeleteBucketNotEmpty=false`), including during fixture teardown.
The HTTP harness used controlled restarts between operations; this does not
establish recovery from crashes during provider mutations or SDK process restart.

To repeat the suite checks, configure the isolated database/provider and
dedicated AWS test credentials described in the [runbook](../EXCHANGE_V3.md),
then run from the repository root:

```bash
EXCHANGE_REQUIRE_TESTS=1 .venv/bin/python -m unittest discover -s packages/exchange/tests -v
EXCHANGE_REQUIRE_TESTS=1 .venv/bin/python -m unittest discover -s tests -v
.venv/bin/python deploy/seaweedfs/test_provider.py
```

The last command requires a provider with strict bucket deletion enabled and
creates/deletes only its own disposable buckets.

## Evidence and remaining scope

Fresh logs and source manifests are retained under
`work/remediation-20260923/` on both the local and remote checkouts. The original
validation evidence remains under `work/validation-20260923T1915Z/`.

Final cleanup verified zero custom database schemas and zero buckets on all
three test S3 endpoints. The four owned service containers and their disposable
data were removed, along with the duplicate manual Go build caches. The project
environments, final provider image, Docker build cache, and evidence remain for
reproduction. Other host services were left untouched.

B1 and B4–B7 from the earlier architecture audit were outside the findings fixed
in this follow-up and remain documented. This work does not establish production
TLS/IdP/IAM integration, real AWS STS access, large-scale throughput, multi-node
availability, or Python 3.10 runtime coverage. No image or package was published.
