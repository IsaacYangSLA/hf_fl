# Exchange remote validation — 2026-09-23

This is the historical validation of `60e4bf8`. See the
[remediation follow-up](2026-09-23-exchange-remediation.md) for subsequent fixes
and new verification results.

The existing Exchange suites and a separate live HTTP/process test pass against
PostgreSQL and MinIO. SeaweedFS 4.47 passes ordinary workflows, but a multipart
retry incompatibility blocks treating it as a drop-in replacement; its strict
bucket-deletion behavior also differs, as described below.
Three focused probes reproduce unresolved application
defects: temporary AWS credentials lose their session token (B2), an acquisition
retry can remain stuck after a metadata outage (B3), and cancellation can move
cleanup into the verification worker pool (B8). Passing the existing suites does
not establish that these defects are fixed.

## Tested source and environment

- Host: `ubuntu@k8s`, reporting hostname `ip-172-31-62-58`; Ubuntu 24.04,
  x86-64, 4 CPUs, approximately 15 GiB RAM. This host reports an AWS kernel.
- Checkout: `/home/ubuntu/wksp/hf_fl`, newly created for this validation.
- Commit: `60e4bf89039b6f9675c9484ad8f9e030b68dd2b8`, detached checkout.
  The seven existing tracked documentation edits were copied as well. Application
  source and tests were not changed. All **178 tracked files** matched the local
  checkout byte for byte by SHA-256 after testing.
- Python: **3.12.3**, using the remote project's `.venv`.
- Docker: **29.2.1**. Test services were bound to loopback addresses.
- PostgreSQL 18 image:
  `postgres@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280`.
- MinIO CI baseline image:
  `quay.io/minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e`.
  This validates the existing pinned baseline; it is not a recommendation to
  deploy the archived MinIO community product.
- CPU-only Torch and the declared local package extras were installed. Exact
  versions are preserved in `requirements.freeze.txt` and the three isolation
  environment records.

Ubuntu's missing `python3.12-venv` package was installed. Public image pulls used
an empty, isolated Docker configuration because the host's existing registry
login failed. Existing services and registry configuration were not changed.

## Results

Counts below are fresh results from this host. The same tests appear in multiple
configurations; these rows must not be added together as unique test coverage.

| Validation | Run | Passed | Skipped | Failed |
|---|---:|---:|---:|---:|
| Standalone Exchange, SQLite/Moto | 120 | 118 | 2 | 0 |
| Standalone Exchange, PostgreSQL/MinIO | 120 | 120 | 0 | 0 |
| Standalone Exchange, PostgreSQL/SeaweedFS default configuration | 120 | 120 | 0 | 0 |
| Full HF²L/application/legacy suite, SQLite/Moto | 248 | 247 | 1 | 0 |
| Full HF²L/application/legacy suite, PostgreSQL/MinIO | 248 | 248 | 0 | 0 |
| Full HF²L/application/legacy suite, PostgreSQL/SeaweedFS | 248 | 247 | 0 | 1 |
| Minimal core architecture/layering/protocol/checkpoint suite | 65 | 63 | 2 | 0 |
| Separate API/worker process HTTP checks, PostgreSQL/MinIO | 16 | 16 | 0 | 0 |
| Separate API/worker process HTTP checks, PostgreSQL/SeaweedFS | 16 | 16 | 0 | 0 |
| Additional SeaweedFS credential/signature checks | 9 | 9 | 0 | 0 |
| Focused B2/B8 intended-contract tests | 2 | 0 | 0 | 2 |
| Focused B3 recovery probe | 1 | 0 | 0 | 1 |

Clean **core-only**, **SDK-only**, and **server-only** installations passed their
dependency/import checks and `pip check`. The core check exercised NumPy
aggregation, a LocalStore round trip, and installed command entry points. These
checks used separate `.venv` directories and private source copies under the
validation directory. The full project environment also passed `pip check`.

The SQLite/Moto skips concern provider signature enforcement and PostgreSQL row
locks. The minimal core skips concern deliberately absent JSON Schema and Torch
dependencies. FastAPI/Starlette deprecation warnings were emitted separately
from failures.

The standalone and root live suites cover storage signatures, versioned objects,
authorization, metadata limits, leases/fencing, transfer interruption and repair,
and a complete Exchange-backed NumPy FedAvg round. Some tests intentionally use
injected failures or provider doubles even when live provider settings are set.

## Live HTTP and process checks

The additional harness launched the actual `hf2l-exchange` CLI API and worker in
separate OS processes, using TCP HTTP, PostgreSQL, and direct S3 transfers. Each
run owned a unique database schema, versioned bucket, and synthetic RSA identity.

It verified:

- Database initialization and database/storage readiness checks.
- API health/readiness and rejection of missing, expired, wrong-issuer,
  wrong-audience, and wrong-scope JWTs.
- Idempotent creation, conflicting replay rejection, membership isolation,
  reader write denial, private-record visibility, and revocation of new grants.
- A **20 MiB + 137 byte file**, uploaded in **five parts**, resuming after an API
  process restart; a separate worker completed verification before publication.
- SDK download with matching SHA-256; exact-version download after overwriting
  the same key; rejection of modified signatures and unsigned object reads.
- Acquisition replay, mutual exclusion, renewal, completion replay, reference
  advancement, and rejection of stale compare-and-swap operations.
- Worker restart with queued work, rejection of incorrect content hashes, and
  release of reclamation quota after failed-upload cleanup.

All 16 grouped checks passed against each provider. The harness stopped its processes and removed its
own schema, multipart uploads, object versions, and bucket. An initial harness
run used an invalid subsecond polling setting; that harness setting was corrected
to one second before the successful run. No application change was needed.

These were controlled restarts between operations, not crashes during provider
mutations. Upload resume used the multipart control API directly, not a restarted
SDK client's persisted `put_record` state. The failed-upload cleanup check asserted
zero reclaiming quota and no remaining multipart uploads; it did not independently
check that failed-object versions were absent before fixture teardown. Successful
teardown exercised version-specific deletion, and the separate S3 conformance
test verified that a cleaned exact version became unavailable. The acquisition
checks do not establish expired-lease takeover; that belongs to the suite tests.

## SeaweedFS compatibility

The same unmodified implementation was exercised against authenticated SeaweedFS
**4.47**, pinned to
`chrislusf/seaweedfs@sha256:ce9e796f1fe6f06968f4c04bdaf8f678dad9c8acdfef3d244133d71bfa6bf882`,
with S3 exposed only on `127.0.0.1:18333`. The standalone suite passed 120/120,
the focused integration/conformance subset passed 13/13, and the separate
API/worker harness passed 16/16. The focused 13 are already included in the 120.

Nine additional provider checks passed: valid signed GET/UploadPart requests
succeeded, and anonymous requests, invalid credentials, modified signatures,
and expired signed downloads were rejected. Multipart completion, exact-version
reads after overwrites, and attempt-scoped version deletion passed.

**Multipart replacement/retry is incompatible in this version.** The broader
application/legacy suite passed 247/248: `test_parts_authorization_and_completion_errors`
failed because re-uploading part 1 returned both its old three-byte entry and
its replacement four-byte entry. A separate probe against the **current v2**
`S3BlobStore` confirmed the problem in three cases: corrected length, different
bytes of the same length, and identical bytes retried. SeaweedFS returned two
entries for part 1 and v2 completion raised `invalid_parts` in every case.
MinIO retained only the latest entry and completed/verified all three cases.

The SDK retries the same part after a transport failure, so repeated identical
uploads are a necessary provider contract. A further probe used the unchanged
current `ExchangeClient.put_record`, v2 API/application, isolated PostgreSQL, and
real provider HTTP. It simulated losing the response after the first successful
UploadPart. Both providers accepted the SDK's retry with HTTP 200; SeaweedFS then
returned HTTP 409 `invalid_parts`, while MinIO reached `published`.
This result is a blocker for choosing
SeaweedFS 4.47 for the current Exchange retry guarantees, despite the existing
120-test standalone suite and ordinary live HTTP checks passing. Use a provider
or corrected SeaweedFS build that passes replacement and response-loss cases;
add these cases to the standalone conformance suite. Do not weaken multipart
validation merely to accept duplicated part numbers. Evidence is retained in
`logs/root-postgres-seaweedfs.log` and `seaweedfs/multipart-overwrite-probe.log`.
The direct SDK evidence is `seaweedfs/sdk-lost-upload-response-probe.log`.

With `-s3.allowDeleteBucketNotEmpty=false`, the 13 focused test methods instead
reported **six fixture teardown errors**: `DeleteBucket` returned `BucketNotEmpty`
despite zero listed objects, versions, delete markers, and multipart uploads.
The same tests pass with SeaweedFS's default recursive bucket deletion enabled.
That default-mode pass does not establish strict S3 bucket-deletion equivalence.
Exchange uses a preconfigured bucket and does not delete buckets at runtime, so
the observed issue concerns provider administration/test teardown. Do not replace
Exchange's exact-version cleanup with recursive bucket deletion to work around it.

An initial candidate run exhausted eight default volume slots when strict-mode
test buckets accumulated. The isolated configuration increased the slot limit
to 128 with a 256 MiB volume-size cap and no preallocation. This removed the
capacity failures; the strict deletion anomaly remained. The candidate report,
startup scripts, authentication probe, and initial/strict/default logs are retained
under `seaweedfs/`. This is evidence for this tested configuration, not a claim of
complete drop-in S3 or production equivalence.

## Confirmed unresolved findings

### B2 — Temporary AWS session credentials are dropped

`StorageSettings.from_env()` copies AWS access and secret keys into explicit
settings, and `S3BlobStore._make_client()` supplies them without a session token.
Both the internal client and public-endpoint signer lose `AWS_SESSION_TOKEN`;
their generated URLs omit `X-Amz-Security-Token`. A plain boto3 environment-chain
control retains the token.

Evidence: `logs/audit-b2-b8.log`; synthetic credentials, zero network requests.
Relevant code: [config.py](../../packages/exchange/src/hf2l_exchange/config.py)
and [storage.py](../../packages/exchange/src/hf2l_exchange/storage.py).

Suggested correction: preserve boto3's credential resolution unless explicit
Exchange overrides are provided. If explicit temporary credentials are supported,
carry their session token into both clients/signers. Test both paths.

### B3 — Same-state acquisition recovery remains stuck

A three-response metadata HTTP 503 window exhausts SDK retries after acquisition.
The adapter abandons the acquisition before the runner has persisted its claim
ownership. Two subsequent attempts using the same run-state and fresh output
directories both return HTTP 409 `acquisition_not_active`. The acquisition key
remains unchanged and no claim ID is saved. A separate fresh-key control acquires
both inputs with fence 2 after abandoned fence 1.

Evidence: `logs/audit-b3.log`; real runner, SDK, FastAPI handlers, JWT and SQLite,
with a deterministic transient-response injection and metadata-only records.
This probe does not perform blob transfer or simulate a physical network outage.
Relevant code: [ExchangeStore](../../hf2l/backends/exchange.py) and
[FedAvgRunner](../../hf2l/fedavg_runner.py).

Suggested correction: record ownership before fetching input details and reconcile
confirmed terminal acquisitions on retry. Replace keys only after confirmed
abandonment; preserve uncertain outcomes for reconciliation. The fresh-key control
is evidence, not a recommendation to blindly delete an operator's run-state.

### B8 — Cancellation can consume verification capacity with cleanup

With one slot per pool, the worker selects one verification item and no cleanup
items. Cancelling that record before dispatch causes `cleanup` to execute on
`verification_0`. `TransferService.process()` ignores its `cleanup` argument,
and acquisition accepts the changed state.

Evidence: `logs/audit-b2-b8.log`; real application, transfer, worker and SQLite
logic, with a recording storage double and a deterministic scheduling hook.
Relevant code: [transfers.py](../../packages/exchange/src/hf2l_exchange/transfers.py)
and [worker.py](../../packages/exchange/src/hf2l_exchange/worker.py).

Suggested correction: enforce the expected lifecycle category transactionally
during acquisition and skip/requeue changed selections. Cover cancellation between
selection and acquisition, not only static queue contents.

## Evidence and reproduction

Evidence is retained at both locations:

```text
Remote: /home/ubuntu/wksp/hf_fl/work/validation-20260923T1915Z/
Local:  work/validation-20260923T1915Z/
```

The directory contains suite logs, source hashes, dependency freezes, the live
HTTP reports and process logs, isolation results, custom harnesses, and provider probes.
The `work/` directory is ignored by Git. This Markdown report is retained under
`docs/validation/`; no commit or push was performed.

From the remote checkout, start the pinned isolated services on ports 15432
(PostgreSQL) and 19000 (S3), then reproduce the baseline checks. The startup
script refuses to replace containers that already exist:

```bash
cd ~/wksp/hf_fl
bash work/validation-20260923T1915Z/start-baseline.sh
export EXCHANGE_REQUIRE_TESTS=1
export EXCHANGE_TEST_DATABASE_URL='postgresql+psycopg://hf2l_test:local-validation-only@127.0.0.1:15432/hf2l_test'
export EXCHANGE_TEST_S3_ENDPOINT='http://127.0.0.1:19000'
export AWS_ACCESS_KEY_ID='hf2l-validation'
export AWS_SECRET_ACCESS_KEY='local-validation-only-password'
export AWS_DEFAULT_REGION='us-east-1'
.venv/bin/python -m unittest discover -s packages/exchange/tests -v
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python work/validation-20260923T1915Z/hf_fl_http_validation/validate_http.py \
  --report-dir work/validation-20260923T1915Z/live-http-repeat
```

The credentials above belong only to disposable loopback test services. The test
fixtures require permission to create and delete their own schemas and buckets;
they must not use production administration credentials. For SQLite/Moto, unset
the two `EXCHANGE_TEST_*` variables before running the suites.

The targeted probes deliberately return nonzero while the defects remain:

```bash
.venv/bin/python work/validation-20260923T1915Z/hf_fl_validation_repros/test_exchange_audit_b2_b8.py
.venv/bin/python work/validation-20260923T1915Z/hf_fl_claim_validation/reproduce_b3.py --require-fixed
```

## Final cleanup

A separate read-only check confirmed **zero test database schemas and zero
buckets on both providers** after all suites and probes finished. All API/worker
processes created by the live harnesses were stopped. The three named validation
containers, their anonymous volumes, and the SeaweedFS test data directory were
removed. No validation container remains running or stopped. Existing host
services were preserved.

The checkout, project/isolation virtual environments, cached images, logs and
reproduction scripts remain for follow-up work. No production Exchange deployment
was left running. `logs/resource-cleanup-check.json` and
`logs/container-cleanup.log` record the final cleanup. The earlier provider report
describes its intermediate handoff with a running container; this final state
supersedes that handoff.

## Scope limits

This run validates Python 3.12, not Python 3.10. It does not establish production
TLS/IdP/IAM configuration, real AWS STS behavior, sustained large-file throughput,
multi-node availability, backup/restore, or production readiness. HF/JFrog adapter
coverage used SDK doubles rather than live external services. B1 and B4–B7 from
the earlier architecture audit were not specifically re-probed in this
Exchange-focused run and must not be considered fixed because the suites pass.
