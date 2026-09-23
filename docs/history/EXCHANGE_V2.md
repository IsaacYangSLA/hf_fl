# Exchange v2: service, SDK and operations

Exchange v2 exchanges bounded JSON metadata and immutable file attachments.
The API authorizes control requests, PostgreSQL stores metadata, and clients move
file bytes directly to private versioned S3. Generic usage requires no model,
training round, participant identifier or ML library. An optional `fedavg.v1`
profile supplies the HF²L application rules.

See the [architecture review and design](ARCHITECTURE_REVIEW_AND_V2_DESIGN.md)
for the rationale and [package guide](../../packages/exchange/README.md) for install
boundaries. This is an unreleased development implementation, not a provisioned
service or a published package.

## Deployment boundary and installation

Use a **fresh database and fresh S3 prefix**. The HTTP API is `/v2`; it does not
serve `/v1`, upgrade legacy data, or provide an importer. The old
`hf2l-exchange-service` command belongs to the
[legacy service](../EXCHANGE_SERVICE.md). The new command is `hf2l-exchange`.

From the repository root, using the project environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e './packages/exchange[server]'
.venv/bin/hf2l-exchange --help
```

SDK-only clients install `./packages/exchange`, without the `server` extra.
Neither installation requires Torch, Hugging Face, NumPy or SafeTensors.
PostgreSQL is the deployment database. SQLite is available for local development;
it serializes writes and is not the scale-out configuration. S3 with bucket
versioning is the only implemented blob provider.

## Configure and start

Supply configuration through the environment or your secret manager:

```bash
export EXCHANGE_DATABASE_URL='postgresql+psycopg://USER:PASSWORD@DB_HOST/exchange_v2'
export EXCHANGE_ISSUER='https://identity.example.com'
export EXCHANGE_AUDIENCE='exchange'
export EXCHANGE_JWKS_URL='https://identity.example.com/.well-known/jwks.json'
export EXCHANGE_ADMIN_SUBJECT='BOOTSTRAP_ADMIN_SUBJECT'
export EXCHANGE_S3_BUCKET='private-exchange-v2'
export EXCHANGE_S3_PREFIX='exchange-v2/'
export EXCHANGE_S3_REGION='us-east-1'
# Set when using an S3-compatible endpoint:
export EXCHANGE_S3_ENDPOINT='https://objects.example.com'
```

Choose exactly one trusted key source: `EXCHANGE_JWKS_URL` or the RSA public PEM
value in `EXCHANGE_JWT_PUBLIC_KEY`. The service validates RS256 access tokens with
`typ=at+jwt`, the configured issuer/audience, `sub`, `iat`, `exp`, and the
`exchange` scope. It does not issue tokens. Human login and workload identity
provisioning belong to the identity provider.

S3 uses its credential provider chain unless a paired
`EXCHANGE_S3_ACCESS_KEY`/`EXCHANGE_S3_SECRET_KEY` is configured. AWS environment
credentials are also accepted. End clients receive only narrowly scoped signed
transfer grants. If service-side and public S3 addresses differ, set
`EXCHANGE_S3_PUBLIC_ENDPOINT`; both addresses must resolve to the same bucket and
use the same signing credentials.

Initialize only the new database, check dependencies, then supervise API and
worker as separate processes:

```bash
.venv/bin/hf2l-exchange init-db
.venv/bin/hf2l-exchange check-db
.venv/bin/hf2l-exchange check-storage
.venv/bin/hf2l-exchange serve --host 127.0.0.1 --port 8000 --workers 2
# Run independently of the API process:
.venv/bin/hf2l-exchange worker
```

Database commands require database settings only. The storage check requires
storage settings only. The worker does not need JWT verification configuration.
`migrate-db` applies the v2 revision ledger; it is not a v1 importer. Stop services
and back up data before future schema upgrades.

Expose the API through HTTPS. The ASGI application requires the HTTPS request
scheme, so configure trusted proxy forwarding when TLS terminates upstream.
Apply connection/request timeouts and rate limits at that boundary. Configured
identity/storage URLs and SDK grant URLs require HTTPS. Explicit
`EXCHANGE_ALLOW_LOCAL_HTTP=true` and SDK `allow_local_http=True` are for local
loopback development only; bind such a development server to loopback.

`GET /health` is process liveness; `GET /ready` checks the schema revision and
versioned storage. Startup does not migrate the database or require dependencies
to be available. Interactive docs and OpenAPI are disabled by default; enable
`EXCHANGE_DOCS_ENABLED=true` only where their exposure is appropriate. They are
not a replacement for access control.

The bucket must be private, have versioning enabled, and prevent end-client
listing, arbitrary writes and deletion. Service identities need multipart
initiation/listing/completion/abort, exact-version reads and signing rights;
cleanup also needs deletion of owned object versions. Do not configure a bucket
lifecycle rule that removes versions referenced by live records. Configure
encryption, TLS, IAM, backup/restore and central log retention for the deployment.

## Spaces, roles and types

Only the configured bootstrap administrator creates spaces. The creator receives
all four explicit roles. `generic.v1` is the default; `fedavg.v1` is optional and
the selected profile cannot change. A space is the isolation boundary; there is
no tenant administration hierarchy or inferred isolation from labels.

| Role | Data permissions | Administration |
|---|---|---|
| `reader` | Read shared published records and their attachments | None |
| `contributor` | Read shared published records and own records; create/publish types permitting this role | None |
| `publisher` | Read published records including private records, and own drafts; publish permitted types, move references, acquire/complete coordinated work | None |
| `admin` | No implicit content-read or publish permission | Memberships, type revisions, policies, cancellation and metadata purge |

Roles are additive. Revoked membership denies new operations even to a former
creator. Existing signed URLs remain bearer capabilities until their expiry;
revocation cannot recall bytes already downloaded.

Administrators register immutable type revisions using JSON Schema draft
2020-12. Records select a revision by its server ID. New revisions do not change
existing drafts or published content. Registration returns both an opaque
revision ID for record creation and a per-kind revision number for the type-read
route. Schemas use an object root, are bounded to 64 KiB and depth 16, and are
validated locally without network retrieval. Local nonrecursive JSON-pointer
references are supported; external, dynamic and recursive references are not. Each kind separately has current publication roles and
`shared`/`private` visibility. Updating policy applies visibility to existing
records and is distinct from changing their pinned schema. A policy change cannot
make a currently referenced kind private; references require shared content.

The generic profile reserves no model kind or FedAvg filename. Its ordinary
`main` reference can identify any shared published record.

## Generic SDK example

The owner token below is an access token for the configured bootstrap subject.
Obtain it from the identity provider, not from the Exchange API. The example
creates a generic space, registers a document type and publishes a local file.
Keep operation state on durable local storage to resume the same upload after an
interruption.

```python
import os
from pathlib import Path
from hf2l_exchange.client import ExchangeClient

with ExchangeClient(os.environ["EXCHANGE_ENDPOINT"], os.environ["EXCHANGE_TOKEN"]) as client:
    space = client.create_space("shared-reports", idempotency_key="example-space-v1")
    revision = client.register_type(
        space.id, "report",
        {"type": "object", "properties": {"title": {"type": "string"}},
         "required": ["title"], "additionalProperties": False},
        idempotency_key="example-report-type-v1",
    )
    record = client.put_record(
        space.id, kind="report", schema_revision_id=revision.id,
        metadata={"title": "Daily observations"},
        files={"observations.csv": Path("observations.csv")},
        state_path=Path("operation-state/report.json"),
    )
    reference = client.set_ref(
        space.id, "main", record.id, idempotency_key="example-first-main-v1"
    )
    print(space.id, record.id, reference.token)
```

Create `observations.csv` before running the example. The API and worker must
both be running for file verification. To exchange only small information, omit
`files`. Supply a callable token provider instead of a string when a long-running
client needs refreshed credentials.

A later publisher resolves `main` first and passes that `ReferenceSnapshot` as
`reference=` to `set_ref`; a competing update fails its precondition. Reusing
an operation key with different request content fails. The example keys identify
one logical setup operation; choose new keys for new logical operations.

Readers use `get_record` or `records` to obtain small metadata before choosing
which attachment to download:

```python
with ExchangeClient(os.environ["EXCHANGE_ENDPOINT"], os.environ["EXCHANGE_TOKEN"]) as client:
    reference = client.resolve(space_id, "main")
    record = client.get_record(space_id, reference.record_id)
    print(record.metadata)
    for attachment in record.attachments:
        client.download_attachment(space_id, record.id, attachment,
                                   Path("downloads") / attachment.path)
```

For a complete runnable example, [generic_exchange.py](../../examples/generic_exchange.py)
uploads a text document, discovers and downloads it, acquires processing work,
creates an uppercase result and completes the acquisition:

```bash
export EXCHANGE_TOKEN='ACCESS_TOKEN'
.venv/bin/python examples/generic_exchange.py \
  --endpoint 'https://exchange.example.com' \
  --input report.txt --work-dir document-run
```

Create the UTF-8 input first. Reuse the work directory only to resume that same
logical run; different jobs need different directories. The token must be the
bootstrap administrator, or use `--space` with an existing generic space and the
required type-administration and publication roles.

The reader needs membership and a data role in the space. Administrators enroll
identities with `set_member` and the service principal ID derived from the trusted
issuer and subject; roles and profile bindings come from administration, not
record metadata. `get_membership` reports the caller's principal ID and roles. In a service
administration environment, the trusted subject can be enrolled as follows:

```python
from hf2l_exchange.auth import principal_id

alice = principal_id(os.environ["EXCHANGE_ISSUER"], "alice-subject")
with ExchangeClient(os.environ["EXCHANGE_ENDPOINT"], os.environ["EXCHANGE_TOKEN"]) as admin:
    admin.set_member(space_id, alice, ["contributor"], subject="alice-subject")
```

`auth` is a server module, used here only by the administrator. The SDK itself
requires no JWT verifier or server dependencies. An administrator can revoke
membership by assigning an empty roles list; the last administrator cannot remove
its own final administrative role.

## HTTP contract

The SDK uses ordinary Bearer-authenticated JSON requests. All scoped paths below
begin with `/v2/spaces/{space}`. Transfer grants carry their own signed
credentials; the API bearer token must never accompany a storage request.

| Resource | Routes and behavior |
|---|---|
| Spaces | `POST /v2/spaces`, `GET/PATCH /v2/spaces/{space}`; creation selects the profile, admin PATCH updates quotas |
| Members | `GET /membership`, `GET /members`, `PUT /members/{principal}`; explicit roles, optional subject and profile bindings |
| Types | `GET /types`, `POST /types/{kind}/revisions`, `GET /types/{kind}/revisions/{revision}` |
| Policy | `PUT /policies/{kind}` changes current publication roles/visibility |
| Records | `POST /records`, `GET /records`, `GET/PATCH/DELETE /records/{id}`, `POST /records/{id}/publish`, `POST /records/{id}/purge` (admin, after cleanup) |
| References | `GET/PUT /refs/{name}`; `ETag` identifies the current reference token |
| Acquisitions | `POST /acquisitions`, `GET /acquisitions/{id}`, `POST /acquisitions/{id}/renew`, `/abandon`, `/complete` |
| Events | `GET /events`; retained authorized cursor feed |
| Transfers | Under `/records/{record}/attachments/{attachment}`: `POST /upload`, `GET /parts`, `POST /grants`, `POST /complete`, `GET /download` |

Space/type/record creation, record publication, reference changes, acquisition
and acquisition completion require a 1–128-character `Idempotency-Key`.
Kind and reference names use 1–128 ASCII characters: an initial letter or digit,
followed by letters, digits, `.`, `_` or `-`. Generic names have no FedAvg
reservation. Creation of a reference uses `If-None-Match: *`; updating it uses the quoted token
in `If-Match`. Draft metadata PATCH requires its quoted record version in
`If-Match`. Missing or failed preconditions are errors, not unconditional writes.

Errors contain `error.code`, `error.detail` and `error.request_id`; responses also
carry `X-Request-ID`. Treat stable codes as machine-readable results. SDK retries
transient transport/status failures with bounded delays and honors `Retry-After`.
A publication/coordination retry must retain its original operation identity.

## Coordination and optional FedAvg

Generic acquisitions operate on an existing reference and explicitly chosen
published inputs. They capture the expected reference token and freeze the input
set. Only one active acquisition can own a given space/reference. A renewed
lease retains the fencing value; a replacement attempt receives a later fence.
Completion validates ownership and the expected reference, accepts the published
shared result and advances the reference in the same transaction. A stale holder
cannot publish through completion or bypass an active acquisition with ordinary
reference updates.

Persist acquisition and completion state paths separately. Explicit acquisition
recovery uses its handle or the original saved key, not holder identity alone.
The default lease is 300 seconds; acquisition accepts 10–3600 seconds, and
renewal uses the configured coordination duration. Renew before expiry for long
computations and stop publication if ownership is lost. Successful completion
can be replayed for the same result; a different result is a conflict.

The trusted `fedavg.v1` profile adds `training.update` and `model.global`, a
protected `main`, participant bindings and common-base/result-provenance checks.
Only `main` carries this protected-reference behavior; other reference names
use the generic rules. The model-global kind must remain publisher-only/shared,
and training updates remain contributor-published. Schemas for mandatory profile
fields use a restricted subset so composed constraints cannot silently make the
profile unusable. Custom generic kinds retain the general supported schema subset.
It selects eligible newest-per-participant inputs with at least two participants,
or accepts an explicit subset of those eligible inputs. The result may declare
the subset actually used, still with at least two distinct participants; it may
not add inputs outside the frozen acquisition. The service checks current
membership/bindings when acquiring and completing.
Checkpoint compatibility, honest training data, example-count quality and model
evaluation remain HF²L application responsibilities.

## HF²L application setup on v2

Install the two local distributions together as shown in the validation section.
The root HF²L application retains its ML dependencies. An administrator creates a
FedAvg space and its immutable initial type revisions:

```python
with ExchangeClient(os.environ["EXCHANGE_ENDPOINT"], os.environ["EXCHANGE_TOKEN"]) as admin:
    space = admin.create_space("training", profile="fedavg.v1",
                               idempotency_key="training-space-v1")
    admin.register_type(space.id, "model.global", {"type": "object"},
                        publish_roles=["publisher"], visibility="shared",
                        idempotency_key="global-type-v1")
    admin.register_type(space.id, "training.update", {"type": "object"},
                        publish_roles=["contributor"], visibility="private",
                        idempotency_key="update-type-v1")
    # Compute this principal ID from the configured issuer and trusted IdP subject.
    admin.set_member(space.id, alice_principal_id, ["reader", "contributor"],
                     subject="alice-subject", bindings={"participant": "alice"})
    print(space.id)
```

Enroll at least two distinct participants, each with its own subject and
participant binding. The owner needs `publisher`; the bootstrap creator already has all roles. Export `EXCHANGE_ENDPOINT` and the current actor's
`EXCHANGE_TOKEN`, or `EXCHANGE_TOKEN_FILE` for refreshed file-based credentials.
Here `EXCHANGE_SPACE_ID` is the printed space ID, not an HF repository name.

Owner initialization uses the existing local model/plugin interface:

```bash
.venv/bin/python -m hf2l.init_repo \
  --backend exchange --repo-id "$EXCHANGE_SPACE_ID" --plugin lenet
```

The owner resolves `main` and supplies its immutable record ID as the common
`BASE_RECORD_ID`. Each participant runs with its own token and its assigned
participant name:

```bash
.venv/bin/python -m hf2l.client_train \
  --backend exchange --repo-id "$EXCHANGE_SPACE_ID" \
  --base-revision "$BASE_RECORD_ID" --participant alice \
  --work-dir work/alice-round-0 --plugin lenet
```

The owner validates and publishes through an acquisition:

```bash
.venv/bin/python -m hf2l.owner_fedavg \
  --backend exchange --repo-id "$EXCHANGE_SPACE_ID" \
  --claim-submissions --claim-lease-seconds 300 \
  --run-state work/round-0-state.json \
  --output-dir work/round-0 --publish
```

V2 Exchange publication requires `--claim-submissions` or `--claim-id`.
`--run-state` preserves the acquisition key, reference and handle across an
interrupted run; a retry uses a new output directory and the same run-state file.
An explicit `--claim-id` resumes a known active acquisition. The owner renews the
lease while processing and refuses publication after ownership loss.

`--require-concurrent-publication` requires a backend with an atomic publication
precondition. HF uses its conditional commit and Exchange uses its reference and
acquisition fencing. JFrog currently provides a preflight check and needs a single
writer; the owner rejects it when the stronger guarantee is requested. A confirmed
primary publication remains a successful result even if a later tag creation
fails; the CLI reports the revision and separate warning.

## Capacity, lifecycle and recovery

Space creation defaults to 10 GiB blob capacity, a 10 GiB per-principal physical
blob limit, 100,000 retained records and 1 GiB canonical metadata. Administrators can change `quota_bytes`,
`principal_quota_bytes`, `quota_records` and `quota_metadata_bytes` with
`PATCH /v2/spaces/{space}`; each supplied limit must be positive and cannot be
reduced below its currently charged usage. The SDK exposes this as
`update_space_limits(space_id, quota_records=..., quota_metadata_bytes=...)`.
The PATCH is serialized with space mutations and takes no `If-Match` header. It increments the space generation
without changing profile or erasing retained data. Metadata per record is bounded
to 64 KiB. The worker expires unfinished drafts; the default draft lifetime is 24 hours. Published
records persist until explicit withdrawal, and references/active inputs protect
records they require.

Cancelling, failing or withdrawing a record releases logical blob allocation but
keeps physical pending-deletion allocation charged until cleanup succeeds.
Reclamation waits for recorded grant expiry and confirmation that provider
mutations are settled. Failed cleanup remains retryable and must not free the
physical budget. Lease expiry alone does not prove an S3 mutation has finished.
Declared and verified content identities are separate; publication requires
verification of the exact object version.

Record count and metadata remain charged for terminal records until an
administrator calls `POST /records/{id}/purge` (SDK `purge_record`) after blob
cleanup. Coordination provenance is retained indefinitely in this version;
historical inputs/results and derived-record relationships can prevent purge.
There is no history-pruning API for those relationships. Monitor retained usage
and increase the relevant space quota when more capacity is required. Metadata
quotas are retained-state limits, not simply concurrent-upload limits.

Upload and completion use attempt-owned storage resources and renewable worker
ownership. A stale attempt can finish remote I/O without gaining the right to
commit or clean a successor's resources. Worker verification streams exact object
versions with bounded memory. Separate verification and cleanup concurrency
prevents a cleanup backlog from taking every verification slot.

Every provider start/complete call also has a durable mutation marker independent
of the worker lease. Its callback settles only its own marker. If a process
disappears before reporting completion, the marker remains: a successful sweep
cannot mark the blob cleaned, release its physical quota, purge its record or
prune the uncertain attempt until the outstanding mutation is resolved. This
conservative condition may need the offline repair procedure below. New start
or repeated completion requests do not launch another provider mutation while
the previous one remains uncertain. Ordinary verification is read-only and can
resume after a worker restart without this operator assertion.

The SDK keeps confirmed multipart progress, local upload state and interrupted
downloads. Upload and verification time budgets are separate. State files identify
logical operations; keep them between retries and use distinct files for new
operations. The API never proxies the large-file payload.

The event feed is pull-based. Save cursors and deduplicate event IDs. Withdrawal,
cancellation, expiry and failure produce authorized tombstone notifications so a
consumer can remove stale local entries. Tombstones identify the affected record
and state; they do not expose withdrawn/private metadata or attachments. Current
membership and event visibility still apply. Other readers receive these
notifications only for previously published records allowed by current shared
visibility; draft identifiers are not exposed by the tombstone path. Terminal
notifications survive metadata purge until normal event retention expires. When
event retention expires a cursor, reconcile current records/references before resuming
at the reported floor. It is not an outbound webhook queue. Idempotency responses
are also retained for a bounded interval; replay after expiry can create new
resources.

### Offline repair of an uncertain provider mutation

A lost callback can leave a durable marker after the remote operation finishes.
First inspect the bounded inventory; the default command is read-only and needs
only database configuration:

```bash
.venv/bin/hf2l-exchange repair-transfers
.venv/bin/hf2l-exchange repair-transfers --attempt ATTEMPT_ID
```

Before applying a repair, stop **all API and worker processes using this
metadata/storage namespace**. Separately establish that the provider has no
outstanding mutating request for each selected attempt. Stopping a process or
waiting for its database lease to expire does not establish remote quiescence;
use the provider's request/operation monitoring and operational controls to
confirm it. Do not clear a marker merely because it is old.

Once both conditions are established, explicitly select up to 100 attempts and
make the two independent operator assertions:

```bash
.venv/bin/hf2l-exchange repair-transfers \
  --attempt ATTEMPT_ID --apply --writers-stopped --provider-quiesced
```

Repeat `--attempt` for additional inspected IDs. Without IDs, inventory lists
only attempts with unresolved markers; explicit IDs can also inspect healthy
attempts. Output is bounded to 100 entries and reports truncation.

Repair requires expired ownership and an eligible lifecycle state. It clears the
selected orphan markers and schedules the action appropriate to that state:

| Attempt state | Scheduled action |
|---|---|
| Completing upload on a draft | `recover_completion`: reconcile/complete the same multipart handle and verify its exact resulting version; retain uploaded parts |
| Uncertain initiation on a draft | `schedule_cleanup`: remove the old attempt's owned resources; only after cleanup succeeds may the client retry with a fresh key |
| Terminal record or cleanup attempt | `schedule_cleanup`: reclaim owned resources after outstanding grants expire |

The command does **not** perform provider I/O or release quota inline. Restart
the worker to perform the scheduled recovery or cleanup, verify the resulting
state and charged capacity, then restore the API. Incorrectly asserting
quiescence can allow an old provider request to create objects after reclamation; these flags are
operator assertions, not automatic detection of provider state.

### Tuning

| Setting | Default | Purpose |
|---|---:|---|
| `EXCHANGE_DRAFT_SECONDS` | 86400 | Draft lifetime, at most seven days |
| `EXCHANGE_COORDINATION_SECONDS` | 300 | Coordination renewal duration, at most one hour |
| `EXCHANGE_GRANT_SECONDS` | 300 | Signed grant lifetime, at most one hour |
| `EXCHANGE_PART_SIZE` | 8388608 | Multipart part bytes |
| `EXCHANGE_MAX_BODY_BYTES` | 1048576 | Maximum control-plane request body |
| `EXCHANGE_WORKER_LEASE_SECONDS` | 300 | Transfer-attempt worker ownership duration |
| `EXCHANGE_WORKER_FAILURE_SECONDS` | 86400 | Recovery/verification failure window |
| `EXCHANGE_WORKER_POLL_SECONDS` | 1 | Worker polling interval |
| `EXCHANGE_WORKER_VERIFY_CONCURRENCY` | 2 | Concurrent verification tasks per worker |
| `EXCHANGE_WORKER_CLEANUP_CONCURRENCY` | 2 | Concurrent cleanup tasks per worker |
| `EXCHANGE_WORKER_BATCH_SIZE` | 32 | Work selection bound |
| `EXCHANGE_OPERATION_RETENTION_SECONDS` | 864000 | Idempotency response retention |
| `EXCHANGE_EVENT_RETENTION_SECONDS` | 2592000 | Event retention |
| `EXCHANGE_POOL_SIZE` / `EXCHANGE_POOL_OVERFLOW` | 5 / 10 | PostgreSQL connections per process |
| `EXCHANGE_POOL_TIMEOUT` / `EXCHANGE_POOL_RECYCLE` | 30 / 1800 | Pool wait/recycling seconds |
| `EXCHANGE_JWKS_TIMEOUT` / `EXCHANGE_JWKS_CACHE_SECONDS` | 5 / 300 | Key retrieval timeout/cache |

Size pools for all API and worker processes. `worker --once` reports a pass and
exits nonzero on failure. Centralize application/worker logs and configure alerting
for dependency failures, verification backlogs, expired acquisitions and unreclaimed
bytes. Per-request logs avoid bodies, bearer tokens and signed URL query strings.

## Validation status and deployment limits

Run the independent service tests and the legacy/application regression suite
from the development environment:

```bash
.venv/bin/python -m pip install -e './packages/exchange[server,test]' -e '.[exchange,service,exchange-test]'
EXCHANGE_REQUIRE_TESTS=1 .venv/bin/python -m unittest discover -s packages/exchange/tests -v
EXCHANGE_REQUIRE_TESTS=1 .venv/bin/python -m unittest discover -s tests -v
```

The live suite uses `EXCHANGE_TEST_DATABASE_URL` and
`EXCHANGE_TEST_S3_ENDPOINT` plus dedicated test credentials. Tests own temporary
schemas/buckets; never provide production database or bucket administration
credentials. Minimal-install checks run in fresh SDK-only/server-only environments
so accidental ML dependencies are detectable. The configured
[Exchange test workflow](../../.github/workflows/exchange_tests.yml) covers Python
3.10/3.12, dependency isolation, generic integration and HF²L regressions, with
PostgreSQL and MinIO pinned by digest for provider checks. This workflow has not
been executed on GitHub for these changes. Local runtime validation uses Python
3.12.1; Python 3.10 validation here is limited to syntax parsing, not execution.

Local verification on 2026-09-22, using the project `.venv` and Python 3.12.1:

| Suite | Database / storage | Result |
|---|---|---|
| Independent Exchange v2 | SQLite / Moto | 114 tests: 112 passed, 2 expected skips |
| Independent Exchange v2 | PostgreSQL 18 / MinIO | 114 passed, no skips |
| HF²L and legacy regressions | SQLite / Moto | 105 tests: 104 passed, 1 expected skip |
| HF²L and legacy regressions | PostgreSQL 18 / MinIO | 106 passed, no skips |

The SQLite skips are provider-signature and PostgreSQL-specific checks; all three
skipped checks run in the live configurations. The independent suite includes
actual process interruption, explicit uncertain-mutation repair, storage grants,
metadata quotas, retained tombstones and coordination tests. The HF²L suite
includes the v2 adapter and a real tensor aggregation round alongside legacy
regressions. Historical counts in the v1 remediation report are separate evidence.

Fresh SDK-only and server-only installation isolation, source dependency checks,
`pip check` and `git diff --check` passed. Python 3.10 syntax parsing covered 55
source files; the local test suites were not run under Python 3.10.

Both distributions built into wheels. Every packaged Python module matched the
final source bytes (18 Exchange modules and 44 HF²L modules). Fresh wheel-installed
SDK and server environments passed dependency-isolation checks and `pip check`;
the SDK environment ran 16 client tests with one expected server-extra skip, and
the server environment passed all 16. Server CLI checks also passed. These are
local build/install results; no distribution has been published.

No production service has been provisioned. Local tests cannot establish
production throughput, TLS/IAM/IdP configuration, log retention or backup/restore
objectives. No arbitrary storage provider, tenant administration, outbound event
delivery, general workflow engine, or v1 importer is claimed.
