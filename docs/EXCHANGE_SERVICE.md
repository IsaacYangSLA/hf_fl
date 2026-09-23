# Legacy Exchange v1 service

This guide describes the retained `hf2l.exchange` service and its `/v1` API.
For new deployments and the current `--backend exchange` adapter, use the
[independent Exchange service runbook](EXCHANGE_V3.md) and
[v3 architecture](ARCHITECTURE_V3.md). The new adapter does not speak this legacy
API. The old service remains for explicit legacy use and regression coverage;
its database is not an input to the new service.

The exchange backend implements authenticated JSON records, private/shared
visibility, immutable published attachments, resumable direct S3 transfers,
conditional references, a durable event feed, and fenced coordinator claims.
It historically served the HF2L `--backend exchange` adapter; the current adapter
now targets the independent `/v2` service. The [historical design document](history/EXCHANGE_SERVICE_DESIGN.md)
describes the resource model and trust boundaries.

## Install and configure

Use PostgreSQL for deployment. SQLite is supported for local development and
serializes writes; it is not the scale-out database configuration. PostgreSQL reads use an MVCC snapshot without taking the space mutation lock.
Provide a private S3 bucket with versioning enabled and an identity provider
issuing RS256 OAuth access tokens. Tokens must have `typ=at+jwt`, the configured
issuer/audience, `sub`, `iat`, `exp`, and the `exchange` scope. The API does not
issue tokens or use a shared client password.

```bash
.venv/bin/python -m pip install -e './packages/exchange[server]' -e '.[service,exchange]'
```

The current source tree's extras depend on the independent Exchange package,
so install both local distributions. The `hf2l.exchange.cli` commands below
explicitly select the retained v1 service.

Set deployment configuration through your environment or secret manager:

```bash
export EXCHANGE_DATABASE_URL='postgresql+psycopg://USER:PASSWORD@DB_HOST/exchange'
export EXCHANGE_ISSUER='https://identity.example.com'
export EXCHANGE_AUDIENCE='exchange-api'
export EXCHANGE_JWKS_URL='https://identity.example.com/.well-known/jwks.json'
export EXCHANGE_ADMIN_SUBJECT='BOOTSTRAP_ADMIN_SUBJECT'
export EXCHANGE_S3_BUCKET='exchange-blobs'
export AWS_DEFAULT_REGION='us-east-1'
# Set this only for an S3-compatible endpoint:
export EXCHANGE_S3_ENDPOINT='https://objects.example.com'
```

Optional tuning variables, with defaults: `EXCHANGE_GRANT_SECONDS` (300, transfer
URL lifetime), `EXCHANGE_UPLOAD_SECONDS` (86400, draft transfer window, renewed
when a blob reaches verification), `EXCHANGE_PART_BYTES` (64 MiB),
`EXCHANGE_MAX_BODY_BYTES` (1 MiB), `EXCHANGE_WORKER_INTERVAL` (5 s),
`EXCHANGE_WORKER_BATCH` (256 blobs per work class per pass),
`EXCHANGE_WORKER_CONCURRENCY` (4 parallel verifications per worker process),
`EXCHANGE_WORKER_LEASE_SECONDS` (3600, per-blob lease so several worker
processes partition work instead of duplicating it) and
`EXCHANGE_WORKER_RECOVER_AFTER` (30 s before an interrupted initiation or
completion is repaired, so the worker does not race the API's own transition).

Use the normal AWS credential provider chain for the service workload. On
self-hosted storage, inject its S3 access key and secret through the environment
or a credentials provider. End clients must not receive these credentials.
For deployments with a pinned signing key, set `EXCHANGE_PUBLIC_KEY_FILE`
instead of `EXCHANGE_JWKS_URL`; this must be the issuer's RSA public PEM key.
No private signing key belongs in the exchange service.

Initialize the empty schema and check storage:

```bash
.venv/bin/python -m hf2l.exchange.cli init-db
.venv/bin/python -m hf2l.exchange.cli check-storage
```

Run these as separate supervised processes with the same configuration:

```bash
.venv/bin/python -m hf2l.exchange.cli serve --host 127.0.0.1 --port 8000
.venv/bin/python -m hf2l.exchange.cli worker
```

Both emit logs with named correlation fields (`--log-level`, default `INFO`). Every API response
carries `X-Request-ID`; error bodies repeat it as `request_id`, and the same
value appears in the server log line for that request, including storage and
database failures (`storage_unavailable`, `database_unavailable`). The worker
logs each failed transition with the blob and record IDs, its state and the
storage error code, and prints per-pass counters. Several worker processes may
run concurrently: each leases the blobs it works on. `worker --once` runs a
single pass.

Expose the API through an HTTPS reverse proxy. Apply connection/request timeouts
and rate limits there; the API limits request bodies to 1 MiB (`413
request_too_large`) and record metadata to 64 KiB (`422 metadata_too_large`,
whose body carries the serialized `size` and the `limit`). Interactive API
documentation (`/docs`) and OpenAPI (`/openapi.json`) are disabled by default.
Set `EXCHANGE_DOCS_ENABLED=true` to enable them on a trusted deployment; `/redoc`
is disabled. Gate enabled documentation at the proxy when appropriate. No file bytes are proxied through the API.

The bucket must deny public access and untrusted deletion. Service permissions
cover `s3:GetBucketVersioning` (readiness/storage check), initiating/listing/completing/
aborting multipart uploads, reading object versions, `s3:ListBucket` (needed so a
missing key reports 404 rather than 403 during completion recovery), listing
versions for recovery, and generating PUT/GET grants. The cleanup worker
additionally needs deletion of object versions. Grant cleanup rights only to
the worker identity where your deployment separates credentials. The configured
S3 endpoint is used for service-side operations. Set `EXCHANGE_S3_PUBLIC_ENDPOINT`
to a participant-reachable HTTPS endpoint for presigning when the internal
endpoint differs. Both must address the same bucket and use the same credentials.
Without the public setting, the internal endpoint is also embedded in transfer URLs.
HTTPS is enforced for configured endpoints and for grants consumed by the SDK.
For local tests only, `EXCHANGE_ALLOW_LOCAL_HTTP=true` permits loopback HTTP;
the Python SDK uses `allow_local_http=True` for the same explicit exception.
Configure encryption at rest. Do not expire noncurrent versions indiscriminately:
a live record can deliberately point to a noncurrent version.

## Create a space and bind identities

For the retained Python SDK, install both local distributions on client machines:

```bash
.venv/bin/python -m pip install -e ./packages/exchange -e '.[exchange]'
```

Obtain a token from your identity provider and supply `EXCHANGE_ENDPOINT` and
`EXCHANGE_TOKEN`. The examples read tokens from the environment; no token value
needs to be put in source code. Automations can pass a token-provider callable
to `hf2l.exchange.client.ExchangeClient`, which reads it for each API request.
The current FL CLI's `EXCHANGE_TOKEN_FILE` support belongs to its v2 adapter;
it does not select this legacy SDK.

Run the following with the bootstrap admin's token:

```python
import os
from hf2l.exchange.client import ExchangeClient

client = ExchangeClient(os.environ['EXCHANGE_ENDPOINT'], os.environ['EXCHANGE_TOKEN'])
space = client.create_space('example-fl', 'my-organization', idempotency_key='example-fl-v1')
space_id = space['id']

client.set_member(space_id, os.environ['EXCHANGE_ISSUER'], 'ALICE_SUBJECT',
                  ['reader', 'contributor'], participant='alice')
client.set_member(space_id, os.environ['EXCHANGE_ISSUER'], 'BOB_SUBJECT',
                  ['reader', 'contributor'], participant='bob')
print(space_id)
client.close()
```

Subjects are exact, case-sensitive identity-provider subject values. The SDK
derives the stable principal ID from issuer and subject. A participant binding
is unique within a space. Set a member's roles to `[]` to revoke access.
Each subsequent API/grant request checks current membership. Already issued
transfer URLs can remain usable until their five-minute expiry.

The participant binding is enforced for the whole life of a training update,
not only at creation. Setting roles to `[]` cancels every draft the member
holds and releases their reservations. Changing or clearing a member's
`participant` cancels only the drafts that carry the previous binding
(`training.update`); message and `model.global` drafts survive, as does every
draft when a member is bound for the first time, and a role change that keeps
the binding leaves drafts alone. Publishing a `training.update` whose recorded
participant no longer equals the creator's current binding fails with
`participant_binding_changed`. A ready update whose creator was rebound, or
whose creator's roles are now `[]` (a revoked member holds no binding, even
if the `participant` string was kept on its row), is excluded from automatic
claims (reported in the claim's `skipped` list), refused as an explicit claim
input with the same code and `record_id`, and blocks the publication of a
claimed aggregate that declares it. Either form of revocation therefore
removes the participant's contributions from the next round without any
further action. Restore the roles or the binding to make the update usable
again, or withdraw it.

Only the configured bootstrap admin can create spaces. The space creator gets
admin, coordinator, and reader roles. Space admins can manage memberships
(`GET /members` lists them; `PUT /members/{principal_id}` sets roles and the
binding); admin alone is not a data-reader or publisher role. Every other
operation requires membership, including for the bootstrap admin once another
admin has revoked it.

Two safeguards keep a space manageable. An admin cannot remove its own admin
role (`cannot_remove_own_admin_role`), and nobody can remove or demote the last
member holding the admin role (`last_admin`). If the remaining admin's identity
is nevertheless lost (subject rotated or deleted, or `EXCHANGE_ISSUER` changed,
which renames every principal), the bootstrap admin has a break-glass path: it
may always call `GET /v1/spaces/{id}/members` and `PUT /v1/spaces/{id}/members/*`
even while not an admin member of the space. Use it to re-add yourself with
`['admin', ...]`, after which normal membership rules apply again; re-adding
yourself with lesser roles is also accepted, because the self-demotion guard
only applies to a member that actually holds the admin role, and break-glass
keeps working while the bootstrap admin is a non-admin member. Each such call
is audited as a `member.bootstrap_grant` event on the space. No direct SQL is
needed to recover a space.

Admins read space policy with `GET /v1/spaces/{id}` and change `quota_bytes`,
`principal_quota_bytes` or `rules` with `PATCH /v1/spaces/{id}` and the returned
`If-Match` generation (`client.get_space` / `client.update_space`). The
per-principal quota bounds the draft reservations one member can hold at a time
and defaults to a quarter of the space quota. Admins can also cancel any
member's draft with `DELETE /records/{id}`, and revoking a member (roles `[]`)
cancels that member's drafts and releases their reservations immediately.

## Exchange small information and large files

As an enrolled contributor:

```python
from pathlib import Path
import os
from hf2l.exchange.client import ExchangeClient

client = ExchangeClient(os.environ['EXCHANGE_ENDPOINT'], os.environ['EXCHANGE_TOKEN'])
space_id = os.environ['EXCHANGE_SPACE_ID']

message = client.put_record(
    space_id, kind='message', metadata={'status': 'training finished'},
    state_path=Path('work/message-upload.json'),
)
result = client.put_record(
    space_id, kind='message', metadata={'description': 'experiment output'},
    files={'output.bin': Path('output.bin')},
    state_path=Path('work/output-upload.json'),
)

for record in client.records(space_id, kind='message', state='ready'):
    print(record['id'], record['metadata'])

record = client.get_record(space_id, result['id'])
attachment = record['attachments'][0]
client.download_attachment(space_id, record['id'], attachment, Path('work/downloaded.bin'))
client.close()
```

The worker must be running for file-backed records to become verified. The SDK
waits for verification and publication (`wait_seconds`, default 3600; the
FedAvg adapter reads `EXCHANGE_WAIT_SECONDS`). Preserve `state_path` to resume
after an interruption: a retry with the same files, kind, base and destination
resumes the same draft and sends only missing parts, even if metadata such as
timestamps changed (the draft's metadata is updated). A retry with different
files cancels the stale draft and starts a new record. The state file is
removed once the record is ready, so a later call with the same path creates a
new record. If a blob fails verification, the SDK cancels the draft to release
its reservation and raises `blob_verification_failed`. The FedAvg adapter keeps
its state file next to the uploaded directory as
`<directory>.exchange-upload.json`. Resume data contains record IDs and
idempotency keys, not access tokens or signed URLs. Transient control-plane
failures (connection errors, 429, 502-504) are retried with backoff. Download
partial files are also resumable and are checked against the full-file digest
before replacement.

Default kinds are `message`, `configuration`, `training.update`, `model.global`,
and `evaluation.result`. Space creation and `PATCH /v1/spaces/{id}` can supply
custom kind rules with allowed creator roles, shared/private visibility, and a
JSON Schema (draft 2020-12) for the kind's metadata. Schemas are checked and
applied without any network access. Local references (`"$ref": "#/$defs/..."`)
and prose containing the word `$ref` are accepted; a `$ref`, `$dynamicRef` or
`$recursiveRef` whose target is not fragment-only, or an `$id`/`$schema`
naming anything but a standard JSON Schema meta-schema URI, is rejected with
`external_schema_references_not_supported` (the body names the `kind`), and a
schema that fails the meta-schema with `invalid_metadata_schema`. Records are
validated against a reference registry that has no retrieval callback, so a
rule that still cannot be resolved (for example a missing local target) makes
record creation, draft metadata updates and publication for that kind fail
with `metadata_schema_unresolvable` instead of an internal error; correct the
rule with `PATCH`.

The service ships one built-in FedAvg profile and no other workflow. It is
keyed to the kinds `training.update` (bound to the creator's participant,
requires a base, private by default) and `model.global` (shared, linked to its
base), to the `main` reference, which only accepts a shared ready
`model.global`, and to the `input_record_ids` metadata field a claimed result
declares. Custom rules may add kinds and change creators, visibility and
schemas, but must keep both profile kinds: a rule set missing one fails with
`profile_kind_required` (`kind` in the body), and `model.global` must stay
shared and its schema must not forbid `input_record_ids`
(`profile_kind_incompatible`, with `kind` and `reason`). The FedAvg adapter
additionally stores its inline manifests under the `hf2l_files` metadata key
of both kinds, so a custom schema for them must accept that property.

Rule changes apply to existing records. Changing a kind's `shared` flag updates
the visibility of every record of that kind already in the space in the same
transaction (audited as a `space.rules_changed` event listing the kinds whose
flag changed), so a project can later make training updates readable by all
contributors, or private again, without a new space. Contributors can publish
messages and training updates; only coordinators can publish global
models/configuration. Training updates are private to their creator and
coordinators unless the rule says otherwise. Shared ready records are readable
by enrolled readers/contributors. Drafts are creator-only.

One record can contain up to 256 named attachments. Names are compared
case-insensitively so a download behaves the same on every filesystem: two
names differing only by case fail with `duplicate_attachment_name`, names that
collide as file and directory (`a` and `a/b`) with
`attachment_name_collides_with_directory`, and a name equal to, nested under
or enclosing an inline HF2L manifest, that is `fedavg_round.json`,
`fedavg_submission.json` or any key of the record's `hf2l_files` metadata,
with `attachment_name_reserved`; the body carries the offending `name`. The
same check runs when a draft's metadata is changed, so an attachment can never
shadow an inline manifest. Attachment descriptors are returned with
the record; record listings use bounded pages with a publication time boundary.
Space byte quotas count both unfinished reservations and retained records.
Cancel an unpublished record with `DELETE /records/{id}` to release its
reservation. `DELETE /uploads/{id}` aborts one attachment transfer only while
it is `reserved`, `initiating` or `uploading` (aborting again is a no-op);
once completion has been requested it fails with `upload_completing`, a
`verifying` or `verified` blob fails with `upload_already_completed`, and a
transfer the worker already `failed` is refused with `upload_not_open`, so a
stale retry cannot destroy a finished transfer. The provider upload ID is
discarded once completion succeeds. Failed/aborted uploads need a new record.
Ready records are
immutable, but their creator (or a space admin) can withdraw one with the same
`DELETE` call: the record becomes `withdrawn`, disappears from other members' reads and ready
discovery (its creator may still inspect metadata), releases its logical quota and its storage versions are reclaimed by the
worker. Withdrawal is refused with `record_referenced`, `record_is_base` or
`record_claimed` while a reference points at the record, another record builds
on it, or an active claim has frozen it. `POST /records`, `PUT /refs/{name}`
and `POST /v1/spaces` require an `Idempotency-Key` header (the SDK supplies one);
a replay returns the stored result, and concurrent identical requests with the
same key both receive it, even for `POST /v1/spaces`, which takes no space
lock. Reusing a key with a different body fails with `idempotency_key_reused`.
`POST /claims` also requires an acquisition key (see below). All four keyed routes require 1–128 characters, and OpenAPI marks the header required.

The `main` reference is reserved for the FedAvg profile: `PUT /refs/main`
accepts only a ready, shared `model.global` record (`aggregate_kind_mismatch`
otherwise) whose base is the current `main` (`aggregate_base_mismatch`).
Other reference names accept any ready shared record.

## Legacy FL adapter compatibility

Current `hf2l.init_repo`, participant commands, and `hf2l.owner_fedavg` select the
independent `/v2` service when passed `--backend exchange`. There is no current
CLI backend selector for `/v1`. Use the [v2 service setup and FL workflow](EXCHANGE_V3.md)
for those commands, including its claim renewal and run-state recovery procedures.

The old FL integration survives only in the frozen
[adapter](../tests/legacy_exchange_adapter.py) and
[owner runner](../tests/legacy_owner_fedavg.py) regression fixtures from `714fd66`.
These fixtures are not shipped as application commands. Their
`exchange-claim.json` state and claim lifecycle do not describe the current
adapter's `--run-state` behavior.

Explicit legacy applications can still use `hf2l.exchange.client.ExchangeClient`
and the `hf2l.exchange.cli` service commands in this guide. The v1 service
retains coordinator claim endpoints: acquire with `POST /claims` and an
`Idempotency-Key`, inspect with `GET /claims` or `GET /claims/{id}`, and renew or
abandon with `POST /claims/{id}:renew` or `POST /claims/{id}:abandon`. Callers must
manage claim leases and fences; those endpoints do not provide an automatic
renewing FL runner. See the [historical design](history/EXCHANGE_SERVICE_DESIGN.md)
for the original resource model.

Each successful publication stores an event transactionally with its state
change. Poll `GET /events?cursor=...` using the returned `next_cursor`, persist
that cursor, and re-query ready records when a `record.ready` event arrives.
Consumers may receive duplicate events and should deduplicate by event ID.
The v1 service provides this pull feed, not outbound webhooks. The existing
HF webhook workflow remains HF-specific.

## Recovery and operational scope

The worker verifies SHA-256 by streaming the exact stored version. This costs
one additional storage read and bounded memory. It reconciles interrupted
initialization/completion and expires unfinished drafts after the transfer
window (24 hours by default). The window is renewed when a blob reaches
verification, and a draft is never expired while one of its blobs is being
completed or verified. Each transfer attempt has an owner token and renewable
lease. Commit and release compare that token and the database clock; a stale
attempt cannot overwrite a successor. A second HTTP completion reports the
in-progress state and never starts another storage completion.

On cancellation, expiry, withdrawal, or terminal failure, logical allocation is
released but bytes move to `pending_deletion_bytes`. The quota check uses both
counters, so repeated cancellation cannot create unbounded unaccounted storage.
Cleanup becomes eligible after cancellation/expiry plus the grant lifetime,
and removes all versions, delete markers, and multipart uploads at that record's
keys. Successful cleanup releases the pending-deletion charge. Each work class
(recovery/verification and cleanup) is selected in its own bounded, ordered
batch so a cleanup backlog cannot starve verification. It never sweeps live
records by prefix. Missing versions/uploads and digest failures become terminal
`failed` records, release logical reservations, and schedule physical cleanup.
Transient errors remain retryable; `EXCHANGE_WORKER_FAILURE_SECONDS` (86400)
bounds repeated unresolved work. Missing/null VersionId is an infrastructure
failure (`503 storage_misconfigured`), preserving `completing` for recovery;
it is not reported as invalid client parts. Recovery of lost initiation aborts
uncommitted multipart uploads and creates a fresh attempt-owned upload.

An S3 operation and a database transaction cannot commit atomically. Ready
records are exposed only after successful verification; lost responses are
reconciled from reserved keys and fixed versions. A CAS conflict may leave an
unreferenced ready aggregate for inspection; its creator or an admin can
withdraw it. Retention of referenced or lineage-bearing ready records remains
an administrative decision: the API refuses to withdraw them, so automatic
cleanup cannot remove a live result.

Schema v2 includes worker tokens, pending-deletion accounting, identity subjects,
retention timestamps/floors, PostgreSQL JSONB columns, and cleanup indexes.
`init-db` creates a new database and refuses an unupgraded v1 database.
For an existing deployment, stop all API/worker processes, back up the database,
and run `.venv/bin/python -m hf2l.exchange.cli migrate-db` before restarting.
The transactional, repeatable migration preserves rows and reconstructs the
pending-deletion budget from existing terminal records. Legacy membership subjects
remain unknown until the admin re-applies their issuer/subject binding; hashes
cannot be reversed. Keep a matching object-version backup/retention policy. Per-principal
rate limiting, identity-provider provisioning, TLS termination and bucket
policy are deployment responsibilities. Space quotas and authorization are
enforced in the API. No production infrastructure is provisioned by these
commands.

## Validation

Install the optional test dependencies and run the offline suite:

```bash
.venv/bin/python -m pip install -e './packages/exchange[server,test]' \
  -e '.[torch,hf,examples,service,exchange,exchange-test]'
.venv/bin/python -m unittest discover -s tests -v
```

The exchange tests default to SQLite and an in-process Moto S3 server, which
also exercises the client SDK's presigned transfers, resume paths and a full
two-participant FedAvg round including claim abandonment and withdrawal. To
test real PostgreSQL and an S3-compatible server, set
`EXCHANGE_TEST_DATABASE_URL` and `EXCHANGE_TEST_S3_ENDPOINT`, and supply
test-only S3 credentials through the normal AWS environment variables. Then run:

```bash
EXCHANGE_REQUIRE_TESTS=1 .venv/bin/python -m unittest discover -s tests -p 'test_exchange*.py' -v
```

Tests create and remove uniquely named PostgreSQL schemas and S3 buckets.
Use dedicated test services and credentials that permit those operations.
Live coverage adds the provider's signature enforcement on tampered and expired
grants. Moto is useful for application behavior; it is not proof of a storage
provider's signature enforcement. Run the live tests for each chosen
provider/version before deployment.

## Read paths, retention, and deployment limits

Pure record, reference, event, upload-status and identity reads use a database
snapshot without an exclusive space lock. Writers still serialize per space to
protect authorization/quota/CAS and event commit order. Membership recovery is
an audited mutation even when reached through the bootstrap membership-list
route. Record pages batch their attachment query; event pages join visibility
and filter feed kinds before LIMIT.

`GET /health` is process liveness. `GET /ready` checks the schema/database and
versioned storage, including the missing-object permission probe. Dependency
outages do not prevent startup. Put readiness on the load balancer; database,
storage and IdP unavailability return JSON 503 errors with `Retry-After`.
JWKS fetches have a bounded wait/timeout, cached keys and a short outage cooldown.

Additional settings:

| Environment variable | Default | Purpose |
|---|---:|---|
| `EXCHANGE_POOL_SIZE` | 10 | PostgreSQL connections per process |
| `EXCHANGE_POOL_OVERFLOW` | 10 | Additional pooled connections |
| `EXCHANGE_POOL_TIMEOUT` | 5 | Seconds waiting for a connection |
| `EXCHANGE_POOL_RECYCLE` | 1800 | Connection recycling age, seconds |
| `EXCHANGE_JWKS_TIMEOUT` | 3 | Key fetch and lock wait, seconds |
| `EXCHANGE_JWKS_CACHE_SECONDS` | 300 | Key-set cache lifetime |
| `EXCHANGE_WORKER_FAILURE_SECONDS` | 86400 | Maximum age for unresolved recovery/verification attempts |
| `EXCHANGE_OPERATION_RETENTION_SECONDS` | 864000 | Idempotency history lifetime |
| `EXCHANGE_EVENT_RETENTION_SECONDS` | 2592000 | Event history lifetime |

Run multiple API processes with `hf2l-exchange-service serve --workers 4`, or
`uvicorn hf2l.exchange.api:create_app --factory --workers 4`. Size the pool for
the total API and worker process count. Database clock values govern leases,
expiry and runtime event/operation timestamps; Unix seconds remain the wire
format. PostgreSQL metadata uses JSONB; SQLite uses JSON.

The worker prunes history in bounded batches. Operation retention must exceed
the upload window plus grant lifetime plus one day for retries. An idempotency
key replay outside that retention window may create a new resource. Event
consumers must persist their cursor and deduplicate IDs. A cursor below the
retention floor returns `410 event_cursor_expired` with `restart_cursor`;
reconcile current records/references before starting from that floor. The feed
is pull-based and has no outbound-delivery acknowledgement/outbox contract.

The Event table records transactional resource events. Successful grants and
denied requests are logged with route/resource, principal when authenticated,
status/code and request ID, rather than creating database audit rows for each
request. Collect the INFO-level application logs centrally and define audit
retention in that collector; deleting event history does not replace audit-log
retention. Neither signed URLs nor bearer tokens are intentionally logged.

`tenant` is an administrative label. **Space is the authorization boundary**;
there is no tenant membership, delegated tenant administrator or tenant-wide
storage partition in this version. Membership listing now includes the original
subject for newly granted identities. Keep the IdP/space roster for legacy rows
and centralized administration. Global identity lifecycle remains at the IdP:
disable issuance there and revoke the identity's memberships in each space when
immediate invalidation of already-issued JWTs is required. The service has no
separate global principal-disable API.

The fixed FedAvg kinds accept an intentionally restricted schema subset:
object `type`, `properties`, `required`, boolean `additionalProperties`, and
annotations. Only `hf2l_files` may be required at the top level. Its schema and
`input_record_ids` may specify their expected type and annotations, but not
nested constraints that could reject the adapter's mandatory fields. Use custom
kinds for arbitrary composed JSON Schemas. Unsupported profile compositions
fail during rule configuration with `profile_kind_incompatible`.

SDK `put_record` has separate `upload_seconds` (86400) and verification
`wait_seconds` (3600) budgets. The verification budget starts after transfers.
Resuming a failed/aborted blob discards its unusable draft and resume file.
Incomplete downloads retain partial files; completed files with bad size/hash
are rejected and discarded. Grant URLs must satisfy the same explicit HTTPS or
local-development policy as configured endpoints.

Advanced publishers can carry `ResolvedReference(revision, generation)` and a
claim handle explicitly into `publish_aggregate(reference=..., claim=...)`,
including across adapter instances. The owner CLI does this automatically.
Existing tag names fail before uploading; if a tag races after main publication,
`PublishResult` still returns the published revision, `tag_created=False`, and a
warning. The CLI prints that revision and warning rather than hiding a successful
publication.

The `Exchange service tests` GitHub workflow runs required dependency checks,
SQLite/Moto on Python 3.10/3.12, and PostgreSQL/MinIO for real concurrency,
schema migration and signed-URL checks. `EXCHANGE_REQUIRE_TESTS=1` turns missing
exchange dependencies into a failure instead of an all-skipped success.
