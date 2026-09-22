# Run the exchange service

The exchange backend implements authenticated JSON records, private/shared
visibility, immutable published attachments, resumable direct S3 transfers,
conditional references, a durable event feed, and fenced coordinator claims.
It works with the existing HF2L client and owner commands through
`--backend exchange`. The [design document](EXCHANGE_SERVICE_DESIGN.md)
describes the resource model and trust boundaries.

## Install and configure

Use PostgreSQL for deployment. SQLite is supported for local development and
serializes its transactions; it is not the scale-out database configuration.
Provide a private S3 bucket with versioning enabled and an identity provider
issuing RS256 OAuth access tokens. Tokens must have `typ=at+jwt`, the configured
issuer/audience, `sub`, `iat`, `exp`, and the `exchange` scope. The API does not
issue tokens or use a shared client password.

```bash
.venv/bin/python -m pip install -e '.[service,exchange]'
```

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

Both emit structured logs (`--log-level`, default `INFO`). Every API response
carries `X-Request-ID`; error bodies repeat it as `request_id`, and the same
value appears in the server log line for that request, including storage and
database failures (`storage_unavailable`, `database_unavailable`). The worker
logs each failed transition with the blob and record IDs, its state and the
storage error code, and prints per-pass counters. Several worker processes may
run concurrently: each leases the blobs it works on. `worker --once` runs a
single pass.

Expose the API through an HTTPS reverse proxy. Apply connection/request timeouts
and rate limits there; the API limits request bodies to 1 MiB and record metadata
to 64 KiB. Interactive API documentation is at `/docs`, and the machine-readable
contract is `/openapi.json`; block or gate these paths at the proxy if the API
is reachable from untrusted networks. No file bytes are proxied through the API.

The bucket must deny public access and untrusted deletion. Service permissions
cover `s3:GetBucketVersioning` (startup check), initiating/listing/completing/
aborting multipart uploads, reading object versions, `s3:ListBucket` (needed so a
missing key reports 404 rather than 403 during completion recovery), listing
versions for recovery, and generating PUT/GET grants. The cleanup worker
additionally needs deletion of object versions. Grant cleanup rights only to
the worker identity where your deployment separates credentials. The configured
S3 endpoint is also the host embedded in the transfer URLs handed to
participants, so it must be reachable by them over HTTPS.
Configure encryption at rest. Do not expire noncurrent versions indiscriminately:
a live record can deliberately point to a noncurrent version.

## Create a space and bind identities

Install `.[exchange]` on client machines. Obtain a token from your identity
provider and supply `EXCHANGE_ENDPOINT` and `EXCHANGE_TOKEN`. The examples read
tokens from the environment; no token value needs to be put in source code.
Automations can use `EXCHANGE_TOKEN_FILE`, whose contents the CLI rereads on
each API request, or pass a token-provider callable to `ExchangeClient`.

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
and `evaluation.result`. Space creation can supply custom kind rules with
allowed creator roles, shared/private visibility, and local JSON Schemas.
Remote JSON Schema references are rejected. Contributors can publish messages
and training updates; only coordinators can publish global models/configuration.
Training updates are private to their creator and coordinators. Shared ready
records are readable by enrolled readers/contributors. Drafts are creator-only.

One record can contain up to 256 named attachments; names must not collide as
file and directory (`a` and `a/b`). Attachment descriptors are returned with
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
`DELETE` call: the record becomes `withdrawn`, disappears from reads and
discovery, releases its quota and its storage versions are reclaimed by the
worker. Withdrawal is refused with `record_referenced`, `record_is_base` or
`record_claimed` while a reference points at the record, another record builds
on it, or an active claim has frozen it. `POST /records`, `PUT /refs/{name}`
and `POST /v1/spaces` require an `Idempotency-Key` header (the SDK supplies one);
a replay returns the stored result, and concurrent identical requests with the
same key both receive it, even for `POST /v1/spaces`, which takes no space
lock. Reusing a key with a different body fails with `idempotency_key_reused`.
`POST /claims` is idempotent by holder instead (see below).

The `main` reference is reserved for the FedAvg profile: `PUT /refs/main`
accepts only a ready, shared `model.global` record (`aggregate_kind_mismatch`
otherwise) whose base is the current `main` (`aggregate_base_mismatch`).
Other reference names accept any ready shared record.

## Existing federated-learning commands

For this backend, `--repo-id` is the generated space ID. Create the space and
memberships first. The owner initializes the global record using its own token:

```bash
.venv/bin/python -m hf2l.init_repo \
  --backend exchange --repo-id "$EXCHANGE_SPACE_ID" --plugin lenet
```

Each participant uses its own token and the owner-supplied immutable base ID:

```bash
.venv/bin/python -m hf2l.client_train \
  --backend exchange --repo-id "$EXCHANGE_SPACE_ID" \
  --base-revision "$BASE_RECORD_ID" --participant alice \
  --work-dir work/alice-round-0 --plugin lenet
```

The participant argument must equal that identity's server-managed binding.
The owner can inspect eligibility without downloading checkpoints:

```bash
.venv/bin/python -m hf2l.owner_fedavg \
  --backend exchange --repo-id "$EXCHANGE_SPACE_ID" \
  --discover-submissions --check-only --output-dir work/readiness
```

For a manually selected or discovered round, use `--submission` or
`--discover-submissions`, then `--publish` as with other backends. For multiple
automated coordinators, acquire a durable claim and freeze the input set:

```bash
.venv/bin/python -m hf2l.owner_fedavg \
  --backend exchange --repo-id "$EXCHANGE_SPACE_ID" \
  --claim-submissions --claim-lease-seconds 3600 \
  --output-dir work/owner-round-1 --publish
```

The claim ID and fence are printed and also written to
`<output-dir>/exchange-claim.json` while the claim is held; the file is
removed once the server has released or completed the claim, and kept when an
abandon request never reached the server so the ID stays available for a
manual abandon. `POST /claims` freezes the newest ready `training.update` per
participant for the current `main` base; older updates from the same
participant are reported as `superseded`, and updates whose creator was revoked
or no longer holds the recorded participant are left out and reported as
`skipped` (the CLI
prints both as `skipped_submission`). A coordinator may instead pass an
explicit `inputs` list of ready update IDs. The call is
idempotent for its holder: while its lease is active, the same coordinator
receives its existing claim (same ID and fence) again, so a lost response or a
restarted job simply re-acquires. An acquisition by a different coordinator
while the lease is active fails with `claim_busy`, and the error body carries
the active `claim_id` and `lease_until`; fewer than two usable candidates fails
with `insufficient_submissions` (the body lists the `skipped` updates); a base
whose claim already produced a result fails with `claim_completed`; an explicit
input whose creator was rebound or revoked fails with `participant_binding_changed`,
as does publishing a claimed aggregate that declares such an update. These are
expected coordinator control conditions. Coordinators and admins can list
claims with `GET /claims?base_record_id=...&workflow=...&active=true` (the
SDK's `client.claims(space_id)`); `active=false` includes completed and expired
ones.
Domain validation still happens in the owner command: in claim mode an input
that fails manifest or allowlist checks is skipped, and the published aggregate
declares exactly the inputs it used, which must be a subset of the frozen set.
If the round fails after acquisition (for example an incompatible checkpoint),
the CLI abandons the claim so `main` is not left frozen; the holder can also
call `POST /claims/{id}:abandon` with its fence, and a space admin can abandon
any claim without one. Withdraw the offending update, then claim again.
After lease expiry, a new acquisition retains the frozen inputs, minus any whose
creator was rebound or revoked in the meantime (reported as `skipped`), or accepts a
new explicit `inputs` list, and advances the fence; an expired lease no longer
blocks a plain generation-fenced `PUT /refs/main`. Stale holders cannot publish
or bypass an active claim by directly updating `main`. A known active claim can
be explicitly resumed with `--claim-id ID` in a new output directory; after a
crash, read the ID from the interrupted run's `exchange-claim.json` or from
`GET /claims`, or simply run `--claim-submissions` again with the same
coordinator identity, which returns the held claim (`--output-dir` must be a
new directory, so the CLI always recovers through this holder idempotency).
Programmatic callers of `ExchangeStore.claim_submissions(state_dir=...)` that
reuse a directory resume the persisted claim while it is still held; a stale
file (claim expired, completed or taken over) is discarded and a fresh
acquisition made instead. A running
coordinator can renew through `POST /claims/{id}:renew` with its fence and
`lease_seconds`; the CLI does not automatically renew, so select a sufficient
lease duration (up to 24 hours).

Each successful publication stores an event transactionally with its state
change. Poll `GET /events?cursor=...` using the returned `next_cursor`, persist
that cursor, and re-query ready records when a `record.ready` event arrives.
Consumers may receive duplicate events and should deduplicate by event ID.
The first implementation provides this pull feed, not outbound webhooks;
an external bridge can dispatch the existing GitHub workflow. The existing HF
webhook workflow remains HF-specific and is not silently redirected.

## Recovery and operational scope

The worker verifies SHA-256 by streaming the exact stored version. This costs
one additional storage read and bounded memory. It reconciles interrupted
initialization/completion and expires unfinished drafts after the transfer
window (24 hours by default). The window is renewed when a blob reaches
verification, and a draft is never expired while one of its blobs is being
completed or verified. Cleanup of expired, cancelled and withdrawn records waits
for upload expiry plus the transfer-grant interval, then removes versions and
multipart uploads at that record's server-generated keys. Each work class
(recovery/verification and cleanup) is selected in its own bounded, ordered
batch so a cleanup backlog cannot starve verification. It never sweeps live
records by prefix. Worker storage failures remain retryable states and are
logged with identifiers.

An S3 operation and a database transaction cannot commit atomically. Ready
records are exposed only after successful verification; lost responses are
reconciled from reserved keys and fixed versions. A CAS conflict may leave an
unreferenced ready aggregate for inspection; its creator or an admin can
withdraw it. Retention of referenced or lineage-bearing ready records remains
an administrative decision: the API refuses to withdraw them, so automatic
cleanup cannot remove a live result.

Schema v1 initialization uses SQLAlchemy `create_all` for a new database; it
does not migrate older deployments. Production schema changes need a reviewed
migration and matching object-version retention/backup policy. Per-principal
rate limiting, identity-provider provisioning, TLS termination and bucket
policy are deployment responsibilities. Space quotas and authorization are
enforced in the API. No production infrastructure is provisioned by these
commands.

## Validation

Install the optional test dependencies and run the offline suite:

```bash
.venv/bin/python -m pip install -e '.[service,exchange,exchange-test]'
.venv/bin/python -m unittest discover -s tests -v
```

The exchange tests default to SQLite and an in-process Moto S3 server, which
also exercises the client SDK's presigned transfers, resume paths and a full
two-participant FedAvg round including claim abandonment and withdrawal. To
test real PostgreSQL and an S3-compatible server, set
`EXCHANGE_TEST_DATABASE_URL` and `EXCHANGE_TEST_S3_ENDPOINT`, and supply
test-only S3 credentials through the normal AWS environment variables. Then run:

```bash
.venv/bin/python -m unittest discover -s tests -p test_exchange.py -v
```

Tests create and remove uniquely named PostgreSQL schemas and S3 buckets.
Use dedicated test services and credentials that permit those operations.
Live coverage adds the provider's signature enforcement on tampered and expired
grants. Moto is useful for application behavior; it is not proof of a storage
provider's signature enforcement. Run the live tests for each chosen
provider/version before deployment.
