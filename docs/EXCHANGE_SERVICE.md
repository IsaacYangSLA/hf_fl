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

Expose the API through an HTTPS reverse proxy. Apply connection/request timeouts
and rate limits there; the API limits request bodies to 1 MiB and record metadata
to 64 KiB. Interactive API documentation is at `/docs`, and the machine-readable
contract is `/openapi.json`. No file bytes are proxied through the API.

The bucket must deny public access and untrusted deletion. Service permissions
cover initiating/listing/completing/aborting multipart uploads, reading object
versions, listing versions for recovery, and generating PUT/GET grants. The
cleanup worker additionally needs deletion of object versions. Grant cleanup
rights only to the worker identity where your deployment separates credentials.
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

Only the configured bootstrap admin can create spaces. The space creator gets
admin, coordinator, and reader roles. Space admins can manage memberships;
admin alone is not a data-reader or publisher role. All spaces require membership,
including access by the bootstrap admin to spaces whose membership was changed.

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
waits for verification and publication. Preserve `state_path` to resume after
an interruption; reuse it only for identical files, metadata, and destination.
Use a new state path for a new record. Resume data contains record IDs and
idempotency keys, not access tokens or signed URLs. Download partial files are
also resumable and are checked against the full-file digest before replacement.

Default kinds are `message`, `configuration`, `training.update`, `model.global`,
and `evaluation.result`. Space creation can supply custom kind rules with
allowed creator roles, shared/private visibility, and local JSON Schemas.
Remote JSON Schema references are rejected. Contributors can publish messages
and training updates; only coordinators can publish global models/configuration.
Training updates are private to their creator and coordinators. Shared ready
records are readable by enrolled readers/contributors. Drafts are creator-only.

One record can contain up to 256 named attachments. Attachment descriptors are
returned with the record; record listings use bounded pages with a publication
time boundary. Space byte quotas count both unfinished reservations and retained
records. Cancel an unpublished record with `DELETE /records/{id}` to release
its reservation. Failed/aborted uploads need a new record; completed records
are immutable and cannot be deleted through the public API.

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

The claim ID and fence are printed. Another acquisition while the lease is
active fails with `claim_busy`; fewer than two candidates fails with
`insufficient_submissions`. Both are expected coordinator control conditions.
Domain validation still happens in the owner command before aggregation.
After lease expiry, a new acquisition retains the frozen inputs and advances
the fence. Stale workers cannot publish or bypass the claim by directly updating
`main`. A known active claim can be explicitly resumed with `--claim-id ID` in
a new output directory. A running coordinator can renew through
`POST /claims/{id}:renew` with its fence and `lease_seconds`; the CLI does not
automatically renew, so select a sufficient lease duration (up to 24 hours).

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
initialization/completion and expires unfinished drafts after 24 hours. Cleanup
waits for upload expiry plus the transfer-grant interval, then removes versions
and multipart uploads at that draft's server-generated keys. It never sweeps
live records by prefix. Worker storage failures remain retryable states.

An S3 operation and a database transaction cannot commit atomically. Ready
records are exposed only after successful verification; lost responses are
reconciled from reserved keys and fixed versions. A CAS conflict may leave an
unreferenced ready aggregate for inspection. Ready-record retention/garbage
collection is deliberately an administrative operation, outside the current
public API, so automatic cleanup cannot remove a live result.

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

The exchange tests default to SQLite and Moto S3 emulation. To test real
PostgreSQL and an S3-compatible server, set `EXCHANGE_TEST_DATABASE_URL` and
`EXCHANGE_TEST_S3_ENDPOINT`, and supply test-only S3 credentials through the
normal AWS environment variables. Then run:

```bash
.venv/bin/python -m unittest discover -s tests -p test_exchange.py -v
```

Tests create and remove uniquely named PostgreSQL schemas and S3 buckets.
Use dedicated test services and credentials that permit those operations.
Live coverage includes signed direct transfers and a full two-participant
FedAvg round. Moto is useful for application behavior; it is not proof of a
storage provider's signature enforcement. Run the live tests for each chosen
provider/version before deployment.
