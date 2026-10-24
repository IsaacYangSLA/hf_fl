# Native Go Exchange acceptance

These opt-in gates use actual native Go HTTPS listeners and workers, PostgreSQL,
and a versioned S3-compatible store. SDK requests are not intercepted. No Python
Exchange service runs behind the native implementation.

The Python SDK remains unchanged. Python is a client and fixture operator.
The retained-state gate also uses the Python reference application while Go
processes are stopped, to check state continuation in both directions.

## Prerequisites

- Build `packages/exchange/cmd/hf2l-exchange` as a native executable.
- Supply an explicitly disposable PostgreSQL database; its test user must be
  allowed to create and drop owned schemas.
- Supply a dedicated S3 test endpoint with credentials allowed to create,
  version, inspect and remove owned buckets.
- Use Python with the current Exchange package, HTTPX, Cryptography, PyJWT,
  Psycopg, Boto3, SQLAlchemy, FastAPI, Uvicorn and JSONSchema. Server dependencies
  support the offline retained-state oracle; Python servers/workers are not launched.
- Create a mode-`0700` evidence root. Keep all settings and secrets outside Git.

Each fixture generates a unique schema and bucket. Never supply production
database credentials or an existing application bucket.

## Private configuration

The database receipt contains `{"databases":{"sdk":"POSTGRESQL_TEST_URL"}}`.
The storage receipt contains `endpoint`, `access_key`, `secret_key`, and `region`.
Create a separate mode-`0600` configuration:

```json
{
  "go_binary": "/path/to/native/hf2l-exchange",
  "database_config": "/path/to/private/database.json",
  "storage_config": "/path/to/private/storage.json",
  "root": "/path/to/private/sdk-evidence",
  "database_key": "sdk"
}
```

An absent evidence root is created privately; an existing root must be owned and
mode-0700. Fixtures create private
children, independent server/client CAs, and native public, managed and private
backend listeners plus a native worker. TLS chains are actually verified; the
private backend requires a verified client certificate.

A loopback HTTP S3 test endpoint is permitted only with the fixture's explicit
local-development setting. Exchange listeners still use HTTPS. Production
storage endpoints require HTTPS.

## Unchanged Python SDK gate

From the repository root:

```sh
export HF2L_GO_EXCHANGE_SDK_CONFIG=/path/to/private/sdk-config.json
export HF2L_GO_EXCHANGE_SDK_PYTHON=/path/to/test-environment/bin/python
go -C packages/exchange test -race -count=1 -timeout=20m \
  -run '^TestPythonSDKAgainstNativeGoExchange$' -v ./integration
```

This checks spaces/idempotency, membership, full bounded JSON Schema, canonical
hashes, large integers, draft CAS, zero-byte/multipart upload, immutable-version
download/hash, pagination, event visibility, revocation, quotas, FedAvg metadata
and coordination fences, managed grants, and restart. Exchange performs no
model training or FedAvg arithmetic.

## Retained-state continuation

Use the same private configuration contract with independent evidence roots:

```sh
export HF2L_GO_EXCHANGE_RETAINED_CONFIG=/path/to/private/retained-config.json
export HF2L_GO_EXCHANGE_RETAINED_PYTHON=/path/to/test-environment/bin/python
go -C packages/exchange test -race -count=1 -timeout=20m \
  -run '^TestRetainedStatePythonAndGo$' -v ./integration
```

Unset retained variables fall back to the SDK variables. This gate checks both
Python-initialized state continued by Go and Go-initialized state continued by
Python: idempotency, Unicode principals, large integers, frozen coordination
inputs, multipart uploads, durable PUT markers and sealed settlement receipts.

## Cleanup and evidence

Both gates preserve the **300-second storage grant duration**. Retirement can
legitimately wait five minutes after the latest issued grant. The twenty-minute
timeout includes control work, grant drain and cleanup.

Cleanup uses authenticated native retirement APIs and the native worker. Zero
allocated/reclaiming bytes and independent absence of object versions, delete
markers and multipart uploads are required before removing owned namespaces.
Historical metadata is retained until the proven-clean test schema is removed.

Private attempt directories contain logs, settings, source/binary hashes and
receipts. Failed attempts remain separate. If cleanup cannot be proven, real
authority and process receipts are preserved for authenticated recovery.
Timeout, age and lease expiry never stand in for provider-quiescence proof.
Do not commit or upload raw fixture directories as CI artifacts.
