# Native Go managed-training lifecycle qualification

This opt-in acceptance gate exercises the actual Go API, SQL manager, scheduler,
controller, provisioner, qualified Linux executor, node ledger, execution
proxies, managed Exchange edge, and transfer gateway. Independent Exchange runs
its ordinary API, managed API, storage backend, and verification worker against
real PostgreSQL and a private versioned S3 bucket.

Python is used for independent Exchange and the unchanged sandbox FL application.
No Python manager API, scheduler, controller, executor, gateway, or other
management service is invoked. The unchanged sandboxed Python FL application
adapter and independent Exchange remain.

## Prerequisites

- Complete isolation and physical backing-I/O qualification for the intended
  networkless CPU runtime. Use its actual qualified profile; there is no fallback.
- Import the immutable approved worker image with HF²L, the managed worker
  adapter, NumPy, and SafeTensors already installed.
- Provide dedicated PostgreSQL databases and operator-owned S3 credentials that
  may create/delete a unique test bucket. Never point this gate at production.
- Install independent Exchange server dependencies, Uvicorn, and NumPy into the
  fixture Python environment.
- Keep the runtime and test files on an owned local filesystem; grant only the
  sudo operations required by the documented qualified runtime/source fetcher.

The test starts two three-component jobs, each requesting 250 millicores,
256 MiB RAM, and 64 MiB disk per owner/participant. The compute pool admits six
components and keeps a third job queued. This is a deliberately tiny NumPy
workflow, not evidence that this resource size fits arbitrary ML jobs.

## Run

Create a private mode-0600 configuration file. All paths are explicit; the test
contains no machine-specific defaults.

~~~json
{
  "owned_root": "/srv/hf2l/qualification",
  "root": "/srv/hf2l/qualification/lifecycle-run-001",
  "profile": "/srv/hf2l/qualification/executor-profile.json",
  "image": "sha256:REPLACE_WITH_THE_QUALIFIED_WORKER_IMAGE_DIGEST",
  "python": "/srv/hf2l/fixture-venv/bin/python",
  "database_config": "/etc/hf2l/private-test-postgres.json",
  "storage_config": "/etc/hf2l/private-test-storage.json"
}
~~~

The root must not exist and must be a child of the qualified owned_root.
Proxy sockets use the qualified root, preserving the executor's path and Unix
socket-length requirements.

The private database file contains a databases object with separate exchange
and lifecycle PostgreSQL URLs. The private storage file contains endpoint,
access_key, secret_key, and optional region. These resource files must be
regular, single-link files owned by the invoking user with no group/world access.

From packages/jobs:

~~~sh
HF2L_GO_LIFECYCLE_CONFIG=/etc/hf2l/private-lifecycle-test.json \
  go test -count=1 -timeout=20m -v ./integration/lifecycle
~~~

Without the environment variable, this external-resource gate explicitly skips.

To qualify the native Go Exchange implementation, additionally set
HF2L_EXCHANGE_GO_BINARY to the absolute path of its built, operator-owned regular
executable. The fixture then launches native serve, serve-managed,
serve-gateway-backend, and worker processes; all post-readiness control operations
use their authenticated HTTPS APIs. Python helpers perform retained-state schema/
S3/seed setup, read-only oracle checks, and the sandboxed ML application. They do
not run an Exchange API or worker in this mode. The private ready/result receipts
record implementation=go and the exact binary SHA-256. An invalid explicit binary
fails closed. Leaving this variable unset preserves the Python Exchange reference
fixture.

The same variable selects the native backend for TestRealExchangeGateway in the
manager transfer package, alongside its existing private PostgreSQL/S3 opt-ins.

## Evidence and cleanup

The gate requires:

- Two jobs running concurrently while a third waits.
- Queued cancellation and cancellation during observed training.
- A fresh two-round federation using disjoint synthetic Alice/Bob NPZ inputs.
- Sample weights 0.4/0.6 and an independently parsed final SafeTensors value 3.2.
- Authenticated terminal artifact downloads with exact size/SHA-256, logs, and
  history.
- Purge with released allocations, zero retained-byte accounting, and independent
  Docker/mount/loop/backing-image checks.

The selected test root retains mode-0600 operational settings and private
receipts, failed attempts, logs, and fixture inputs. Normal shutdown removes its owned Exchange bucket and database
schema, manager schema after confirmed cleanup, and temporary service processes.
A manager schema is retained for recovery when owned cleanup cannot be confirmed.
When recovery cannot prove cleanup, the independent Exchange fixture is also
retained; its private PID and exact operational settings are recorded for an
operator to resume native cleanup. Do not delete its bucket or manager schema
before confirming fencing, physical cleanup, and released accounting.
The independently owned qualified runtime is left to its operator's shutdown.

Artifact downloads use the normal 300-second storage capability lifetime.
Retirement keeps bytes charged until those capabilities expire and the real
Exchange worker confirms physical deletion. Several minutes in the purge stage
are expected; the 15-minute gate deadline includes this drain and training
margin. The acceptance gate does not shorten the capability lifetime.
