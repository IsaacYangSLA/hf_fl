# Go job manager

The native Go implementation supplies the manager API, dashboard,
administration, scheduler, controller, provisioning, node and participant
services, transfer gateway, execution proxies, collection, and retention.
It does not call a Python manager through HTTP, RPC, or a manager subprocess.

The Python implementation remains a compatibility reference and rollback
option. Select one controller implementation per deployment and follow the
[cutover procedure](#cutover-and-rollback) before changing retained state.

## Boundaries

| Component | Implementation |
| --- | --- |
| Manager API, OIDC sessions, ACLs, queue, lifecycle, trusted services | Go under `packages/jobs/internal/` |
| Browser dashboard | Existing HTML, CSS, and JavaScript, embedded in the Go binary |
| Model training and evaluation | Existing HF²L Python application and local plugins |
| Sandboxed training/build application adapters | Existing Python adapters and fixed, qualified worker commands |
| Exchange API, verification worker, private transfer backend | Independent native Go Exchange or retained Python reference; see [Go Exchange](GO_EXCHANGE.md) |
| Database, identity provider, object storage, sandbox runtime | Separately deployed infrastructure |

Retained sandboxed adapters preserve source/wheel verification, durable round
state, checkpoint validation, and publication safety. They do not require a
Python manager service. Managed execution remains the qualified Linux CPU
profile; native participant GPU training is a separate workflow.

## Build

Use Linux and **Go 1.26 or later**. From the repository root:

```sh
mkdir -p dist
go -C packages/jobs build -trimpath -o ../../dist/hf2l-jobs ./cmd/hf2l-jobs
./dist/hf2l-jobs --help
./dist/hf2l-jobs serve --help
```

The [Go module](../packages/jobs/go.mod) pins dependency versions and checksums.
The dashboard uses the same [static assets](../packages/jobs/src/hf2l_jobs/static/index.html)
as the reference implementation; Node.js is not required.

Install this binary explicitly in the service account's executable path.
The Python wheel still installs the Python reference command. Check which
executable each supervisor invokes before switching a deployment.

## Configuration

The [operator guide](JOB_MANAGER.md) defines project roles, catalogs, APIs,
resource accounting, and authentication. The [deployment guide](../deploy/jobs/README.md)
defines infrastructure and runtime qualification. The Go binary does not install
PostgreSQL, OIDC, storage, certificates, or persistent boot units.

The Go command reads the same `HF2L_JOBS_` environment settings and `JOBS_`
aliases; conflicting aliases are rejected. Load private environment values
through the supervisor and keep credentials outside the checkout.

Use `--config /etc/hf2l/jobs.json` for trusted operational JSON. It overrides
the operational-file environment setting. Top-level sections remain `executor`,
`node`, `provisioner`, `service`, `gateway`, `proxy`, `retention`, `boundaries`,
`controller`, `secrets`, `nodes`, and `participants`. Each service validates the
fields it uses. Merge fragments into that service's complete configuration.

Configuration files must be bounded regular files, without symlinks or
group/world write access. Private files must exclude group/world access;
use mode 0600 for private configuration and secrets.

For example, the public listener's `service` fragment is:

```json
{
  "service": {
    "host": "127.0.0.1",
    "port": 8082,
    "tls_certificate": "/etc/hf2l/service.crt",
    "tls_key": "/etc/hf2l/service.key",
    "graceful_shutdown_timeout_seconds": 15
  }
}
```

Use the full manager identity configuration for `serve`, `node-api`, and
`controller`, as with the reference implementation. Other standalone service
commands validate their own required settings.

Human access uses HTTPS, OIDC authorization code with PKCE, server-side sessions,
CSRF, and exact-origin checks. The dashboard is `/dashboard/` and the API base
is `/api/jobs/v1`. Project `submitter` and `admin` members can create jobs.
Creation grants the caller job-admin membership; other project members do not
automatically see the new job.

Public `serve` and private `node-api` listeners are separate. Private callbacks
require verified client certificates and current signed node/workload authority;
forwarded certificate headers do not establish identity. Plain HTTP is limited
to explicitly enabled loopback development.

## Bootstrap and commands

Initialize only a new manager database:

```sh
./dist/hf2l-jobs init-db --config /etc/hf2l/jobs.json
```

Use `migrate-db` for a supported existing database. The shared revision remains
`0003_administrative_audit`. Startup checks schema state instead of silently
initializing or migrating it.

Trusted local administration retains the existing command shape:

```sh
./dist/hf2l-jobs admin --config /etc/hf2l/jobs.json project-create \
  --id research --name Research --quota-file /etc/hf2l/research-quota.json
./dist/hf2l-jobs admin --config /etc/hf2l/jobs.json project-member \
  --project research --principal HUMAN_PRINCIPAL_ID --role submitter
```

Keep `--config` before the admin operation. Use the operator guide for quotas,
pools, sources, images, datasets, and secret references. Healthy pools require
actual qualification. Object-store registration checks the backend's fixed
namespace and versioning.

Supervise the required commands separately, each with private configuration and
least-privilege identity:

| Command | Responsibility |
| --- | --- |
| `serve` | Human API and embedded dashboard |
| `controller` | Scheduling, provisioning, lifecycle reconciliation |
| `node-agent` | Local reservation watchdog and execution reconciliation |
| `node-api` | Private manager callbacks over mTLS |
| `managed-node` | Registered remote execution node |
| `participant-agent` | Autonomous approved external participant |
| `exchange-edge` | Managed Exchange mTLS boundary |
| `gateway` | Workload-authorized artifact transfers |
| `proxy` | Explicitly assigned execution Unix-socket proxy |
| `runtime` | Named sandboxed Python FL application adapter |

After dependencies, catalogs, and the qualified runtime are prepared, separate
supervised processes can run:

```sh
./dist/hf2l-jobs serve --config /etc/hf2l/jobs.json
./dist/hf2l-jobs node-api --config /etc/hf2l/jobs.json
./dist/hf2l-jobs controller --config /etc/hf2l/jobs.json
```

These are blocking services, not consecutive commands in one terminal.
Configure remote/participant agents on their approved execution nodes. Org S
and Org P do not need access to independent participant machines.

The controller manages per-execution proxies. The standalone `proxy` command
needs a complete assigned configuration. Keep pools unhealthy until runtime
identity, dependency, storage, and health checks pass. Manager `/readyz` alone
does not qualify admission.

## Independent Exchange private transfer backend

The Go gateway needs a private Exchange control interface for origin grants
and durable PUT fences. The independent [Go Exchange service](GO_EXCHANGE.md)
uses existing authorization and transfer ledgers; its private backend routes
are absent from public ingress. Build/install the Exchange binary separately:

```sh
./dist/hf2l-exchange serve-gateway-backend --host 127.0.0.1 --port 8445 \
  --tls-cert /etc/hf2l/backend-server.crt \
  --tls-key /etc/hf2l/backend-server.key \
  --client-ca /etc/hf2l/backend-client-ca.pem
```

The retained [Python reference backend](../packages/exchange/src/hf2l_exchange/gateway_api.py)
is an alternative during qualification/rollback; its Uvicorn factory must
supply HTTPS and required client-certificate verification. Select one backend
implementation explicitly and follow the Exchange cutover procedure.

Load the Exchange server settings through that service's private environment:
versioned storage, the normal service issuer, a distinct workload issuer/key,
the trusted backend assertion secret, and explicit provisioning principal IDs.
The fixed transfer audience defaults to `hf2l-transfer`. Configure the managed
Exchange audience separately, such as `exchange-managed`, and match the Go
settings.

Additional Go gateway fields are:

```json
{
  "gateway": {
    "backend_endpoint": "https://localhost:8445",
    "backend_secret_file": "/etc/hf2l/backend-assertion.secret",
    "ca_file": "/etc/hf2l/service-ca.pem",
    "backend_client_certificate": "/etc/hf2l/gateway-backend-client.crt",
    "backend_client_key": "/etc/hf2l/gateway-backend-client.key"
  }
}
```

This fragment also needs the gateway's external server certificate,
execution-client CA, fixed origin endpoints, and workload settings. Use a
dedicated backend client certificate with client-auth purpose. `ca_file` trusts
the backend server; the gateway's `client_ca_file` authenticates workloads.

The managed Exchange edge can likewise set `backend_client_certificate` and
`backend_client_key` under `boundaries.exchange`. They authenticate its
connection to the managed Exchange backend; they do not replace the original
workload identity in the signed assertion. Keep the edge backend endpoint
separate from the gateway's private transfer-backend endpoint.

Private operations verify signed assertions and current certificate-bound
transfer authority. Only the trusted gateway receives origin storage
descriptors. A sealed receipt can settle its exact prior PUT after token expiry
or revocation; it cannot authorize new work or settle a successor mutation.
Storage probes additionally require an allowlisted service principal and
inspect only the configured namespace. Drain outstanding mutations before
rotating assertion keys.

Do not expose this backend through the public Exchange API or an unauthenticated
proxy. Generic Exchange clients keep their existing `/v2` API and SDK.

## Cutover and rollback

1. Record the Go binary, source revision, and dependency hashes.
2. Back up PostgreSQL, ownership ledgers, runtime profiles, source snapshots,
   and storage/version metadata. Test a restore separately.
3. Stop admission and competing controllers. Reconcile active or uncertain
   executions and publications before changing the control plane.
4. Validate a copy of retained data with Go. Preserve principal IDs, immutable
   hashes, memberships, accounting, and schema revision. Do not run `init-db`
   over retained state.
5. Prepare private Exchange access and Go services. Revalidate actual runtime,
   host/device identities, TLS, OIDC, storage, and restart ordering.
6. Run [qualified runtime acceptance](#qualified-runtime-acceptance) before
   admission: concurrent jobs, queue
   advancement, cancellation, recovery, foreign-job denial, streaming
   revocation, and physical purge/accounting.
7. For rollback, first stop Go admission/controller and reconcile uncertain
   effects. Verify schema/state compatibility before starting the reference
   implementation. Never run both controllers over the same jobs.

Unit tests or qualification from another deployment do not establish this
deployment's isolation or readiness. Managed GPU, Kubernetes, HA, and off-node
disaster recovery remain separate work.

## Developer checks

From the repository root:

```sh
go -C packages/jobs vet ./...
go -C packages/jobs test -race -count=1 ./...
```

Frozen Python-derived fixtures cover canonical JSON, principals, specifications,
cursors, schema, and migrations. PostgreSQL gates create unique owned schemas
and require an explicit disposable database URL:

| Variable | Tests |
| --- | --- |
| `JOBS_TEST_DATABASE_URL` | Store migrations and manager concurrency |
| `HF2L_GO_SCHEDULER_TEST_DATABASE_URL` | Gang admission and queue advancement |
| `GO_CONTROLLER_TEST_DATABASE_URL` | Outbox ownership, recovery, cancellation |
| `HF2L_GO_HTTP_TEST_DATABASE_URL` | Go HTTP/auth over PostgreSQL |

The [Go workflow](../.github/workflows/jobs_go_tests.yml) runs formatting, vet,
builds, race checks, PostgreSQL, an actual Go-backed browser gate, and the
separate live transfer integration gate.
Python regression and sandbox-application tests remain in their original
workflow.

The browser gate sets `HF2L_GO_BROWSER_PYTHON` to an interpreter with
Playwright and Chromium. It exercises the Go OIDC client, SQL-backed sessions,
job creation, views, permissions, and logout without intercepted manager APIs.
Lifecycle fixture transitions in that test do not execute sandboxed training.

The live gate starts an actual private Exchange HTTPS/mTLS application and
uses the Go gateway with PostgreSQL and MinIO. Configure:

- `HF2L_GO_EXCHANGE_TEST_PYTHON`: an interpreter with Exchange server,
  Uvicorn, Boto3, Cryptography, and Psycopg.
- `HF2L_GO_EXCHANGE_TEST_DATABASE_CONFIG`: a private JSON file containing
  `{"databases":{"exchange":"POSTGRESQL_TEST_URL"}}`.
- `HF2L_GO_EXCHANGE_TEST_STORAGE_CONFIG`: a private JSON file containing
  fixed `endpoint`, `access_key`, `secret_key`, and `region`.
- `HF2L_GO_REQUIRE_EXCHANGE_INTEGRATION=1`: fail on missing prerequisites.

Run the configured gate:

```sh
go -C packages/jobs test -count=1 -run TestRealExchangeGateway -v ./internal/transfer
```

Use private temporary directories and disposable infrastructure. The fixture
owns its database schema, bucket objects/versions, uploads, certificates, and
processes and removes them on completion. This does not qualify a production
object store or privileged CPU runtime.

## Qualified runtime acceptance

Browser and transfer integration tests do not execute a complete managed
federation. The following opt-in gates require an independently qualified CPU
runtime and disposable, operator-owned resources. They are separate from the
hosted CI jobs above. Their presence in the source tree is not a passing
deployment qualification record.

### CPU executor

The [real executor instructions](../packages/jobs/internal/executor/INTEGRATION.md)
describe the node ledger/watchdog, concurrent execution, cancellation,
lease expiry, retained state, and physical cleanup gate. Prepare a new private
networkless CPU runtime, passing isolation and backing-I/O reports, and the exact
immutable worker image qualified by those reports. The test does not pull images
or change daemon settings.

Set all three explicit inputs:

| Variable | Input |
| --- | --- |
| `HF2L_TEST_QUALIFIED_PROFILE` | Private executor profile and its referenced qualification reports |
| `HF2L_TEST_WORKER_IMAGE` | Exact qualified image digest, with the stock FL/build adapters and offline dependencies installed |
| `HF2L_TEST_EXECUTOR_ROOT` | Fresh private test directory beneath the profile's owned root |

From the repository root:

```sh
go -C packages/jobs test -race -tags integration -count=1 \
  -run '^TestQualifiedCPULifecycle$' -v ./internal/executor
```

This gate runs actual qualified sandboxes and checks the executor/build
application. It does not establish the full API-to-federation workflow. Its
instructions also document recovery of a failed, receipt-bound executor attempt.

### Complete managed federation

The [native lifecycle fixture](../packages/jobs/integration/lifecycle/README.md)
exercises the Go API, SQL manager, scheduler, controller, provisioner, executor,
proxies, managed Exchange edge, and transfer gateway. Independent Exchange
services and a real versioned S3 bucket supply storage; the named sandboxed
Python FL application adapter performs training.

In addition to the qualified runtime and imported worker image, prepare:

- Separate disposable manager/lifecycle and Exchange PostgreSQL databases.
- Operator-owned S3 credentials permitted to create and remove a unique test
  bucket, including versions and multipart uploads.
- A fixture Python environment with independent Exchange server dependencies,
  Uvicorn, and NumPy.
- Only the required runtime/source-fetch sudo permissions and an owned local
  filesystem with enough capacity for concurrent execution and retained state.

Set `HF2L_GO_LIFECYCLE_CONFIG` to a private mode-0600 JSON file owned by the
invoking user. Its explicit fields are `owned_root`, `root`, `profile`, `image`,
`python`, `database_config`, and `storage_config`. The new `root` must not
already exist and must be below the qualified `owned_root`. The linked fixture
guide specifies the resource-file shapes and small synthetic job sizes.

```sh
HF2L_GO_LIFECYCLE_CONFIG=/etc/hf2l/private-lifecycle-test.json \
  go -C packages/jobs test -count=1 -timeout=20m \
  -run '^TestNativeGoFederatedLifecycle$' -v ./integration/lifecycle
```

The assertions cover two jobs running concurrently with a third queued, queued
and in-training cancellation, a fresh two-round federation with local managed
Alice/Bob participants, authenticated results/logs/history, and purge with
physical absence and zero accounting. The numerical check uses disjoint
synthetic inputs, weights 0.4/0.6, and an independent scalar FedAvg oracle; it
is not a model-quality benchmark or a remote-participant qualification.

Without its explicit configuration, the gate skips. Record the actual run,
failed attempts, qualification hashes, and cleanup results before cutover.
Keep retained fixture roots private: they contain operational settings,
test credentials, inputs, logs, and recovery evidence. Unconfirmed cleanup
retains recovery state and charges rather than treating missing processes as
proof of deletion. The operator owns final shutdown of the qualified runtime.
