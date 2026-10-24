# HF²L Exchange

The Exchange SDK and service are installable independently of the HF²L
federated-learning application. The generic API exchanges bounded JSON metadata
and immutable file attachments; applications choose their own record types.
The server offers private, versioned S3 transfers with PostgreSQL metadata.

This is an unreleased development package. The package version `0.1.0.dev0`,
HTTP API version `/v2`, database revision, and selected application-profile version
are independent identifiers. No package publication is implied by this checkout.

## Choose server and client implementations

Org S can build the native **Go API and worker** using the
[Go Exchange guide](../../docs/GO_EXCHANGE.md). They do not call a Python
Exchange bridge or execute ML workloads. Org P, Alice, and Bob keep the same
Python SDK and training tools. The HTTP API and current persistence contract
remain shared; cutover requires explicit compatibility checks and qualification.

The Python server remains a reference and rollback implementation. The beginner
Compose walkthrough continues to use that reference deployment. Exchange itself
uses versioned S3; Hugging Face/JFrog/local stores are training-layer adapters.

## Install the Python SDK or reference server

The SDK and Python reference service require Python 3.11 or later. Run these commands from the
repository root, using the project environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e ./packages/exchange
```

The base SDK requires only HTTPX and its transport dependencies. It does not
install FastAPI, SQLAlchemy, Torch, NumPy, SafeTensors, or Hugging Face.

For the Python reference API and worker processes:

```sh
.venv/bin/python -m pip install -e './packages/exchange[server]'
.venv/bin/hf2l-exchange --help
```

The server adds database, authentication, JSON Schema, and S3 dependencies. It
still does not install the ML stack. The `hf2l-exchange` command operates the new
v2 service; the existing `hf2l-exchange-service` command belongs to the legacy
service bundled in the separate `hf2l` distribution.

For repository development including HF²L adapters and all regression tests,
install both local distributions together so the unreleased exchange dependency
is resolved locally:

```sh
.venv/bin/python -m pip install -e './packages/exchange[server,test]' -e '.[torch,hf,examples,exchange,service,exchange-test]'
.venv/bin/python -m unittest discover -s packages/exchange/tests -v
.venv/bin/python -m unittest discover -s tests -v
```

The HF²L v3 distribution uses NumPy and SafeTensors as its base runtime. Torch,
Hugging Face, and training examples are optional extras. Both local distributions
must be specified together when installing the unreleased exchange extra.

## Architecture and compatibility

The package uses a `src` layout with public imports under `hf2l_exchange`.
Domain values and the SDK do not import the HF²L application or server adapters.
The server owns authorization, publication, and storage lifecycle invariants.
An optional trusted FedAvg profile adds application constraints without making
them requirements for generic spaces. Opt-in managed spaces add persisted,
certificate-bound workload grants, a separate authenticated ingress, and
structured transfer descriptors for a trusted gateway. The SDK's
`ExchangeClient.for_execution(proxy_socket, space=...)` uses an assigned Unix
socket and carries no upstream credentials. The standalone package does not
provision that proxy, gateway or runtime isolation; see the
[managed-workload contract](../../docs/EXCHANGE_V3.md#managed-workloads-and-transfers)
and [job-manager deployment guide](../../docs/JOB_MANAGER.md).

Public API tokens must be RS256 access JWTs with `typ=at+jwt`, the configured
issuer/audience, required subject/timestamps and the `exchange` scope. An OIDC
provider must explicitly supply that contract. Workload tokens use a separate
issuer, configured audience and certificate binding and are rejected by public ingress.
Roles and bindings come from current space membership and persisted grants,
not from caller-selected token roles.

The `/v2` service uses a fresh database and storage prefix. It does not reinterpret
legacy records or provide a v1 API compatibility layer. The v3 architecture
retains this HTTP version while generalizing the federated-learning application.
Read the repository [v3 design](../../docs/ARCHITECTURE_V3.md) and
[operator guide](../../docs/EXCHANGE_V3.md) before configuring a deployment.
The [audit findings](../../docs/ARCHITECTURE_V3.md#current-implementation-limitations)
describe resolved defects and the limits of the implemented workflows.
The implementation preserves AWS session tokens, recovers interrupted
HF²L acquisition setup, and prevents cleanup from entering verification slots.
The current database revision is `0003_workload_grants`: existing `0001_initial`
or `0002_event_sequence` installations must stop API/worker processes, back up the database, run
`hf2l-exchange migrate-db` and `check-db`, then restart. SQLite event IDs retain
their cursor sequence after history pruning; the frozen initial migration is
preserved. Revision `0003_workload_grants` adds managed-space workload grants and
revocation records, and is also required for ordinary Exchange deployments. Readiness probes stay under the configured S3 prefix while retaining
the bucket-versioning check.
The operator guide explains credential configuration, recovery safeguards and
the Python reference worker's batch scheduling limitation. Consult the
[Go guide](../../docs/GO_EXCHANGE.md) for native-service commands, schema
compatibility preflight, and its separate qualification requirements.

Unmodified SeaweedFS 4.47 fails multipart upload retries. An optional
[provider compatibility build](../../deploy/seaweedfs/README.md) applies a
provider patch for one S3 gateway. The patched provider binary passed remote
Exchange and application suites and live HTTP checks in that topology; see the
[remediation report](../../docs/validation/2026-09-23-exchange-remediation.md).
Exchange continues to require exact versions and size/SHA-256 verification.

## Validation boundaries

The [native Go workflow](../../.github/workflows/exchange_go_tests.yml) adds
Go formatting/build/vet/race tests, PostgreSQL compatibility, actual Python-SDK
requests to Go HTTPS services with MinIO, and bidirectional retained-state gates.
These configured checks do not imply a deployment has passed qualification.

The existing Python CI workflow checks SDK and server imports in separate minimal
environments, then runs SQLite/Moto tests, PostgreSQL and MinIO integration
tests, and the existing HF²L regression suite. PostgreSQL uses a pinned image
digest. MinIO is built from verified upstream commit
`7aac2a2c5b7c882e68c1ce017d8256be2feea27f` and source-archive SHA-256
`71794c2df26aad0cc99e8421c58b7aa2dd55969f979b0e7d1e931042e9fabcd6`,
using the [shared Dockerfile](../../examples/first_federation/Dockerfile.minio)
and its pinned build/runtime images. Local source checks can be run with:

```sh
.venv/bin/python scripts/check_exchange_dependencies.py --mode source
```

The `sdk` and `server` modes assert that unwanted packages are absent, so run them
in clean environments matching the relevant installation. Passing integration
tests does not establish deployment throughput or backup/restore performance,
or demonstrate that the known implementation limitations are absent. Recorded
local test results in the operator guide are historical. The
[October 8 remediation record](../../docs/validation/2026-10-08-repository-remediation.md)
records historical local source, package, and workflow checks; remote CI execution
was not part of that validation.

The generated [HTTP contract](../../docs/generated/exchange-api.json),
[error inventory](../../docs/generated/exchange-errors.json), and
[environment table](../../docs/generated/exchange-environment.md) can be refreshed
from the installed source without starting services:

```sh
.venv/bin/hf2l-exchange export-contract --output-dir docs/generated
```

Run the command from the repository root with the server extra installed.
