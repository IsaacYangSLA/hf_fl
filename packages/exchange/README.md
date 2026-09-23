# HF²L Exchange

The Exchange SDK and service are installable independently of the HF²L
federated-learning application. The generic API exchanges bounded JSON metadata
and immutable file attachments; applications choose their own record types.
The server offers private, versioned S3 transfers with PostgreSQL metadata.

This is an unreleased development package. The package version `0.1.0.dev0`,
HTTP API version `/v2`, database revision, and selected application-profile version
are independent identifiers. No package publication is implied by this checkout.

## Install from this repository

Run these commands from the repository root, using the project environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e ./packages/exchange
```

The base SDK requires only HTTPX and its transport dependencies. It does not
install FastAPI, SQLAlchemy, Torch, NumPy, SafeTensors, or Hugging Face.

For the API and worker processes:

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
them requirements for generic spaces.

The `/v2` service uses a fresh database and storage prefix. It does not reinterpret
legacy records or provide a v1 API compatibility layer. The v3 architecture
retains this HTTP version while generalizing the federated-learning application.
Read the repository [v3 design](../../docs/ARCHITECTURE_V3.md) and
[operator guide](../../docs/EXCHANGE_V3.md) before configuring a deployment.
The [audit findings](../../docs/ARCHITECTURE_V3.md#current-implementation-limitations)
distinguish resolved Exchange defects from remaining application limitations.
The implementation preserves AWS session tokens, recovers interrupted
HF²L acquisition setup, and prevents cleanup from entering verification slots.
The operator guide explains credential configuration, recovery safeguards and
the worker's remaining batch scheduling limitation.

Unmodified SeaweedFS 4.47 fails multipart upload retries. An optional
[provider compatibility build](../../deploy/seaweedfs/README.md) applies a
provider patch for one S3 gateway. The patched provider binary passed remote
Exchange and application suites and live HTTP checks in that topology; see the
[remediation report](../../docs/validation/2026-09-23-exchange-remediation.md).
Exchange continues to require exact versions and size/SHA-256 verification.

## Validation boundaries

The configured CI workflow checks SDK and server imports in separate minimal
environments, then runs SQLite/Moto tests, PostgreSQL and pinned-MinIO integration
tests, and the existing HF²L regression suite. Local source checks can be run with:

```sh
.venv/bin/python scripts/check_exchange_dependencies.py --mode source
```

The `sdk` and `server` modes assert that unwanted packages are absent, so run them
in clean environments matching the relevant installation. Passing integration
tests does not establish deployment throughput or backup/restore performance,
or demonstrate that the known implementation limitations are absent. Recorded
local test results in the operator guide are historical; remote CI execution was
not part of that validation.
