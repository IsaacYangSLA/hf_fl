# HF²L Exchange Python client

The Exchange service is implemented in Go. This package provides the Python
client library used by Org P, Alice, and Bob to exchange information and model
files. It does not include a Python server or install a server command.

Org S builds and operates the Go service using the
[Go Exchange guide](../../docs/GO_EXCHANGE.md) or the
[Go Docker Compose guide](../../deploy/compose/go/README.md). Docker Compose
starts packaged services from a shared configuration file. Org P aggregates
models in its own environment; participants train on their own machines.

## Install the client

The client requires Python 3.11 or later. Run these commands from the repository
root. A virtual environment is a private directory containing this project's
Python tools and dependencies. The first command creates it; the second installs
this package from the checkout:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e ./packages/exchange
```

The only direct runtime dependency is HTTPX, the library used for network
requests. Installing the client does not install model-training libraries,
database libraries, or a server framework. The former `server` installation
extra and Python `hf2l-exchange` command have been removed. Build the Go
`hf2l-exchange` executable for server and maintenance operations.

This is an unreleased development package. Its package version, request format
version, database revision, and model-profile version are separate identifiers;
a checkout does not imply the same package is available from a public index.
Use the exact agreed repository revision.

## Client interface

The public Python imports remain under `hf2l_exchange`:

| Module | Responsibility |
| --- | --- |
| `client` | `ExchangeClient`, the typed service client. |
| `client_types` | Request results and client errors represented as Python values. |
| `client_state` | Private local operation state for resuming interrupted requests. |
| `transfer_client` | Verified file upload/download and managed transfer handling. |
| `domain` | `principal_id`, the stable account identifier derived from the exact login issuer and account subject. |

The service preserves the `/v2` request interface; this path identifies version
two of its network interface. The existing Python client works with the native
Go service. A service upgrade still requires the explicit compatibility and
qualification procedure in the [Go guide](../../docs/GO_EXCHANGE.md).

The client's managed-execution mode uses an assigned local Unix socket—a local
communication endpoint represented by a filesystem path. The existing
`ExchangeClient.for_execution(proxy_socket, space=...)` interface carries no
upstream credentials into a training execution. This package does not provision
the proxy, gateway, or execution isolation. See the
[managed-workload contract](../../docs/EXCHANGE_V3.md#managed-workloads-and-transfers).

Server-side permissions, schema validation, durable publication, and storage
cleanup are implemented by the Go service. The retained Python identity helper
and client result types do not implement those server responsibilities.

## Development checks

Run the client tests with the package installed into the same environment:

```sh
.venv/bin/python -m unittest discover -s packages/exchange/tests -v
.venv/bin/python scripts/check_exchange_dependencies.py --mode source
```

The source check rejects prohibited dependencies. Its `sdk` mode additionally
checks a clean client-only environment; SDK means software development kit,
here the client library. Run that mode only in a fresh environment containing
this package and its required dependencies:

```sh
.venv/bin/python scripts/check_exchange_dependencies.py --mode sdk
```

The [Go Exchange workflow](../../.github/workflows/exchange_go_tests.yml) tests
the server and the Python client's live requests against native Go services.
Local client tests check recovery, credentials, transfer boundaries, and request
formats without embedding another server implementation. A passing client test
suite does not qualify a deployment's storage, permissions, or model quality.

The service contracts are the documented request/response formats. Refresh the
[generated contracts](../../docs/generated/exchange-api.json) with the built Go
executable, from the repository root. The command exports the API document and
embedded reference artifacts. Configuration changes also require updating the
embedded environment reference before rebuilding and exporting:

```sh
./dist/hf2l-exchange export-contract --output-dir docs/generated
```

See the [operator guide](../../docs/EXCHANGE_V3.md) for account setup, storage,
permissions, recovery, and explicit database migration commands.
