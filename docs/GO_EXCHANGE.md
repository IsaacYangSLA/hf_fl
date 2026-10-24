# Go Exchange

Org S can run the Exchange API and verification/recovery worker as native Go
processes. The implementation is independent of the Go job manager. It does
not invoke a Python Exchange server, bridge requests to Python, or execute
training code.

The Python SDK remains the client interface for Org P, Alice, and Bob. Their
existing `ExchangeClient` calls and HF²L Exchange-backed trainers use the same
`/v2` API. The Python server remains a reference implementation and a rollback
option. Installing a binary does not migrate or qualify a deployment.

## Who does what

| Role | Responsibility |
| --- | --- |
| Org S | Build/install the server, configure identity, PostgreSQL and S3, supervise API/worker, back up state, and qualify a cutover. |
| Org P | Agree on the trainer/model, manage delegated project membership, publish checkpoints, and aggregate participant updates using the existing client tools. |
| Alice and Bob | Install the Python SDK/application, run the agreed trainer on their own machines and private data, and submit updates. |

Org S and Org P need no SSH or filesystem access to independent participant
machines. Exchange transports metadata and files; it does not deploy trainers
to participants. The [beginner walkthrough](../examples/first_federation/README.md)
continues to use its supplied Python-reference Compose stack. Follow it as
written unless deliberately qualifying a Go service deployment.

## Build and install

Use Linux and **Go 1.26 or later**. From the repository root:

```sh
umask 022
mkdir -p dist
go -C packages/exchange build -trimpath -o ../../dist/hf2l-exchange ./cmd/hf2l-exchange
./dist/hf2l-exchange --help
./dist/hf2l-exchange serve --help
```

The [Go module](../packages/exchange/go.mod) pins dependencies and checksums.
Install the binary into an operator-owned executable location and configure
supervisors with its explicit path. Set a non-writable-by-group mode explicitly;
for example, an administrator can install it with:

```sh
sudo install -o root -g root -m 0755 ./dist/hf2l-exchange /usr/local/bin/hf2l-exchange
/usr/local/bin/hf2l-exchange --help
```

Use mode 0700 for a private test binary and 0600 for private configuration.
A build inherited from a group-writable umask can otherwise produce an unsafe
executable mode.

The Python wheel also installs a command
named `hf2l-exchange`; verify which executable is being started.

Clients still install the Python SDK, without the server extra:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e ./packages/exchange
```

SDK/application Python requirements remain unchanged. The Go server requires
neither the Python SDK nor an ML environment.

## Configuration and services

Use the existing `EXCHANGE_` settings in the
[operator runbook](EXCHANGE_V3.md#configure-and-start) and
[environment table](generated/exchange-environment.md).
Keep database credentials, signing material, S3 keys, and backend secrets in
the service's private environment, outside source control.

PostgreSQL is the deployment metadata store. SQLite is for development and
tests. **Versioned S3-compatible storage is the only Exchange blob backend.**
MinIO and the documented patched SeaweedFS are S3 implementations.
Hugging Face, JFrog, and local filesystem stores are alternatives in the
[HF²L training layer](../README.md#model-storage-four-backends), not selectable
Exchange storage implementations.

Configure the public issuer/audience and one RS256 verification-key source.
The public token contract remains `typ=at+jwt`, required timestamps/subject,
and `exchange` scope. Managed workloads have a distinct issuer, audience,
certificate binding, current grant, and membership checks. The private backend
also requires its trusted assertion secret and explicit service-principal
allowlist. Do not use one listener or identity contract for all three.

For a **new** database, configure storage and identity before starting services:

```sh
./dist/hf2l-exchange init-db
./dist/hf2l-exchange check-db
./dist/hf2l-exchange check-storage
./dist/hf2l-exchange check-compatibility
./dist/hf2l-exchange serve --host 127.0.0.1 --port 8441 \
  --tls-cert /etc/hf2l/exchange-server.crt --tls-key /etc/hf2l/exchange-server.key
# Supervise this as a separate process:
./dist/hf2l-exchange worker
```

Use `migrate-db` for supported older schemas, never `init-db` over retained
data. The current revision remains `0003_workload_grants`. Schema changes
are explicit; startup does not silently initialize or migrate a database.
Database checks and compatibility preflight require only database settings.
An incompatible retained schema makes `check-compatibility` exit with status 1;
API startup performs the same check before admission. The worker can still
reclaim storage when unrelated metadata schemas are incompatible.
The worker requires database/storage settings, not public JWT verification.

| Command | Purpose |
| --- | --- |
| `serve` | Public `/v2` API; rejects managed workload tokens. |
| `serve-managed` | Separate managed ingress behind the trusted workload-authenticating edge. |
| `serve-gateway-backend` | Private transfer authorization, mutation fences, receipt settlement, and storage probes. |
| `worker` | Verification, recovery, retention, and reclamation; `--once` runs one pass. |
| `repair-transfers` | Reviewed operator recovery of interrupted provider mutations. |
| `init-db`, `migrate-db`, `check-db` | Explicit database lifecycle. |
| `check-storage`, `check-compatibility` | Storage probe and retained-schema compatibility preflight. |
| `export-contract` | Write generated contract artifacts without starting a listener. |

Use each command's `--help` for options. Put the command before its flags.
The Go HTTP process accepts only
`--workers 1`; other values fail explicitly. HTTP requests run concurrently
in Go goroutines. This flag does not configure verification/cleanup pools;
those retain the separate `EXCHANGE_WORKER_*` settings.

## TLS and private transfer backend

Listeners accept `--host`, `--port`, `--tls-cert`, `--tls-key`, and
`--client-ca`. Use server certificates with the endpoint's DNS/IP SANs and
server-auth purpose. Ordinary HTTPS clients must trust the service CA.
The private transfer backend requires TLS **and verified client certificates**:

```sh
./dist/hf2l-exchange serve-gateway-backend --host 127.0.0.1 --port 8445 \
  --tls-cert /etc/hf2l/backend-server.crt \
  --tls-key /etc/hf2l/backend-server.key \
  --client-ca /etc/hf2l/backend-client-ca.pem
```

Only the trusted gateway should reach this listener. Its client certificate
uses client-auth purpose; the assertion secret and current Exchange authority
remain mandatory. Do not expose the backend through the public API.
The [Go manager integration](GO_JOB_MANAGER.md#independent-exchange-private-transfer-backend)
configures the corresponding private endpoint, trust bundle, backend client
certificate, and secret. The default transfer audience is `hf2l-transfer`;
the managed Exchange workload audience is separately configured and must match
the manager.

Public and managed listeners also need deliberate TLS configuration. An
explicit loopback-only local HTTP option is for development, not a substitute
for private-backend mTLS. Forwarded identity headers alone do not authenticate
a workload.

## Compatibility, cutover, and rollback

Go and Python use the existing `/v2` wire protocol and current Exchange schema.
This is not a v1 importer or a production-cutover instruction. Keep the
reference binary/environment available until the actual deployment qualifies.

JSON Schema validation remains Draft 2020-12. Common Python regular-expression
patterns are supported; Python-specific extensions cannot all be translated
with identical semantics. Unsupported schemas fail closed. Run
`check-compatibility` against a restored copy of retained data before cutover;
it checks stored schemas without rewriting them and reports safe identifiers
and error codes. Do not edit retained schema history to bypass a failure.

The supported Python-style grammar includes named/numeric groups and
backreferences, fixed-width lookbehind, lookahead, character classes/boundaries,
ASCII and scoped flags, case folding, and atomic/possessive constructs.
Unicode properties and case folding follow the native Go compiler's Unicode
tables, with explicit compatibility handling for common Python cases; this
does not emulate a fixed Python Unicode version.

| Unsupported construct or bound | Safe feature code |
| --- | --- |
| Case-insensitive dynamic backreferences | `casefold_backreference` |
| Non-ASCII capture names | `unicode_capture_name` |
| Unicode named escapes (`\N{...}`) | `unicode_name_escape` |
| Repeat counts above signed 32-bit range | `large_repeat` |
| Python 3.14 end anchor (`\z`) | `python314_end_anchor` |
| Pattern above 65,536 bytes | `regex_source_limit` |
| Group nesting above 256 | `regex_nesting_limit` |
| Translation expansion above 1 MiB | `regex_expansion_limit` |

Observed toolchain Unicode versions differ:

| Runtime used in compatibility probes | Unicode tables |
| --- | --- |
| Python 3.11.17 reference | 14 |
| Go 1.26.10 | 15 |
| Go 1.27.3 | 17 |

For example, Kawi U+11F02 matches native `\w`/`\b` and U+11F50 matches
native `\d` on both Go versions, while the Python reference rejects them.
Cyrillic U+1C89/U+1C8A case folding differs additionally between Go versions.
A surrounding JSON Schema `not` can reverse the resulting acceptance decision.

`check-compatibility` verifies supported grammar and bounds; it does not prove
universal Unicode-semantic equivalence. For stable cross-runtime patterns,
use `(?a)` with ASCII categories/boundaries and explicit ASCII classes such
as `[A-Za-z0-9_]` or `[0-9]`. ASCII-mode/case-fold controls were consistent
in the observed probes. Otherwise pin the Go compiler and qualify representative
Unicode inputs, including negated schemas, against the chosen Python runtime.
Python releases can also change Unicode behavior.

Schema registration rejects these with `invalid_schema` and detail
`unsupported_regex:<feature>`. Metadata regex matching has a 100 ms budget.
Exhaustion rejects the entire schema evaluation with
`metadata_schema_mismatch` / `regex_timeout`; it does not return a false
match that a surrounding `not` could invert into acceptance.
Use supported patterns for new schemas. Preflight checks every retained
revision: adding a new revision does not clear an incompatible older one.
Do not edit or delete immutable type history just to pass preflight. Remain
on the Python reference or use an operator-reviewed fresh namespace and
export/migration plan, qualified before cutover. No automatic rewrite occurs.

1. Record source/binary/dependency hashes and back up the database and exact
   S3 version/prefix metadata. Exercise a restore independently.
2. Stop admission, API mutations, and all old workers before switching.
   Reconcile in-flight uploads, provider mutations, verification ownership,
   publication, and retained receipts; preserve failed-attempt evidence.
3. Run `check-db` and `check-compatibility` on the restored copy using Go.
   Test supported explicit migrations there if needed.
4. Qualify real HTTPS, identity, Python SDK operations, current ACLs,
   versioned S3 multipart/retry/verification, worker recovery, and cleanup
   against the intended deployment. Managed deployments additionally qualify
   workload/edge/gateway behavior and their runtime.
5. Start the selected implementation with scoped credentials, then enable
   admission only after dependency checks and acceptance pass.
6. For rollback, stop Go mutations and workers, reconcile uncertain effects,
   and verify retained-state compatibility before starting the Python
   reference. Restore the tested backup if state is incompatible.

Malformed retained mutation ledgers fail closed: null/non-array ledgers,
non-string markers, or duplicate markers cannot be silently normalized by
settlement or repair. The worker retains physical charges and ownership
authority. `repair-transfers` inventory reports `mutation_ledger_valid: false`
and `mutation_count: null`; applying repair to that attempt fails with
`attempt_not_repairable`. Recovery requires operator review and proven provider
quiescence. Do not edit immutable history or automatically prune unknown
mutation records to clear the hold.

Do not operate competing old/new workers during a cutover. Passing unit tests
or another deployment's integration suite does not establish throughput,
backup recovery, runtime isolation, or production readiness.

## Developer checks and evidence

Use a private temporary root and isolated database/storage fixtures. From the
repository root:

```sh
go -C packages/exchange mod verify
go -C packages/exchange vet ./...
go -C packages/exchange test -race -count=1 ./...
```

Set the PostgreSQL fixtures explicitly; tests create their own unique schemas
inside a disposable test database:

| Tests | Database environment setting |
| --- | --- |
| Store and worker | `HF2L_EXCHANGE_TEST_DATABASE_URL` |
| Application service | `HF2L_GO_EXCHANGE_TEST_DATABASE_URL` |
| Private gateway backend | `EXCHANGE_GO_GATEWAY_TEST_DATABASE_URL` |
| HTTP API | `HF2L_EXCHANGE_HTTP_TEST_DATABASE_URL` |

CI points all four settings at its owned test database. Set both
`HF2L_EXCHANGE_TEST_PYTHON` and `HF2L_GO_EXCHANGE_REFERENCE_PYTHON` to the same
Python environment with the current reference server/SQLAlchemy for persistence
and coordination oracles. Do not point fixtures at a production database.

The [Go Exchange CI workflow](../.github/workflows/exchange_go_tests.yml)
checks formatting, module checksums, build/vet, and SQLite/PostgreSQL race tests
on Go 1.26 and 1.27. Its integration gate uses the unchanged Python SDK
against the actual Go HTTPS service with PostgreSQL and MinIO. Python-reference regression checks
remain in the [existing workflow](../.github/workflows/exchange_tests.yml).

A configured workflow or test fixture is not a recorded passing result.
Keep release and qualification evidence tied to the tested revision.

To run the live gates, prepare a private mode-0600 JSON file containing
`go_binary` (absolute native binary path), `database_config` (private PostgreSQL
receipt), `storage_config` (private S3 receipt), `root` (owned private scratch
directory), and `database_key` (key in the database receipt's `databases` map).
The storage receipt contains `endpoint`, `access_key`, `secret_key`, and
`region`. Use dedicated test resources with schema-creation and
bucket/version/multipart privileges.

Install the current Python SDK plus HTTPX, Cryptography, PyJWT, Psycopg, and
Boto3 for the live SDK harness. The retained-state gate additionally uses the
Python reference server dependencies to verify continuation in both directions;
this test dependency is not a Go-server runtime dependency.

```sh
HF2L_GO_EXCHANGE_SDK_CONFIG=/etc/hf2l/private-sdk-test.json \
HF2L_GO_EXCHANGE_SDK_PYTHON=/opt/hf2l-test/bin/python \
  go -C packages/exchange test -race -count=1 -timeout=20m \
  -run '^TestPythonSDKAgainstNativeGoExchange$' -v ./integration

HF2L_GO_EXCHANGE_RETAINED_CONFIG=/etc/hf2l/private-retained-test.json \
HF2L_GO_EXCHANGE_RETAINED_PYTHON=/opt/hf2l-test/bin/python \
  go -C packages/exchange test -race -count=1 -timeout=20m \
  -run '^TestRetainedStatePythonAndGo$' -v ./integration
```

A separate provider gate tests the native S3 adapter directly, including exact
versions, multipart operations, signed transfers, and scoped cleanup:

```sh
HF2L_GO_EXCHANGE_STORAGE_CONFIG=/etc/hf2l/private-s3-test.json \
HF2L_GO_REQUIRE_STORAGE_INTEGRATION=1 \
  go -C packages/exchange test -race -count=1 \
  -run '^TestRealS3MultipartStore$' -v ./internal/storage
```

Its private JSON uses the same `endpoint`, `access_key`, `secret_key`, and
`region` fields. It creates a fresh versioned bucket and removes only its
owned fixture resources.

The SDK gate starts actual native public/managed/private HTTPS listeners and
the native worker; it creates uniquely owned PostgreSQL/S3 namespaces and
waits for normal transfer-grant drain during cleanup. The retained-state gate
checks Python → Go and Go → Python continuation. Missing fixture configuration
skips these opt-in developer gates; CI supplies it explicitly. Neither gate
proves model quality or qualified sandbox execution.

Private fixture roots can contain credentials, certificates, and ephemeral
tokens; do not publish raw fixture directories as CI artifacts.
