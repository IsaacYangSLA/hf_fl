# Colossus test plan — 2026-10-08

## Objective and scope

Execute the current HF²L working tree on the available `ipp1-3414` machine,
covering the declared Python `>=3.10` requirement, Linux behavior, real
PostgreSQL and S3 service boundaries, installed distribution isolation, and
the documented manual cyclic workflow. This plan supplements the
[macOS remediation validation](2026-10-08-repository-remediation.md) and the
[existing CI workflow](../../.github/workflows/exchange_tests.yml).

Results will be recorded separately in
[`2026-10-08-colossus-results.md`](2026-10-08-colossus-results.md), with actual
commands, versions, execution totals, failures, fixes, and remaining limits.
Expected totals below are acceptance criteria, not completed results.

## Execution environment

| Item | Initial observation or intended setup |
|---|---|
| Machine | `ipp1-3414`, accessed through the existing SSH route |
| OS | Linux, kernel `7.0.0-31`, x86_64 |
| CPU and disk | 20 CPU cores; approximately 890 GB available disk space at preflight |
| Native interpreter | Python 3.14.4 |
| Other interpreters | Separate `uv` managed CPython 3.10, 3.11, 3.12, and 3.13 installations; record resolved patch versions |
| Containers | Docker 29.1.3 through the existing `sudo -n` permission |
| GPU | No `nvidia-smi` executable observed; all planned ML checks use CPU |
| Task directory | `/localhome/local-isaacy/hf2l-validation/20261008-01a11d42` |

Use a snapshot of the current local working tree, including uncommitted source
and new regression tests and binary golden fixtures. Hash the transferred
files and verify those hashes remotely before installation. Initialize an
isolated Git checkout for source layering checks and SCM versioning. Record
the source baseline and snapshot fingerprint rather than implying that the
uncommitted remediation has a published commit.

During execution, the user designated the remote machine as the primary
development environment. The repository was cloned from GitHub at
`/localhome/local-isaacy/wksp/dev/hf_fl`, and the verified snapshot changes
were preserved there. New source and documentation edits are made in this
remote clone. The isolated validation workspace remains the evidence and
environment location; the Mac checkout is no longer used for development.

Create separate virtual environments and logs for each interpreter. Limit
Torch, OpenMP, MKL, and OpenBLAS CPU threads so independent runs do not
oversubscribe the machine. Record each environment's dependency versions and
`pip check` result. Resolve dependencies from package metadata without
silently pinning around a failure; investigate and record any required fix.

All databases, buckets, credentials, temporary files, and containers belong
to this validation task. Publish service ports only on `127.0.0.1`, using
available task-specific ports. Use synthetic local credentials. Tests already
create per-test database schemas and versioned buckets. Do not reset or
modify existing machine projects or services. Remove the task's service
containers after execution and retain source snapshots, manifests, and logs
as evidence.

## Test matrix

| Gate | Environments | Execution and acceptance criteria |
|---|---|---|
| A. Full application regression | Python 3.10, 3.11, 3.12, 3.13, and 3.14 | Run every test under `tests` with Exchange dependencies required. Include numerical goldens, protocol validation, dependency layering, plugin diagnostics, listeners, cyclic lineage/tampering, publication safety, and legacy compatibility. No failures or errors. Baseline: 467 executed, 466 passed, one live-S3 skip. |
| B. Full Exchange regression | The same five interpreters | Run every test under `packages/exchange/tests` against SQLite and loopback Moto. Include migration/event cursors, readiness prefix, API permissions, multipart transfers, workers, recovery, contracts, and SDK behavior. No failures or errors. Baseline: 148 executed, 146 passed, live-S3 and PostgreSQL concurrency skips. |
| C. Live service regression | Python 3.12; PostgreSQL 18 and MinIO | Repeat both complete suites with `EXCHANGE_TEST_DATABASE_URL` and `EXCHANGE_TEST_S3_ENDPOINT`. Verify that signature rejection and row-lock concurrency tests execute. Target: all 615 baseline tests pass with none of the three service-related skips. |
| D. Distribution and dependency boundaries | Fresh Python 3.12 core-only, SDK-only, and server-only wheel environments | Build both wheels, inspect package contents, run `twine check`, and check distribution metadata. Install each supported boundary independently; run dependency isolation scripts and `pip check`. Exercise actual NumPy aggregation, LocalStore round trip, imports, and command help entry points where applicable. |
| E. Generated contracts | Python 3.12 full environment | Regenerate FL documents, Exchange OpenAPI, error inventory, and environment table into task-owned output directories. All four must match the checked-in artifacts byte-for-byte. |
| F. Actual cyclic CLI walkthrough | Python 3.12 full environment, LocalStore, builtin LeNet | Initialize with seed 7; train Alice on 64 synthetic examples and Bob on 96, one epoch each. Bob downloads Alice's immutable submission using the documented cyclic flags. Verify output checkpoint hashes, source participant, predecessor lineage, detached revisions, and unchanged global `main`. Check command output and plugin diagnostics use their intended streams. |
| G. Minimum Hugging Face SDK regression | Isolated Python 3.12 environment with `huggingface_hub==0.32.0` | Execute the two publication boundary regressions, including parent-aware preupload filtering when output weights match `main` and published checkpoint/manifest hash coherence. No provider account or publication is needed. |
| H. Final evidence and cleanup | Task directory and remote checkout documentation | Record actual interpreter/dependency/service versions, image digests, test counts and skip reasons, timings, snapshot identity, artifact/log locations, fixes, and cleanup status. Run whitespace validation on repository edits. |

## Supplemental gate added during execution

After the initial plan, add a Linux line and branch coverage measurement to
quantify the coverage discussed in the repository review. Repeat both full
suites under Python 3.12 in the primary remote development environment,
capturing inherited Python subprocesses and crash exits. Collect only
production HF²L and Exchange packages; exclude tests, examples, scripts, and
external dependencies. Install instrumentation tools and save all coverage
data, configuration, and reports outside the development checkout.

Record package-level covered/possible lines and branches, coverage tool
version, collection scope, execution counts, expected skips, and meaningful
remaining gaps. Treat this as a measurement, with no new coverage threshold.
These repeats do not increase the count of unique test methods.

## Commands and service configuration

For each complete environment, install CPU Torch and the two local
distributions with their regression dependencies, following CI:

```bash
python -m pip install --upgrade pip
python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
python -m pip install -e './packages/exchange[server,test]' \
  -e '.[torch,hf,examples,exchange,service,exchange-test,build]'
python -m pip check
EXCHANGE_REQUIRE_TESTS=1 python -m unittest discover -s tests -v
EXCHANGE_REQUIRE_TESTS=1 python -m unittest discover -s packages/exchange/tests -v
```

Each command uses the selected virtual environment's interpreter and records
its output and exit status separately. `EXCHANGE_REQUIRE_TESTS=1` prevents
missing optional dependencies from turning required Exchange integration
tests into silent skips. An interpreter installation or dependency resolution
failure is reported as a blocked gate until corrected; it is not counted as a
successful regression run.

Use the immutable service images already specified in CI:

```text
postgres@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280
quay.io/minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e
```

Wait for `pg_isready` and MinIO's readiness endpoint before the live run. Set
these environment variables using the actual allocated loopback ports:

```text
EXCHANGE_REQUIRE_TESTS=1
EXCHANGE_TEST_DATABASE_URL=postgresql+psycopg://hf2l_test:local-test-only@127.0.0.1:<postgres-port>/hf2l_test
EXCHANGE_TEST_S3_ENDPOINT=http://127.0.0.1:<minio-port>
AWS_ACCESS_KEY_ID=hf2l-local-test
AWS_SECRET_ACCESS_KEY=local-test-only-password
AWS_DEFAULT_REGION=us-east-1
```

Run the live application and Exchange suites sequentially against these
services to keep the evidence attributable. Preserve container readiness
checks and image IDs in the service log.

Distribution and contract commands include:

```bash
python -m build --wheel --outdir <task-wheels> .
python -m build --wheel --outdir <task-wheels> packages/exchange
python -m twine check <task-wheels>/*.whl
python scripts/check_hf2l_dependencies.py --mode source
python scripts/check_exchange_dependencies.py --mode source
python scripts/check_hf2l_dependencies.py --mode core
python scripts/check_exchange_dependencies.py --mode sdk
python scripts/check_exchange_dependencies.py --mode server
python -m hf2l.cli export-contract --output <task-contracts>/fl-documents.json
python -m hf2l_exchange.cli export-contract --output-dir <task-contracts>/exchange
```

The `core`, `sdk`, and `server` checks run in their corresponding fresh wheel
environments, not the full development environment. Place all output paths
inside the task directory. Run the cyclic recipe from the current
[training guide](../TRAINING_GUIDE.md#cyclic-federated-learning-without-fedavg), recording the
actual immutable revisions instead of copying an example revision.

## Completion criteria and limits

The plan is complete when each gate has an observed outcome, failures have
been diagnosed and any authorized repository fixes retested, evidence is
saved, and task service containers are removed. Report unresolved gates
explicitly, with their causes and practical effect.

This is functional compatibility and integration validation. It does not
measure GPU execution, distributed training throughput, sustained load,
multi-node availability, production backup/restore, IAM/STS/IdP integration,
or real Hugging Face and JFrog accounts. MinIO checks exercise a real S3 HTTP
implementation with local credentials. The minimum Hugging Face SDK check
uses deterministic publication boundary fixtures; it does not publish to a
remote model repository. Python versions newer than those listed here are
not established by this run.
