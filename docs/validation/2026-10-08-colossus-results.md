# Colossus test results — 2026-10-08

> **Historical record.** Completion below applies to the recorded October 8
> source snapshot and gates. Python 3.10 results, dependency versions, service
> substitutions, development locations, and cleanup describe that run; they do
> not establish current support, environment availability, or regression results.
> The referenced evidence is external task material, not included in this report.
> Consult [current package requirements](../../pyproject.toml) and the
> [Exchange runbook](../EXCHANGE_V3.md) for current installation and validation.

**Status: complete.** All functional compatibility, live-service,
packaging, contract, workflow, and supplemental coverage gates passed.
MinIO used the documented source-build substitution below. No production
source fixes were required during this run. This record implements the
[test plan](2026-10-08-colossus-test-plan.md).

## Source and development location

The workspace parent is `/localhome/local-isaacy/wksp/dev`.
The GitHub repository was cloned on `ipp1-3414` at
`/localhome/local-isaacy/wksp/dev/hf_fl`, with origin
`https://github.com/IsaacYangSLA/hf_fl.git` and HEAD
`38a3d4121b6796cbfdd7f354645157852393a18a`. The uncommitted remediation
changes and regression fixtures were preserved by transferring and verifying
all 240 files in the working-tree snapshot.

The source archive SHA-256 is
`5ebbce450633aea717e17914698273a0850fee29c88bbd2f98f9d27e2d627598`;
its per-file manifest SHA-256 is
`219fbb6602514ab58714519ff5af780e327fc919d240bacf49dca8b01d7d5438`.
The snapshot includes changes beyond the GitHub commit; the baseline commit
alone does not identify the code tested here.

The remote GitHub clone is now the primary development checkout. Subsequent
source and documentation edits are made there. The Mac checkout is no longer
used for development. The initial five compatibility runs used the identical
verified source snapshot in the isolated validation workspace.

## Machine and isolation

- Host: `ipp1-3414`, Linux `7.0.0-31`, x86_64, 20 CPU cores.
- Initial free disk space: approximately 890 GB.
- Native Python: 3.14.4; Python 3.10–3.13 installed separately through `uv`.
- Validation root: `/localhome/local-isaacy/hf2l-validation/20261008-01a11d42`.
- Independent full virtual environments: `envs/full-3.10` through
  `envs/full-3.14`, with CPU Torch and task-scoped caches/logs.
- SQLite and loopback Moto were used for the five compatibility runs.
  `EXCHANGE_REQUIRE_TESTS=1` made Exchange integration dependencies required.
- CPU thread counts were limited for concurrent execution. No GPU validation
  is included.

## Completed Python compatibility matrix

| Python | Application suite | Exchange suite | Passed / skipped | Application / Exchange runner time |
|---|---|---|---|---|
| 3.10.22 | 467 executed; 466 passed, 1 skipped | 148 executed; 146 passed, 2 skipped | 612 / 3 | 103.298 s / 43.275 s |
| 3.11.17 | 467 executed; 466 passed, 1 skipped | 148 executed; 146 passed, 2 skipped | 612 / 3 | 88.702 s / 39.152 s |
| 3.12.15 | 467 executed; 466 passed, 1 skipped | 148 executed; 146 passed, 2 skipped | 612 / 3 | 87.624 s / 39.288 s |
| 3.13.16 | 467 executed; 466 passed, 1 skipped | 148 executed; 146 passed, 2 skipped | 612 / 3 | 86.471 s / 37.932 s |
| 3.14.4 | 467 executed; 466 passed, 1 skipped | 148 executed; 146 passed, 2 skipped | 612 / 3 | 85.518 s / 38.337 s |

All ten suite executions exited successfully with no errors or failures.
These runs total 3,075 executions: 3,060 passed and 15 expected skips.
The two complete suites contain 615 unique test methods. The same methods
repeat across interpreters; 3,075 is the execution count, not the unique count. Timings above are the unittest runners' reported durations, excluding
installation and interpreter startup.

The three skips per interpreter are:

- The application live S3 signature rejection test.
- The Exchange live S3 signature rejection test, because Moto does not enforce
  presigned signatures.
- The Exchange PostgreSQL row-lock concurrency test, because the baseline
  uses SQLite.

Both source dependency boundary scripts and `pip check` passed in all five
environments. Dependency versions were resolved independently; the actual
versions below are compatibility evidence, not a lock file.

| Dependency | Python 3.10 | Python 3.11 | Python 3.12–3.14 |
|---|---|---|---|
| NumPy | 2.2.6 | 2.4.6 | 2.5.3 |
| SQLAlchemy | 2.0.54 | 2.1.4 | 2.1.4 |
| Torch | 2.14.1+cpu | 2.14.1+cpu | 2.14.1+cpu |
| SafeTensors | 0.8.0 | 0.8.0 | 0.8.0 |
| Hugging Face Hub | 2.2.0 | 2.2.0 | 2.2.0 |
| FastAPI | 0.143.0 | 0.143.0 | 0.143.0 |
| HTTPX | 0.28.1 | 0.28.1 | 0.28.1 |
| Moto | 5.2.3 | 5.2.3 | 5.2.3 |

## Completed packaging, contracts, and workflow gates

| Gate | Observed result |
|---|---|
| Both wheel builds and metadata validation | Passed; both wheels built and `twine check` succeeded. `Requires-Python: >=3.10` verified. |
| Wheel source inclusion | All 100 runtime Python files matched source bytes: 80 HF²L/example files and 20 Exchange files. |
| Fresh core environment | Passed with 3 distribution packages; actual NumPy aggregation, LocalStore round trip, entry points, metadata consistency, and import isolation verified. |
| Fresh SDK environment | Passed with 8 distribution packages; SDK import and dependency isolation verified without HF²L/server dependencies. |
| Fresh server environment | Passed with 37 distribution packages; server import and dependency isolation verified without HF²L/ML dependencies. |
| Generated contracts | FL documents, Exchange OpenAPI, errors, and environment table matched all four checked-in files byte-for-byte. Repeated exports from installed wheels also matched. |
| Actual cyclic CLI walkthrough | All three commands succeeded and all 27 assertions passed; builtin LeNet trained Alice on 64 and Bob on 96 synthetic examples, one epoch each. |
| Minimum Hugging Face SDK publication boundary | Both existing publication regression tests passed with `huggingface_hub==0.32.0` imported from its isolated target installation. |

The wheels were built from the remote primary checkout:

```text
hf2l-0.1.2.dev16+g38a3d4121.d20261008-py3-none-any.whl
hf2l_exchange-0.1.0.dev0-py3-none-any.whl
```

The HF²L build used the recorded version override
`0.1.2.dev16+g38a3d4121.d20261008`. Fresh wheel boundary checks ran from
outside the source checkout with Python's isolated `-I` mode. Imports were
verified to resolve inside the corresponding installed environment rather
than through the source tree. All 25 packaging/contract commands exited
successfully.

The actual cyclic CLI run produced these distinct immutable revisions:

| Snapshot | Revision |
|---|---|
| Initial global | `54a3120f04174467a5ec0d3ae116255f` |
| Alice submission | `234a69d9ef68431889e3dfc28da98b07` |
| Bob submission | `cb57567fde4f46cfbda96caa35a34e80` |

Bob trained from Alice's published checkpoint bytes. Both participants changed
their input weights, their manifest digests matched published bytes, and
Bob's context/submission lineage contained Alice as the sole predecessor.
Global snapshot bytes, the `main` reference, and its generation stayed
unchanged. Training progress was routed to stderr.

The 0.32.0 check installed only that SDK into an isolated `--target`
directory and confirmed its actual import path and version before running
`tests.test_cyclic_handoffs.HuggingFaceCyclicPublicationTests`. Base
dependencies remained unchanged. This covers the two publication boundaries;
it is not a full suite or a clean minimum-dependency installation.

The dedicated primary development environment is ready at
`/localhome/local-isaacy/wksp/dev/hf_fl/.venv`, using Python 3.12.15
and the same 109 resolved dependencies as the verified compatibility
baseline. The final environment's `pip check`, source boundaries, command
help, and NumPy checkpoint round trip passed. Both editable distributions'
import paths resolve inside the primary remote clone.

Stable development tools are independent of validation workspace retention:

| Tool | Retained development location |
|---|---|
| `uv` 0.12.23 | `/localhome/local-isaacy/.local/bin/uv` |
| CPython 3.12.15 | `/localhome/local-isaacy/.local/share/uv/python/cpython-3.12.15-linux-x86_64-gnu` |
| Primary virtual environment | `/localhome/local-isaacy/wksp/dev/hf_fl/.venv` |

The primary virtual environment was rebound to that stable interpreter and
rechecked with the verified dependency constraints. Its base interpreter
therefore does not depend on the external validation directory.

## Live PostgreSQL and S3 repeat

Both complete suites passed on Python 3.12.15 with real task-owned services:

| Suite | Executed / passed / skipped | Runner time |
|---|---|---|
| Exchange | 148 / 148 / 0 | 47.440 s |
| Application | 467 / 467 / 0 | 131.088 s |
| Combined live run | **615 / 615 / 0** | 178.528 s combined runner time |

The three service-dependent tests skipped under SQLite/Moto executed
successfully here, including presigned signature rejection and PostgreSQL
row-lock concurrency. The five baseline matrix runs plus this live repeat
total 3,690 full-suite executions: 3,675 passed and 15 expected baseline
skips, covering the same 615 unique test methods.

### Service identity and plan deviation

PostgreSQL reported `18.6 (Debian 18.6-1.pgdg13+2)`, using the exact CI
image:

```text
postgres@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280
```

The planned MinIO Quay image could not be pulled: registry manifest requests
returned `401 UNAUTHORIZED`. Anonymous-registry and documented image
alternatives also failed. To complete the functional S3 gate, MinIO was built
from the official source release `RELEASE.2025-10-15T17-29-55Z`, commit
`9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a`, with Go 1.24.8. The cloned
source remained unchanged; a 1,363-file source hash manifest was retained.

This local source build is a documented substitution for the unavailable
pinned registry artifact. That official container artifact was not tested.

| MinIO artifact | Observed identity |
|---|---|
| Runtime version string | `DEVELOPMENT.GOGET`, commit `9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a`, Go 1.24.8 linux/amd64 |
| Local image SHA-256 | `6160917425ed44632567966e3638b8fb0b0414a7c8739178e4dd22c27cc76988` |
| Binary SHA-256 | `cb8d50e1c12494feb77e76432c284775aac6c95c2da93f910d658aa18820c992` |
| Source manifest SHA-256 | `97ef602199bc56d26d584de4e81af8104d087f02740db640dacad6d97e657d88` |

Services published only on loopback: PostgreSQL port 32769 and MinIO port
32770. Both had 2 CPU / 2 GB memory limits; MinIO also had a 256-process
limit. Readiness was checked before execution. Tests used synthetic
credentials, per-test PostgreSQL schemas, and versioned buckets.

Both task-owned service containers and both anonymous data volumes were
removed after execution. Container and volume absence was verified. Service
images, source/build artifacts, and evidence logs were retained for
reproduction.

## Supplemental coverage measurement

This gate was added during execution to assess the Linux test coverage. It
repeated both full suites under Python 3.12.15 with Coverage.py 7.16.2,
using the primary remote checkout. All 615 executions completed: 612 passed
and the same three SQLite/Moto service-dependent skips were expected.

| Production package | Line coverage | Branch coverage |
|---|---|---|
| HF²L | 89.33% (5,319 / 5,954) | 77.82% (1,589 / 2,042) |
| Exchange | 90.71% (2,930 / 3,230) | 75.90% (756 / 996) |
| Combined | **89.82% (8,249 / 9,184)** | **77.19% (2,345 / 3,038)** |

Line coverage divides covered executable lines by executable statements.
Branch coverage divides covered branch destinations by possible branch
destinations. These figures combine unit and integration execution over 85
production package files, including inherited Python subprocess execution,
crash-exit handling, and SIGTERM capture. Tests, example files, scripts, and
external dependencies are excluded. Coverage combined 24 runtime databases;
the measurement is not an isolated pure-unit coverage claim.

The built-in LeNet and VGG plugin modules remain the weakest areas in the
instrumented suites: 26.98% and 25.71% line coverage, respectively. The
separate actual LeNet cyclic walkthrough above was not included in this
coverage collection. Meaningful branch gaps remain in Exchange application
rejection paths, the HF²L Exchange adapter, and transfer failure handling.
The measurement does not add a CI coverage threshold.

The initial instrumentation attempt used an incorrect environment variable
for the coverage configuration path; it produced no coverage databases and
was excluded. The corrected run uses `COVERAGE_PROCESS_START`, with
subprocess and crash collection configured in the retained `coverage.ini`.
Coverage tools and their startup hook were installed in the external
validation artifact directory; the production source and development
dependency environment were not changed by the measurement.

Across the five compatibility runs, live-service repeat, and supplemental
coverage repeat, there were 4,305 full-suite executions: 4,287 passed and
18 expected SQLite/Moto skips. These are repeated executions of the same
615 unique test methods. The two minimum-SDK publication reruns and the
27 CLI assertions are separate focused evidence, not additional unique
suite methods.

## Completion and cleanup

All planned gates and the added coverage measurement have observed passing
outcomes. The remote GitHub clone, stable tools, and primary development
environment are ready. Task-owned PostgreSQL/MinIO containers and data
volumes were removed and their absence verified. Source snapshots, built
wheels, MinIO build artifacts/images, coverage reports, environments, and
logs remain in the external validation directory as evidence.

The repository's `git diff --check` and explicit whitespace checks for
both new validation documents passed. Historical validation records were
preserved. No commit, package publication, model publication, or deployment
was made.

## Evidence and reproduction

All evidence paths below are on `ipp1-3414` under the validation root:

- `results/python-3.10.json` through `results/python-3.14.json`: exact
  commands, exit codes, step durations, and resolved interpreter versions.
- `logs/python-<version>/application.log` and `exchange.log`: complete
  suite output, including executed totals and skip reasons.
- `logs/python-<version>/freeze.log`: actual dependency inventories.
- `logs/python-<version>/pip-check.log` and
  `source-boundary-{hf2l,exchange}.log`: metadata and source isolation checks.
- `results/source-identity.json` and `development-checkout.json`:
  source transfer and primary GitHub clone identity.
- `artifacts/hf2l-colossus-source.tar.gz` and
  `hf2l-colossus-source-manifest.json`: source archive and per-file SHA-256s.
- `tools/run-version.py`: compatibility-run driver.
- `results/wheel-contracts.json` and `logs/wheel-contracts/`: packaging,
  source-byte inventory, fresh environment checks, contract hashes, and logs.
- `artifacts/wheels/`: built wheels; `envs/{core,sdk,server}-3.12/`:
  fresh wheel boundary environments.
- `results/cyclic-smoke.json`, `logs/cyclic-smoke/`, and
  `artifacts/cyclic-smoke/`: commands, 27 assertions, contexts, manifests,
  model snapshots, and separate stdout/stderr logs.
- `results/hf-minimum-0.32.json` and `artifacts/hf-minimum-0.32/`:
  SDK import identity and the two publication regression results.
- `results/development-env.json`, `stable-development-tools.json`, and
  `logs/development-env/stable-rebind/`: final primary editable installation,
  dependency constraints, stable interpreter placement, and rechecks.
- `results/live-services.json` and `logs/live-services/`: exact fixture
  identities, readiness, all 615 live tests, runtime versions, and verified
  container/volume cleanup.
- `artifacts/minio-build/`: unchanged official source checkout, file
  manifest, build context, and source-built MinIO binary.
- `results/coverage.json` and `logs/coverage/`: coverage methodology,
  test totals, package metrics, and the corrected instrumentation run.
- `artifacts/coverage/coverage.json`, `coverage.ini`, and
  `html/index.html`: detailed coverage data, configuration, and HTML report.

The full suites used each selected environment's interpreter with:

```bash
EXCHANGE_REQUIRE_TESTS=1 <venv>/bin/python -m unittest discover -s tests -v
EXCHANGE_REQUIRE_TESTS=1 <venv>/bin/python -m unittest discover -s packages/exchange/tests -v
<venv>/bin/python -m pip check
<venv>/bin/python scripts/check_hf2l_dependencies.py --mode source
<venv>/bin/python scripts/check_exchange_dependencies.py --mode source
```

Use the [test plan](2026-10-08-colossus-test-plan.md) for installation,
live-service variables, and all gate descriptions. The JSON evidence files
contain the exact commands used, including resolved task paths and versions.

## Verification limits

The completed matrix establishes the tested Linux CPU/dependency combinations
for Python 3.10–3.14. It does not establish newer Python versions, GPU
execution, sustained load, distributed throughput, multi-node availability,
production IAM/STS/IdP integration, real Hugging Face or JFrog publication,
production TLS, or backup/restore behavior. The S3 result covers the recorded
MinIO source build; the unavailable pinned MinIO registry image was not
validated. No package or deployment has been published.
