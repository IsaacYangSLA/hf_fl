# Repository remediation — 2026-10-08

Validation covered the working tree based on
`38a3d4121b6796cbfdd7f354645157852393a18a`, before committing the changes.
The commands below ran locally on macOS with Python 3.12.10. Database and object
storage fixtures used SQLite and isolated loopback Moto services; no live
provider or model account was used.

## Changes covered

| Change | Regression evidence |
|---|---|
| Automatic and fenced FedAvg validate each client's floating tensors before choosing participants and weights. Invalid inputs are skipped; explicit invalid selections and unsafe global/reduction values still fail. Schema-1 checksum maps are verified when supplied. | [`test_runner_hardening.py`](../../tests/test_runner_hardening.py), existing checkpoint/round suites, and Exchange fenced-round regressions |
| Algorithm parameter comparisons distinguish JSON booleans from numbers while retaining numeric equivalence and object key-order independence. | [`test_json_values.py`](../../tests/test_json_values.py) and runner parameter regressions |
| Manual cyclic download/train/upload handoffs validate immutable predecessors, checkpoint digests, source identity, and bounded lineage. FedAvg rejects cyclic submissions; listeners retain their global FedAvg workflow. | [`test_cyclic_handoffs.py`](../../tests/test_cyclic_handoffs.py), existing workflow/store contracts, and the actual README CLI recipe below |
| SQLite event IDs remain monotonic after pruning. Revision `0002_event_sequence` upgrades the frozen baseline, preserves retained rows and cursor floors, and fails closed for unknown ledgers. | Seven [`test_event_sequence.py`](../../packages/exchange/tests/test_event_sequence.py) regressions and existing migration/application tests |
| JFrog detached submissions and tags reject reserved mutable reference aliases. | [`test_jfrog_revision_safety.py`](../../tests/test_jfrog_revision_safety.py) |
| Python stdout from plugin imports, training, and evaluation is redirected to stderr around plugin calls, preserving command and listener output. | [`test_plugin_output.py`](../../tests/test_plugin_output.py) and listener/CLI suites |
| S3 readiness probes use the configured object prefix and still fail on denied access or disabled versioning. | Four [`test_readiness_prefix.py`](../../packages/exchange/tests/test_readiness_prefix.py) regressions |
| Case-collision fixtures and listener temporary directories support the native macOS filesystem and temporary-path aliases. Production symlink rejection remains enforced. | Protocol, listener, CLI, and authenticated Exchange integration tests under the default macOS temporary directory |

Model cards, current guides, generated schemas, and the FedAvg diagrams were
updated to describe the implemented behavior. Historical validation records
retain their original dates and counts.

## Completed verification

| Check | Result |
|---|---|
| Complete application, numeric, architecture, listener, and legacy suite | 467 executed: 466 passed, 1 expected skip; no errors or failures |
| Complete standalone Exchange suite | 148 executed: 146 passed, 2 expected skips; no errors or failures |
| Combined suite execution totals | 615 executed: 612 passed, 3 expected skips |
| Focused changed behavior, typed protocol, and layering checks before the final runs | 111 passed; subsequent final cyclic suite: 23 passed |
| Actual README cyclic CLI recipe | Builtin LeNet initialized with seed 7; Alice trained 64 synthetic examples and Bob trained 96, one epoch each. Both submissions were detached, Bob used Alice's immutable revision, lineage matched, and global `main` stayed unchanged. |
| Hugging Face publication regressions with isolated minimum `huggingface_hub==0.32.0` | Two passed, including parent-aware preupload filtering and published checkpoint/manifest hash coherence |
| HF2L and Exchange source dependency boundaries | Passed |
| Fresh wheel-installed minimal HF2L core | Passed dependency isolation, actual NumPy aggregation, LocalStore round trip, and core command help entry points |
| Fresh wheel-installed SDK-only and server-only environments | Passed dependency isolation and imports |
| Dependency metadata consistency | Passed in the full environment (108 packages) and fresh core/SDK/server environments (3/8/37 packages) |
| Generated FL and Exchange contracts | All four regenerate byte-for-byte: FL documents, OpenAPI, error inventory, and server environment table |
| Both wheel builds and `twine check` | Passed; all 65 HF2L package, 15 example, and 20 Exchange package Python files are included |
| Whitespace validation | `git diff --check` passed |

Counts are the test runners' execution totals; suites and focused runs share
helpers and scenarios. The final complete suites used the native macOS temporary
directory, without a `TMPDIR` override. An earlier run exposed two shared
Exchange listener fixture paths that still contained `/var` symlink ancestors;
those fixtures were corrected and both complete suites rerun successfully.

The application skip covers live S3 signature enforcement. The Exchange skips
cover live S3 signatures and PostgreSQL row-lock concurrency. Loopback fixture
access was allowed outside the restricted sandbox for these local test runs.

The full environment used NumPy 2.5.3, SafeTensors 0.8.0, Torch 2.14.1,
`huggingface_hub` 2.2.0, FastAPI 0.143.0, SQLAlchemy 2.1.4, HTTPX 0.28.1, and
Moto 5.2.3. The isolated 0.32.0 check covered the two publication regressions;
it was not a repeat of the entire application suite on that older SDK.

## Reproduction

Install the development distributions and extras as documented in the
[current Exchange guide](../EXCHANGE_V3.md#validation-status-and-deployment-limits),
then run from the repository root:

```bash
EXCHANGE_REQUIRE_TESTS=1 .venv/bin/python -m unittest discover -s tests -v
EXCHANGE_REQUIRE_TESTS=1 .venv/bin/python -m unittest discover -s packages/exchange/tests -v
.venv/bin/python scripts/check_hf2l_dependencies.py --mode source
.venv/bin/python scripts/check_exchange_dependencies.py --mode source
.venv/bin/python -m hf2l.cli export-contract --output /tmp/fl-documents.json
.venv/bin/python -m hf2l_exchange.cli export-contract --output-dir /tmp/exchange-contracts
```

The minimal `core`, `sdk`, and `server` dependency checks require separate fresh
environments containing only the corresponding wheel and its declared extras.
The tested root wheel version was `0.1.2.dev16+g38a3d4121.d20261008`; the
standalone Exchange wheel version was `0.1.0.dev0`.

Local evidence logs are retained under `/private/tmp/`:

- `hf2l-remediation-app-tests.log`
- `hf2l-remediation-exchange-tests.log`
- `hf2l-remediation-focused.log`
- `hf2l-remediation-cyclic-cli.log`
- `hf2l-remediation-core-build.log`
- `hf2l-remediation-exchange-build.log`

Built wheels and fresh boundary environments are in
`/private/tmp/hf2l-remediation-wheels`, `hf2l-remediation-core`,
`hf2l-remediation-sdk`, and `hf2l-remediation-server`.

## Verification limits

This run did not exercise PostgreSQL, MinIO, patched SeaweedFS, real Hugging Face
or JFrog accounts, live IAM/STS/IdP integration, production TLS, or Python 3.10.
It does not establish deployment throughput, backup/restore behavior, or
availability under multi-process or multi-node operation. Manual cyclic hops
require caller scheduling; listeners do not orchestrate cyclic or swarm work.
Remaining limits are described in the [current architecture guide](../ARCHITECTURE_V3.md#current-implementation-limitations).
No package, image, or deployment was published.
