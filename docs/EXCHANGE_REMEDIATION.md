# Exchange review remediation

This records the working-tree changes following the assessment of `8f7fee7`.
The status lines for `9f670c9` in [the original review](EXCHANGE_REVIEW_FINDINGS.md)
remain historical evidence; they do not describe this implementation.

The 43 findings that were open or partial at `8f7fee7` now have the remedies
below. “Addressed” means the reported failure or contract omission has a remedy,
not that every optional enhancement in the original recommendation exists.
The explicitly scoped contracts below are intentional limitations.

| Findings | Implemented remedy and verification |
|---|---|
| F05, F27 | Read snapshots avoid the exclusive space lock; record pages batch blob loading; event visibility and feed types are filtered in SQL before LIMIT. Tests count attachment queries and prove PostgreSQL reads proceed while a writer holds the space lock. |
| F09, F18, F51 | HTTP and worker storage attempts have renewable UUID ownership tokens. Commit/release check ownership; stale attempts cannot overwrite successors. Duplicate completion reports progress; losing initialization aborts only its own MPU. Controlled interleaving tests cover these paths and lease renewal. |
| F11, F12, F20, F22 | SDK tests cover confirmed-part resume without re-PUT, actual multipart negatives, interrupted downloads/integrity failures, unclaimed publication, existing tags, and initialization recovery. Already-failed uploads discard poisoned drafts/state. Upload and verification have separate time budgets. |
| F13, F33 | JWT issuer/type/algorithm and exact error contracts are tested. JWKS uses configurable timeout/cache, serialized key retrieval, outage cooldown and retryable 503. Tests exercise successful JWKS key selection and outage classification. |
| F16, F42 | Fixed-profile rules accept a documented restricted schema subset; compositions cannot indirectly forbid mandatory FedAvg fields. Generic custom kinds retain general local JSON Schemas. Tests cover malformed rules, composition rejection and metadata PATCH schema/CAS validation. |
| F17, F41 | Claim acquisition requires a persisted per-attempt idempotency key. Different jobs using one principal cannot share a fence accidentally; lost responses replay the saved key. Explicit claim resume remains available. Tests cover acquisition recovery, renewal, fencing and expiry. |
| F19 | Released logical allocation becomes pending-deletion allocation and remains charged to the space quota until physical cleanup. Cleanup eligibility is shortened safely using the signed-grant lifetime. Tests verify cancellation/expiry, physical deletion and budget release. Deployment rate limiting remains an operator responsibility. |
| F28 | Added record-expiry and blob-cleanup indexes; work selection excludes active leases before LIMIT and separates pending work from cleanup. Tests exercise starvation prevention on SQLite and PostgreSQL. Production-scale query-plan/load tuning remains deployment validation. |
| F29, F44 | Resource events form a retained pull feed; bounded worker pruning updates cursor-expiry floors. Idempotency operations have creation times and a validated retention window. Per-request audit decisions belong to centrally collected application logs. Tests cover event visibility, paging, expired cursors and operation pruning. Outbound acknowledged delivery is outside this contract. |
| F30, F49 | New memberships retain their subject for administration. Documentation consistently defines spaces as the authorization boundary and tenant as a label. Global identity lifecycle belongs to the IdP, with per-space revocation for already-issued JWTs. Legacy principal hashes require an external roster; there is no tenant-admin or global principal-disable API. |
| F32, F57 | Publication accepts an explicit resolved revision/generation and claim handle; the owner CLI passes them. Tags are preflighted. A later tag failure returns the successfully published revision plus a warning, rather than hiding main publication. Cross-instance and partial-success tests cover these paths. |
| F34, F35, F36 | Separate dependency readiness and liveness; startup tolerates dependency outages. PostgreSQL pool settings and API worker count are configurable. Infrastructure failures carry Retry-After. Tests cover readiness, configuration and environment validation. |
| F37, F62 | Added required exchange CI on SQLite/Moto (Python 3.10/3.12) and PostgreSQL/MinIO. Missing optional dependencies fail in required-test mode. PostgreSQL concurrency and real S3 signature tests passed locally; the new GitHub workflow has not yet run remotely. |
| F38, F39, F40, F61, F64 | Added exact-code authorization matrices, cross-space database-constraint checks, coordinator/private-event visibility, filtered cursor continuation, actual open-MPU cancellation/expiry and SDK recovery-code assertions. Corrected tests that previously overclaimed their exercised behavior. |
| F48, C05 | HTTPS is required for control/data-plane endpoints and consumed grants, with an explicit loopback-only development exception. S3 operations and public signing can use different endpoints addressing the same bucket. Tests cover URL policy and public signer configuration. |
| F50, C06 | Missing uploads/versions and digest failures become terminal record failures with cleanup. Unresolved work has a retry-age bound. Missing/null VersionId is a distinct infrastructure error, preserves completion recovery state and returns `storage_misconfigured`. Tests verify terminal cleanup and misconfiguration preservation. |
| F54, F55 | Distributed lease/expiry decisions use database time; PostgreSQL metadata uses JSONB. Worker item failures are isolated and outage backoff caps its exponent before exponentiation. Tests simulate a long outage and verify repeatable SQLite/PostgreSQL migration. |
| F58, F65, F66, F67 | Corrected the attachment example and console alias documentation. All four keyed routes document and expose required 1–128-character headers. Interactive docs/OpenAPI are disabled by default and explicitly configurable. Tests inspect header schemas and docs settings. |

The other 31 confirmed findings were already addressed at the assessment base:
F01, F02, F03, F04, F06, F07, F08, F10, F14, F15, F21, F23, F24, F25, F26,
F31, F43, F45, F46, F47, F52, F53, F56, F59, F63, F68, C01, C02, C03, C04,
C07. Their regression coverage remains in the full suite. The storage check
also now probes missing-key permissions (C03), and the SDK initialization-wait
branch has direct coverage (C07). F60 remains refuted and is excluded from the
74 confirmed findings.

## Validation and rollout

- SQLite/Moto: 92 tests, successful with one expected live-signature skip.
- PostgreSQL 18/MinIO: 93 tests, successful with no skips, including migration,
  signatures and controlled concurrency checks.
- Tests run with the project `.venv` and `EXCHANGE_REQUIRE_TESTS=1`.

These are local integration results, not production load results or certification
of every S3-compatible provider. Deployment TLS, IAM, IdP availability, log
retention, rate limiting and backup/restore still require operator configuration.

**Existing deployments must stop API/workers, back up the database, run
`hf2l-exchange-service migrate-db`, and then restart.** Schema v2 adds attempt
ownership, physical quota accounting, identity subjects, retention and indexes.
The migration is transactional and repeatable and reconstructs pending-deletion
bytes from legacy terminal records. See [the deployment guide](EXCHANGE_SERVICE.md)
for the complete settings and upgrade procedure.
