# Multi-job implementation validation

**Date:** 2026-10-09

**Status:** CPU v1 implementation and required validation completed for the tested scope; provenance and limits below.

Development and tests run on the Linux development host. The Mac is a control client and artifact viewer. Source changes remain uncommitted during validation.

## Environment and provenance

- Primary source checkout: `/localhome/local-isaacy/wksp/dev/hf_fl`.
- Validation artifacts: `/localhome/local-isaacy/hf2l-validation/20261009-jobs`.
- GitHub baseline: `38a3d4121b6796cbfdd7f354645157852393a18a`, with the implementation's working changes.
- Host: `ipp1-3414`, Ubuntu 26.04.1 LTS x86_64, kernel `7.0.0-31-generic`.
- Confirmed control-plane test interpreter: Python 3.12.15.
- Live PostgreSQL: 18.6, Debian `18.6-1.pgdg13+2`, normal READ COMMITTED isolation.
- CPU runtime installation pins official gVisor release `20261005.0`; actual isolation qualification is recorded separately.
- Completed-FL source freeze v2: `final-source-freeze-v2.json`, 144 source files; record SHA-256 `9eeb2809bf32f916f5f8f85eb30cccfd77deae774c810f44e360e3f10d8e8acc`. It changes only `participants.py` from the preserved earlier `final-source-freeze.json` (record SHA-256 `ee2f1ebbb7b895d9a902085c3e841ed2ba501a290a85736612b45b1ae0165bd2`), fixing confirmed stop-receipt/event transaction races. Completed managed-node/autonomous participant FL gates use v2.
- Proxy follow-up source freeze v3: `final-source-freeze-v3.json`, 144 files; record SHA-256 `56ff81742feecbf6f9516678f5ca9a2a0894bd134c2a4c8e84fd531556fa33e7`. Its sole additional change is `execution_proxy.py`, covering controlled credential-provider denial/service responses. Targeted affected/HTTPS tests cover that delta.
- Final delivery source freeze v4: `final-source-freeze-v4.json`, 144 files; record SHA-256 `439b58fcc97ed6ad85ae4a791da8fc4b15f4ff7cb9256b1c67b29c137904aae0`. Its sole additional deltas are strict-compatible client certificate issuance in `certificates.py`, `execution_proxy.py`, and `managed_client.py`. Actual strict mTLS follow-ups cover those paths; final updated-wheel matrix uses v4. Documentation updates do not mutate production source.

## Completed live control-plane gates

| Suite | Executed | Passed | Skipped | Duration |
| --- | ---: | ---: | ---: | ---: |
| ManagerHTTPIntegrationTests | 11 | 11 | 0 | 12.307 s |
| PostgreSQLConcurrencyTests | 9 | 9 | 0 | 7.035 s |

The manager HTTP suite uses actual loopback HTTPS OIDC discovery, RS256 JWKS validation, S256 PKCE authorization-code exchange, and introspection. Manager requests use HTTPS ASGI clients; its unbuffered SSE gate uses an actual loopback HTTPS Uvicorn server.

Verified controls include ACL enforcement before queue/history/search/counts/pagination, foreign-job 404 responses, durable idempotency and optimistic versions, last-admin safety, bearer/session verification, CSRF origin/state/nonce checks, one-use callbacks, provider revocation/online checks, absolute session expiry, no platform-role content bypass, restrictive response headers, and authenticated stream reconnect/recheck.

The PostgreSQL suite runs four races using two independent processes each. It verifies pool/gang admission locking, project running-job quotas, exclusive GPU ledger constraints, bounded backfill and unrelated-pool progress, transaction rollback of allocation/epoch/deadline/outbox, quarantine accounting across controllers, stale-epoch callbacks, and one live component assignment. GPU checks cover bookkeeping only.

Evidence:

- `system-results.json`, `system-logs/http-postgres-final.log`.
- `system-concurrency/results.json`, `system-concurrency/logs/final.log`.
- No owned test schemas remained after either suite.

These are control-plane gates. Historical job fixtures are seeded transactionally, and fixture termination/revocation flags are simulated. They do not establish actual FL execution, sandbox isolation, physical GPU isolation, or executor-confirmed termination.

An initial fixture run lost its Docker bridge forwarder while the dedicated runtime was being initialized. The fixture owner recovered only its task-owned services on a dedicated bridge; final passing logs are separate from that failed infrastructure attempt.

The staged current-schema gate passed **21 tests** (12 actual TLS/API/SSE plus nine PostgreSQL races), zero failures/errors/skips, in 20.620 seconds on Python 3.12.15. It adds authenticated default-quorum rejection for zero/one participants before any durable job/attempt/allocation/resource is created. Evidence: `system-results-current-schema.json` and `system-logs/http-postgres-current-schema.log`; source hashes and absence of owned schemas are recorded. The earlier 20-test, 20.756-second rerun remains in `system-results-current-schema.json.pre-quorum`. An initial stdin multiprocessing runner had four import-entrypoint harness errors; the corrected importable runner and failed logs are retained. These repeated gates are not additional distinct tests to add to the final aggregate.

The latest recorded control-plane gate passed **21 tests** (12 actual HTTPS/OIDC/API/SSE and nine actual PostgreSQL 18.6 concurrency tests), zero failures/errors/skips, in **22.049 seconds** on Python 3.12.15. Evidence: `system-results-final-freeze.json` and `system-logs/http-postgres-final-freeze.log`; test source hashes and no remaining owned schemas are recorded. Its scope remains control-plane validation, separate from the runtime jobs below.

## Dashboard gate

The expanded packaged UI gate passed 10 tests in 19.253 seconds: two static security checks, six focused Chromium interactions, and two actual SQL/FastAPI HTTPS integration scenarios. Verified flows include real job creation persistence, ACL concealment, CSRF and Secure/HttpOnly sessions, attempt-filtered bounded logs with plaintext XSS rendering, trusted artifact locators and attachment bytes, membership changes/cancellation, stream ACL/session revocation, external participant enrollment/status, and artifact pagination/unavailable-state rendering. Identity is synthetic and the manager/database/API are real; these fixtures do not run FL training or qualify runtime isolation.

Evidence is retained separately under `/localhome/local-isaacy/hf2l-validation/20261009-jobs-dashboard`: `final-browser.log` and desktop/mobile detail plus real-API queue screenshots.

## CPU isolation and bounded source-fetch gates

The actual gVisor qualification passed **197 of 197 checks** in `runtime-qualification/run-006/qualification.json`. These are runtime assertions, not 197 additional unit test methods. It used Docker 29.1.3 with cgroup v2/systemd, official `runsc release-20261005.0`, a separately owned Docker/containerd daemon in a private network namespace, and the approved Python base image `sha256:2e3f788256a7e2abe86eb972dd72d7bcdf4273f5d775817d2e3619170852559b`.

Verified boundaries include concurrent private source/state/cache/log roots; read-only source/runtime; denied host, foreign-job, process, runtime-socket, abstract Unix socket, and network access; own versus foreign proxy access; CPU throttling; bounded disk/tmpfs/I/O; PID and OOM containment. The PID-exhausted sacrificial job terminated while its sibling remained usable; graceful `EAGAIN` is not claimed. The OOM sacrificial job exited 137 while its sibling remained usable.

The qualifier recorded no remaining owned containers or cleanup failures. `runtime/setup-verification.json` confirms publication of a separate executor profile, status calls preserving that profile, and rejection of failed qualification reports or runtime reinstall while owned services run. The owned daemon remained available for the subsequent FL acceptance gates; final job-resource inventory and intentionally retained runtime/services are recorded below.

Runtime provenance:

```text
runsc SHA-256:
210b437a9cfae51e8f8c9074ed19b8b5e59477178e2e391a18117d8d6b924f7a

executor-profile SHA-256 at publication:
18248e96fff90eeb5b4c5946267864b3bd62595c4eef3454f58d466c9332f717
```

The 197 checks qualify the tested CPU runtime policy. The final HF²L worker image's package/training smoke and complete managed FL job tests are separate gates; the report does not claim those checks ran on every image.

A real public-HTTPS fetch of the pinned baseline produced 230 regular files, 3,112,187 source bytes, and no Git history in 2.175 seconds. Its receiver was limited to 8 MiB with a 512 MiB Git address-space limit and 120-second CPU limit. No fetch workspace remained. Evidence: `/localhome/local-isaacy/hf2l-validation/jobs-security-fetch-20261009/https-fetch-proof.json`. Fetching proves bounded source materialization, not job training.

The final streamed fetch repeated the pinned public source gate in 2.358 seconds: 230 files, 3,112,187 logical bytes, and 3,878,912 filesystem bytes. Git commit/tree/blob hashes were verified, extraction chunks never exceeded 64 KiB, the 8 MiB temporary workspace was empty after cleanup, and no Git directory entered the snapshot. Evidence: `/localhome/local-isaacy/hf2l-validation/20261009-jobs-security/https-streamed-fetch-proof.json`; source module SHA-256 `02cb623df51746a7ec804f21df27fed35749ace0f2281f5f2ac4763dc34e3dbb`. The operator's bounded Git preparation process and tmpfs receiver are separate from qualified worker cgroup memory limits.

## Supplemental backing-device I/O and production adapter

The additional qualification bundle passed **23 assertions**, separate from the original 197 CPU isolation assertions. Two actual gVisor runs at 8 and 16 MiB/s read four distinct, uncached 64 MiB inputs: source, dataset, build products, and a private immutable image layer. At the production cap, observed throughput was 15.978–16.002 MiB/s, kernel `io.stat` recorded exactly 268,435,456 read bytes, and the sibling continued with 161 heartbeats.

Five production `LinuxExecutor` assertions verified the promoted profile, actual Docker read/write limits for private loop and `/dev/sda` backing devices, refusal of unsupported `/dev/shm` backing, fixed worker command/runsc/network policy, and owned loop/container cleanup. This adapter probe deliberately used a base without the worker and exited 1; it is not a successful FL job.

The physical device identity is fixed by sysfs provenance (`/dev/sda`, `8:0`). Cached page reads are memory accesses; these limits cover actual backing block I/O. Unsupported or nonblock-backed input paths fail closed.

Evidence: `readonly-io-qualification/summary.json`, SHA-256 `635a7a87d95df2d54720430dd75b293f4df4a00d0fbe684b13b55463a75d645f`. Its report list preserves the passing probes and earlier harness failures. The promoted executor-profile SHA-256 is `7b4383123b3bbc58c086ae922978bb40f178d93991af941c62aa233812d8665f`.

One early derived-image cleanup accidentally pruned the then-untagged worker parent. The final probe cleanup used `--no-prune`, removed only its own images/input bytes, and recorded cleanup. Worker restoration and the final pinned image are a separate packaging gate; completed earlier image-smoke evidence remains an intermediate result.

## Reusable I/O qualification and profile republication

The repository command `deploy/jobs/runtime/qualify_readonly_io.py` repeated the actual backing-I/O/adapter gate: **23 assertions passed**, plus three negative admission checks for outside-root paths, traversal, and mutable image references. It atomically promoted the executor profile only after all probes and owned cleanup passed, retaining the original 197-check isolation evidence.

The final run read exactly 268,435,456 physical bytes per rate test. At 16 MiB/s its four inputs measured 15.977–16.001 MiB/s, and its sibling completed 162 heartbeats; the 8 MiB/s sibling completed 320 heartbeats. No synthetic input bytes, canary containers, or derived probe image remained. The approved parent image remains intentionally pinned for operator reuse.

Evidence: `readonly-io-reproducible/readonly-io-f47e82eb8843/qualification.json`, SHA-256 `31e9e73255a55e1796d048f0462a6bd0cdfcf6ffdfc283ce223f738d85f74cf0`. These are repeated qualification assertions, not 23 additional distinct unit tests.

The executed qualifier SHA-256 is `a5abd443bb896a60fd7f3a82804979e4419d9924ff8750a814a522fd85407472`; delivered source is `c91ac136fba4dc14d21d46df29c7449be0a7245cf6ff99b9de45d2be23c28608`. Appending one LF at EOF to delivered bytes exactly reproduces the executed hash. Evidence: `readonly-io-reproducible/qualifier-source-normalization-proof.json`; executable source bytes are identical.

The profile publisher subsequently preserved the hash-verified supplemental proof during actual republication. Its 14 focused regression tests passed; corrupt proof is rejected without overwriting the active profile, and a changed runtime clears supplemental admission until requalification. Evidence: `readonly-io-reproducible/profile-republish-proof.json`; the republished profile SHA-256 is `2acec4d73e521f441daf1c68fb15a8ad2ccccf58f69ccfa94ea9cb468ba5b49e`.

## Administrative migration and policy history

The administrative audit foundation suite passed **46 tests, zero failures/errors/skips**, in 3.141 seconds. It includes four actual PostgreSQL 18.6 migration preservation, rollback, index, and ordering tests. Migration `0003_administrative_audit` adds durable append-only policy history separate from project/pool rows.

Snapshots omit credentials, tokens, source contents, and host paths. Large approved arrays are represented by count and exact SHA-256. Project creation/update and pool mutation owners write the sanitized audit in the same transaction as the policy change.

Evidence: `admin-audit/results.json` and `admin-audit/final-tests.log`; the JSON records implementation/test hashes. These suite counts overlap tests eligible for the final aggregate and must not be added to it as distinct additional tests.

## Actual sandbox publication recovery and credential isolation

`managed-failures/managed-publication-failures.json` records four actual initialization-worker executions through assigned Unix proxies, mTLS, Exchange/PostgreSQL, and S3. It uses the qualified gVisor policy and worker image `sha256:b85dd5e40686f70f487d270a37ae977860a647426a0860063f804b588c5432fb`.

- Accepted initial-model publication with a lost acknowledgement exited with uncertainty (4). A fenced successor resolved the actual published blob hashes and exited 0 without reinitialization or changing `main`; exactly one initial model was published.
- An unknown initial publication exited 4 twice across fenced attempts and did not replay. Its publication-attempt count remained unchanged.
- Retained manifest and checkpoint hashes stayed identical across those attempts.
- Foreign-job paths and caller-supplied credentials were rejected at the execution Unix proxy. A copied job JWT with another execution certificate returned 401; an own certificate-bound token could not access another job's space.

All owned containers, volumes, test schema, and bucket were cleaned. This gate validates initialization recovery and credential isolation with real sandbox workers. It does not claim complete FedAvg training or two completed concurrent jobs; those remain a separate live gate.

## Independent security and artifact integration

The independent acceptance suite passed **40 tests, zero failures/errors/skips**, on Python 3.12.15 with bounded-source quota tests enabled. It exercises current job ACLs, source execution restrictions and limits, artifact path/locator confinement, actual node mTLS identity forwarding, and verified attachment delivery. Its fixtures include real filesystem and TLS boundaries; this suite is separate from complete FL training and the runtime isolation qualifier.

Evidence: `/localhome/local-isaacy/hf2l-validation/20261009-jobs-security/security-artifact-acceptance.json` and its matching `.log`. The JSON records the tested implementation and test-file SHA-256 values.

The final focused security revalidation passed **35 tests**, zero failures/errors/skips, in 3.607 seconds. It covers real SQL ACLs, actual TLS certificate boundaries, SHA-1/SHA-256 Git object verification, tmpfs quotas, descriptor extraction, and physical source storage. Evidence: `/localhome/local-isaacy/hf2l-validation/20261009-jobs-security/security-source-storage-acceptance.json` and matching log. Implementation/test hashes remained unchanged during this run.

The independent external-contract review passed **140 tests**, zero failures/errors/skips, in 30.625 seconds: 94 participant, 20 cleanup, and 26 build-delivery cases. It verifies current grants/CSRs/dispatch, actual TLS proxy boundaries, private cleanup, and opaque wheel transfer. Its runtime fixtures are deterministic and do not establish actual remote federated training. Evidence: `/localhome/local-isaacy/hf2l-validation/20261009-jobs-security/external-participant-security-review.json` and matching log. These counts overlap the final aggregate and earlier owner suites.

## Participant stop-receipt concurrency follow-up

The final participant follow-up passed **158 focused executions**, zero skips: 105 participant unit tests in 24.523 seconds, seven actual PostgreSQL concurrency tests in 6.617 seconds, 20 cleanup tests in 5.188 seconds, and 26 build-transfer tests in 3.841 seconds. These overlap earlier participant cohorts and are not additional unique tests to sum into the final package aggregate.

Two real PostgreSQL connections at READ COMMITTED exercise concurrent participant stops/controller events and bootstrap/dispatch overlapping a committed stop. Exact receipt replay adds no event or timestamp change; a replay changing `never_started` is rejected with `external_stop_receipt_immutable`. Evidence: `results/external-stop-lock-participant-postgres.json` and matching log, plus `/localhome/local-isaacy/hf2l-validation/20261009-jobs-security/external-stop-lock-participants.json` and matching log. The final `participants.py` SHA-256 is `9814ea785740b20039faa4e39793b8fb3ecc866f4ab4a549dd27be0ee4ba013b`. This is a control-plane/cleanup/build regression gate, separate from autonomous participant FL.

## Versioned Exchange object-budget gate

The frozen blob-budget acceptance passed **22 tests**, zero failures/errors/skips, in 5.669 seconds: 20 budget/ownership/quota/queue/cleanup cases and two actual PostgreSQL/MinIO HTTP cases. Real managed fixed-issuer JWTs and the trusted backend channel verify pending/committed namespace and per-principal hard caps, neighboring namespace denial, and unchanged legacy RSA authentication.

Terminal compute release preserves the Project and separate object-store Pool allowance. Retirement with `cleanup_pending: true` keeps it charged while S3 versions physically exist; the existing Exchange worker deletes owned versions, and an authoritative `cleanup_pending: false` read releases it exactly once. Unknown namespace-create acknowledgements must adopt the original stable request and retire its owned namespace before release.

Evidence: `blob-budget/acceptance.json` and matching `.log`; blob module SHA-256 `85599de430149a4bfdc403795837525f5cba0fe9d693f484cf7e234bf77ba2b4`. The fixtures confirm owned schema/bucket cleanup. This validates the object-store accounting/authentication boundary; fresh complete Manager/Provisioner/runtime integration remains a separate gate.

The operator enrollment contract also passed **18 CLI tests**, zero failures/errors/skips, in 3.281 seconds using actual PostgreSQL and a temporary versioned S3 bucket. It verifies successful readiness, suspended-versioning rollback without policy/audit mutation, approved ceilings/current-usage floors, immutable backend identity, duplicate registrations, and rejection of generic pool reclassification. Source hashes remained unchanged. Evidence: `cli-object-store-stage/focused-results.json`.

## Approved worker image build and smoke

The intermediate offline image build produced `sha256:ab453cfe297793ba37d2b1fb403ed0cbcca9f95609953464f5db6ad11c234d26` from the approved base. Its recorded interpreter is CPython 3.14.5 with Torch 2.14.1+cpu. Hash-pinned binary inputs include build 1.6.1, pyproject-hooks 1.3.3, wheel 0.48.0, and setuptools 84.0.0.

That image passed actual gVisor CPU checkpoint training and an offline PEP 517 build smoke. This verifies the build tools and training dependencies inside that image; the submitted-plugin build lifecycle and complete concurrent FL remain separate gates.

Evidence: `runtime-image/build-6631bd2f/manifest.json`, `logs/image-cpu-training.log`, and `logs/image-build-frontend.log`. The manifest records all wheel hashes and individual build/smoke return codes.

The restored live candidate is `sha256:afa3d81ca179dd1bfe5f321d9104fbf57724c310b787ec8834f3aaea2faa49c4`, recorded in `runtime-image/restore-6b1b2cbd/manifest.json`. It reuses the same 46 SHA-pinned wheel inputs and attested worker source bytes, with a new Docker-created digest. Actual gVisor CPU checkpoint and offline build smokes passed again. A recovery tag prevents accidental parent pruning; jobs still require explicit immutable-digest approval.

The saved recovery archive contains 1,443,636,736 bytes with SHA-256 `0e491ee616bfe4a64f47566eca375cc7af2053333691c769e553809e798d1707`. The manifest records recovery provenance, inputs, source hashes, archive, and smoke return codes. Full live pipelines must approve and test this replacement explicitly; prior complete-smoke evidence is not substituted for their final result.

## Actual submitted build and private-wheel training

The complete build gate passed on the restored immutable worker image `sha256:afa3d81ca179dd1bfe5f321d9104fbf57724c310b787ec8834f3aaea2faa49c4`. It used actual Manager/Controller, PostgreSQL/S3, mTLS Exchange/gateway, assigned Unix proxies, and four gVisor executions: build, owner, Alice, and Bob.

The submitted PEP 517 hook passed **24 isolation assertions** against host/network/metadata/credentials, another real job's code/cache, and foreign sockets. It had no execution proxy and no writable source. Its verified private wheel completed and the build allocation was confirmed released before training began. All three training sandboxes loaded only the verified wheel from read-only `/job/build` into their private site-packages; no host-side source hook, plugin, or model loading occurred.

LeNet completed round 1 from two eight-example updates. Downloaded checkpoint hashes matched, and every FedAvg tensor matched with maximum error **0.0**, verified inside the owner sandbox. Four runtime resources reached `RELEASED`; the independent cleanup audit confirms containers, mounts, and backing images absent, service cleanup errors empty, and retained history preserved.

Evidence: `build-acceptance-final-005/result.json` and `build-acceptance-final-005/cleanup-audit.json`. The result binds the exact source commit `ec9614def390366638cdc8802591bd3b779c5a66`, source/spec/wheel hashes, execution order, control-plane hashes, and tested profile. This is the complete local managed build-and-train gate; autonomous participant build transfer and concurrent-job acceptance are separate.

## Concurrent training, cancellation, and physical purge

The final10 run completed **24 normal check categories and three physical-purge categories** with actual Manager/Controller, PostgreSQL, S3, mTLS services, assigned Unix proxies, and the restored qualified worker image. Two jobs ran concurrently while a third waited for CPU capacity. The three jobs reached `SUCCEEDED` at absolute targets **2, 2, and 1**, producing eight global models, ten training updates, ten real training epochs, and five FedAvg rounds. Downloaded checkpoint bytes/hashes and every FedAvg tensor were verified; maximum tensor error was **0.0**.

The completed scope also covers HTTPS API restart with the controller/proxy owner retained, duplicate-controller adoption, current running metrics/stdout, all nine trained sandboxes' private-code/state checks, exact terminal public-log bytes, artifact downloads, and current ACL grant/revocation. Transparent proxy-owner process death is not claimed. A queued cancellation never started; a running cancellation waited for confirmed initialization and actual training before revocation and confirmed stop, and both reached `CANCELLED`.

Five authenticated purges preserved unrelated siblings and held the prepaid model-storage cap while `cleanup_pending` was true. After physical cleanup, the owned S3 bucket had **zero raw versions, delete markers, and unfinished multipart uploads**. Project retained usage and execution/object-store Pool usage were zero, all twelve runtime ledgers reached `RELEASED`, and fixture cleanup errors were empty. One temporary backing-detachment uncertainty is retained in the trace; subsequent release confirmations are recorded. All 66 hashed Jobs/Exchange source files stayed unchanged during the 368.522-second run.

Evidence: `manager-live-final-10/completed-training-cancel-purge-scope.json`, the original `results.json`, and `durable-state.json`. **The native whole-driver result remains FAILED.** Its final assertion incorrectly expected five jobs in public history after explicit purge; the implemented public list correctly omitted them. The completed-scope report preserves the original failed result and its SHA-256 `d5729b615ac4f7b08ba9ecb979ff75ab76a742b2a3b61b6f3b449616b20b2532`; it does not relabel the native run as passed.

A separate narrow audit passed in **1.426 seconds** over real HTTPS/OIDC and PostgreSQL. It restored the exact exported final10 Job rows, decoded their timestamps, reconstructed the original fixture Project and creator-admin ACLs, and used the original synthetic issuer/subjects with a fresh fixture signing key. The original runtime schema had already been removed; compute and object-store resources were not recreated. Public history returned zero, all five authorized direct details contained only minimal audit metadata without specification/participants/resources, and all five unrelated-user reads returned 404. Six source hashes remained unchanged, and cleanup errors were empty.

Audit evidence: `manager-live-final-10/restored-history-audit-02/results.json`, bound to durable export SHA-256 `026ce57d46360061afd40224978cb8ef1428b0c31672ff40aa891fe52fa847b9`. This is a restored-data read audit, separate from the original runtime run. The managed remote-node/autonomous participant gates, completed package/Python matrix, and final runtime inventory are recorded below.

The independent read-only physical audit also passed: `manager-live-final-10/independent-post-purge-physical-audit.json`. Actual private-Docker inspection found all twelve containers absent; exact mounts, kernel loop associations, fixed images, and private source/config/retained/restart paths were absent. Both Node and executor ledgers recorded twelve `RELEASED` executions. It performed no mutations; shared PostgreSQL/MinIO services remained for other required gates. This confirms final10 owned raw cleanup without claiming final shared-daemon teardown.

## Managed remote-node and autonomous participant training

The managed remote-node final09 gate passed **29 assertions** in **187.390 seconds** using the production `compose_node` and central `create_services` factories, independent HTTPS/mTLS listeners, node-private approvals/ledgers, and verification-only credentials. Two jobs each completed actual owner/Alice/Bob round-1 training: six gVisor executions, four real client epochs, downloaded checkpoint hashes verified, and every FedAvg tensor matched with maximum error **0.0**. The second job waited for its remote pools, then ran after release.

The gate verifies wrong peer/registration/execution denial, durable node affinity, private source and scoped proxies, all six worker logs through authorized HTTPS, historical checkpoint and node-artifact bytes, current ACLs, and minimal authorized post-purge audit details. Six exact typed purge receipts account for twelve shared/per-attempt auxiliary rows. All six allocations were released with termination/storage deletion confirmed; node private/shared charges and raw manager budgets were zero. Actual S3 object versions and unfinished uploads were absent, and adapter/service cleanup errors were empty.

Evidence: `managed-remote-live/run-final-09/results.json`, SHA-256 `719b1f1d310a260b7321d834a56b086b255bea5c77036c8b5ac95aad2e09bd8d`; independent `post-run-verification.json`, SHA-256 `f52130fa170e89b0c2b9127cd045a4cc568030a4a9095cc269a4478c86431f02`. All 66 Jobs/Exchange source hashes stayed unchanged and matched the v2 freeze subset. Earlier driver assertion failures remain retained separately.

The autonomous participant final08 gate also passed with actual LeNet training from Alice's approved NPZ and Bob's locally approved synthetic data. It produced two real client epochs/updates and round 1 with maximum FedAvg tensor error **0.0**. An unavailable Alice endpoint did not stall healthy Bob. Running and terminal logs followed current ACLs. A second job was cancelled only after confirmed initialization and actual running training; both external stop acknowledgements and grant revocation preceded `CANCELLED`.

Two authenticated physical purges removed job-owned data, S3 versions/delete markers/unfinished uploads, and retention/object-Pool charges. Alice's input dataset remained present with its original hash. All six owner/participant Node executions were `RELEASED`, stopped, and disk-released; cleanup errors were empty. Evidence: `external-live/final-08/result.json`, SHA-256 `2728fa6fddc4b3b491681b49bf3deb64701d8f1ff30844c3def1b2114066a22a`; 66 source hashes stayed unchanged.

Both gates used **independent logical nodes on one qualified physical CPU host**. They establish the tested production factories, TLS identities, local approvals, lifecycle, training, and cleanup behavior; multiple physical hosts, GPU execution, and Kubernetes remain outside this qualification. These actual FL results used v2 source. A subsequent bounded proxy error-mapping fix passed its focused HTTPS/proxy regression and is recorded in v3 provenance below; it does not change the worker isolation policy. Completed package/Python/coverage and final inventory with intentional daemon retention are recorded below.

## Controlled proxy revocation responses

After the completed v2 training gates, a narrow credential-provider error-mapping fix passed **43 affected tests** (18 execution-proxy and 25 supervisor tests), zero failures/errors/skips, in **49.885 seconds** (51.088 seconds process wall time). Five new cases verify rejection before request-body consumption, transfer construction, or downstream sends. An actual Unix-socket proxy to mTLS manager starts healthy, then maps the manager's revoked-assignment 404 to a controlled 403 with no downstream Exchange/gateway/storage request.

Known credential-provider authority errors 401/403/404/410 map to fixed `403 execution_authority_denied`. Timeout/rate/service errors 408/429/5xx and the exact `409 participant_assignment_not_ready` map to fixed `503 execution_service_unavailable`; raw provider details are not exposed. JWT validation and unexpected-error handling retain their existing behavior.

Evidence: `/localhome/local-isaacy/hf2l-validation/20261009-jobs-gateway/execution-proxy-authority-denial-tests.json` and matching log, log SHA-256 `82de6e0e00a21eb8dc386b4b33079d90f8a43da7e4f8535b25a08e63954f5fba`. Source stayed unchanged during the gate; `execution_proxy.py` SHA-256 is `a55b8d8d20ab90530effa98a6529bd04b252b014210ccb0ff4b0aade0ed2c7c4`.

This targeted HTTP/supervisor regression covers the sole v2-to-v3 production-source delta. Ordinary authorization, worker behavior, sandbox policy, and runtime image are unchanged. The actual completed FL evidence remains tied to v2; it is not relabeled as a full FL rerun on v3. The completed updated-wheel matrix, final job-resource inventory, and intentional service retention are recorded below.

## Strict client certificate issuance

The v4 follow-up passed **26 strict certificate/mTLS checks on each of Python 3.12.15 and 3.14.4**, zero failures/errors/skips. Actual central execution, local proxy, and artifact-broker mTLS paths succeeded; missing client certificates and wrong certificate purpose were rejected. New leaves carry key-derived SKI, issuer-matching AKI, critical digital-signature-only KeyUsage, `CA=false`, and client-auth-only EKU. Issuer admission policy is unchanged.

Python 3.14.4/OpenSSL 3.5.5 retained its default client/server verification flags **557088** and hostname checking. The Python 3.12.15/OpenSSL 3.5.9 tests explicitly enabled strict verification (32768 to 32800); they are not evidence that Python 3.12 has the same default flags as 3.14. Strict verification was not weakened.

Evidence: `strict-pki-issuance/issuer-3.12.15.json` and `issuer-3.14.4.json` (SHA-256 `b7d4d4f49fd64dfe79665db408ecd918541f0c9fd3004e45f1de49766e8ac7a8`). The affected Python 3.14.4 supervisor suite also passed 25 tests in 50.187 seconds; two actual HTTPS dashboard/API browser scenarios passed in 8.659 seconds with strict Python TLS defaults. Browser synthetic-certificate trust settings remain explicit in the fixture's scope. Evidence: `strict-tls-fixtures/python314-supervisor-final.json` and `python314-browser-tests.json`. Earlier failed fixture runs are retained.

V4 changes only the three client issuance paths in `certificates.py`, `execution_proxy.py`, and `managed_client.py`. Completed actual FL remains v2 evidence; v3 covers proxy error mapping, and v4 covers this strict issuance follow-up. Runtime worker-critical bytes/profile/image are unchanged. The [deployment guide](../../deploy/jobs/README.md#certificate-authority-and-strict-tls-preflight) supplies a compliant operator CA recipe and strict chain/purpose/hostname preflight.

## Bounded log stream regression

The frozen log-stream suite passed **23 tests**, zero failures/errors/skips, in 0.797 seconds. It covers durable byte cursors, source rotation/truncation markers, prepaid manager log capacity, terminal catchup, and UTF-8 overflow that cannot resume later ASCII after truncation. Unexpected budget exhaustion records a bounded omission marker and advances the durable cursor without preventing stop.

Evidence: `job-logs/log-stream-tests-final.log`; module SHA-256 `063fbb20b9f5bbd902dfe6fe96eb90c1b4fa4f279061d84df04bace084f5529e`. This is the focused regression gate; the completed final10 scope above additionally verifies actual running stdout and exact terminal gVisor log bytes through the public HTTPS API.

## Retained-copy filesystem accounting

An actual production-format 64 MiB ext4 loop image and `LinuxExecutor.collect/release` exercised 282 valid files, including deep tiny paths and bulk data. The first atomic restart copy began only after the old image and mount were absent; release and owned mount cleanup were confirmed.

The retained immutable and restart copies occupied 107,438,080 bytes, exceeding the earlier scratch-plus-logical-payload estimate of 104,755,480 bytes. The final two-copy reservations of 138,412,032 bytes cover these actual bytes. Collection budgets therefore hold full conservative copy capacity until confirmed physical purge, including unused remainder for filesystem blocks and directory metadata. They are capacity bounds rather than exact payload billing.

Evidence: `/localhome/local-isaacy/hf2l-validation/20261009-multi-job/retained-copy-physical-proof.json`. This is an actual filesystem/executor ordering proof; `sandbox_executed=false`, so it does not add gVisor isolation or FL assertions.

## Independent lifecycle and in-flight provider writes

The final independent lifecycle gate passed **32 tests**, zero failures/errors/skips, in 6.777 seconds. It includes actual admission/planner quotas, shared source/blob budgets across retry, lost namespace-creation acknowledgement adoption, strict owned retirement, live-allocation refusal, and the gateway PUT/cleanup overlap regression.

The original overlap proof held a provider PUT beyond its one-second signed expiry and observed premature cleanup plus a late synthetic raw part. The repaired proof records one durable mutation fence while held, zero cleanup operations, `cleanup_pending: true`, and eight reclaiming bytes. After a known 204 response and closed stream, the fence clears, one cleanup operation runs, and pending/raw data are absent.

Evidence under `/localhome/local-isaacy/hf2l-validation/20261009-multi-job`: `lifecycle-acceptance.log`, `gateway-put-overlap-proof.json`, and `gateway-put-overlap-proof-after.json`. This exercises actual Manager/Exchange/transfer/gateway code with a synthetic delayed provider; it does not claim an actual MinIO overlap or sandbox execution. Ambiguous provider outcomes require the documented selected offline repair after writers stop and provider quiescence is established.

The frozen gateway fence suite passed **30 tests**, zero failures/errors/skips, in 17.955 seconds (18.866 seconds process wall time). Seven new fence cases include an actual mTLS gateway forwarding a 65,537-byte PUT to a paused HTTPS origin beyond a real one-second URL expiry. Retirement holds the mutation fence and reclaiming bytes while provider I/O remains active. Full body EOF, known successful acknowledgement, and upstream close settle the exact receipt after revoke/retirement; HTTP errors, timeout, disconnect/cancellation, non-success, close failure, or failed settlement leave it pending.

Evidence: `/localhome/local-isaacy/hf2l-validation/20261009-jobs-gateway/gateway-mutation-fence-tests.json` and matching log. Gateway SHA-256 `8a31a5413a9bdf345c75ebeb66c34e323727eef01da0b9ba68d62227e2ef4688`; transfer module SHA-256 `8c3d00734ec26d00f331a17b74772ab603e9efdfefe9c37999e2f093703cbb61`. The paused origin is a test provider over actual HTTPS; this is a focused fence/TLS gate, separate from complete runsc FL and the final owned aggregate.

The matching Exchange regression passed **234 of 236 tests** in 43.852 seconds, zero failures/errors. Two expected skips are explicit: Moto cannot enforce modified presigned-download signatures, and the normal SQLite runner cannot exercise the PostgreSQL row-lock recovery test. Evidence: `/localhome/local-isaacy/hf2l-validation/20261009-jobs-gateway/exchange-gateway-fence-tests.json` and byte-identical persistent `exchange-gateway-fence-tests-retained.log`. Fifteen focused mutation/repair cases pass within this total. Completed actual provider/PostgreSQL gates and final package cohorts have separate evidence below.

## Final owned runtime inventory

The first final inventory failed on **three inert zero-byte Unix socket entries** left after administrative proxy-supervisor closure. They had no kernel listener, credentials, or private worker payload; administrative close was not treated as proof of job termination. The original failure and socket diagnostics remain preserved.

After renewed exact ownership/path/kernel checks and authorization, housekeeping removed only those three endpoint entries and their empty execution-key directories. It changed no source, ledgers, services, or images. A fresh inventory passed, followed by an independent v4 source/physical-state confirmation.

The final confirmation checks **24 accepted execution identities**, **seven read-only SQLite ledgers**, **96 private paths**, and **668 retained artifact locators**. Every execution is released, stopped, and disk-released; shared auxiliary reservations are zero. Owned job containers, mounts in checked namespaces, loop devices, and referenced private payloads are absent. All **144 source files** match v4 with exactly the three expected PKI deltas; this does not relabel earlier training as v4 executions.

Evidence: `final-runtime-inventory.json` (original FAILED), `final-runtime-proxy-socket-diagnostics.json`, `final-runtime-socket-housekeeping.json`, `final-runtime-inventory-after-housekeeping.json` (passed), and `final-runtime-provenance-v4.json`, SHA-256 `903c489623c5dba27b4eaa7fa34a6ee251b20b7396927c46ce562761e49c2d4c`.

The isolated qualified runtime daemon, its pinned worker/base image IDs, verified binaries/profile, and shared PostgreSQL/MinIO fixtures are **intentionally retained for future remote development**. Audit ledgers, receipts, evidence, ownership tombstones, and empty structural directories are retained. This is completed job-resource cleanup, with retained services explicit; it is not a claim that every task-owned service/image was removed.

## Built distributions and Python cohorts

The v4 packaging run builds all three distributions (`hf2l`, `hf2l-exchange`, `hf2l-jobs`) as wheels and source archives. Twine metadata validation and packaged-byte/source comparisons passed. Its 159-file packaging snapshot has SHA-256 `4ea8ca116edb88777e2d118dc21b8c2e055902a84d8d8880f8e2d40cfea6d539`; this broader packaging snapshot is distinct from the 144-file production freeze.

Clean manager-only and manager-server wheel environments passed on **Python 3.10.22, 3.11.17, 3.12.15, 3.13.16, and 3.14.4**. Checks cover install/import, CLI commands, packaged dashboard assets, dependency consistency, and absence of ML/application/Exchange dependencies from these manager environments. Python 3.11/3.13 cover clean install/service boundaries, not a full functional suite. Evidence: `packaging/run-e6cefa14/results.json`, `packaging/parallel-clean-2a04a5fb/results.json`, and `packaging/parallel-314-26e69358/results.json`.

Completed functional cohorts are recorded separately:

| Interpreter/cohort | Executed | Passed | Skipped | Source scope |
| --- | ---: | ---: | ---: | --- |
| Python 3.10 jobs baseline | 984 | 934 | 50 | Preserved earlier complete cohort |
| Python 3.10 final affected modules | 115 | 115 | 0 | V4 certificates, proxy, supervisor, artifact broker, and secrets |
| Python 3.10 Exchange baseline | 236 | 234 | 2 | Preserved baseline |
| Python 3.12 jobs | 993 | 964 | 29 | V4; actual PostgreSQL enabled |
| Python 3.12 Exchange | 236 | 235 | 1 | V4; actual PostgreSQL enabled |
| Python 3.12 runtime wheel tests | 41 | 41 | 0 | V4 built-wheel runtime cohort |
| Python 3.12 offline build | 15 | 14 | 1 | V4; qualified live-build counterpart recorded separately |
| Python 3.12 standalone compatibility | 56 | 56 | 0 | V4 focused existing-workflow compatibility |
| Python 3.12 mandatory browser | 10 | 10 | 0 | V4 packaged dashboard/API/browser gate |
| Python 3.14 jobs | 993 | 943 | 50 | V4; optional live/ML/browser fixtures absent here |
| Python 3.14 Exchange | 236 | 234 | 2 | V4; normal provider/database cohort |
| Python 3.14 runtime wheel tests | 41 | 41 | 0 | V4 built-wheel runtime cohort |
| Python 3.14 offline build | 15 | 14 | 1 | V4; qualified live-build counterpart recorded separately |
| Python 3.14 standalone compatibility | 56 | 56 | 0 | V4 focused existing-workflow compatibility |

These are repeated cohort executions, not unique tests to add into one aggregate. Python 3.10's preserved baseline plus approved source deltas and 115 affected checks is explicitly documented; it is not a single full v4 run. Full skipped-test inventories, interpreter/build/dependency manifests, wheel/archive hashes, and source comparisons remain in each run's JSON/logs.

The 50 optional jobs skips in the Python 3.14 manager cohort include 22 unconfigured PostgreSQL cases, two live PostgreSQL/S3 object-budget cases, 14 missing offline build-frontend/backend cases, one explicitly qualified live-build case, eight browser cases, two ML/runtime-extra cases, and one privileged source-workspace case. Dedicated actual PostgreSQL, browser, source-fetch, build, and runsc training qualifications have separate evidence above. The Python 3.14 Exchange skips are Moto's unsupported presigned-signature enforcement and its unconfigured PostgreSQL row-lock recovery case; Python 3.12 runs that database case. Python 3.10's retained raw skip lines and class/subtest counter distinction are preserved in the merged report. Offline-build cohorts intentionally omit the privileged live qualification, which passed separately on the approved runtime image.

The final coordinator passed: Python 3.12 runtime 41/41, offline build 14 passed plus one explicitly qualified-live-build skip, standalone compatibility 56/56, and mandatory browser 10/10 with zero skips. Its 159-file snapshot stayed identical at start/end. Evidence: `packaging/run-e6cefa14/results.json`; the coverage scope is recorded below. The final cohort source is v4; the closing matrix preserves earlier Python 3.10 baseline provenance rather than presenting a fabricated single full-v4 run.

Final merged matrix: `packaging/final-matrix-v4.json`, SHA-256 `9cf78d8eef2b11dfc3f117832120bc874648dd1bc8cc77fd2bd1603a1be98ba9`. Preserved Python 3.10 runtime-wheel payload proof: `packaging/preserved-runtime310-v4-payload-proof.json`, SHA-256 `7895d90c9dfc3878fa103815dcf0b9b5688c4e38cd9d78c8f5905be666615702`. The proof compares Python/manager asset payloads, permits exactly the three PKI issuance changes, and confirms unchanged runtime/workflow/build and HF²L/Exchange payloads; it does not claim identical wheel metadata or ZIP timestamps.

## Manager test coverage

Fresh Python 3.12 coverage covers **45 `hf2l_jobs` files** across the manager SQLite/PostgreSQL/TLS suite and runtime/private-build tests:

| Measure | Covered / total | Coverage |
| --- | ---: | ---: |
| Statements | 14,168 / 17,279 | **82.00%** |
| Branches | 4,477 / 6,540 | **68.46%** |

There are 3,111 uncovered statements and 2,063 uncovered branches. The figures describe the new manager package, not combined whole-repository coverage. Worker child processes, browser execution, and live sandbox qualification are excluded; their explicit acceptance evidence is recorded separately. Old and aborted coverage data were excluded. The coverage tool's default combined statement/branch percentage is a different measure; the fractions above state each measure directly.

Evidence: `packaging/run-e6cefa14/coverage.json`, `coverage.ini`, `logs/coverage-report.log`, and the coordinator's `results.json`. These are fresh scope-specific results, separate from the dated standalone repository coverage in earlier reports. Tests provide substantial exercised behavior; uncovered branch paths remain, and this is not full coverage.

## Documentation checks

All relative links in the operator, deployment, package, design, root README, and validation guides resolve. Twenty-two JSON examples across these six files parse; independent command review validates 18 manager and five Exchange CLI examples; the job creation body validates against the implemented `JobSpec` and the core `RoundConfig` minimum-participant rule. Independent factory review checks managed-node and participant-agent configuration keys, listener schemas, local approvals, and central enrollment. The selected transfer-repair examples and opaque inventory ownership IDs match the implementation, including stopped writers, independent provider quiescence, and physical cleanup confirmation. Both new CA/preflight shell blocks pass syntax review, and the documented CA and leaf extensions match the actual issuers; documentation review generated no keys and launched no services. These checks do not constitute deployment readiness.

## Acceptance summary and limits

| Gate | Completed evidence |
| --- | --- |
| Manager authorization, scheduling, lifecycle, and collectors | Python 3.12 jobs 993 executed / 964 passed / 29 explicit optional skips; separate actual PostgreSQL and focused security gates |
| Managed Exchange, transfer, and proxies | Complete local/managed-node/autonomous participant scopes, durable PUT fence tests, targeted v3 proxy and v4 strict PKI follow-ups |
| CPU runtime | 197 original isolation plus 23 backing-I/O/adapter assertions; fixed image/profile provenance retained |
| Submitted builds | Actual qualified private-wheel build/training with 24 hook-isolation assertions and confirmed release |
| Concurrent local FL, queue, cancel, and purge | Completed final10 runtime scopes and restored read audit; native driver FAILED at its invalid post-purge history assertion remains unchanged |
| Managed remote-node / autonomous participant FL | Final09 and final08 passed using independent logical factories/TLS identities on one physical CPU host |
| Existing workflow compatibility | Final built-wheel runtime and 56 focused standalone compatibility checks |
| Python and distributions | Five clean manager/server interpreter versions, functional cohorts with explicit skips, wheels/source archives/Twine/byte comparison passed |
| Manager coverage | 82.00% statements and 68.46% branches; manager-only scope and exclusions explicit |
| Source provenance | V2 actual FL, v3 proxy, v4 strict PKI, 144-file source cross-check, and unchanged 159-file packaging snapshot |
| Execution cleanup | 24 identities, seven ledgers, 96 paths, and 668 locators checked; intentionally retained runtime/images/PostgreSQL/MinIO explicit |
| Operator runbooks | JSON examples, links, CLI/schema contracts, strict CA recipe, and independent prose/evidence review passed |

The accepted v1 scope is managed FedAvg with the qualified CPU profile on `ipp1-3414`. Every additional physical node must qualify its own runtime/backing devices and approved TLS/catalog configuration. These colocated-node results do not establish multiple-physical-host, GPU, or Kubernetes qualification. Automatic cyclic scheduling, pause, preemption, shared GPUs, and mid-epoch optimizer-state recovery remain later work. Production OIDC, certificates, storage allocation, and service supervision use the operator setup described in the runbooks.
