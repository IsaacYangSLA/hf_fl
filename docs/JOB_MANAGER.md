# Operating the HF²L job manager

**Status:** implemented CPU v1 runbook; runtime qualification is required for each deployment.

The job manager runs independent managed FedAvg jobs in one deployment. Each job has an immutable specification, authorized source snapshot, separate Exchange space, workload identities, state, logs, and artifacts. Resource availability determines admission from the durable queue.

The packaged dashboard is served at `/dashboard/`; the API base is `/api/jobs/v1`. Node.js is not required. PostgreSQL is the deployment database. The [deployment guide](../deploy/jobs/README.md) describes the trusted service boundaries, and the [design](MULTI_JOB_DESIGN.md) specifies the isolation contract.

## 1. Install and initialize

Install the application, Exchange server, and manager into the deployment's dedicated Python environment:

```sh
python -m pip install -e 'packages/exchange[server]' -e '.[examples]' -e 'packages/jobs[server]'
hf2l-jobs --help
```

The manager requires Python 3.10 or later. Clean manager/server wheels are validated on Python 3.10–3.14; functional cohorts and exact patch versions are recorded in the validation report. The qualified default training image is separately pinned to CPython 3.14. Manager processes do not import job training plugins. The approved runtime image must contain the FL dependencies needed by its jobs.

Configure `HF2L_JOBS_DATABASE_URL` for a dedicated manager PostgreSQL database. Initialize a new database with `hf2l-jobs init-db`; apply upgrades with `hf2l-jobs migrate-db`. Services check the schema instead of silently changing it at startup. The current manager revision is `0003_administrative_audit`; upgrades preserve the original ledger, trusted artifact locators and log-storage charges, and add sanitized trusted-administration audit records. Legacy artifacts without a trusted locator remain metadata-only until a trusted collector supplies one; arbitrary old locator strings are not parsed as paths. SQLite is an isolated test backend.

Trusted operational settings use `hf2l-jobs <command> --config /etc/hf2l/jobs.json`, or `HF2L_JOBS_OPERATIONAL_CONFIG_FILE`. The configuration's sections are `executor`, `node`, `provisioner`, `service`, `gateway`, `proxy`, `retention`, `boundaries`, `controller`, `secrets`, `nodes`, and `participants`. Job requests cannot replace this trusted configuration.

## 2. Human login and authorization

Set the following server environment variables. The `JOBS_` prefix is also supported; configuring both prefixes with different values is rejected.

| Variable | Purpose/default |
| --- | --- |
| `HF2L_JOBS_DATABASE_URL` | Dedicated PostgreSQL URL |
| `HF2L_JOBS_CURSOR_SECRET_FILE` | Cursor signing secret, at least 32 bytes |
| `HF2L_JOBS_SESSION_SECRET_FILE` | Distinct session signing secret, at least 32 bytes |
| `HF2L_JOBS_OIDC_ISSUER` | Fixed trusted human OIDC issuer |
| `HF2L_JOBS_OIDC_CLIENT_ID` | Registered OIDC client |
| `HF2L_JOBS_OIDC_CLIENT_SECRET_FILE` | Confidential client secret, when required |
| `HF2L_JOBS_OIDC_REDIRECT_URI` | Exact HTTPS `/auth/callback` URL registered with the provider |
| `HF2L_JOBS_AUDIENCE` | Human API audience; default `hf2l-jobs` |
| `HF2L_JOBS_OIDC_JWKS_URL` | Optional fixed JWKS endpoint; otherwise trusted provider discovery |
| `HF2L_JOBS_OIDC_PUBLIC_KEY_FILE` | Fixed public key alternative to a fixed JWKS URL |
| `HF2L_JOBS_OIDC_INTROSPECTION_URL` | Optional provider online identity check |
| `HF2L_JOBS_OIDC_ENDPOINT_ORIGINS` | Comma-separated explicitly trusted extra HTTPS endpoint origins |
| `HF2L_JOBS_PLATFORM_OPERATOR_IDS` | Comma-separated stable human principal IDs for resource administration |

Serve the manager over HTTPS. Authorization code flow uses PKCE, state, and nonce. Browser credentials remain in server-side sessions; session cookies are Secure, HttpOnly, and SameSite=Lax. A session expires after 30 minutes idle or eight hours absolute. Identity is checked online at least every 15 minutes; without an introspection endpoint, fresh authorization is required at that interval. Account disabling is not instantaneous without provider revocation integration.

`GET /auth/session` returns the browser session's CSRF token. Mutations authenticated by a session require `X-CSRF-Token` and the matching same-origin `Origin`; the dashboard supplies them. API clients may use an approved human access token without storing it in browser local storage. It must be an RS256 JWT with `typ: at+jwt`, the configured human issuer/audience (`hf2l-jobs` by default), and a scope containing `jobs`; an arbitrary OIDC ID token or provider-default access token is not this API credential.

Project membership permits job creation. The creator receives job-admin membership; other project members do not automatically see that job. A human principal ID is the SHA-256 of compact JSON `[issuer, subject]`; use the authenticated `/auth/session` principal ID or the fixed issuer/subject pair when granting project membership.

| Membership | Job actions |
| --- | --- |
| `reader` | View metadata, history, logs, metrics, and retained artifacts |
| `operator` | Reader actions plus cancel, retry, reconcile |
| `admin` | Operator actions plus membership changes and purge |

A platform operator can inspect resource health and manage pools through `GET /api/jobs/v1/pools` and `PUT /api/jobs/v1/pools/{id}`. Job content still requires explicit job membership. Revoking job membership blocks subsequent reads, downloads, and stream refetches. Inaccessible jobs return 404.

## 3. Trusted bootstrap

Use the local `hf2l-jobs admin` commands to create projects, grant submitter permission, register explicitly allocatable pools, and approve source/image/dataset/secret-reference catalogs: Register the manager source filesystem and the distinct model-object allocation with `storage-pool-set` and `object-store-pool-set` as described in the deployment guide before enabling admission.

```sh
hf2l-jobs admin --config /etc/hf2l/jobs.json project-create \
  --id research --name Research --quota-file /etc/hf2l/research-quota.json \
  --retention-days 90
hf2l-jobs admin --config /etc/hf2l/jobs.json project-member \
  --project research --principal HUMAN_PRINCIPAL_ID --role submitter
hf2l-jobs admin --config /etc/hf2l/jobs.json pool-set --file /etc/hf2l/cpu-pool.json
hf2l-jobs admin --config /etc/hf2l/jobs.json source-approve --file /etc/hf2l/source.json
hf2l-jobs admin --config /etc/hf2l/jobs.json image-approve --file /etc/hf2l/image.json
hf2l-jobs admin --config /etc/hf2l/jobs.json dataset-approve --file /etc/hf2l/dataset.json
hf2l-jobs admin --config /etc/hf2l/jobs.json dataset-approve --file /etc/hf2l/bob-dataset.json
```

Update an existing project with the trusted command:

```sh
hf2l-jobs admin --config /etc/hf2l/jobs.json project-update \
  --id research --quota-file /etc/hf2l/research-quota.json --retention-days 90
```

`--quota-file` replaces the quota object and accepts the same known fields as creation; `--name` and `--retention-days` are optional. The transaction locks the project and refuses quotas below current admitted CPU/RAM/disk/GPU/job usage or charged retained bytes. It increments the project version and records a sanitized before/after administrative audit identified by the invoking Unix UID. Project creation and pool updates are also audited. Changing retention affects expiration assigned to later terminal jobs; it does not rewrite an existing job's `artifacts_expire_at`.

Source approval binds a source identifier to permitted projects and exact commit object IDs. The provisioner materializes a verified commit tree without Git history, repository configuration, credentials, hooks, or submodules. Public HTTPS fetching validates approved hosts and resolved addresses and rejects redirects/private endpoints. Trusted operator mirrors are a separate approval path; a job cannot select a host path. Private repositories require an operator-prepared trusted Git object mirror; direct private HTTPS credential handling is not implemented. Symlinks, submodules, and special source files are rejected. Source fetching uses a separately bounded task-owned tmpfs object receiver, strict byte/file limits, process address-space/CPU/file-size limits, bounded output, and a wall timeout; required quota tooling missing means provisioning fails closed. Trusted provisioning needs approved `sudo -n` mount/umount and Linux `prlimit` access. Creation resolves a runtime-image alias to the approved exact SHA-256 digest in the stored immutable specification and its hash. An idempotency replay uses the original request hash; retries reuse the stored digest instead of resolving an alias again. A disabled or retired required digest fails closed.

Managed listener state binds the complete source/runtime specification through a versioned SHA-256 identity. The full canonical binding and per-file source manifest remain verified separately. This keeps listener identities bounded for large repositories while refusing state reuse when any bound input changes. Existing listener state using the earlier raw-JSON identity is intentionally incompatible, even when the inputs match. Drain active training before upgrading, and explicitly reconcile affected jobs and their published checkpoints before attempting recovery; the manager does not rewrite that state identity automatically.

For remote-only execution, register the manager's own bounded source/provisioning storage with `hf2l-jobs admin storage-pool-set` and `provisioner.storage_pool_id`, as shown in the deployment guide. This storage-only pool does not advertise CPU/RAM or a sandbox. Local/mixed deployments can use their explicit local runtime pool.

Dataset bindings identify locally approved participant datasets. Raw datasets stay at participant nodes. Autonomous external participants do not consume manager server allocations; managed participants require matching component assignments and node reservations.

### Bootstrap JSON inputs

These examples use explicit capacity after reserving resources for the control plane. Select values that fit the qualified node, and use the same node/pool IDs in operational configuration.

`research-quota.json`:

```json
{
  "cpu_millicores": 12000,
  "memory_bytes": 25769803776,
  "disk_bytes": 34359738368,
  "gpu_count": 0,
  "max_running_jobs": 3,
  "retained_bytes": 68719476736
}
```

`cpu-pool.json`:

```json
{
  "id": "cpu-primary",
  "name": "Qualified CPU pool",
  "node_id": "node-primary",
  "cpu_millicores": 6000,
  "memory_bytes": 12884901888,
  "disk_bytes": 34359738368,
  "gpu_uuids": [],
  "gpu_profiles": [],
  "sandbox_profiles": [
    "runsc-cpu-v1"
  ],
  "healthy": false,
  "quarantined": false
}
```

Register the pool unhealthy initially. Set `healthy` to true only after runtime qualification; the administration command verifies that the pool matches the qualified node and does not exceed its capacity.

`source.json` approving this repository's baseline commit:

```json
{
  "id": "hf2l-source",
  "project_id": "research",
  "url": "https://github.com/IsaacYangSLA/hf_fl.git",
  "allowed_commits": [
    "38a3d4121b6796cbfdd7f354645157852393a18a"
  ],
  "max_bytes": 8388608,
  "max_files": 1000,
  "max_git_bytes": 8388608,
  "max_git_files": 4000
}
```

Add `github.com` to trusted `provisioner.allowed_source_hosts`. Approve the actual intended commit; the example commit does not contain the new manager. For a private repository, replace `url` with an operator-owned absolute `mirror_path`; do not include both. The mirror contains the approved Git objects and is never mounted into a job. Source and temporary Git-workspace storage are reserved against project and pool budgets before fetch. The immutable snapshot settles to actual filesystem blocks plus owned metadata; the temporary workspace is released only after confirmed empty, unmounted deletion. Failed materialization stays charged until owned cleanup is confirmed. `max_bytes`/`max_files` bound the materialized tree; `max_git_bytes`/`max_git_files` bound the fetch receiver. Defaults are 256 MiB and 100,000 entries per bound, with a hard 1 GiB byte ceiling. Admission reserves the configured tree and Git-object upper bounds plus filesystem metadata and bounded fetch-workspace overhead before writing. Size those limits to the intended repository and provision enough storage-pool/project capacity; admission cannot rely on the eventual small snapshot to bypass the preflight reservation.

`image.json` contains `id`, `digest`, and optionally `project_id`/`enabled`. Set the digest to the actual preloaded runtime image's `sha256:<64 lowercase hex>`; mutable image tags are not approval identifiers. A different digest requires a new approval ID; an existing image approval cannot be retargeted. To restore a job whose pinned image is missing, load that exact image from its retained archive. A newly built digest requires a newly created job.

`dataset.json`:

```json
{
  "id": "alice-mnist",
  "project_id": "research",
  "participant_id": "alice",
  "dataset_label": "Locally approved synthetic MNIST data",
  "node_id": "node-primary"
}
```

Create `bob-dataset.json` with the same shape, changing `id` to `bob-mnist`, `participant_id` to `bob`, and its label accordingly. For a managed participant, also set the approved `node_id`; its local agent owns the actual dataset mapping. Secret approval files use `id`, `project_id`, and `reference`, where `reference` is a private regular file readable by the trusted provisioner. Approval never prints its value. Delivery also requires the matching project/role/option scope under trusted `secrets.references`, as shown in the deployment guide.

## 4. Create and inspect jobs

Fetch `GET /api/jobs/v1/catalog` to discover the caller's authorized project/source/image/dataset choices. Use the dashboard creation form or `POST /api/jobs/v1/jobs` with an immutable specification and a unique `Idempotency-Key`.

A specification contains `project_id`, `name`, `source_id`, `source_commit`, `runtime_image`, `plugin`, finite JSON `options`, approved `secret_refs`, `participants`, `components`, an absolute `target_round`, and `max_duration_seconds`. Exactly one component is the owner. Each component requests a pool, CPU millicores, memory bytes, disk bytes, and the approved sandbox profile. Inline credentials, arbitrary commands, host mounts, executor flags, and unknown fields are rejected.

Successful creation returns HTTP 202, the queued job, and its detail URL. Repeating the same idempotency key with the same specification returns the same job only while the caller still has current project/job authorization; changing the body conflicts. Revoked membership does not regain access through idempotency replay. To change source, training options, participants, or limits, create another job.

| Request | Result |
| --- | --- |
| `GET /jobs?view=queued` | Jobs waiting for allocatable resources |
| `GET /jobs?view=current` | Admitted/provisioning/running/reconciling jobs |
| `GET /jobs?view=history` | Completed, failed, or cancelled jobs |
| `GET /jobs/{id}` | Detail, version, current round, attempt, deadline, cleanup state |
| `GET /jobs/{id}/attempts` | Infrastructure attempt history |
| `GET /jobs/{id}/events` | Durable lifecycle timeline |
| `GET /jobs/{id}/logs` | Bounded authorized log pages |
| `GET /jobs/{id}/artifacts` | Retained artifact metadata and expiry status |
| `GET /jobs/{id}/artifacts/{artifact_id}/download` | Brokered attachment bytes after a fresh ACL/locator check |

Source files appear through the same artifact endpoints with `kind: source`, their exact relative `source_path`, and per-file size/SHA-256. Downloads use the owned settled snapshot, require current reader access, and expire with source retention; no archive or second source copy is created or charged.

All paths in the table are relative to `/api/jobs/v1`. Lists and counts use current job membership before pagination. Signed cursors bind the principal and filters; treat them as opaque.

The dashboard distinguishes resource waiting from `RUNNING / waiting_participants`. Its event stream sends authorized invalidations; REST refetch is the source of truth, with 10-second polling as a fallback. Logs are attributed to attempt and component and use bounded cursor pages. The controller captures a redacted canonical stream up to 960 KiB per execution in chunks up to 64 KiB; rotation loss and source-cap truncation produce explicit markers. Admission also prepays a 1 MiB manager database log budget per component/attempt, held until raw log deletion. Chunks consume that budget without a second project charge. Unexpected exhaustion records a bounded omission marker and dropped-byte/truncation metadata while advancing the source cursor, so log capture cannot block stop confirmation. Terminal catch-up remains subject to retention. This is a bounded diagnostic record, not unlimited console history. Names, logs, and output are rendered as text under a restrictive content security policy.

### Example create body

This CPU pilot allocates an owner and two managed participants as a gang. The managed FedAvg owner consumes the flat `options.minimum_participants` field, with a default of 2. Set an integer quorum of at least 2 and no greater than the declared participant count. Nested `round_cfg` remains opaque plugin data and does not control this managed quorum. Configure the matching locally approved synthetic binding shown in the deployment guide. Replace the commit and identifiers with authorized catalog entries; ensure the approved runtime contains the selected plugin and dependencies.

```json
{
  "project_id": "research",
  "name": "Synthetic MNIST federated experiment",
  "source_id": "hf2l-source",
  "source_commit": "38a3d4121b6796cbfdd7f354645157852393a18a",
  "runtime_image": "hf2l-cpu",
  "plugin": "lenet",
  "options": {
    "minimum_participants": 2
  },
  "secret_refs": {},
  "participants": [
    {
      "participant_id": "alice",
      "dataset_binding": "alice-mnist",
      "mode": "managed",
      "component_id": "alice-client"
    },
    {
      "participant_id": "bob",
      "dataset_binding": "bob-mnist",
      "mode": "managed",
      "component_id": "bob-client"
    }
  ],
  "components": [
    {
      "component_id": "owner",
      "role": "owner",
      "resources": {
        "pool_id": "cpu-primary",
        "cpu_millicores": 1000,
        "memory_bytes": 2147483648,
        "disk_bytes": 1073741824,
        "gpu_count": 0,
        "sandbox_profile": "runsc-cpu-v1"
      }
    },
    {
      "component_id": "alice-client",
      "role": "participant",
      "participant_id": "alice",
      "resources": {
        "pool_id": "cpu-primary",
        "cpu_millicores": 1000,
        "memory_bytes": 2147483648,
        "disk_bytes": 1073741824,
        "gpu_count": 0,
        "sandbox_profile": "runsc-cpu-v1"
      }
    },
    {
      "component_id": "bob-client",
      "role": "participant",
      "participant_id": "bob",
      "resources": {
        "pool_id": "cpu-primary",
        "cpu_millicores": 1000,
        "memory_bytes": 2147483648,
        "disk_bytes": 1073741824,
        "gpu_count": 0,
        "sandbox_profile": "runsc-cpu-v1"
      }
    }
  ],
  "target_round": 2,
  "max_duration_seconds": 3600
}
```

Two such jobs require 6 CPU cores and 12 GiB RAM, fitting the example pool; a third waits for capacity. The 32 GiB pool disk, 68 GiB node physical capacity, and separate 32 GiB model-object allocation also allow conservative source, collection, retained-copy, and per-attempt budgets, so compute release can admit it while prior results remain retained.

The dashboard submits this shape directly. An autonomous external participant uses `mode: "external"` without `component_id` or a server participant component; that job waits for its separately approved participant execution/proxy to join. Participant data bindings remain local and cannot be selected as arbitrary job paths.

### Enroll an external participant

For an external participant already listed in the immutable specification, an authorized job operator submits `POST /jobs/{job_id}/participants/{participant_id}/enroll` with `{"node_id":"APPROVED_NODE_ID"}`, the expected `If-Match`, and an idempotency key. The server returns HTTP 202; `GET` of the corresponding `/enrollment` endpoint exposes metadata only. The node and its dataset binding must have prior local/operator approval. This creates no server `ManagerAllocation`.

Actual assignment, source transfer, short-lived credentials, heartbeat, and confirmed stop use the separate private mTLS node API. Browser/human access never returns worker/node JWTs. See the deployment guide for participant-agent setup.

## 5. Lifecycle operations

Read a job immediately before a mutation and send its quoted integer version in `If-Match`, plus a fresh `Idempotency-Key`. A stale version conflicts. Session clients also send the CSRF header.

- `POST /jobs/{id}/cancel`: fences writes, requests termination, reconciles publication outcomes, and releases compute only after termination/fencing is confirmed.
- `POST /jobs/{id}/retry`: creates a new infrastructure attempt of an eligible failed job with the same immutable specification. A deadline-expired job returns `409 job_deadline_expired`.
- `POST /jobs/{id}/reconcile`: submits operator evidence for an unresolved publication/runtime outcome. The body is `{"evidence":{"publication_id":"...","outcome":"published","evidence_ref":"..."}}`, with `outcome` either `published` or `not_published`. References may name an actual Exchange record, `exchange:<space>:<record>`, or `sha256:<intent fingerprint>`; the trusted observer verifies the actual immutable publication/absence and stopped-runtime evidence instead of trusting the declared outcome.
- `PUT/DELETE /jobs/{id}/members/{principal_id}`: job-admin membership changes; at least one effective admin must remain.
- `POST /jobs/{id}/purge`: authorized removal of a terminal job with no live runtime; ownership/audit tombstones remain until deletion is confirmed.

Cancellation during an unresolved publication can enter `NEEDS_ATTENTION / reconciliation_required` even after workers stop. The manager preserves the cancellation intent and retained evidence; an operator must resolve the actual publication before cleanup and final outcome advance. A missing acknowledgement does not prove that the write was absent.

Resource reservations are durable and gang components start only after every required node acknowledges them. Queue ordering is FIFO within compatible pools with at most three younger-job backfills. Lost node contact quarantines capacity; an expired heartbeat does not authorize reuse.

The first reservation establishes one absolute deadline. Provisioning, participant waiting, automatic infrastructure retries, and subsequent queue waits count against it. Automatic transient retries use 1/2/4-minute delays, at most three times. Plugins/model validation errors fail instead of being retried indefinitely.

The target is an absolute final round. Restart reads durable `main`, completes immediately if the target is already reached, or runs only the remaining rounds. Unknown publication outcomes enter reconciliation; they are never blindly republished.

## 6. Workload service boundary

Configure a fixed workload issuer and distinct Exchange, transfer gateway, and node audiences:

```text
HF2L_JOBS_WORKLOAD_ISSUER=https://workload.example.invalid
HF2L_JOBS_WORKLOAD_EXCHANGE_AUDIENCE=exchange-managed
HF2L_JOBS_WORKLOAD_GATEWAY_AUDIENCE=hf2l-transfer
HF2L_JOBS_NODE_AUDIENCE=hf2l-nodes
HF2L_JOBS_WORKLOAD_PRIVATE_KEY_FILE=/etc/hf2l/secrets/workload-signing.pem
HF2L_JOBS_WORKLOAD_PUBLIC_KEY_FILE=/etc/hf2l/workload-public.pem
```

Keep signing keys and each execution's mTLS key outside job sandboxes. Workload tokens bind job, attempt, component, space, grant, epoch, and certificate thumbprint, with a maximum 300-second lifetime. Exchange also checks current membership and its active grant ledger; copying a token to another execution does not confer authority.

The execution issuer requires an operator CA/key with valid critical CA/signing extensions and SKI. Issued client identities carry key-derived SKI, issuer-matching AKI, critical digital-signature usage, and client-auth-only EKU. Run the [strict CA/TLS preflight](../deploy/jobs/README.md#certificate-authority-and-strict-tls-preflight) before enabling service/node connections; retain strict chain and purpose verification.

The managed mTLS ingress is separate from public human/legacy traffic. Verified peer identity must come from trusted TLS transport, not forwarded certificate headers. Transfers use the authenticated gateway and structured per-execution proxy operations. Private origin storage URLs and credentials are not workload artifacts.

The runtime must enforce private source/state/cache volumes, read-only source/image, enforced writable-volume limits, CPU/memory/PID bounds, and default-deny egress. Only its assigned operation proxy is reachable. An unavailable or unhealthy isolation profile refuses execution.

### Exchange managed configuration

Configure the shared Exchange server explicitly for the same workload issuer/key and Exchange audience as the manager broker:

| Exchange variable | Required binding |
| --- | --- |
| `EXCHANGE_WORKLOAD_ISSUER` | Equals `HF2L_JOBS_WORKLOAD_ISSUER` |
| `EXCHANGE_WORKLOAD_PUBLIC_KEY` | PEM public verification key matching the manager signer |
| `EXCHANGE_WORKLOAD_AUDIENCE` | Equals `HF2L_JOBS_WORKLOAD_EXCHANGE_AUDIENCE`; configure explicitly |
| `EXCHANGE_TRUSTED_BACKEND_SECRET` | Private authenticated TLS-termination/backend channel secret, at least 32 bytes |
| `EXCHANGE_PROVISIONING_PRINCIPAL_IDS` | Trusted human/service provisioner principal IDs only |
| `EXCHANGE_DOWNLOAD_BROKER_PRINCIPAL_IDS` | Explicit trusted dashboard download broker principal IDs only |

Exchange's standalone workload-audience default is `exchange-workload`, while the manager broker default is `exchange-managed`; an explicit common value is necessary. This configuration is additive: existing deployments without a workload issuer keep their legacy authentication behavior.

Apply Exchange migration `0003_workload_grants` before enabling managed services. It retains the existing event sequence migration. Managed namespace retirement is idempotent and requires revoked grants; it retains namespace history, membership, and grant/revocation tombstones. Physical blob deletion uses Exchange's cleanup worker. A pending blob cleanup must not be reported as completed deletion.

## 7. Retention and recovery

Default raw logs, source snapshots, and checkpoints expire 90 days after termination, configurable per project. Metadata, outcome, history, ACLs, and provenance remain until authorized purge. Expired artifacts appear as expired entries. Retained storage remains charged until physical deletion is confirmed. Gang admission and static-fit validation reserve collection capacity of component disk plus 4 MiB before execution. Logical artifact bytes transfer to child records while the unused parent remainder stays charged for physical blocks and directory metadata; parent plus children retain the conservative cap. The full execution-state disk budget also remains charged until purge. Project storage quotas are conservative capacity bounds, not exact payload billing. Central source-fetch accounting settles actual snapshot filesystem blocks and owned metadata after temporary-workspace cleanup. Node-private source/build copies retain their conservative Git/filesystem peak reservation until confirmed purge, deduplicated across attempts for the same job/component. These ledgers cover separate physical copies and can retain different amounts.

An explicitly purged job is omitted from current, queue, and history lists. An authorized direct `GET /jobs/{id}` retains a minimal audit tombstone containing identity/outcome/timestamps without the specification, participants, or resource summary. Current job ACLs still apply to that tombstone; unrelated or revoked readers receive 404. Purge does not restore expired content.

Exchange model/update bytes also prepay a separate object-store allowance of `owner.disk_bytes * (1 + target_round * (1 + participant_count))`, held across attempts and termination. The exact namespace/principal quotas bind the owned space. Release requires authoritative retirement plus confirmed physical blob cleanup; run the Exchange worker. This approved object-store allocation is distinct from manager statvfs capacity and node disks.

An execution proxy rejects known revoked assignment authority with a bounded 403 before consuming the request body or contacting Exchange/storage. Known transient credential-provider failures return a bounded 503 for reconciliation; neither response grants a fallback identity or broadens access.

Unresolved provider writes retain cleanup/accounting fences. URL/JWT/lease expiry and local process death do not prove an in-flight provider write has finished. The deployment guide describes selected Exchange `repair-transfers` maintenance after all writers stop and actual provider quiescence is established; repair schedules cleanup rather than confirming physical deletion.

Cancellation before dispatch confirms cleanup only after the controller proves that the current attempt has no reservations, provisioning effects, resources, assigned node, or unfinished dispatch. Historical attempts must already be fenced, and unknown operations require their exact authoritative closure. The proof is durable and audited, so restart can safely complete previously interrupted queued cancellation. Uncertain external effects retain cleanup and accounting fences. Stopping an execution proxy that never started does not create new resource directories. Legacy empty proxy directories can be removed only for a proven initial attempt with no effects; removal checks ownership, permissions, mount identity, allowed directory names, and emptiness, and never adopts a marker or deletes a file. Retry cleanup continues through ordinary ownership-marker validation.

A terminal result and `cleanup_status` are independent. Failed cleanup remains visible and keeps affected resources charged or quarantined. Cleanup only deletes resources recorded as owned by the job/attempt/component. On restart, the controller reconciles durable operations and resource ownership rather than assuming absence or replaying unknown work.

For operational readiness and executed tests, consult the [implementation validation record](validation/2026-10-09-multi-job-implementation.md).

## 8. Exporting results

Use the [authenticated export utility](JOB_EXPORTS.md) to retain checkpoints, outputs, logs, and sanitized metadata before configured artifact expiry. The utility verifies downloaded sizes and hashes, follows API pagination, and reports incomplete exports. It requires an authorized session and an explicit HTTPS Manager origin and output directory.
