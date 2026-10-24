# Job manager deployment

For the native binary and cutover procedure, start with the [Go manager guide](../../docs/GO_JOB_MANAGER.md).
This runbook supplies shared topology, qualification, and operational contracts;
select the intended Go or reference Python executable explicitly. Runtime helpers
and sandboxed Python FL application adapters retain their existing role.

The Go transfer gateway uses the independent Exchange private HTTPS backend.
The [native Go Exchange service](../../docs/GO_EXCHANGE.md) can supply that
backend with `serve-gateway-backend`; keep API, managed ingress, and private
transfer listeners distinct. The Python reference remains a rollback option.
Apply the Go guide’s [backend configuration](../../docs/GO_JOB_MANAGER.md#independent-exchange-private-transfer-backend)
before using the gateway configuration fragments below. Its control interface
is separate from both the public Exchange API and the managed workload ingress.

Use this runbook to configure the HF²L manager, its PostgreSQL database, controller, trusted node agent, shared Exchange service, transfer gateway, and per-execution proxies. The repository provides runtime helpers and service commands; it does not provide a complete production stack installer. Read the [operator guide](../../docs/JOB_MANAGER.md) for configuration, catalog approvals, job creation, and lifecycle actions.

## Trusted service boundaries

| Service | Access and credentials |
| --- | --- |
| Manager/dashboard | Public HTTPS; human OIDC/session authentication |
| Manager PostgreSQL | Private control plane; no job access |
| Controller/provisioner | Trusted catalog, signing keys, resource/ownership ledgers |
| Node agent | Trusted qualified runtime socket and local reservation/watchdog ledger |
| Managed Exchange ingress | Dedicated mTLS listener; current workload grant and membership checks |
| Transfer gateway | mTLS workload grant checks; private origin storage access |
| Execution proxy | One assigned Unix socket per component; its mTLS key stays outside the sandbox |

The public human/legacy Exchange ingress rejects managed workload tokens. Do not forward unverified certificate identity headers into managed services. Node/provisioning routes are private and require a distinct node audience. The private blob origin is never a workload-accessible endpoint.

The runtime has no ordinary network connectivity: its only approved service access is the assigned Unix operation proxy. Each job/component owns separate source, writable state, cache, logs, and bounded volumes. Never mount the workspace parent, host home, other jobs, or a runtime socket.

## Certificate authority and strict TLS preflight

Use an operator-approved execution CA with a valid certificate/private-key pair, critical `CA=true` BasicConstraints, critical certificate-signing KeyUsage, and a Subject Key Identifier (SKI). Trust bundles for node/service identities must also contain a valid chain with the correct purpose and hostname. Keep CA/private identity keys on the trusted issuer or owning service; nodes receive only the execution CA's public certificate.

For a new direct execution CA, run this as its trusted administrator with an existing private parent directory. The new directory must not already exist:

```sh
set -eu
umask 077
: "${HF2L_PKI_PARENT:?Set an existing operator-owned private PKI directory}"
HF2L_CA_DIR="$HF2L_PKI_PARENT/execution-ca"
mkdir -m 0700 "$HF2L_CA_DIR"
cat > "$HF2L_CA_DIR/ca.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = ca_extensions
prompt = no
[dn]
CN = HF2L execution CA
[ca_extensions]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out "$HF2L_CA_DIR/client-ca-key.pem"
openssl req -new -x509 -sha256 -days 730 \
  -key "$HF2L_CA_DIR/client-ca-key.pem" \
  -config "$HF2L_CA_DIR/ca.cnf" \
  -out "$HF2L_CA_DIR/client-ca.pem"
chmod 0600 "$HF2L_CA_DIR/client-ca-key.pem"
openssl verify -x509_strict \
  -CAfile "$HF2L_CA_DIR/client-ca.pem" "$HF2L_CA_DIR/client-ca.pem"
openssl x509 -in "$HF2L_CA_DIR/client-ca.pem" -noout -checkend 86400
openssl x509 -in "$HF2L_CA_DIR/client-ca.pem" -pubkey -noout \
  > "$HF2L_CA_DIR/cert-public.pem"
openssl pkey -in "$HF2L_CA_DIR/client-ca-key.pem" -pubout \
  > "$HF2L_CA_DIR/key-public.pem"
cmp "$HF2L_CA_DIR/cert-public.pem" "$HF2L_CA_DIR/key-public.pem"
```

Point central `provisioner.client_ca_certificate` and `client_ca_key` at the resulting certificate/key, or install them into the configured private paths. Publish only the public certificate to execution trust stores. This CA signs client identities; service server certificates need their own approved issuer, server-auth purpose, and endpoint DNS/IP Subject Alternative Name.

All three automatic client issuance paths—central execution, local proxy, and artifact broker—issue `CA=false` leaves with key-derived SKI, issuer-matching Authority Key Identifier (AKI), critical digital-signature-only KeyUsage, and client-auth-only Extended Key Usage. Verify an actual issued client leaf and a server identity with the deployment's trust bundles:

```sh
openssl verify -x509_strict -purpose sslclient \
  -CAfile "$HF2L_EXECUTION_CA_CERT" "$HF2L_ISSUED_CLIENT_CERT"
openssl verify -x509_strict -purpose sslserver \
  -verify_hostname "$HF2L_SERVICE_DNS" \
  -CAfile "$HF2L_SERVICE_CA_CERT" "$HF2L_SERVICE_CERT"
```

For an IP endpoint use `-verify_ip` with its actual address. Include approved intermediate certificates with `-untrusted` when the leaf's issuer is an intermediate. Confirm service/client private keys match their certificates and that the chain covers the configured execution lifetime. Preserve Python/OpenSSL strict verification; do not clear `VERIFY_X509_STRICT` or bypass chain, purpose, or hostname checks to admit a noncompliant certificate.

## CPU runtime setup

The administrator helper `runtime/setup.py` requires Linux x86_64, Python 3.12 or later, cgroup v2, Docker, systemd, and approved noninteractive `sudo` access to the explicit runtime operations. The manager distribution itself supports Python 3.11 or later.

Choose a new short absolute runtime directory owned by the operator, at least three path components below `/`, with enough space for its dedicated Docker data and bounded job volumes. Unix socket path limits apply. The helper refuses system Docker roots and foreign/unmarked directories. Verified runtime executables are staged in an owned `/opt/hf2l-jobs-runtime-<id>` directory so unprivileged runtime sidecars can traverse them without broadening private home-directory permissions. It neither rewrites `/etc/docker` nor restarts the system Docker service.

```sh
python3 deploy/jobs/runtime/setup.py install --root /srv/hf2l/runtime
python3 deploy/jobs/runtime/setup.py start --root /srv/hf2l/runtime
python3 deploy/jobs/runtime/setup.py status --root /srv/hf2l/runtime
```

The install pins official gVisor release `20261005.0`, downloaded over HTTPS and verified against both a hard-coded SHA-512 and the official HTTPS checksum. This is checksum verification, not a signature claim.

```text
archive SHA-512:
79869ae9a589355a46d46fdac068d9a954e741741ffe77c64e38c56ea955498c1cb04e9bce44e1cce5155333e6b76bee72347c6661bb7c78fd2fe3aad198c8fe

runsc SHA-256:
210b437a9cfae51e8f8c9074ed19b8b5e59477178e2e391a18117d8d6b924f7a
```

The owned runtime uses separate containerd and Docker sockets, data/state roots, and namespaces. Both daemons run in owned systemd transient units with private network namespaces and bounded CPU/memory/tasks. Docker uses `runsc`, sandbox netstack, networkless containers, private cgroup namespaces, no packet/raw-network access, no runtime flag override, and a separate configuration tree. It permits the specifically mounted execution Unix socket, while direct filesystem access remains disabled.

Daemon startup bounds Go threading with `GOMAXPROCS=2` and pins both daemons to an explicit host CPU mask. For a new runtime, `setup.py start --cpu-count N` selects up to N CPUs available to the operator; the default maximum is 2 and a one-CPU host is supported. Its private `runtime-policy.json` records the requested count and exact selected mask. Restart reuses that policy, and unavailable configured CPUs refuse startup. Changing the policy requires a new owned runtime root and fresh isolation and backing-I/O qualification.

The qualified profile binds the policy file hash, requested count, exact mask, and threading environment. Setup, both qualifiers, and the executor compare the active daemon/containerd affinity with that identity; modified policy bytes or process affinity refuse admission. Select a count suitable for the deployment's capacity before qualification.

Install/start success reports `ready_for_qualification`; it does not establish a qualified profile. Preload an approved immutable runtime image into that explicit daemon. Never choose a mutable tag at job launch.

## Build the trusted runtime image

The deployment builder `runtime/build_image.py` stages the trusted application, Exchange, and manager wheels plus an exact, hashed dependency wheelhouse on the trusted host. This builds the deployment runtime, not a submitted job's package hooks. Its Docker build is offline (`--network=none`).

The image builder targets CPython 3.14/`cp314`, with CPU Torch `2.14.1+cpu`; other Python/image ABI combinations require qualification. Preload and independently approve the immutable Python 3.14 base image in the owned daemon. Pass the deployment's actual operator-approved immutable local base image ID with `--base-image`; the builder requires it explicitly and does not assume a previously qualified image exists.

```sh
python3 deploy/jobs/runtime/build_image.py \
  --docker-host unix:///srv/hf2l/runtime/docker.sock \
  --base-image sha256:YOUR_ACTUAL_APPROVED_BASE_IMAGE_DIGEST \
  --python /usr/bin/python3.14 \
  --uv /usr/local/bin/uv \
  --output-dir /srv/hf2l/validation/runtime-image
```

Use the deployment's actual persistent UV path and host CPython 3.14 interpreter. The output parent stays outside the source checkout. The builder verifies the preloaded base, wheel hashes, runtime ABI, package installs, and nonroot read-only/networkless CPU training/checkpoint smoke. It emits an immutable `image_id`, manifests, dependency hashes, and logs. `--stage-only` stages inputs and does not build or qualify an image; preparing uncached host inputs can access package indexes.

For a frozen release, pass `--source-commit` with the full Git commit and run from its clean checkout. Tracked, untracked, and ignored additions are refused. Keep caches and generated manifests outside that checkout.

### Prepare and approve cached inputs

A cached rebuild requires three separately approved wheelhouses:

| Argument | Contents and manifest |
| --- | --- |
| `--build-wheelhouse` | Exactly seven host frontend wheels; `build-wheel-manifest.json` is in the wheelhouse's **parent** directory |
| `--project-wheelhouse` | Exactly `hf2l`, `hf2l-exchange`, and `hf2l-jobs`; `manifest.json` is inside the wheelhouse |
| `--reuse-wheelhouse` | A complete prior runtime dependency cache, including the pinned worker build frontends and CPU Torch; `wheel-manifest.json` is inside the wheelhouse |

The seven host frontend pins are `build==1.6.1`, `packaging==26.3`, `pip==26.2.1`, `pyproject-hooks==1.3.3`, `setuptools==84.0.0`, `setuptools-scm==9.2.2`, and `wheel==0.48.0`. The dependency cache must include worker frontends `build==1.6.1`, `pyproject-hooks==1.3.3`, and `wheel==0.48.0`, plus the requested CPU Torch version and all runtime dependencies.

Frontend and runtime dependency manifests contain records with `filename`, normalized distribution `name`, exact `version`, and lowercase SHA-256 `sha256`; `size_bytes` is optional. Records can be a JSON array or an object with a `wheels` array. A project manifest accepts this same format or legacy records containing only `filename` and `sha256`. For legacy project records, the builder derives name/version from verified wheel metadata; when either identity field is supplied, both are required and must match.

Prepare the frontend cache while connected to the operator's approved package sources. Run from the trusted checkout with an approved CPython 3.14 interpreter that already has pip. Set `HF2L_BUILD_PYTHON` to that interpreter and `HF2L_FRONTEND_CACHE` to a new absolute directory outside the checkout, whose parent already exists:

```sh
set -eu
test -n "$HF2L_BUILD_PYTHON" && test -n "$HF2L_FRONTEND_CACHE"
umask 077
HF2L_FRONTEND_CACHE="$HF2L_FRONTEND_CACHE" "$HF2L_BUILD_PYTHON" -B - <<'PYTHON'
import json
import os
from pathlib import Path
import subprocess
import sys
from deploy.jobs.runtime.build_image import (
    BUILD_FRONTEND, ROOT, digest, verify_wheel_cache, wheel_metadata,
)

assert sys.version_info[:2] == (3, 14)
parent = Path(os.environ["HF2L_FRONTEND_CACHE"])
if (not parent.is_absolute() or ".." in parent.parts
        or any(p.is_symlink() for p in (parent, *parent.parents))
        or parent == ROOT or ROOT in parent.parents):
    raise ValueError("Cache must be an absolute safe path outside the checkout")
parent.mkdir(mode=0o700, exist_ok=False)
wheels = parent / "build-wheelhouse"
wheels.mkdir(mode=0o700)
subprocess.run([
    sys.executable, "-m", "pip", "download", "--only-binary=:all:",
    "--no-deps", "--dest", str(wheels),
    *[name + "==" + version for name, version in sorted(BUILD_FRONTEND.items())],
], check=True)
records = []
for path in sorted(wheels.glob("*.whl")):
    name, version = wheel_metadata(path)
    records.append({"filename": path.name, "name": name, "version": version,
                    "sha256": digest(path), "size_bytes": path.stat().st_size})
manifest = parent / "build-wheel-manifest.json"
with manifest.open("x") as stream:
    json.dump({"wheels": records}, stream, indent=2, sort_keys=True)
    stream.write("\n")
verify_wheel_cache(wheels, manifest, BUILD_FRONTEND)
PYTHON
```

A newly generated checksum records the bytes obtained; it does not independently establish their approval. Compare these records with approved upstream or internal release provenance, approve the exact hashes, and retain that evidence before using the cache for a build.

The initial online build produces `project-wheels` and a dependency `wheelhouse/wheel-manifest.json`. Its `project-wheels` directory needs a project manifest before reuse. Select the three project wheels built from the approved frozen source and record their hashes outside the checkout. Set `HF2L_PROJECT_WHEELS` to that existing absolute directory; this example refuses to overwrite an existing manifest:

```sh
set -eu
test -n "$HF2L_BUILD_PYTHON" && test -n "$HF2L_PROJECT_WHEELS"
HF2L_PROJECT_WHEELS="$HF2L_PROJECT_WHEELS" "$HF2L_BUILD_PYTHON" -B - <<'PYTHON'
import json
import os
from pathlib import Path
from deploy.jobs.runtime.build_image import (
    PROJECT_NAMES, ROOT, digest, verify_wheel_cache, wheel_metadata,
)

wheels = Path(os.environ["HF2L_PROJECT_WHEELS"])
if (not wheels.is_absolute() or ".." in wheels.parts
        or any(p.is_symlink() for p in (wheels, *wheels.parents))
        or wheels == ROOT or ROOT in wheels.parents):
    raise ValueError("Project wheels must be a safe directory outside the checkout")
records = []
for path in sorted(wheels.glob("*.whl")):
    name, version = wheel_metadata(path)
    records.append({"filename": path.name, "name": name, "version": version,
                    "sha256": digest(path), "size_bytes": path.stat().st_size})
if len(records) != 3 or {r["name"] for r in records} != PROJECT_NAMES:
    raise ValueError("Expected exactly the three frozen project wheels")
manifest = wheels / "manifest.json"
with manifest.open("x") as stream:
    json.dump({"wheels": records}, stream, indent=2, sort_keys=True)
    stream.write("\n")
verify_wheel_cache(wheels, manifest)
PYTHON
```

Approve those project hashes against the recorded frozen source/build provenance. Keep the frontend, project, and dependency caches immutable after approval. Every cache wheel, including older project wheels in a reused dependency cache, is verified before Git, UV, or copying. Missing or additional wheels, duplicate identities, metadata/hash mismatches, and symlinks in cache paths are rejected. The three newly approved project wheels replace older project wheels when staging the runtime.

### Rebuild from all three verified caches

Set the variables below to the approved cache directories and full source commit, then run from the unchanged frozen checkout:

```sh
python3 deploy/jobs/runtime/build_image.py \
  --docker-host unix:///srv/hf2l/runtime/docker.sock \
  --base-image sha256:YOUR_ACTUAL_APPROVED_BASE_IMAGE_DIGEST \
  --source-commit "$HF2L_SOURCE_COMMIT" \
  --build-wheelhouse "$HF2L_FRONTEND_CACHE/build-wheelhouse" \
  --project-wheelhouse "$HF2L_PROJECT_WHEELS" \
  --reuse-wheelhouse "$HF2L_RUNTIME_WHEELHOUSE" \
  --python /usr/bin/python3.14 \
  --uv /usr/local/bin/uv \
  --output-dir /srv/hf2l/validation/runtime-image
```

With `--reuse-wheelhouse`, both other cache arguments are required. The builder creates an unseeded host environment with UV offline/config suppression, installs the exact frontend wheels with no index or dependency resolution, and resolves runtime wheels from the verified local caches. Interpreter downloads and missing-input fallback downloads are disabled. Inherited pip/UV resolver settings are removed, and direct URL dependencies in the active approved wheels are rejected before subprocesses run. A missing pinned frontend, CPU Torch wheel, or unresolved runtime dependency fails the build. `--build-wheelhouse` without `--reuse-wheelhouse` reuses host tools while remaining host preparation can access package indexes.

Use the resulting worker `image_id` in runtime qualification, then approve that ID under the job catalog's `hf2l-cpu` image identifier. The Python base image ID is not the worker image approval. Image build/smoke alone does not admit jobs.

## Qualification and admission

Run adversarial qualification against the owned daemon and approved runtime image:

```sh
python3 deploy/jobs/runtime/qualify.py \
  --docker-host unix:///srv/hf2l/runtime/docker.sock \
  --daemon-config /srv/hf2l/runtime/daemon.json \
  --image sha256:YOUR_ACTUAL_APPROVED_IMAGE_DIGEST \
  --output-dir /srv/hf2l/validation/cpu-profile \
  --host-ip YOUR_HOST_IP
```

Replace the image and host address with actual operator-approved values. Run as a nonroot operator so sandbox UID/GID are nonzero. The qualifier creates only labelled synthetic resources in the selected daemon and records cleanup; any failed check leaves the result unqualified.

Qualification checks concurrent synthetic sandboxes, source/state/cache/log separation, host and foreign filesystem access, other execution sockets, runtime/socket access, denied network routes, read-only source/runtime, and CPU/PID/disk/tmpfs/OOM containment. These establish the tested CPU profile and do not qualify GPU drivers or Kubernetes.

Keep the ready-only `profile.json` separate from the qualified `executor-profile.json`; `setup.py status` deliberately rewrites only the ready-only report. Promote executor evidence only after the qualification result passes. The `publish-profile` action verifies the report checks, runtime/daemon hashes, Docker resource root, and current isolated-daemon health before producing `executor-profile.json`. Publish the passing report using:

```sh
python3 deploy/jobs/runtime/setup.py publish-profile \
  --root /srv/hf2l/runtime \
  --qualification /srv/hf2l/validation/cpu-profile/qualification.json \
  --resource-root /srv/hf2l
```

Use the actual report path printed by `qualify.py`. Point trusted executor configuration at the qualified `runsc-cpu-v1` profile and keep the associated node/pool capacity explicit. Set a pool healthy only after this evidence is verified. If the profile or active runtime policy is unavailable or unhealthy, the node refuses execution. There is no ordinary-process or plain-container fallback.

### Qualify physical backing I/O

The initial isolation profile also needs node-local backing-device qualification. Run the repository helper as the same trusted nonroot node operator, after the original profile publication:

```sh
python3 deploy/jobs/runtime/qualify_readonly_io.py \
  --profile /srv/hf2l/runtime/executor-profile.json \
  --root /srv/hf2l/validation/readonly-io \
  --base-image sha256:YOUR_ACTUAL_APPROVED_BASE_IMAGE_DIGEST
```

Use an operator-approved immutable Python-capable image already loaded in this explicit daemon; the helper does not pull an image. Its root must be private, inside the qualified owned resource root, and outside the source checkout, with at least 512 MiB free for bounded synthetic canaries. It probes uncached reads from source, dataset, build, and image backing paths while a sibling continues, validates actual executor device limits, and checks owned cleanup.

Only a passing complete report atomically adds `backing_io_qualified`, verified `backing_devices`, and the backing-I/O report path/hash/check count/time to the executor profile. It preserves the original isolation evidence, pins its parent image under a task-specific tag, and removes derived images with `--no-prune`. Isolation qualification alone does not satisfy the current executor's physical-I/O gate.

Republishing the original profile preserves supplemental admission only when the runtime, base policy, and private hash-verified report still match. Corrupt evidence refuses republication without overwriting the active profile; changed runtime evidence requires the backing-I/O qualifier again.

The executor verifies device/sysfs identities for its root, daemon image storage, source, build, and dataset inputs. Physical read/write limits apply to backing block I/O; cached pages are memory reads. Unsupported/nonblock-backed paths or changed device identities fail closed. Qualify each node's actual filesystem/device arrangement; copying another node's profile is not admission evidence.

## Trusted configuration examples

These are operational inputs, not job-request fields. Replace example paths, endpoints, certificates, principal IDs, and capacities with the deployment's approved values. Keep configurations operator-owned and not group/world writable; secret/key/token files must be private regular files (mode 0600).

The controller/node configuration can share one trusted file:

```json
{
  "service": {
    "host": "127.0.0.1",
    "port": 8082,
    "tls_certificate": "/etc/hf2l/tls/manager.pem",
    "tls_key": "/etc/hf2l/tls/manager-key.pem"
  },
  "executor": {
    "root": "/srv/hf2l/executions",
    "profile_path": "/srv/hf2l/runtime/executor-profile.json"
  },
  "node": {
    "node_id": "node-primary",
    "pool_id": "cpu-primary",
    "ledger_path": "/srv/hf2l/node-ledger.sqlite",
    "capacity": {
      "cpu_millicores": 6000,
      "memory_bytes": 12884901888,
      "disk_bytes": 73014444032,
      "pids": 128,
      "io_bps": 16777216
    },
    "dataset_bindings": {
      "alice-mnist": {
        "kind": "synthetic",
        "project_id": "research",
        "participant_id": "alice"
      },
      "bob-mnist": {
        "kind": "synthetic",
        "project_id": "research",
        "participant_id": "bob"
      }
    }
  },
  "provisioner": {
    "root": "/srv/hf2l",
    "exchange_endpoint": "https://exchange-admin.example.invalid",
    "admin_token_file": "/etc/hf2l/secrets/provisioner-token",
    "client_ca_certificate": "/etc/hf2l/tls/client-ca.pem",
    "client_ca_key": "/etc/hf2l/secrets/client-ca-key.pem",
    "managed_exchange_endpoint": "https://exchange-workload.example.invalid",
    "gateway_endpoint": "https://transfer.example.invalid",
    "service_ca_file": "/etc/hf2l/tls/service-ca.pem",
    "exchange_ca_file": "/etc/hf2l/tls/service-ca.pem",
    "allowed_source_hosts": [
      "github.com"
    ],
    "exchange_storage_pool_id": "model-objects",
    "exchange_storage": {
      "registration_id": "approved-s3",
      "endpoint": "https://private-s3.example.invalid",
      "bucket": "hf2l",
      "prefix": "exchange-v2/",
      "region": "us-east-1",
      "capacity_bytes": 34359738368
    }
  }
}
```

CPU/memory capacity must cover the registered pool. Physical node disk capacity must be at least twice the advertised pool disk budget plus 4 MiB to retain a verified copy during collection; this example node advertises 68 GiB physical capacity for the 32 GiB pool. `executor.root`, materialized resources, and provisioner paths must lie beneath the qualified resource root. Synthetic bindings are for the pilot; locally approved NPZ bindings use trusted node configuration `{"kind":"npz","host_path":"/srv/participant-data/alice/dataset.npz","project_id":"research","participant_id":"alice"}`. The node verifies the current assignment and regular, single-link, non-symlink local file before mounting it read-only; the provisioner supplies the worker path `/job/data/data.npz`. Job input cannot choose its host path.

### Submitted-source builds

A job may include a `build` component with its own pool/resource request. The controller reserves the gang, runs the build inside the qualified sandbox, and verifies its bounded outputs before starting consumers. It does not execute submitted hooks in the manager.

Register `provisioner.build_approvals` keyed by the immutable component ID. Each entry contains `approved_dependencies` (distribution name to exact installed version) and optional `project_subdir` (default `.`). Include the fixed `build` frontend and all required PEP 517 backend inputs; obtain their exact versions from the approved runtime's wheel manifest. The runtime image must contain those approved inputs.

Build dependencies and source commits are pinned. Builds have no network, source credentials, plugin secrets, or execution proxy. Requirements outside the approved inputs fail; they are not downloaded as a fallback. Private build state/output remains associated with the job's resource and retention ledgers. Node-private source/build peak storage is prepaid once per job/component across retries and remains reserved until confirmed purge; central snapshots have a separate settled-byte ledger. Verified wheel manifests bind each basename to its SHA-256 and byte count. Owner/client sandboxes receive these immutable files at `/job/build` and use the fixed offline installer (`pip --no-index --no-deps`) into their private `/job/state/site-packages`. A retry reuses the verified manifest; changed wheel bytes are rejected. The manager does not import plugins, run pip, or unpack submitted wheels.

### Job-bound plugin secrets

Approving a database secret reference is only the catalog gate. To enable delivery, add the same reference to the controller's trusted `secrets` section:

```json
{
  "secrets": {
    "private_root": "/srv/hf2l/plugin-secrets",
    "references": {
      "training-api-key": {
        "project_id": "research",
        "path": "/srv/hf2l/plugin-secrets/training-api-key",
        "roles": [
          "participant"
        ],
        "option_names": [
          "api_key"
        ],
        "purpose": "plugin_option"
      }
    }
  }
}
```

The source file and its parent directory must be private; values are limited to 8 KiB. The approved database reference path must equal this trusted path. Optional `component_ids` restrict delivery further. A job requests only `secret_refs: {"api_key":"training-api-key"}`, and the resolver checks project, component role, option name, and any component restriction. The value is copied only into the assigned worker's private readonly secret input; credentials never enter searchable job metadata or browser storage. Builds do not receive plugin secret inputs.

Merge this section into the controller configuration; use secret-file references, not literal secret values in job options.

For a managed-node or autonomous participant-agent, approve the node's own private file with an optional `node.secret_refs` mapping. Its field names match the controller approval:

```json
{
  "node": {
    "secret_refs": {
      "training-api-key": {
        "project_id": "research",
        "path": "/etc/hf2l/local-plugin-secrets/training-api-key",
        "roles": ["participant"],
        "option_names": ["api_key"],
        "purpose": "plugin_option"
      }
    }
  }
}
```

Merge this fragment into the complete node configuration. On a managed node, also include `"secret_refs": ["training-api-key"]` in its local source/runtime catalog. An autonomous agent derives those approved IDs from `node.secret_refs`; its `participants.agent.catalog` accepts only sources, runtime images, and allowed source hosts. The local project/role/option/component policy must match the immutable assignment's approved secret-option names; a missing assigned approval fails. Secret source files remain outside worker mounts, and only the assigned readonly manifest enters that worker. Node configuration carries local plugin secrets and public verification material; the manager's database, signing key, provisioning token, and CA private key stay on the manager.

Gateway configuration:

```json
{
  "gateway": {
    "host": "127.0.0.1",
    "port": 8444,
    "tls_certificate": "/etc/hf2l/tls/gateway.pem",
    "tls_key": "/etc/hf2l/secrets/gateway-key.pem",
    "client_ca_file": "/etc/hf2l/tls/client-ca.pem",
    "origin_endpoints": [
      "https://storage.internal.example.invalid"
    ],
    "origin_ca_file": "/etc/hf2l/tls/storage-ca.pem",
    "max_part_bytes": 67108864,
    "max_download_bytes": 1099511627776
  }
}
```

The gateway uses the same Exchange database/storage configuration as Exchange through `EXCHANGE_*` environment variables. Its workload audience is the manager broker's gateway audience (`hf2l-transfer` by default). Origin endpoints are an explicit allowlist; they are not user-selected URLs.

Managed Exchange edge configuration:

```json
{
  "boundaries": {
    "exchange": {
      "host": "127.0.0.1",
      "port": 8443,
      "backend_endpoint": "https://exchange-backend.internal.example.invalid",
      "backend_secret_file": "/etc/hf2l/secrets/exchange-backend-secret",
      "ca_file": "/etc/hf2l/tls/service-ca.pem",
      "tls_certificate": "/etc/hf2l/tls/exchange-edge.pem",
      "tls_key": "/etc/hf2l/secrets/exchange-edge-key.pem",
      "client_ca_file": "/etc/hf2l/tls/client-ca.pem"
    }
  }
}
```

The `exchange-edge` CLI listener obtains the actual TLS peer certificate and authenticates its forwarding into the private managed Exchange backend with the configured backend secret. Stock Uvicorn does not supply this peer-identity contract by itself. Keep the managed backend inaccessible to jobs and public users.

### Private node callback listener

The manager's public `serve` process does not trust client-supplied certificate headers. Run node callbacks on the separate verified-mTLS listener:

```json
{
  "boundaries": {
    "nodes": {
      "host": "127.0.0.1",
      "port": 8445,
      "tls_certificate": "/etc/hf2l/tls/node-api.pem",
      "tls_key": "/etc/hf2l/secrets/node-api-key.pem",
      "client_ca_file": "/etc/hf2l/tls/node-client-ca.pem"
    }
  }
}
```

Merge `boundaries.nodes` into the central manager configuration, together with its `provisioner` and `nodes` and/or `participants` registrations. A boundaries-only file cannot compose the assignment services. Supply the manager database, OIDC, session/cursor, and workload broker environment, then run `hf2l-jobs node-api --config /etc/hf2l/jobs.json`. This listener obtains peer identity from actual TLS and validates the fixed node audience plus current assignment/grant ledger. Keep node JWTs and node identity keys outside worker sandboxes. Public manager traffic cannot supply this authority. For agents on another host, bind `boundaries.nodes.host` to the approved private network interface instead of the loopback example and route TLS directly to this listener; forwarded certificate headers do not substitute for verified mTLS.

### Manager storage for remote-only execution

A controller without a local execution node needs an explicitly bounded storage pool for its own source snapshots and provisioning files. These bytes stay on the manager; a remote compute allocation cannot account for them.

Set the central `provisioner.root` to an existing private directory owned by the manager service's Unix UID (mode 0700), and add `provisioner.storage_pool_id`:

```json
{
  "provisioner": {
    "root": "/srv/hf2l/manager",
    "storage_pool_id": "manager-source-storage"
  }
}
```

Merge these fields into the complete provisioner configuration; the two-field fragment does not replace its endpoint/key settings. Create `manager-storage.json` with exactly the supported fields:

```json
{
  "id": "manager-source-storage",
  "name": "Manager source storage",
  "node_id": "manager-storage",
  "disk_bytes": 8589934592
}
```

Select the disk capacity after reserving space for the operating system, other approved workloads, and safety headroom. It must cover source/Git/metadata peak reservations and retained content. Then run:

```sh
hf2l-jobs admin --config /etc/hf2l/jobs.json storage-pool-set \
  --file /etc/hf2l/manager-storage.json
```

The command validates actual writable/free filesystem capacity, private ownership and symlink-free ancestry, and pins the configured root's device/inode identity. It refuses duplicate manager-storage pools on the same backing filesystem and reductions below retained/reserved usage, and writes a transactional audit. Callers cannot supply another host root in the pool JSON. This storage-only pool has zero CPU/RAM, no GPU or sandbox profiles, and internally verified healthy status; it needs no runtime NodeAgent and grants no execution capacity.

Budget component scratch, its prepaid immutable collection copy (disk plus 4 MiB), source/fetch/build copies, shared remote auxiliary storage, and per-attempt private metadata. Static full-cost requests that can never fit are rejected before persistence; requests that fit an empty pool but face temporary usage remain queued. Dedicated manager-storage pools cannot be mutated through generic pool PUT or `pool-set`; use the trusted storage command.

Local/mixed deployments can charge manager files to the same explicitly configured local runtime pool. Remote-only deployments must use a separately qualified manager-storage pool. Node-private source/build/config/proxy files have their own prepaid capacity and historical cleanup receipts; neither ledger is released merely because a remote node stops replying.

## Exchange model-object storage

Model checkpoints and participant updates use a separate, explicitly approved S3 allocation. It is distinct from the manager's source filesystem pool and every execution-node disk pool. Merge these required fields into the central provisioner configuration:

```json
{
  "provisioner": {
    "exchange_storage_pool_id": "model-objects",
    "exchange_storage": {
      "registration_id": "approved-s3",
      "endpoint": "https://private-s3.example.invalid",
      "bucket": "hf2l",
      "prefix": "exchange-v2/",
      "region": "us-east-1",
      "capacity_bytes": 34359738368
    }
  }
}
```

The capacity is the operator-approved allocation for this fixed endpoint/bucket/prefix. Portable S3 has no physical-total-capacity discovery API; select the allocation from the storage provider's approved capacity. An empty relative prefix is also valid. The example reserves 32 GiB, enough for three retained seven-GiB namespace budgets in the operator guide.

Create `object-store-pool.json` with only the supported fields:

```json
{
  "id": "model-objects",
  "name": "Model objects",
  "disk_bytes": 34359738368
}
```

For the enrollment command, supply `EXCHANGE_S3_ENDPOINT`, `EXCHANGE_S3_BUCKET`, `EXCHANGE_S3_PREFIX`, and `EXCHANGE_S3_REGION` matching that trusted configuration. Supply its private command credentials through `EXCHANGE_S3_ACCESS_KEY`/`EXCHANGE_S3_SECRET_KEY` and optional `EXCHANGE_S3_SESSION_TOKEN`, or the approved AWS provider chain. Then run:

```sh
hf2l-jobs admin --config /etc/hf2l/jobs.json object-store-pool-set \
  --file /etc/hf2l/object-store-pool.json
```

Enrollment verifies actual bucket versioning and a scoped missing-object HEAD, rejects a different backend and duplicate endpoint/bucket/prefix registrations, checks capacity against the approved ceiling and existing usage, and records a sanitized transactional audit. The object-store pool has zero CPU/RAM/GPU and no execution profile. Generic pool PUT/`pool-set` cannot mutate it. Backend/service identity is hash-bound; credentials are not stored in the manager database, and manager startup does not need the S3 command credentials. Missing or changed approval refuses production admission.

For each immutable job, admission prepays one Project and object-store Pool allowance:

```text
namespace bytes = owner.disk_bytes * (1 + target_round * (1 + participant_count))
per-principal bytes = owner.disk_bytes * (target_round + 1)
```

The namespace covers the initial global model, each target-round global model, and every participant update; retries share the original allowance. The exact namespace and principal byte quotas are supplied to Exchange at space creation and checked again when binding the owned space. Existing Exchange record and metadata limits remain separate.

For the guide's owner disk of 1 GiB, target round 2, and two participants, the namespace allowance is 7 GiB and each principal allowance is 3 GiB. Include these bytes in the Project retained quota as well as the separate object-store capacity. Requests that cannot fit an empty approved allocation are rejected; temporary occupation queues them.

The gateway records a durable upload-write fence before any origin PUT bytes. It settles that exact fence only after the full declared body is consumed, a successful upstream acknowledgement is received, and the upstream stream is closed. Settlement can rearm owned cleanup after retirement. Timeout, disconnect, cancellation, non-success, or uncertain stream closure keeps the fence and storage charge pending for explicit repair.

Termination retains the full allowance. Authorized purge/expiry revokes grants, retires the owned namespace, and waits for authoritative `cleanup_pending: false` before releasing it. A request acknowledgement, missing node, or missing metadata response cannot release bytes. Run the Exchange cleanup worker so versioned objects and unfinished uploads are physically reclaimed; namespace, membership, and grant/audit history remain.

## Isolated managed nodes

Use `managed-node` when the controller dispatches to a separate node process or host. Its trust configuration is distinct from the local controller configuration above. The node has its own qualified executor, ledger, source/image approvals, identity key, and execution proxies. The manager retains its database, workload signer, provisioning token, and execution-CA private key.

Set the node's `HF2L_JOBS_WORKLOAD_ISSUER`, `HF2L_JOBS_WORKLOAD_PUBLIC_KEY_FILE`, `HF2L_JOBS_WORKLOAD_EXCHANGE_AUDIENCE`, `HF2L_JOBS_WORKLOAD_GATEWAY_AUDIENCE`, and `HF2L_JOBS_NODE_AUDIENCE` to the manager's fixed values. Omit `HF2L_JOBS_WORKLOAD_PRIVATE_KEY_FILE`. The node verifies grants and obtains only short-lived assignment credentials and public certificates from the private manager node API.

On each node, create a private local catalog such as `/etc/hf2l/node-catalog.json`:

```json
{
  "sources": [
    {
      "source_id": "hf2l-source",
      "projects": [
        "research"
      ],
      "commits": [
        "38a3d4121b6796cbfdd7f354645157852393a18a"
      ],
      "url": "https://github.com/IsaacYangSLA/hf_fl.git",
      "max_bytes": 8388608,
      "max_files": 1000,
      "max_git_bytes": 8388608,
      "max_git_files": 4000
    }
  ],
  "runtime_images": {
    "hf2l-cpu": "sha256:afa3d81ca179dd1bfe5f321d9104fbf57724c310b787ec8834f3aaea2faa49c4"
  },
  "allowed_source_hosts": [
    "github.com"
  ],
  "datasets": {
    "alice-mnist": [
      "alice"
    ],
    "bob-mnist": [
      "bob"
    ]
  }
}
```

The local source approval must match the centrally approved exact commit and source manifest. A trusted local `mirror_path` can replace `url`; it is an operator-selected object store, not a path supplied by a job. Preload and locally approve the exact runtime image digest. Qualify this node's runtime policy before starting admission.

Example managed node configuration:

```json
{
  "executor": {
    "root": "/srv/hf2l/executions",
    "profile_path": "/srv/hf2l/runtime/executor-profile.json"
  },
  "service": {
    "host": "0.0.0.0",
    "port": 9444,
    "certificate": "/etc/hf2l/tls/node-server.pem",
    "key": "/etc/hf2l/secrets/node-server-key.pem",
    "client_ca": "/etc/hf2l/tls/manager-client-ca.pem"
  },
  "node": {
    "node_id": "node-primary",
    "pool_id": "cpu-primary",
    "registration_id": "node-primary-v1",
    "ledger_path": "/srv/hf2l/executions/node-ledger.sqlite",
    "capacity": {
      "cpu_millicores": 6000,
      "memory_bytes": 12884901888,
      "disk_bytes": 73014444032
    },
    "registry_file": "/etc/hf2l/node-catalog.json",
    "manager_endpoint": "https://manager-node-api.example.invalid:8445",
    "manager_ca_file": "/etc/hf2l/tls/manager-server-ca.pem",
    "identity_certificate": "/etc/hf2l/tls/node-client.pem",
    "identity_key": "/etc/hf2l/secrets/node-client-key.pem",
    "manager_certificate_thumbprint": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "execution_ca_certificate": "/etc/hf2l/tls/execution-ca.pem",
    "exchange_endpoint": "https://managed-exchange.example.invalid",
    "gateway_endpoint": "https://transfer.example.invalid",
    "service_ca_file": "/etc/hf2l/tls/service-ca.pem",
    "dataset_bindings": {
      "alice-mnist": {
        "kind": "synthetic",
        "project_id": "research",
        "participant_id": "alice"
      },
      "bob-mnist": {
        "kind": "synthetic",
        "project_id": "research",
        "participant_id": "bob"
      }
    }
  }
}
```

Replace the example thumbprint with the base64url SHA-256 of the manager client certificate's DER bytes (43 characters without padding). Identity and server private keys remain private files. The node ledger and optional short `proxy_socket_root` must be inside its qualified executor root. Optional `node.build_inputs` supplies local approvals for each build component's exact dependencies and project subdirectory; optional `node.secret_refs` supplies local, job-scoped secret approvals.

Merge a matching endpoint registration into the manager's trusted configuration:

```json
{
  "nodes": {
    "client_certificate": "/etc/hf2l/tls/manager-client.pem",
    "client_key": "/etc/hf2l/secrets/manager-client-key.pem",
    "endpoints": {
      "node-primary": {
        "origin": "https://node-primary.example.invalid:9444",
        "ca_file": "/etc/hf2l/tls/node-server-ca.pem",
        "pool_id": "cpu-primary",
        "registration_id": "node-primary-v1",
        "certificate_file": "/etc/hf2l/tls/node-client.pem",
        "enabled": true
      }
    }
  }
}
```

The registration pins the node's client identity used for callbacks; the endpoint CA verifies its server identity. Configure either `certificate_file` or `certificate_thumbprint`, exactly one. Start `hf2l-jobs managed-node --config /etc/hf2l/managed-node.json`, then the manager's private `node-api` and controller. Mark the pool healthy through `admin pool-set` only after its registered mTLS qualification endpoint confirms current profile and capacity. Qualification uses a separate node-platform grant with no job authority; a caller cannot manufacture a job allocation to promote a pool.

## Participant machines and enrollment

An external participant contributes locally approved data and does not consume the manager's pool allocation. Run a separately qualified `participant-agent` on that machine. Use the same verification-only workload environment as managed nodes. The agent's local `node.pool_id` is `external`, and each local dataset entry must name its project and participant. NPZ paths belong only in trusted local configuration; training receives a fixed read-only path. For the LeNet example, the archive contains numeric `x` images shaped `[N,28,28]` or `[N,1,28,28]` and `y` labels shaped `[N]` in the range 0–9; images must be finite and the dataset nonempty. The loader disables pickled objects.

On the manager, approve a dataset binding such as `alice-local` for project `research`, participant `alice`, and node `alice-external`. Register its node identity and fixed mTLS endpoint:

```json
{
  "participants": {
    "client_certificate": "/etc/hf2l/tls/manager-client.pem",
    "client_key": "/etc/hf2l/secrets/manager-client-key.pem",
    "nodes": {
      "alice-external": {
        "certificate_file": "/etc/hf2l/tls/alice-node-client.pem",
        "dataset_bindings": {
          "alice-local": {
            "kind": "npz",
            "path": "/job/data/data.npz"
          }
        },
        "resources": {
          "cpu_millicores": 1000,
          "memory_bytes": 2147483648,
          "disk_bytes": 1073741824
        },
        "endpoint": "https://alice-node.example.invalid:9445",
        "ca_file": "/etc/hf2l/tls/participant-server-ca.pem",
        "enabled": true
      }
    }
  }
}
```

The participant agent uses:

```json
{
  "executor": {
    "root": "/srv/hf2l/executions",
    "profile_path": "/srv/hf2l/runtime/executor-profile.json"
  },
  "node": {
    "node_id": "alice-external",
    "pool_id": "external",
    "ledger_path": "/srv/hf2l/executions/node-ledger.sqlite",
    "capacity": {
      "cpu_millicores": 1000,
      "memory_bytes": 2147483648,
      "disk_bytes": 17179869184
    },
    "dataset_bindings": {
      "alice-local": {
        "kind": "npz",
        "host_path": "/srv/participant-data/alice/dataset.npz",
        "project_id": "research",
        "participant_id": "alice"
      }
    }
  },
  "participants": {
    "agent": {
      "manager_endpoint": "https://manager-node-api.example.invalid:8445",
      "manager_ca_file": "/etc/hf2l/tls/manager-server-ca.pem",
      "node_certificate": "/etc/hf2l/tls/alice-node-client.pem",
      "node_key": "/etc/hf2l/secrets/alice-node-client-key.pem",
      "certificate_ca_file": "/etc/hf2l/tls/execution-ca.pem",
      "managed_exchange_endpoint": "https://managed-exchange.example.invalid",
      "gateway_endpoint": "https://transfer.example.invalid",
      "service_ca_file": "/etc/hf2l/tls/service-ca.pem",
      "manager_certificate_thumbprints": [
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      ],
      "catalog": {
        "sources": [
          {
            "source_id": "hf2l-source",
            "projects": [
              "research"
            ],
            "commits": [
              "38a3d4121b6796cbfdd7f354645157852393a18a"
            ],
            "url": "https://github.com/IsaacYangSLA/hf_fl.git",
            "max_bytes": 8388608,
            "max_files": 1000,
            "max_git_bytes": 8388608,
            "max_git_files": 4000
          }
        ],
        "runtime_images": {
          "hf2l-cpu": "sha256:afa3d81ca179dd1bfe5f321d9104fbf57724c310b787ec8834f3aaea2faa49c4"
        },
        "allowed_source_hosts": [
          "github.com"
        ]
      }
    }
  },
  "boundaries": {
    "participants": {
      "host": "0.0.0.0",
      "port": 9445,
      "tls_certificate": "/etc/hf2l/tls/alice-node-server.pem",
      "tls_key": "/etc/hf2l/secrets/alice-node-server-key.pem",
      "client_ca_file": "/etc/hf2l/tls/manager-client-ca.pem"
    }
  }
}
```

Replace the manager certificate thumbprint and configure public CA files; the agent receives no CA private key. Start `hf2l-jobs participant-agent --config /etc/hf2l/participant-agent.json`. An authorized operator creates a job with Alice's `mode` set to `external` and `dataset_binding` set to `alice-local`, then enrolls `alice-external` from the dashboard or `POST /api/jobs/v1/jobs/{job_id}/participants/alice/enroll` with body `{"node_id":"alice-external"}`, quoted-version `If-Match`, and `Idempotency-Key`. Session requests also require CSRF and Origin headers. Keep at least two participants for the FedAvg quorum.

The central manager checks current job access and locally approved binding/identity before dispatch. The node verifies its own source/image/dataset approvals and the current assignment, and obtains public execution certificates through scoped CSR requests. Heartbeats, cancellation, stop acknowledgement, and retained-data deletion use the private node listener. A successor epoch waits for confirmed grant revocation and runtime/proxy termination. Offline participant cleanup remains pending and retains its resource charges until an exact owned-node receipt is confirmed.

## Exchange backend and service launch

Initialize/migrate the independent Exchange database with `hf2l-exchange migrate-db`. Configure its human issuer/audience, workload issuer/key/audience, provisioner/download-broker principals, database, private blob storage, and backend secret as described in the operator guide.

Start the ordinary trusted provisioner/public Exchange ingress and the separate private managed backend with explicit HTTPS:

```sh
python -m uvicorn hf2l_exchange.api:create_app --factory \
  --host 127.0.0.1 --port 8441 \
  --ssl-certfile /etc/hf2l/tls/exchange-admin.pem \
  --ssl-keyfile /etc/hf2l/secrets/exchange-admin-key.pem \
  --no-proxy-headers --no-access-log

python -m uvicorn hf2l_exchange.api:create_managed_app --factory \
  --host 127.0.0.1 --port 8442 \
  --ssl-certfile /etc/hf2l/tls/exchange-backend.pem \
  --ssl-keyfile /etc/hf2l/secrets/exchange-backend-key.pem \
  --no-proxy-headers --no-access-log
```

Expose only the intended public manager/ordinary ingress through approved HTTPS routing. The managed edge and gateway require mTLS, and the managed backend stays private. Certificate hostnames must match configured endpoint URLs. Loopback examples suit the single-host pilot. For remote agents, bind the managed edge/gateway and node callback listeners to approved private interfaces or use TCP TLS pass-through that preserves actual client-certificate verification at these listeners.

Run the Exchange worker as a supervised service with the same database and private storage environment before admitting jobs:

```sh
hf2l-exchange check-storage
hf2l-exchange worker
```

The worker verifies completed uploads and executes owned cleanup. Retired namespace budgets remain charged until this cleanup is confirmed; stopping the worker leaves cleanup pending.

### Repair unresolved provider writes

An expired URL, JWT, or local lease does not prove that a provider request has finished. A gateway crash or timeout also cannot establish that fact. Keep the affected cleanup and object-store budget pending until the write is conclusively resolved or externally fenced.

Use the existing trusted Exchange maintenance command with the deployment's Exchange database environment. Inspect the bounded inventory first:

```sh
hf2l-exchange repair-transfers
hf2l-exchange repair-transfers --attempt TRANSFER_ATTEMPT_ID
```

Inventory contains opaque `space_id`, `record_id`, and `attachment_id`, plus attempt state and eligibility. Match `space_id` to the affected job's authorized manager detail and select only its exact transfer attempts. No object key, provider upload ID, origin URL, or token is exposed. Repeat distinct `--attempt` arguments for at most 100 selected IDs; there is no job-filter flag or automatic global repair.

Before applying, stop **all write-capable Exchange API, managed edge, gateway, and worker processes**, and stop or fence any legacy direct-upload clients holding origin grants for the selected keys. Managed workers receive no origin URLs; stop their execution/control write paths as well. Establish separately that every selected provider write has finished or has been conclusively fenced at the provider. Keep those writers stopped during repair. The two affirmative flags record these operational assertions; the command cannot infer provider quiescence from elapsed time.

Then apply the exact checked selection:

```sh
hf2l-exchange repair-transfers --attempt TRANSFER_ATTEMPT_ID \
  --apply --writers-stopped --provider-quiesced
```

Restart the Exchange worker to perform the scheduled physical cleanup or completion recovery. Inspect the selected attempts again. For a retired job namespace, wait for authoritative `cleanup_pending: false` before the manager confirms purge or releases its object budget. A successful repair command clears an eligible fence and schedules work; it is not proof that raw objects have already been deleted. Resume write services after the required cleanup/reconciliation is confirmed. Job publication reconciliation remains an explicit manager operation when its outcome is unknown.

## Services and shutdown

The manager CLI provides:

```sh
hf2l-jobs serve --config /etc/hf2l/jobs.json
hf2l-jobs controller --config /etc/hf2l/jobs.json --interval 5
hf2l-jobs node-agent --config /etc/hf2l/jobs.json --interval 5
hf2l-jobs node-api --config /etc/hf2l/jobs.json
hf2l-jobs gateway --config /etc/hf2l/gateway.json
hf2l-jobs exchange-edge --config /etc/hf2l/exchange-edge.json
```

The runtime helper's `systemd-run --collect` units are transient. Install/start does not enable them at boot, and the repository supplies no persistent systemd units for this application stack. Provide operator-owned service definitions with private configuration/environment files, an explicit service UID, dependency ordering, bounded resources, and restart/stop policies. Keep the manager stop timeout longer than its configured graceful shutdown period.

After a reboot or daemon restart, start the owned runtime with its existing CPU policy, check the current isolation and backing-I/O evidence against the active runtime, and restore the private Exchange backend/edge, gateway, cleanup worker, node callback listener, and required agents. Keep pools unhealthy until their qualification and capacity checks succeed; then run the controller and expose the manager. Persist PostgreSQL, ownership ledgers, qualified profiles, source snapshots, and retained worker volumes across service restarts. A service restart is not permission to release reservations or delete retained bytes.

The controller creates and supervises per-execution proxy sockets automatically. The separate `hf2l-jobs proxy --config` command serves an explicitly assigned trusted proxy configuration when operating it independently. Use per-service trusted configuration and private key permissions. A per-execution proxy is not a shared browser ingress. The controller records intended operations before external side effects; the node enforces a local monotonic execution watchdog.

To shut down, stop admission, cancel/fence active jobs through the manager, confirm runtime termination and owned-container cleanup, then stop the owned daemon:

```sh
python3 deploy/jobs/runtime/setup.py stop --root /srv/hf2l/runtime
```

The helper refuses daemon stop while containers are running and preserves owned data. Do not delete retained state or release quarantined capacity before confirmed fencing/termination.

## Deployment limits and evidence

CPU `runsc-cpu-v1` is the implemented managed profile. The executor refuses nonzero GPU limits; GPU fields in resource schemas and scheduling ledgers do not provide a GPU runtime. GPU and Kubernetes execution require separate implementation and qualification. Standalone native GPU training remains a separate workflow. Participant training and raw datasets remain at participant machines; managed participant pools and dataset bindings require local approval.

The [implementation validation record](../../docs/validation/2026-10-09-multi-job-implementation.md) records exact tested versions, runtime provenance, service topology, test results, and cleanup. Production OIDC/provider, TLS certificates, private storage, and service supervision remain operator-supplied deployment configuration.
