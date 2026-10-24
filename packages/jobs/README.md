# HF²L job manager

`hf2l-jobs` provides an independently packaged control plane for multiple federated learning jobs in one deployment: authorized job creation and history, a durable resource queue, lifecycle reconciliation, a packaged web dashboard, and trusted Linux execution components.

Managed jobs use FedAvg with a separate Exchange space, immutable source snapshot, workload identity, state, logs, and artifacts per job. Training plugins execute inside a qualified CPU sandbox. Participant data remains on participant machines.

## Native Go manager

The Go implementation covers the manager API, authentication, scheduling,
lifecycle, provisioning, node/participant services, gateways/proxies, collection,
and retention. It embeds the same dashboard and uses the existing manager schema
and API contracts. It does not invoke a Python manager through HTTP, RPC, or a
manager subprocess.

From the repository root, on Linux with Go 1.26 or later:

```sh
mkdir -p dist
go -C packages/jobs build -trimpath -o ../../dist/hf2l-jobs ./cmd/hf2l-jobs
./dist/hf2l-jobs --help
```

Read the [Go build, deployment and cutover guide](../../docs/GO_JOB_MANAGER.md).
The independent Exchange service and sandboxed Python FL training/build
application adapters remain separate dependencies. Runtime qualification and
operational acceptance are required before enabling admission.

## Python reference installation

The Python implementation remains available for compatibility checks and
controlled rollback. From a checkout, install its dependencies into a dedicated
environment:

```sh
python -m pip install -e 'packages/exchange[server]' -e '.[examples]' -e 'packages/jobs[server]'
hf2l-jobs --help
```

The distributions require Python 3.11 or later. CI checks clean manager/server wheels on Python 3.11–3.14; functional cohort scope and exact versions are in the [validation report](../../docs/validation/2026-10-09-multi-job-implementation.md). PostgreSQL is the deployment database; SQLite supports isolated tests. Trusted bootstrap includes separate bounded source-filesystem and model-object pools.

## Operation

The Go binary retains the operational command names and trusted configuration
shape below. Select the executable explicitly; do not run competing Go and
Python controllers against the same retained jobs.

The package exposes `hf2l-jobs init-db`, `migrate-db`, `serve`, `controller`, `node-agent`, `node-api`, `managed-node`, `participant-agent`, `gateway`, `exchange-edge`, `proxy`, `runtime`, and trusted local `admin` commands. The server serves both `/api/jobs/v1` and its packaged dashboard. Node.js is not required. Services require explicit trusted configuration and schema initialization/migration; installing the package does not provision PostgreSQL, identity providers, certificates, storage, or persistent service units.

See the repository [operator guide](../../docs/JOB_MANAGER.md) for configuration, resource admission, source/image approvals, authentication, lifecycle actions, and retention. See the [deployment guide](../../deploy/jobs/README.md) for the sandbox qualification and service topology. The [design](../../docs/MULTI_JOB_DESIGN.md) defines the isolation and lifecycle contracts.

## Compatibility

Existing standalone HF²L CLI workflows and unmanaged Exchange deployments remain separate. Managed jobs use their own control-plane database and explicitly configured workload authorization. Managed execution currently supports the qualified, networkless `runsc-cpu-v1` CPU profile and an assigned Unix operation proxy. The executor refuses nonzero GPU limits. Standalone native GPU training is separate; managed GPU and Kubernetes execution require their own implementation and qualification.
