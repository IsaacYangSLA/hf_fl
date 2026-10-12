# HF²L job manager

`hf2l-jobs` provides an independently packaged control plane for multiple federated learning jobs in one deployment: authorized job creation and history, a durable resource queue, lifecycle reconciliation, a packaged web dashboard, and trusted Linux execution components.

Managed jobs use FedAvg with a separate Exchange space, immutable source snapshot, workload identity, state, logs, and artifacts per job. Training plugins execute inside a qualified CPU sandbox. Participant data remains on participant machines.

## Installation

From a checkout, install the Exchange service, the FL application, and the manager into a dedicated environment:

```sh
python -m pip install -e 'packages/exchange[server]' -e '.[examples]' -e 'packages/jobs[server]'
hf2l-jobs --help
```

The distributions require Python 3.10 or later. Clean manager/server wheels are validated on Python 3.10–3.14; functional cohort scope and exact versions are in the [validation report](../../docs/validation/2026-10-09-multi-job-implementation.md). PostgreSQL is the deployment database; SQLite supports isolated tests. Trusted bootstrap includes separate bounded source-filesystem and model-object pools.

## Operation

The package exposes `hf2l-jobs init-db`, `migrate-db`, `serve`, `controller`, `node-agent`, `node-api`, `managed-node`, `participant-agent`, `gateway`, `exchange-edge`, `proxy`, `runtime`, and trusted local `admin` commands. The server serves both `/api/jobs/v1` and its packaged dashboard. Node.js is not required.

See the repository [operator guide](../../docs/JOB_MANAGER.md) for configuration, resource admission, source/image approvals, authentication, lifecycle actions, and retention. See the [deployment guide](../../deploy/jobs/README.md) for the sandbox qualification and service topology. The [design](../../docs/MULTI_JOB_DESIGN.md) defines the isolation and lifecycle contracts.

## Compatibility

Existing standalone HF²L CLI workflows and unmanaged Exchange deployments remain separate. Managed jobs use their own control-plane database and explicitly configured workload authorization. CPU execution is the initial managed profile; GPU and Kubernetes profiles require separate qualification.
