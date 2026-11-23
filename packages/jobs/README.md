# HF²L job manager and Python execution adapters

The job manager server is implemented in Go. It provides authorized job creation
and history, resource queues, lifecycle management, a browser dashboard, and
trusted execution services. The Python manager/server implementation has been
removed; installing this Python package does not install a server.

## Build the Go services

From the repository root, on Linux with Go 1.26 or later:

```sh
mkdir -p dist
go -C packages/jobs build -trimpath -o ../../dist/hf2l-jobs ./cmd/hf2l-jobs
./dist/hf2l-jobs --help
```

Read the [Go manager guide](../../docs/GO_JOB_MANAGER.md),
[Go Docker Compose guide](../../deploy/compose/go/README.md), and
[managed deployment guide](../../deploy/jobs/README.md). The dashboard and
application interface, scheduling controller, node services, transfer gateway,
and execution proxies are Go components. Their configuration and deployment
remain explicit operator tasks.

## Python training/build adapters

The `hf2l-jobs` Python distribution now contains only the sandboxed application
adapters and their immutable input contracts. A sandbox is the isolated execution
environment that constrains a job's files, resource use, and network access.
Python 3.14 or 3.15 is required.

Install the adapter package alongside the HF²L application and Exchange
client library when building the approved training image. The
[deployment image build](../../deploy/jobs/README.md#build-the-trusted-runtime-image)
selects Python 3.14. For a manual installation from the repository root in
the image build environment, `python3.14` selects the same Python release.

```sh
python3.14 -m pip install ./packages/jobs
python3.14 -m hf2l_jobs.runtime --help
```

The equivalent installed command is `hf2l-jobs-runtime`. There is no Python
`hf2l-jobs` server command. The Go executor launches the fixed
`python -m hf2l_jobs.runtime --config /run/hf2l/runtime.json` command inside its
qualified sandbox. The configuration identifies one training or offline-build
operation; it cannot select a manager server.

The package's required dependency is Pydantic, the library that checks the
adapter input fields. The optional `build` dependencies provide the approved
Python build frontend and package-format checks for offline wheel builds. A
wheel is an installable Python package archive. Source hooks run only in the
isolated build worker, using verified local inputs and approved dependencies.
Training libraries belong in qualified worker images, not in Go service images.

## Managed execution

Each managed job has its own Exchange space, immutable source snapshot,
execution identity, state, logs, and artifacts. The Go manager coordinates the
job; Python adapters run approved training, evaluation, and aggregation.
Participant data remains under participant control.

Runtime qualification and operational acceptance are required before enabling
job admission. The current managed executor supports the qualified processor-only
`runsc-cpu-v1` profile and its assigned local request-forwarding socket. It rejects
nonzero graphics-processor limits. Native participant training on graphics
processors remains a separate workflow.

Removing the Python servers does not change the Go database schema or authorize
reinitializing retained databases. Follow the Go operational guides for backups,
explicit migrations, service startup, and deployment checks.
