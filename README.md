# HF²L (hf_fl)

HF²L coordinates federated learning across organizations. Each participant trains
with its own data and shares a model checkpoint. The project aggregator combines
those updates and publishes the next shared model.

You can reuse an existing training job, choose where model artifacts are stored,
and automate rounds when ready. An optional job manager adds resource queues,
isolated execution, and a web dashboard.

This repository is an alpha implementation. Use the guides for the exact setup
and deployment requirements.

## Start here: your first federation

Follow **[Your first federation](examples/first_federation/README.md)**.
It starts with no HF²L services installed and walks through two complete rounds
using a tiny NumPy model.

| Who | What they do |
| --- | --- |
| **Org S — Service** | Deploy the shared services, manage accounts, and create/delegate the project. |
| **Org P — Aggregator** | Agree on the model, enroll participants, initialize the checkpoint, aggregate, evaluate, and publish. |
| **Org A — Alice** | Train locally on private data and submit an update. |
| **Org B — Bob** | Independently train locally and submit an update. |

Org S deploys the included [Compose stack](examples/first_federation/compose.yaml).
Org P, Alice, and Bob install client tools; they do not deploy server stacks.
The walkthrough needs no Hugging Face account, Torch, GPU, or external dataset.

A round follows this sequence:

1. Org P publishes a common starting checkpoint.
2. Alice and Bob download that exact version and train locally.
3. Each uploads an update and its training sample count.
4. Org P validates the updates, runs FedAvg, and publishes the next checkpoint.

To adapt your own trainer, start with
[Use your existing training job](examples/first_federation/README.md#use-your-existing-training-job).

## Choose how to run training

| Workflow | Use it when | Guide |
| --- | --- | --- |
| **Manual steps** | Keep your existing trainer: download → train → upload → aggregate. | [Training guide](docs/TRAINING_GUIDE.md#client-option-a-three-independent-steps) |
| **Training plugin** | Let HF²L call trusted local training/evaluation code. | [Plugin contract](docs/TRAINING_GUIDE.md#plugin-interface) |
| **Automatic listeners** | Have clients watch for new checkpoints and the owner publish completed rounds. | [Client and owner listeners](docs/CLIENT_LISTENER.md) |
| **Managed jobs** | Schedule multiple projects/jobs with permissions, capacity limits, and isolated CPU execution. | [Job manager](docs/JOB_MANAGER.md) |

Manual, plugin, and listener workflows support all four model-store backends
below. Managed jobs currently use Exchange-backed FedAvg and a separately
qualified CPU runtime.

For sequential training, there is also an explicit
[cyclic handoff workflow](docs/TRAINING_GUIDE.md#cyclic-federated-learning-without-fedavg).
Participant order is chosen by the caller.

## Replaceable components

### Model storage: four backends

Use `--backend` with the training and listener commands. Changing the backend
changes artifact transport; it does not require rewriting your trainer.

| Backend | Select with | Setup and limits |
| --- | --- | --- |
| **Local filesystem** | `--backend local` | [Local setup](docs/TRAINING_GUIDE.md#local-store). No server or account; requires a trusted local POSIX filesystem. Principal names provide attribution, not remote authentication. |
| **Hugging Face Hub** | `--backend huggingface` | [Hub setup](docs/TRAINING_GUIDE.md#hugging-face-hub). The default; participants submit updates through pull requests. |
| **JFrog Artifactory** | `--backend jfrog` | [Artifactory setup](docs/TRAINING_GUIDE.md#jfrog-artifactory). Uses a Hugging Face package repository and unique named submission revisions. Publication uses preflight checks; use one aggregator. |
| **HF²L Exchange** | `--backend exchange` | [Exchange setup](docs/EXCHANGE_V3.md). Authenticated spaces, permissions, immutable attachments, and coordinated publication. |

### Other components you can choose

These are separate configuration choices, rather than additional `--backend`
values.

| Component | Available choices | Where to configure it |
| --- | --- | --- |
| **Exchange object storage** | Versioned S3-compatible storage. The supplied deployment uses **MinIO**; an optional **patched SeaweedFS** build is available. | [S3 settings](docs/EXCHANGE_V3.md#configure-and-start), including `EXCHANGE_S3_ENDPOINT` and `EXCHANGE_S3_BUCKET`. |
| **Identity provider** | A provider meeting the documented OIDC/token requirements. The beginner stack supplies **Keycloak**. | [Exchange identity settings](docs/EXCHANGE_V3.md#configure-and-start) and [manager authentication](docs/JOB_MANAGER.md). |
| **Metadata database** | **PostgreSQL** for deployments; **SQLite** for local development and tests. | `EXCHANGE_DATABASE_URL` and `JOBS_DATABASE_URL`; see the service guides. |
| **Model and training code** | Your existing trainer or a trusted local Python plugin. Bundled examples include **LeNet** and **VGG/CIFAR-10**. | [Training and evaluation hooks](docs/TRAINING_GUIDE.md#plugin-interface), using `--plugin` and `--plugin-arg`. |
| **Checkpoint array processing** | **NumPy** or optional **Torch**. BF16 processing requires Torch. | `--array-backend numpy` or `--array-backend torch`; [checkpoint handling](docs/TRAINING_GUIDE.md#large-models). |

**MinIO and SeaweedFS are storage underneath Exchange.** Both use the same S3
adapter; neither is a separate model-store backend. The
[SeaweedFS compatibility build](deploy/seaweedfs/README.md) requires the supplied
patch and one S3 gateway. Unmodified SeaweedFS 4.47 fails the multipart retry
contract. Qualify another S3 deployment against the documented conformance tests.

Training implementations must export compatible **SafeTensors** checkpoints:
the same configuration, tensor names, shapes, dtypes, and shard layout.
**FedAvg** is the supplied aggregation algorithm, with sample-count or uniform
weighting. Additional algorithms and checkpoint formats require implementation.

## Install from source

HF²L, Exchange, and the manager require **Python 3.11 or later**.
The beginner walkthrough uses **Python 3.12** and lists its host prerequisites.
Python 3.10 is [no longer supported by Python](https://peps.python.org/pep-0619/#3-10-lifespan).

From the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/hf2l --help
```

This installs the NumPy/SafeTensors core and local backend. Add the packages
needed for your chosen workflow:

| Need | Install into the same environment |
| --- | --- |
| Hugging Face integration | `.venv/bin/python -m pip install -e '.[hf]'` |
| JFrog integration | `.venv/bin/python -m pip install -e '.[jfrog]'` |
| Torch and bundled training plugins | `.venv/bin/python -m pip install -e '.[examples]'` |
| HF²L with Exchange | `.venv/bin/python -m pip install -e ./packages/exchange -e '.[exchange]'` |
| Exchange service | `.venv/bin/python -m pip install -e './packages/exchange[server]'` |
| Job manager and dashboard | `.venv/bin/python -m pip install -e './packages/jobs[server]'` |

Installing a package does not deploy its services. Follow the beginner
walkthrough or the relevant operator guide. Generic Exchange clients can install
only `./packages/exchange` in a fresh environment, without HF²L or ML libraries.

Use separate credentials for the service administrator, aggregator, and each
participant. Follow the [authentication instructions](docs/TRAINING_GUIDE.md#install-and-authenticate);
keep credentials out of source control. These development interfaces may be
newer than published packages, so use an agreed source revision.

## Managed jobs and dashboard

The optional manager provides:

- Job creation, cancellation, resource queues, current jobs, and retained history.
- OIDC login and job-specific access permissions.
- Private job source snapshots, Exchange spaces, artifacts, and execution credentials.
- Resource reservations, recovery, logs, checkpoints, and authenticated result exports.

Concurrency depends on the configured resource pools and project limits.
Managed training uses the qualified **Linux/Docker/gVisor CPU** runtime;
GPU and Kubernetes execution are not supported deployment alternatives.

The beginner Compose example runs Exchange and its dependencies. Deploy the
manager/dashboard and qualify its runtime separately using the
[managed deployment guide](deploy/jobs/README.md). The beginner stack lacks the
managed Exchange, OIDC, and database configuration the manager requires; see
[using the beginner Compose stack](docs/JOB_MANAGER.md#using-the-beginner-compose-stack).

## Guides and examples

| Goal | Read |
| --- | --- |
| Complete your first project | [Beginner walkthrough](examples/first_federation/README.md) |
| Reuse a trainer, configure a backend, or run CLI commands | [Training guide](docs/TRAINING_GUIDE.md) |
| Run a real CIFAR-10 example with automatic rounds | [Two-client Exchange demo](examples/exchange_cifar10/README.md) |
| Exchange metadata/files without federated learning | [Generic SDK example](docs/EXCHANGE_V3.md#generic-sdk-example) |
| Operate Exchange and its storage | [Exchange runbook](docs/EXCHANGE_V3.md) |
| Operate, deploy, and export managed jobs | [Job manager](docs/JOB_MANAGER.md), [deployment](deploy/jobs/README.md), [exports](docs/JOB_EXPORTS.md) |
| Build packages or run developer checks | [Build](docs/TRAINING_GUIDE.md#build-and-install-the-wheel), [validation](docs/TRAINING_GUIDE.md#local-validation) |
| Understand component boundaries | [Architecture](docs/ARCHITECTURE_V3.md) and [multi-job design](docs/MULTI_JOB_DESIGN.md) |

Raw datasets stay with participants; model updates are shared with authorized
readers and trusted service administrators. The beginner example does not
provide secure aggregation or differential privacy.
