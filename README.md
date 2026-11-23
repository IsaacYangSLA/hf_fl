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
| **Org S — Service** | Deploy shared services, manage accounts and resources, and grant selected accounts permission to create studies. |
| **Org P — Aggregator** | Agree on the model, enroll participants, initialize the checkpoint, aggregate, evaluate, and publish. |
| **Org A — Alice** | Train locally on private data and submit an update. |
| **Org B — Bob** | Independently train locally and submit an update. |

Org S deploys the included [Compose stack](examples/first_federation/compose.yaml).
Org P, Alice, and Bob install client tools; they do not deploy server stacks.
The supplied Compose stack runs the native [Go Exchange service](docs/GO_EXCHANGE.md)
and its background worker. The Python client library and participant trainers
remain on each organization's machine.
For Docker Compose with the Go Exchange and optional Go dashboard, follow the
[Go services Compose guide](deploy/compose/go/README.md). It requires separately
configured databases, identity, and storage; it does not start managed training.
The walkthrough needs no Hugging Face account, Torch, GPU, or external dataset.

A round follows this sequence:

1. Org P publishes a common starting checkpoint.
2. Alice and Bob download that exact version and train locally.
3. Each uploads an update and its training sample count.
4. Org P validates the updates, runs FedAvg, and publishes the next checkpoint.

Org P shares the agreed trainer revision, model configuration, and dependencies.
Alice and Bob install and run that code themselves; Org P and Org S do not need
access to participant machines. Formal human approval is an optional external
process; Exchange authentication and project membership are still required.

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
below. Participant-controlled native trainers can use their own CPUs or GPUs.
Managed jobs currently use Exchange-backed FedAvg and a separately qualified
CPU runtime.

For sequential training, there is also an explicit
[cyclic handoff workflow](docs/TRAINING_GUIDE.md#cyclic-federated-learning-without-fedavg).
Participant order is chosen by the caller.

## Replaceable components

A **backend** is the component that reads and writes model artifacts: saved
checkpoints and the metadata describing them. The four backend names below are
the complete choices accepted by the model-store factory, the function that
constructs this component.

### Model storage: four backends

Use `--backend` with the training and listener commands. Changing the backend
changes artifact transport; it does not require rewriting your trainer.

| Backend | Select with | Setup and limits |
| --- | --- | --- |
| **Local filesystem** | `--backend local` | [Local setup](docs/TRAINING_GUIDE.md#local-store). No server or account; requires a trusted local POSIX filesystem. Principal names provide attribution, not remote authentication. |
| **Hugging Face Hub** | `--backend huggingface` | [Hub setup](docs/TRAINING_GUIDE.md#hugging-face-hub). The default; participants submit updates through pull requests. |
| **JFrog Artifactory** | `--backend jfrog` | [Artifactory setup](docs/TRAINING_GUIDE.md#jfrog-artifactory). Uses a Hugging Face package repository and unique named submission revisions. Publication uses preflight checks; use one aggregator. |
| **HF²L Exchange** | `--backend exchange` | [Exchange setup](docs/EXCHANGE_V3.md). Authenticated spaces, permissions, immutable attachments, and coordinated publication. |

The standalone beginner walkthrough uses an Exchange **space**, a boundary for
membership, records and files. A manager **study** is a collaboration with its
own administrators, enrollment and jobs. Creating either one does not create the
other or grant membership in it.

### Other components you can choose

These are separate configuration choices, rather than additional `--backend`
values.

| Component | Available choices | Where to configure it |
| --- | --- | --- |
| **Service deployment** | Native **Go** Exchange and manager; Python clients, training, and aggregation remain separate. | [Go Exchange](docs/GO_EXCHANGE.md), [Go manager](docs/GO_JOB_MANAGER.md), and [Go Compose](deploy/compose/go/README.md). |
| **Exchange object storage** | Versioned S3-compatible storage. The supplied deployment uses **MinIO**; an optional **patched SeaweedFS** build is available. | [S3 settings](docs/EXCHANGE_V3.md#configure-and-start), including `EXCHANGE_S3_ENDPOINT` and `EXCHANGE_S3_BUCKET`. |
| **Identity provider** | A provider meeting the documented OIDC/token requirements. The beginner stack supplies **Keycloak**. | [Exchange identity settings](docs/EXCHANGE_V3.md#configure-and-start) and [manager authentication](docs/JOB_MANAGER.md). |
| **Metadata database** | **PostgreSQL** for deployments; **SQLite** for local development and tests. | `EXCHANGE_DATABASE_URL` and `JOBS_DATABASE_URL`; see the service guides. |
| **Model and training code** | Your existing trainer or a trusted local Python plugin. Bundled examples include **LeNet** and **VGG/CIFAR-10**. | [Training and evaluation hooks](docs/TRAINING_GUIDE.md#plugin-interface), using `--plugin` and `--plugin-arg`. |
| **Checkpoint array processing** | **NumPy** or optional **Torch**. BF16 aggregation requires explicitly selecting Torch. | `--array-backend numpy` or `--array-backend torch`; [checkpoint handling](docs/TRAINING_GUIDE.md#large-models). |

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

HF²L, the Exchange Python client library, and the isolated training/build adapters
require **Python 3.14 or 3.15**. The native [Go Exchange service](docs/GO_EXCHANGE.md)
and [Go manager](docs/GO_JOB_MANAGER.md) build separately on Linux with Go 1.26 or later.
The beginner walkthrough uses **Python 3.14**. Install the versioned
command `python3.14` alongside your system Python. On Linux, one option is
`uv python install 3.14`, where uv is a tool for installing Python versions.
Follow its guide to make the installed command available in your shell.
[Python downloads](https://www.python.org/downloads/)
[uv's Python installation guide](https://docs.astral.sh/uv/guides/install-python/)

A virtual environment is a directory with its own Python commands and packages.
From the repository root, `scripts/setup_venv.py` checks the Python version and
creates or verifies the `.venv` environment. Substitute `python3.15` to select
Python 3.15. The existing environment's Python release must match the selected
release. Each `&&` runs the next command only if the preceding command succeeds.

```bash
python3.14 scripts/setup_venv.py .venv &&
  .venv/bin/python -m pip install -e . &&
  .venv/bin/hf2l --help
```

If setup rejects an existing `.venv`, deactivate it if active, move it to an
unused backup path, and rerun setup. You can also pass a new directory and
use it in place of `.venv` in subsequent commands.

The base installation includes the NumPy/SafeTensors core and local backend.
Add the packages needed for your chosen workflow:

| Need | Install into the same environment |
| --- | --- |
| Hugging Face integration | `.venv/bin/python -m pip install -e '.[hf]'` |
| JFrog integration | `.venv/bin/python -m pip install -e '.[jfrog]'` |
| Torch and bundled training plugins | `.venv/bin/python -m pip install -e '.[examples]'` |
| HF²L with Exchange | `.venv/bin/python -m pip install -e ./packages/exchange -e '.[exchange]'` |

Optional dependencies must support your Python version and platform. PyTorch,
the library used by the bundled training examples, has no upstream prebuilt
packages for Intel-based Macs on Python 3.14 or 3.15. Use a supported Linux
environment for those examples. [PyTorch's Intel Mac support announcement](https://dev-discuss.pytorch.org/t/pytorch-macos-x86-builds-deprecation-starting-january-2024/1690)

Installing a package does not deploy its services. Follow the beginner
walkthrough or the relevant operator guide. Generic Exchange clients can install
only `./packages/exchange` in a fresh environment, without HF²L or ML libraries.

Use separate credentials for the service administrator, aggregator, and each
participant. Follow the [authentication instructions](docs/TRAINING_GUIDE.md#install-and-authenticate);
keep credentials out of source control. These development interfaces may be
newer than published packages, so use an agreed source revision.

## Managed jobs and dashboard

The native [Go manager](docs/GO_JOB_MANAGER.md) serves the existing dashboard
and API and implements scheduling, lifecycle, provisioning, and trusted node
services. The retained Python server implementations have been removed. Follow the Go
guide to deploy services or upgrade existing state; Python remains in client
and isolated training/build code. Client listeners and the optional
[owner-side webhook relay](examples/hf_webhook_relay.py) also remain Python
programs; the service implementation change does not remove caller-owned
automation.

The optional manager provides:

- Job creation, cancellation, resource queues, current jobs, and retained history.
- OIDC login and job-specific access permissions.
- Private job source snapshots, Exchange spaces, artifacts, and execution credentials.
- Resource reservations, recovery, logs, checkpoints, and authenticated result exports.

Concurrency depends on the configured resource pools and project limits.
Managed training uses the qualified **Linux/Docker/gVisor CPU** runtime;
GPU and Kubernetes execution are not supported managed deployment alternatives.
Participants running their own training outside this managed runtime can use
their trainer's hardware, including GPUs. The isolation qualification applies
to the configured managed execution path; ordinary client tools do not run
inside that sandbox.

The supplied Go Compose deployment starts services only; it does not provide
training capacity or launch automated rounds. The beginner Compose example runs
Exchange and its dependencies. Deploy the
manager/dashboard and qualify its runtime separately using the
[managed deployment guide](deploy/jobs/README.md). The beginner stack lacks the
managed Exchange, OIDC, and database configuration the manager requires; see
[using the beginner Compose stack](docs/JOB_MANAGER.md#using-the-beginner-compose-stack).

## Study creation

Org S is the shared service operator. Org P leads a collaboration, called a
study; the manager stores each study as a project. A **study creator** is an
account with servicewide permission to create studies. Org S grants this role
to selected accounts once; an authorized Org P can then open **Studies** in the
dashboard and use **Create study** with a study name, without asking Org S to
create each study.
Existing project administrators do not receive this role automatically.

The creator becomes administrator of that study only. The role grants no access
to other studies or their private jobs, and no authority over service accounts,
resource pools, quotas, or other service settings. Signing in alone grants none
of these permissions. Org S can revoke creation permission immediately,
including for existing signed-in sessions; separate administrator memberships
in existing studies remain in place.

A new study starts with registration closed, participant approval required,
zero resource quotas (resource allowances), and a 14-day job-retention period
(the time finished jobs' stored output is kept). Org P opens registration
and reviews participant requests. Org S still allocates resources and enables
training capacity; creating a study does not start automated training. See the
[creation and operator handoff](docs/JOB_MANAGER.md#study-creation-and-ownership).

## Study signup and participant approval

The Go manager includes a [signup and study enrollment workflow](docs/STUDY_ENROLLMENT.md).
Org S configures trusted account connections, including GitHub or Hugging Face
through the login provider. Alice and Bob sign in and request to join a study;
Org P reviews and approves each request. Signing in alone grants no study or
private-job access.

For an existing project created through trusted administration, Org P explicitly
enables the study policy. Newly dashboard-created studies already require
approval. Every participant requires approval; closing signup does not remove
the rule.
Approval establishes participation eligibility, while node, dataset, and
job-specific permissions remain separately controlled.

## Guides and examples

See the [documentation index](docs/README.md) for current guides, generated
contracts, and historical records.

| Goal | Read |
| --- | --- |
| Complete your first project | [Beginner walkthrough](examples/first_federation/README.md) |
| Reuse a trainer, configure a backend, or run CLI commands | [Training guide](docs/TRAINING_GUIDE.md) |
| Run a real CIFAR-10 example with automatic rounds | [Two-client Exchange demo](examples/exchange_cifar10/README.md) |
| Exchange metadata/files without federated learning | [Generic SDK example](docs/EXCHANGE_V3.md#generic-sdk-example) |
| Operate Exchange and its storage | [Native Go Exchange](docs/GO_EXCHANGE.md), [shared runbook](docs/EXCHANGE_V3.md) |
| Operate, deploy, and export managed jobs | [Go manager](docs/GO_JOB_MANAGER.md), [operator guide](docs/JOB_MANAGER.md), [deployment](deploy/jobs/README.md), [exports](docs/JOB_EXPORTS.md) |
| Build packages or run developer checks | [Build](docs/TRAINING_GUIDE.md#build-and-install-the-wheel), [validation](docs/TRAINING_GUIDE.md#local-validation) |
| Understand component boundaries | [Architecture](docs/ARCHITECTURE_V3.md) and [multi-job design](docs/MULTI_JOB_DESIGN.md) |

Raw datasets stay with participants; model updates are shared with authorized
readers and trusted service administrators. The beginner example does not
provide secure aggregation or differential privacy.

For organization-owned training and aggregation pods, see the [Kubernetes example](examples/kubernetes/README.md).
