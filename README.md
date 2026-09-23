# HF²L (HF2L/HFFL): Hugging Face Federated Learning

**HF²L** stands for **Hugging Face Federated Learning**. It can also be written
as **HFFL**; the project name stylizes the two consecutive `F` characters as
`F²`. This repository is a proof of concept (POC) for coordinating federated
model training through Hugging Face Hub, JFrog Artifactory, the authenticated
Exchange service, or a local artifact store. Generic applications can use the
independent Exchange SDK to exchange metadata and large files without installing
the ML application.

The [v3 architecture](docs/ARCHITECTURE_V3.md) consolidates the prior reviews and
the implemented sibling v2 service. The [current Exchange runbook](docs/EXCHANGE_V3.md)
documents installation, authorization, transfers, coordination and recovery.
Architecture v3 preserves the `/v2` Exchange API and the existing HF²L document
formats; it does not rename them to version 3.

## Three design pillars

| Design | What it enables |
|:---|:---|
| **1. Pluggable models and client training** | Model-specific initialization, training, and evaluation can live in local plugins. Alice, Bob, and other clients may use different reviewed training implementations, frameworks, hyperparameters, and private datasets as long as they produce the same checkpoint schema. The included LeNet/MNIST and VGG/CIFAR-10 plugins demonstrate switching models by joining a differently initialized model repository without changing transport or FedAvg code. |
| **2. Two client integration approaches** | Use three independent steps—download, train with arbitrary local code, and upload—or use the plugin-style `python -m hf2l.client_train` command to run all three around a trusted local training plugin. |
| **3. Federated rounds with a shared base** | Synchronous **FedAvg** is implemented by `python -m hf2l.owner_fedavg`: participants train from one immutable global base and the owner validates, averages, and publishes their updates. Cyclic submission handoffs and swarm coordination are not implemented by the current client workflow. |

## Contents

- [Three design pillars](#three-design-pillars)
- [Design overview](#design-overview)
- [Install and authenticate](#install-and-authenticate)
  - [Local store](#local-store)
  - [Hugging Face Hub](#hugging-face-hub)
  - [JFrog Artifactory](#jfrog-artifactory)
- [Owner: initialize a repository](#owner-initialize-a-repository)
  - [LeNet with MNIST-shaped data](#lenet-with-mnist-shaped-data)
  - [VGG with CIFAR-10 data](#vgg-with-cifar-10-data)
- [Client option A: three independent steps](#client-option-a-three-independent-steps)
  - [Download the exact base](#1-download-the-exact-base)
  - [Train with any local code](#2-train-with-any-local-code)
  - [Validate and upload a submission](#3-validate-and-upload-a-submission)
- [Client option B: trusted training plugin](#client-option-b-trusted-training-plugin)
- [Cyclic federated learning without FedAvg](#cyclic-federated-learning-without-fedavg)
- [FedAvg: validate, average, and publish submissions](#fedavg-validate-average-and-publish-submissions)
  - [Automatically discover the current round](#automatically-discover-the-current-round)
  - [Explicitly select submissions](#explicitly-select-submissions)
- [Large models](#large-models)
- [Build and install the wheel](#build-and-install-the-wheel)
- [Local validation](#local-validation)

The model repository provides versioned transport without hard-coding a
model class, dataset, training loop, or federation schedule into that transport
layer.

The shared checkpoint contract is deliberately small:

- `config.json`
- either `model.safetensors`, or `model.safetensors.index.json` and its shards
- identical tensor names, shapes, dtypes, configuration, and shard filenames
  across the round

Only weights, configuration, checksums, and non-secret submission metadata are
uploaded. Client datasets and training code remain local.

## Design overview

The [v3 architecture](docs/ARCHITECTURE_V3.md) describes the current component
boundaries, accepted review concepts and invariants. The independent
[Exchange service](docs/EXCHANGE_V3.md) provides authenticated metadata exchange,
PostgreSQL persistence and authorized private S3 transfers. Its optional FedAvg
profile supplies the FL rules; generic spaces need no model vocabulary.

The [historical slides](docs/history/DESIGN_SLIDES.md) and
[legacy v1 service guide](docs/EXCHANGE_SERVICE.md) describe earlier interfaces.
New `--backend exchange` usage targets the independent service's `/v2` API.

## Install and authenticate

Create a local environment in this source checkout. Base installation supports
NumPy/SafeTensors processing and the local backend; install the extras used by
your application:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
# Hugging Face and the training examples used below:
.venv/bin/python -m pip install -e '.[hf,examples]'
```

For JFrog, use `.venv/bin/python -m pip install -e '.[jfrog,examples]'`.
Torch alone is available through `.[torch]`; it is required for BF16 checkpoints
and Torch training. These integration changes are unreleased; earlier published
packages do not necessarily expose the interfaces described here.

The independent Exchange SDK and server are separate installations:

```bash
# Generic SDK, without HF²L or ML dependencies:
.venv/bin/python -m pip install -e './packages/exchange'
# Or install the server and HF²L adapter together:
.venv/bin/python -m pip install -e './packages/exchange[server]' -e '.[exchange]'
```

The unified `.venv/bin/hf2l --help` lists the application commands. Existing
`python -m hf2l.client_download`, owner commands and console aliases remain
supported. `.venv/bin/hf2l-exchange --help` lists the independent service commands.

### Local store

Use `--backend local --endpoint work/local-store --local-principal ACTOR` with
the initialization, download, upload, training and owner commands below. The
environment equivalents are `HF2L_LOCAL_ROOT` and `HF2L_LOCAL_PRINCIPAL`.
For example, seed a local repository from an existing checkpoint:

```bash
.venv/bin/hf2l init --backend local --endpoint work/local-store \
  --local-principal owner --repo-id local/demo --model-dir path/to/checkpoint
```

Alice uses `--local-principal alice --participant alice` when uploading, and Bob
uses his own matching values. Both must train from the same immutable base
revision. The owner discovers their detached submissions and publishes with:

```bash
.venv/bin/hf2l round --backend local --endpoint work/local-store \
  --local-principal owner --repo-id local/demo --discover-submissions \
  --output-dir work/local-round-1 --array-backend numpy --publish --json
```

The store uses a trusted local POSIX filesystem, immutable snapshots and an
advisory lock around atomic reference updates. Principal names provide local
attribution; filesystem access controls protect the store. They are not remote
authentication, and network filesystems are not supported. A local round needs
no HF account or Exchange deployment. Training through the example plugins still
requires the `examples` extra.

### Hugging Face Hub

Each person uses a separate HF account. Authenticate with:

```bash
.venv/bin/hf auth login
```

Alternatively, set `HF_TOKEN` securely. The default backend is `huggingface`,
so existing commands do not require a `--backend` argument. The owner needs
repository write permission; clients use their own credentials and need
permission to open pull requests.

### JFrog Artifactory

An Artifactory administrator must first create a **local Hugging Face** package
repository. Each user receives a separate access or identity token with the
minimum required read/deploy permissions. Configure the SDK-compatible endpoint:

```bash
export HF_ENDPOINT="https://COMPANY.jfrog.io/artifactory/api/huggingfaceml/hf-local"
export HF_TOKEN="YOUR_OWN_JFROG_TOKEN"
export HF_HUB_ETAG_TIMEOUT=86400
export HF_HUB_DOWNLOAD_TIMEOUT=86400
```

Add `--backend jfrog` to every HF²L command. `--endpoint` can be supplied instead
of `HF_ENDPOINT`; `JFROG_ACCESS_TOKEN` can be used instead of `HF_TOKEN`. JFrog
supports model download/upload and named revisions, but not Hub pull requests.
The HF²L client commands therefore store each JFrog update under a generated
unique named revision. The owner discovers its manifest with Artifactory Query
Language (AQL). Server permissions must prevent overwriting those revisions.
The one-day timeouts above are suitable for very large transfers; choose values
appropriate for your network and model sizes. HF²L also handles Artifactory
versions that return a literal `commitUrl` placeholder after a successful
commit: it reconstructs the response URL from the configured endpoint,
repository ID, and server-returned commit OID, then resolves the revision back
from Artifactory.
See JFrog's [Hugging Face repository
documentation](https://docs.jfrog.com/artifactory/docs/hugging-face-repositories)
and [`jf hf` command
reference](https://docs.jfrog.com/artifactory/docs/use-hugging-face-with-jfrog-cli).

Never place a token in source control or share the owner's token. Disable
overwrite permission for participant uploads so a named submission revision
cannot be replaced, and restrict writes to `main` to the designated owner.
The JFrog adapter's public `publish_submission` method currently accepts `main`
as a caller-supplied revision. Generated client-command names avoid `main`, but
direct library callers must enforce that restriction themselves; the adapter
does not enforce it.

## Owner: initialize a repository

Initialize from any intentional, local HF-style model export:

```bash
.venv/bin/python -m hf2l.init_repo \
  --repo-id OWNER_OR_ORG/my-fedavg-model \
  --model-dir /path/to/exported-model
```

The directory may also contain model code, tokenizer files, and a model card;
those files are copied during initialization. Local `.git`, `.cache`,
and `__pycache__` paths are excluded. A symlink elsewhere in the export causes
initialization to fail. Review the directory before upload.

For JFrog, the Artifactory repository itself must already exist. Initialize a
model package inside it with the same command plus the backend selection:

```bash
.venv/bin/python -m hf2l.init_repo \
  --backend jfrog \
  --repo-id OWNER_OR_ORG/my-fedavg-model \
  --model-dir /path/to/exported-model
```

JFrog visibility and write access are repository permissions, so `--private`
is intentionally rejected for that backend.

Or initialize using one of the trusted local example plugins.

### LeNet with MNIST-shaped data

The compact LeNet POC uses grayscale `[N, 1, 28, 28]` inputs:

Its model and data implementations are
[`examples/lenet_model.py`](examples/lenet_model.py) and
[`examples/mnist_data.py`](examples/mnist_data.py).

```bash
.venv/bin/python -m hf2l.init_repo \
  --repo-id OWNER_OR_ORG/lenet-fedavg-poc \
  --plugin lenet \
  --plugin-arg seed=20260903
```

The script validates the checkpoint, publishes it, and prints the immutable
initial `main` revision. Give that exact revision to all clients.

### VGG with CIFAR-10 data

Create a separate repository containing the VGG-11-style CIFAR-10 checkpoint:

Its model and data implementations are
[`examples/vgg_model.py`](examples/vgg_model.py) and
[`examples/cifar10_data.py`](examples/cifar10_data.py).

```bash
.venv/bin/python -m hf2l.init_repo \
  --repo-id OWNER_OR_ORG/vgg-cifar10-fedavg-poc \
  --plugin vgg-cifar10 \
  --plugin-arg seed=20260903 \
  --plugin-arg width_multiplier=0.25
```

The `0.25` width multiplier keeps the POC lightweight while retaining the
VGG-11 layer topology. Use `width_multiplier=1.0` for the standard channel
widths. Once initialized, this repository uses the same
`python -m hf2l.client_download`, `python -m hf2l.client_upload`, and
`python -m hf2l.owner_fedavg` modules as LeNet. Do not mix LeNet and VGG
checkpoints in one repository or round; their tensor schemas are intentionally
different.

## Client option A: three independent steps

### 1. Download the exact base

```bash
.venv/bin/python -m hf2l.client_download \
  --repo-id OWNER_OR_ORG/my-fedavg-model \
  --base-revision OWNER_SUPPLIED_COMMIT_SHA \
  --work-dir work/alice-round-0
```

This creates:

```text
work/alice-round-0/
├── base_model/                  immutable input checkpoint
└── fedavg_client_context.json   backend, repo, base revision, and round
```

Use a new work directory for every attempt and round.

### 2. Train with any local code

Your trainer is entirely independent of these scripts. It must load
`base_model` and write a complete checkpoint to another directory:

```bash
.venv/bin/python /private/my_train.py \
  --input work/alice-round-0/base_model \
  --output work/alice-round-0/trained_model \
  --dataset /private/alice-data
```

Do not overwrite `base_model`. Save with the same config and SafeTensors shard
layout. For example, a Transformers trainer can load from the input directory
and call `save_pretrained(output_dir, safe_serialization=True)` using the same
`max_shard_size` as the base checkpoint.

Optionally create a non-secret metadata object:

```json
{
  "dataset": "private images, version 3",
  "hyperparameters": {"epochs": 2, "learning_rate": 0.00002},
  "metrics": {"local_loss": 0.42}
}
```

### 3. Validate and upload a submission

```bash
.venv/bin/python -m hf2l.client_upload \
  --work-dir work/alice-round-0 \
  --trained-dir work/alice-round-0/trained_model \
  --participant alice \
  --num-examples 12500 \
  --metadata-json /private/alice-training-metadata.json
```

The script checks the trained checkpoint against the downloaded base and opens
a PR whose parent is the exact base commit on Hugging Face Hub. It prints a
backend-neutral `submission_revision` such as `refs/pr/1`. Send that value to
the owner; do not merge the client PR directly.

On JFrog, add `--backend jfrog`. The command uploads a unique named revision
such as `r0000-alice-a1b2c3d4e5f6` instead of opening a PR:

```bash
.venv/bin/python -m hf2l.client_upload \
  --backend jfrog \
  --work-dir work/alice-round-0 \
  --participant alice \
  --num-examples 12500
```

Both backends write `base_revision`, `submission_revision`, and SHA-256 values
for every checkpoint artifact into `fedavg_submission.json`.

## Client option B: trusted training plugin

`python -m hf2l.client_train` composes the same download and upload functions around a
trusted local plugin. A participant joining the LeNet repository runs:

```bash
.venv/bin/python -m hf2l.client_train \
  --repo-id OWNER_OR_ORG/lenet-fedavg-poc \
  --base-revision OWNER_SUPPLIED_COMMIT_SHA \
  --participant alice \
  --work-dir work/alice-round-0 \
  --plugin lenet \
  --plugin-arg synthetic_examples=1000 \
  --plugin-arg epochs=8 \
  --plugin-arg learning_rate=0.2
```

For private LeNet NPZ data, add
`--plugin-arg dataset_npz=/private/alice-images.npz`. The example NPZ format is
`x` shaped `[N, 28, 28]` or `[N, 1, 28, 28]` and integer `y` shaped `[N]`.

The same participant can join the separate VGG/CIFAR-10 repository by changing
only the repository, plugin, data, and training options:

```bash
.venv/bin/python -m hf2l.client_train \
  --repo-id OWNER_OR_ORG/vgg-cifar10-fedavg-poc \
  --base-revision VGG_REPO_MAIN_COMMIT_SHA \
  --participant alice \
  --work-dir work/alice-vgg-round-0 \
  --plugin vgg-cifar10 \
  --plugin-arg dataset_npz=/private/alice-cifar10.npz \
  --plugin-arg epochs=5 \
  --plugin-arg learning_rate=0.01
```

The CIFAR-10 NPZ format uses integer `y` shaped `[N]` and `x` shaped either
`[N, 32, 32, 3]` or `[N, 3, 32, 32]`. Pixels may be `uint8` values in
`[0, 255]` or floating-point values in `[0, 1]`; the plugin applies standard
CIFAR-10 channel normalization. Omitting `dataset_npz` uses deterministic
synthetic RGB data for an offline smoke test, not for meaningful evaluation.

Users of the three-step workflow make the same switch in their own trainer:
load the VGG repository checkpoint, train it on local CIFAR-10 data, and write a
complete compatible checkpoint before running the unchanged upload command.

The package recognizes the built-in `lenet` and `vgg-cifar10` plugin names.
For custom training, pass the path to a reviewed local Python file, such as
`--plugin /private/alice_plugin.py`. Plugins are ordinary Python and execute
with the caller's permissions; the commands never load code from a remote
submission.

### Plugin interface

A custom plugin may implement any subset needed by the command that loads it:

```python
def initialize_model(output_dir, options):
    # Write a complete checkpoint. Return optional JSON metadata.
    return {"model": "my-model"}

def train_model(base_dir, output_dir, options):
    # Load base_dir, train however you want, and save to output_dir.
    # num_examples is required; all other returned fields are optional metadata.
    return {"num_examples": 12500, "metrics": {"loss": 0.42}}

def evaluate_model(model_dir, options):
    # Optional owner-controlled evaluation. Return JSON metadata.
    return {"accuracy": 0.91}
```

Each repeated `--plugin-arg KEY=VALUE` is JSON-decoded when possible, so
numbers, booleans, arrays, and objects retain their types.

## Cyclic federated learning without FedAvg

Cyclic weight transfer would pass each participant's trained checkpoint to the
next participant without averaging. **Submission-to-submission handoffs are not
supported by the current client commands**, including on Hugging Face and
JFrog. Linear swarm handoffs and automated swarm coordination are also not
implemented.

Client download requires `fedavg_round.json` and validates its checkpoint
hashes. Client upload writes checkpoint artifacts and `fedavg_submission.json`,
without updating the global round record. A changed HF PR snapshot can inherit
the old round record and fail checksum validation; a detached submission can
lack that record altogether. Passing a predecessor's submission revision as
`--base-revision` therefore does not provide a working cyclic workflow.

Supporting this design would require submission-aware download validation of
the predecessor's manifest, hashes, and lineage, plus explicit backend rules
for using submissions as bases and a coordinator that enforces participant
order and one successor. The implemented workflow below uses a common global
base and owner-controlled FedAvg publication.

## FedAvg: validate, average, and publish submissions

To run FedAvg automatically when two eligible HF PRs are ready, see the
[webhook-triggered GitHub workflow setup](docs/FEDAVG_WORKFLOW.md).

### Automatically discover the current round

With `--discover-submissions`, the owner does not need to supply individual
revisions. On Hub, the script lists open pull requests. On JFrog, it searches
for `fedavg_submission.json` artifacts with AQL and obtains the uploader from
Artifactory metadata.

The recommended discovery mode also uses an allowlist that binds each approved
repository identity to the participant ID in that user's submission manifest.
Use the HF username on Hub and the JFrog uploader identity on Artifactory:

```bash
.venv/bin/python -m hf2l.create_allowlist \
  --participant alice-hf=alice \
  --participant bob-hf=bob \
  --output participant_allowlist.json
```

```json
{
  "alice-hf": "alice",
  "bob-hf": "bob"
}
```

Repository identities are matched case-insensitively; participant IDs are
matched exactly. Each identity and participant ID must appear only once. The
generator rejects duplicate identities, duplicate participant IDs, and an existing output file. Do not
commit the real allowlist if its membership is sensitive. The repository's
[`examples/participant_allowlist.example.json`](examples/participant_allowlist.example.json)
remains a placeholder reference.

Then discover eligible submissions and aggregate without publishing:

```bash
.venv/bin/python -m hf2l.owner_fedavg \
  --repo-id OWNER_OR_ORG/my-fedavg-model \
  --discover-submissions \
  --allowlist participant_allowlist.json \
  --output-dir work/owner-check-round-1
```

For each run, automatic discovery:

1. Pins the current `main` revision and reads its current FedAvg round.
2. Lists backend submissions and rejects authors outside the allowlist.
3. Pins each candidate revision. Hub additionally verifies commit ancestry.
4. Downloads only `fedavg_submission.json` and verifies its repository, base
   revision, source round, backend, participant ID, and example count.
5. Downloads full checkpoints only for eligible submissions, then validates
   tensors and shard layouts before aggregation. SHA-256 verification applies
   to schema-2 base round records and submission manifests.

Legacy schema-1 documents remain readable, but the owner currently skips their
checkpoint hash verification even if they supply a hash map. Client download
does verify a supplied schema-1 base hash map. Use schema-2 records produced by
the current initialization and client commands for owner-side checksum checks.

In discovery mode, unauthorized, stale, or invalid records are reported as
`skipped_submission=...`. Automatic discovery and claimed rounds also skip
malformed, deleted or incompatible checkpoints, and publish only when at least
the required number of fully validated participants remain (two by default).
Explicitly selected invalid submissions fail the run. A transport outage remains
a failure. Duplicate eligible participant IDs fail unless the backend's selection
policy already chose one submission per participant, as the Exchange profile
does; otherwise withdraw a superseded submission or select revisions explicitly.

On backends without participant bindings, such as HF and JFrog,
`--discover-submissions` without `--allowlist` reports a warning and considers
every compatible discovered submission. Local and Exchange use their explicit
participant bindings. An allowlist remains appropriate for an untrusted HF/JFrog
repository; compatibility checks and example counts do not establish honest
training or protect against poisoned model updates.

`--discover-prs` remains an alias for Hub-only scripts written against HF²L
0.1.0.

For JFrog, run the same command with `--backend jfrog`; `HF_ENDPOINT` identifies
the Artifactory repository. AQL access is required in addition to model read
access.

### Explicitly select submissions

Manual selection remains available:

```bash
.venv/bin/python -m hf2l.owner_fedavg \
  --repo-id OWNER_OR_ORG/my-fedavg-model \
  --submission refs/pr/1 \
  --submission refs/pr/2 \
  --output-dir work/owner-check-round-1
```

For JFrog, use the revisions printed by the clients and add `--backend jfrog`:

```bash
.venv/bin/python -m hf2l.owner_fedavg \
  --backend jfrog \
  --repo-id OWNER_OR_ORG/my-fedavg-model \
  --submission r0000-alice-a1b2c3d4e5f6 \
  --submission r0000-bob-112233445566 \
  --output-dir work/owner-check-round-1
```

You may add `--allowlist participant_allowlist.json`; selected uploader
identities must then match their mapped participant IDs. `--pr` remains a Hub
alias for `--submission`.

For either selection mode, the owner verifies that current `main` is the
clients' declared base, repository identities and participant IDs satisfy the
optional allowlist, participant IDs are distinct, example counts are positive,
and checkpoint schemas match. It verifies hashes for schema-2 base and
submission documents; the schema-1 limitation described above applies to both
selection modes. On Hub it also checks that every PR descends from the base. It computes
dataset-size-weighted FedAvg:

```text
theta_next = sum(num_examples_i * theta_i) / sum(num_examples_i)
```

Use `--weighting uniform` only when equal client weighting is intended. Integer
and Boolean tensors are copied only when every client value is unchanged;
differing non-floating state is rejected because an arithmetic mean is not
well-defined.

Evaluation is optional and must come from an owner-trusted local plugin:

```bash
.venv/bin/python -m hf2l.owner_fedavg \
  --repo-id OWNER_OR_ORG/lenet-fedavg-poc \
  --submission refs/pr/1 --submission refs/pr/2 \
  --output-dir work/owner-check-round-1 \
  --plugin lenet \
  --plugin-arg eval_examples=1000
```

For the VGG repository, use `--repo-id
OWNER_OR_ORG/vgg-cifar10-fedavg-poc` and `--plugin vgg-cifar10`. Aggregation itself remains
model-agnostic; only
optional evaluation needs the model-specific plugin.

`--json` controls the owner's result rendering; it does not capture output from
evaluation plugins. The built-in LeNet evaluator's model loader prints to
stdout, so a run with `--plugin lenet --json` does not produce a standalone JSON
stream. Other trusted plugins can also print. For machine-readable stdout,
omit evaluation or use a plugin whose entire evaluation path is quiet. The
library runner likewise does not suppress plugin output.

After inspecting the aggregate, rerun into a new directory and publish:

```bash
.venv/bin/python -m hf2l.owner_fedavg \
  --repo-id OWNER_OR_ORG/my-fedavg-model \
  --discover-submissions \
  --allowlist participant_allowlist.json \
  --output-dir work/owner-publish-round-1 \
  --publish \
  --tag fedavg-round-1
```

On Hub, publication uses `parent_commit=BASE_SHA`, so the Hub rejects it if
`main` changed after validation. On JFrog, the script re-reads `main` immediately
before upload and only the designated owner/coordinator may write `main`.
Artifactory does not provide the same atomic Git compare-and-swap, so concurrent
owner processes require an external lock.

On Hub, the accepted conditional commit's immutable OID identifies the published
result; the adapter does not re-read `main` to establish success. JFrog reads
`main` back after its upload. Hub client PRs remain unmerged; the JFrog client
commands use separate named submission revisions, subject to the direct-library
and server-permission restrictions above. `fedavg_round.json` records
the backend, selection mode, base and resolved input revisions, uploader
identities, checksums, example counts, and aggregation coefficients.

## Large models

The Hub client uses HF's large-file transport. Current JFrog versions can also
enable Xet for local, remote, and virtual `huggingfaceml` repositories. JFrog
documents Xet support for files larger than 50 GB; consult its version matrix
before selecting `huggingface_hub` and `hf_xet` versions.

Aggregation works one SafeTensors shard at a time instead of loading all client
models as Python state dictionaries. It retains the growing output shard, the
current base tensor, the corresponding tensor from every client, and the
accumulator. With the default NumPy backend and SafeTensors 0.8.0, input tensor
payloads are private copies. Torch inputs can use memory-mapped storage, but
resident pages still contribute to memory use. Dtype conversion, scaling,
finite-value checks, and output casting can allocate additional arrays or
tensors. Keep shards reasonably sized and budget for the number and size of
participant tensors as well as these temporary allocations.

`--accumulator-dtype float32` is the memory-conscious default. Float64 model
tensors remain float64. Use `--accumulator-dtype float64` when the added
precision justifies roughly doubling accumulator memory. Disk must still hold
the base, every selected submission snapshot, and the aggregate.

Checkpoint discovery reads SafeTensors headers without Torch. Use
`--array-backend numpy` for supported non-BF16 checkpoints or
`--array-backend torch` with the Torch extra. Both execute the same averaging
policy through their array operations. `--weighting examples` is the default;
`--weighting uniform` gives each accepted participant equal weight. Algorithm
strategy injection is a library interface; FedProx is not implemented by merely
selecting a different label.

## Build and install the wheel

The ASCII Python distribution name for HF²L is `hf2l`. `setuptools-scm`
derives the package version from Git tags, so `pyproject.toml` and Python code
do not contain a manually synchronized release number. Create the release
commit and tag it before building official artifacts, for example:

```bash
git tag 0.1.1
git push origin 0.1.1
```

Build from that clean, exact tag using the project virtual environment:

```bash
.venv/bin/python -m pip install -e '.[build]'
.venv/bin/python -m build
.venv/bin/python -m twine check dist/*
```

Install the resulting wheel into another environment with:

```bash
python3 -m venv /path/to/consumer-venv
/path/to/consumer-venv/bin/python -m pip install dist/hf2l-VERSION-py3-none-any.whl
```

At a release tag, the wheel uses that exact version. Between tags,
`setuptools-scm` produces a PEP 440 development version containing commit
distance and revision information; a dirty checkout is also marked. Inspect
the computed version with `.venv/bin/python -m setuptools_scm` before
publishing.

The examples above use Python module execution. Installing the package also
creates the unified `hf2l` command and these retained console-command aliases:

- `hf2l-init-repo`
- `hf2l-client-download`
- `hf2l-client-train`
- `hf2l-client-upload`
- `hf2l-create-allowlist`
- `hf2l-owner-fedavg`
- `hf2l-exchange-service`

For example, `hf2l-client-download` is equivalent to
`python -m hf2l.client_download`. `hf2l-exchange-service` is the legacy v1
service command; the independent package installs `hf2l-exchange` for `/v2`.

## Local validation

No live HF account is needed for the local suites. Install both editable
distributions and their testing/training extras first:

```bash
.venv/bin/python -m pip install -e './packages/exchange[server,test]' \
  -e '.[torch,hf,examples,exchange,service,exchange-test]'
.venv/bin/python -m unittest discover -s tests -v
EXCHANGE_REQUIRE_TESTS=1 .venv/bin/python -m unittest discover -s packages/exchange/tests -v
```

Provider and process-recovery checks also run against PostgreSQL/MinIO when
configured. See the [current validation record](docs/EXCHANGE_V3.md#validation-status-and-deployment-limits)
for completed checks and limits; historical counts are not combined-tree evidence.
