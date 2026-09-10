# HF²L (HF2L/HFFL): Hugging Face Federated Learning

**HF²L** stands for **Hugging Face Federated Learning**. It can also be written
as **HFFL**; the project name stylizes the two consecutive `F` characters as
`F²`. This repository is a proof of concept (POC) for coordinating federated
model training through either Hugging Face Hub or a JFrog Artifactory
`huggingfaceml` repository.

## Three design pillars

| Design | What it enables |
|:---|:---|
| **1. Pluggable models and client training** | Model-specific initialization, training, and evaluation can live in local plugins. Alice, Bob, and other clients may use different reviewed training implementations, frameworks, hyperparameters, and private datasets as long as they produce the same checkpoint schema. The included LeNet/MNIST and VGG/CIFAR-10 plugins demonstrate switching models by joining a differently initialized model repository without changing transport or FedAvg code. |
| **2. Two client integration approaches** | Use three independent steps—download, train with arbitrary local code, and upload—or use the plugin-style `python -m hf2l.client_train` command to run all three around a trusted local training plugin. |
| **3. Multiple federated-learning styles** | Synchronous **FedAvg** is implemented by `python -m hf2l.owner_fedavg`; sequential **cyclic federated learning** uses immutable submission-to-submission handoffs without averaging. A linear **swarm** follows the cyclic handoff pattern, while a branching swarm can follow the FedAvg fan-out/fan-in pattern when peers train from the same base. Swarm peer selection and coordination remain policy-specific. |

## Contents

- [Three design pillars](#three-design-pillars)
- [Design overview](#design-overview)
- [Install and authenticate](#install-and-authenticate)
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

[`docs/DESIGN_SLIDES.md`](docs/DESIGN_SLIDES.md) is a concise four-slide
overview of the system architecture, client and owner operation sequence,
credential boundaries, and large-model transfer and aggregation strategy. A
rendered version is also available as
[`docs/DESIGN_SLIDES.pdf`](docs/DESIGN_SLIDES.pdf).

## Install and authenticate

Create a local environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install \
  'git+https://github.com/IsaacYangSLA/hf_fl.git@main'
```

Release 0.1.1 or newer can instead be installed with
`.venv/bin/python -m pip install 'hf2l>=0.1.1'`. For JFrog's currently documented
client version range, use `.venv/bin/python -m pip install 'hf2l[jfrog]>=0.1.1'`.
A source checkout may use `.venv/bin/python -m pip install -e .` for editable
Hub development or `.venv/bin/python -m pip install -e '.[jfrog]'` for JFrog.

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
HF²L therefore stores each JFrog client update under a generated immutable
revision and discovers its manifest with Artifactory Query Language (AQL).
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
cannot be replaced.

## Owner: initialize a repository

Initialize from any intentional, local HF-style model export:

```bash
.venv/bin/python -m hf2l.init_repo \
  --repo-id OWNER_OR_ORG/my-fedavg-model \
  --model-dir /path/to/exported-model
```

The directory may also contain model code, tokenizer files, and a model card;
those files are copied during initialization. Local `.git`, `.cache`,
`__pycache__`, and symlinks are excluded. Review the directory before upload.

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

The same client scripts can also implement cyclic federated learning, sometimes
called cyclical weight transfer. There is no averaging: exactly one participant
trains the checkpoint and hands that result to the next participant. For four
participants, the lineage is:

```text
main@C0
  -> Alice submission@A1
  -> Bob submission@B1
  -> Carol submission@C1
  -> Dave submission@D1
  -> Alice submission@A2
  -> ...
```

More precisely, after Dave produces `D1`, Alice downloads `D1`, trains it, and
creates the next submission. The order repeats as `Alice -> Bob -> Carol -> Dave ->
Alice`. With two participants it is simply `Alice -> Bob -> Alice`.

Each handoff uses an immutable resolved revision:

1. Alice starts with the initial `main` SHA, uses the download/train/upload
   workflow above, and sends Bob her submission and resolved revision.
2. Bob passes Alice's resolved revision as `--base-revision`, trains that checkpoint,
   uploads his result, and sends his new revision to the next participant.
3. Every later participant repeats the same operation using only the immediate
   predecessor's revision. After the last participant, control returns to
   Alice.

For example, Bob's download command is:

```bash
.venv/bin/python -m hf2l.client_download \
  --repo-id OWNER_OR_ORG/my-fedavg-model \
  --base-revision ALICE_RESOLVED_REVISION \
  --work-dir work/bob-cycle-1
```

Bob then trains `work/bob-cycle-1/base_model` and runs
`python -m hf2l.client_upload` as
shown above with `--participant bob`.

On Hugging Face Hub, the upload creates a PR whose parent is Alice's pinned
commit. The commit DAG retains Alice's commit as an ancestor. See the Hub
documentation for [PR refs and local
access](https://huggingface.co/docs/hub/en/repositories-pull-requests-discussions)
and the [`parent_commit` behavior of
`create_commit`](https://huggingface.co/docs/huggingface_hub/en/package_reference/hf_api#huggingface_hub.HfApi.create_commit).

On JFrog, add `--backend jfrog` to every command. Each handoff is a unique named
revision. JFrog does not maintain the same Git ancestry, so the submission
manifest records the exact predecessor in `base_revision`; an external cyclic
coordinator must enforce the participant order and single-successor rule.

Always hand off the exact resolved revision, not only a mutable name.
`python -m hf2l.client_download` resolves the input and records it as
`base_revision` in `fedavg_client_context.json`.

### Operating rules for the cycle

- Only the designated next participant should extend the chain. A backend can
  accept two submissions with the same base, so storage alone does not prevent
  a fork.
- Keep `main` fixed while the chain is active. On Hub, do not merge intermediate
  PRs. On JFrog, do not upload intermediate client revisions to `main`.
- Never run `python -m hf2l.owner_fedavg` on the cyclic submissions. It requires multiple updates
  from one common `main` commit and computes an average, which is a different
  protocol.
- Keep using new work directories. The upload step verifies that each trained
  checkpoint has the same tensor names, shapes, dtypes, configuration, and
  shard layout as its immediate predecessor.
- Put non-secret cyclic metadata such as `protocol`, `cycle`, `position`, and
  `predecessor_revision` in `--metadata-json`.
- Do not execute code from a predecessor's submission. Use reviewed local training code
  and treat the downloaded content as model data.

At a checkpoint or release boundary on Hub, the owner can review and merge only
the newest PR after verifying its ancestry. The Hub supports merging through its UI or
[`HfApi.merge_pull_request`](https://huggingface.co/docs/huggingface_hub/en/package_reference/hf_api#huggingface_hub.HfApi.merge_pull_request).
For JFrog, the owner validates the explicit manifest chain and uploads the
latest accepted snapshot to `main` under an exclusive coordinator lock.

The current `fedavg_round.json` value does not advance at each cyclic handoff;
it belongs to the FedAvg publishing path. Use the training metadata for manual
cyclic tracking. A fully automated cyclic deployment should add a dedicated
state record containing the ordered participant list, cycle number, expected
next participant, predecessor revision, and latest accepted submission. An [HF
webhook](https://huggingface.co/docs/hub/en/webhooks) can notify an external
coordinator when a PR changes, but that coordinator must still enforce the
order and select a single successor. A JFrog webhook or pipeline can notify the
same kind of external coordinator.

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
   SHA-256 checksums, tensors, and shard layouts before aggregation.

In discovery mode, unauthorized, stale, or invalid records are reported as
`skipped_submission=...` and do not stop the round. At least two eligible submissions are
required. A checkpoint-layout mismatch still stops aggregation because the
models cannot be averaged safely. If multiple eligible submissions claim the same
participant ID, aggregation also stops so the owner can close the superseded
record or explicitly choose one with `--submission`.

Running `--discover-submissions` without `--allowlist` is supported but prints a
warning and considers every compatible discovered submission. Do not use that mode for an
untrusted repository: participant names and example counts are
self-reported, and compatibility checks do not protect against poisoned model
updates.

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
and checkpoint schemas and hashes match. On Hub it also checks that every PR
descends from the base. It computes
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

The script reads `main` back after publication. Hub client PRs remain unmerged;
JFrog client revisions remain separate from `main`. `fedavg_round.json` records
the backend, selection mode, base and resolved input revisions, uploader
identities, checksums, example counts, and aggregation coefficients.

## Large models

The Hub client uses HF's large-file transport. Current JFrog versions can also
enable Xet for local, remote, and virtual `huggingfaceml` repositories. JFrog
documents Xet support for files larger than 50 GB; consult its version matrix
before selecting `huggingface_hub` and `hf_xet` versions.

Aggregation works one SafeTensors shard at a time instead of loading all client
models as Python
state dictionaries. Peak RAM is driven mainly by one output shard, one current
tensor from each client (normally memory-mapped), and the accumulator. Keep
shards reasonably sized when exporting the initial model.

`--accumulator-dtype float32` is the memory-conscious default. Float64 model
tensors remain float64. Use `--accumulator-dtype float64` when the added
precision justifies roughly doubling accumulator memory. Disk must still hold
the base, every selected submission snapshot, and the aggregate.

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
creates these equivalent console-command aliases:

- `hf2l-init-repo`
- `hf2l-client-download`
- `hf2l-client-train`
- `hf2l-client-upload`
- `hf2l-create-allowlist`
- `hf2l-owner-fedavg`

For example, `hf2l-client-download` is equivalent to
`python -m hf2l.client_download`.

## Local validation

No HF access is needed for the unit tests:

```bash
.venv/bin/python -m unittest discover -s tests -v
```
