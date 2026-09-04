# Generic Hugging Face FedAvg demo

This demo coordinates a synchronous federated-learning round through a Hugging
Face model repository without hard-coding a model class, dataset, or training
loop into the Hub workflow.

The shared checkpoint contract is deliberately small:

- `config.json`
- either `model.safetensors`, or `model.safetensors.index.json` and its shards
- identical tensor names, shapes, dtypes, configuration, and shard filenames
  across the round

Clients can either use one trusted local Python plugin for the complete flow or
run download, arbitrary training, and upload as three separate commands. Only
weights, configuration, and non-secret submission metadata are added to a
client PR. Client datasets remain local.

## Design overview

[`DESIGN_SLIDES.md`](DESIGN_SLIDES.md) is a concise four-slide overview of the
system architecture, client and owner operation sequence, credential boundaries,
and large-model transfer and aggregation strategy. A rendered version is also
available as [`DESIGN_SLIDES.pdf`](DESIGN_SLIDES.pdf).

## Install and authenticate

Each person uses a separate HF account and local environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/hf auth login
```

Alternatively, set `HF_TOKEN` securely. Every command resolves credentials in
this order: `--token`, `HF_TOKEN`, then the token cached by `hf auth login`.
Never share tokens. The owner needs repository write permission. Clients use
their own credentials and need permission to open pull requests.

## Owner: initialize a repository

Initialize from any intentional, local HF-style model export:

```bash
.venv/bin/python init_repo.py \
  --repo-id OWNER_OR_ORG/my-fedavg-model \
  --model-dir /path/to/exported-model
```

The directory may also contain model code, tokenizer files, and a model card;
those files are copied during initialization. Local `.git`, `.cache`,
`__pycache__`, and symlinks are excluded. Review the directory before upload.

Or initialize using a trusted local plugin. The included plugin preserves the
original LeNet demo:

```bash
.venv/bin/python init_repo.py \
  --repo-id OWNER_OR_ORG/lenet-fedavg-demo \
  --plugin plugins/lenet_demo.py \
  --plugin-arg seed=20260903
```

The script validates the checkpoint before creating the HF repository and
prints the initial `main` commit SHA. Give that exact SHA to all clients.

## Client option A: three independent steps

### 1. Download the exact base

```bash
.venv/bin/python client_download.py \
  --repo-id OWNER_OR_ORG/my-fedavg-model \
  --base-revision OWNER_SUPPLIED_COMMIT_SHA \
  --work-dir work/alice-round-0
```

This creates:

```text
work/alice-round-0/
├── base_model/                  immutable input checkpoint
└── fedavg_client_context.json   repo, base SHA, and source round
```

Use a new work directory for every attempt and round.

### 2. Train with any local code

Your trainer is entirely independent of these scripts. It must load
`base_model` and write a complete checkpoint to another directory:

```bash
python /private/my_train.py \
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

### 3. Validate and upload a PR

```bash
.venv/bin/python client_upload.py \
  --work-dir work/alice-round-0 \
  --trained-dir work/alice-round-0/trained_model \
  --participant alice \
  --num-examples 12500 \
  --metadata-json /private/alice-training-metadata.json
```

The script checks the trained checkpoint against the downloaded base and opens
a PR whose parent is the exact base commit. Send the printed `pr_revision`
(such as `refs/pr/1`) to the owner. Do not merge the PR directly.

## Client option B: trusted training plugin

`client_train.py` composes the same download and upload functions around a
trusted local plugin:

```bash
.venv/bin/python client_train.py \
  --repo-id OWNER_OR_ORG/lenet-fedavg-demo \
  --base-revision OWNER_SUPPLIED_COMMIT_SHA \
  --participant alice \
  --work-dir work/alice-round-0 \
  --plugin plugins/lenet_demo.py \
  --plugin-arg synthetic_examples=1000 \
  --plugin-arg epochs=8 \
  --plugin-arg learning_rate=0.2
```

For private LeNet NPZ data, add
`--plugin-arg dataset_npz=/private/alice-images.npz`. The example NPZ format is
`x` shaped `[N, 28, 28]` or `[N, 1, 28, 28]` and integer `y` shaped `[N]`.

Plugins are ordinary Python and execute with the caller's permissions. Use
only reviewed local files; the scripts never load code from an HF PR.

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

## Owner: validate and average client PRs

### Automatically discover the current round

With `--discover-prs`, the owner does not need to supply individual `--pr`
arguments. The script lists the repository's open pull requests and selects
the submissions that are eligible for the current round.

The recommended discovery mode also uses an allowlist that binds each approved
HF username to the participant ID that must appear in that user's submission
manifest. Copy and edit the example:

```bash
cp participant_allowlist.example.json participant_allowlist.json
```

```json
{
  "alice-hf": "alice",
  "bob-hf": "bob"
}
```

HF usernames are matched case-insensitively; participant IDs are matched
exactly. Each username and participant ID must appear only once, so the file
defines a one-to-one identity mapping. Do not commit the real allowlist if its
membership is sensitive; `participant_allowlist.example.json` is intended to
remain a placeholder template.

Then discover eligible open PRs and aggregate without changing HF:

```bash
.venv/bin/python owner_fedavg.py \
  --repo-id OWNER_OR_ORG/my-fedavg-model \
  --discover-prs \
  --allowlist participant_allowlist.json \
  --output-dir work/owner-check-round-1
```

For each run, automatic discovery:

1. Pins the current `main` commit and reads its current FedAvg round.
2. Lists open model-repository PRs and rejects authors outside the allowlist.
3. Pins each candidate PR's head commit and confirms it descends from current
   `main`.
4. Downloads only `fedavg_submission.json` and verifies its repository, base
   commit, source round, participant ID, and positive example count.
5. Downloads full checkpoints only for eligible PRs, then validates their
   tensor and shard layouts before aggregation.

In discovery mode, unauthorized, stale, or invalid-manifest PRs are reported as
`skipped_pr=...` and do not stop the round. At least two eligible PRs are
required. A checkpoint-layout mismatch still stops aggregation because the
models cannot be averaged safely. If multiple eligible PRs claim the same
participant ID, aggregation also stops so the owner can close the superseded
PR or explicitly choose one with `--pr`.

Running `--discover-prs` without `--allowlist` is supported but prints a
warning and considers every compatible open PR. Do not use that mode for an
untrusted or public HF repository: participant names and example counts are
self-reported, and compatibility checks do not protect against poisoned model
updates.

### Explicitly select PRs

Manual selection remains available:

```bash
.venv/bin/python owner_fedavg.py \
  --repo-id OWNER_OR_ORG/my-fedavg-model \
  --pr 1 \
  --pr 2 \
  --output-dir work/owner-check-round-1
```

You may also add `--allowlist participant_allowlist.json` to manual selection;
the selected PR authors must then match their mapped participant IDs.

For either selection mode, the owner verifies that current `main` is the
clients' declared base, every PR descends from it, HF authors and participant
IDs satisfy the optional allowlist, participant IDs are distinct, example
counts are positive, and checkpoint schemas match. It computes
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
.venv/bin/python owner_fedavg.py \
  --repo-id OWNER_OR_ORG/lenet-fedavg-demo \
  --pr 1 --pr 2 \
  --output-dir work/owner-check-round-1 \
  --plugin plugins/lenet_demo.py \
  --plugin-arg eval_examples=1000
```

After inspecting the aggregate, rerun into a new directory and publish:

```bash
.venv/bin/python owner_fedavg.py \
  --repo-id OWNER_OR_ORG/my-fedavg-model \
  --discover-prs \
  --allowlist participant_allowlist.json \
  --output-dir work/owner-publish-round-1 \
  --publish \
  --tag fedavg-round-1
```

Publication uses `parent_commit=BASE_SHA`; HF rejects it if `main` changed
after validation. The script then reads `main` back and verifies the published
SHA. Client PRs remain unmerged because each contains one local model, not the
aggregate. The new `fedavg_round.json` records whether PRs were discovered or
selected explicitly, whether an allowlist was enforced, and each accepted PR's
HF author, participant ID, pinned commit, example count, and aggregation
coefficient.

## Large models

The Hub client transparently uses HF's large-file transport. Aggregation works
one SafeTensors shard at a time instead of loading all PR models as Python
state dictionaries. Peak RAM is driven mainly by one output shard, one current
tensor from each client (normally memory-mapped), and the accumulator. Keep
shards reasonably sized when exporting the initial model.

`--accumulator-dtype float32` is the memory-conscious default. Float64 model
tensors remain float64. Use `--accumulator-dtype float64` when the added
precision justifies roughly doubling accumulator memory. Disk must still hold
the base, every selected PR snapshot, and the aggregate.

## Security and protocol limitations

This is an orchestration demo, not a secure or Byzantine-robust FL system:

- The owner can inspect every client model, and updates can leak training data.
- Example counts and participant names are self-reported.
- There is no secure aggregation, differential privacy, signing, attestation,
  malware sandboxing, or poisoning defense.
- Plugins are trusted local code. Never execute code supplied by a client PR.
- All clients in one round must use the same architecture and checkpoint layout.

## Local validation

No HF access is needed for the unit tests:

```bash
.venv/bin/python -m unittest discover -s tests -v
```
