# Generic Hugging Face federated learning demo

> **Supported workflows:** this repository supports both synchronous **FedAvg**
> and sequential **cyclic federated learning**. Swarm learning follows the same
> immutable PR-to-PR checkpoint handoff; the swarm's peer-selection policy is
> an external coordination concern.

## Contents

- [Design overview](#design-overview)
- [Install and authenticate](#install-and-authenticate)
- [Owner: initialize a repository](#owner-initialize-a-repository)
- [Client option A: three independent steps](#client-option-a-three-independent-steps)
  - [Download the exact base](#1-download-the-exact-base)
  - [Train with any local code](#2-train-with-any-local-code)
  - [Validate and upload a PR](#3-validate-and-upload-a-pr)
- [Client option B: trusted training plugin](#client-option-b-trusted-training-plugin)
- [Cyclic federated learning without FedAvg](#cyclic-federated-learning-without-fedavg)
- [FedAvg: validate, average, and publish client PRs](#fedavg-validate-average-and-publish-client-prs)
  - [Automatically discover the current round](#automatically-discover-the-current-round)
  - [Explicitly select PRs](#explicitly-select-prs)
- [Large models](#large-models)
- [Security and protocol limitations](#security-and-protocol-limitations)
- [Local validation](#local-validation)

The Hub repository provides versioned model transport without hard-coding a
model class, dataset, or training loop into the workflow. In FedAvg mode,
multiple clients train from one common commit and the owner averages their
updates. In cyclic mode, one client trains the preceding client's PR checkpoint
and passes a new PR to the next client. A linear swarm uses the cyclic pattern;
a branching swarm can use the FedAvg path when several peers train from the
same checkpoint.

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

## Cyclic federated learning without FedAvg

The same client scripts can also implement cyclic federated learning, sometimes
called cyclical weight transfer. There is no averaging: exactly one participant
trains the checkpoint and hands that result to the next participant. For four
participants, the lineage is:

```text
main@C0
  -> Alice PR@A1
  -> Bob PR@B1
  -> Carol PR@C1
  -> Dave PR@D1
  -> Alice PR@A2
  -> ...
```

More precisely, after Dave produces `D1`, Alice downloads `D1`, trains it, and
creates the next PR. The order repeats as `Alice -> Bob -> Carol -> Dave ->
Alice`. With two participants it is simply `Alice -> Bob -> Alice`.

Each handoff uses an immutable commit SHA:

1. Alice starts with the initial `main` SHA, uses the download/train/upload
   workflow above, and sends Bob her PR revision and PR head SHA.
2. Bob passes Alice's PR head SHA as `--base-revision`, trains that checkpoint,
   uploads his result, and sends his new PR head SHA to the next participant.
3. Every later participant repeats the same operation using only the immediate
   predecessor's PR head SHA. After the last participant, control returns to
   Alice.

For example, Bob's download command is:

```bash
.venv/bin/python client_download.py \
  --repo-id OWNER_OR_ORG/my-fedavg-model \
  --base-revision ALICE_PR_HEAD_SHA \
  --work-dir work/bob-cycle-1
```

Bob then trains `work/bob-cycle-1/base_model` and runs `client_upload.py` as
shown above with `--participant bob`. The upload creates a new Hub PR whose
parent is Alice's pinned commit. Hugging Face stores PRs as repository refs, so
Bob's commit retains Alice's commit as an ancestor even though neither PR has
yet been merged into `main`. See the Hub documentation for [PR refs and local
access](https://huggingface.co/docs/hub/en/repositories-pull-requests-discussions)
and the [`parent_commit` behavior of
`create_commit`](https://huggingface.co/docs/huggingface_hub/en/package_reference/hf_api#huggingface_hub.HfApi.create_commit).

Use the exact PR head SHA for a handoff, not only `refs/pr/N`, because the ref
can move if its author updates the PR. `client_download.py` resolves either form
to a SHA and records it as `base_commit` in `fedavg_client_context.json`.

### Operating rules for the cycle

- Only the designated next participant should extend the chain. HF can store
  two PRs with the same parent, so `parent_commit` preserves ancestry but does
  not prevent two participants from creating a fork.
- Do not merge intermediate PRs. Keep `main` fixed while the chain is active,
  then merge only the latest accepted PR at the chosen release boundary.
- Never run `owner_fedavg.py` on the cyclic PRs. It requires multiple updates
  from one common `main` commit and computes an average, which is a different
  protocol.
- Keep using new work directories. The upload step verifies that each trained
  checkpoint has the same tensor names, shapes, dtypes, configuration, and
  shard layout as its immediate predecessor.
- Put non-secret cyclic metadata such as `protocol`, `cycle`, `position`, and
  `predecessor_commit` in `--metadata-json`. Each commit preserves the manifest
  that was current at that point, providing an auditable lineage.
- Do not execute code from a predecessor's PR. Use reviewed local training code
  and treat the downloaded content as model data.

At a checkpoint or release boundary, the repository owner can review and merge
only the newest PR in the chain; its ancestry contains all preceding cyclic
updates. The owner should first verify that the newest PR still descends from
the intended `main` SHA and close the older, superseded PRs after the merge.
The Hub supports merging through its UI or
[`HfApi.merge_pull_request`](https://huggingface.co/docs/huggingface_hub/en/package_reference/hf_api#huggingface_hub.HfApi.merge_pull_request).

The current `fedavg_round.json` value does not advance at each cyclic handoff;
it belongs to the FedAvg publishing path. Use the training metadata for manual
cyclic tracking. A fully automated cyclic deployment should add a dedicated
state record containing the ordered participant list, cycle number, expected
next participant, predecessor SHA, and latest accepted PR. An [HF
webhook](https://huggingface.co/docs/hub/en/webhooks) can notify an external
coordinator when a PR changes, but that coordinator must still enforce the
order and select a single successor.

## FedAvg: validate, average, and publish client PRs

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
