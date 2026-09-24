# Client and owner listeners

The client listener watches a global model reference, runs a trusted local
training plugin for each new round, and uploads the participant's update. The
owner listener waits for enough eligible updates on the current immutable base,
runs FedAvg, and publishes the next global model. Both support all four
model-store backends: `huggingface`, `jfrog`, `exchange`, and `local`.

They poll through the shared `ModelStore` interface. No event broker, webhook
endpoint, or extra service is required. The Exchange event feed and HF PR
webhook relay remain separate mechanisms. Run one light polling process per
client and one for the owner; training and aggregation run only when work is
ready. A scheduler can instead invoke either role with `--once`.

`ClientListener` and `OwnerListener` share `DurableListener` in
[`hf2l/listener/engine.py`](../hf2l/listener/engine.py). The shared engine owns
state validation, locking, atomic progress writes, retry backoff, and run limits.
Each role implements its own readiness and work steps through the existing
client workflow or `FedAvgRunner`. The engine has no provider-specific logic.

For Python integrations, subclass `DurableListener`, implement `poll_once()`,
and define the job statuses and `success_status` for that workflow. Persist
progress before remote effects and raise `UncertainOperation` when their outcome
cannot be established. `OwnerListener` accepts a `RoundConfig` and an optional
aggregator through the existing aggregation interface; a custom aggregator
requires a stable `configuration_id` identifying its implementation and settings.
Use listeners as context managers and close the caller-owned model store.

## Install and start

Install the backend and training dependencies described in the
[repository README](../README.md#install-and-authenticate). Run these commands
from the repository root with the project virtual environment.

```bash
.venv/bin/hf2l listen \
  --backend huggingface --repo-id OWNER_OR_ORG/lenet-fedavg-poc \
  --participant alice --state-dir work/alice-listener \
  --plugin lenet --plugin-arg dataset_npz=/private/alice-images.npz \
  --plugin-arg epochs=2
```

The default role is `client`, preserving existing commands and client state.
Equivalent module entry points are `.venv/bin/python -m hf2l.cli listen` and
`.venv/bin/python -m hf2l.cli.listen`. The retained
`.venv/bin/hf2l-client-listen` alias starts the same CLI. The training plugin uses
the same [`train_model(base_dir, output_dir, options)` contract](../README.md#plugin-interface)
as `hf2l.client_train`: write a compatible checkpoint and return JSON metadata
containing a positive integer `num_examples`. Plugins execute locally with the
participant's permissions. Review and install the plugin locally; the listener
does not load training code from remote submissions.

| Client option | Meaning |
| --- | --- |
| `--repo-id`, `--participant` | Required repository or Exchange space and participant identity. |
| `--state-dir` | Required durable directory belonging to this listener. Reuse it on restart. |
| `--plugin` | Required built-in plugin or trusted local Python file. |
| `--plugin-arg KEY=VALUE` | Repeated plugin options; values are JSON-decoded when possible. |
| `--reference main` | Global model reference to watch; defaults to `main`. Standard owner publication advances `main`. |
| `--resolve-uncertain submitted` | Record a previously uncertain upload as submitted after external confirmation. |
| `--resolve-uncertain retry` | Authorize another upload attempt after external reconciliation. |

Start the owner separately with its publishing credentials:

```bash
.venv/bin/hf2l listen --role owner \
  --backend huggingface --repo-id OWNER_OR_ORG/lenet-fedavg-poc \
  --state-dir work/owner-listener --minimum-participants 2 \
  --allowlist /private/approved-participants.json
```

The owner automatically discovers submissions and publishes eligible rounds.
It supports `main` as the global reference and does not require `--participant`.

| Owner option | Meaning |
| --- | --- |
| `--minimum-participants 2` | Minimum distinct eligible participants on the current immutable base; at least two. |
| `--allowlist PATH` | Approved participant mapping used by discovery and validation; recommended for HF/JFrog. |
| `--weighting examples` | FedAvg weighting (`examples` or `uniform`). |
| `--array-backend numpy`, `--accumulator-dtype float32` | Checkpoint reduction implementation and precision. |
| `--plugin`, `--plugin-arg KEY=VALUE` | Optional trusted local evaluation plugin and options. |
| `--claim-lease-seconds 3600` | Exchange claim lease, from 10 to 3600 seconds; renewed while working. |
| `--require-concurrent-publication` | Require backend conditional publication; rejects JFrog's preflight-only behavior. |
| `--resolve-uncertain published` | Record an externally confirmed global publication as complete. |
| `--resolve-uncertain retry` | Authorize another aggregation attempt after reconciling the previous publication. |

| Shared option | Meaning |
| --- | --- |
| `--role client\|owner` | Work to perform; defaults to `client`. |
| `--poll-interval 30` | Seconds between successful polling cycles. |
| `--max-backoff 300` | Upper bound in seconds for retry backoff after errors; at least `--poll-interval`. |
| `--once` | Perform one cycle, including any ready work, then exit. An owner publishes at most one round. |
| `--max-rounds N` | Stop after this many successful submissions (client) or publications (owner) during this invocation. |

Backend selection and authentication use the existing `--backend`, `--endpoint`,
`--token`, and `--local-principal` arguments and their environment equivalents.
Prefer a credential helper or environment configuration over command-line tokens.
Tokens are not saved in listener state. Give the owner and each client separate
credentials and state directories.

A successful `--once` cycle exits `0`, including idle, skipped, and not-ready
cycles. A retryable failure in that mode exits `1`; an uncertain remote operation
exits `2` and requires reconciliation. An interrupted listener exits `130`.
Operational events are JSON lines on standard output; errors go to standard error.

## Backend commands and permissions

### Hugging Face

Authenticate using `hf auth login` or `HF_TOKEN`. A participant needs permission
to read the global model and open an update PR. The client resolves the watched
reference to a commit SHA; the uploaded PR is based on that immutable commit.

The owner discovers eligible update PRs and uses the existing conditional
parent-commit publication. Configure an allowlist to bind approved repository
identities to participants. The existing [HF webhook workflow](FEDAVG_WORKFLOW.md)
is another way to schedule FedAvg after two eligible PRs arrive. Choose a
coordination mechanism for your deployment; neither listener deploys or requires
the webhook relay.

### JFrog

Configure `HF_ENDPOINT` and a participant's `JFROG_ACCESS_TOKEN` or `HF_TOKEN`
as described in the [JFrog setup](../README.md#jfrog-artifactory):

```bash
.venv/bin/hf2l listen \
  --backend jfrog --repo-id OWNER_OR_ORG/lenet-fedavg-poc \
  --participant alice --state-dir work/alice-jfrog-listener \
  --plugin lenet --plugin-arg dataset_npz=/private/alice-images.npz
```

Use `--role owner` with publishing credentials, a separate state directory,
and an allowlist for the owner. Submissions use generated named revisions.
Server permissions must prevent overwriting participant revisions and restrict
`main` publication to one owner. JFrog publication uses a preflight check;
listeners do not add atomic publication or fenced coordination. Run only one
publishing coordinator for a JFrog repository.

### Exchange

Set `EXCHANGE_ENDPOINT` and the participant's `EXCHANGE_TOKEN`, or set
`EXCHANGE_TOKEN_FILE` to a securely maintained token file:

```bash
.venv/bin/hf2l listen \
  --backend exchange --repo-id "$EXCHANGE_SPACE_ID" \
  --participant alice --state-dir work/alice-exchange-listener \
  --plugin vgg-cifar10 --plugin-arg dataset_npz=/private/alice-cifar10.npz \
  --plugin-arg epochs=1
```

The token-file provider rereads the file for requests. An external issuer or
refresher must replace it before expiry; listeners do not issue tokens. An
explicit `--token` or `EXCHANGE_TOKEN` takes precedence over `EXCHANGE_TOKEN_FILE`.

The space must use the FedAvg profile. Participant tokens need access to global
models and permission to publish their own updates. The owner token needs
publication and coordination permissions. The owner listener uses fenced claims,
renews leases, and preserves unresolved claim state across attempts. Publication
of an unreferenced `model.global` record does not trigger training; the owner must
successfully advance `main`. See the [Exchange runbook](EXCHANGE_V3.md) for setup,
authorization, and claim handling.

The [two-client VGG/CIFAR-10 walkthrough](../examples/exchange_cifar10/README.md)
starts `listen_client.py` for each client and `listen_owner.py` for the owner.
With separate state directories and `--max-rounds 2`, all three processes
complete two rounds automatically. Each wrapper uses its bootstrap descriptor
for endpoint and space, then follows current `main`. The descriptor does not
fix a listener's base revision across rounds. Manual commands are also documented.

### Local: two clients and a separate owner

This example uses synthetic LeNet data for a no-network smoke test. Install
`.[examples]` first. Use fresh store and state directories for a new experiment.

Initialize the global model:

```bash
.venv/bin/hf2l init \
  --backend local --endpoint work/listener-store --local-principal owner \
  --repo-id local/listener-demo --plugin lenet --plugin-arg seed=7
```

Run Alice's listener in one terminal:

```bash
.venv/bin/hf2l listen \
  --backend local --endpoint work/listener-store --local-principal alice \
  --repo-id local/listener-demo --participant alice \
  --state-dir work/alice-local-listener --plugin lenet \
  --plugin-arg synthetic_examples=64 --plugin-arg epochs=1 \
  --poll-interval 2 --max-rounds 2
```

Run Bob's listener in another terminal:

```bash
.venv/bin/hf2l listen \
  --backend local --endpoint work/listener-store --local-principal bob \
  --repo-id local/listener-demo --participant bob \
  --state-dir work/bob-local-listener --plugin lenet \
  --plugin-arg synthetic_examples=96 --plugin-arg epochs=1 \
  --poll-interval 2 --max-rounds 2
```

Start the owner in a third terminal, before or after the clients:

```bash
.venv/bin/hf2l listen --role owner \
  --backend local --endpoint work/listener-store --local-principal owner \
  --repo-id local/listener-demo --state-dir work/owner-local-listener \
  --minimum-participants 2 --array-backend numpy \
  --poll-interval 2 --max-rounds 2
```

The owner waits for both initial updates and publishes global round 1. Clients
observe it, train again, submit, and exit after their second submission. The
owner publishes global round 2 and exits. For sequential execution, use `--once`
for each client, then `--once` for the owner; reuse each state directory next time.

The local backend trusts a POSIX filesystem. Principal names attribute operations;
they are not remote authentication. Protect the store and listener directories
using filesystem permissions, and do not use network filesystems.

## Round selection and lifecycle

Clients process the current global round on first start, including the initialized
round. They resolve and pin its immutable revision, validate the round and
checkpoint, run the plugin, and validate output before upload. They recheck the
watched reference before training and upload; stale work is skipped. A reference
can still change immediately after the final check, so owner eligibility checks
remain necessary.

Completed revisions are not trained again. Clients remember the completed source
round number, so metadata-only commits or rollback to an older completed round
do not schedule duplicate work. Each client's revision is pinned independently;
only updates based on the owner's common immutable base are eligible.

Owners keep checking submission metadata while `main` is unchanged. Reaching the
threshold starts an aggregation attempt pinned to that base; it does not guarantee
publication. The runner revalidates identities, manifests, ancestry, checkpoint
hashes, compatibility, and participant counts before reduction. Readiness checks
download metadata only; checkpoint downloads and evaluation happen during an
aggregation attempt. After publication, the owner watches the new global round.

Polling reads current state rather than replaying historical events. An offline
client can skip intervening global rounds and join the current one. Processes
must run to notice readiness promptly, but expensive work runs only when ready.

## Durable state and recovery

Keep each listener's state directory on durable local storage. `state.json`
tracks jobs keyed by immutable revision. Client `jobs/<revision-hash>/`
directories retain `work/` checkpoints and `training-result.json`. Owner jobs use
numbered `attempt-000001/`, `attempt-000002/`, and so on, each with its own output
and `result.json` when completed. Attempts interrupted before publication can be
cleaned up on retry; published and uncertain output is retained. Exchange
`claim-state.json` is outside
attempt directories so retries can reuse it. Do not share state between actors.

An exclusive POSIX lock prevents two processes from operating on one state
directory. Separate directories do not coordinate duplicate listeners for the
same actor. Run one listener per participant and repository, and one publishing
coordinator where the backend requires it.

Progress is saved before side effects. Safe download, training, reduction, and
evaluation failures retry with bounded backoff. Interrupted local work may run
again; plugins should tolerate repeated execution. Owner retries create fresh
attempt directories while preserving claim recovery state. Completed artifacts
consume disk across rounds and are not automatically pruned.

State binds the backend location, repository, role/reference, and configuration
fingerprints. Client identity also binds the participant and training plugin/options.
Owner identity binds aggregation settings, allowlist contents, and evaluation
configuration. Restart
with the same configuration; credentials can be refreshed without changing the
saved identity. Fingerprints do not freeze dataset contents or imported plugin
modules: keep those inputs stable during recovery.

An interrupted remote publication or lost response may already have succeeded.
The listener records publication intent before that operation and stops when its
outcome is uncertain. Preserve the state and inspect the backend's immutable
record or revision, manifest, and reference to establish the outcome.

- For a confirmed client submission, restart with `--resolve-uncertain submitted`.
- For a confirmed owner publication, restart with `--resolve-uncertain published`.
- After establishing that another attempt is appropriate, use
  `--resolve-uncertain retry`. Clients reuse retained trained output subject to
  current-round checks. Owners make a new aggregation attempt while preserving
  backend claim safeguards.

These options are explicit operator decisions, not backend queries. An incorrect
retry can duplicate an operation; unresolved Exchange claims remain subject to
server fencing and cannot be cleared simply by retrying locally. Never delete
state to clear an unknown outcome. This provides durable job tracking, not an
exactly-once delivery guarantee.
