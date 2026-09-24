# Per-client listener

The client listener watches a global model reference, runs a trusted local
training plugin for each new round it observes, and uploads the participant's
update. It supports all four model-store backends: `huggingface`, `jfrog`,
`exchange`, and `local`.

It uses polling through the shared `ModelStore` interface. No event broker,
webhook endpoint, or extra backend service is required. The Exchange event feed
and the HF PR webhook relay remain separate mechanisms. This command does not
implement SSE, a push subscription, or an owner aggregation listener.

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

The equivalent entry points are `.venv/bin/python -m hf2l.cli listen` and
`.venv/bin/hf2l-client-listen`. The training plugin uses the same
[`train_model(base_dir, output_dir, options)` contract](../README.md#plugin-interface)
as `hf2l.client_train`: write a compatible checkpoint and return JSON metadata
containing a positive integer `num_examples`. Plugins execute locally with the
participant's permissions. They must be reviewed and installed by that
participant; the listener does not load training code from remote submissions.

| Option | Meaning |
| --- | --- |
| `--repo-id`, `--participant` | Required repository or Exchange space and participant identity. |
| `--state-dir` | Required durable directory belonging to this listener. Reuse it on restart. |
| `--plugin` | Required built-in plugin or trusted local Python file. |
| `--plugin-arg KEY=VALUE` | Repeated plugin options; values are JSON-decoded when possible. |
| `--reference main` | Global model reference to watch; defaults to `main`. Standard owner publication advances `main`. |
| `--poll-interval 30` | Seconds between successful polling cycles. |
| `--max-backoff 300` | Upper bound in seconds for retry backoff after errors. |
| `--once` | Perform one polling cycle, including training and upload if a new round is ready, then exit. |
| `--max-rounds N` | Stop after this many new successful submissions during the current invocation. |
| `--resolve-uncertain submitted` | Record a previously uncertain upload as submitted after external confirmation. |
| `--resolve-uncertain retry` | Authorize another upload attempt after external reconciliation. |

Backend selection and authentication use the existing `--backend`, `--endpoint`,
`--token`, and `--local-principal` arguments and their environment equivalents.
Prefer a credential helper or environment configuration over passing a token on
the command line. Tokens are not saved in listener state.

A successful `--once` cycle exits with status `0`, including an idle cycle or a
skipped round. A retryable failure in that mode exits `1`; an uncertain upload
exits `2` and requires reconciliation. An interrupted listener exits `130`.
`--max-backoff` must be at least `--poll-interval`. Operational events are emitted
as JSON lines on standard output; errors are written to standard error.

## Backend commands and permissions

Use one process, credentials, and state directory per participant. Keep owner
credentials with the separate aggregation job.

### Hugging Face

Authenticate as the participant using `hf auth login` or `HF_TOKEN`, then run
the command above. The participant needs permission to read the global model
and open an update PR. The listener resolves the watched reference to a commit
SHA; the uploaded PR is based on that immutable commit.

The existing [HF webhook workflow](FEDAVG_WORKFLOW.md) can separately trigger
owner FedAvg after two eligible PRs arrive. The listener neither deploys nor
requires that relay.

### JFrog

Configure `HF_ENDPOINT` and a participant's `JFROG_ACCESS_TOKEN` or `HF_TOKEN`
as described in the [JFrog setup](../README.md#jfrog-artifactory):

```bash
.venv/bin/hf2l listen \
  --backend jfrog --repo-id OWNER_OR_ORG/lenet-fedavg-poc \
  --participant alice --state-dir work/alice-jfrog-listener \
  --plugin lenet --plugin-arg dataset_npz=/private/alice-images.npz
```

The listener resolves the global revision and validates its downloaded round
metadata and checkpoint. Submissions use generated named revisions. Server
permissions must prevent overwriting participant revisions and restrict `main`
publication to one owner. JFrog publication uses a preflight check; the listener
does not add atomic publication or fenced coordination to that backend.

### Exchange

Set `EXCHANGE_ENDPOINT` to the service endpoint and use the participant's
`EXCHANGE_TOKEN`, or set `EXCHANGE_TOKEN_FILE` to a securely maintained token file:

```bash
.venv/bin/hf2l listen \
  --backend exchange --repo-id "$EXCHANGE_SPACE_ID" \
  --participant alice --state-dir work/alice-exchange-listener \
  --plugin vgg-cifar10 --plugin-arg dataset_npz=/private/alice-cifar10.npz \
  --plugin-arg epochs=1
```

For long-running processes, the existing Exchange token-file provider rereads
the file for requests. An external credential issuer or refresher must replace
the file before expiry; the listener does not issue tokens. An explicit
`--token` or `EXCHANGE_TOKEN` takes precedence over `EXCHANGE_TOKEN_FILE`.

The space must be configured for the FedAvg profile, and the token must grant
the participant access to the global model and permission to publish its own
training update. The listener polls the global reference. Publication of an
unreferenced `model.global` record does not trigger training; the owner must
successfully advance `main`. See the [Exchange runbook](EXCHANGE_V3.md) for space
setup, authorization, and owner claim handling.

### Local: two clients and a separate owner

This example uses synthetic LeNet data for a no-network smoke test. Install
`.[examples]` first; the local backend itself needs no network service. Use a
fresh store and state directories for a new experiment.

The owner initializes the global model:

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

After both clients have submitted the initial round, the owner aggregates:

```bash
.venv/bin/hf2l round \
  --backend local --endpoint work/listener-store --local-principal owner \
  --repo-id local/listener-demo --discover-submissions \
  --minimum-participants 2 --output-dir work/listener-aggregate-1 \
  --array-backend numpy --publish --json
```

Both listeners observe the newly published global round, train again, submit,
and exit after their second successful submission. The owner can aggregate
those updates with the same command and a fresh
`--output-dir work/listener-aggregate-2`. To exercise one round with sequential
commands instead, replace `--max-rounds 2` with `--once` for each client.

The local backend trusts a POSIX filesystem. Principal names attribute local
operations; they are not remote authentication. Protect the store and listener
directories using filesystem permissions, and do not use network filesystems.

## Round selection and lifecycle

On its first start, the listener processes the current global round, including
the initialized round. It does not wait for a change before its first training
job. On later polls it resolves and pins the immutable revision, downloads and
validates the round and checkpoint, then runs the plugin and validates the
result before upload.

The listener rechecks the watched reference before training and before upload.
If the owner advanced the round while the job was running, it discards that
attempt as stale and returns to the latest state. These checks cannot eliminate
a reference change immediately after the final check; owner-side eligibility
validation remains necessary.

Completed revisions are not trained again. The listener also remembers the
completed round number, so a metadata-only commit or rollback to an older
completed round does not schedule another submission. Each client's revision
is pinned independently; only updates based on the owner's common immutable
round base are eligible for aggregation.

Polling reads current state rather than replaying historical events. A client
that was offline can skip intervening global rounds and join the current one.
The listener process must run to notice new rounds promptly, but training runs
only when work is available. A scheduler can instead run the same command with
`--once`, always reusing its durable state directory.

## Durable state and recovery

Keep each listener's state directory on durable local storage. Its `state.json`
tracks jobs; each `jobs/<revision-hash>/` directory retains the job's `work/`
checkpoints and `training-result.json`. Do not share state between participants.
An exclusive POSIX lock prevents two processes
from operating on the same directory simultaneously. Separate directories do
not coordinate duplicate listeners for the same participant: run only one
listener per participant and repository.

The listener saves job progress before side effects and remembers successful
submissions across restarts. Download and training failures can be retried;
training interrupted before a durable completion record can run again, so
plugins should tolerate repeated local execution. Completed training artifacts
are retained for recovery and consume disk space across rounds; the listener
does not automatically prune them. Ordinary retries use backoff capped by
`--max-backoff`.

State is bound to the backend location, repository, watched reference,
participant, and a fingerprint of the training plugin and options. Restart
with the same training configuration; changing it or pointing an existing state
directory at a different repository is rejected. This prevents silently resuming
a partially completed job with a different trainer. Credentials can be refreshed
without becoming part of the saved identity.
The fingerprint covers the plugin source file and option values, not imported
modules or the contents of a dataset path. Keep those inputs stable while
resuming a pending job.

An interrupted upload or lost response is different: the backend may already
have accepted the submission. The listener stops rather than blindly retrying
that upload. Inspect the participant's PR, named revision, Exchange update, or
local submission and its manifest to establish the outcome.

- If the submission was accepted, restart the same command with
  `--resolve-uncertain submitted` to record that outcome locally, then check
  the current global round.
- If reconciliation establishes that a retry is appropriate, restart with
  `--resolve-uncertain retry`. This explicitly authorizes a further upload
  attempt using the retained training output, subject to the current round
  checks. An incorrect decision can create a duplicate submission.

These options are explicit operator decisions, not backend queries. Do not
delete the state directory to clear an uncertain outcome: that discards the
duplicate-suppression and recovery information. This is durable local job
tracking, not an exactly-once upload guarantee.
