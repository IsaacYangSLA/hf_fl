# Two-client VGG / CIFAR-10 FedAvg with Exchange

This runnable scenario uses the Exchange `/v2` service, a separate verification
worker, and S3 blob transfers to train a VGG model with two clients. Each client
downloads the same immutable global checkpoint, trains on its own CIFAR-10
partition, and submits its checkpoint and sample count. The owner claims both
updates, computes sample-weighted FedAvg, evaluates the aggregate, and publishes
the next global checkpoint with a fenced update of `main`. One listener per
client polls for that publication and starts its next training job. An owner
listener polls for eligible updates and starts aggregation. The three listeners
complete two rounds automatically, each with its own credentials and durable state.

The quick start runs all three actors on one machine with distinct credentials.
It uses real images and a reduced-width VGG-11-style network adapted to 32×32
inputs. This is a workflow demonstration, not an accuracy benchmark. One short
round is not expected to produce a useful classifier.

| Actor | Input | Exchange permissions | Output |
| --- | --- | --- | --- |
| Owner | Initial model, held-out evaluation data | Bootstrap administrator; publisher with coordination capability in its space | Global model and round descriptor |
| `client1` | 256 training images, common round descriptor | Reader/contributor, bound to `client1` | Private training update |
| `client2` | 384 different training images, same descriptor | Reader/contributor, bound to `client2` | Private training update |

For these sample counts, `W_next = 0.4 * W_client1 + 0.6 * W_client2`.
Training images stay on each client's filesystem. Checkpoints travel directly
to/from blob storage using service-issued grants; metadata goes to Exchange.
Private updates are accessible to their author and the authorized owner.

## 1. Install in the source checkout

Run every command below from the repository root using the project `.venv`.
Create it if it does not exist:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
# CPU PyTorch; skip this line if the environment already has suitable PyTorch.
.venv/bin/python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
.venv/bin/python -m pip install -e './packages/exchange[server]' \
  -e '.[examples,exchange,exchange-test]'
```

The examples extra supplies the model's Hugging Face serialization dependency;
this scenario does not contact a Hugging Face repository. It does not require
torchvision. Allow room for the dataset archive and multiple model copies.

## 2. Prepare actual CIFAR-10 partitions

```bash
.venv/bin/python examples/exchange_cifar10/prepare_data.py \
  --output-dir work/exchange-cifar10/data \
  --client1-examples 256 --client2-examples 384 --eval-examples 1000
```

The script downloads the official binary archive into `work/cifar10-cache`,
verifies its published checksum, and parses it without extracting archive paths
or loading pickle. Download speed depends on the dataset host. An existing copy
can be supplied with `--archive /path/to/cifar-10-binary.tar.gz`; it is checked too.

The [official CIFAR-10 dataset](https://www.cs.toronto.edu/~kriz/cifar.html)
contains 50,000 training and 10,000 test images. A fixed seed selects disjoint
training shards and a held-out subset from the test split. The outputs are:

```text
work/exchange-cifar10/data/
  client1.npz       # uint8 NCHW images, int64 labels, source indices
  client2.npz
  evaluation.npz   # test split only
  data.json        # source, checksums, seed, split names and sample counts
```

Existing output directories are refused. Client and owner commands require explicit
NPZ paths, so the VGG plugin's synthetic-data fallback is never selected.

## 3. Start Exchange in terminal A

```bash
.venv/bin/python examples/exchange_cifar10/start_service.py \
  --work-dir work/exchange-cifar10/service --emulated-storage
```

Wait for `Exchange ready`. Keep this terminal open through all rounds. The
launcher runs the actual API and worker with SQLite and a local Moto S3 emulator.
It creates a unique versioned bucket and three private token files:

```text
work/exchange-cifar10/service/
  service.json
  owner.token
  client1.token
  client2.token
  api.log
  worker.log
  storage.log
```

API JWT authentication and membership authorization are enabled. The launcher
generates a temporary signing key, configures its public key as trusted, and
issues distinct RS256 tokens. This is a local credential fixture with a default
24-hour lifetime, not an identity provider. It has no token-refresh service.
HTTP endpoints bind only to loopback; use `--port` and `--storage-port` if the
defaults 8765/8766 are occupied.

Moto demonstrates the transfer flow; it does **not** validate a real provider's
S3 authorization or versioning conformance. See the real-storage option below.

## 4. Owner: create the federation in terminal B

```bash
.venv/bin/python examples/exchange_cifar10/setup_federation.py \
  --service-config work/exchange-cifar10/service/service.json \
  --output-dir work/exchange-cifar10/federation
```

This creates a `fedavg.v1` space, registers shared `model.global` and private
`training.update` types, and binds each client's subject to its participant name.
The owner initializes the built-in `vgg-cifar10` model at width multiplier 0.25
(578,410 parameters), publishes it, and writes `federation/round.json` containing
the space ID, immutable base record ID, endpoint, and target round number 1.
It contains no bearer token. Give both clients this bootstrap descriptor. The
listener uses it to identify the endpoint and space, then watches `main`; its
base revision is not a permanent training target. Each job pins and validates
the current immutable global model. The owner listener also follows current
`main` and accepts only eligible updates based on its common immutable revision.
The manual owner command instead uses the descriptor's exact base.

## 5. Owner: start the FedAvg listener

Run in terminal B after setup completes:

```bash
.venv/bin/python examples/exchange_cifar10/listen_owner.py \
  --round-file work/exchange-cifar10/federation/round.json \
  --token-file work/exchange-cifar10/service/owner.token \
  --eval-data work/exchange-cifar10/data/evaluation.npz \
  --state-dir work/exchange-cifar10/listeners/owner \
  --poll-interval 2 --max-rounds 2
```

The owner checks metadata every two seconds and waits for at least two distinct
eligible participants on current `main`. It reports `not_ready` until the
threshold is met. Leave it running while starting the clients. Each ready round
acquires a fenced claim, validates checkpoints, computes sample-weighted FedAvg
in float32 using NumPy, evaluates on the held-out data, and advances `main`.
In this newly created space, only the two bound clients contribute.

The wrapper selects the existing `vgg-cifar10` evaluation plugin, CPU execution,
a batch size of 128, and two computation threads. Override `--device`,
`--batch-size`, or `--threads` if needed. It never receives training data or
participant credentials. Owner publication remains a privileged operation.

## 6. Clients: start one listener each

Run client 1 in terminal C:

```bash
.venv/bin/python examples/exchange_cifar10/listen_client.py \
  --round-file work/exchange-cifar10/federation/round.json \
  --participant client1 \
  --token-file work/exchange-cifar10/service/client1.token \
  --dataset work/exchange-cifar10/data/client1.npz \
  --state-dir work/exchange-cifar10/listeners/client1 \
  --poll-interval 2 --max-rounds 2
```

Run client 2 in terminal D:

```bash
.venv/bin/python examples/exchange_cifar10/listen_client.py \
  --round-file work/exchange-cifar10/federation/round.json \
  --participant client2 \
  --token-file work/exchange-cifar10/service/client2.token \
  --dataset work/exchange-cifar10/data/client2.npz \
  --state-dir work/exchange-cifar10/listeners/client2 \
  --poll-interval 2 --max-rounds 2
```

Each job performs one local epoch with batch size 64, SGD learning rate 0.01,
CPU execution, and two computation threads. Override `--epochs`, `--batch-size`,
`--learning-rate`, `--device cuda:0`, or `--threads` as appropriate. The submitted
sample count is the shard size, not the number of epoch visits.

Clients immediately train the initialized round and report `submitted` for
`source_round: 0`. The owner discovers those updates and reports `published`
for the same source round after publishing global round 1. Both clients detect
that publication, train again, submit for `source_round: 1`, and exit. The owner
then publishes global round 2 and exits. `--max-rounds 2` bounds each process's
successful work in this invocation. No command is needed between rounds.

These are polling listeners. Their common engine supplies state, locking,
backoff, and run limits; client and owner work remains separate. No broker or
webhook is required. Aggregation begins only after the owner's eligibility and
checkpoint checks succeed.

## 7. Inspect the two published rounds

Each listener writes `state.json` under its state directory. Both client states
should contain two jobs with status `submitted`; the owner should contain two
jobs with status `published`. The source rounds are 0 and 1; current Exchange
`main` points to the resulting global round 2.

Owner output is retained under:

```text
listeners/owner/
  state.json
  jobs/<base-revision-hash>/
    attempt-000001/
      result.json
      aggregated_model/
        fedavg_round.json
        ...checkpoint files...
```

Each published job's `result` in `state.json` identifies its aggregate directory
and publication revision. `result.json` contains the base revision, participants,
weights, evaluation, and publication. With the demo sample counts, expect
`client1` coefficient `0.4` and `client2` coefficient `0.6`; held-out accuracy is
measured, not a target. All updates in an aggregate must refer to its pinned base.

Attempts interrupted before publication can be removed on retry; completed and
uncertain publication artifacts are retained. Unresolved Exchange claim state
is kept in the job's `claim-state.json`, outside those
attempts, and cleared after confirmed completion or abandonment. Client job
checkpoints and training metadata remain under each client's state directory.
Unlike `aggregate.py`, the owner listener does not generate `next-round.json`:
listeners discover the next immutable base directly from `main`.

```mermaid
sequenceDiagram
    participant O as Owner listener
    participant E as Exchange main + blobs
    participant C1 as Client 1 listener
    participant C2 as Client 2 listener
    Note over O,E: Owner initialized global round 0 before listening
    loop Two rounds
        O->>E: Poll main and eligible submission metadata
        E-->>O: Not ready until two distinct eligible participants
        C1->>E: Poll main; pin and download global checkpoint
        C2->>E: Poll main; pin and download global checkpoint
        C1->>C1: Train on client 1 data
        C2->>C2: Train on client 2 data
        C1->>E: Upload update for pinned base
        C2->>E: Upload update for pinned base
        O->>E: Poll; claim eligible updates on current immutable base
        O->>O: Validate, FedAvg, and held-out evaluation
        O->>E: Publish next global model; advance main through claim fence
        Note over C1,C2: Next poll sees the new round
    end
```

### Restarting or scheduling a listener

Reuse the same `--state-dir`, actor identity, datasets, and plugin options when
restarting. Completed work stays recorded and is not repeated. `--max-rounds`
counts successful work during each invocation, so a restart with `--max-rounds 2`
requests two further submissions or publications; it is not a lifetime limit.
Omit it to keep listening until interrupted. For a two-round demo interrupted
after one success, restart that actor with `--max-rounds 1`.

For scheduled or sequential execution, replace `--max-rounds 2` with `--once`
in all three commands, keeping their existing state and configuration. Run each
client once, then the owner once; repeat for the next round. An owner cycle
with fewer than two eligible participants exits successfully without aggregation.
An idle client cycle does not retrain a completed round.

Token files are reread for requests. Longer experiments need a separate issuer
or refresher to replace them before expiry; the temporary service's 24-hour
fixture has no automatic refresh. See the [listener guide](../../docs/CLIENT_LISTENER.md)
for all four backends, configuration binding, backoff, and uncertain-publication
recovery.

### Optional: manual training and aggregation

Use `train_client.py` and `aggregate.py` when you want to start every job
yourself. Choose manual commands instead of listeners for the same actors to
avoid duplicate work. For the initial round:

```bash
.venv/bin/python examples/exchange_cifar10/train_client.py \
  --round-file work/exchange-cifar10/federation/round.json \
  --participant client1 \
  --token-file work/exchange-cifar10/service/client1.token \
  --dataset work/exchange-cifar10/data/client1.npz \
  --work-dir work/exchange-cifar10/round1/client1

.venv/bin/python examples/exchange_cifar10/train_client.py \
  --round-file work/exchange-cifar10/federation/round.json \
  --participant client2 \
  --token-file work/exchange-cifar10/service/client2.token \
  --dataset work/exchange-cifar10/data/client2.npz \
  --work-dir work/exchange-cifar10/round1/client2

# Run only after both clients finish successfully:
.venv/bin/python examples/exchange_cifar10/aggregate.py \
  --round-file work/exchange-cifar10/federation/round.json \
  --token-file work/exchange-cifar10/service/owner.token \
  --eval-data work/exchange-cifar10/data/evaluation.npz \
  --output-dir work/exchange-cifar10/round1/owner
```

The manual owner wrapper verifies exactly `client1` and `client2`, their sample
counts and coefficients, the expected round/base, valid evaluation accuracy,
and a new publication revision. It prints those results and writes
`round1/owner/next-round.json`. For round 2, repeat both client commands with
that descriptor and fresh work directories under `round2/`, then aggregate:

```bash
.venv/bin/python examples/exchange_cifar10/aggregate.py \
  --round-file work/exchange-cifar10/round1/owner/next-round.json \
  --token-file work/exchange-cifar10/service/owner.token \
  --eval-data work/exchange-cifar10/data/evaluation.npz \
  --output-dir work/exchange-cifar10/round2/owner
```

Manual commands pin the descriptor's exact immutable base. Both clients must
receive the descriptor produced by the preceding successful publication. You
can also combine client listeners with manual owner commands: wait for both
`submitted` events for the relevant source round before each aggregation, and
do not start an owner listener concurrently.

## Full-sized training

To use all available images, prepare a different directory with default counts:

```bash
.venv/bin/python examples/exchange_cifar10/prepare_data.py \
  --output-dir work/exchange-cifar10/full-data
```

This produces two disjoint 25,000-image training shards and all 10,000 test
images, giving equal FedAvg weights. Point the actor commands at those files.
Use fresh listener state directories when changing the data or training
configuration. For the full-width model, create a **new federation** using
`setup_federation.py --width-multiplier 1.0` and a fresh output directory
(along with the required `--service-config`). It has 9,225,610 parameters and
requires more compute and checkpoint storage. Each client eagerly loads its
shard into memory. Choose epochs and number of rounds for your experiment;
the demo does not supply an accuracy-tuned training recipe.

## Use a real S3 provider or an existing Exchange service

Instead of `--emulated-storage`, the same temporary launcher can use an existing
authenticated, compatible S3 endpoint:

```bash
# Configure the server's usual AWS credential chain outside the command line.
.venv/bin/python examples/exchange_cifar10/start_service.py \
  --work-dir work/exchange-cifar10/service-s3 \
  --s3-endpoint https://YOUR-S3-ENDPOINT --s3-region us-east-1
```

Its credentials must permit creation of a new bucket, enabling versioning,
normal object/multipart operations, and deletion of its bucket and every version
on shutdown. The launcher runs `check-storage` before reporting readiness. This
is a capability preflight, not the full provider validation suite. S3 credentials
belong only to the service/worker; clients receive scoped transfer grants.
Use the printed `service.json` path in the setup command. The API still runs
locally; this option changes blob storage only. See the
[Exchange runbook](../../docs/EXCHANGE_V3.md) for supported deployment
configuration and provider-validation boundaries.

For an already deployed Exchange service, skip `start_service.py`. Supply a
local JSON configuration to `setup_federation.py` with this shape:

```json
{
  "endpoint": "https://exchange.example.org",
  "issuer": "https://YOUR-TRUSTED-ISSUER",
  "allow_local_http": false,
  "identities": {
    "owner": {"subject": "OWNER-SUBJECT", "token_file": "/private/owner.token"},
    "client1": {"subject": "CLIENT1-SUBJECT"},
    "client2": {"subject": "CLIENT2-SUBJECT"}
  }
}
```

Use actual issuer and subject claims from accepted tokens; all three must use
the specified trusted issuer. The owner must be authorized to create a space
(bootstrap administrator); the script grants the client memberships. Obtain
each client's token through your identity provider and pass its private path
to the corresponding listener or manual training command. Give each client only
its own token, its local data, and the shared round descriptor. The demonstration's local
token directory is for a single trusted operator, not filesystem isolation
between different users. For remote clients, both the API and the granted blob
URLs must be reachable over HTTPS.

## Failure handling and shutdown

Listeners reuse their durable state directories. Restart with the same command
and training configuration; download or training failures retry with backoff,
bounded by `--max-backoff` (300 seconds by default). Safe owner aggregation
and evaluation failures also retry. An uncertain submission or owner publication
stops that listener because the operation may already have succeeded. Preserve
state and inspect the immutable update/global record, manifest, and `main`. After
confirming success, restart clients with `--resolve-uncertain submitted` or the
owner with `--resolve-uncertain published`. Use `--resolve-uncertain retry` only
when another attempt is appropriate; Exchange claim fencing still applies. These
are explicit recovery decisions, not automatic backend queries. See
[durable state and recovery](../../docs/CLIENT_LISTENER.md#durable-state-and-recovery).

The manual training, setup, and owner scripts require fresh work/output
directories. Preserve failed output and inspect service logs rather than
deleting evidence and blindly retrying. A manual client failure may occur after
its submission reached the service; inspect that submission before starting
another attempt. For an owner retry, first reconcile publication, then reuse
the original `--run-state` with a new
`--output-dir`. Do not generate a second claim state for the same attempt.
See [owner recovery](../../docs/EXCHANGE_V3.md#hf²l-application-setup) for the underlying CLI.
After a successful create-space response, setup writes its ID to `setup.json`.
An ambiguous response or local write failure can leave a space without that
file; inspect service state in that case. Setup does not automatically resume
or roll back a partially configured space.

When finished, stop the owner and any running client listeners with Ctrl-C first, then press
Ctrl-C in terminal A. The launcher stops its API/worker and removes only its
unique bucket, including versions and unfinished uploads.
Local datasets, checkpoints, tokens, SQLite, and logs remain for inspection.
**The stopped service cannot be resumed:** its blobs have been deleted. Use
fresh service/federation/round/listener directories for the next demonstration;
the data and download cache can be reused. A cleanup failure reports the bucket in
`service/runtime.json` for follow-up. Hard termination cannot run cleanup.

Authentication and private records do not provide secure aggregation or
differential privacy: the owner reads each submitted checkpoint. The local
fixture is not a TLS, high-availability, or identity-provider deployment test.

## Verification of this scenario

The fully automatic owner-and-client listener flow was validated on September
23, 2026 (September 24 UTC) using the project `.venv`, CPU execution, SQLite,
the authenticated Exchange API, its separate worker, and Moto HTTP blob storage.
It used checksum-verified CIFAR-10 data with 256/384 training images, 1,000
held-out images, and the width-0.25 VGG model:

- The owner started first and waited with `not_ready`. All three listener
  wrappers then completed two rounds and exited 0 with `--max-rounds 2`.
  No manual aggregation command ran between rounds.
- Four client updates produced two owner publications and two completed fenced
  claims. Both clients used the same immutable base in each round, and the
  second round's base was the first owner's publication.
- All 18 checkpoint tensors (578,410 parameters) matched an independent
  float32 calculation `0.4 * client1 + 0.6 * client2` with maximum error zero
  in both rounds.
- Restarting the owner with its existing state and `--once` exited 0 with
  `not_ready` for the next base, adding no publication or claim.
- Shutdown removed the launcher's bucket, stopped all owned processes, and
  released both service ports.

An earlier client-listener run with manually triggered owner rounds additionally
checked interruption: client 1 exited 130 after SIGTERM following its first
submission; an idle `--once` restart preserved state and created no duplicate,
and a later restart submitted the next round. Client 2 remained running throughout.

Earlier manual-client validation checked that one update caused
`409 insufficient_participants`, retrying with preserved owner state succeeded
after the second update, and membership rules denied anonymous and peer-private
reads. Dataset-parser and service lifecycle tests cover malformed input,
partial-start cleanup, and preservation of an unrelated bucket.

Held-out accuracy was 9.5% after each tiny demonstration round; this validates
the workflow, not model quality. Full-dataset, full-width, GPU, and real-provider
training were not run. Moto checks do not establish real S3-provider conformance.
