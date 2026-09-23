# Two-client VGG / CIFAR-10 FedAvg with Exchange

This runnable scenario uses the Exchange `/v2` service, a separate verification
worker, and S3 blob transfers to train a VGG model with two clients. Each client
downloads the same immutable global checkpoint, trains on its own CIFAR-10
partition, and submits its checkpoint and sample count. The owner claims both
updates, computes sample-weighted FedAvg, evaluates the aggregate, and publishes
the next global checkpoint with a fenced update of `main`.

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

Existing output directories are refused. Both actor wrappers require explicit
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
It contains no bearer token. Both clients must receive this exact descriptor.

## 5. Clients: train independently and submit

Client 1 runs:

```bash
.venv/bin/python examples/exchange_cifar10/train_client.py \
  --round-file work/exchange-cifar10/federation/round.json \
  --participant client1 \
  --token-file work/exchange-cifar10/service/client1.token \
  --dataset work/exchange-cifar10/data/client1.npz \
  --work-dir work/exchange-cifar10/round1/client1
```

Client 2 runs, optionally in another terminal at the same time:

```bash
.venv/bin/python examples/exchange_cifar10/train_client.py \
  --round-file work/exchange-cifar10/federation/round.json \
  --participant client2 \
  --token-file work/exchange-cifar10/service/client2.token \
  --dataset work/exchange-cifar10/data/client2.npz \
  --work-dir work/exchange-cifar10/round1/client2
```

Each command performs one local epoch with batch size 64, SGD learning rate 0.01,
CPU execution, and two computation threads. Override with `--epochs`,
`--batch-size`, `--learning-rate`, `--device cuda:0`, or `--threads` as appropriate.
The submitted sample count is the shard size, not the number of epoch visits.
Wait for both commands to finish successfully before invoking the owner.

## 6. Owner: aggregate, evaluate, and publish

```bash
.venv/bin/python examples/exchange_cifar10/aggregate.py \
  --round-file work/exchange-cifar10/federation/round.json \
  --token-file work/exchange-cifar10/service/owner.token \
  --eval-data work/exchange-cifar10/data/evaluation.npz \
  --output-dir work/exchange-cifar10/round1/owner
```

This requires at least two eligible participants on the expected base, acquires
an exclusive round claim, validates the checkpoints, accumulates in float32,
evaluates on the owner's held-out data, and publishes through the claim fence.
In this newly created space, only the two bound clients contribute. The wrapper
checks the persisted result for exactly `client1` and `client2`, their sample
counts and coefficients, the expected round/base, valid evaluation accuracy,
and a new published revision.

Expected coefficient output:

```text
client1: coefficient=0.400000
client2: coefficient=0.600000
held_out_accuracy=...   # measured, not an accuracy target
new_base_revision=...
next_round_file=.../round1/owner/next-round.json
```

Inspect `round1/owner/result.json` for publication and evaluation evidence and
`round1/owner/aggregated_model/` for the resulting checkpoint. While the operation
is unresolved, `round1/owner.run-state.json` preserves claim/publication recovery
state. The runner clears it after confirmed completion or abandonment.

## More rounds and full-sized training

For round 2, repeat both client commands with:

- `--round-file work/exchange-cifar10/round1/owner/next-round.json`
- Fresh client work directories under `work/exchange-cifar10/round2/`
- The same respective data shard and token as before

Then repeat the owner command with that same round descriptor and
`--output-dir work/exchange-cifar10/round2/owner`. Always use the descriptor
produced by the preceding successful owner publication. Reusing a mutable
`main` name independently on each client would lose the common-base guarantee.

To use all available images, prepare a different directory with default counts:

```bash
.venv/bin/python examples/exchange_cifar10/prepare_data.py \
  --output-dir work/exchange-cifar10/full-data
```

This produces two disjoint 25,000-image training shards and all 10,000 test
images, giving equal FedAvg weights. Point the actor commands at those files.
For the full-width model, create a **new federation** using
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
to the corresponding training command. Give each client only its own token,
its local data, and the shared round descriptor. The demonstration's local
token directory is for a single trusted operator, not filesystem isolation
between different users. For remote clients, both the API and the granted blob
URLs must be reachable over HTTPS.

## Failure handling and shutdown

The actor scripts refuse reused work/output directories. Preserve failed output
and inspect the service logs rather than deleting evidence and blindly retrying.
A client failure may occur after its submission reached the service; inspect
that submission before starting another attempt. For an owner retry, first
reconcile publication, then reuse the original `--run-state` with a new
`--output-dir`. Do not generate a second claim state for the same attempt.
See [owner recovery](../../docs/EXCHANGE_V3.md#hf²l-application-setup) for the underlying CLI.
After a successful create-space response, setup writes its ID to `setup.json`.
An ambiguous response or local write failure can leave a space without that
file; inspect service state in that case. Setup does not automatically resume
or roll back a partially configured space.

When finished, press Ctrl-C in terminal A. The launcher stops its API/worker and
removes only its unique bucket, including versions and unfinished uploads.
Local datasets, checkpoints, tokens, SQLite, and logs remain for inspection.
**The stopped service cannot be resumed:** its blobs have been deleted. Use
fresh service/federation/round directories for the next demonstration; the data
and download cache can be reused. A cleanup failure reports the bucket in
`service/runtime.json` for follow-up. Hard termination cannot run cleanup.

Authentication and private records do not provide secure aggregation or
differential privacy: the owner reads each submitted checkpoint. The local
fixture is not a TLS, high-availability, or identity-provider deployment test.

## Verification of this scenario

Validated on September 23, 2026 using the project `.venv`, CPU execution,
SQLite, the actual Exchange API/worker, and Moto blob storage:

- Two complete training/aggregation/publication rounds on the checksum-verified
  official archive, using 256/384 training images and 1,000 held-out images.
- All 18 checkpoint tensors (578,410 parameters) matched the independent
  float32 calculation `0.4 * client1 + 0.6 * client2` exactly in both rounds.
  Both clients' weights changed from their common starting model.
- Aggregation with only one update returned `409 insufficient_participants`.
  After client 2 submitted, retrying with the preserved state published round 2.
- Anonymous API access was denied; each client could read the shared global
  model but could not read the other client's private update. The owner could
  read both updates. `main` and the next-round descriptor matched publication.
- The ten offline dataset-parser/preparation tests passed. Service lifecycle
  checks covered isolated credentials, partial-start failure, and cleanup that
  preserved an unrelated bucket. External-endpoint lifecycle checks also used
  an emulator; these checks do not establish real S3-provider conformance.

Held-out accuracy was 9.5% after each tiny demonstration round. Full-dataset,
full-width, GPU, and real-provider training were not run for this scenario.
