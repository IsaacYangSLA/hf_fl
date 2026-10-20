# Your first federation

This example starts with **no HF²L services installed**. **Org S (Service)**
deploys one shared Compose stack. **Org P (Aggregator)** controls the project
and aggregates model updates. Alice in Org A and Bob in Org B retain their own
training machines, code, and private datasets.

Complete two manual **download → local training → upload → aggregation**
rounds using a tiny NumPy model. No Hugging Face account, Torch, GPU, or external
dataset download is required.

## Responsibilities

| Organization and person | Responsibility | Machine |
| --- | --- | --- |
| Org S: service administrator | DNS, HTTPS, Compose, storage, identity accounts, initial project creation, delegation, service operations | Org S's Linux server |
| Org P: aggregator | Model agreement, participant approval/enrollment, initial checkpoint, aggregation, evaluation, publication, round invitations | Org P's aggregation workstation |
| Org A: Alice | Own login, private dataset, local training, own submission | Org A's training machine |
| Org B: Bob | Same responsibilities independently | Org B's training machine |

Org S and Org P use **separate accounts, credential profiles, and workspaces**.
Org S operates the shared services and identity accounts. Org P retains
project-level participant enrollment and controls aggregation; only Alice and
Bob contribute training updates.

The existing technical names remain unchanged: `bootstrap-admin` is Org S's
service administrator; `owner` is Org P's aggregator account. Commands and
variables such as `--owner owner`, `OWNER_WORK`, `OWNER_PROFILE`, and
`as_owner` refer to Org P's aggregator. Org P keeps the project's `admin`,
`publisher`, and `reader` permissions.

~~~mermaid
flowchart LR
    subgraph OrgS["Org S (Service)"]
        Stack["One Compose stack: HTTPS + identity + Exchange + storage"]
    end
    subgraph OrgP["Org P (Aggregator)"]
        Aggregator["Approve participants / initialize / aggregate / evaluate / publish"]
    end
    OrgS -->|Delegate project and trusted identity metadata| Aggregator
    Aggregator <-->|project operations and checkpoints over HTTPS| Stack
    Alice["Org A: Alice / local data and trainer"] <-->|checkpoints over HTTPS| Stack
    Bob["Org B: Bob / local data and trainer"] <-->|checkpoints over HTTPS| Stack
~~~

**Privacy:** datasets and training programs remain within each organization.
Model updates leave it. Alice and Bob cannot read each other's private updates;
Org P's authorized aggregator and Org S's trusted infrastructure administrators
can access hosted model material. This example provides neither secure aggregation nor differential
privacy, and does not defend against malicious model updates.

## 1. Agree on the project and install the client tools

**Who:** all four organizations. **Machine:** each role's machine.
**Directory:** a new work directory. **Input:** common model agreement and source
commit. **Success:** everyone has the same source/checkpoint contract.
**Handoff:** Org P distributes the agreement and full source revision.

For this example, agree on the supplied two-class model, common feature/label
meanings, participant IDs `alice` and `bob`, and two contributors per round.
Alice uses 64 unique training examples and Bob 96: FedAvg coefficients are
**0.4 and 0.6**. Org P generates a separate 200-example evaluation dataset.
Each round starts from one immutable common base.

### Prerequisites

**Org S server:** Linux, Git, Python 3.12 with venv, Docker Engine and Docker
Compose v2 with the Buildx plugin, persistent disk, and Docker permissions.
Reserve three public DNS names pointing to this server: `exchange.example.org`, `auth.example.org`, and
`objects.example.org`. Allow inbound TCP 80/443 for Caddy and certificate
issuance. Keep backend/database/storage administration ports private.

**Org S administrator only:** install the
[Docker Engine for your Linux distribution](https://docs.docker.com/engine/install/),
the [Compose plugin](https://docs.docker.com/compose/install/linux/), and the
[Buildx plugin](https://github.com/docker/buildx#linux-packages) using Docker's
distribution package instructions. These links cover host prerequisites;
the bootstrap below installs the HF²L service stack.

**Preflight — who:** Org S administrator. **Machine:** Org S Linux server.
**Directory:** any directory. **Input:** installed Docker and authorized daemon
access. **Success:** all three commands report versions without errors.
**Handoff:** proceed to source installation and stack initialization.

~~~bash
docker compose version
docker buildx version
docker info --format '{{.ServerVersion}}'
~~~

If direct daemon access is unavailable but this account already has authorized
noninteractive sudo access, repeat the checks with `sudo -n docker` in place of
`docker`. The stack helper detects direct Docker access first, then that existing
sudo authorization. If neither works, ask the server administrator to provide
approved Docker access before proceeding.

**Org P's aggregator, Alice, and Bob:** Linux (or a Linux environment such as WSL2), Git,
Python 3.12 with venv, package-index access for installation, browser access
(possibly another device), and outbound HTTPS to all three names. The helpers
use POSIX file locking and permissions; native Windows is not supported.
Participants install **no server stack or Docker**.

Replace all example DNS names with Org S's actual names. Use publicly trusted
HTTPS certificates; never disable verification. Private internal TLS is an
explicit alternative for an exercise with configured DNS and CA trust.

### Install one exact source revision independently

Org P selects a reviewed commit **containing this example** and sends everyone
its full 40-character `SOURCE_REVISION`. Do not use a moving `main` as the
version. These development interfaces may be newer than published packages.

~~~bash
export SOURCE_REVISION='<full-commit-ID-containing-this-example>'
git clone https://github.com/IsaacYangSLA/hf_fl.git
cd hf_fl
git checkout --detach "$SOURCE_REVISION"
test "$(git rev-parse HEAD)" = "$SOURCE_REVISION"
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install . ./packages/exchange 'PyJWT[crypto]>=2.9,<3'
export EXAMPLE=examples/first_federation
export EXCHANGE_ENDPOINT=https://exchange.example.org
export ISSUER=https://auth.example.org/realms/hf2l
~~~

All subsequent commands run from **that repository root with its environment
activated**. Each role keeps its own private working directory. On a single
practice machine, use separate terminals and credential profiles; do not share
an authenticated profile between people.

## 2. Org S deploys the shared Compose stack

**Who:** Org S service administrator only. **Machine:** Org S Linux server.
**Directory:** repository root. **Input:** three configured DNS names.
**Success:** service status checks pass over HTTPS.
**Handoff:** service URLs and individually delivered account credentials.

[compose.yaml](compose.yaml) runs PostgreSQL, MinIO, Keycloak, Caddy, Exchange API,
and its verification/cleanup worker. It runs no training code. Only Caddy
publishes ports. Volumes preserve data across an ordinary stop/start.

Bootstrap builds both the Exchange API image and MinIO using Docker Buildx;
no host Go installation is needed. The MinIO build uses an official upstream
source archive pinned by commit and SHA-256, pinned build/runtime images, and
Go module checksum verification. The first build downloads source and Go modules
and can take several minutes. Allow access to the configured registries, GitHub,
Go module proxy/checksum services, and Python package index. Build and source
pins are recorded in [images.example.json](images.example.json).

The upstream [MinIO community repository](https://github.com/minio/minio) is
archived. This example uses its pinned community source for a teaching exercise;
production planning must choose a maintained storage provider and security
policy, then run the [Exchange provider conformance checks](../../docs/EXCHANGE_V3.md#validation-status-and-deployment-limits)
against the selected version and topology. The image retains its upstream source
archive, license and build notice.

Choose a private absolute runtime directory outside the checkout:

~~~bash
export RUNTIME_DIR="$HOME/.local/share/hf2l-first-federation"
python "$EXAMPLE/stack.py" --runtime-dir "$RUNTIME_DIR" init \
  --exchange-host exchange.example.org \
  --auth-host auth.example.org \
  --objects-host objects.example.org
python "$EXAMPLE/stack.py" --runtime-dir "$RUNTIME_DIR" bootstrap
python "$EXAMPLE/stack.py" --runtime-dir "$RUNTIME_DIR" status
~~~

Bootstrap creates the `hf2l` realm, public device-login client `hf2l-cli`, four
distinct accounts (`bootstrap-admin`, `owner`, `alice`, `bob`), current Exchange
schema `0003_workload_grants`, and a private versioned bucket. Database and
storage credentials stay service-side.

Read the generated paths printed by bootstrap. Private `accounts.json` contains
passwords: deliver **only each recipient's own credential** through a private
channel. Never send the whole file to participants. `identities.json` records
actual issuer/subjects from Keycloak; usernames are not JWT subjects.

Ask Org P, Alice, and Bob to check all three HTTPS names from
**their own networks**.
An unauthenticated object-store request may return access denied: distinguish
that from DNS, TLS, or connection failure. A server-local status check does not
prove cross-organization object transfers work.

## 3. Org S creates and delegates the project to Org P

**Who:** Org S administrator. **Machine:** Org S server.
**Directory:** repository root. **Input:** bootstrap-admin login and trusted
identity mapping. **Success:** durable project state with a space ID.
**Handoff:** delegated project state and trusted project identities to Org P.

Device login displays a verification URL and user code. Use the
**bootstrap-admin** account in the browser; put no password on the command line.

~~~bash
export ADMIN_PROFILE="$HOME/.local/share/hf2l-credentials/bootstrap-admin"
export PROJECT_STATE="$RUNTIME_DIR/project.json"
python "$EXAMPLE/auth.py" login --issuer "$ISSUER" \
  --client-id hf2l-cli --profile "$ADMIN_PROFILE"
python "$EXAMPLE/auth.py" identity --profile "$ADMIN_PROFILE"
python "$EXAMPLE/auth.py" run --profile "$ADMIN_PROFILE" -- \
  python "$EXAMPLE/project.py" create \
    --state "$PROJECT_STATE" --name first-federation \
    --identities "$RUNTIME_DIR/identities.json" --owner owner
~~~

Only the deployment bootstrap administrator can create Exchange spaces. The
helper configures the FedAvg types and grants Org P's `owner` account explicit
`admin`, `reader`, and `publisher` permissions. Org P uses project administration
to enroll participants; Org S continues operating the services.

### Handoff: Org S sends project metadata to Org P

On Org S's server, prepare a handoff directory containing only the completed
project state and identity metadata for `owner`, `alice`, and `bob`:

~~~bash
export HANDOFF_DIR="$RUNTIME_DIR/org-p-handoff"
umask 077
mkdir -p "$HANDOFF_DIR"
chmod 700 "$HANDOFF_DIR"
cp "$PROJECT_STATE" "$HANDOFF_DIR/project.json"
python - "$RUNTIME_DIR/identities.json" "$HANDOFF_DIR/identities.json" <<'PY'
import json
import sys
from pathlib import Path

source = json.loads(Path(sys.argv[1]).read_text())
receipt = {
    "issuer": source["issuer"],
    "client_id": source["client_id"],
    "accounts": {
        name: {
            field: source["accounts"][name][field]
            for field in ("username", "subject", "principal_id")
        }
        for name in ("owner", "alice", "bob")
    },
}
output = Path(sys.argv[2])
output.write_text(json.dumps(receipt, indent=2) + "\n")
output.chmod(0o600)
PY
chmod 600 "$HANDOFF_DIR/project.json"
~~~

Org S sends these **two files** to Org P through an authenticated file-transfer
channel, together with the service URLs and agreed source revision. Org P places
them in its own `OWNER_WORK` directory in step 4. Deliver the `owner` account's
individual credential separately.

Org S retains its original `project.json` for setup recovery. Org P uses its own
copy as the working state for enrollment and round invitations. Do not share or
mount Org S's runtime directory: `accounts.json`, bootstrap-admin credentials,
login profiles, private keys, database credentials, and storage credentials stay
with Org S. The two handoff files contain identity/project metadata, not bearer
credentials; keep them private.

## 4. Org P initializes the model and invites participants

**Who:** Org P aggregator. **Machine:** Org P's aggregation workstation.
**Directory:** repository root. **Input:** delegated state, trusted identities,
`owner` account. **Success:** initial global model and two invitations.
**Handoff:** Alice's invitation to Org A, Bob's invitation to Org B.

~~~bash
export OWNER_WORK="$HOME/.local/share/hf2l-owner"
mkdir -p "$OWNER_WORK"
chmod 700 "$OWNER_WORK"
# Place only project.json and identities.json received from Org S here.
export PROJECT_STATE="$OWNER_WORK/project.json"
export OWNER_PROFILE="$OWNER_WORK/login"
python "$EXAMPLE/auth.py" login --issuer "$ISSUER" \
  --client-id hf2l-cli --profile "$OWNER_PROFILE"
as_owner() {
  python "$EXAMPLE/auth.py" run --profile "$OWNER_PROFILE" -- "$@"
}
export SPACE_ID="$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["space_id"])' "$PROJECT_STATE")"
as_owner python "$EXAMPLE/project.py" enroll \
  --state "$PROJECT_STATE" --identities "$OWNER_WORK/identities.json" \
  --user alice --participant alice
as_owner python "$EXAMPLE/project.py" enroll \
  --state "$PROJECT_STATE" --identities "$OWNER_WORK/identities.json" \
  --user bob --participant bob
python "$EXAMPLE/model.py" init --output "$OWNER_WORK/initial-model"
python "$EXAMPLE/model.py" data --output "$OWNER_WORK/evaluation.npz" \
  --examples 200 --seed 33
as_owner hf2l init --backend exchange --repo-id "$SPACE_ID" \
  --model-dir "$OWNER_WORK/initial-model"
for participant in alice bob; do
  as_owner python "$EXAMPLE/project.py" invite \
    --state "$PROJECT_STATE" --participant "$participant" \
    --source-revision "$SOURCE_REVISION" \
    --output "$OWNER_WORK/$participant-round-0.json"
done
as_owner python "$EXAMPLE/project.py" inspect --state "$PROJECT_STATE"
~~~

Enrollment uses trusted Keycloak subjects and approved participant bindings.
Do not accept an unverified JWT payload or arbitrary participant-supplied ID.

An invitation contains endpoints, participant ID, exact source revision, model
agreement and **immutable base revision**. It contains no credentials, private
keys, storage secrets, dataset, or training code. Send it separately from the
account credential. `--repo-id` is an opaque Exchange **space ID**, not a Git URL;
`--base-revision` is an immutable model record ID, not `main` or a source commit.

## 5. Alice and Bob complete their first local training round

**Who:** Alice and Bob separately. **Machine:** each organization's training
machine. **Directory:** repository root. **Input:** own invitation/account.
**Success:** published update ID and actual example count.
**Handoff:** submission ID and base confirmation to Org P, never raw data/code.

Alice sets:

~~~bash
export PARTICIPANT=alice
export NUM_EXAMPLES=64
export DATA_SEED=11
~~~

Bob sets these in **his own terminal**:

~~~bash
export PARTICIPANT=bob
export NUM_EXAMPLES=96
export DATA_SEED=22
~~~

Both run the following independently. Save your own invitation as
`round-0.json` under your private `ACTOR_WORK` directory.

~~~bash
export ACTOR_WORK="$HOME/.local/share/hf2l-$PARTICIPANT"
mkdir -p "$ACTOR_WORK"
chmod 700 "$ACTOR_WORK"
export INVITATION="$ACTOR_WORK/round-0.json"
export PROFILE="$ACTOR_WORK/login"
# Place your own invitation at "$INVITATION" before continuing.
python "$EXAMPLE/auth.py" login --issuer "$ISSUER" \
  --client-id hf2l-cli --profile "$PROFILE"
python "$EXAMPLE/auth.py" identity --profile "$PROFILE"
as_me() {
  python "$EXAMPLE/auth.py" run --profile "$PROFILE" -- "$@"
}
export SPACE_ID="$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["space_id"])' "$INVITATION")"
export BASE_REVISION="$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["base_revision"])' "$INVITATION")"
python "$EXAMPLE/model.py" data --output "$ACTOR_WORK/private-data.npz" \
  --examples "$NUM_EXAMPLES" --seed "$DATA_SEED"

# 1. Download the exact base selected for this round.
as_me hf2l download --backend exchange --repo-id "$SPACE_ID" \
  --base-revision "$BASE_REVISION" --work-dir "$ACTOR_WORK/round-0"

# 2. Run training locally; this trainer makes no service requests.
python "$EXAMPLE/model.py" train \
  --input "$ACTOR_WORK/round-0/base_model" \
  --output "$ACTOR_WORK/round-0/trained_model" \
  --dataset "$ACTOR_WORK/private-data.npz"

# 3. Validate and upload only the compatible checkpoint and metadata.
as_me hf2l upload --backend exchange --work-dir "$ACTOR_WORK/round-0" \
  --trained-dir "$ACTOR_WORK/round-0/trained_model" \
  --participant "$PARTICIPANT" --num-examples "$NUM_EXAMPLES"
~~~

Before using an invitation, compare its source revision, endpoints, participant
and model agreement with Org P's authenticated handoff. The trainer prints
actual `num_examples`; use that count, not batches or repeated epoch visits.

The authentication wrapper renews tokens during a command, atomically updates a
private token file, clears inherited `EXCHANGE_TOKEN` and rejects token
overrides. Do not add `--token`, `--token-file` or token environment assignments.
Only one command can use a given profile at a time; use independent login
profiles for intentional concurrency.

## 6. Org P aggregates, evaluates, and publishes round one

**Who:** Org P aggregator. **Machine:** Org P's aggregation workstation.
**Directory:** repository root with step 4's environment.
**Input:** two successful compatible submissions against the initial base.
**Success:** new global record, evaluation, coefficients 0.4/0.6.
**Handoff:** fresh invitations identifying the next round's base.

~~~bash
export BASE_REVISION="$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["base_revision"])' "$OWNER_WORK/alice-round-0.json")"
as_owner hf2l round --backend exchange --repo-id "$SPACE_ID" \
  --expected-base-revision "$BASE_REVISION" \
  --claim-submissions --claim-lease-seconds 300 \
  --minimum-participants 2 --array-backend numpy \
  --plugin "$EXAMPLE/model.py" \
  --plugin-arg "dataset=$OWNER_WORK/evaluation.npz" \
  --run-state "$OWNER_WORK/round-0-state.json" \
  --output-dir "$OWNER_WORK/round-0-result" --publish --json
as_owner python "$EXAMPLE/project.py" inspect --state "$PROJECT_STATE"
for participant in alice bob; do
  as_owner python "$EXAMPLE/project.py" invite \
    --state "$PROJECT_STATE" --participant "$participant" \
    --source-revision "$SOURCE_REVISION" \
    --output "$OWNER_WORK/$participant-round-1.json"
done
~~~

Read the structured round result: both contributors, actual counts, expected
coefficients, evaluation, previous base, checkpoint hashes and publication.
Evaluation runs before publication; an evaluation failure prevents publication.
This small example reports accuracy/loss without imposing a quality threshold.

The local checkpoint is `round-0-result/aggregated_model`. Do not infer
publication success from that directory alone. The command uses **fenced claims**
and conditional publication against the expected base; discovery alone is
insufficient.

## 7. Complete round two and retrieve the final model

**Who:** Alice/Bob, then Org P aggregator. **Machines/directories:** their existing
environments. **Input:** new `round-1.json` invitations.
**Success:** second aggregate based on the first aggregate.
**Handoff:** final global record and evaluation to authorized collaborators.

Alice and Bob each save the new invitation and repeat, retaining their original
local dataset:

~~~bash
export INVITATION="$ACTOR_WORK/round-1.json"
export BASE_REVISION="$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["base_revision"])' "$INVITATION")"
as_me hf2l download --backend exchange --repo-id "$SPACE_ID" \
  --base-revision "$BASE_REVISION" --work-dir "$ACTOR_WORK/round-1"
python "$EXAMPLE/model.py" train \
  --input "$ACTOR_WORK/round-1/base_model" \
  --output "$ACTOR_WORK/round-1/trained_model" \
  --dataset "$ACTOR_WORK/private-data.npz"
as_me hf2l upload --backend exchange --work-dir "$ACTOR_WORK/round-1" \
  --trained-dir "$ACTOR_WORK/round-1/trained_model" \
  --participant "$PARTICIPANT" --num-examples "$NUM_EXAMPLES"
~~~

After both uploads, Org P's aggregator runs:

~~~bash
export BASE_REVISION="$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["base_revision"])' "$OWNER_WORK/alice-round-1.json")"
as_owner hf2l round --backend exchange --repo-id "$SPACE_ID" \
  --expected-base-revision "$BASE_REVISION" \
  --claim-submissions --claim-lease-seconds 300 \
  --minimum-participants 2 --array-backend numpy \
  --plugin "$EXAMPLE/model.py" \
  --plugin-arg "dataset=$OWNER_WORK/evaluation.npz" \
  --run-state "$OWNER_WORK/round-1-state.json" \
  --output-dir "$OWNER_WORK/round-1-result" --publish --json
as_owner python "$EXAMPLE/project.py" inspect --state "$PROJECT_STATE"
~~~

Use a **new** claim state for each logical round, as shown. Preserve old state
for recovery. Verify round two's base equals round one's published record.

For final retrieval, Org P generates another invitation per participant
with `project.py invite` and a new output filename. Participants read its new
`base_revision` and run `hf2l download` into a fresh directory. Downloading the
final model does not submit an update or start a new round.

## 8. Inspect, stop, and resume

**Who:** Org P inspects project results; Org S operates services.
**Machines/directories:** their existing environments.
**Input:** project state and runtime directory.
**Success:** persistent history and checkpoints survive restart.
**Handoff:** final record/checkpoint and operating ownership.

Org P's artifacts include the initial checkpoint, both result directories, structured
round results and claim state. Participants retain their base/trained
checkpoints, client context and submission receipts. Keep datasets local.

On Org S's server, the **Org S administrator** runs:

~~~bash
python "$EXAMPLE/stack.py" --runtime-dir "$RUNTIME_DIR" stop
python "$EXAMPLE/stack.py" --runtime-dir "$RUNTIME_DIR" start
python "$EXAMPLE/stack.py" --runtime-dir "$RUNTIME_DIR" status
~~~

Then **Org P's aggregator** reruns authenticated `project.py inspect`, verifies the same
space/current record, and asks an authorized participant to download it into a
fresh directory. This confirms stored models remain usable.

When finished, **Org S** runs `stop`. An ordinary stop preserves volumes and runtime
credentials. Only for intentional, irreversible destruction:

~~~bash
python "$EXAMPLE/stack.py" --runtime-dir "$RUNTIME_DIR" reset --confirm-delete-data
~~~

Back up necessary artifacts first. Do not delete runtime credentials while
expecting retained volumes to work with newly generated credentials.

## Use your existing training job

Keep the download/upload commands and replace only the middle step:

~~~bash
python your_existing_train.py \
  --input "$ACTOR_WORK/round-0/base_model" \
  --output "$ACTOR_WORK/round-0/trained_model" \
  --dataset /your/organization/private/data
~~~

These flags are an adapter convention: map them onto your framework or scheduler.
HF²L does not execute code received from another organization. Review your
organization's local code and data permissions.

| Input/output | Contract |
| --- | --- |
| `--input` | Load the complete immutable downloaded checkpoint; do not reinitialize or modify it. |
| `--dataset` | Organization-local path; never include data in invitations/checkpoint uploads. |
| `--output` | Fresh complete checkpoint directory, separate from input. |
| `--num-examples` | Number of unique examples actually used, not batches or epoch visits. |

Preserve identical `config.json`, tensor names/shapes/dtypes and shard filenames
and layout. Write `model.safetensors`, or a valid SafeTensors index and every
referenced shard. Nonfloating values must remain unchanged. An optimizer
snapshot is not a complete model checkpoint.

Architecture, feature/label or layout changes require a new agreement and
compatible initial model. Schema validation cannot establish model quality or
safety.

## Troubleshooting and recovery

| Symptom | Who | Action |
| --- | --- | --- |
| DNS/TLS failure | Org S and affected organization's network operator | Check all three names and trusted chains from the caller. Never bypass TLS verification. |
| API works, object transfer fails | Org S | Check external object reachability, versioning, storage checks and signed Host/path/query preservation. |
| Upload stays pending verification | Org S | Check the independent Exchange worker, database and storage. API readiness alone is insufficient. |
| `401` or wrong scope/audience | Account holder, then Org S | Log in to correct realm/client; verify `at+jwt`, RS256, Exchange audience/scope. Use intended profile/wrapper. |
| `403` or wrong participant | Org P aggregator | Verify actual issuer/subject, explicit roles and participant binding against trusted identities. |
| Peer-private update denied | No repair needed | Expected: Alice and Bob cannot read each other's updates. Org P has the authorized view. |
| Insufficient contributions | Org P aggregator and missing participant | Both uploads must finish against the same base; inspect rejected/skipped inputs. |
| Stale base | Org P aggregator | Inspect current reference and distribute new invitations; do not silently repurpose an old logical round. |
| Incompatible checkpoint | Participant | Preserve configuration, tensor/shard contract and downloaded base. |
| Interrupted project setup or enrollment | Org S for project creation; Org P for enrollment | Retain each organization's own state and retry the same operation; do not blindly create another project. |
| Uncertain publication | Org P aggregator | Inspect reference/result; retry with the **same run-state** and a **fresh output directory**. |
| Expired login/refresh session | Account holder | Device-login again with same profile. Local training needs no token; transfers do. |

Never include credential profiles, `accounts.json`, bearer/refresh tokens or
storage secrets in support reports.

## Next steps

No manager/dashboard, gVisor runtime, remote training agent or automatic
listener is needed: the stack coordinates artifacts while each organization
controls its own training. Read the [Exchange operator guide](../../docs/EXCHANGE_V3.md)
for internals/upgrades and the [CIFAR-10 example](../exchange_cifar10/README.md)
for automatic listeners after understanding these manual handoffs.


## Optional: qualify the example in an isolated local exercise

**Who:** a maintainer or Org S administrator. **Machine:** an isolated Linux
test host, not the organizations' training machines. **Directory:** repository
root. **Input:** a fresh private runtime directory and qualification tools.
**Success:** the verifier reports completed gates in its private summary.
**Handoff:** sanitized results, never credentials or the private evidence tree.

This is not required for Alice and Bob. Install Playwright in a separate test
environment containing the client dependencies above; provide Chromium and
`certutil`. Configure local test DNS (or hosts entries) so these names resolve
to loopback:

~~~text
127.0.0.1 exchange.first-federation.test auth.first-federation.test objects.first-federation.test
~~~

Ensure loopback ports 8443 and 8080 are available, then run:

~~~bash
python "$EXAMPLE/verify.py" \
  --runtime-dir "$HOME/.local/share/hf2l-first-federation-qualification" \
  --python /absolute/path/to/test-environment/bin/python \
  --browser-executable /absolute/path/to/chromium
~~~

Use a new runtime directory for a complete run. The verifier uses real Compose
services, private test HTTPS, independent browser device logins, two training
rounds, authorization failures, token renewal, recovery and persistent restart.
It writes a private `summary.json` under a sibling
`<runtime>-verification/<run-id>/` directory. Inspect gate results: an attempted
run or a partial-stage result is not a passing qualification.

The verifier stops its own stack on completion/failure and removes its owned
containers and network while retaining persistent volumes and private runtime
configuration/evidence. It never performs destructive reset. Review retained
evidence and clean up the owned test stack deliberately when no longer needed.

Local test DNS and CA qualification do **not** verify public certificate
issuance or reachability from other organizations. Org S must still coordinate
the external-network checks in step 2 with Org P, Alice, and Bob before
Org P invites real participants.
