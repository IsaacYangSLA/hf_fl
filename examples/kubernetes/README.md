# Run each organization in its own Kubernetes cluster

Kubernetes runs applications packaged as container images. A **pod** is the unit
that runs a container. An image contains the application and its dependencies;
an image registry distributes it. This example reuses the small NumPy model from
[Your first federation](../first_federation/README.md), which trains on generated
numbers rather than downloading a dataset. NumPy is a Python array library.

Org A runs Alice, Org B runs Bob, and Org P runs aggregation in **three separately
controlled clusters**. Org S operates Exchange, the service that stores models
and coordinates submissions. No organization receives another organization's
cluster credentials, private dataset, or operating permissions.

Two execution patterns are supported:

| Pattern | Alice and Bob | Org P |
| --- | --- | --- |
| Persistent plug-in | A pod runs the existing listener, which waits for rounds and calls its locally installed training code. The pod remains running between rounds. | A separate persistent listener pod averages updates and optionally evaluates the result. |
| Prepare / train / clean up | The organization's local client prepares a temporary pod, runs training inside it, retrieves the result, and removes the pod. | The same persistent aggregation pod remains in Org P's cluster. |

A **listener** watches for work and performs its organization's part of a round.
A **plug-in** is trusted local Python code called by the listener. **Aggregation**
combines participant updates; this example uses FedAvg, an average weighted by
each participant's number of examples. A plug-in imported inside a pod runs with
that pod's permissions. Kubernetes does not review training code for its owner.

## Who does what

| Organization | Work and handoff |
| --- | --- |
| Org S | Deploy reachable Exchange and identity services, provide their public address and certificate trust, and assign the required service permissions. Operate no participant cluster. |
| Org P | Obtain the standalone Exchange space and authorize Alice and Bob with their participant bindings and grants. If using a dashboard-managed study, create or manage that study and approve their enrollment too. Agree on model compatibility, initialize the global model in Org P's cluster, and run aggregation. |
| Org A / Alice | Review and install her selected image, provision her private data and credentials, and run her listener or temporary training pods in her own cluster. |
| Org B / Bob | Do the same independently in his own cluster with his own data and credentials. |

A **study** is the dashboard's managed project; an Exchange **space** holds the
federation's model records. This runnable example uses the standalone Exchange
path from the first-federation guide; it does not require the job manager or its
dashboard. Configure that space's model types, permissions, participant bindings,
and grants as that guide describes. Creating a dashboard study does not
automatically configure this standalone listener example. The
[first-federation project setup](../first_federation/README.md)
explains the standalone service handoff. Complete its Org S and Org P setup
sections before the first training round.

When using a dashboard-managed study, each participant must request enrollment
and receive Org P's approval. For the standalone Exchange path here, Org P instead
authorizes each participant's identity, binding, and space grants; there is no
dashboard enrollment step. Review of training code is an optional human process; the pod feature adds no central code
approval requirement. Each participant decides which image it will run. An image
change must preserve the agreed checkpoint format or start a separately
configured project with a compatible initial model.

## Prerequisites and names

A **namespace** groups resources within a cluster. A **context** is a locally
configured cluster connection selected by the `kubectl` command. The connection
file is called a **kubeconfig**; keep it with the organization that owns it.
A **PersistentVolumeClaim**, abbreviated **PVC**, requests storage that survives
a pod replacement. A **Job** runs a bounded task to completion. A **Deployment**
keeps a selected number of application pods running. A **Secret** is a cluster
resource used here to mount private files; it does not replace the cluster's
own access controls or encrypted storage policy.

Each organization needs:

- Its own cluster connection and permission to create a namespace, PVCs, Jobs,
  Deployments, and Secrets. A default storage class must provision the PVCs;
  a storage class tells Kubernetes how to obtain persistent disks.
- A way for its nodes to pull the reviewed training image. Configure a private
  registry's pull credentials locally when required; do not share them with Org S.
- Python 3.14 or 3.15 on the administrative workstation. The renderer below
  uses the versioned `python3.14` command to create configuration files.
  Substitute `python3.15` to select Python 3.15. Docker, an image-building
  tool, is needed where the example image is built.
- Its own Exchange account token in a private file and the public certificate
  authority bundle supplied by Org S. A token proves the account's identity;
  a certificate authority bundle identifies trusted encrypted service endpoints.
- Network access from the **actual pods** to the Exchange address and the object
  download/upload addresses it returns. The loopback address `localhost` refers
  to the pod itself, so the first-federation local tunnel address is unsuitable.
  Use an approved reachable HTTPS address. HTTPS is encrypted web communication.

No incoming connection to Alice's or Bob's cluster is required by Org P or Org S.
Persistent listeners make outgoing service requests. This example gives their
pods no Kubernetes service-account token, which is a credential for the cluster's
own control service.

Commands below use a shell: `export` sets a named value, `$NAME` substitutes that
value, quotes keep a path or value together, and a trailing backslash continues a
command. Replace the illustrative registry and service addresses with your own.
Names beginning with `hf2l-` identify only resources from this example.

## 1. Agree on and build the training image

**Who:** each organization, or a mutually trusted image builder. Run from the
repository root containing the code you reviewed. `TRAINING_IMAGE` names the
image in your registry; `HF2L_VERSION` records its Python package version.
`-f` selects the Dockerfile, `-t` names the output, and the final `.` supplies
the repository as the build input. The image copies only application sources,
not your Git connection settings or private runtime files.

```sh
export TRAINING_IMAGE=registry.example.test/hf2l-training:study-demo
export HF2L_VERSION=0.0.dev0
docker build -f examples/kubernetes/Dockerfile \
  --build-arg HF2L_VERSION="$HF2L_VERSION" -t "$TRAINING_IMAGE" .
docker push "$TRAINING_IMAGE"
```

Agree on the source revision and image digest, the immutable identifier printed
by the registry when the image is pushed. Prefer that digest to a movable tag
when setting `TRAINING_IMAGE` for deployment. Each organization loads or pulls
that image into its own cluster independently. It contains the HF²L Python
client, the Exchange client, NumPy, and the reviewed example trainer; it contains
no services, dataset, account token, or cluster credentials. Torch, a separate
training library, is not needed.

## 2. Each organization prepares only its own namespace

**Who:** Alice on Org A's administrative workstation, Bob on Org B's, and Org P's
operator on Org P's. Run this section separately. `CONTEXT` selects your cluster;
`NAMESPACE` is the example's resource group inside that cluster; `ROLE` selects
`alice`, `bob`, or `owner`. `SPACE_ID` is the existing Exchange space identifier.
`ENDPOINT` is its reachable HTTPS service address. `OUT` is a local directory
for rendered resource descriptions, which contain no account tokens.

```sh
export CONTEXT=your-own-cluster
export NAMESPACE=hf2l-study
export ROLE=alice
export SPACE_ID=your-existing-exchange-space
export ENDPOINT=https://exchange.example.test
export OUT="$HOME/hf2l-kubernetes-$ROLE"
kubectl --context "$CONTEXT" create namespace "$NAMESPACE"
python3.14 examples/kubernetes/configure.py --role "$ROLE" \
  --image "$TRAINING_IMAGE" --space "$SPACE_ID" --endpoint "$ENDPOINT" \
  --output-dir "$OUT"
```

Bob sets `ROLE=bob`; Org P sets `ROLE=owner`. Each uses its own `CONTEXT`, and can
choose its own namespace. If the namespace already exists, inspect it and reuse
it without rerunning `create namespace`. The renderer produces JSON, a structured
text format also accepted by `kubectl`; braces hold named fields and arrays hold
lists. It writes `storage.json`, `data-job.json`, and `listener.json`. Org P also
gets `owner-init.json` for one-time initial publication. Review these files before
applying them.

`TOKEN_FILE` names your private account-token file; `CA_FILE` names the public
certificate authority bundle. The Secret stores them under the literal file
names `token` and `ca.crt`. Its name includes your role. The `--from-file` options
read these files; their contents are not placed in command arguments.

```sh
export TOKEN_FILE="$HOME/private/hf2l-access-token"
export CA_FILE="$HOME/private/hf2l-service-ca.crt"
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" create secret generic \
  "hf2l-$ROLE-exchange" --from-file=token="$TOKEN_FILE" --from-file=ca.crt="$CA_FILE"
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" apply -f "$OUT/storage.json"
```

The two claims hold private data and listener state separately. The generated
resources run as non-administrator user number `10001`, use a read-only image,
limit processor and memory use, and mount data read-only for training. They mount
only this organization's Exchange credentials. They mount no kubeconfig. Have a
cluster administrator adapt storage limits, image-pull policy, and network policy
before using larger models or production data.

## 3. Provision private data inside each organization's cluster

**Who:** Alice, Bob, and Org P, independently. For this synthetic example,
`data-job.json` generates each role's own file `private-data.npz` on its data PVC.
The `.npz` file stores NumPy arrays. Alice uses 64 examples with generation seed
11; Bob uses 96 with seed 22; Org P uses 80 evaluation examples with seed 33.
A seed selects a repeatable sequence for data generation. The datasets differ.

`apply` creates the Job. `wait` blocks until it reports successful completion,
with `--timeout=180s` limiting the wait to 180 seconds. `logs` displays its output.

```sh
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" apply -f "$OUT/data-job.json"
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" wait \
  --for=condition=complete "job/hf2l-$ROLE-data" --timeout=180s
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" logs "job/hf2l-$ROLE-data"
```

For real training, **do not run the generator**. Each organization provisions its
existing data claim with its own approved transfer method and adapts the trainer
and generated claim references. Do not send real data to the example image's
publisher. The two participants can use different data; their output model
structure must match the common base model.

## 4. Org P initializes once, then all three start persistent pods

**Who:** Org P first. Use the `owner` settings from section 2. Org P must already
have permission to publish the global model. In this standalone Exchange
example, Alice and Bob must have authorized space access with their corresponding
participant bindings and grants, as configured in the first-federation guide.
If also using a dashboard-managed study, they must additionally request enrollment
and receive Org P's approval for that study. On a **new, uninitialized**
space, the initialization Job creates the NumPy model and publishes it from
inside Org P's cluster. The state claim retains its publication receipt.

```sh
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" apply -f "$OUT/owner-init.json"
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" wait \
  --for=condition=complete job/hf2l-owner-init --timeout=180s
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" logs job/hf2l-owner-init
```

The Job also publishes a **round description**, the `fedavg_round.json` file
that records the round number, checkpoint files, and their content fingerprints.
The listener needs this valid HF²L record; weights and model configuration alone
are insufficient. If the existing space already has a compatible global model
with its valid round description, skip this Job.
Never rerun initialization to recover a listener. If initialization fails or its
publication outcome is uncertain, inspect the Job output and remote space before
retrying; do not delete its receipt or overwrite a possibly published model.

**Who:** Org P, Alice, and Bob, each using their own role and connection. `apply`
starts the role's Deployment; `rollout status` waits for its pod to start; `logs
-f` follows new output until interrupted. `--timeout=180s` is a startup limit,
not a training duration.

```sh
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" apply -f "$OUT/listener.json"
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" rollout status \
  "deployment/hf2l-$ROLE" --timeout=180s
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" logs -f "deployment/hf2l-$ROLE"
```

Org P waits for two updates. Alice's and Bob's pods train against their own data,
upload their model updates, and wait for the next global model. Org P aggregates
inside its own pod. The supplied example counts are 64 for Alice and 96 for Bob. Adding them gives
a total of 160 examples. Dividing Alice's 64 examples by that total gives weight
0.4; dividing Bob's 96 examples by the same total gives weight 0.6. Only model artifacts and metrics cross
the organization boundary.

These pods have no round limit and keep running between rounds. Observing two
rounds does not automatically stop the example. A running pod alone does not
prove that learning is making progress: check each listener's logs and the
published global-model revisions. A single replica and the Deployment's
`Recreate` replacement policy avoid deliberately starting two listeners over one
state directory. Preserve the state PVC when replacing a pod; do not run a second
listener over the same state manually.

The image's default command shows help. The rendered Deployment explicitly runs
`hf2l listen`; it does not start the job manager, a server, or a cluster-wide
controller. This supports organization-run listeners rather than remote
participant scheduling by the manager.

## 5. Keep account tokens current

**Who:** each account holder using that account's existing sign-in or approved
renewal process. Exchange tokens expire. The client reads `EXCHANGE_TOKEN_FILE`
before requests; that environment setting names a file rather than freezing a
token value at startup. The example mounts the whole Secret directory, so
Kubernetes can eventually project Secret updates into the running pod. It does
not use a `subPath` mount, which would pin an individual mounted file.

After replacing your local `TOKEN_FILE` with a fresh token, the following command
creates a proposed Secret update locally and pipes it to `apply`. The `|` passes
one command's output directly to the next, and `--dry-run=client -o json` generates
the description without creating a second Secret. Keep your terminal and cluster
administrative access private. Do not set `EXCHANGE_TOKEN` as well: it takes
precedence over the file setting.

```sh
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" create secret generic \
  "hf2l-$ROLE-exchange" --from-file=token="$TOKEN_FILE" --from-file=ca.crt="$CA_FILE" \
  --dry-run=client -o json | \
  kubectl --context "$CONTEXT" --namespace "$NAMESPACE" apply -f -
```

Allow for Kubernetes' projection delay. Expired tokens prevent authenticated
operations until renewed. Inspect the listener logs; if it exited, restart it
after renewal while preserving its state. This
example does not install a background token-renewal service or store refresh
credentials in the training image. Check failures and renew promptly; see the
[listener recovery guide](../../docs/CLIENT_LISTENER.md) for uncertain operations.

## 6. Optional: prepare, train, and clean up a temporary participant pod

**Who:** Alice or Bob on their own administrative workstation or organization-run
client. Org P's aggregation Deployment stays in its own cluster. A temporary
training pod receives only the selected base model, local trainer options, and
access to its organization's data PVC. Exchange authentication stays with the
local client; the temporary training pod receives no Exchange or cluster token.
Do not also run that participant's persistent listener against the same round.

Install the current HF²L client and Exchange client as described in the
[first-federation guide](../first_federation/README.md). Run the following host
commands from that repository root with the `.venv` environment created
there. `kubectl` must be available on this local client. Make a private copy of `alice-pod.example.json` and adapt it
for your own role. This configuration uses JSON fields: `kubeconfig` names your
absolute cluster-connection file; `context` selects its connection; `namespace`
selects the target resource group; `image` names the reviewed worker;
`plugin` names the trainer inside it; `dataset_claim` names your own data PVC.
The `resources` fields request and cap processor and memory. In the example,
`100m` is one tenth of a processor core, `1` is one whole core, and `Mi` denotes
multiples of 1,048,576 bytes of memory. Timeout fields are seconds;
`max_transfer_bytes` bounds transferred checkpoint data in bytes.
The supplied limit is 67,108,864 bytes, or 64 times 1,048,576 bytes. No other
organization should receive this private configuration or kubeconfig.

`BASE_DIR` is an already downloaded immutable round checkpoint; `TRAINED_DIR`
is a separate local directory for the trained output; `OPTIONS_FILE` is a private
JSON file holding the two trainer options. `pod_config` points to your private
pod configuration, while `dataset` names the data file **inside the pod**.
The `cat` command writes the following JSON through `EOF`, the chosen closing
marker, into that file. Replace the absolute path before running it.

```sh
export BASE_DIR="$HOME/private/round/base_model"
export TRAINED_DIR="$HOME/private/round/trained_model"
export OPTIONS_FILE="$HOME/private/round/options.json"
cat > "$OPTIONS_FILE" <<'EOF'
{"pod_config": "/private/alice/pod.json", "dataset": "/data/private-data.npz"}
EOF
.venv/bin/python -m hf2l.kubernetes run --base-dir "$BASE_DIR" \
  --output-dir "$TRAINED_DIR" --options-file "$OPTIONS_FILE"
```

The combined `run` command performs preparation, training, result retrieval, and
cleanup. To place these operations in an existing three-step training process,
use the following phases. `pre` creates the pod and stages the base; `train`
executes the trainer inside it; `post` retrieves its result and removes the pod.
`cleanup` removes an interrupted attempt's pod without claiming successful
training. The adapter records the selected attempt beside the base directory;
do not delete that record to retry an uncertain operation.

```sh
.venv/bin/python -m hf2l.kubernetes pre --base-dir "$BASE_DIR" \
  --output-dir "$TRAINED_DIR" --options-file "$OPTIONS_FILE"
.venv/bin/python -m hf2l.kubernetes train --base-dir "$BASE_DIR"
.venv/bin/python -m hf2l.kubernetes post --base-dir "$BASE_DIR"
```

An external three-step runner must call `cleanup --base-dir "$BASE_DIR"` when
training fails or is interrupted before `post`; skipping its cleanup step can
leave a pod allocated. Prefer the combined `run` command or the built-in
`kubernetes` training plug-in, which performs cleanup on failure. For example,
replace a local trainer selection with `--plugin kubernetes --plugin-arg
pod_config=/private/alice/pod.json --plugin-arg dataset=/data/private-data.npz`.
Use the existing [separate download/train/upload workflow](../first_federation/README.md#5-alice-and-bob-complete-their-first-local-training-round)
to download before this step and upload only its verified successful output
using your own account. No new Exchange protocol or central cluster access is
required. A failed or uncertain attempt must be inspected before retrying.

## 7. Pause and clean up only your own resources

**Who:** each organization. First Org P sets `ROLE=owner` and scales its listener
to zero, then Alice and Bob each scale theirs to zero using their own settings.
`--replicas=0` asks the Deployment to run no pods. Participants may finish a local
update against the last published model before they stop. This is a pause, not
a claim of a coordinated final-round barrier. Check the logs for uncertain
publication before resuming.

```sh
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" scale \
  "deployment/hf2l-$ROLE" --replicas=0
```

To resume, keep both PVCs and apply `listener.json` again; it restores one replica
using the saved listener state. To remove application pods after preserving any
needed models and logs, delete only the resources rendered for your own role:

```sh
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" delete -f "$OUT/listener.json"
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" delete -f "$OUT/data-job.json" --ignore-not-found
```

Org P also deletes its initialization Job with `delete -f "$OUT/owner-init.json"`
when it no longer needs its output. These commands preserve data and state.
Deleting `storage.json` destroys the claims and may delete their underlying data,
depending on the cluster's retention settings; do that only after your own export
and retention decision. Removing this example does not tear down Org S services
or another organization's resources.

## Continue the same round after a pod stops

This optional example uses a **checkpoint**, a complete save of one
participant's training progress. A replacement pod continues the same round
from the latest verified checkpoint. A **round** is one cycle in which Alice and
Bob train from Org P's shared model and Org P combines their updates. When the
shared model advances, the participants start a new round using that model.

Org A and Org B each operate their own Kubernetes namespace, a named area of a
cluster, and control their own data, training pods and storage. Org P runs the
combining process in its own cluster. Org S runs the shared services.

Each participant keeps two areas on storage that lives beyond a pod:

- **Received models** contain verified copies of Org P's versioned shared models.
  Training treats each version as read-only.
- **Private recovery state** contains local checkpoints, a record of training
  progress, and a separate location for a finished result awaiting submission.
  Only the finished model and approved metrics go to the shared services.

The **starting-model fingerprint** is a value calculated from the shared model's
file contents. HF²L combines it with the study, participant, round, starting
model version, training settings, training code and dataset versions to identify
the work to recover. Keep the original dataset and pinned container image
available while a round can still be resumed. A **container image** packages the
trainer and the software it uses. Pinning means keeping the exact image by its
content fingerprint.

Use an independent storage claim, a Kubernetes request for storage that
survives pod deletion. Size it for the current and previous checkpoint, a
checkpoint being written, the received model, and a completed result awaiting
submission. Use storage that supports finishing and making a whole directory
visible in one operation. Test recovery on each storage type you use. A disk
tied to one cluster machine can support replacement on that machine. Moving to
another machine requires storage that remains available there.

Pause, interruption, and cancellation have different outcomes.

| Operation | What the participant should expect |
|---|---|
| Planned pause | The trainer finishes an update, saves progress and reports that it is paused. Wait for that report before deleting or scaling down the pod. Resume explicitly. |
| Unexpected pod stop | A replacement restores the latest usable save once the previous execution is confirmed stopped. Work after that save may repeat. |
| Cancellation | The saved request prevents automatic restart. |
| Completed training | Recovery reuses the verified result for submission. |
| Shared model advances | The next round loads that shared model. Previous-round progress stays associated with its original starting model. |

If the grace period for pod shutdown expires, the latest earlier completed
checkpoint remains usable. A missing pod record or an inaccessible machine does
not confirm that its old process has stopped. Resolve that condition before
starting a competing replacement. If storage becomes unavailable, restore access
to it before attempting recovery.

### Prepare participant recovery settings

Each participant creates a private settings file in **JSON**, a text format for
named values. Braces group the settings, quoted names identify each setting,
colons separate names from values, commas separate settings, and brackets group
a list. Supply the following values.

- `study_id` as an identifier that uniquely names this study instance. Use the
  same identifier for both participants in the same study.
- `trainer_version` as the identifier of the exact training image, including the
  training code and its software dependencies.
- `dataset_version` as the identifier of the exact local dataset contents, such
  as a fingerprint returned by the `sha256sum` command on that file.
- `runtime_path_options` as a list of arguments that identify paths inside a pod.
  The example's `dataset` argument points to its local input path. Its content is
  identified separately by `dataset_version`.
- Optional `max_bytes` and `max_files` as the maximum size in bytes and number of
  files allowed in one saved bundle.

In this template, replace `example-study-01`, `your-pinned-image-id` and
`your-dataset-fingerprint` with the actual identifiers described above.

```json
{
  "study_id": "example-study-01",
  "trainer_version": "your-pinned-image-id",
  "dataset_version": "your-dataset-fingerprint",
  "runtime_path_options": ["dataset"]
}
```

The example trainer uses one process and reads each group of input examples
synchronously, meaning it finishes using a group before preparing the next.
Its checkpoint contains model parameters, the state used to calculate
parameter changes, the shuffled input order and next position, the state of
random input transforms, and counts used to report training metrics. A trainer
that prepares input in the background needs its own verified save and restore
support for that work. A change in training settings, code or data requires an
explicit compatibility decision before restoring old state.

### Persistent listener

A **listener** is a program that watches for new shared models and invokes the
training plug-in. For each participant, use your existing example role, image,
space, service address and output directory with the manifest generator.
A **manifest** describes the resources Kubernetes should run. Add the
`--recovery-config` option followed by the path to your settings file. The
generator adds `recovery-config.json`, the configuration resource to apply in
the participant's namespace, and adds recovery arguments to the listener
manifest. The listener's private storage already appears inside the pod at
`/work`. Its recovery state is in `/work/recovery`.

Apply the generated configuration resource before starting the updated
listener. To plan a stop, request pause, confirm the saved paused status, and
then stop or replace the pod. The listener reads the durable record after
replacement and waits for an explicit resume. After an unexpected stop,
Kubernetes restarts the listener and its recovery helper selects any unfinished,
eligible work to restore.

For the commands below, `CONTEXT` selects your cluster, `NAMESPACE` selects
your study's named area, and `OUT` is the directory produced by the example
generator. Set `LISTENER` to the deployment name in `listener.json`. A
**deployment** tells Kubernetes to keep the listener running. Use your
participant's values. The dollar sign before a name asks the shell to insert
its value. The quote marks keep that value together as one argument.

`kubectl apply -f` applies the resource from the named file. After your storage
and data are ready, apply the recovery configuration and listener.

```sh
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" apply -f "$OUT/recovery-config.json"
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" apply -f "$OUT/listener.json"
```

`kubectl exec` runs a command in an existing pod. The target
`deployment/$LISTENER` selects the listener's deployment. The two hyphens
`--` end the Kubernetes options. The `python` command here is Python 3.14
inside the example image. Its `-m` option runs the named module.
Here `hf2l.recovery_client` is the participant's recovery control command,
`status` displays saved work, and `--root` gives the private directory to
inspect. The response contains `work_id`, the identifier of an exact round
request, and `phase`, its current stage.

```sh
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" exec "deployment/$LISTENER" -- \
  python -m hf2l.recovery_client status --root /work/recovery
```

Set `WORK_ID` to the value of `work_id` for the round you want to pause.
Use `pause` to request a pause. `--work-id` identifies the work affected by
the request. Run the status command again until the phase is `paused`, meaning
the listener has stopped training and saved recovery state.

```sh
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" exec "deployment/$LISTENER" -- \
  python -m hf2l.recovery_client pause --root /work/recovery --work-id "$WORK_ID"
```

You can now replace the listener pod and keep its storage claim. Wait for the
replacement listener to start. The `resume` action tells it to continue the
same work. The `cancel` action instead records that the work must stop.

```sh
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" exec "deployment/$LISTENER" -- \
  python -m hf2l.recovery_client resume --root /work/recovery --work-id "$WORK_ID"
```

The opt-in renderer uses `/work/recovery-listener` for the listener's saved
progress record. Keep that path and `/work/recovery` through replacement.
Begin with a new study, or enable recovery before a new round starts. For an
existing study, stop the legacy listener and confirm any previous worker and
submission have settled before enabling the new listener.

### Temporary training pods

Use the same recovery settings and the same instance of the example trainer.
In this mode a **supervisor** is the participant's process that starts and
observes temporary pods. Run it with access to the same private storage when
it restarts. The supervisor keeps the cluster connection files. The workers
receive the verified starting model, any verified recovery checkpoint and
the read-only dataset. Each worker has a separate writable directory for
its saves and result.

Start with your existing temporary pod settings. Select the example trainer
path and use separate claims for the dataset and for recovery. A **claim**
is a named request for Kubernetes storage. Mount the recovery claim in the
supervisor, and allow the worker to mount its assigned areas of that same
claim. Use a storage class that supports concurrent mounts to your supervisor
and worker placement. A claim that only supports mounts on one machine
requires both on that machine. Storage that supports mounts from multiple
machines lets those processes run on different machines.

Add `recovery_volume` to the pod settings. It is a group of settings in the
same JSON format described above. `claim` is the name of the participant-owned
recovery claim, and `mount_path` is its absolute mount path in the
supervisor. `pause_grace_seconds` is the time allowed for a worker to finish
an update and save when asked to pause. `max_restarts` bounds replacement
attempts after confirmed worker stops. Use the selected image's content
identifier in the existing `image` setting. For a locally tagged test image,
also set `image_id` to the expected exact image identifier reported by
Kubernetes.

The following value assumes the supervisor mounts a claim named
`alice-recovery` at `/var/hf2l/recovery`. It allows 30 seconds for a worker
to save and allows two replacement attempts.

```json
{
  "recovery_volume": {
    "claim": "alice-recovery",
    "mount_path": "/var/hf2l/recovery",
    "pause_grace_seconds": 30,
    "max_restarts": 2
  }
}
```

The supervisor needs permission in the participant's namespace to read,
create, patch and delete its pods and read its storage claims. Give the
supervisor and this example's worker account, numbered 10001, access to their
respective directories on the mounted claim. The recovery directory passed
to HF²L must be inside that mount. For this example,
`/var/hf2l/recovery/state` is a suitable recovery directory.

Use the same `hf2l.recovery_client` commands from the supervisor with
`--root` set to that directory. The `resume` action changes the saved
request. A running supervised launcher can then continue, or you can rerun
the same manual launch with the original work directory and settings.
An automatic listener can use this launcher as its training plug-in. For
restart of the supervisor itself, keep its launch command and mounted
storage under a restart mechanism controlled by the participant.


With Exchange, the artifact service that shares models, select the round's
starting revision before launching. A **revision** is the identifier of an
exact published model version. The following values configure the command.

- `SPACE_ID` names the participant's Exchange space and `ROLE` is that
  participant's name, `alice` or `bob`.
- `ROUND_WORK` is the original private work directory for this round. Keep
  it available to the supervisor. Prepare it using the normal manual
  workflow's model download step.
- `BASE_REVISION` is the intended starting model revision.
- `POD_CONFIG` points to the supervisor's pod settings, based on
  `alice-pod.example.json` with your cluster, namespace, image, claims and
  the recovery settings described above.
- `RECOVERY_ROOT` is the private recovery directory on the recovery claim.
  `RECOVERY_CONFIG` points to the participant's recovery settings file.
- `--backend exchange` selects Exchange, `--repo-id` selects its space,
  `--participant` selects the local name, `--work-dir` gives the workspace,
  and `--base-revision` pins the starting shared model.
- `--plugin kubernetes` invokes the temporary pod launcher.
  Each `--plugin-arg` passes one named setting. The equals sign separates
  its name and value. `pod_config` selects the pod settings file and
  `dataset` points to the private dataset as seen inside the worker.
- `steps=100` sets the number of completed parameter updates.
  `checkpoint_every=10` saves the complete state every ten updates.
- `--recovery-root` and `--recovery-config` enable the new recovery
  interface together. A backslash at the end of a line continues the
  command on the next line.

```sh
.venv/bin/python -m hf2l.client_train --backend exchange --repo-id "$SPACE_ID" \
  --participant "$ROLE" --work-dir "$ROUND_WORK" --base-revision "$BASE_REVISION" \
  --plugin kubernetes --plugin-arg pod_config="$POD_CONFIG" \
  --plugin-arg dataset=/data/private-data.npz \
  --plugin-arg steps=100 --plugin-arg checkpoint_every=10 \
  --recovery-root "$RECOVERY_ROOT" --recovery-config "$RECOVERY_CONFIG"
```

For an automatic listener that launches temporary workers, run the listener
as the participant's supervisor. Give it its own saved listener state path
and configure the same plug-in, pod settings and recovery arguments. The
listener selects the starting revision as it observes new shared models.

### Adapt your own training code

A training **plug-in** is the function HF²L calls to train or evaluate the
participant's model. To add recovery, provide a function named
`train_recoverable` with four arguments. `base_dir` is the read-only starting
model directory, `output_dir` is where to write the finished model,
`options` holds the plug-in's settings, and `context` supplies recovery
operations for this round. Keep your existing `train_model` function for
work that uses the original plug-in interface.

- `context.checkpoint_dir` is the verified private checkpoint to restore
  when present. `context.completed_steps` is the count of saved updates.
  Continue from the next unfinished update.
- `context.save(step, writer)` saves progress after `step` completed
  updates. The `writer` function receives a new directory and must finish
  writing all related state before returning. Save step zero before the first
  update. Keep private training state in these directories.
- `context.pause_requested()` tells you when to stop at a completed update.
  At that boundary save the current step if
  `context.last_saved_step`, the newest complete save, is older.
  Call `context.pause()` to end the callback with the paused outcome.
- At completion, write the publishable model to `output_dir` and return
  the usual example count and metrics. For the supplied trainer, the
  example count equals the size of the participant's input dataset.
  Repeating unsaved updates after a stop leaves that count the same.

The runnable trainer in `trainer.py` includes model parameters, the running
average of recent parameter changes, input ordering, progress counters and
random choices in each save. It demonstrates reproducible recovery with
fixed software and one process. A custom trainer must also save any
additional state that changes its subsequent updates. Test this on a small
run by comparing an uninterrupted result to a paused and an abruptly stopped
run resumed from a complete checkpoint.

Ordinary pod removal keeps recovery storage. Delete the storage only
after settling finished results, cancelling remaining work, and confirming
every execution that uses it has stopped. Retain the original shared
model, compatible settings and trainer image for any work you still
intend to recover.

Recovery uses one durable workspace per participant round and starting model.
Keep its mount path, recovery root, and saved submission files available at
the same locations when replacing a pod. Use the original workspace for
continuation. Starting another workspace with the same recovery root for
that round is rejected.
