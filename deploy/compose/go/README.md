# Go services with Docker Compose

Docker Compose starts a group of packaged services from one configuration file.
This example runs the Go Exchange server and its independent background worker.
An optional service starts the Go job manager's dashboard and application
interface. The image contains Go executables; it runs no Python server or
participant training.

The implementation languages of HF²L's own components are:

| Component | Implementation and location |
| --- | --- |
| Exchange server and background worker | Go, in this Compose deployment. |
| Optional manager server | Go, in this Compose deployment. |
| Dashboard page | HTML, CSS, and JavaScript, embedded in the manager. These describe page structure, appearance, and browser behavior. |
| Client library, trainer, and aggregation application | Python, in each organization's own environment, outside this Compose deployment. |

**Who:** Org S operates the shared services. **Machine:** Org S's Linux server.
**Directory:** repository root. Org P aggregates models using its client tools.
Alice and Bob install and start the agreed trainer themselves on their own
machines and private data.

## Scope and prerequisites

This is a **services-only example**, not an installer for the complete
infrastructure or managed execution system. Org S first provides:

| Dependency | Preparation |
| --- | --- |
| Docker Engine and Compose 2.24.0 or later | Authorized Docker access. This Compose version supports optional environment files. |
| PostgreSQL | Dedicated Exchange database/user and, for the optional manager, a separate manager database/user. Use deployment databases, not SQLite. |
| Keycloak or a compatible login provider | Exchange identity/token configuration from the [Exchange runbook](../../../docs/EXCHANGE_V3.md#configure-and-start). The manager additionally needs its confidential browser client and exact callback from the [manager login guide](../../../docs/JOB_MANAGER.md#2-human-login-and-authorization). |
| Versioned S3-compatible storage | S3 is the object-storage interface implemented by providers such as MinIO. Prepare a private versioned bucket and credentials for the documented transfers, verification, and cleanup operations. |
| Certificates and trust | HTTPS encrypts connections and verifies server identity. Its underlying certificate protocol, TLS, requires server certificates matching the names clients use, matching private keys, and trusted issuing certificates. |
| Network access and persistence | Containers must reach the database, login provider, and storage. Clients must reach the advertised Exchange, login, and model-storage addresses. Preserve databases, storage versions, and private configuration across restarts. |

Inside a container, `localhost` identifies that container, not the Docker host
or another container. Use reachable dependency addresses and certificates
matching their names. Keep database and storage-administration ports private.

The [beginner Compose stack](../../../examples/first_federation/README.md)
also runs Go Exchange, and additionally prepares its supporting services.
Use that walkthrough when starting with no infrastructure installed. This file
is a separate services-only deployment, not an override for the beginner stack.
Its generated environment cannot simply be reused: database addresses belong to
its own Docker network, and it does not configure the manager database or browser
login client. Python operator tools may prepare configuration or storage; they
do not run an Exchange or manager server.

This example does not start a scheduling controller, execution agents, private
transfer services, or an isolated training runtime. Follow the separate
[managed deployment guide](../../jobs/README.md) for those components and their
qualification. Starting the dashboard alone does not execute queued jobs.
Native participant trainers can use their own graphics processors; the managed
executor remains processor-only.

## 1. Prepare source and private files

Build from the exact reviewed source revision agreed by the organizations.
Record that revision and any local changes with the deployment evidence.
The build downloads pinned base images and Go dependencies; the host does not
need Go installed.

The commands below run from the repository root. `HF2L_CONFIG_DIR` names a new
private absolute directory outside the checkout. `$HOME` expands to your home
directory. `umask 077` makes newly created files private. `mkdir -p` creates
missing directories; `chmod 700` permits only the owner to access the directory.

~~~sh
export HF2L_CONFIG_DIR="$HOME/.config/hf2l-go-compose"
umask 077
mkdir -p "$HF2L_CONFIG_DIR"
chmod 700 "$HF2L_CONFIG_DIR"
~~~

Keep this directory and all private evidence out of Git. Use different private
directories and dependency namespaces for independent deployments.

| File inside that directory | Required contents |
| --- | --- |
| `compose.env` | Compose settings generated below. |
| `exchange.env` | Exchange database, identity, and storage settings. |
| `service-ca.crt` | Public issuing certificates trusted for outgoing login, storage, and other service connections. Include all required public/private issuers. |
| `exchange-server.crt` | Exchange server certificate and required intermediate certificates. |
| `exchange-server.key` | Matching private key. |
| `jobs.env` and `jobs.json` | Manager environment and operational settings, only when enabling the manager. |
| Manager certificates and secret files | Files referenced by manager settings, only when enabling the manager. |

Private files must be regular files owned by the account running the containers,
without symbolic links. A symbolic link redirects one path to another; the Go
private-file readers reject this substitution. Set private keys, configuration,
and secrets to mode 0600: owner read/write only. Public certificate files may use
mode 0644, readable by other accounts; the private parent directory still limits
access.

Generate `compose.env` below. `id -u` and `id -g` supply your numeric user/group
identifiers so the non-root container process can read your owner-only files.
The host directory is mounted read-only at `/run/hf2l` in each container.
`cat` writes the lines between the `EOF` markers; `>` replaces the named file.
Run this only for a new configuration, or preserve intentionally changed values.

~~~sh
cat > "$HF2L_CONFIG_DIR/compose.env" <<EOF
HF2L_CONFIG_DIR=$HF2L_CONFIG_DIR
HF2L_SERVICE_UID=$(id -u)
HF2L_SERVICE_GID=$(id -g)
HF2L_BIND_ADDRESS=127.0.0.1
HF2L_EXCHANGE_PORT=8441
HF2L_MANAGER_PORT=8082
HF2L_GO_IMAGE=hf2l-go-services:approved-release-1
EOF
~~~

The default address `127.0.0.1` accepts connections only from the server itself.
The numbers 8441 and 8082 are host ports for Exchange and the manager.
`HF2L_GO_IMAGE` names the packaged Go programs; the colon separates their name
from the version label, here `approved-release-1`. Choose a new unique label
for every reviewed source/build and keep it unchanged for that deployment.
Independent deployments must not build different sources under the same label.
For clients on another machine, provide approved routing to these listeners or
change `HF2L_BIND_ADDRESS` to the intended private server address and permit the
corresponding traffic. Keep certificate verification enabled. Exchange itself
still receives an encrypted connection; forwarded headers cannot replace it.

## 2. Configure Exchange

An environment file contains one `NAME=value` setting per line; `=` separates a
setting's name from its value. Fill in `exchange.env` using the full
[Exchange configuration guide](../../../docs/EXCHANGE_V3.md#configure-and-start).

| Setting | Value to supply |
| --- | --- |
| `EXCHANGE_DATABASE_URL` | Dedicated PostgreSQL address and credentials; encode reserved password characters as required by the connection-address format. |
| `EXCHANGE_ISSUER` | Exact trusted login issuer address. |
| `EXCHANGE_AUDIENCE` | Registered Exchange token recipient, normally `exchange`. |
| `EXCHANGE_JWKS_URL` or `EXCHANGE_JWT_PUBLIC_KEY` | Exactly one trusted token-verification key source: published verification-key address or explicit public key. |
| `EXCHANGE_ADMIN_SUBJECT` | Actual bootstrap administrator account subject assigned by the provider, not its display name. |
| `EXCHANGE_S3_ENDPOINT` | Storage address reachable from the Go containers. |
| `EXCHANGE_S3_PUBLIC_ENDPOINT` | Client model-transfer address if different; it must identify the same bucket. |
| `EXCHANGE_S3_BUCKET`, `EXCHANGE_S3_PREFIX`, `EXCHANGE_S3_REGION` | Private bucket, owned object-name prefix, and signing region. |
| `EXCHANGE_S3_ACCESS_KEY`, `EXCHANGE_S3_SECRET_KEY` | Storage service credentials, supplied together. |

Compose explicitly sets `SSL_CERT_FILE` and `AWS_CA_BUNDLE` to
`/run/hf2l/service-ca.crt`. These select trusted issuing certificates for outgoing
service and storage connections. Install the file before running maintenance
containers.

Obtain server certificates through your organization's approved process.
Configure identity tokens using the complete
[Go Exchange contract](../../../docs/GO_EXCHANGE.md#configuration-and-services);
a generic provider-default token is not automatically an Exchange credential.
Compose expands variable references in unquoted and double-quoted environment
values. Use its [environment-file quoting rules](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/#env-file-syntax)
to preserve literal secret values, including dollar signs; do not treat these
files as interchangeable with shell scripts. Validate quoting with non-secret
sample values rather than printing expanded production credentials.
A published verification-key address avoids multiline public-key values in the
environment file. Keep real credentials out of shell history and support output.

## 3. Build and check configuration

The shell function `dcompose` abbreviates Docker Compose. `--env-file` selects
private Compose settings; `--file` selects the repository configuration.
`"$@"` forwards later arguments unchanged. Keep `HF2L_CONFIG_DIR` set and run
from the repository root.

~~~sh
dcompose() {
  docker compose \
    --env-file "$HF2L_CONFIG_DIR/compose.env" \
    --file deploy/compose/go/compose.yaml "$@"
}
dcompose config --quiet
dcompose build exchange-api exchange-worker
~~~

For a second independent deployment, `--project-name` overrides the default
Compose resource name. Choose a unique name and different host ports in its own
`compose.env`, then use that project-name option for **every** command, including
maintenance, startup, and shutdown. For example, `hf2l-go-second` below is an
arbitrary new resource name; replace it with your chosen name:

~~~sh
dcompose --project-name hf2l-go-second config --quiet
~~~

`config --quiet` validates configuration without printing expanded secrets.
`build` creates the shared Go service image. Neither command initializes the
deployment databases.

Use administrator-approved Docker access consistently. If the account already
has authorized noninteractive administrator access, use `sudo -n docker` in the
function instead of `docker`. Do not weaken socket permissions or grant the
containers privileged access.

## 4. Initialize and start Exchange

`run` creates a maintenance container. `--rm` removes it afterward; `--no-deps`
prevents it starting other services. `exchange-api` selects service settings;
the absolute executable path selects the Go program. `init-db` initializes an
empty database. Run the following **only for a new database**:

~~~sh
dcompose run --rm --no-deps exchange-api /usr/local/bin/hf2l-exchange init-db
~~~

For retained data, do not run initialization. Back it up and follow the
[Go Exchange cutover procedure](../../../docs/GO_EXCHANGE.md#compatibility-cutover-and-rollback).
Stop old writers/workers, reconcile unfinished transfers, and verify retained
compatibility before changing implementations. Use `migrate-db` only for a
documented supported schema upgrade.

The following checks verify database revision, versioned storage, and retained
validation rules. Run them against the prepared new or retained database:

~~~sh
dcompose run --rm --no-deps exchange-api /usr/local/bin/hf2l-exchange check-db
dcompose run --rm --no-deps exchange-api /usr/local/bin/hf2l-exchange check-storage
dcompose run --rm --no-deps exchange-api /usr/local/bin/hf2l-exchange check-compatibility
dcompose up -d exchange-api exchange-worker
dcompose ps
dcompose logs --tail 100 exchange-api exchange-worker
~~~

`up -d` starts background services; `ps` shows their state. `logs --tail 100`
shows their latest 100 log lines. Exchange listens with its own certificate on
container port 8441. Keep the worker running independently: it verifies uploads
and completes storage cleanup.

## 5. Optionally start the Go dashboard

A **study creator** is a selected account that Org S, the service operator,
permits to create studies. After the trusted grant, Org P, the study lead, can
create studies from **Studies** using **Create study** and administer only those
studies. Existing project administration does not grant creation permission.
New studies have closed registration, required participant approval, zero
resource allowances, and 14-day job retention (how long finished jobs' stored output is kept). Org S still supplies training capacity. See the
[operator's creation and resource handoff](../../../docs/JOB_MANAGER.md#study-creation-and-ownership).


A Compose profile is a named optional service group. The `manager` profile
adds the dashboard/application server, without scheduling or execution.

First create the manager database and configure its browser login client using
the [operator guide](../../../docs/JOB_MANAGER.md). Create `jobs.env`,
`jobs.json`, and their referenced secret/certificate files. All file paths inside
the container must refer to the mounted `/run/hf2l/` directory.

`jobs.env` supplies the manager database, fixed login issuer/client/callback,
distinct session/cursor signing secret files, and other required identity
settings. Register the actual browser-visible callback address exactly.

In `jobs.json`, configure `service.host` as `0.0.0.0` and `service.port` as
8082 **inside the container**. Set `service.tls_certificate` and
`service.tls_key` to the mounted manager certificate/key. Listening only on
container loopback prevents Docker's published port from working. This service
section is only part of the complete manager configuration; the file is not
generated for you.

`--profile manager` includes the optional service. These commands initialize
only a new manager database and start the server. For retained data, follow the
[manager cutover procedure](../../../docs/GO_JOB_MANAGER.md#cutover-and-rollback)
and its supported migration instead of initialization.

~~~sh
dcompose --profile manager config --quiet
dcompose --profile manager build manager
dcompose --profile manager run --rm --no-deps manager \
  /usr/local/bin/hf2l-jobs init-db --config /run/hf2l/jobs.json
dcompose --profile manager up -d manager
dcompose --profile manager logs --tail 100 manager
~~~

The manager also serves `/signup` for trusted account connections and the
dashboard's **Studies** page for participant requests and Org P approval.
Configure optional signup choices in `jobs.env` using
`HF2L_JOBS_OIDC_SIGNUP_PROVIDERS_JSON`; its values identify operator-configured
brokers, not their private credentials. Follow the
[study enrollment guide](../../../docs/STUDY_ENROLLMENT.md) for GitHub/Hugging Face
setup, participant permissions, and approval. The manager database must be at
revision `0005_study_creators`; use the explicit migration procedure for
retained databases before starting the new executable.

Open `/dashboard/` on the configured manager HTTPS address. Org S creates
projects and grants explicit project membership through trusted administration.
Successful login alone grants no right to create jobs.

This minimal example does not mount execution storage or collect job outputs.
Serving retained artifacts also requires their approved persistent storage at
the configured locations. Do not enable admission or claim a working managed
federation from dashboard startup alone.

## 6. Verify access from the actual client machines

Org S coordinates these checks with Org P, Alice, and Bob, each using their
own account and machine:

1. Exchange `/health` responds over trusted HTTPS.
2. Exchange `/ready` confirms database revision and versioned storage access.
3. Login discovery returns the exact issuer and accounts obtain the intended
   credentials. If enabled, the manager completes browser login and returns to
   its registered callback.
4. Org S creates/delegates a test project; Org P enrolls its participants.
   Alice and Bob download the intended model and upload their own result.
   Verify permitted downloads and denied foreign-project operations.
5. The worker completes verification. Pending transfers or a failed worker are
   failures even if the readiness address responds.
6. Restart the Go services and confirm project/model persistence and permissions.

Configuration parsing, a successful image build, or another deployment's test
results do not qualify this deployment. This services-only example does not
establish managed isolation, concurrent training admission, or model quality.

## 7. Stop and restart

`stop` stops selected services while retaining their containers. Restart uses the
same external databases, object storage, and private files.

~~~sh
dcompose stop exchange-api exchange-worker
dcompose up -d exchange-api exchange-worker
~~~

If the manager was enabled, use its profile consistently:

~~~sh
dcompose --profile manager stop manager exchange-api exchange-worker
dcompose --profile manager up -d exchange-api exchange-worker manager
~~~

`down` removes this Compose project's service containers and network. It does
not delete external databases, model versions, or the private directory.

~~~sh
dcompose --profile manager down
~~~

These commands do not stop remote participant training, cancel managed jobs, or
prove remote execution termination. Drain/reconcile managed work before shutting
down a larger deployment. Back up databases, model versions, and configuration
through the relevant operator procedures; shutdown is not a backup.



## Public certificates and account setup

For public certificates obtained and renewed through port 443, see the
[Caddy certificate tutorial](CADDY.md). It keeps private keys on the server
and verifies the encrypted connection to Exchange. Public certificate setup
is separate from the login provider and from managed execution qualification.

An identity provider is the service that authenticates people and issues their
login credentials. Configure one stable trusted issuer, the provider address
that identifies those credentials, for this deployment. The manager's exact
public callback address is the page where that provider returns browser login;
register it with the provider and set the same address in manager configuration.
Its audience is the intended recipient of a credential; configure the manager's
human audience and Exchange's human audience according to their respective
guides. Do not substitute a workload audience for a human login audience.
Changing an issuer changes user identity even when the email address is the same.

GitHub and Hugging Face signup choices require operator-configured connections
at that trusted provider. The manager redirects through that provider; a signup
button does not configure the external account connection, accept arbitrary
external access credentials, or approve study participation. If online token
introspection, the provider's check of a credential's current validity, is
enabled, verify that endpoint and its client credentials for the token type
actually issued. Follow [study enrollment](../../../docs/STUDY_ENROLLMENT.md)
for the exact signup settings, provider setup, request lifecycle, and approval
requirements before offering a public signup link.

After starting these services, Org S must still configure approved study
creators and the resource policy, catalog and source approvals, qualified
execution hosts, controller, node agent, private Exchange backend, transfer
gateway, and per-execution proxies before advertising managed training. The
[managed deployment runbook](../../jobs/README.md) gives those boundaries and
operational steps. A working dashboard or successful signup proves neither
training admission nor available compute, storage, or transfer budget.


For Keycloak specifically, verify real access-token introspection using the
configured browser client. Its access-token audience list must include the
manager's configured human audience (normally `hf2l-jobs`) and that browser
client identifier (for example `hf2l-dashboard`), so the provider can report the
credential as active to that client. The identity token still targets the
browser client. Other providers can have different introspection rules; do not
add this second audience without checking their contract. Signup connections
for GitHub or Hugging Face belong in the trusted provider's operator settings,
with only approved client callbacks. Keep provider account credentials and
client secrets out of this repository.
