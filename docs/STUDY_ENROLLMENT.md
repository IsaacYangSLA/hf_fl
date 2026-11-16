# Sign up and request study participation

A **study** is a collaboration stored as a manager project. **Org P** owns the
study; **Org S** operates the service. Participants can request to join after
Org P enables signup and opens registration.
An **identity provider** verifies a person's account. Signing in establishes who
the person is; a separate study application asks Org P to allow that person to
participate. **Approval is required for every participant in an enabled study.**

The manager, its signup pages, and study enrollment are Go services. Python
remains in participant clients, training, aggregation, and execution adapters.
This guide requires the [Go manager](GO_JOB_MANAGER.md) and its dashboard; the
Exchange-only beginner stack does not provide these manager pages.

## Who does what

| Role | Work and machine |
| --- | --- |
| Org S — service operator | On the service machine, configure trusted login, optional external-account connections, the manager database, and the dashboard. Grant selected Org P accounts study-creation permission; separately provision study quotas and execution resources. Trusted project creation and membership delegation remain available. |
| Org P — project owner/aggregator | With study-creation permission, create a named study in its own browser. As that study’s administrator, enable signup, describe the study, review each actual applicant, and approve or reject requests. Separately agree on training code and arrange approved datasets/execution. |
| Alice in Org A and Bob in Org B | Each uses their own account and browser to sign in, request participation, and follow the decision. Each organization installs and runs its own agreed training code. |

Org S and Org P need no login or filesystem access to Alice's or Bob's machine.
A signup request contains a participant name and optional message, not training
data, repository credentials, or executable training code.

## 1. Org S prepares the manager

Deploy and configure the manager following the [operator guide](JOB_MANAGER.md)
or [services-only Compose guide](../deploy/compose/go/README.md). Docker Compose
starts a group of packaged services from one configuration file; that example
adds the dashboard but not a complete training execution system.

The current manager database revision is `0005_study_creators`. A revision
identifies the database layout required by the executable. For retained data,
back up the database, stop writers, and use the explicit migration procedure.
`hf2l-jobs` is the installed Go command; `migrate-db` upgrades a supported existing
database, and `--config` selects the operator-owned settings file:

```sh
hf2l-jobs migrate-db --config /etc/hf2l/jobs.json
```

Initialize only a new database with `init-db`. Migration preserves existing
projects and memberships and does not automatically enable their study policy or grant study-creation permission to existing project administrators.
The Exchange database has its own independent revision and is not migrated by
this manager command.

Keep the manager's existing trusted login issuer, browser client, exact callback,
credential verification, and session protections. An **issuer** is the trusted
login service address; a **subject** is the account identifier that service
assigns. The manager derives the stable **principal**, its internal identity
identifier, from that exact issuer and subject. A display name or email address
cannot substitute for that identity.

### Allow Org P to create a study

A **study creator** is a selected account that can create studies across the
service. It has more permission than an ordinary signed-in account and less
than Org S, which controls the service. The grant permits creation, not access
to another study or its private jobs. Existing project administrators do not
receive this grant automatically.

First, Org P signs in and obtains its stable principal from the manager session;
see [human login and authorization](JOB_MANAGER.md#2-human-login-and-authorization).
Org S then runs trusted administration on the service machine. In the following
commands, `admin` selects trusted local administration, `study-creator-set`
changes study-creation permission, `--principal` selects the exact account,
`STABLE_ID` is its principal, and `--enabled=true` grants permission while
`--enabled=false` revokes it. `--config` selects Org S’s settings file.

```sh
hf2l-jobs admin --config /etc/hf2l/jobs.json study-creator-set --principal STABLE_ID --enabled=true
hf2l-jobs admin --config /etc/hf2l/jobs.json study-creator-set --principal STABLE_ID --enabled=false
```

Run the first command to grant access; the second illustrates later revocation.
Org P opens **Studies**, selects **Create study**, and supplies only a study
name. The new study initially has registration closed, participant approval
required, all six resource allowances set to zero (processor capacity, memory, working disk, graphics processors, simultaneous jobs, and retained storage), and finished-job retention
of 14 days. Only its creator receives administrator membership. Org S must
separately assign usable quotas and execution resources before jobs can run.

Revocation prevents new study creation immediately, including through existing
signed-in sessions. It preserves administrator membership already recorded in
studies that the account created. Study creators cannot grant this permission,
change service settings, allocate resource pools, or set their own quotas.
A resource pool is shared execution capacity assigned by Org S.

A manager study and an Exchange-only project are separate records. Creating
one does not create the other; Exchange-only commands do not grant access to
the manager’s study pages. See [trusted bootstrap](JOB_MANAGER.md#3-trusted-bootstrap)
for operator-created projects and resource setup.

### Public hosting, including Azure

**HTTPS** is encrypted web access that verifies the server's identity using a
certificate trusted by the browser. **DNS** maps a hostname to its network
address. Azure can assign a public DNS name through a public address resource's
name-label setting; use the exact hostname Azure assigns. See the
[Azure public-address documentation](https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/virtual-network-public-ip-address).
A browser-trusted HTTPS address using that hostname can be registered as the
login callback; a purchased domain name is not inherently required.

A certificate purchase is also unnecessary when using a free issuer such as
[Let's Encrypt](https://letsencrypt.org/). Caddy, the request-routing server used
by the beginner stack, can obtain and renew public certificates automatically.
Follow its [HTTPS quick-start](https://caddyserver.com/docs/quick-starts/https)
and [automatic HTTPS requirements](https://caddyserver.com/docs/automatic-https):

- Configure the exact public name to reach the intended server and permit the
  certificate issuer to verify control of that name.
- For the documented public setup, allow incoming ports 80 and 443 through both
  cloud network rules and the machine's firewall, with those ports reaching Caddy.
- Preserve Caddy's writable certificate data across restarts so renewal retains
  its account and certificates. Keep the connection from Caddy to native Go
  services encrypted and certificate-verified too.

One Azure-provided name does not give control of arbitrary names beneath it.
The beginner stack requires three distinct configured names for Exchange, login,
and object storage. Do not invent an authentication or storage subdomain under
an Azure-owned name; provide names you can actually configure or arrange an
independently designed routing setup. The manager's callback and the identity
broker's callback are separate addresses; register each exact address with the
appropriate application.

These are hosting prerequisites, not an Azure deployment template or a record
that public certificates or external-provider login have passed on Azure.

### Optional GitHub and Hugging Face account connections

An **identity broker** accepts login through another account service and returns
a verified identity under the manager's existing trusted issuer. Configure these
connections in Keycloak; the manager continues to trust its one configured
Keycloak issuer. It does not accept a GitHub or Hugging Face access token directly.

Org S needs an application registration and its private credentials at each
chosen account service. A **callback** is the address to which that service
returns the browser after login. Use the exact broker callback shown by Keycloak,
not the manager's separate `/auth/callback` address.

| Account service | Org S setup |
| --- | --- |
| GitHub | Add Keycloak's built-in GitHub identity provider. Register the displayed broker callback in the GitHub application, and put that application's identifier and secret in Keycloak. See the [official Keycloak GitHub procedure](https://www.keycloak.org/docs/latest/server_admin/#_github). |
| Hugging Face | Add Keycloak's generic OpenID Connect provider. OpenID Connect, or OIDC, is the login protocol that conveys verified account identity. Configure it using Hugging Face's [published discovery document](https://huggingface.co/.well-known/openid-configuration), register the displayed broker callback in the Hugging Face application, and supply its identifier/secret to Keycloak. See [Sign in with Hugging Face](https://huggingface.co/docs/hub/oauth). |

For Hugging Face, `openid` requests the account identity and `profile` requests
basic profile information; use those login permissions rather than private
repository or training-job permissions. Keep signature and issuer verification
enabled. Require proof before linking an external account to an existing account;
do not grant project roles or study approval from an email, username, or upstream
organization claim. External application secrets belong in Keycloak's private
configuration, never participant invitations or the public provider list.

Creating a broker connection does not change the manager's required token
recipient and permissions. Configure its existing browser client to issue the
manager's `hf2l-jobs` recipient and `jobs` permission as described in the
[login guide](JOB_MANAGER.md#2-human-login-and-authorization).

### Select signup buttons

The optional `HF2L_JOBS_OIDC_SIGNUP_PROVIDERS_JSON` environment setting selects
which configured login choices the manager displays. JSON is a text format for
named values: braces contain an entry, brackets contain a list, quotes enclose
text, a colon joins a field to its value, and commas separate entries.

Each entry has an `id`, the fixed choice used by the manager; a `label`, the
button's visible name; and an optional `broker_alias`, the exact provider name
configured in Keycloak. In this example, `github` and `huggingface` select the
operator-configured brokers with those aliases. `organization` has no broker
alias and uses the normal trusted login page. The single quotes below preserve
the JSON as one environment-file value:

```dotenv
HF2L_JOBS_OIDC_SIGNUP_PROVIDERS_JSON='[{"id":"github","label":"GitHub","broker_alias":"github"},{"id":"huggingface","label":"Hugging Face","broker_alias":"huggingface"},{"id":"organization","label":"Organization account"}]'
```

Put that setting in the manager's private environment, such as the services-only
Compose deployment's `jobs.env`, and restart the manager. It contains choices,
not external application secrets. Omitting the setting, or supplying an empty
list, shows only **Organization account**. This uses the existing login provider;
it does not create an HF²L password database or enable that provider's own
account-registration policy.

The manager accepts at most 16 choices. IDs start with a lowercase letter and
contain only lowercase letters, digits, underscores, or hyphens, up to 64
characters. Labels contain 1–100 characters without control characters. Broker
aliases contain up to 128 letters/digits/dots/underscores/hyphens and start with
a letter or digit. Unknown fields, duplicate IDs, and malformed configuration
are rejected. The operator selects aliases; a caller cannot supply an arbitrary
login-service address.

## 2. Org P enables signup for its study

**Who:** the study administrator: its creator or an account delegated by Org S. **Machine:** Org P's browser.
Open the manager dashboard, select **Studies**, and choose **View study** for the
owned project. Under **Org P: signup settings**, enter **Study description**,
select **Accept new participant requests**, and choose **Enable study signup**.

Before the first enablement, finish or cancel every nonterminal project job,
including queued jobs. The manager refuses enablement while such jobs exist;
it does not silently change the participation rules of work already in progress.
Do not treat a cancellation request as proof that execution has terminated;
follow the manager's job cleanup and reconciliation procedures.

Enabling signup permanently enables that project's approval requirement. It
cannot later be disabled to bypass approval. **Save signup settings** can close
or reopen requests. Closing requests leaves pending applications and existing
approvals intact; it does not cancel jobs or revoke an approval.

Only signed-in users can browse open studies. A closed study remains visible to
its own applicants and project administrators. Descriptions are therefore shared
with prospective applicants when registration is open; include no private job
or dataset information.

## 3. Alice and Bob each request participation

Each participant independently:

1. Opens `/signup` on the manager's advertised address and chooses a configured
   account option. The provider verifies the account; HF²L does not collect that
   provider's password.
2. Completes login and reaches `/dashboard/`, then selects **Studies** and
   **View study** for the intended project.
3. Under **Your participation**, enters the agreed **Participant name**, such
   as `alice` or `bob`, and optionally a **Message to Org P**. Chooses
   **Request to join**.
4. Checks the resulting **Pending** status and waits for Org P's decision.
   A pending request can be cancelled with **Withdraw request**.

The request is bound to the signed-in principal. It cannot select another
person's identity or approve itself. Two pending requests may propose the same
participant name; submitting first does not reserve that name. Org P can approve
only one identity for a given participant name in a study.

## 4. Org P reviews every participant

In the study's **Org P: participant requests** section, review the actual
principal and the agreed participant name through the organizations' trusted
communication channel. The applicant's message is a claim to assess, not identity
proof. Optionally enter **Response to participant**, then choose **Approve** or
**Reject**. Only a project administrator can perform these reviews.

| State | Meaning and next action |
| --- | --- |
| Pending | Awaiting review; the applicant can withdraw. |
| Approved | Eligible under that study's participation policy; the approved principal/name binding is fixed. |
| Rejected | Not eligible; the applicant may send a new request while registration is open. |
| Withdrawn | The applicant cancelled the pending request; they may apply again while registration is open. |

A reapplication keeps the same application identifier and increments its saved
version. Rejection/withdrawal history is recorded in the administrative audit.
**Approved applications cannot be withdrawn, rejected, renamed, or revoked
through this initial interface.** Review carefully before approving. Closing
registration is not revocation. Use existing job cancellation, execution fencing,
and account/membership controls for the separate actions they authorize; those
operations do not erase this study approval.

Applicants see only their own application. Project administrators can review all
applications for their own study. Application messages and review reasons are
visible to those parties; keep secrets and private training data out of them.

## 5. What approval permits

Approval grants **participant eligibility only**. It grants no project-admin role,
job-creation role, access to existing private jobs, direct Exchange membership,
node registration, dataset access, or permission to run arbitrary code.

Preparing a job's source, storage, and execution resources is called
**provisioning**. For an enabled study, job creation, job retry, and provisioning
each check approval for every participant name, including locally managed
participants. The server resolves each approved name to its trusted applicant
identity. Thus a historical job cannot bypass the newly enabled policy merely
by being retried, and a retained queued job is checked again before execution
preparation. External participant enrollment and execution access also repeat
the current eligibility check. Org P must still configure approved nodes,
datasets, model/trainer agreement, resource capacity, and job-specific permissions
through the existing managed-job workflow.

A project without enabled study signup retains its existing administrative
membership/enrollment behavior. The optional source-code approval process is a
separate policy; making that optional does not waive the study's mandatory
participant approval.

## Interface and retry details

The browser supplies the required request protections. For other clients, an
**API** is the set of request addresses and rules below. All study addresses
start with `/api/jobs/v1` and require a verified human identity. A slash separates
path parts; `{study}` and `{application}` mean the returned study/application
identifiers, not literal braces to send. `GET` reads, `PUT` saves settings, and
`POST` submits an application or action.

| Method and path after the common prefix | Allowed caller and request |
| --- | --- |
| `GET /studies` | Signed-in caller; list visible studies. |
| `GET /studies/{study}` | Caller permitted to see that study. |
| `PUT /studies/{study}/settings` | Project administrator; `description` text up to 2,000 characters and `registration_open` true/false. First save enables the policy. |
| `GET /studies/{study}/application` | Read the caller's own application; returns `application` as an entry or null. |
| `POST /studies/{study}/applications` | Signed-in applicant; agreed `participant_id` and optional `message` up to 2,000 characters. Identity comes from login. |
| `GET /studies/{study}/applications` | Project administrator; list that study's applications. |
| `POST /studies/{study}/applications/{application}/approve` | Project administrator; optional `reason` up to 1,000 characters. |
| `POST /studies/{study}/applications/{application}/reject` | Project administrator; optional `reason` up to 1,000 characters. |
| `POST /studies/{study}/applications/{application}/withdraw` | The applicant, for their own pending request; empty object. |

Every mutation requires `Idempotency-Key`, a unique operation identifier that
lets a repeated identical request return safely. Each study/application entry
includes `version`, its current positive whole-number version marker.
Settings/review/withdrawal also require `If-Match` with that version written as
decimal text enclosed in double quotes. Single-object responses also expose this
quoted version in `ETag`, the corresponding response-header marker; application
lists and the own-application wrapper supply the entry's `version` field instead.
On a version conflict, reload before making a new decision. Reuse the same
operation identifier only to retry the same operation with the same contents;
use a new identifier for a changed choice.

Cross-site request forgery, or CSRF, means another website submitting an action
through an existing browser login. To prevent this, browser-session mutations
additionally require `X-CSRF-Token` from `/auth/session` and the matching `Origin`,
the browser's service address.
Do not place login credentials in browser storage or disable these checks.

Both list routes return `items` and `next_cursor`. A cursor is an opaque next-page
marker; send the returned marker unchanged for the next page. `limit` selects
1–100 entries, default 50. Study cursors are bound to the caller; application
cursors are bound to caller and study. Do not reuse another caller's marker.
The dashboard provides **More** and **Previous** controls rather than exposing
these markers for editing.

The public `/auth/providers` address returns configured signup-button choices;
`/auth/signup?provider=...` accepts only one configured `id`. In that address,
`?` begins the query and `=` joins `provider` to its selected value. Unknown or
repeated choices fail instead of changing the trusted issuer. Callback processing
uses the same verified login flow and `/auth/callback` as normal login.

## Verification and limits

Before opening real registration, Org S and Org P verify:

- Each configured account option returns through the exact trusted issuer and
  callback. A missing upstream application registration is a deployment blocker
  for that option; publishing a button does not configure it.
- A new signed-in applicant has no job-creation or private-job access, can apply
  only as themselves, and cannot review another applicant.
- Org P approval is required, participant names remain uniquely approved, and
  rejected/withdrawn requests can be retried with the correct saved version.
- Closing registration prevents new requests without rewriting pending or
  approved state. First enablement fails while nonterminal jobs exist.
- Repeated requests do not duplicate decisions; stale versions, missing browser
  protections, and cross-study application/cursor use are rejected.
- State survives manager restart and the explicit database migration preserves
  existing memberships without opting old projects in.

Local tests using a controlled login service do not qualify real GitHub or
Hugging Face application credentials, external connectivity, or provider policy.
Those require Org S's actual broker configuration and account checks. This
feature does not deploy training services or establish model quality.
