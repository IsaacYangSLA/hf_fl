# Trigger FedAvg from a Hugging Face webhook

This HF-specific integration remains supported by [architecture v3](ARCHITECTURE_V3.md).
The unified owner command and the existing `hf2l.owner_fedavg` entry point use the
same runner. `readiness.json` remains the workflow handoff contract; a design
revision does not rename it. For the independent Exchange service and fenced
coordination, see [its runbook](EXCHANGE_V3.md).

The [GitHub workflow](../.github/workflows/fed_avg.yml) starts its `fed_avg`
job when at least two open HF PRs from distinct approved participants declare
the latest HF `main` commit as their training base.

```text
HF PR opened, reopened, or updated
  -> HTTPS relay verifies the webhook secret and repository
  -> GitHub repository_dispatch (hf-pr-update)
  -> check_prs reads current HF main and submission metadata
  -> fed_avg runs only when at least two eligible PRs exist
  -> aggregate is published to HF main as the next round
```

HF sends its own JSON payload and `X-Webhook-Secret` header. GitHub's dispatch
API requires GitHub authentication and an `event_type`, so configure an HTTPS
relay between them. The included [WSGI relay](../examples/hf_webhook_relay.py)
performs that translation. See the [HF webhook protocol](https://huggingface.co/docs/hub/en/webhooks)
and [GitHub repository dispatch API](https://docs.github.com/en/rest/repos/repos#create-a-repository-dispatch-event).

## GitHub configuration

Put the workflow and supporting code on the GitHub repository's default branch.
[`repository_dispatch` runs workflows from that branch](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#repository_dispatch).
In **Settings -> Secrets and variables -> Actions**, configure:

| Kind | Name | Value |
| --- | --- | --- |
| Variable | `HF_REPO_ID` | HF model repository, such as `owner/my-fedavg-model` |
| Secret | `HF_TOKEN` | Owner HF token with read and write access to that model repository |
| Secret | `HF_PARTICIPANT_ALLOWLIST` | JSON mapping approved HF usernames to distinct participant IDs |

For example, the allowlist secret can contain:

```json
{"alice-hf": "alice", "bob-hf": "bob"}
```

The model repository must already be initialized with HF2L, and participants
must upload complete submissions using the client workflow in the README.
The workflow publishes automatically after checkpoint validation; it does not
run an evaluation plugin. Add trusted owner evaluation options to the final
owner command if required for your model.

## Run the HTTPS relay

On the relay host, install this checkout and a WSGI server in its project venv:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install gunicorn
```

Set these environment variables through your host's secret/configuration
manager:

| Name | Value |
| --- | --- |
| `HF_WEBHOOK_SECRET` | A random ASCII secret, also configured in HF webhook settings |
| `HF_REPO_ID` | The same HF model repository configured in GitHub |
| `GITHUB_REPOSITORY` | GitHub owner/repository containing the workflow |
| `GITHUB_DISPATCH_TOKEN` | GitHub token authorized to create repository dispatches |

A fine-grained GitHub PAT restricted to the target GitHub repository needs
**Contents: write** for this API. A GitHub App installation token also works;
the host must refresh it before expiry. The relay has no need for `HF_TOKEN`.

From the checkout root, start the relay behind an HTTPS reverse proxy:

```bash
.venv/bin/gunicorn \
  --bind 127.0.0.1:8000 \
  --workers 2 \
  --timeout 30 \
  examples.hf_webhook_relay:application
```

Route your public `https://YOUR_HOST/hf-webhook` URL to the local server.
Configure the proxy's request body limit to 1 MiB and a request timeout.
The relay checks the shared secret, only accepts the configured HF model repo,
and dispatches to a fixed GitHub repository. It never forwards incoming code,
URLs, branch selections, or PR titles to the workflow.

## Hugging Face configuration

In [HF webhook settings](https://huggingface.co/settings/webhooks):

1. Watch the exact model repository in `HF_REPO_ID`.
2. Set the target URL to `https://YOUR_HOST/hf-webhook`.
3. Set the secret to the relay's `HF_WEBHOOK_SECRET`.
4. Enable repository updates and discussions/PR events.

The relay handles open PR creation/status events (`discussion`) and commits
to `refs/pr/N` (`repo.content`). It ignores ordinary discussions, comments,
and updates to `main`, including the workflow's own aggregate publication.
Use the HF webhook activity page to inspect delivery status and replay failures.
A successful dispatch returns HTTP 202; ignored events return 200; a failed
GitHub request returns 502.

For PRs that already exist when you enable the integration, run **Actions ->
FedAvg on Hugging Face -> Run workflow** once. Manual runs use the same checks.

## Selection and concurrency

`check_prs` invokes `hf2l.owner_fedavg --check-only`. It downloads only the round
record and submission manifests, checks author/participant bindings, base SHA,
round, ancestry, and example counts, then writes `readiness.json`. Fewer than
two eligible submissions is a successful check with `ready=false`; the
`fed_avg` job is skipped. Duplicate eligible participant identities fail the
check so the owner can close superseded PRs.

`fed_avg` discovers and validates the current eligible PRs again, including
full checkpoint checksums and tensor compatibility. If more than two qualify,
all are included with example-count weighting. PRs changed or closed between
jobs can change eligibility; the owner command still requires at least two.
Malformed, deleted or incompatible automatically discovered candidates are
reported and skipped; publication requires at least two fully validated
participants after those checks. Transport outages fail the run.

The workflow serializes its runs without cancelling an active aggregation.
It passes the checked base SHA via `--expected-base-revision`, and publication
uses HF's `parent_commit` guard. A changed `main` fails the run instead of
publishing an aggregate against another base. Re-run the workflow to check
the new round. After successful publication, old PRs become stale and cannot
trigger the same round again. They remain open and unmerged.

The relay does not persist webhook delivery IDs. Duplicate/replayed events
can start extra checks, but serialized workflows and the updated base prevent
repeated publication of a completed round. API/network errors remain failures;
they are not treated as an insufficient-PR result.

The default CPU GitHub runner is suitable for small models. For large models,
change `fed_avg.runs-on` and its timeout to fit checkpoint memory, disk, and
runtime requirements.
