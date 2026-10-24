# Exporting job results

The `tools/export_jobs.py` utility downloads jobs visible to an authenticated Manager user through the existing HTTPS API. It follows pagination and verifies each artifact's advertised byte count and SHA-256 while streaming. Checkpoints are stored as opaque bytes under artifact IDs.

## Authentication and trust

Use a valid Manager browser session obtained through its configured login flow. The utility reads a private JSON session file containing the exact Manager origin and the value of its `__Host-hf2l_jobs` session cookie (omit the cookie name and equals sign):

```json
{
  "base_url": "https://manager.example.invalid",
  "session_cookie": "YOUR_AUTHENTICATED_SESSION_COOKIE"
}
```

Use a regular single-link file owned by the current user, with mode 0600 and no symbolic links in its path. The client refuses group/world permissions and files larger than 64 KiB, and validates the current session before exporting. Keep it outside the export directory. A trusted Python caller may create it using `tools.jobs_client.JobsClient.save_session()` after authenticating its session.

TLS certificate, hostname, and strict chain-purpose checks remain enabled. By default the client uses the system CA roots. Pass `--ca-file` to select the deployment's CA trust bundle. Requests stay on the configured HTTPS origin; redirects and environment proxy settings are disabled.

## Run an export

Install the manager's Python dependencies, including HTTPX, and run from the repository checkout:

```sh
python -m tools.export_jobs \
  --manager-url https://manager.example.invalid \
  --session-file /private/job-session.json \
  --output /private/job-exports \
  --ca-file /private/service-ca.pem
```

Replace the example paths and origin with the deployment's approved values. The output directory must be private and owned by the current user. Omit `--ca-file` for a service trusted by the system CA roots.

Without `--job-id`, the utility exports all terminal jobs accessible through the history view. Repeat `--job-id OPAQUE_JOB_ID` to select specific jobs. `--include-active` permits snapshots of unfinished jobs; these are explicitly incomplete.

Each job directory contains sanitized job metadata, attempts, events, logs, artifact descriptors, a manifest, and downloaded checkpoints/outputs/log artifacts. Source snapshot bytes and private input artifacts are excluded; sanitized job provenance and source artifact descriptors can remain in the metadata. Credential-named files and recognized credential byte patterns are omitted; private fields, recognizable token text, and recognized host-path prefixes are removed from exported metadata. These are bounded pattern filters, not a guarantee that arbitrary output contains no sensitive information. Review results before sharing them; checkpoint bytes remain opaque and are never deserialized.

Artifact downloads are published atomically after size and hash verification. The manifest is written last. After validating the job identity and opening its output directory, refresh removes that job's previous manifest before writing new metadata; a failure before that point can leave the previous snapshot intact. Artifacts already marked unavailable and expired log entries are recorded as incomplete. An HTTP failure, availability change during download, or size/hash mismatch aborts that job's refresh without a new manifest. Earlier jobs in the same invocation can already have completed manifests. Exit status is 0 for complete exports, 2 for incomplete snapshots, and 1 for errors. Inspect `excluded_artifact_ids` and `unavailable_artifact_ids` when reviewing results.

Use a new private output directory for each export snapshot. Refreshing an existing job directory replaces current metadata and verified downloads but does not remove older artifact files. Treat only files named by the current manifest as belonging to that snapshot; an excluded artifact does not make `complete` false. A manifest's `complete` flag means the selected result classes were available for a terminal job, not that source files or excluded content were exported.

Exports do not change job retention or purge jobs. Arrange prompt export and backup according to the deployment's storage and retention policy.
