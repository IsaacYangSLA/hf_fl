#!/usr/bin/env python3
"""Export authorized job results through authenticated Manager APIs.

Provide a private session file created by JobsClient.save_session(). Downloads
use opaque artifact IDs as filenames; checkpoints are never deserialized.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import httpx
from urllib.parse import quote
try:
    from .jobs_client import API, JobsClient, JobsClientError, atomic_json, private_directory
except ImportError:
    from jobs_client import API, JobsClient, JobsClientError, atomic_json, private_directory

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SECRET = re.compile(r"(?:password|passwd|secret|token|credential|private.?key|access.?key|api.?key|authorization|cookie|auth.?state|client.?state)", re.I)
_PEM = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.S)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_ASSIGNMENT = re.compile(r"(?i)\b(password|passwd|secret|token|credential|api_key|access_key|authorization|cookie)\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)")
_HOST_PATH = re.compile(r"(?<![A-Za-z0-9])/(?:srv|etc|localhome|home|root|run|var|tmp|Users|private)(?:/[^\s\"'<>]+)*")
_TERMINAL = {"SUCCEEDED", "FAILED", "CANCELLED"}


class SensitiveArtifact(JobsClientError):
    """Recognized credential bytes were refused before atomic publication."""


class CredentialGuard:
    """Scan opaque chunks for credential formats without parsing models."""
    patterns = (
        re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
        re.compile(rb"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"),
        re.compile(rb"__Host-hf2l_jobs="),
        re.compile(rb"(?i)[\"'](?:password|passwd|client_secret|access_token|refresh_token|session_cookie|csrf_token|private_key|credentials|cookies|storageState)[\"']\s*:"),
        re.compile(rb"(?i)\b(?:password|passwd|client_secret|access_token|refresh_token|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID)\s*="),
    )

    def __init__(self):
        self.tail = b""

    def feed(self, chunk):
        value = self.tail + chunk
        if any(pattern.search(value) for pattern in self.patterns):
            raise SensitiveArtifact("Credential content cannot be exported")
        # Bounded overlap catches markers split between stream chunks.
        self.tail = value[-65536:]

    def finish(self):
        pass


def credential_filename(name):
    value = str(name).lower()
    return bool(_SECRET.search(value) or value.endswith((".pem", ".key", ".p12", ".pfx"))
                or Path(value).name in {".env", ".netrc", ".npmrc", "id_rsa", "id_ed25519"}
                or Path(value).name.startswith(".env."))


def opaque_id(value):
    if not isinstance(value, str) or not _ID.fullmatch(value) or value in {".", ".."}:
        raise JobsClientError("Invalid opaque job or artifact ID")
    return value


def sanitize(value):
    """Remove private fields and redact credential patterns and host paths."""
    if isinstance(value, dict):
        return {str(key): sanitize(item) for key, item in value.items()
                if not _SECRET.search(str(key)) and str(key) not in {
                    "locator", "locator_json", "host_path", "private_path", "origin_url",
                    "download_url", "issuer_configuration", "node_configuration"}}
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        try:
            CredentialGuard().feed(value.encode("utf-8"))
        except SensitiveArtifact:
            return "[credential-containing text omitted]"
        value = _PEM.sub("[private key omitted]", value)
        value = _JWT.sub("[token omitted]", value)
        value = _ASSIGNMENT.sub("[credential omitted]", value)
        return _HOST_PATH.sub("[host path omitted]", value)
    return value


def export_job(client, job_id, output_root):
    """Publish a completed export manifest last; failures retain no success marker."""
    job_id = opaque_id(job_id)
    path = API + "/jobs/" + quote(job_id, safe="")
    job = client.get_json(path)
    if job.get("id") != job_id:
        raise JobsClientError("Manager returned another job identity")
    root = private_directory(Path(output_root) / job_id)
    # A stale manifest must never make an interrupted refresh appear successful.
    (root / "manifest.json").unlink(missing_ok=True)
    atomic_json(root / "job.json", sanitize(job))
    attempts = client.get_json(path + "/attempts")
    if not isinstance(attempts, dict) or not isinstance(attempts.get("items"), list):
        raise JobsClientError("Invalid attempts collection")
    atomic_json(root / "attempts.json", sanitize(attempts["items"]))
    unavailable_logs = []
    for resource in ("events", "logs"):
        items = list(client.iter_pages(path + "/" + resource))
        if resource == "logs":
            unavailable_logs = [item.get("id") for item in items if item.get("expired")]
        atomic_json(root / (resource + ".json"), sanitize(items))
    artifacts = list(client.iter_pages(path + "/artifacts"))
    atomic_json(root / "artifacts.json", sanitize(artifacts))
    files = []
    unavailable = []
    excluded = []
    for item in artifacts:
        artifact_id = opaque_id(item.get("id"))
        # Only result classes enter exports. Source snapshots and private inputs
        # are not results; credential-named output files are also excluded.
        if item.get("kind") not in {"checkpoint", "output", "log"} or credential_filename(item.get("name", "")):
            excluded.append(artifact_id)
            continue
        if not item.get("download_available"):
            unavailable.append(artifact_id)
            continue
        detail = client.get_json(path + "/artifacts/" + quote(artifact_id, safe=""))
        if detail.get("id") != artifact_id or not detail.get("download_available"):
            raise JobsClientError("Artifact availability changed during export")
        try:
            verified = client.stream_download(
                path + "/artifacts/" + quote(artifact_id, safe="") + "/download",
                root / "artifacts" / artifact_id,
                expected_size=detail.get("size_bytes"), expected_sha256=detail.get("sha256"),
                content_guard=CredentialGuard())
        except SensitiveArtifact:
            excluded.append(artifact_id)
            continue
        files.append({"id": artifact_id, "kind": detail.get("kind"), **verified})
    manifest = {"format": "hf2l-job-export-v1", "job_id": job_id,
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "job_state": job.get("state"), "files": files,
                "unavailable_artifact_ids": unavailable,
                "unavailable_log_ids": unavailable_logs,
                "excluded_artifact_ids": excluded,
                "complete": not unavailable and not unavailable_logs and job.get("state") in _TERMINAL,
                "provenance": sanitize({"spec_hash": job.get("spec_hash"),
                    "source_id": job.get("spec", {}).get("source_id"),
                    "source_commit": job.get("spec", {}).get("source_commit"),
                    "runtime_image": job.get("spec", {}).get("runtime_image")})}
    atomic_json(root / "manifest.json", manifest)
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path, help="CA trust bundle; defaults to system CA roots")
    parser.add_argument("--manager-url", required=True, help="Manager HTTPS origin")
    parser.add_argument("--output", type=Path, required=True, help="Private result export directory")
    parser.add_argument("--job-id", action="append", default=[])
    parser.add_argument("--include-active", action="store_true",
                        help="Export an explicitly incomplete snapshot of active jobs")
    args = parser.parse_args(argv)
    try:
        with JobsClient(args.manager_url, ca_file=args.ca_file, session_file=args.session_file) as client:
            identities = args.job_id or [
                item["id"] for item in client.iter_pages(API + "/jobs", params={"view": "all" if args.include_active else "history"})]
            summaries = []
            for identity in identities:
                job = client.get_json(API + "/jobs/" + quote(opaque_id(identity), safe=""))
                if job.get("state") not in _TERMINAL and not args.include_active:
                    raise JobsClientError("Only terminal jobs can be exported without --include-active")
                summaries.append(export_job(client, identity, args.output))
        print(json.dumps({"exported_jobs": len(summaries),
                          "complete": all(item["complete"] for item in summaries)}))
        return 0 if all(item["complete"] for item in summaries) else 2
    except (JobsClientError, OSError, ValueError, httpx.HTTPError) as error:
        # Avoid remote response bodies or exception messages containing inputs.
        print("Export failed (" + type(error).__name__ + "); no successful manifest for incomplete downloads.",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
