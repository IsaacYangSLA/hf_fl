"""WSGI relay: authenticated Hugging Face events -> GitHub repository_dispatch.

Serve behind HTTPS using gunicorn; see docs/FEDAVG_WORKFLOW.md.
"""

from __future__ import annotations

import hmac
import json
import os
import re
from urllib.error import URLError
from urllib.request import Request, urlopen

MAX_BODY_BYTES = 1024 * 1024


def relevant_event(payload: dict, repo_id: str) -> bool:
    repo = payload.get("repo")
    event = payload.get("event")
    if not isinstance(repo, dict) or not isinstance(event, dict):
        return False
    if repo.get("type") != "model" or repo.get("name") != repo_id:
        return False
    if event.get("scope") == "discussion":
        discussion = payload.get("discussion")
        return (
            event.get("action") in ("create", "update")
            and isinstance(discussion, dict)
            and discussion.get("isPullRequest") is True
            and discussion.get("status") == "open"
        )
    if event.get("scope") == "repo.content" and event.get("action") == "update":
        refs = payload.get("updatedRefs", [])
        return isinstance(refs, list) and any(
            isinstance(ref, dict)
            and isinstance(ref.get("ref"), str)
            and re.fullmatch(r"refs/pr/[0-9]+", ref["ref"])
            and ref.get("newSha")
            for ref in refs
        )
    return False


def dispatch(repository: str, token: str) -> None:
    # Use configured destinations only. No incoming URL, code, or ref is forwarded.
    request = Request(
        f"https://api.github.com/repos/{repository}/dispatches",
        data=json.dumps({"event_type": "hf-pr-update"}).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "hf2l-webhook-relay",
            "X-GitHub-Api-Version": "2026-03-10",
        },
        method="POST",
    )
    with urlopen(request, timeout=15) as response:
        if response.status != 204:
            raise RuntimeError("GitHub did not accept the dispatch")


def application(environ, start_response):
    def respond(status, message):
        body = (message + "\n").encode("utf-8")
        start_response(status, [
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Content-Length", str(len(body))),
        ])
        return [body]

    if environ.get("PATH_INFO") != "/hf-webhook":
        return respond("404 Not Found", "Not found")
    if environ.get("REQUEST_METHOD") != "POST":
        return respond("405 Method Not Allowed", "Use POST")

    secret = os.environ.get("HF_WEBHOOK_SECRET", "")
    token = os.environ.get("GITHUB_DISPATCH_TOKEN", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    repo_id = os.environ.get("HF_REPO_ID", "")
    if not secret or not token or not repo_id or not re.fullmatch(r"[\w.-]+/[\w.-]+", repository):
        return respond("503 Service Unavailable", "Relay configuration is incomplete")
    supplied = environ.get("HTTP_X_WEBHOOK_SECRET", "")
    if not hmac.compare_digest(supplied.encode("utf-8"), secret.encode("utf-8")):
        return respond("403 Forbidden", "Invalid webhook secret")
    try:
        size = int(environ.get("CONTENT_LENGTH", ""))
    except ValueError:
        return respond("400 Bad Request", "Content-Length is required")
    if not 0 < size <= MAX_BODY_BYTES:
        return respond("413 Content Too Large", "Invalid payload size")
    try:
        payload = json.loads(environ["wsgi.input"].read(size))
    except (ValueError, UnicodeError):
        return respond("400 Bad Request", "Invalid JSON")
    if not isinstance(payload, dict):
        return respond("400 Bad Request", "Expected a JSON object")
    if not relevant_event(payload, repo_id):
        return respond("200 OK", "Ignored")
    try:
        dispatch(repository, token)
    except (URLError, OSError, RuntimeError):
        # Do not echo upstream errors, tokens, or incoming payloads into logs/responses.
        return respond("502 Bad Gateway", "GitHub dispatch failed; retry delivery")
    return respond("202 Accepted", "Workflow dispatched")
