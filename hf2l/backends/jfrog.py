"""JFrog Artifactory HuggingFaceML implementation of the HF²L contract."""

from __future__ import annotations

import json
import re
import shutil
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import contextmanager
from pathlib import Path
from threading import RLock
from typing import Any, Iterator

from huggingface_hub import HfApi
from huggingface_hub import hf_api as huggingface_hf_api

from hf2l.backends.base import ModelStore, PublishResult, SubmissionCandidate


_ENDPOINT_MARKER = "/api/huggingfaceml/"
_PLACEHOLDER_COMMIT_URLS = {"commitUrl", "hf://commitUrl"}
_COMMIT_INFO_LOCK = RLock()


def _safe_revision_component(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9.-]+", "-", value.strip()).strip("-.")
    return value[:48] or "participant"


def _validate_revision(value: str) -> str:
    value = value.strip()
    if not value or re.fullmatch(r"[A-Za-z0-9.-]+", value) is None:
        raise ValueError(
            "JFrog revision identifiers may contain only letters, numbers, "
            "hyphens, and periods"
        )
    return value


@contextmanager
def _jfrog_commit_info_compat(endpoint: str, repo_id: str) -> Iterator[None]:
    """Repair the placeholder commit URL returned by some JFrog versions."""

    with _COMMIT_INFO_LOCK:
        original_commit_info = huggingface_hf_api.CommitInfo

        def compatible_commit_info(*args: Any, **kwargs: Any) -> Any:
            if kwargs.get("commit_url") in _PLACEHOLDER_COMMIT_URLS:
                oid = str(kwargs.get("oid", "")).strip()
                if not oid:
                    raise ValueError("JFrog commit response did not include a commit OID")
                kwargs["commit_url"] = f"{endpoint}/{repo_id}/commit/{oid}"
            return original_commit_info(*args, **kwargs)

        huggingface_hf_api.CommitInfo = compatible_commit_info  # type: ignore[misc]
        try:
            yield
        finally:
            huggingface_hf_api.CommitInfo = original_commit_info


@contextmanager
def _selected_folder(folder: Path, paths: list[str]) -> Iterator[Path]:
    """Stage exactly the validated files accepted by the protocol."""

    with tempfile.TemporaryDirectory(prefix="hf2l-jfrog-upload-") as temporary:
        staging = Path(temporary)
        for relative in paths:
            source = folder / relative
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        yield staging


class JFrogStore(ModelStore):
    name = "jfrog"

    def __init__(self, token: str | None, endpoint: str):
        endpoint = endpoint.rstrip("/")
        if _ENDPOINT_MARKER not in endpoint:
            raise ValueError(
                "JFrog --endpoint must end with /artifactory/api/huggingfaceml/REPO_KEY"
            )
        artifactory_url, repo_key = endpoint.rsplit(_ENDPOINT_MARKER, 1)
        if not repo_key or "/" in repo_key:
            raise ValueError("JFrog endpoint must contain exactly one repository key")
        self.endpoint = endpoint
        self.artifactory_url = artifactory_url.rstrip("/")
        self.repo_key = repo_key
        self.token = token
        self.api = HfApi(endpoint=endpoint, token=token)

    def _upload_folder(self, repo_id: str, folder: Path, revision: str) -> None:
        """Upload despite Artifactory's placeholder commit-response URL.

        Some Artifactory HuggingFaceML versions return the literal
        ``hf://commitUrl`` after successfully creating a commit. Recent
        ``huggingface_hub`` clients reject that placeholder while building the
        return value. Repair it only while this synchronous upload is active so
        Xet's resumable multi-commit pipeline can finish all batches.
        """

        with _jfrog_commit_info_compat(self.endpoint, repo_id):
            self.api.upload_folder(
                repo_id=repo_id,
                repo_type="model",
                folder_path=folder,
                revision=revision,
            )

    def _request(
        self, url: str, *, data: bytes | None = None, content_type: str | None = None
    ) -> bytes:
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(url, data=data, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"JFrog request failed with HTTP {exc.code}: {detail}") from exc

    def resolve_revision(self, repo_id: str, revision: str) -> str:
        revision = _validate_revision(revision)
        resolved = self.api.model_info(repo_id, revision=revision).sha
        if not resolved:
            raise RuntimeError(f"JFrog did not resolve revision {revision!r}")
        return resolved

    def download_snapshot(
        self,
        repo_id: str,
        revision: str,
        local_dir: Path,
        *,
        allow_patterns: str | list[str] | None = None,
    ) -> None:
        self.api.snapshot_download(
            repo_id=repo_id,
            repo_type="model",
            revision=revision,
            local_dir=local_dir,
            allow_patterns=allow_patterns,
            etag_timeout=86400,
        )

    def initialize_repository(
        self, repo_id: str, folder: Path, *, private: bool
    ) -> PublishResult:
        if private:
            raise ValueError(
                "--private is a Hugging Face Hub option; configure JFrog "
                "repository permissions instead"
            )
        self._upload_folder(repo_id, folder, "main")
        resolved = self.resolve_revision(repo_id, "main")
        return PublishResult(resolved, self.endpoint, resolved)

    def new_submission_revision(self, participant: str, source_round: int) -> str:
        participant_component = _safe_revision_component(participant)
        return f"r{source_round:04d}-{participant_component}-{uuid.uuid4().hex[:12]}"

    def publish_submission(
        self,
        repo_id: str,
        folder: Path,
        paths: list[str],
        *,
        participant: str,
        source_round: int,
        base_revision: str,
        submission_revision: str | None,
    ) -> PublishResult:
        del participant, source_round, base_revision
        if not submission_revision:
            raise ValueError("JFrog submissions require a unique named revision")
        submission_revision = _validate_revision(submission_revision)
        with _selected_folder(folder, paths) as staging:
            self._upload_folder(repo_id, staging, submission_revision)
        resolved = self.resolve_revision(repo_id, submission_revision)
        return PublishResult(submission_revision, resolved_revision=resolved)

    def _manifest_items(self, repo_id: str) -> tuple[list[dict[str, Any]], list[str]]:
        query = (
            "items.find("
            + json.dumps(
                {
                    "repo": {"$eq": self.repo_key},
                    "name": {"$eq": "fedavg_submission.json"},
                },
                separators=(",", ":"),
            )
            + ').include("repo","path","name","created_by","sha256","modified")'
        )
        payload = self._request(
            f"{self.artifactory_url}/api/search/aql",
            data=query.encode("utf-8"),
            content_type="text/plain",
        )
        response = json.loads(payload)
        results = response.get("results", [])
        if not isinstance(results, list):
            raise RuntimeError("JFrog AQL returned an invalid results object")
        manifests: list[dict[str, Any]] = []
        skipped: list[str] = []
        for item in results:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path", "")).strip("/")
            name = str(item.get("name", ""))
            quoted_path = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
            artifact_url = (
                f"{self.artifactory_url}/{urllib.parse.quote(self.repo_key, safe='')}/"
                f"{quoted_path}/{urllib.parse.quote(name, safe='')}"
            )
            try:
                manifest = json.loads(self._request(artifact_url))
            except (RuntimeError, json.JSONDecodeError) as exc:
                skipped.append(f"{path}/{name}: unreadable manifest ({exc})")
                continue
            if not isinstance(manifest, dict) or manifest.get("repo_id") != repo_id:
                continue
            manifests.append({"item": item, "manifest": manifest})
        return manifests, skipped

    def discover_submissions(
        self, repo_id: str
    ) -> tuple[list[SubmissionCandidate], list[str]]:
        records, skipped = self._manifest_items(repo_id)
        candidates: list[SubmissionCandidate] = []
        seen: set[str] = set()
        for record in records:
            item = record["item"]
            manifest = record["manifest"]
            revision = str(manifest.get("submission_revision", "")).strip()
            author = str(item.get("created_by", "")).strip()
            if not revision:
                skipped.append(f"{item.get('path', '')}: missing submission_revision")
                continue
            if revision in seen:
                skipped.append(f"{revision}: duplicate manifest artifacts")
                continue
            if not author:
                skipped.append(f"{revision}: missing JFrog uploader identity")
                continue
            seen.add(revision)
            candidates.append(SubmissionCandidate(revision, revision, author))
        candidates.sort(key=lambda candidate: candidate.identifier)
        return candidates, skipped

    def explicit_submissions(
        self, repo_id: str, values: list[str]
    ) -> list[SubmissionCandidate]:
        candidates, skipped = self.discover_submissions(repo_id)
        by_revision = {candidate.revision: candidate for candidate in candidates}
        selected: list[SubmissionCandidate] = []
        seen: set[str] = set()
        for raw_value in values:
            value = _validate_revision(raw_value)
            if value in seen:
                raise ValueError(f"Duplicate submission selection: {value}")
            seen.add(value)
            try:
                selected.append(by_revision[value])
            except KeyError as exc:
                detail = f"; discovery skips: {'; '.join(skipped)}" if skipped else ""
                raise ValueError(
                    f"JFrog submission {value!r} was not found in AQL results{detail}"
                ) from exc
        return selected

    def publish_aggregate(
        self,
        repo_id: str,
        folder: Path,
        paths: list[str],
        *,
        expected_base: str,
        next_round: int,
        tag: str | None,
        reference=None,
        claim=None,
    ) -> PublishResult:
        del next_round
        if tag:
            tag = _validate_revision(tag)
        current = self.resolve_revision(repo_id, "main")
        if current != expected_base:
            raise RuntimeError(
                f"JFrog main changed before publication: expected {expected_base}, found {current}"
        )
        with _selected_folder(folder, paths) as staging:
            self._upload_folder(repo_id, staging, "main")
            published = self.resolve_revision(repo_id, "main")
            if published == expected_base:
                raise RuntimeError("JFrog main did not advance after aggregate upload")
            if tag:
                self._upload_folder(repo_id, staging, tag)
        return PublishResult(published, resolved_revision=published)
