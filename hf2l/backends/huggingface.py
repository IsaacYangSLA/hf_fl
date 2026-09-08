"""Hugging Face Hub implementation of the HF²L storage contract."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from huggingface_hub import CommitOperationAdd, HfApi

from hf2l.backends.base import ModelStore, PublishResult, SubmissionCandidate


def normalize_pr(value: str) -> str:
    value = value.strip()
    if value.isdigit():
        return f"refs/pr/{value}"
    if value.startswith("refs/pr/") and value.removeprefix("refs/pr/").isdigit():
        return value
    raise ValueError(f"PR must be a number or refs/pr/N, received {value!r}")


class HuggingFaceStore(ModelStore):
    name = "huggingface"
    supports_ancestry = True

    def __init__(self, token: str | None, endpoint: str | None = None):
        kwargs: dict[str, Any] = {"token": token}
        if endpoint:
            kwargs["endpoint"] = endpoint
        self.api = HfApi(**kwargs)

    def resolve_revision(self, repo_id: str, revision: str) -> str:
        resolved = self.api.model_info(repo_id, revision=revision).sha
        if not resolved:
            raise RuntimeError(f"Hugging Face did not resolve revision {revision!r}")
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
        )

    def initialize_repository(
        self, repo_id: str, folder: Path, *, private: bool
    ) -> PublishResult:
        repo_url = self.api.create_repo(
            repo_id=repo_id,
            repo_type="model",
            private=private,
            exist_ok=False,
        )
        result = self.api.upload_folder(
            repo_id=repo_id,
            repo_type="model",
            folder_path=folder,
            commit_message="Initialize FedAvg round 0",
        )
        return PublishResult(str(result.oid), str(repo_url), str(result.oid))

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
        del submission_revision
        operations = [
            CommitOperationAdd(path_in_repo=path, path_or_fileobj=folder / path)
            for path in paths
        ]
        result = self.api.create_commit(
            repo_id=repo_id,
            repo_type="model",
            operations=operations,
            commit_message=f"FedAvg client update from {participant} for round {source_round}",
            parent_commit=base_revision,
            create_pr=True,
        )
        if not result.pr_revision:
            raise RuntimeError("The Hub did not return a PR revision")
        return PublishResult(
            str(result.pr_revision),
            str(result.pr_url) if result.pr_url else None,
            str(result.oid),
        )

    def discover_submissions(
        self, repo_id: str
    ) -> tuple[list[SubmissionCandidate], list[str]]:
        candidates: list[SubmissionCandidate] = []
        skipped: list[str] = []
        discussions = self.api.get_repo_discussions(
            repo_id=repo_id,
            repo_type="model",
            discussion_type="pull_request",
            discussion_status="open",
        )
        for discussion in discussions:
            if not discussion.is_pull_request:
                continue
            number = int(discussion.num)
            revision = f"refs/pr/{number}"
            author = discussion.author.strip() if isinstance(discussion.author, str) else ""
            if not author:
                skipped.append(f"{revision}: missing HF author")
                continue
            candidates.append(SubmissionCandidate(revision, revision, author))
        candidates.sort(key=lambda candidate: int(candidate.identifier.removeprefix("refs/pr/")))
        return candidates, skipped

    def explicit_submissions(
        self, repo_id: str, values: list[str]
    ) -> list[SubmissionCandidate]:
        candidates: list[SubmissionCandidate] = []
        seen: set[int] = set()
        for value in values:
            revision = normalize_pr(value)
            number = int(revision.removeprefix("refs/pr/"))
            if number in seen:
                raise ValueError(f"Duplicate submission selection: {revision}")
            seen.add(number)
            details = self.api.get_discussion_details(
                repo_id=repo_id,
                discussion_num=number,
                repo_type="model",
            )
            if not details.is_pull_request:
                raise ValueError(f"Discussion {number} is not a pull request")
            author = details.author.strip() if isinstance(details.author, str) else ""
            if not author:
                raise ValueError(f"{revision} has no HF author")
            candidates.append(SubmissionCandidate(revision, revision, author))
        return candidates

    def is_descendant(self, repo_id: str, revision: str, base_revision: str) -> bool:
        history = self.api.list_repo_commits(repo_id, revision=revision)
        return any(commit.commit_id == base_revision for commit in history)

    def publish_aggregate(
        self,
        repo_id: str,
        folder: Path,
        paths: list[str],
        *,
        expected_base: str,
        next_round: int,
        tag: str | None,
    ) -> PublishResult:
        operations = [
            CommitOperationAdd(path_in_repo=path, path_or_fileobj=folder / path)
            for path in paths
        ]
        result = self.api.create_commit(
            repo_id=repo_id,
            repo_type="model",
            revision="main",
            parent_commit=expected_base,
            operations=operations,
            commit_message=f"Publish FedAvg round {next_round}",
        )
        published = self.resolve_revision(repo_id, "main")
        if published != result.oid:
            raise RuntimeError(
                f"Post-publish verification failed: main={published}, commit={result.oid}"
            )
        if tag:
            self.api.create_tag(
                repo_id,
                repo_type="model",
                tag=tag,
                revision=result.oid,
                tag_message=f"FedAvg round {next_round}",
                exist_ok=False,
            )
        return PublishResult(
            str(result.oid),
            str(result.commit_url) if result.commit_url else None,
            str(result.oid),
        )
