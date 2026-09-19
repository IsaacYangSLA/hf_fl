"""Backend contract shared by Hugging Face Hub and JFrog Artifactory."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SubmissionCandidate:
    """One immutable client submission exposed by a model store."""

    identifier: str
    revision: str
    author: str
    participant: str | None = None


@dataclass(frozen=True)
class PublishResult:
    """Backend-neutral result of publishing a model snapshot."""

    revision: str
    url: str | None = None
    resolved_revision: str | None = None


class ModelStore(ABC):
    """Operations the transport-independent client and owner workflows need."""

    name: str
    supports_ancestry: bool = False

    @abstractmethod
    def resolve_revision(self, repo_id: str, revision: str) -> str:
        """Resolve a mutable or named revision to the backend's immutable ID."""

    @abstractmethod
    def download_snapshot(
        self,
        repo_id: str,
        revision: str,
        local_dir: Path,
        *,
        allow_patterns: str | list[str] | None = None,
    ) -> None:
        """Download one model snapshot."""

    @abstractmethod
    def initialize_repository(
        self, repo_id: str, folder: Path, *, private: bool
    ) -> PublishResult:
        """Publish the initial main snapshot."""

    @abstractmethod
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
        """Publish one client checkpoint without changing main."""

    @abstractmethod
    def discover_submissions(
        self, repo_id: str
    ) -> tuple[list[SubmissionCandidate], list[str]]:
        """Discover candidate submissions and describe records that were skipped."""

    @abstractmethod
    def explicit_submissions(
        self, repo_id: str, values: list[str]
    ) -> list[SubmissionCandidate]:
        """Resolve explicitly selected submission identifiers."""

    def is_descendant(self, repo_id: str, revision: str, base_revision: str) -> bool:
        """Return whether revision descends from base when the backend has a DAG."""

        return True

    @abstractmethod
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
        """Publish an accepted aggregate to main."""

    def new_submission_revision(self, participant: str, source_round: int) -> str | None:
        """Return a unique named revision when the backend does not use PR refs."""

        return None

    def claim_submissions(
        self, repo_id: str, claim_id: str | None = None, lease_seconds: int = 3600
    ) -> list[SubmissionCandidate]:
        """Acquire a fenced claim freezing this round's inputs, when the backend supports one."""

        raise ValueError(f"The {self.name} backend does not support claims")

    def abandon_claim(self, repo_id: str) -> None:
        """Release a held claim so another coordinator can decide the round."""
