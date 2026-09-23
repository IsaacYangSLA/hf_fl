"""Standard-library ports for the federated-learning application layer."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


@dataclass(frozen=True)
class SubmissionCandidate:
    """One immutable client submission exposed by a model store."""

    identifier: str
    revision: str
    author: str
    participant: str | None = None


class PublicationConsistency(str, Enum):
    ATOMIC = "atomic_conditional"
    PREFLIGHT = "preflight_only"


@dataclass(frozen=True)
class BackendCapabilities:
    publication: PublicationConsistency
    fenced_coordination: bool = False
    ancestry: bool = False
    pull_requests: bool = False
    requires_coordination_for_publication: bool = False
    binds_participants: bool = False
    named_submission_revisions: bool = False


@dataclass(frozen=True)
class ResolvedReference:
    revision: str
    generation: int | None = None
    token: str | None = None


@dataclass(frozen=True)
class RoundContext:
    repo_id: str
    reference: ResolvedReference
    round_number: int
    reference_name: str = "main"


@dataclass(frozen=True)
class ClaimHandle:
    id: str
    fence: int
    reference: ResolvedReference
    input_ids: tuple[str, ...]
    lease_until: float
    provider_handle: object


class RevisionNotFound(ValueError):
    """The selected immutable revision or requested snapshot no longer exists."""


class PublicationUncertain(RuntimeError):
    """A primary write may have succeeded; reconcile before retrying it."""


@dataclass(frozen=True)
class PublishResult:
    """Backend-neutral result of publishing a model snapshot."""

    revision: str
    url: str | None = None
    resolved_revision: str | None = None
    warnings: tuple[str, ...] = ()
    tag_created: bool | None = None


class ModelStore(ABC):
    """Operations the transport-independent client and owner workflows need."""

    name: str
    supports_ancestry: bool = False
    capabilities = BackendCapabilities(PublicationConsistency.PREFLIGHT)

    def close(self) -> None:
        """Release owned resources; repeated calls are safe."""

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def resolve_reference(self, repo_id: str, name: str = "main") -> ResolvedReference:
        return ResolvedReference(self.resolve_revision(repo_id, name))

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
        self, repo_id: str, *, context: RoundContext | None = None
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
        reference=None,
        claim=None,
    ) -> PublishResult:
        """Publish an accepted aggregate to main."""

    def new_submission_revision(self, participant: str, source_round: int) -> str | None:
        """Return a unique named revision when the backend does not use PR refs."""

        return None

    def claim_submissions(
        self, repo_id: str, *, context: RoundContext, acquisition_key: str,
        claim_id: str | None = None, lease_seconds: int = 3600,
    ) -> tuple[ClaimHandle, list[SubmissionCandidate]]:
        """Acquire or resume explicitly owned, fenced round inputs."""
        raise ValueError(f"The {self.name} backend does not support claims")

    def renew_claim(self, repo_id: str, claim: ClaimHandle, lease_seconds: int) -> ClaimHandle:
        raise ValueError(f"The {self.name} backend does not support claims")

    def abandon_claim(self, repo_id: str, claim: ClaimHandle) -> None:
        raise ValueError(f"The {self.name} backend does not support claims")
