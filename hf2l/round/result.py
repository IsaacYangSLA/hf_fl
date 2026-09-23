"""Serializable outcomes from the owner application, without presentation policy."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any, Literal

from hf2l.core.ports import PublishResult, ResolvedReference


@dataclass(frozen=True)
class SkippedSubmission:
    candidate: str
    reason: str


@dataclass(frozen=True)
class RoundResult:
    status: Literal["not_ready", "ready", "aggregated", "published"]
    backend: str
    base: ResolvedReference
    round_number: int
    eligible: tuple[dict[str, Any], ...] = ()
    skipped: tuple[SkippedSubmission, ...] = ()
    warnings: tuple[str, ...] = ()
    aggregate_dir: Path | None = None
    evaluation: dict[str, Any] | None = None
    publication: PublishResult | None = None
    claim_id: str | None = None
    minimum_participants: int = 2

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["aggregate_dir"] = str(self.aggregate_dir) if self.aggregate_dir is not None else None
        return json.loads(json.dumps(result, allow_nan=False))

    def readiness(self) -> dict[str, Any]:
        return {"ready": len(self.eligible) >= self.minimum_participants,
                "eligible_count": len(self.eligible), "base_revision": self.base.revision}
