"""Command-line independent configuration for one owner round."""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Literal

from hf2l.core.protocol import AlgorithmSpec


@dataclass(frozen=True)
class RoundConfig:
    repo_id: str
    output_dir: Path
    selection: Literal["discover", "explicit", "claim"] = "discover"
    submissions: tuple[str, ...] = ()
    use_pull_requests: bool = False
    allowlist: Path | None = None
    expected_base_revision: str | None = None
    algorithm: AlgorithmSpec = field(default_factory=lambda: AlgorithmSpec("fedavg"))
    weighting: Literal["examples", "uniform"] = "examples"
    minimum_participants: int = 2
    accumulator_dtype: Literal["float32", "float64"] = "float32"
    array_backend: Literal["numpy", "torch"] = "numpy"
    plugin: str | None = None
    plugin_arg: tuple[str, ...] = ()
    check_only: bool = False
    publish: bool = False
    tag: str | None = None
    run_state: Path | None = None
    claim_id: str | None = None
    claim_lease_seconds: int = 3600
    require_concurrent_publication: bool = False

    def validate(self) -> None:
        if not isinstance(self.algorithm, AlgorithmSpec):
            raise ValueError("algorithm must be an AlgorithmSpec")
        for name in ("use_pull_requests", "check_only", "publish", "require_concurrent_publication"):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be a boolean")
        if not self.repo_id or not isinstance(self.repo_id, str):
            raise ValueError("repo_id must not be empty")
        if self.selection not in {"discover", "explicit", "claim"}:
            raise ValueError("selection must be discover, explicit, or claim")
        if self.selection == "explicit" and not self.submissions:
            raise ValueError("Explicit selection requires at least one submission")
        if self.selection != "explicit" and self.submissions:
            raise ValueError("Submission identifiers require explicit selection")
        if self.claim_id and self.selection != "claim":
            raise ValueError("claim_id requires claim selection")
        if isinstance(self.minimum_participants, bool) or not isinstance(self.minimum_participants, int) or self.minimum_participants < 2:
            raise ValueError("minimum_participants must be an integer of at least two")
        if self.weighting not in {"examples", "uniform"}:
            raise ValueError("weighting must be examples or uniform")
        if self.accumulator_dtype not in {"float32", "float64"}:
            raise ValueError("accumulator_dtype must be float32 or float64")
        if self.array_backend not in {"numpy", "torch"}:
            raise ValueError("array_backend must be numpy or torch")
        if isinstance(self.claim_lease_seconds, bool) or not isinstance(self.claim_lease_seconds, int) or not 10 <= self.claim_lease_seconds <= 3600:
            raise ValueError("claim_lease_seconds must be between 10 and 3600")
        if self.tag and not self.publish:
            raise ValueError("--tag requires --publish")
        if self.check_only and (self.publish or self.plugin or self.plugin_arg):
            raise ValueError("--check-only cannot publish or evaluate a model")
        if self.plugin_arg and not self.plugin:
            raise ValueError("--plugin-arg requires --plugin")
        if self.selection == "claim" and (self.check_only or not self.publish):
            raise ValueError("Claims require --publish and cannot use --check-only")

    @classmethod
    def from_namespace(cls, value: object) -> "RoundConfig":
        """Translate old CLI-shaped callers at the boundary, never in the workflow."""
        options = vars(value)
        shared = {item.name: options[item.name] for item in fields(cls) if item.name in options}
        shared.setdefault("repo_id", "")
        shared.setdefault("output_dir", Path("."))
        shared["output_dir"] = Path(shared["output_dir"])
        shared["selection"] = (
            "claim" if options.get("claim_submissions") or options.get("claim_id") else
            "discover" if options.get("discover_submissions") or options.get("discover_prs") else "explicit"
        )
        shared["submissions"] = tuple(options.get("submission") or options.get("pr") or ())
        shared["use_pull_requests"] = bool(options.get("pr") or options.get("discover_prs"))
        shared["plugin_arg"] = tuple(options.get("plugin_arg") or ())
        # Old Python callers retain their numerical backend; the new CLI passes its default explicitly.
        shared.setdefault("array_backend", "torch")
        algorithm = shared.get("algorithm", "fedavg")
        if isinstance(algorithm, str):
            shared["algorithm"] = AlgorithmSpec(algorithm)
        return cls(**shared)
