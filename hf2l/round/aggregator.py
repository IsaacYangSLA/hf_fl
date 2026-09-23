"""Algorithm strategy seam; built-in FedAvg delegates all tensor math to checkpoints."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, ClassVar, Mapping, Protocol, Sequence

from hf2l.checkpoint.aggregate import aggregate_shards
from hf2l.checkpoint.format import get_ops
from hf2l.checkpoint.layout import CheckpointLayout
from hf2l.core.protocol import AlgorithmSpec, ROUND_FILE, SUBMISSION_FILE


class Aggregator(Protocol):
    """Injected algorithms own weights and reduction while rounds own trust and publication.

    Optional ``server_only_parameters`` names owner-side choices that need not
    match a client's algorithm descriptor. Every other parameter must match.
    """

    spec: AlgorithmSpec
    minimum_participants: int

    def coefficients(self, submissions: Sequence[Mapping[str, Any]]) -> Sequence[float]: ...

    def reduce(self, reference: CheckpointLayout, clients: Sequence[CheckpointLayout],
               coefficients: Sequence[float], output_dir: Path, *,
               accumulator_dtype: str, array_backend: str) -> CheckpointLayout: ...


@dataclass(frozen=True)
class FedAvg:
    weighting: str = "examples"
    minimum_participants: int = 2
    # Weighting is selected by the owner and does not change the client training algorithm.
    server_only_parameters: ClassVar[frozenset[str]] = frozenset({"weighting"})

    def __post_init__(self) -> None:
        if self.weighting not in {"examples", "uniform"}:
            raise ValueError("FedAvg weighting must be examples or uniform")

    @property
    def spec(self) -> AlgorithmSpec:
        return AlgorithmSpec("fedavg", params={"weighting": self.weighting})

    def coefficients(self, submissions: Sequence[Mapping[str, Any]]) -> tuple[float, ...]:
        if not submissions:
            raise ValueError("At least one submission is required for weighting")
        if self.weighting == "uniform":
            return (1.0 / len(submissions),) * len(submissions)
        counts = [item["num_examples"] for item in submissions]
        if any(isinstance(n, bool) or not isinstance(n, int) or n <= 0 for n in counts):
            raise ValueError("num_examples must be positive integers")
        total = sum(counts)
        return tuple(n / total for n in counts)

    def reduce(self, reference: CheckpointLayout, clients: Sequence[CheckpointLayout],
               coefficients: Sequence[float], output_dir: Path, *,
               accumulator_dtype: str, array_backend: str) -> CheckpointLayout:
        return aggregate_shards(reference, list(clients), list(coefficients), output_dir,
                                accumulator_dtype=accumulator_dtype,
                                ops=get_ops(reference, prefer=array_backend),
                                exclude=(ROUND_FILE, SUBMISSION_FILE, "server_state", ".hf2l"))


def _fedavg(spec: AlgorithmSpec, weighting: str) -> Aggregator:
    if spec.version != 1:
        raise ValueError("Unsupported FedAvg algorithm version")
    unknown = set(spec.params) - {"weighting"}
    if unknown:
        raise ValueError(f"Unsupported FedAvg parameters: {sorted(unknown)}")
    return FedAvg(spec.params.get("weighting", weighting))


AGGREGATORS: dict[str, Callable[[AlgorithmSpec, str], Aggregator]] = {"fedavg": _fedavg}


def make_aggregator(spec: AlgorithmSpec, *, weighting: str = "examples") -> Aggregator:
    try:
        factory = AGGREGATORS[spec.name]
    except KeyError as exc:
        raise ValueError(f"Unknown aggregation algorithm {spec.name!r}") from exc
    return factory(spec, weighting)
