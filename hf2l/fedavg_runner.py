"""FedAvg application orchestration, independent of command-line parsing."""

from __future__ import annotations

import json
import fcntl
import os
import threading
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any


from hf2l.allowlist import load_allowlist
from hf2l.backends.base import (ClaimHandle, PublicationConsistency, PublicationUncertain,
                                RoundContext, SubmissionCandidate)
from hf2l.checkpoint_utils import (
    average_tensor,
    discover_checkpoint,
    validate_coefficients,
    validate_compatible,
)
from hf2l.hub_helpers import (
    ROUND_FILE,
    SUBMISSION_FILE,
    SCHEMA_VERSION,
    artifact_hashes,
    read_json,
    regular_file_paths,
    require_new_directory,
    utc_now,
    validate_artifact_hashes,
    write_json,
)
from hf2l.plugin_loader import load_plugin, parse_plugin_args, require_callable
from hf2l.core.protocol import RoundRecord, SubmissionManifest
from hf2l.round.config import RoundConfig
from hf2l.round.result import RoundResult, SkippedSubmission
from hf2l.round.aggregator import Aggregator, make_aggregator


def validate_submission_manifest(
    manifest: dict[str, Any],
    *,
    repo_id: str,
    base_revision: str,
    current_round: int,
    revision: str,
    expected_participant: str | None,
    expected_backend: str = "huggingface",
    expected_submission_revision: str | None = None,
) -> tuple[str, int]:
    document = SubmissionManifest.from_dict(manifest)
    if document.repo_id != repo_id:
        raise ValueError(f"{revision} declares a different repository")
    if document.backend != expected_backend:
        raise ValueError(f"{revision} declares backend {document.backend!r}; expected {expected_backend!r}")
    if document.base_revision != base_revision:
        raise ValueError(f"{revision} used base {document.base_revision}; current main is {base_revision}")
    if document.source_round != current_round:
        raise ValueError(f"{revision} declares source round {document.source_round}; current round is {current_round}")
    if expected_participant is not None and document.participant != expected_participant:
        raise ValueError(f"{revision} author is approved only as participant {expected_participant!r}, not {document.participant!r}")
    if document.schema_version >= 2 and expected_submission_revision is not None:
        if document.submission_revision != expected_submission_revision:
            raise ValueError(f"{revision} declares submission revision {document.submission_revision!r}")
    return document.participant, document.num_examples


def validate_state(reference: dict[str, Any], candidate: dict[str, Any]) -> None:
    """Compatibility helper retained for small in-memory callers and tests."""
    if reference.keys() != candidate.keys():
        missing = sorted(reference.keys() - candidate.keys())
        extra = sorted(candidate.keys() - reference.keys())
        raise ValueError(f"State-dict keys differ: missing={missing[:5]}, extra={extra[:5]}")
    for key, reference_tensor in reference.items():
        candidate_tensor = candidate[key]
        if reference_tensor.shape != candidate_tensor.shape:
            raise ValueError(
                f"Shape mismatch for {key}: {reference_tensor.shape} != {candidate_tensor.shape}"
            )
        if reference_tensor.dtype != candidate_tensor.dtype:
            raise ValueError(
                f"Dtype mismatch for {key}: {reference_tensor.dtype} != {candidate_tensor.dtype}"
            )


def fedavg_states(
    reference: dict[str, Any],
    client_states: list[dict[str, Any]],
    coefficients: list[float],
) -> dict[str, Any]:
    """Average a small state dict; production CLI aggregation streams by shard."""
    validate_coefficients(coefficients, len(client_states))
    for state in client_states:
        validate_state(reference, state)
    return {
        key: average_tensor(
            reference_tensor,
            [state[key] for state in client_states],
            coefficients,
            "float64",
            key,
        )
        for key, reference_tensor in reference.items()
    }


def _read_round(path: Path, label: str) -> int:
    try:
        return RoundRecord.from_dict(read_json(path / ROUND_FILE)).round
    except ValueError as exc:
        raise ValueError(f"The {label} model has an invalid round record: {exc}") from exc


class RunState:
    """Persist ownership before acquisition, independently of disposable output files."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.lock = None

    def acquire(self, context: RoundContext, lease_seconds: int = 3600) -> dict:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = self.path.with_name(self.path.name + ".lock").open("a")
        try:
            fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self.lock.close()
            self.lock = None
            raise ValueError("Another coordinator is using this run-state file") from exc
        identity = {"repo_id": context.repo_id, "reference": asdict(context.reference),
                    "reference_name": context.reference_name}
        if self.path.exists():
            saved = read_json(self.path)
            if any(saved.get(k) != v for k, v in identity.items()):
                raise ValueError("Run state belongs to a different round; reconcile its claim before using a new state file")
            return saved
        saved = {**identity, "acquisition_key": uuid.uuid4().hex, "lease_seconds": lease_seconds}
        self._write(saved)
        return saved

    def _write(self, value):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(self.path.name + ".tmp")
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(self.path)
        directory = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def remember(self, claim: ClaimHandle):
        saved = read_json(self.path)
        saved.update(claim_id=claim.id, fence=claim.fence, lease_until=claim.lease_until)
        self._write(saved)

    def clear(self):
        self.path.unlink(missing_ok=True)

    def close(self):
        if self.lock is not None:
            self.lock.close()
            self.lock = None


class ClaimRenewal:
    """Keep a runner's explicit claim alive and fail closed after renewal loss."""

    def __init__(self, store, repo_id, claim, lease_seconds, state, *, interval=None):
        self.store, self.repo_id, self.claim = store, repo_id, claim
        self.lease_seconds, self.state = lease_seconds, state
        self.fixed_interval = interval
        self.interval = interval if interval is not None else max(0.1, min(10, (claim.lease_until - time.time()) / 3))
        self.failure = None
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._run, name="fedavg-claim-renewal", daemon=True)

    def start(self):
        self.thread.start()

    def _run(self):
        while not self.stopped.wait(self.interval):
            try:
                renewed = self.store.renew_claim(self.repo_id, self.claim, self.lease_seconds)
                if (renewed.id, renewed.fence) != (self.claim.id, self.claim.fence):
                    raise ValueError("Claim ownership changed during renewal")
                self.claim = renewed
                if self.fixed_interval is None:
                    self.interval = max(0.1, min(10, (renewed.lease_until - time.time()) / 3))
                self.state.remember(renewed)
            except Exception as exc:
                self.failure = exc
                self.stopped.set()

    def check(self):
        if self.failure is not None:
            raise RuntimeError("Coordination lease was lost; publication is stopped") from self.failure

    def close(self):
        self.stopped.set()
        if self.thread.ident is not None:
            self.thread.join()


class FedAvgRunner:
    """Run one round, returning structured data and retaining explicit claim ownership."""

    def __init__(self, store, *, aggregator: Aggregator | None = None):
        self.store = store
        self.aggregator = aggregator
        self.context = None
        self.renewal = None
        self.run_state = None
        self.published = False
        self._started = False
        self.warnings: list[str] = []
        self.skipped: list[SkippedSubmission] = []

    def _check_lease(self):
        if self.renewal:
            self.renewal.check()

    def run(self, config: RoundConfig | object) -> RoundResult:
        if self._started:
            raise RuntimeError("Create a new FedAvgRunner for each round")
        self._started = True
        config = config if isinstance(config, RoundConfig) else RoundConfig.from_namespace(config)
        try:
            return self._execute(config)
        except Exception as exc:
            # An uncertain primary write requires reconciliation, never an automatic retry.
            if self.renewal and not self.published and not isinstance(exc, PublicationUncertain):
                self.renewal.close()
                try:
                    self.store.abandon_claim(config.repo_id, self.renewal.claim)
                    self.run_state.clear()
                except Exception as release_error:
                    self.warnings.append(f"Could not abandon claim: {release_error}")
            raise
        finally:
            if self.renewal:
                self.renewal.close()
            if self.run_state:
                self.run_state.close()

    def _publication_succeeded(self):
        self.published = True
        if self.renewal:
            self.renewal.close()
        if self.run_state:
            try:
                self.run_state.clear()
            except OSError as exc:
                self.warnings.append(f"publication succeeded, but run-state cleanup failed: {exc}")

    def _skip(self, candidate: str, reason: object):
        self.skipped.append(SkippedSubmission(candidate, str(reason)))

    def _finish(self, config: RoundConfig, result: RoundResult) -> RoundResult:
        # The publication outcome remains successful even when the report cannot be persisted.
        try:
            write_json(Path(config.output_dir) / "result.json", result.to_dict())
        except OSError as exc:
            if not self.published:
                raise
            from dataclasses import replace
            warning = f"publication succeeded, but result report could not be written: {exc}"
            self.warnings.append(warning)
            result = replace(result, warnings=(*result.warnings, warning))
        return result

    def _execute(self, config: RoundConfig) -> RoundResult:
        store = self.store
        capabilities = store.capabilities
        claiming = config.selection == "claim"
        if config.require_concurrent_publication and capabilities.publication != PublicationConsistency.ATOMIC:
            raise ValueError(f"{store.name} provides preflight-only publication; use one writer or an atomic backend")
        config.validate()
        if capabilities.requires_coordination_for_publication and config.publish and not claiming:
            raise ValueError("This backend requires --claim-submissions or --claim-id for publication")
        if claiming and not capabilities.fenced_coordination:
            raise ValueError(f"{store.name} does not support fenced coordination")
        if config.use_pull_requests and not capabilities.pull_requests:
            raise ValueError("This backend has no pull requests; use --submission or --discover-submissions")
        if config.publish and capabilities.publication == PublicationConsistency.PREFLIGHT:
            self.warnings.append("This backend requires a single publishing coordinator")
        automatic = config.selection in {"discover", "claim"}
        allowlist = load_allowlist(config.allowlist) if config.allowlist else None
        if automatic and allowlist is None and not capabilities.binds_participants:
            self.warnings.append("Automatic discovery without --allowlist accepts every compatible repository submission")
        aggregator = self.aggregator or make_aggregator(config.algorithm, weighting=config.weighting)
        if isinstance(aggregator.minimum_participants, bool) or not isinstance(aggregator.minimum_participants, int) or aggregator.minimum_participants < 2:
            raise ValueError("An aggregator must require at least two participants")
        minimum = max(config.minimum_participants, aggregator.minimum_participants)

        output_dir = Path(config.output_dir).resolve()
        require_new_directory(output_dir)
        base_reference = store.resolve_reference(config.repo_id, "main")
        base_revision = base_reference.revision
        if config.expected_base_revision and base_revision != config.expected_base_revision:
            raise ValueError(f"Main changed since readiness check: expected {config.expected_base_revision}; found {base_revision}")
        base_dir = output_dir / "downloads" / "base"
        store.download_snapshot(config.repo_id, base_revision, base_dir, allow_patterns=ROUND_FILE)
        current_round = _read_round(base_dir, "main")
        base_round_record = read_json(base_dir / ROUND_FILE)
        if int(base_round_record.get("schema_version", 1)) >= 2 and base_round_record.get("backend") != store.name:
            raise ValueError(f"Main declares backend {base_round_record.get('backend')!r}; expected {store.name!r}")

        context = RoundContext(config.repo_id, base_reference, current_round)
        self.context = context
        if claiming:
            self.run_state = RunState(config.run_state or output_dir.with_name(output_dir.name + ".run-state.json"))
            saved = self.run_state.acquire(context, config.claim_lease_seconds)
            claim, candidates = store.claim_submissions(
                config.repo_id, context=context, acquisition_key=saved["acquisition_key"],
                claim_id=config.claim_id or saved.get("claim_id"), lease_seconds=saved["lease_seconds"],
            )
            self.renewal = ClaimRenewal(store, config.repo_id, claim, saved["lease_seconds"], self.run_state)
            self.run_state.remember(claim)
            self.renewal.start()
        elif automatic:
            candidates, skipped = store.discover_submissions(config.repo_id, context=context)
            for reason in skipped:
                self._skip("discovery", reason)
        else:
            candidates = store.explicit_submissions(config.repo_id, list(config.submissions))

        authorized: list[SubmissionCandidate] = []
        for candidate in candidates:
            if allowlist is not None and candidate.author.casefold() not in allowlist:
                reason = f"{candidate.identifier} author={candidate.author}: not in allowlist"
                if automatic:
                    self._skip(candidate.identifier, reason)
                    continue
                raise ValueError(reason)
            authorized.append(candidate)

        prepared: list[tuple[SubmissionCandidate, str, dict[str, Any], str, int]] = []
        seen_participants: set[str] = set()
        for candidate_index, candidate in enumerate(authorized, start=1):
            self._check_lease()
            revision = candidate.revision
            manifest_dir = output_dir / "discovery" / f"submission-{candidate_index}"
            try:
                resolved_revision = store.resolve_revision(config.repo_id, revision)
                if capabilities.ancestry and not store.is_descendant(config.repo_id, resolved_revision, base_revision):
                    raise ValueError(f"{revision} is not descended from current main {base_revision}")
                store.download_snapshot(config.repo_id, resolved_revision, manifest_dir, allow_patterns=SUBMISSION_FILE)
                manifest = read_json(manifest_dir / SUBMISSION_FILE)
                expected_participant = allowlist[candidate.author.casefold()] if allowlist is not None else candidate.participant
                if candidate.participant is not None and expected_participant != candidate.participant:
                    raise ValueError("Allowlist differs from server-bound participant identity")
                if capabilities.binds_participants and not candidate.participant:
                    raise ValueError("Backend did not provide a bound participant identity")
                participant, num_examples = validate_submission_manifest(
                    manifest, repo_id=config.repo_id, base_revision=base_revision, current_round=current_round,
                    revision=revision, expected_participant=expected_participant, expected_backend=store.name,
                    expected_submission_revision=candidate.identifier if capabilities.named_submission_revisions else None,
                )
                # New producers declare algorithm identity; old manifests without it remain readable.
                algorithm_value = manifest.get("algorithm_spec")
                if algorithm_value is None and isinstance(manifest.get("algorithm"), dict):
                    algorithm_value = manifest["algorithm"]
                if algorithm_value is not None:
                    from hf2l.core.protocol import AlgorithmSpec
                    declared = AlgorithmSpec.from_dict(algorithm_value)
                    if (declared.name, declared.version) != (aggregator.spec.name, aggregator.spec.version):
                        raise ValueError(f"{revision} declares a different aggregation algorithm")
                    owner_parameters = getattr(aggregator, "server_only_parameters", frozenset())
                    declared_training = {k: v for k, v in declared.params.items() if k not in owner_parameters}
                    expected_training = {k: v for k, v in aggregator.spec.params.items() if k not in owner_parameters}
                    if declared_training != expected_training:
                        raise ValueError(f"{revision} declares different algorithm parameters")
            except (ValueError, FileNotFoundError) as exc:
                if automatic:
                    self._skip(candidate.identifier, exc)
                    continue
                raise
            if participant in seen_participants:
                raise ValueError(f"Duplicate participant {participant!r} among eligible submissions; withdraw the superseded submission or select revisions explicitly")
            seen_participants.add(participant)
            prepared.append((candidate, resolved_revision, manifest, participant, num_examples))

        if config.check_only:
            eligible = tuple({"participant": participant, "author": candidate.author,
                              "submission_revision": candidate.revision, "resolved_revision": resolved,
                              "num_examples": count} for candidate, resolved, _, participant, count in prepared)
            result = RoundResult("ready" if len(prepared) >= minimum else "not_ready", store.name,
                                 base_reference, current_round, eligible, tuple(self.skipped), tuple(self.warnings),
                                 minimum_participants=minimum)
            write_json(output_dir / "readiness.json", result.readiness())
            return self._finish(config, result)

        if len(prepared) < minimum:
            mode = "eligible" if automatic else "selected"
            threshold = "two" if minimum == 2 else str(minimum)
            raise ValueError(f"FedAvg requires at least {threshold} {mode} client submissions; found {len(prepared)}")
        store.download_snapshot(config.repo_id, base_revision, base_dir)
        reference = discover_checkpoint(base_dir)
        if int(base_round_record.get("schema_version", 1)) >= 2:
            validate_artifact_hashes(base_dir, reference.artifact_paths,
                                     base_round_record.get("checkpoint_files_sha256"), "main")
        submissions: list[dict[str, Any]] = []
        client_layouts = []
        for index, item in enumerate(prepared, start=1):
            self._check_lease()
            candidate, resolved_revision, manifest, participant, num_examples = item
            client_dir = output_dir / "downloads" / f"client-{index}"
            try:
                store.download_snapshot(config.repo_id, resolved_revision, client_dir)
                if read_json(client_dir / SUBMISSION_FILE) != manifest:
                    raise ValueError(f"Manifest changed while downloading {candidate.identifier}")
                client_layout = discover_checkpoint(client_dir)
                validate_compatible(reference, client_layout)
                if int(manifest.get("schema_version", 1)) >= 2:
                    validate_artifact_hashes(client_dir, client_layout.artifact_paths,
                                            manifest.get("checkpoint_files_sha256"), candidate.identifier)
            except (ValueError, FileNotFoundError) as exc:
                if automatic:
                    self._skip(candidate.identifier, exc)
                    continue
                raise
            client_layouts.append(client_layout)
            submissions.append({"participant": participant, "author": candidate.author,
                                "submission_revision": candidate.revision, "resolved_revision": resolved_revision,
                                "num_examples": num_examples, "training": manifest.get("training", {})})
        if len(submissions) < minimum:
            threshold = "two" if minimum == 2 else str(minimum)
            raise ValueError(f"FedAvg requires at least {threshold} valid client checkpoints; found {len(submissions)}")
        coefficients = list(aggregator.coefficients(submissions))
        validate_coefficients(coefficients, len(submissions))
        aggregate_dir = output_dir / "aggregated_model"
        self._check_lease()
        aggregate = aggregator.reduce(reference, client_layouts, coefficients, aggregate_dir,
                                      accumulator_dtype=config.accumulator_dtype, array_backend=config.array_backend)
        # A custom reducer must return the same checkpoint contract and finite-aggregation policy is its responsibility.
        validate_compatible(reference, aggregate)
        self._check_lease()
        evaluation: dict[str, Any] | None = None
        if config.plugin:
            plugin = load_plugin(config.plugin)
            evaluate_model = require_callable(plugin, "evaluate_model")
            evaluation = evaluate_model(aggregate_dir, parse_plugin_args(list(config.plugin_arg)))
            if not isinstance(evaluation, dict):
                raise ValueError("evaluate_model(...) must return a metadata dictionary")
            json.dumps(evaluation, allow_nan=False)
        next_round = current_round + 1
        for submission, coefficient in zip(submissions, coefficients, strict=True):
            submission["coefficient"] = coefficient
        description = f"FedAvg with {aggregator.spec.params.get('weighting', config.weighting)} weighting" if aggregator.spec.name == "fedavg" else aggregator.spec.name
        round_record = {
            "schema_version": SCHEMA_VERSION, "round": next_round, "backend": store.name,
            "algorithm": description, "algorithm_spec": aggregator.spec.to_dict(),
            "accumulator_dtype": config.accumulator_dtype, "array_backend": config.array_backend,
            "base_revision": base_revision, "created_at": utc_now(),
            "checkpoint_files": list(aggregate.artifact_paths), "evaluation": evaluation,
            "selection": {"mode": "automatic_submissions" if automatic else "explicit_submissions",
                          "allowlist_enforced": allowlist is not None, "minimum_participants": minimum},
            "submissions": submissions,
        }
        round_record["checkpoint_files_sha256"] = artifact_hashes(aggregate_dir, aggregate.artifact_paths)
        RoundRecord.from_dict(round_record)
        write_json(aggregate_dir / ROUND_FILE, round_record)
        publication = None
        if config.publish:
            self._check_lease()
            publication = store.publish_aggregate(
                config.repo_id, aggregate_dir, regular_file_paths(aggregate_dir), expected_base=base_revision,
                next_round=next_round, tag=config.tag, reference=base_reference,
                claim=self.renewal.claim if self.renewal else None,
            )
            self._publication_succeeded()
            self.warnings.extend(publication.warnings)
        result = RoundResult("published" if publication else "aggregated", store.name, base_reference, next_round,
                             tuple(submissions), tuple(self.skipped), tuple(self.warnings), aggregate_dir,
                             evaluation, publication, self.renewal.claim.id if self.renewal else None, minimum)
        return self._finish(config, result)


def run_round(store, config: RoundConfig, *, aggregator: Aggregator | None = None) -> RoundResult:
    """Run a round without owning the caller's store lifetime or writing to stdout/stderr."""
    if not isinstance(config, RoundConfig):
        raise TypeError("run_round requires RoundConfig")
    return FedAvgRunner(store, aggregator=aggregator).run(config)
