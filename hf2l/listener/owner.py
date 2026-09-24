"""Reconcile eligible submissions and publish successive owner rounds.

The listener supplies scheduling and durable publication intent. Selection,
checkpoint validation, aggregation, evaluation, and conditional publication
remain the responsibility of the existing round runner and model-store ports.
"""

from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import tempfile

from hf2l.common.fs import file_sha256, read_json
from hf2l.core.ports import ModelStore, PublicationConsistency, PublicationUncertain
from hf2l.core.protocol import ROUND_FILE, RoundRecord
from hf2l.fedavg_runner import run_round
from hf2l.listener.engine import DurableListener, ListenerStateError, UncertainOperation, _digest, _text
from hf2l.round.config import RoundConfig


class UncertainAggregation(UncertainOperation):
    """An aggregate may have been published; inspect it before allowing replay."""


class OwnerListener(DurableListener):
    """One owner watches main and aggregates when enough eligible inputs exist.

``config.output_dir`` is ignored: every attempt gets a fresh directory beneath
``state_dir``. The listener owns base selection and claim recovery. Configuration
and allowlist contents are bound to this state without persisting option secrets.
Custom aggregators must supply a stable ``configuration_id`` identifying their
implementation and settings. The caller owns and closes the model store.
"""

    statuses = {"pending", "aggregating", "publishing", "uncertain", "published", "skipped"}
    terminal_statuses = {"published", "skipped"}
    success_status = "published"
    # A failed metadata probe may be superseded before its source round is known.
    round_optional_statuses = {"pending", "skipped"}

    def __init__(self, store: ModelStore, *, config: RoundConfig, state_dir: Path,
                 source_id: str, configuration_id: str = "", on_event=None, aggregator=None):
        if not isinstance(config, RoundConfig):
            raise ListenerStateError("Owner listener requires a RoundConfig")
        self.store = store
        self.repo_id = _text(config.repo_id, "repo_id")
        self.reference = "main"
        _text(source_id, "source_id")
        if not isinstance(configuration_id, str) or (aggregator is not None and not configuration_id):
            raise ListenerStateError("A custom aggregator requires a stable configuration_id")
        if config.selection not in {"discover", "claim"} or config.submissions or config.use_pull_requests:
            raise ListenerStateError("Owner listener discovers submissions automatically")
        if (config.expected_base_revision is not None or config.run_state is not None
                or config.claim_id is not None or config.tag is not None or config.check_only):
            raise ListenerStateError("Owner listener owns base selection, claim state and publication")
        claiming = store.capabilities.requires_coordination_for_publication or config.selection == "claim"
        self.config = replace(config, publish=True, selection="claim" if claiming else "discover",
                              output_dir=Path("."),
                              allowlist=Path(config.allowlist).expanduser().resolve() if config.allowlist else None)
        self.config.validate()
        if claiming and not store.capabilities.fenced_coordination:
            raise ListenerStateError("This backend cannot provide required fenced coordination")
        if (config.require_concurrent_publication
                and store.capabilities.publication != PublicationConsistency.ATOMIC):
            raise ListenerStateError("This backend requires a single publishing coordinator; atomic publication is unavailable")
        self.aggregator = aggregator
        self._allowlist_digest = self._policy_digest()
        options = asdict(self.config)
        options.pop("output_dir")
        options["allowlist"] = str(self.config.allowlist) if self.config.allowlist else None
        options["allowlist_sha256"] = self._allowlist_digest
        options["implementation"] = configuration_id
        identity = {"role": "owner", "backend": store.name, "repo_id": self.repo_id,
                    "reference": "main", "source_hash": _digest(source_id),
                    "configuration_hash": _digest(json.dumps(options, sort_keys=True,
                                                              separators=(",", ":"), allow_nan=False))}
        super().__init__(state_dir=state_dir, identity=identity, on_event=on_event)

    def _policy_digest(self):
        return file_sha256(self.config.allowlist) if self.config.allowlist else None

    def _check_policy(self):
        try:
            unchanged = self._policy_digest() == self._allowlist_digest
        except OSError as exc:
            raise ListenerStateError("Cannot read the configured owner allowlist") from exc
        if not unchanged:
            raise ListenerStateError("Owner allowlist changed; reconcile saved work before changing configuration")

    def _validate_state(self):
        super()._validate_state()
        for job in self.state["jobs"].values():
            if type(job.get("attempt", 0)) is not int or job.get("attempt", 0) < 0:
                raise ListenerStateError("Malformed owner attempt number")

    def _current_revision(self):
        return _text(self.store.resolve_reference(self.repo_id, "main").revision, "resolved revision")

    def _probe(self, revision):
        # The runner downloads only round/submission metadata in check-only mode.
        # Clean up every probe so a waiting listener cannot accumulate artifacts.
        with tempfile.TemporaryDirectory(prefix=".probe-", dir=self.root) as temporary:
            config = replace(self.config, output_dir=Path(temporary) / "readiness",
                             selection="discover", check_only=True, publish=False,
                             expected_base_revision=revision, plugin=None, plugin_arg=())
            return run_round(self.store, config, aggregator=self.aggregator)

    def poll_once(self) -> str:
        self._require_open()
        job = self.state["jobs"].get(self.state["active"])
        if job and job["status"] in self.uncertain_statuses:
            raise UncertainAggregation(
                "Aggregate outcome is unknown; inspect the backend and use --resolve-uncertain published or retry")
        self._check_policy()
        if job and job["status"] == "aggregating" and job["attempt"]:
            # This attempt never crossed the durable publication boundary.
            # Bound disk usage even if the next readiness probe fails or waits.
            # Acquisition state lives separately and is preserved for recovery.
            self._remove_owned(self._job_dir(job) / f"attempt-{job['attempt']:06d}")
        revision = self._current_revision()
        if job and job["revision"] != revision:
            self._finish(job, "skipped", reason="reference_advanced")
            job = None
        if job is None:
            if revision in self.state["jobs"]:
                self._emit("idle")
                return "idle"
            job = {"revision": revision, "source_round": None, "status": "pending", "attempt": 0}
            self.state["jobs"][revision] = job
            self.state["active"] = revision
            self._save()

        probe = self._probe(revision)
        if probe.base.revision != revision:
            raise ValueError("Readiness result does not match the pinned owner base")
        if job["source_round"] is not None and job["source_round"] != probe.round_number:
            raise ValueError("Pinned round metadata changed during owner readiness check")
        job["source_round"] = probe.round_number
        if probe.round_number <= self.state["completed_round"]:
            self._finish(job, "skipped", reason="round_already_completed")
            return "skipped"
        if probe.status != "ready":
            self._set_status(job, "pending")
            self._emit("not_ready", job, eligible_count=len(probe.eligible),
                       minimum_participants=probe.minimum_participants)
            return "not_ready"
        if self._current_revision() != revision:
            self._finish(job, "skipped", reason="reference_advanced")
            return "skipped"
        self._check_policy()

        job_dir = self._job_dir(job)
        job["attempt"] += 1
        attempt_dir = self._safe(job_dir / f"attempt-{job['attempt']:06d}")
        claim_state = self._safe(job_dir / "claim-state.json")
        self._safe(claim_state.with_name(claim_state.name + ".lock"))
        # Store the next attempt number before creating artifacts. A crashed
        # aggregation can retry with fresh output and the SAME acquisition state.
        self._set_status(job, "aggregating")
        self._emit("aggregating", job, attempt=job["attempt"])

        def before_publish(context, aggregate_dir):
            self._check_policy()
            if (context.repo_id != self.repo_id or context.reference.revision != revision
                    or context.round_number != job["source_round"] or context.reference_name != "main"):
                raise ListenerStateError("Publication context differs from the scheduled owner job")
            document_path = self._safe(aggregate_dir / ROUND_FILE)
            document = RoundRecord.from_dict(read_json(document_path))
            if document.round != job["source_round"] + 1 or document.base_revision != revision:
                raise ListenerStateError("Aggregate manifest differs from the scheduled owner job")
            job["publication_intent"] = {
                "base": asdict(context.reference), "source_round": job["source_round"],
                "target_round": document.round, "aggregate_dir": str(aggregate_dir),
                "manifest_sha256": hashlib.sha256(document_path.read_bytes()).hexdigest(),
            }
            self._set_status(job, "publishing")

        config = replace(self.config, output_dir=attempt_dir, expected_base_revision=revision,
                         run_state=claim_state if self.config.selection == "claim" else None)
        try:
            result = run_round(self.store, config, aggregator=self.aggregator, before_publish=before_publish)
        except Exception as exc:
            # PublicationUncertain may also come from replaying an acquisition
            # whose completion was lost before this process reached its hook.
            if job["status"] == "publishing" or isinstance(exc, PublicationUncertain):
                self._set_status(job, "uncertain")
                self._emit("uncertain", job, error_type=type(exc).__name__)
                raise UncertainAggregation(
                    "Aggregate outcome is unknown; inspect the remote publication before explicit recovery") from exc
            raise
        if result.status != "published" or result.publication is None:
            self._set_status(job, "uncertain")
            raise UncertainAggregation("The owner runner did not confirm its publication outcome")
        self._finish(job, "published", result=result.to_dict())
        return "published"

    def resolve_uncertain(self, action: str) -> None:
        """Apply the operator's remote reconciliation without bypassing claims.

``published`` acknowledges a confirmed publication. ``retry`` is appropriate
only after confirming non-publication. Saved acquisition state is retained;
Exchange may still reject replay until its own uncertain outcome is resolved.
"""
        self._require_open()
        if action not in {"published", "retry"}:
            raise ListenerStateError("Owner recovery action must be published or retry")
        job = self.state["jobs"].get(self.state["active"])
        if not job or job["status"] not in self.uncertain_statuses:
            raise ListenerStateError("No uncertain aggregate needs recovery")
        if action == "published":
            self._finish(job, "published", reconciled=True)
        else:
            self._set_status(job, "pending")
            self._emit("retry_authorized", job)
