"""Poll published references and run one recoverable client job at a time.

Provider notifications can eventually wake this controller, but readiness is
always established by resolving and validating the published model reference.
Publication has no portable idempotency contract: an interrupted attempt must
be reconciled explicitly before another upload is permitted.
"""

from __future__ import annotations

import json
import tempfile
import time  # Compatibility for callers patching this module's polling clock.
from pathlib import Path

from hf2l.common.fs import read_json, write_json
from hf2l.core.ports import ModelStore
from hf2l.core.protocol import CLIENT_CONTEXT_FILE, ROUND_FILE, ClientContext, RoundRecord
from hf2l.listener.engine import DurableListener, ListenerStateError, UncertainOperation, _digest, _text
from hf2l.listener.workflow import download_round, submit_round, train_round, validate_submission


class UncertainSubmission(UncertainOperation):
    """A submission may exist remotely; automatic replay would risk duplicates."""


class ClientListener(DurableListener):
    """One participant and reference, with durable local progress and a lock.

Use as a context manager. The caller owns the store and must close it. State is
bound to the effective provider endpoint and training configuration by hashes;
credentials and plugin options are never copied into the state document.
"""

    statuses = {"pending", "downloading", "training", "ready", "publishing",
                "uncertain", "submitted", "skipped"}
    terminal_statuses = {"submitted", "skipped"}
    success_status = "submitted"

    def __init__(self, store: ModelStore, *, repo_id: str, participant: str,
                 state_dir: Path, source_id: str, training_id: str, train_model,
                 options: dict | None = None, reference: str = "main", on_event=None):
        self.store = store
        self.repo_id = _text(repo_id, "repo_id")
        self.participant = _text(participant, "participant")
        self.reference = _text(reference, "reference")
        if not isinstance(source_id, str) or not source_id or not isinstance(training_id, str) or not training_id:
            raise ListenerStateError("source_id and training_id are required")
        if not callable(train_model):
            raise ListenerStateError("train_model must be callable")
        self.train_model = train_model
        self.options = json.loads(json.dumps({} if options is None else options, allow_nan=False))
        if not isinstance(self.options, dict):
            raise ListenerStateError("Training options must be a JSON object")
        # Preserve the original schema-one identity exactly: existing clients
        # must reopen their state without a migration or duplicate submission.
        identity = {"backend": store.name, "repo_id": repo_id, "participant": participant,
                    "reference": reference, "source_hash": _digest(source_id),
                    "training_hash": _digest(json.dumps(
                        {"trainer": training_id, "options": self.options},
                        sort_keys=True, separators=(",", ":"), allow_nan=False))}
        super().__init__(state_dir=state_dir, identity=identity, on_event=on_event)

    def _current_revision(self):
        revision = self.store.resolve_reference(self.repo_id, self.reference).revision
        return _text(revision, "resolved revision")

    def _round_metadata(self, revision):
        # Fetch only small metadata until a new round warrants a large transfer.
        with tempfile.TemporaryDirectory(prefix=".probe-", dir=self.root) as temporary:
            destination = Path(temporary)
            self.store.download_snapshot(self.repo_id, revision, destination, allow_patterns=ROUND_FILE)
            document = RoundRecord.from_dict(read_json(destination / ROUND_FILE))
        if document.schema_version >= 2 and document.to_dict().get("backend") != self.store.name:
            raise ValueError("Published round declares a different backend")
        return document.round

    def _is_current(self, job):
        if self._current_revision() == job["revision"]:
            return True
        self._finish(job, "skipped", reason="reference_advanced")
        return False

    def _check_context(self, job, work_dir):
        """A resumed job must not silently use another round's local context."""
        try:
            context = ClientContext.from_dict(read_json(self._safe(work_dir / CLIENT_CONTEXT_FILE)))
        except ValueError as exc:
            raise ListenerStateError("Saved listener context is invalid; preserve the job for recovery") from exc
        expected = (self.store.name, self.repo_id, job["revision"], job["source_round"], "base_model")
        actual = (context.backend, context.repo_id, context.base_revision,
                  context.source_round, context.base_model_dir)
        if actual != expected:
            raise ListenerStateError("Saved client context does not match the scheduled listener job")

    def poll_once(self) -> str:
        """Reconcile current state and submit at most one newly eligible round."""
        self._require_open()
        active = self.state["active"]
        job = self.state["jobs"].get(active)
        if job and job["status"] in {"publishing", "uncertain"}:
            raise UncertainSubmission("Submission outcome is unknown; reconcile it and use --resolve-uncertain submitted or retry")
        revision = self._current_revision()
        if job and job["revision"] != revision:
            self._finish(job, "skipped", reason="reference_advanced")
            job = None
        if job is None:
            if revision in self.state["jobs"]:
                self._emit("idle")
                return "idle"
            source_round = self._round_metadata(revision)
            job = {"revision": revision, "source_round": source_round, "status": "pending"}
            self.state["jobs"][revision] = job
            self.state["active"] = revision
            self._save()
            if source_round <= self.state["completed_round"]:
                self._finish(job, "skipped", reason="round_already_completed")
                return "skipped"

        job_dir = self._job_dir(job)
        work_dir = self._safe(job_dir / "work")
        if job["status"] in {"pending", "downloading"}:
            self._set_status(job, "downloading")
            self._remove_owned(work_dir)
            context = download_round(self.store, self.repo_id, revision, work_dir)
            if context["source_round"] != job["source_round"]:
                raise ValueError("Pinned round metadata changed during download")
            if not self._is_current(job):
                return "skipped"
            self._set_status(job, "training")

        if job["status"] == "training":
            if not self._is_current(job):
                return "skipped"
            self._check_context(job, work_dir)
            self._remove_owned(work_dir / "trained_model")
            self._emit("training", job)
            metadata = train_round(self.train_model, self.options, self.participant, work_dir)
            write_json(self._safe(job_dir / "training-result.json"), metadata)
            self._set_status(job, "ready")

        if not self._is_current(job):
            return "skipped"
        self._check_context(job, work_dir)
        metadata = read_json(self._safe(job_dir / "training-result.json"))
        validate_submission(work_dir, self.participant, metadata)
        # Persist BEFORE calling any remote write. Even process termination or
        # an exception after a successful write leaves a visible recovery fence.
        self._set_status(job, "publishing")
        self._emit("publishing", job)
        try:
            result = submit_round(self.store, work_dir, self.participant, metadata)
        except Exception as exc:
            self._set_status(job, "uncertain")
            self._emit("uncertain", job, error_type=type(exc).__name__)
            raise UncertainSubmission("Submission outcome is unknown; inspect the remote submission before explicit recovery") from exc
        self._finish(job, "submitted", result=result)
        return "submitted"

    def resolve_uncertain(self, action: str) -> None:
        """Record the operator's remote reconciliation, without guessing it."""
        self._require_open()
        if action not in {"submitted", "retry"}:
            raise ListenerStateError("Recovery action must be submitted or retry")
        active = self.state["active"]
        job = self.state["jobs"].get(active)
        if not job or job["status"] not in {"publishing", "uncertain"}:
            raise ListenerStateError("No uncertain submission needs recovery")
        if action == "submitted":
            self._finish(job, "submitted", reconciled=True)
        else:
            self._set_status(job, "ready")
            self._emit("retry_authorized", job)
