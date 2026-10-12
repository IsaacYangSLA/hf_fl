"""Authoritative, fenced publication observations without loading model artifacts."""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
from .executor import ExecutionIdentity
from sqlalchemy import select

from .collection import SafeCollector, CollectionError
from .domain import JobSpec
from .reconciliation import PublicationObservation
from .workflow import publication_intent_fingerprint, PublicationResolution


class PublicationEvidenceError(ValueError):
    pass


def _value(item, name, default=None):
    return item.get(name, default) if isinstance(item, Mapping) else getattr(item, name, default)


def _json(collector, path):
    try:
        data = collector.read(path, max_bytes=1024 * 1024)
    except CollectionError as exc:
        if isinstance(exc.__cause__, FileNotFoundError):
            return None
        raise
    if data is None:
        return None
    value = json.loads(data.decode("utf-8"))
    if not isinstance(value, dict):
        raise PublicationEvidenceError("Publication evidence must be a bounded object")
    return value


class _RemoteState:
    """Read only bounded relative evidence through an approved node adapter."""
    def __init__(self, reader, identity):
        self.reader, self.identity = reader, identity
        self.reads, self.total = 0, 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, path, *, max_bytes=1024 * 1024):
        if (not isinstance(path, str) or not path or path.startswith("/") or
                "\\" in path or len(path) > 4096 or
                any(part in {"", ".", ".."} for part in path.split("/")) or
                any(ord(char) < 32 or ord(char) == 127 for char in path)):
            raise PublicationEvidenceError("Remote evidence path is not a bounded relative file")
        if type(max_bytes) is not int or not 0 < max_bytes <= 1024 * 1024:
            raise PublicationEvidenceError("Remote evidence read exceeds the JSON bound")
        self.reads += 1
        if self.reads > 32:
            raise PublicationEvidenceError("Remote evidence inspection exceeds its operation bound")
        try:
            data = self.reader(self.identity, path, max_bytes=max_bytes)
        except FileNotFoundError:
            return None
        if data is None:
            return None
        if not isinstance(data, bytes) or len(data) > max_bytes:
            raise PublicationEvidenceError("Approved node returned oversized or invalid evidence")
        self.total += len(data)
        if self.total > 16 * 1024 * 1024:
            raise PublicationEvidenceError("Remote evidence exceeds its aggregate byte bound")
        return data


class AuthoritativePublicationObserver:
    """Compare stopped component intent IDs/hashes to current Exchange records.

    state_roots is a trusted node adapter and MUST return only confirmed-stopped
    execution roots. A callback, process exit or user-selected outcome is not
    proof of publication/nonpublication.
    """
    def __init__(self, database, exchange, state_roots=None, principal=None, *, max_ancestry=1024,
                 state_reader=None, external_state_reader=None):
        self.database, self.exchange = database, exchange
        self.state_roots, self.principal = state_roots, principal
        if not callable(principal) or (not callable(state_roots) and not callable(state_reader)):
            raise ValueError("A trusted state adapter and workload principal resolver are required")
        self.state_reader = state_reader
        self.external_state_reader = external_state_reader
        self.max_ancestry = max_ancestry

    def _barrier(self, job_id, attempt_id):
        from .models import Attempt, Allocation, ProvisioningOperation, ProvisioningResource, Job
        with self.database.transaction(immediate=False) as session:
            attempt = session.get(Attempt, attempt_id)
            if attempt is None or attempt.job_id != job_id or not attempt.revocation_confirmed:
                raise PublicationEvidenceError("Grant revocation is not durably confirmed")
            allocations = list(session.scalars(select(Allocation).where(Allocation.attempt_id == attempt_id)))
            if any(not allocation.termination_confirmed for allocation in allocations):
                raise PublicationEvidenceError("Execution termination is not durably confirmed")
            operations = list(session.scalars(select(ProvisioningOperation).where(ProvisioningOperation.attempt_id == attempt_id)))
            started = {row.component_id for row in operations if row.operation == "start" and row.state != "refused"}
            revokes = [row.id for row in operations if row.operation == "revoke" and row.state in {"confirmed", "ready", "done"}]
            stops = {row.component_id: row.id for row in operations if row.operation == "stop" and row.state in {"confirmed", "ready", "done"}}
            from types import SimpleNamespace
            from .resources import stable_key
            job = session.get(Job, job_id)
            spec = JobSpec.model_validate(job.spec_json)
            external = []
            executions = list(session.scalars(select(ProvisioningResource).where(
                ProvisioningResource.job_id == job_id, ProvisioningResource.attempt_id == attempt_id,
                ProvisioningResource.kind == "external_execution", ProvisioningResource.state != "deleted")))
            seen = set()
            for row in executions:
                details = row.details_json or {}
                participant = next((item for item in spec.participants if item.participant_id == details.get("participant_id")), None)
                expected = "participant-" + stable_key(details.get("participant_id"))[:40]
                if (participant is None or participant.mode != "external" or row.component_id != expected or
                        details.get("dataset_binding") != participant.dataset_binding or
                        row.component_id in seen or type(details.get("epoch")) is not int or details.get("epoch") != attempt.epoch or
                        details.get("spec_digest") != job.spec_hash or
                        any(row.ownership_json.get(key) != expected_value for key, expected_value in
                            {"job_id": job_id, "attempt_id": attempt_id, "component_id": row.component_id}.items())):
                    raise PublicationEvidenceError("External publication identity differs from the immutable job")
                seen.add(row.component_id)
                stop_id = details.get("termination_operation_id")
                if details.get("termination_confirmed") is not True or not isinstance(stop_id, str) or not stop_id:
                    raise PublicationEvidenceError("External execution has no exact confirmed termination receipt")
                never_started = details.get("stop_receipt", {}).get("never_started") is True
                receipt = details.get("stop_receipt", {})
                if never_started and any(receipt.get(key) != expected_value for key, expected_value in
                    {"job_id": job_id, "attempt_id": attempt_id, "component_id": row.component_id,
                     "epoch": attempt.epoch, "termination_operation_id": stop_id}.items()):
                    raise PublicationEvidenceError("External absence proof belongs to another execution")
                if not never_started:
                    started.add(row.component_id)
                    stops[row.component_id] = stop_id
                    external.append(SimpleNamespace(component_id=row.component_id, role="participant",
                                                    participant_id=participant.participant_id))
            return attempt.epoch, started, revokes[0] if revokes else None, stops, external

    def _main(self, space):
        try:
            reference = self.exchange.request("GET", self.exchange.path(space, "/refs/main"))
        except Exception as exc:
            if getattr(exc, "code", None) == "reference_not_found":
                return None, 0
            raise
        record = self.exchange.get_record(space, reference["record_id"])
        round_document = self._inline(record, "fedavg_round.json")
        number = round_document.get("round")
        if type(number) is not int or number < 0 or _value(record, "kind") != "model.global" or _value(record, "state") != "published":
            raise PublicationEvidenceError("Main does not name a valid published global model")
        return record, number

    @staticmethod
    def _inline(record, name):
        metadata = _value(record, "metadata", {})
        files = metadata.get("hf2l_files", {})
        document = files.get(name, {}) if isinstance(files, Mapping) else {}
        if not isinstance(document, Mapping):
            raise PublicationEvidenceError("Malformed inline publication metadata")
        return document

    def _in_chain(self, space, record_id, main):
        current = main
        for _ in range(self.max_ancestry):
            if current is None:
                return False
            if _value(current, "id") == record_id:
                return True
            parent = _value(current, "metadata", {}).get("base_record_id")
            if parent is None:
                parent = self._inline(current, "fedavg_round.json").get("base_revision")
            if not isinstance(parent, str) or not parent:
                return False
            previous = self.exchange.get_record(space, parent)
            if _value(previous, "kind") != "model.global" or _value(previous, "state") != "published":
                raise PublicationEvidenceError("Global publication ancestry is malformed")
            if self._inline(previous, "fedavg_round.json").get("round") != self._inline(current, "fedavg_round.json").get("round") - 1:
                raise PublicationEvidenceError("Global publication ancestry changes round sequence")
            current = previous
        raise PublicationEvidenceError("Publication ancestry exceeds its inspection bound")

    def _record_proof(self, job_id, space, component, intent, upload, role, main, manifest, manifest_sha):
        record_id = upload.get("record_id") if upload else None
        if not isinstance(record_id, str) or not record_id:
            raise PublicationEvidenceError("Lost record creation requires an immutable server receipt")
        try:
            record = self.exchange.get_record(space, record_id)
        except Exception:
            # 404 can mean purged/invisible; a missing record is not proof of absence.
            raise PublicationEvidenceError("Saved publication record cannot be inspected") from None
        if _value(record, "space_id") != space or _value(record, "creator") != self.principal(job_id, component.component_id, component.participant_id):
            raise PublicationEvidenceError("Publication receipt belongs to another space or principal")
        expected_kind = "training.update" if role == "client" else "model.global"
        if _value(record, "kind") != expected_kind:
            raise PublicationEvidenceError("Publication kind differs from the durable intent")
        expected_hashes = intent.get("checkpoint_files_sha256", {}) if role != "owner" else manifest.get("checkpoint_files_sha256", {})
        if not isinstance(expected_hashes, dict):
            raise PublicationEvidenceError("Malformed publication hash intent")
        attachments = {_value(item, "path"): _value(item, "sha256") for item in _value(record, "attachments", ())}
        if any(attachments.get(name) != digest for name, digest in expected_hashes.items()):
            raise PublicationEvidenceError("Publication bytes differ from the retained checkpoint hashes")
        manifest_hash = intent.get("manifest_sha256") if role == "init" else intent.get("publication_intent", {}).get("manifest_sha256") if role == "owner" else None
        if manifest_hash and manifest_sha != manifest_hash:
            raise PublicationEvidenceError("Retained round manifest differs from its persisted intent")
        inline_name = "fedavg_submission.json" if role == "client" else "fedavg_round.json"
        published_manifest = self._inline(record, inline_name)
        if published_manifest.get("complete_manifest") == "fedavg_round-full.json":
            if attachments.get("fedavg_round-full.json") != manifest_sha:
                raise PublicationEvidenceError("Published full manifest differs from the retained bytes")
        elif json.dumps(published_manifest, sort_keys=True, separators=(",", ":")) != json.dumps(manifest, sort_keys=True, separators=(",", ":")):
            raise PublicationEvidenceError("Published inline manifest differs from the retained intent")
        if role == "owner":
            target = intent["publication_intent"]["target_round"]
            if self._inline(record, "fedavg_round.json").get("round") != target:
                raise PublicationEvidenceError("Published owner round differs from the scheduled target")
        if role == "client":
            if _value(record, "creator_bindings", {}).get("participant") != component.participant_id:
                raise PublicationEvidenceError("Submission participant binding differs from the immutable job")
            metadata = _value(record, "metadata", {})
            if metadata.get("base_record_id") != intent.get("base_revision"):
                raise PublicationEvidenceError("Submission base differs from the saved publication")
        state = _value(record, "state")
        if state == "published":
            if role != "client" and not self._in_chain(space, record_id, main):
                # Artifact publication and the main-reference commit are separate.
                # Old writes are fenced; a retained immutable orphan can be used
                # for the exact same reference/acquisition retry without reaggregation.
                if role == "init" and main is not None:
                    raise PublicationEvidenceError("Initial publication conflicts with an existing main")
                return "absent", record_id
            return "confirmed", record_id
        if state in {"cancelled", "failed", "withdrawn", "expired", "draft"}:
            # All execution grants are revoked and processes are stopped. This
            # exact immutable draft cannot become published by the old attempt.
            return "absent", record_id
        raise PublicationEvidenceError("Publication server state is unresolved")

    def __call__(self, job, attempt, space) -> PublicationObservation:
        job_id, attempt_id = _value(job, "id"), _value(attempt, "id")
        try:
            epoch, started, revoke_operation, stop_operations, external = self._barrier(job_id, attempt_id)
            if not started:
                return PublicationObservation(True, "absent", 0 if space is None else self._main(space)[1],
                                              {"source": "durable_never_started_operations"})
            if space is None:
                raise PublicationEvidenceError("A started workload has no owned Exchange space")
            main, current_round = self._main(space)
            spec = JobSpec.model_validate(_value(job, "spec_json"))
            roots = self.state_roots(job, attempt) if self.state_roots is not None else {}
            directives, observed_ids, explicit_proofs = {}, [], []
            from .models import Attempt
            with self.database.transaction(immediate=False) as session:
                requested = (session.get(Attempt, attempt_id).details_json or {}).get("reconciliation_evidence")
            for component in (*spec.components, *external):
                if component.component_id not in started or component.role == "build":
                    continue
                root = roots.get(component.component_id)
                if root is not None:
                    reader = SafeCollector(root, max_files=10000, max_entries=50000, max_file_bytes=256 * 1024**2,
                                           max_total_bytes=4 * 1024**3)
                elif component in external and self.external_state_reader is not None:
                    reader = _RemoteState(self.external_state_reader, ExecutionIdentity(job_id, attempt_id, component.component_id, epoch))
                elif component not in external and self.state_reader is not None:
                    reader = _RemoteState(self.state_reader, ExecutionIdentity(job_id, attempt_id, component.component_id, epoch))
                else:
                    raise PublicationEvidenceError("Stopped execution has no retained publication state")
                with reader as collector:
                    progress = _json(collector, "progress.json")
                    if progress is None or progress.get("job_id") != job_id or progress.get("component_id") != component.component_id:
                        raise PublicationEvidenceError("Worker state has no matching durable identity")
                    initial = _json(collector, "initialization.json") if component.role == "owner" else None
                    listener = _json(collector, "listener/state.json")
                    pending = []
                    if initial and initial.get("phase") in {"publishing", "uncertain"}:
                        pending.append(("init", initial, "initial-model.exchange-upload.json", "initial-model/fedavg_round.json"))
                    if listener:
                        active_key = listener.get("active")
                        active = listener.get("jobs", {}).get(active_key) if active_key else None
                        if active and active.get("status") in {"publishing", "uncertain"}:
                            revision = active.get("revision")
                            if not isinstance(revision, str):
                                raise PublicationEvidenceError("Malformed listener publication input")
                            directory = "listener/jobs/" + hashlib.sha256(revision.encode()).hexdigest()
                            if component.role == "owner":
                                aggregate = active.get("publication_intent", {}).get("aggregate_dir")
                                # Worker absolute paths are interpreted only under its fixed state mount.
                                if not isinstance(aggregate, str) or not aggregate.startswith("/job/state/"):
                                    raise PublicationEvidenceError("Owner intent does not use its assigned state root")
                                relative = aggregate.removeprefix("/job/state/")
                                pending.append(("owner", active, str(Path(relative).parent / (Path(relative).name + ".exchange-upload.json")), relative + "/fedavg_round.json"))
                            else:
                                intent = _json(collector, directory + "/work/client-publication-intent.json")
                                if intent is None:
                                    raise PublicationEvidenceError("Client publication intent is unavailable")
                                pending.append(("client", intent, directory + "/work/trained_model.exchange-upload.json",
                                                directory + "/work/trained_model/fedavg_submission.json"))
                    elif progress.get("phase") != "completed" and initial is None:
                        raise PublicationEvidenceError("Worker stopped before publication state was established")
                    resolutions = []
                    for role, intent, upload_path, manifest_path in pending:
                        upload = _json(collector, upload_path)
                        manifest_bytes = collector.read(manifest_path, max_bytes=1024 * 1024)
                        if manifest_bytes is None:
                            raise PublicationEvidenceError("Retained publication manifest is unavailable")
                        manifest = json.loads(manifest_bytes)
                        if not isinstance(manifest, dict):
                            raise PublicationEvidenceError("Publication manifest must be a bounded object")
                        action, record_id = self._record_proof(job_id, space, component, intent, upload, role, main,
                                                              manifest, hashlib.sha256(manifest_bytes).hexdigest())
                        if not revoke_operation or not stop_operations.get(component.component_id):
                            raise PublicationEvidenceError("Exact revocation/termination receipts are missing")
                        acquisition_id = None
                        if role == "owner":
                            claim_state = _json(collector, directory + "/claim-state.json")
                            acquisition_id = claim_state.get("claim_id") if claim_state else None
                            if acquisition_id:
                                acquisition = self.exchange.get_acquisition(space, acquisition_id)
                                if action == "confirmed" and (_value(acquisition, "state") != "completed" or
                                        _value(acquisition, "result_record_id") != record_id):
                                    raise PublicationEvidenceError("Owner acquisition did not confirm this exact publication")
                                if action == "absent" and _value(acquisition, "state") == "completed":
                                    raise PublicationEvidenceError("Completed acquisition cannot prove nonpublication")
                        proof = PublicationResolution(role=role, action=action, intent_sha256=publication_intent_fingerprint(role, intent),
                            old_attempt_id=attempt_id, old_epoch=epoch, revocation_operation_id=revoke_operation,
                            termination_operation_id=stop_operations[component.component_id], grants_revoked=True,
                            termination_confirmed=True, record_id=record_id, acquisition_id=acquisition_id)
                        resolutions.append(proof.model_dump(mode="json"))
                        observed_ids.append(record_id)
                        explicit_proofs.append({"ids": {record_id, upload.get("key"), proof.intent_sha256},
                            "outcome": "published" if action == "confirmed" else "not_published",
                            "references": {record_id, "exchange:" + space + ":" + record_id,
                                           "sha256:" + proof.intent_sha256}})
                    if resolutions:
                        directives[component.component_id] = resolutions
            if requested and not any(requested.get("publication_id") in proof["ids"] and
                                     requested.get("outcome") == proof["outcome"] and
                                     requested.get("evidence_ref") in proof["references"] for proof in explicit_proofs):
                raise PublicationEvidenceError("Requested proof does not match a fenced immutable publication")
            from .models import Attempt
            with self.database.transaction() as session:
                stored = session.get(Attempt, attempt_id)
                stored.details_json = {**stored.details_json, "reconciliation_directives": directives}
            return PublicationObservation(True, "confirmed" if main is not None else "absent", current_round,
                {"source": "exchange_records_and_fenced_durable_intents", "record_ids": observed_ids, "directives": directives})
        except Exception as exc:
            return PublicationObservation(False, "unknown", None, {"reason": type(exc).__name__})
