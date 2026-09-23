"""FedAvg application adapter for the optional fedavg.v1 Exchange profile."""
from __future__ import annotations

import fnmatch
import json
import os
import re
import tempfile
from functools import wraps
from pathlib import Path

from hf2l.core.ports import (BackendCapabilities, ClaimHandle, ModelStore, PublicationConsistency,
                                  PublicationUncertain, PublishResult, RevisionNotFound, ResolvedReference, RoundContext,
                                  SubmissionCandidate)
from hf2l_exchange.client import ExchangeClient, ExchangeError
from hf2l_exchange.client_types import ReferenceSnapshot
from hf2l.common.fs import checked_file_paths, read_json, write_json
from hf2l.core.protocol import ROUND_FILE, SUBMISSION_FILE

INLINE_FILES_KEY = "hf2l_files"
INLINE_MANIFEST_NAMES = (ROUND_FILE, SUBMISSION_FILE)
INLINE_METADATA_BUDGET = 65536 * 3 // 4
ROUND_FULL_FILE = "fedavg_round-full.json"
SUMMARY_LEVELS = (("participant", "resolved_revision", "num_examples", "coefficient"),
                  ("participant", "num_examples", "coefficient"))


def metadata_size(value):
    return len(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


def names_collide(left, right):
    left, right = left.casefold(), right.casefold()
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def scalars(mapping, limit):
    """The scalar entries of ``mapping``, taken in key order while their serialized size stays within ``limit``."""
    kept, used = {}, 2
    for key in sorted(mapping):
        value = mapping[key]
        if isinstance(value, (dict, list)):
            continue
        cost = metadata_size({key: value})
        if used + cost > limit:
            break
        kept[key] = value
        used += cost
    return kept


def bounded_round(full, budget):
    """Shrink a round manifest to at most ``budget`` serialized bytes for inline storage.

    Every top-level field survives and ``submission_count`` is added. Submissions keep the fullest summary that fits:
    identity, weight and as many scalar training values as an equal share of the remaining budget allows; then the
    same without revision and training; then only a ``participants`` name list; past that only the count.
    Evaluation keeps scalar values only. ``complete_manifest`` names the attachment holding the unabridged manifest.
    """
    items = full.get("submissions", [])
    bounded = {key: value for key, value in full.items() if key != "submissions"}
    bounded.update(evaluation=None, complete_manifest=ROUND_FULL_FILE, submission_count=len(items))
    if isinstance(full.get("evaluation"), dict):
        bounded["evaluation"] = scalars(full["evaluation"], budget // 8)
    for level, fields in enumerate(SUMMARY_LEVELS):
        summaries = [{key: item.get(key) for key in fields} for item in items]
        if level == 0:
            for entry in summaries:
                entry["training"] = {}
        candidate = {**bounded, "submissions": summaries}
        remaining = budget - metadata_size(candidate)
        if remaining < 0:
            continue
        if level == 0:
            share = remaining // max(1, len(items))
            for entry, item in zip(summaries, items):
                if isinstance(item.get("training"), dict):
                    entry["training"] = scalars(item["training"], share)
        return candidate
    candidate = {**bounded, "participants": [item.get("participant") for item in items]}
    return candidate if metadata_size(candidate) <= budget else bounded


def _revision_read(method):
    """Normalize an absent object without hiding permission failures or outages."""
    @wraps(method)
    def call(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except Exception as exc:
            status = getattr(exc, "status", None) or getattr(getattr(exc, "response", None), "status_code", None)
            if status == 404:
                raise RevisionNotFound("The selected revision or snapshot is unavailable") from exc
            raise
    return call


class ExchangeStore(ModelStore):
    name = "exchange"
    capabilities = BackendCapabilities(PublicationConsistency.ATOMIC, fenced_coordination=True,
        requires_coordination_for_publication=True, binds_participants=True)

    def __init__(self, token, endpoint, *, client=None, wait_seconds=None):
        self._owns_client = client is None
        self._closed = False
        self.client = client or ExchangeClient(
            endpoint, token,
            allow_local_http=os.environ.get("EXCHANGE_ALLOW_LOCAL_HTTP", "").lower() in ("true", "1"),
        )
        self.wait_seconds = wait_seconds or int(os.environ.get("EXCHANGE_WAIT_SECONDS", "3600"))

    def close(self):
        if not self._closed:
            self._closed = True
            if self._owns_client:
                self.client.close()

    @staticmethod
    def _snapshot(reference, name="main"):
        if reference.token is None:
            raise ValueError("Exchange publication requires the observed reference token")
        return ReferenceSnapshot(name, reference.revision, reference.token)

    def _require_profile(self, repo_id):
        if self.client.get_space(repo_id).profile != "fedavg.v1":
            raise ValueError("The Exchange model adapter requires a space with profile fedavg.v1")

    def resolve_reference(self, repo_id, name="main"):
        value = self.client.resolve(repo_id, name)
        return ResolvedReference(value.record_id, token=value.token)

    @_revision_read
    def resolve_revision(self, repo_id, revision):
        if re.fullmatch(r"[a-f0-9]{32}", revision):
            return self.client.get_record(repo_id, revision).id
        return self.client.resolve(repo_id, revision).record_id

    @_revision_read
    def download_snapshot(self, repo_id, revision, local_dir, *, allow_patterns=None):
        record = self.client.get_record(repo_id, revision)
        if record.state != "published":
            raise ValueError("Only published records can be downloaded")
        inline = self._inline_manifests(record.to_dict())
        self._check_layout(record.to_dict(), inline)
        patterns = [allow_patterns] if isinstance(allow_patterns, str) else allow_patterns
        def wanted(name):
            return patterns is None or any(fnmatch.fnmatch(name, pattern) for pattern in patterns)
        for name, content in inline.items():
            if wanted(name):
                if name == SUBMISSION_FILE and (
                    content.get("participant") != record.creator_bindings.get("participant") or
                    content.get("base_revision") != record.metadata.get("base_record_id") or
                    content.get("num_examples") != record.metadata.get("sample_count")
                ):
                    raise ValueError("Manifest differs from server-bound participant, base, or sample count")
                write_json(self.client.safe_destination(local_dir, name), content)
        if patterns is not None and set(patterns) <= set(INLINE_MANIFEST_NAMES):
            return
        for attachment in record.attachments:
            if wanted(attachment.path):
                destination = self.client.safe_destination(local_dir, attachment.path)
                self.client.download_attachment(repo_id, record.id, attachment, destination)

    @staticmethod
    def _inline_manifests(record):
        inline = record["metadata"].get(INLINE_FILES_KEY, {})
        if not isinstance(inline, dict) or not all(isinstance(v, dict) for v in inline.values()):
            raise ValueError("Malformed inline HF2L manifests")
        if any(name not in INLINE_MANIFEST_NAMES for name in inline):
            raise ValueError("Unknown inline HF2L manifest")
        return inline

    @staticmethod
    def _check_layout(record, inline):
        names = [attachment.get("path", attachment.get("name")) for attachment in record["attachments"]]
        reserved = set(INLINE_MANIFEST_NAMES) | set(inline)
        for index, name in enumerate(names):
            if any(names_collide(name, other) for other in reserved):
                raise ValueError(f"Attachment {name!r} shadows an inline manifest in record {record['id']}")
            if any(names_collide(name, other) for other in names[index + 1:]):
                raise ValueError(f"Attachment {name!r} collides with another attachment in record {record['id']}")

    def _publish(self, repo_id, folder, paths, kind, base=None, extra=None):
        self._require_profile(repo_id)
        files, inline, extra, complete = {}, {}, dict(extra or {}), None
        for name in checked_file_paths(folder, paths):
            path = self.client.safe_destination(folder, name)
            if name in INLINE_MANIFEST_NAMES:
                inline[name] = read_json(path)
            elif name == ROUND_FULL_FILE:
                complete = read_json(path)
            elif any(names_collide(name, reserved) for reserved in (*INLINE_MANIFEST_NAMES, ROUND_FULL_FILE)):
                raise ValueError(f"Attachment name {name!r} is reserved for HF2L manifests")
            else:
                files[name] = path
        if ROUND_FILE in inline and inline[ROUND_FILE].get("complete_manifest") == ROUND_FULL_FILE:
            if complete is None:
                raise ValueError("The complete round manifest attachment is missing")
            inline[ROUND_FILE] = complete
        if base is not None:
            extra["base_record_id"] = base
        if kind == "training.update":
            extra["sample_count"] = inline[SUBMISSION_FILE]["num_examples"]
        else:
            extra.setdefault("inputs", [])
        # Overflow manifests are generated in adapter-owned staging, never in the input snapshot.
        with tempfile.TemporaryDirectory(prefix="hf2l-exchange-manifest-") as temporary:
            if ROUND_FILE in inline:
                self._bound_round(Path(temporary), files, inline, extra)
            revisions = [value for value in self.client.types(repo_id) if value.kind == kind]
            if not revisions:
                raise ValueError(f"The profile has no registered type for {kind}")
            schema = max(revisions, key=lambda value: value.revision)
            record = self.client.put_record(
                repo_id, kind=kind, schema_revision_id=schema.id,
                metadata={INLINE_FILES_KEY: inline, **extra}, files=files,
                verification_seconds=self.wait_seconds,
                state_path=Path(folder).parent / (Path(folder).name + ".exchange-upload.json"),
            )
            return record.id

    @staticmethod
    def _bound_round(folder, files, inline, extra):
        if metadata_size({INLINE_FILES_KEY: inline, **extra}) <= INLINE_METADATA_BUDGET:
            return
        complete = ExchangeClient.safe_destination(folder, ROUND_FULL_FILE)
        write_json(complete, inline[ROUND_FILE])
        files[ROUND_FULL_FILE] = complete
        budget = INLINE_METADATA_BUDGET - metadata_size({INLINE_FILES_KEY: {**inline, ROUND_FILE: {}}, **extra})
        inline[ROUND_FILE] = bounded_round(inline[ROUND_FILE], budget)
        if metadata_size({INLINE_FILES_KEY: inline, **extra}) > INLINE_METADATA_BUDGET:
            raise ValueError("Round metadata exceeds the inline budget after bounding its manifest")

    def initialize_repository(self, repo_id, folder, *, private):
        paths = checked_file_paths(folder)
        revision = self._publish(repo_id, folder, paths, "model.global")
        self.client.set_ref(repo_id, "main", revision, idempotency_key="initialize-" + revision)
        return PublishResult(revision, resolved_revision=revision)

    def publish_submission(self, repo_id, folder, paths, *, participant, source_round, base_revision, submission_revision):
        if self.client.get_membership(repo_id).bindings.get("participant") != participant:
            raise ValueError("Participant must match the authenticated membership")
        revision = self._publish(repo_id, folder, paths, "training.update", base_revision)
        return PublishResult(revision, resolved_revision=revision)

    @staticmethod
    def _candidate(record):
        participant = record.creator_bindings.get("participant")
        if record.state != "published" or record.kind != "training.update" or not participant:
            raise ValueError("Record is not a published participant submission")
        return SubmissionCandidate(record.id, record.id, record.creator, participant)

    def discover_submissions(self, repo_id, *, context: RoundContext | None = None):
        if context is None or context.repo_id != repo_id:
            raise ValueError("Exchange discovery requires the explicit round context")
        newest, skipped, order = {}, [], {}
        for record in self.client.records(repo_id, kind="training.update", state="published"):
            if record.metadata.get("base_record_id") != context.reference.revision:
                continue
            candidate = self._candidate(record)
            rank = (record.published_at or 0, record.id)
            previous = newest.get(candidate.participant)
            if previous and rank <= order[candidate.participant]:
                skipped.append(f"{candidate.identifier}: superseded by {previous.identifier}")
                continue
            if previous:
                skipped.append(f"{previous.identifier}: superseded by {candidate.identifier}")
            newest[candidate.participant] = candidate
            order[candidate.participant] = rank
        return sorted(newest.values(), key=lambda c: c.identifier), skipped

    def explicit_submissions(self, repo_id, values):
        if len(set(values)) != len(values):
            raise ValueError("Duplicate submission selection")
        return [self._candidate(self.client.get_record(repo_id, value)) for value in values]

    @staticmethod
    def _claim(value, reference, reference_name="main"):
        if value.state != "active":
            raise ValueError("The coordination attempt is no longer active")
        if value.reference != reference_name:
            raise ValueError("Claim belongs to a different reference")
        if value.expected_token != reference.token:
            raise ValueError("Claim base no longer matches the explicit reference")
        return ClaimHandle(value.id, value.fence, reference, value.input_ids, value.lease_until, value)

    def claim_submissions(self, repo_id, *, context, acquisition_key, claim_id=None, lease_seconds=3600):
        self._require_profile(repo_id)
        if context.repo_id != repo_id:
            raise ValueError("Round context belongs to a different space")
        value = (self.client.get_acquisition(repo_id, claim_id) if claim_id else
                 self.client.acquire(repo_id, reference=self._snapshot(context.reference, context.reference_name),
                                     input_ids=(), idempotency_key=acquisition_key, lease_seconds=lease_seconds))
        self._claim(value, context.reference, context.reference_name)
        if claim_id:
            # Reading an attempt is not proof of its ownership; renewal verifies it.
            value = self.client.renew(repo_id, value)
        claim = self._claim(value, context.reference, context.reference_name)
        try:
            return claim, self.explicit_submissions(repo_id, claim.input_ids)
        except Exception:
            try:
                self.client.abandon(repo_id, value)
            except Exception:
                pass  # The persisted acquisition key remains available for reconciliation.
            raise

    def renew_claim(self, repo_id, claim, lease_seconds):
        value = self.client.renew(repo_id, claim.provider_handle)
        return self._claim(value, claim.reference)

    def abandon_claim(self, repo_id, claim):
        self.client.abandon(repo_id, claim.provider_handle)

    def publish_aggregate(self, repo_id, folder, paths, *, expected_base, next_round, tag, reference=None, claim=None):
        if claim is None:
            raise ValueError("fedavg.v1 aggregation requires an explicit fenced claim")
        if reference is None or reference.revision != expected_base:
            raise ValueError("Publication requires the explicit observed reference")
        if claim.provider_handle.reference != "main":
            raise ValueError("Aggregate publication requires a claim for main")
        if claim.reference != reference:
            raise ValueError("Claim differs from the publication reference")
        used = [entry["resolved_revision"] for entry in read_json(
            self.client.safe_destination(folder, ROUND_FILE))["submissions"]]
        if claim and (len(set(used)) < 2 or not set(used) <= set(claim.input_ids)):
            raise ValueError("Aggregate must use at least two distinct inputs from the frozen claim")
        revision = self._publish(repo_id, folder, paths, "model.global", expected_base, {"inputs": used})
        try:
            self.client.complete(repo_id, claim.provider_handle, revision, idempotency_key="aggregate-" + revision)
        except ExchangeError as exc:
            if exc.status < 500 and exc.status != 408:
                raise
            raise PublicationUncertain(f"Publication of {revision} requires reconciliation") from exc
        except Exception as exc:
            raise PublicationUncertain(f"Publication of {revision} requires reconciliation") from exc
        warnings, tagged = (), None
        if tag:
            try:
                self.client.set_ref(repo_id, tag, revision, idempotency_key="tag-" + revision)
                tagged = True
            except Exception as exc:
                tagged = False
                warnings = (f"Published {revision}, but tag {tag!r} failed: {exc}",)
        return PublishResult(revision, resolved_revision=revision, warnings=warnings, tag_created=tagged)
