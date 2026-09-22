"""ModelStore bridge to generic Exchange records and versioned blob transfers."""
import fnmatch
import os
from pathlib import Path

from hf2l.backends.base import ModelStore, PublishResult, SubmissionCandidate
from hf2l.exchange.client import ExchangeClient, ExchangeError
from hf2l.exchange.protocol import (INLINE_FILES_KEY, INLINE_MANIFEST_NAMES, METADATA_LIMIT_BYTES, metadata_size,
                                    names_collide)
from hf2l.hub_helpers import ROUND_FILE, SUBMISSION_FILE, read_json, write_json

# Held-claim state written into the coordinator's output directory; removed after publish or abandon.
CLAIM_FILE = "exchange-claim.json"
# GET /claims/{id} outcomes that mean a persisted claim is no longer ours to resume.
STALE_CLAIM_CODES = ("claim_not_active", "claim_not_found", "claim_held_by_other")
# Record metadata size above which the complete round manifest becomes an attachment; headroom under the limit.
INLINE_METADATA_BUDGET = METADATA_LIMIT_BYTES * 3 // 4
# Attachment carrying the complete round manifest whenever the inline copy had to be bounded.
ROUND_FULL_FILE = "fedavg_round-full.json"
# Per-submission fields of the bounded inline round manifest, from the fullest summary to the smallest that may fit.
SUMMARY_LEVELS = (("participant", "resolved_revision", "num_examples", "coefficient"),
                  ("participant", "num_examples", "coefficient"))


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


class ExchangeStore(ModelStore):
    name = "exchange"

    def __init__(self, token, endpoint, *, client=None, wait_seconds=None):
        self.client = client or ExchangeClient(endpoint, token)
        self.wait_seconds = wait_seconds or int(os.environ.get("EXCHANGE_WAIT_SECONDS", "3600"))
        self.main_refs = {}
        self.claim = None
        self.claim_state = None

    def resolve_revision(self, repo_id, revision):
        if revision.startswith("rec_"):
            return self.client.get_record(repo_id, revision)["id"]
        resolved = self.client.resolve(repo_id, revision)
        if revision == "main":
            self.main_refs[repo_id] = resolved
        return resolved["record_id"]

    def download_snapshot(self, repo_id, revision, local_dir, *, allow_patterns=None):
        record = self.client.get_record(repo_id, revision)
        if record["state"] != "ready":
            raise ValueError("Only ready records can be downloaded")
        inline = self._inline_manifests(record)
        self._check_layout(record, inline)
        patterns = [allow_patterns] if isinstance(allow_patterns, str) else allow_patterns
        def wanted(name):
            return patterns is None or any(fnmatch.fnmatch(name, pattern) for pattern in patterns)
        for name, content in inline.items():
            if wanted(name):
                if name == SUBMISSION_FILE and (content.get("participant") != record["participant"] or
                                                content.get("base_revision") != record["base_record_id"]):
                    raise ValueError("Manifest differs from server-bound participant or base")
                write_json(self.client.safe_destination(local_dir, name), content)
        if patterns is not None and set(patterns) <= set(INLINE_MANIFEST_NAMES):
            # A manifest-only read never touches attachments, so none can shadow the checked inline copies.
            return
        for attachment in record["attachments"]:
            if wanted(attachment["name"]):
                destination = self.client.safe_destination(local_dir, attachment["name"])
                try:
                    self.client.download_attachment(repo_id, record["id"], attachment, destination)
                except OSError as exc:
                    raise ValueError(f"Cannot materialise attachment {attachment['name']!r} of record "
                                     f"{record['id']}: {exc}") from exc

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
        """Refuse a record whose attachments would shadow a manifest or collide on disk (accepted before validation)."""
        names = [attachment["name"] for attachment in record["attachments"]]
        reserved = set(INLINE_MANIFEST_NAMES) | set(inline)
        for index, name in enumerate(names):
            if any(names_collide(name, other) for other in reserved):
                raise ValueError(f"Attachment {name!r} shadows an inline manifest in record {record['id']}")
            if any(names_collide(name, other) for other in names[index + 1:]):
                raise ValueError(f"Attachment {name!r} collides with another attachment in record {record['id']}")

    def _publish(self, repo_id, folder, paths, kind, base=None, extra=None):
        files, inline, extra, complete = {}, {}, extra or {}, None
        for name in paths:
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
            # A snapshot of a bounded round record is published from its unabridged manifest, never from the copy.
            if complete is None:
                raise ValueError(f"{ROUND_FILE} names {ROUND_FULL_FILE} as its complete manifest, which is not published")
            inline[ROUND_FILE] = complete
        if ROUND_FILE in inline:
            self._bound_round(folder, files, inline, extra)
        record = self.client.put_record(repo_id, kind=kind, metadata={INLINE_FILES_KEY: inline, **extra}, files=files,
                                        base_record_id=base, wait_seconds=self.wait_seconds,
                                        state_path=Path(folder).parent / (Path(folder).name + ".exchange-upload.json"))
        return record["id"]

    @staticmethod
    def _bound_round(folder, files, inline, extra):
        """Keep the record metadata within the inline budget; the complete round manifest becomes an attachment."""
        if metadata_size({INLINE_FILES_KEY: inline, **extra}) <= INLINE_METADATA_BUDGET:
            return
        complete = ExchangeClient.safe_destination(folder, ROUND_FULL_FILE)
        write_json(complete, inline[ROUND_FILE])
        files[ROUND_FULL_FILE] = complete
        budget = INLINE_METADATA_BUDGET - metadata_size({INLINE_FILES_KEY: {**inline, ROUND_FILE: {}}, **extra})
        inline[ROUND_FILE] = bounded_round(inline[ROUND_FILE], budget)
        size = metadata_size({INLINE_FILES_KEY: inline, **extra})
        if size > INLINE_METADATA_BUDGET:
            # Only top-level fields are left: many checkpoint shards, or a provenance list of over a thousand inputs.
            raise ValueError(f"Record metadata is {size} bytes with {ROUND_FILE} bounded to its top-level fields; "
                             f"the inline budget is {INLINE_METADATA_BUDGET} bytes")

    def initialize_repository(self, repo_id, folder, *, private):
        # Space creation/membership is an explicit administrative operation.
        paths = [p.relative_to(folder).as_posix() for p in Path(folder).rglob("*") if p.is_file()]
        revision = self._publish(repo_id, folder, paths, "model.global")
        self.client.set_ref(repo_id, "main", revision, idempotency_key="initialize-" + revision)
        return PublishResult(revision, resolved_revision=revision)

    def publish_submission(self, repo_id, folder, paths, *, participant, source_round, base_revision, submission_revision):
        me = self.client.request("GET", self.client.path(repo_id, "/me"))
        if me["participant"] != participant:
            raise ValueError("Participant must match the authenticated membership")
        revision = self._publish(repo_id, folder, paths, "training.update", base_revision)
        return PublishResult(revision, resolved_revision=revision)

    def _candidate(self, record):
        if record["state"] != "ready" or record["kind"] != "training.update" or not record["participant"]:
            raise ValueError("Record is not a ready participant submission")
        return SubmissionCandidate(record["id"], record["id"], record["created_by"], record["participant"])

    def discover_submissions(self, repo_id):
        """Newest ready update per participant for the pinned base; superseded records are reported, not fatal."""
        pinned = self.main_refs.get(repo_id)
        if not pinned:
            raise ValueError("Resolve main with this store before discovering submissions")
        newest, skipped = {}, []
        records = self.client.records(repo_id, kind="training.update", state="ready", base_record_id=pinned["record_id"])
        for record in records:
            try:
                candidate = self._candidate(record)
            except ValueError as exc:
                skipped.append(f"{record['id']}: {exc}")
                continue
            previous = newest.get(candidate.participant)
            if previous:
                skipped.append(f"{previous.identifier}: superseded by {candidate.identifier} for participant {candidate.participant!r}")
            newest[candidate.participant] = candidate
        return sorted(newest.values(), key=lambda c: c.identifier), skipped

    def explicit_submissions(self, repo_id, values):
        if len(set(values)) != len(values):
            raise ValueError("Duplicate submission selection")
        return [self._candidate(self.client.get_record(repo_id, value)) for value in values]

    def claim_submissions(self, repo_id, claim_id=None, lease_seconds=3600, state_dir=None):
        """Acquire or resume the fenced claim for the pinned main and return its frozen inputs.

        An explicit ``claim_id`` must name a live claim held by this identity. Otherwise a claim persisted in
        ``state_dir`` by an interrupted run that reuses the directory is resumed while it is still active, and a
        stale file is discarded in favour of a fresh acquisition. ``POST /claims`` returns the holder's own live
        claim, so the owner CLI (whose output directory is always new) recovers through that path.
        """
        self.claim_state = Path(state_dir) / CLAIM_FILE if state_dir else None
        self.claim = self.client.get_claim(repo_id, claim_id) if claim_id else self._resume_claim(repo_id)
        if not self.claim:
            self.claim = self.client.request("POST", self.client.path(repo_id, "/claims"),
                                             body={"lease_seconds": lease_seconds})
        self._remember_claim(repo_id)
        pinned = self.main_refs.get(repo_id)
        if not pinned or pinned["record_id"] != self.claim["base_record_id"]:
            self.abandon_claim(repo_id)
            raise ValueError("Claim base no longer matches the pinned main revision")
        print(f"exchange_claim_id={self.claim['id']} fence={self.claim['fence']}")
        for superseded in self.claim.get("superseded", []):
            print(f"skipped_submission={superseded}: superseded by a newer update from the same participant")
        for skipped in self.claim.get("skipped", []):
            print(f"skipped_submission={skipped}: creator's participant binding changed or membership revoked")
        return self.explicit_submissions(repo_id, self.claim["inputs"])

    def _resume_claim(self, repo_id):
        """Return the claim persisted by an interrupted run while it is still held; drop the file otherwise."""
        if not self.claim_state or not self.claim_state.exists():
            return None
        saved = read_json(self.claim_state)
        if saved.get("space") != repo_id or not saved.get("claim_id"):
            return None
        try:
            return self.client.get_claim(repo_id, saved["claim_id"])
        except ExchangeError as exc:
            if exc.code not in STALE_CLAIM_CODES:
                raise
            self.claim_state.unlink(missing_ok=True)
            return None

    def _remember_claim(self, repo_id):
        """Persist the held claim so a crashed round can be resumed (--claim-id) or abandoned by its ID."""
        if self.claim_state:
            saved = {key: self.claim[key] for key in ("fence", "base_record_id", "lease_until")}
            write_json(self.claim_state, {"space": repo_id, "claim_id": self.claim["id"], **saved})

    def _forget_claim(self):
        """Drop the held claim and its persisted record once the server has released or completed it."""
        self.claim = None
        if self.claim_state:
            self.claim_state.unlink(missing_ok=True)

    def abandon_claim(self, repo_id):
        if not self.claim:
            return
        claim, self.claim = self.claim, None
        try:
            self.client.request("POST", self.client.path(repo_id, "/claims/" + claim["id"] + ":abandon"), body={"fence": claim["fence"]})
        except ExchangeError as exc:
            if exc.code not in ("claim_not_found", "claim_held_by_other", "claim_fence_changed"):
                # The claim may still be held server-side: keep its persisted ID for a manual abandon.
                raise
        self._forget_claim()

    def publish_aggregate(self, repo_id, folder, paths, *, expected_base, next_round, tag):
        pinned = self.main_refs.get(repo_id)
        if not pinned or pinned["record_id"] != expected_base:
            raise ValueError("Resolve main with this store before publishing an aggregate")
        extra = None
        if self.claim:
            # Provenance names exactly the inputs that were aggregated; the server checks they were frozen.
            used = [s["resolved_revision"] for s in read_json(self.client.safe_destination(folder, ROUND_FILE))["submissions"]]
            extra = {"input_record_ids": used}
        revision = self._publish(repo_id, folder, paths, "model.global", expected_base, extra)
        if self.claim:
            self.client.request("POST", self.client.path(repo_id, "/claims/" + self.claim["id"] + ":publish"),
                                body={"record_id": revision, "fence": self.claim["fence"]})
            self._forget_claim()
        else:
            self.client.set_ref(repo_id, "main", revision, generation=pinned["generation"], idempotency_key="aggregate-" + revision)
        if tag:
            self.client.set_ref(repo_id, tag, revision, idempotency_key="tag-" + revision)
        return PublishResult(revision, resolved_revision=revision)
