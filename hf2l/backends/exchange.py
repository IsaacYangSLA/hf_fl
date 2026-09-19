"""ModelStore bridge to generic Exchange records and versioned blob transfers."""
import fnmatch
import os
from pathlib import Path

from hf2l.backends.base import ModelStore, PublishResult, SubmissionCandidate
from hf2l.exchange.client import ExchangeClient, ExchangeError
from hf2l.hub_helpers import ROUND_FILE, SUBMISSION_FILE, read_json, write_json


class ExchangeStore(ModelStore):
    name = "exchange"

    def __init__(self, token, endpoint, *, client=None, wait_seconds=None):
        self.client = client or ExchangeClient(endpoint, token)
        self.wait_seconds = wait_seconds or int(os.environ.get("EXCHANGE_WAIT_SECONDS", "3600"))
        self.main_refs = {}
        self.claim = None

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
        patterns = [allow_patterns] if isinstance(allow_patterns, str) else allow_patterns
        def wanted(name):
            return patterns is None or any(fnmatch.fnmatch(name, pattern) for pattern in patterns)
        inline = record["metadata"].get("hf2l_files", {})
        if not isinstance(inline, dict) or not all(isinstance(v, dict) for v in inline.values()):
            raise ValueError("Malformed inline HF2L manifests")
        for name, content in inline.items():
            if name not in (ROUND_FILE, SUBMISSION_FILE):
                raise ValueError("Unknown inline HF2L manifest")
            if wanted(name):
                if name == SUBMISSION_FILE and (content.get("participant") != record["participant"] or
                                                content.get("base_revision") != record["base_record_id"]):
                    raise ValueError("Manifest differs from server-bound participant or base")
                write_json(self.client.safe_destination(local_dir, name), content)
        for attachment in record["attachments"]:
            if wanted(attachment["name"]):
                self.client.download_attachment(repo_id, record["id"], attachment,
                                                self.client.safe_destination(local_dir, attachment["name"]))

    def _publish(self, repo_id, folder, paths, kind, base=None, extra=None):
        files, inline = {}, {}
        for name in paths:
            path = self.client.safe_destination(folder, name)
            if name in (ROUND_FILE, SUBMISSION_FILE):
                inline[name] = read_json(path)
            else:
                files[name] = path
        record = self.client.put_record(repo_id, kind=kind, metadata={"hf2l_files": inline, **(extra or {})}, files=files,
                                        base_record_id=base, wait_seconds=self.wait_seconds,
                                        state_path=Path(folder).parent / (Path(folder).name + ".exchange-upload.json"))
        return record["id"]

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

    def claim_submissions(self, repo_id, claim_id=None, lease_seconds=3600):
        self.claim = self.client.request("GET", self.client.path(repo_id, "/claims/" + claim_id)) if claim_id else self.client.request(
            "POST", self.client.path(repo_id, "/claims"), body={"lease_seconds": lease_seconds})
        pinned = self.main_refs.get(repo_id)
        if not pinned or pinned["record_id"] != self.claim["base_record_id"]:
            self.abandon_claim(repo_id)
            raise ValueError("Claim base no longer matches the pinned main revision")
        print(f"exchange_claim_id={self.claim['id']} fence={self.claim['fence']}")
        for superseded in self.claim.get("superseded", []):
            print(f"skipped_submission={superseded}: superseded by a newer update from the same participant")
        return self.explicit_submissions(repo_id, self.claim["inputs"])

    def abandon_claim(self, repo_id):
        if not self.claim:
            return
        claim, self.claim = self.claim, None
        try:
            self.client.request("POST", self.client.path(repo_id, "/claims/" + claim["id"] + ":abandon"), body={"fence": claim["fence"]})
        except ExchangeError as exc:
            if exc.code not in ("claim_not_found", "claim_held_by_other", "claim_fence_changed"):
                raise

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
            self.claim = None
        else:
            self.client.set_ref(repo_id, "main", revision, generation=pinned["generation"], idempotency_key="aggregate-" + revision)
        if tag:
            self.client.set_ref(repo_id, tag, revision, idempotency_key="tag-" + revision)
        return PublishResult(revision, resolved_revision=revision)
