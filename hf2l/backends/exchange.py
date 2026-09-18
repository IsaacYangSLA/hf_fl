"""ModelStore bridge to generic Exchange records and versioned blob transfers."""
import fnmatch
import json
from pathlib import Path

from hf2l.backends.base import ModelStore, PublishResult, SubmissionCandidate
from hf2l.exchange.client import ExchangeClient
from hf2l.hub_helpers import ROUND_FILE, SUBMISSION_FILE, read_json, write_json


class ExchangeStore(ModelStore):
    name = "exchange"

    def __init__(self, token, endpoint, *, client=None):
        self.client = client or ExchangeClient(endpoint, token)
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
                                        base_record_id=base, state_path=Path(folder).parent / (Path(folder).name + ".exchange-upload.json"))
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
        return [self._candidate(r) for r in self.client.records(repo_id, kind="training.update", state="ready")], []

    def explicit_submissions(self, repo_id, values):
        if len(set(values)) != len(values):
            raise ValueError("Duplicate submission selection")
        return [self._candidate(self.client.get_record(repo_id, value)) for value in values]

    def claim_submissions(self, repo_id, claim_id=None, lease_seconds=3600):
        self.claim = self.client.request("GET", self.client.path(repo_id, "/claims/" + claim_id)) if claim_id else self.client.request(
            "POST", self.client.path(repo_id, "/claims"), body={"lease_seconds": lease_seconds})
        pinned = self.main_refs.get(repo_id)
        if not pinned or pinned["record_id"] != self.claim["base_record_id"]:
            raise ValueError("Claim base no longer matches the pinned main revision")
        print(f"exchange_claim_id={self.claim['id']} fence={self.claim['fence']}")
        return self.explicit_submissions(repo_id, self.claim["inputs"])

    def publish_aggregate(self, repo_id, folder, paths, *, expected_base, next_round, tag):
        pinned = self.main_refs.get(repo_id)
        if not pinned or pinned["record_id"] != expected_base:
            raise ValueError("Resolve main with this store before publishing an aggregate")
        extra = {"input_record_ids": self.claim["inputs"]} if self.claim else None
        revision = self._publish(repo_id, folder, paths, "model.global", expected_base, extra)
        if self.claim:
            self.client.request("POST", self.client.path(repo_id, "/claims/" + self.claim["id"] + ":publish"),
                                body={"record_id": revision, "fence": self.claim["fence"]})
        else:
            self.client.set_ref(repo_id, "main", revision, generation=pinned["generation"], idempotency_key="aggregate-" + revision)
        if tag:
            self.client.set_ref(repo_id, tag, revision, idempotency_key="tag-" + revision)
        return PublishResult(revision, resolved_revision=revision)
