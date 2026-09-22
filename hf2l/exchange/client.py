"""Client SDK for JSON records and resumable direct-to-storage transfers."""
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import time
from urllib.parse import quote, urlparse
import uuid

import httpx

from .protocol import METADATA_LIMIT_BYTES, metadata_size

RETRYABLE_STATUS = (429, 502, 503, 504)


class ExchangeError(RuntimeError):
    def __init__(self, status, code, details=None, message=None):
        # details carries the server's extra error fields, such as the ID of the claim that is busy.
        self.status, self.code, self.details = status, code, dict(details or {})
        super().__init__(message or f"Exchange HTTP {status}: {code}")


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save_state(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as target:
        os.chmod(temporary, 0o600)
        json.dump(value, target, sort_keys=True)
    temporary.replace(path)


class ExchangeClient:
    def __init__(self, endpoint, token, *, http=None, transfer=None, retries=3):
        self.endpoint = endpoint.rstrip("/")
        address = urlparse(self.endpoint)
        if address.scheme != "https" and not (address.scheme == "http" and address.hostname in ("127.0.0.1", "localhost", "testserver")):
            raise ValueError("Exchange endpoint requires HTTPS except on localhost")
        self.token = token
        self.retries = retries
        self.http = http or httpx.Client(timeout=60, follow_redirects=False)
        # A separate client ensures the API bearer token never reaches object storage.
        self.transfer = transfer or httpx.Client(timeout=300, follow_redirects=False)

    def close(self):
        self.http.close()
        self.transfer.close()

    def request(self, method, path, *, body=None, headers=None, params=None):
        # Every control-plane call is idempotent (keys, state machines, CAS), so transient failures are retried.
        for attempt in range(self.retries):
            token = self.token() if callable(self.token) else self.token
            request_headers = {"Authorization": "Bearer " + token, **(headers or {})}
            try:
                response = self.http.request(method, self.endpoint + path, json=body,
                                             headers=request_headers, params=params)
            except httpx.TransportError:
                if attempt + 1 == self.retries:
                    raise ExchangeError(503, "connection_failed") from None
                time.sleep(2 ** attempt)
                continue
            if response.status_code in RETRYABLE_STATUS and attempt + 1 < self.retries:
                time.sleep(2 ** attempt)
                continue
            if response.status_code >= 300:
                try:
                    details = response.json()
                except ValueError:
                    details = {}
                details = details if isinstance(details, dict) else {}
                raise ExchangeError(response.status_code, details.get("code", "request_failed"), details)
            return response.json()

    def path(self, space, suffix=""):
        return "/v1/spaces/" + quote(space, safe="") + suffix

    def create_space(self, name, tenant, *, idempotency_key=None, **options):
        return self.request("POST", "/v1/spaces", body={"name": name, "tenant": tenant, **options},
                            headers={"Idempotency-Key": idempotency_key or uuid.uuid4().hex})

    def get_space(self, space):
        return self.request("GET", self.path(space))

    def update_space(self, space, generation, **changes):
        return self.request("PATCH", self.path(space), body=changes, headers={"If-Match": f'"{generation}"'})

    def set_member(self, space, issuer, subject, roles, participant=None):
        principal = hashlib.sha256(json.dumps([issuer, subject], separators=(",", ":")).encode()).hexdigest()
        return self.request("PUT", self.path(space, "/members/" + principal),
                            body={"subject": subject, "roles": roles, "participant": participant})

    def get_record(self, space, record):
        return self.request("GET", self.path(space, "/records/" + quote(record, safe="")))

    def cancel_record(self, space, record):
        return self.request("DELETE", self.path(space, "/records/" + quote(record, safe="")))

    def records(self, space, **filters):
        cursor = ""
        while True:
            response = self.request("GET", self.path(space, "/records"), params={**filters, "cursor": cursor})
            yield from response["items"]
            cursor = response["next_cursor"]
            if not cursor:
                return

    def resolve(self, space, name="main"):
        return self.request("GET", self.path(space, "/refs/" + quote(name, safe="")))

    def claims(self, space, *, base_record_id=None, workflow=None, active=True):
        """Coordinators and admins list claims, by default only those with an unexpired lease and no result."""
        params = {"active": "true" if active else "false"}
        if base_record_id:
            params["base_record_id"] = base_record_id
        if workflow:
            params["workflow"] = workflow
        return self.request("GET", self.path(space, "/claims"), params=params)["items"]

    def get_claim(self, space, claim_id):
        return self.request("GET", self.path(space, "/claims/" + quote(claim_id, safe="")))

    def set_ref(self, space, name, record, *, generation=None, idempotency_key=None):
        headers = {"Idempotency-Key": idempotency_key or uuid.uuid4().hex}
        headers["If-Match" if generation is not None else "If-None-Match"] = f'"{generation}"' if generation is not None else "*"
        return self.request("PUT", self.path(space, "/refs/" + quote(name, safe="")),
                            body={"record_id": record}, headers=headers)

    def put_record(self, space, *, kind, metadata, files=None, base_record_id=None,
                   state_path=None, wait_seconds=3600):
        files = {name: Path(path) for name, path in (files or {}).items()}
        for path in files.values():
            if path.is_symlink() or not path.is_file():
                raise ValueError("Uploads must be regular files")
        size = metadata_size(metadata)
        if size > METADATA_LIMIT_BYTES:
            # Refused before any draft or transfer exists: the same request would fail server-side after the upload.
            raise ExchangeError(422, "metadata_too_large", {"size": size, "limit": METADATA_LIMIT_BYTES},
                                f"Record metadata is {size} bytes; the exchange accepts at most {METADATA_LIMIT_BYTES}")
        body = {"kind": kind, "metadata": metadata, "base_record_id": base_record_id,
                "attachments": [{"name": name, "size_bytes": path.stat().st_size, "sha256": sha256(path)}
                                for name, path in files.items()]}
        # Metadata is deliberately excluded: a retry with refreshed timestamps must resume the same transfer.
        fingerprint = hashlib.sha256(json.dumps(
            [self.endpoint, space, kind, base_record_id, body["attachments"]], sort_keys=True).encode()).hexdigest()
        state_path = Path(state_path) if state_path else None
        state = json.loads(state_path.read_text()) if state_path and state_path.exists() else {}
        if state.get("fingerprint") != fingerprint:
            if state.get("record_id"):
                self._discard(space, state["record_id"])
            state = {"fingerprint": fingerprint, "key": uuid.uuid4().hex}
        if state_path:
            save_state(state_path, state)
        if "record_id" not in state:
            record = self.request("POST", self.path(space, "/records"), body=body,
                                  headers={"Idempotency-Key": state["key"]})
            state["record_id"] = record["id"]
            if state_path:
                save_state(state_path, state)
        record = self.get_record(space, state["record_id"])
        if record["state"] == "ready":
            return self._finish(record, state_path)
        if record["state"] != "draft":
            self._forget(state_path)
            raise ExchangeError(409, "record_not_uploadable")
        if record["metadata"] != metadata:
            record = self.request("PATCH", self.path(space, f"/records/{record['id']}"), body={"metadata": metadata},
                                  headers={"If-Match": f'"{record["generation"]}"'})
        deadline = time.monotonic() + wait_seconds
        for attachment in record["attachments"]:
            if attachment["state"] == "verified":
                continue
            self._upload(space, record["id"], attachment, files[attachment["name"]], deadline)
        while True:
            try:
                return self._finish(self.request("POST", self.path(space, f"/records/{record['id']}:publish")), state_path)
            except ExchangeError as exc:
                if exc.code != "blobs_not_verified" or time.monotonic() >= deadline:
                    raise
                status = self.get_record(space, record["id"])
                if any(blob["state"] in ("failed", "aborted") for blob in status["attachments"]):
                    # The draft can never publish; release its reservation so the next attempt starts clean.
                    self._discard(space, record["id"])
                    self._forget(state_path)
                    raise ExchangeError(409, "blob_verification_failed") from None
                time.sleep(1)

    def _finish(self, record, state_path):
        self._forget(state_path)
        return record

    @staticmethod
    def _forget(state_path):
        if state_path:
            Path(state_path).unlink(missing_ok=True)

    def _discard(self, space, record):
        try:
            self.cancel_record(space, record)
        except ExchangeError:
            pass

    def _upload(self, space, record, attachment, file, deadline):
        identifier = attachment["id"]
        while True:
            try:
                started = self.request("POST", self.path(space, f"/records/{record}/blobs/{identifier}/uploads"))
                break
            except ExchangeError as exc:
                # The worker repairs an interrupted initialization within one tick.
                if exc.code != "upload_initialization_pending" or time.monotonic() >= deadline:
                    raise
                time.sleep(1)
        if started["state"] in ("verifying", "verified"):
            return
        if started["state"] in ("completing",):
            self.request("POST", self.path(space, f"/uploads/{identifier}:complete"))
            return
        if started["state"] != "uploading":
            raise ExchangeError(409, "upload_not_open")
        status = self.request("GET", self.path(space, f"/uploads/{identifier}"))
        chunk_size = status["part_bytes"]
        present = {p["part_number"] for p in status["parts"] if p["size_bytes"] == min(
            chunk_size, attachment["size_bytes"] - (p["part_number"] - 1) * chunk_size)}
        with file.open("rb") as source:
            for number in range(1, max(1, math.ceil(attachment["size_bytes"] / chunk_size)) + 1):
                if number in present:
                    continue
                source.seek((number - 1) * chunk_size)
                data = source.read(chunk_size)
                for attempt in range(3):
                    grant = self.request("POST", self.path(space, f"/uploads/{identifier}/parts:authorize"),
                                         body={"part_numbers": [number]})["parts"][0]
                    try:
                        response = self.transfer.put(grant["url"], content=data, headers=grant["headers"])
                        if response.is_success:
                            break
                    except httpx.TransportError:
                        pass
                    if attempt == 2 or time.monotonic() >= deadline:
                        raise ExchangeError(503, "blob_transfer_failed")
        self.request("POST", self.path(space, f"/uploads/{identifier}:complete"))

    def download_attachment(self, space, record, attachment, output):
        output = Path(output)
        if output.is_symlink():
            raise ValueError("Refusing symlink download destination")
        if output.exists() and sha256(output) == attachment["sha256"]:
            return output
        output.parent.mkdir(parents=True, exist_ok=True)
        partial = output.with_name(output.name + "." + attachment["id"] + ".part")
        if partial.is_symlink():
            raise ValueError("Refusing symlink partial download")
        for attempt in range(3):
            offset = partial.stat().st_size if partial.exists() else 0
            if offset >= attachment["size_bytes"] and partial.exists():
                break
            grant = self.request("POST", self.path(space, f"/records/{record}/blobs/{attachment['id']}:download"))
            headers = {"Range": f"bytes={offset}-"} if offset else {}
            try:
                with self.transfer.stream("GET", grant["url"], headers=headers) as response:
                    if response.status_code not in (200, 206):
                        continue
                    with partial.open("ab" if offset and response.status_code == 206 else "wb") as target:
                        for chunk in response.iter_bytes(1024 * 1024):
                            target.write(chunk)
            except httpx.TransportError:
                continue
        if not partial.exists() or partial.stat().st_size < attachment["size_bytes"]:
            # Keep the partial file: the next attempt resumes from its current offset.
            raise ExchangeError(503, "download_incomplete")
        if partial.stat().st_size != attachment["size_bytes"] or sha256(partial) != attachment["sha256"]:
            partial.unlink(missing_ok=True)
            raise ExchangeError(409, "download_integrity_failed")
        partial.replace(output)
        return output

    @staticmethod
    def safe_destination(root, name):
        path = PurePosixPath(name)
        if path.is_absolute() or any(p in ("..", ".", "") for p in name.split("/")) or "\\" in name:
            raise ValueError("Unsafe attachment name")
        root = Path(root).resolve()
        destination = root.joinpath(*path.parts)
        if not destination.resolve().is_relative_to(root):
            raise ValueError("Attachment escapes download directory")
        return destination
