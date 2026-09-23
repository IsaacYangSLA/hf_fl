"""Lightweight exchange v2 facade: typed control API, transfers, durable recovery."""
from email.utils import parsedate_to_datetime
import json
from pathlib import Path
import time
from urllib.parse import quote
import uuid

import httpx

from .client_state import StateRepository
from .client_types import (AttachmentDescriptor, CoordinationHandle, EventDescriptor, ExchangeError,
                           MemberDescriptor, RecordDescriptor, ReferenceSnapshot, SpaceDescriptor, TypeRevision)
from .transfer_client import TransferManager, require_tls, safe_destination, sha256


class ExchangeClient:
    def __init__(self, endpoint, token, *, http=None, transfer=None, retries=3,
                 allow_local_http=False, sleep=time.sleep):
        if retries < 1:
            raise ValueError("retries must be positive")
        self.endpoint = endpoint.rstrip("/")
        require_tls(self.endpoint, allow_local_http=allow_local_http)
        self.token, self.retries, self.sleep = token, retries, sleep
        self.http = http or httpx.Client(timeout=60, follow_redirects=False)
        self.transfers = TransferManager(self.request, self.path, http=transfer,
                                         allow_local_http=allow_local_http, retries=retries, sleep=sleep)
        self._own_http, self._own_transfer = http is None, transfer is None

    def close(self):
        if self._own_http:
            self.http.close()
        if self._own_transfer:
            self.transfers.http.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def request(self, method, path, *, body=None, headers=None, params=None, deadline=None):
        """Internal JSON transport. Public methods return SDK descriptor values."""
        for attempt in range(self.retries):
            remaining = deadline - time.monotonic() if deadline is not None else 60
            if remaining <= 0:
                raise ExchangeError(408, "request_deadline_exceeded")
            token = self.token() if callable(self.token) else self.token
            request_headers = {**(headers or {}), "Authorization": "Bearer " + token}
            try:
                response = self.http.request(method, self.endpoint + path, json=body,
                                             headers=request_headers, params=params, follow_redirects=False,
                                             timeout=min(60, remaining))
            except httpx.TransportError:
                if attempt + 1 == self.retries:
                    raise ExchangeError(503, "connection_failed") from None
                self._sleep(min(60, 2 ** attempt), deadline)
                continue
            if deadline is not None and time.monotonic() >= deadline:
                raise ExchangeError(408, "request_deadline_exceeded")
            if response.status_code in (429, 502, 503, 504) and attempt + 1 < self.retries:
                retry = response.headers.get("Retry-After")
                try:
                    delay = float(retry) if retry else 2 ** attempt
                except ValueError:
                    try:
                        delay = parsedate_to_datetime(retry).timestamp() - time.time()
                    except (TypeError, ValueError, OverflowError):
                        delay = 2 ** attempt
                self._sleep(min(60, max(0, delay)), deadline)
                continue
            if response.status_code == 401 and callable(self.token) and attempt + 1 < self.retries:
                continue
            if response.status_code >= 300:
                try:
                    payload = response.json()
                except ValueError:
                    payload = {}
                error = payload.get("error", payload) if isinstance(payload, dict) else {}
                if not isinstance(error, dict):
                    error = {}
                raise ExchangeError(response.status_code, error.get("code", "request_failed"), error)
            if response.status_code == 204:
                return {}
            return response.json()
        raise ExchangeError(503, "connection_failed")

    def _sleep(self, seconds, deadline=None):
        remaining = deadline - time.monotonic() if deadline is not None else seconds
        if remaining <= 0:
            raise ExchangeError(408, "request_deadline_exceeded")
        self.sleep(min(seconds, remaining))

    @staticmethod
    def path(space, suffix=""):
        return "/v2/spaces/" + quote(space, safe="") + suffix

    @staticmethod
    def _key(key=None):
        return {"Idempotency-Key": key or uuid.uuid4().hex}

    @staticmethod
    def _record(record):
        return "/records/" + quote(record, safe="")

    def create_space(self, name, *, profile="generic.v1", idempotency_key=None, **options):
        return SpaceDescriptor.from_dict(self.request("POST", "/v2/spaces",
            body={"name": name, "profile": profile, **options}, headers=self._key(idempotency_key)))

    def get_space(self, space):
        return SpaceDescriptor.from_dict(self.request("GET", self.path(space)))

    def update_space_limits(self, space, **limits):
        return SpaceDescriptor.from_dict(self.request("PATCH", self.path(space), body=limits))

    def register_type(self, space, kind, schema, *, publish_roles=None, visibility=None, idempotency_key=None):
        # Policy defaults belong to the space profile. Explicit values, including
        # empty lists, must reach the service unchanged for validation.
        body = {"schema": schema}
        if publish_roles is not None:
            body["publish_roles"] = publish_roles
        if visibility is not None:
            body["visibility"] = visibility
        return TypeRevision.from_dict(self.request("POST", self.path(space,
            "/types/" + quote(kind, safe="") + "/revisions"), body=body, headers=self._key(idempotency_key)))

    def types(self, space):
        return tuple(TypeRevision.from_dict(item) for item in self.request("GET", self.path(space, "/types"))["items"])

    def get_type(self, space, kind, revision):
        return TypeRevision.from_dict(self.request("GET", self.path(space,
            "/types/" + quote(kind, safe="") + "/revisions/" + quote(str(revision), safe=""))))

    def set_policy(self, space, kind, *, publish_roles, visibility):
        self.request("PUT", self.path(space, "/policies/" + quote(kind, safe="")),
                     body={"publish_roles": publish_roles, "visibility": visibility})

    def members(self, space):
        return tuple(MemberDescriptor.from_dict(item) for item in self.request("GET", self.path(space, "/members"))["items"])

    def get_membership(self, space):
        return MemberDescriptor.from_dict(self.request("GET", self.path(space, "/membership")))

    def set_member(self, space, principal, roles, *, subject=None, bindings=None):
        return MemberDescriptor.from_dict(self.request("PUT", self.path(space,
            "/members/" + quote(principal, safe="")), body={"roles": list(roles), "subject": subject,
                                                          "bindings": bindings or {}}))

    def create_record(self, space, *, kind, schema_revision_id, metadata, attachments=(), idempotency_key=None, deadline=None):
        return RecordDescriptor.from_dict(self.request("POST", self.path(space, "/records"),
            body={"kind": kind, "schema_revision_id": schema_revision_id,
                  "metadata": metadata, "attachments": list(attachments)}, headers=self._key(idempotency_key), deadline=deadline))

    def get_record(self, space, record, *, deadline=None):
        return RecordDescriptor.from_dict(self.request("GET", self.path(space, self._record(record)), deadline=deadline))

    def update_record(self, space, record, *, metadata, version):
        return RecordDescriptor.from_dict(self.request("PATCH", self.path(space, self._record(record)),
            body={"metadata": metadata}, headers={"If-Match": f'"{version}"'}))

    def cancel_record(self, space, record):
        self.request("DELETE", self.path(space, self._record(record)))

    def purge_record(self, space, record):
        self.request("POST", self.path(space, self._record(record) + "/purge"))

    def publish_record(self, space, record, *, idempotency_key=None, deadline=None):
        return RecordDescriptor.from_dict(self.request("POST", self.path(space, self._record(record) + "/publish"),
                                                      headers=self._key(idempotency_key), deadline=deadline))

    def records(self, space, **filters):
        cursor = None
        while True:
            params = dict(filters)
            if cursor is not None:
                params["after"] = cursor
            response = self.request("GET", self.path(space, "/records"), params=params)
            yield from (RecordDescriptor.from_dict(item) for item in response["items"])
            cursor = response.get("next_cursor")
            if cursor in (None, ""):
                return

    def events(self, space, *, cursor=0, limit=100):
        """Return one retained feed page and its next cursor, including empty-page progress."""
        response = self.request("GET", self.path(space, "/events"), params={"after": cursor, "limit": limit})
        return tuple(EventDescriptor.from_dict(item) for item in response["items"]), response.get("next_cursor")

    def resolve(self, space, name):
        return ReferenceSnapshot.from_dict(self.request("GET", self.path(space, "/refs/" + quote(name, safe=""))))

    def set_ref(self, space, name, record_id, *, reference=None, idempotency_key=None):
        if reference is not None and reference.name != name:
            raise ValueError("Reference snapshot belongs to another name")
        headers = self._key(idempotency_key)
        headers["If-Match" if reference is not None else "If-None-Match"] = f'"{reference.token}"' if reference else "*"
        return ReferenceSnapshot.from_dict(self.request("PUT", self.path(space, "/refs/" + quote(name, safe="")),
                                                        body={"record_id": record_id}, headers=headers))

    def acquire(self, space, *, reference, input_ids=(), expected_token=None, lease_seconds=None,
                idempotency_key=None, state_path=None):
        name = reference.name if isinstance(reference, ReferenceSnapshot) else reference
        token = reference.token if isinstance(reference, ReferenceSnapshot) else expected_token
        if token is None:
            raise ValueError("An expected reference token or '*' is required")
        body = {"reference": name, "expected_token": str(token), "input_record_ids": list(input_ids)}
        if lease_seconds is not None:
            body["lease_seconds"] = lease_seconds
        repository = StateRepository(state_path)
        state = repository.begin("acquire", [self.endpoint, space, body], idempotency_key=idempotency_key)
        # Replaying the acquisition request resolves a response lost before its id was persisted.
        response = self.request("POST", self.path(space, "/acquisitions"), body=body, headers=self._key(state["key"]))
        handle = CoordinationHandle.from_dict(response)
        state["acquisition_id"] = handle.id
        repository.save(state)
        return handle

    def get_acquisition(self, space, acquisition_id):
        return CoordinationHandle.from_dict(self.request("GET", self.path(space,
            "/acquisitions/" + quote(acquisition_id, safe=""))))

    def renew(self, space, handle):
        body = {"fence": handle.fence}
        return CoordinationHandle.from_dict(self.request("POST", self.path(space,
            "/acquisitions/" + quote(handle.id, safe="") + "/renew"), body=body))

    def abandon(self, space, handle):
        return CoordinationHandle.from_dict(self.request("POST", self.path(space,
            "/acquisitions/" + quote(handle.id, safe="") + "/abandon"), body={"fence": handle.fence}))

    def complete(self, space, handle, record_id, *, idempotency_key=None, state_path=None):
        body = {"fence": handle.fence, "result_record_id": record_id}
        repository = StateRepository(state_path)
        state = repository.begin("complete", [self.endpoint, space, handle.id, body], idempotency_key=idempotency_key)
        return CoordinationHandle.from_dict(self.request("POST", self.path(space,
            "/acquisitions/" + quote(handle.id, safe="") + "/complete"), body=body, headers=self._key(state["key"])))

    def put_record(self, space, *, kind, metadata, schema_revision_id=None, type_revision=None,
                   files=None, state_path=None, upload_seconds=86400, verification_seconds=3600):
        revision = schema_revision_id or type_revision
        if not revision:
            raise ValueError("schema_revision_id is required")
        if upload_seconds <= 0 or verification_seconds <= 0:
            raise ValueError("Transfer time budgets must be positive")
        if len(json.dumps(metadata, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()) > 65536:
            raise ExchangeError(422, "metadata_too_large")
        files = {name: Path(path) for name, path in (files or {}).items()}
        for name, path in files.items():
            safe_destination(Path.cwd(), name)
            if path.is_symlink() or not path.is_file():
                raise ValueError("Uploads must be regular files")
        attachments = [{"path": name, "size": path.stat().st_size, "sha256": sha256(path)}
                       for name, path in sorted(files.items())]
        identity = [self.endpoint, space, kind, revision, metadata, attachments]
        repository = StateRepository(state_path)
        state = repository.begin("put_record", identity)
        deadline = time.monotonic() + upload_seconds
        if "record_id" not in state:
            record = self.create_record(space, kind=kind, schema_revision_id=revision,
                                        metadata=metadata, attachments=attachments, idempotency_key=state["key"], deadline=deadline)
            state["record_id"] = record.id
            state["publish_key"] = uuid.uuid4().hex
            repository.save(state)
        record = self.get_record(space, state["record_id"], deadline=deadline)
        if record.state == "published":
            return record
        self._check_uploadable(space, record, repository)
        for attachment in record.attachments:
            if attachment.state != "verified":
                self.transfers.upload(space, record.id, attachment, files[attachment.path], deadline=deadline)
        # Verification gets its full budget even after a long upload or resumed upload.
        deadline = time.monotonic() + verification_seconds
        while True:
            try:
                return self.publish_record(space, record.id, idempotency_key=state["publish_key"], deadline=deadline)
            except ExchangeError as exc:
                if exc.code in ("blob_verification_failed", "attachment_failed", "record_failed"):
                    self._discard(space, record.id, repository)
                    raise
                if exc.code not in ("blobs_not_verified", "attachments_not_verified", "verification_pending"):
                    raise
                record = self.get_record(space, record.id, deadline=deadline)
                self._check_uploadable(space, record, repository)
                if time.monotonic() >= deadline:
                    raise ExchangeError(408, "verification_deadline_exceeded") from None
                self._sleep(1, deadline)

    def _check_uploadable(self, space, record, repository):
        if record.state == "failed" or any(item.state in ("failed", "aborted", "cancelled") for item in record.attachments):
            self._discard(space, record.id, repository)
            raise ExchangeError(409, "blob_verification_failed")
        if record.state != "draft":
            repository.remove()
            raise ExchangeError(409, "record_not_uploadable")

    def _discard(self, space, record_id, repository):
        try:
            self.cancel_record(space, record_id)
        except ExchangeError as exc:
            if exc.status != 404:
                raise
        repository.remove()

    def download_attachment(self, space, record, attachment, output, *, seconds=3600):
        return self.transfers.download(space, record, attachment, output, seconds=seconds)

    safe_destination = staticmethod(safe_destination)
