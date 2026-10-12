"""Resumable byte transfer without control-plane credentials or server imports."""
import hashlib
import ipaddress
import json
import math
from pathlib import Path, PurePosixPath
import re
import time
from urllib.parse import quote, urlsplit

import httpx

from .client_types import AttachmentDescriptor, ExchangeError


def require_tls(url: str, *, allow_local_http=False):
    parsed = urlsplit(url)
    if parsed.username or parsed.password or not parsed.hostname or parsed.fragment:
        raise ValueError("Invalid service or transfer URL")
    if parsed.scheme == "https":
        return
    local = parsed.hostname == "localhost"
    try:
        local = local or ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        pass
    if parsed.scheme != "http" or not allow_local_http or not local:
        raise ValueError("HTTPS is required; local HTTP must be explicitly enabled")


def sha256(path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_destination(root, name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or any(part in ("..", ".", "") for part in name.split("/")) or "\\" in name:
        raise ValueError("Unsafe attachment path")
    root = Path(root).resolve()
    destination = root.joinpath(*path.parts)
    if not destination.resolve().is_relative_to(root):
        raise ValueError("Attachment escapes download directory")
    return destination


class TransferManager:
    def __init__(self, request, path, *, http=None, allow_local_http=False, retries=3, sleep=time.sleep):
        self.request, self.path = request, path
        self.http = http or httpx.Client(timeout=300, follow_redirects=False)
        self.allow_local_http = allow_local_http
        self.retries = retries
        self.sleep = sleep
        self._check_client()

    def _check_client(self):
        if self.http.auth is not None or self.http.cookies or any(
                name.lower() in ("authorization", "proxy-authorization", "cookie") for name in self.http.headers):
            raise ValueError("Transfer client must not contain authentication headers")

    @staticmethod
    def _remaining(deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ExchangeError(408, "transfer_deadline_exceeded")
        return remaining

    def _sleep(self, deadline):
        self.sleep(min(1, self._remaining(deadline)))

    @staticmethod
    def _headers(grant):
        headers = dict(grant.get("headers") or {})
        if any(name.lower() in ("authorization", "proxy-authorization", "cookie") for name in headers):
            raise ValueError("Transfer grants must not contain bearer or cookie credentials")
        return headers

    def _attachment_path(self, space, record, attachment):
        return self.path(space, "/records/" + quote(record, safe="") + "/attachments/" + quote(attachment, safe=""))

    def upload(self, space, record, attachment: AttachmentDescriptor, file, *, deadline):
        file = Path(file)
        base = self._attachment_path(space, record, attachment.id)
        while True:
            if time.monotonic() >= deadline:
                raise ExchangeError(408, "upload_deadline_exceeded")
            try:
                started = self.request("POST", base + "/upload", deadline=deadline)
            except ExchangeError as exc:
                if exc.code not in ("upload_initialization_pending", "transfer_pending", "transfer_busy"):
                    raise
                self._sleep(deadline)
                continue
            if started["state"] in ("completing", "verifying", "verified"):
                return
            if started["state"] in ("initiating", "initializing", "reserved"):
                self._sleep(deadline)
                continue
            if started["state"] != "uploading":
                raise ExchangeError(409, "upload_not_open", started)
            break
        if started.get("protocol") != "s3-multipart-v1":
            raise ExchangeError(409, "unsupported_transfer_protocol")
        part_size = started["part_size"]
        if not isinstance(part_size, int) or part_size <= 0:
            raise ExchangeError(502, "invalid_transfer_descriptor")
        parts = self.request("GET", base + "/parts", deadline=deadline)["parts"]
        count = max(1, math.ceil(attachment.size / part_size))
        present = {part["number"] for part in parts if 1 <= part["number"] <= count and part["size"] ==
                   min(part_size, attachment.size - (part["number"] - 1) * part_size)}
        with file.open("rb") as source:
            for number in range(1, count + 1):
                if number in present:
                    continue
                source.seek((number - 1) * part_size)
                data = source.read(min(part_size, max(0, attachment.size - (number - 1) * part_size)))
                for attempt in range(self.retries):
                    if time.monotonic() >= deadline:
                        raise ExchangeError(408, "upload_deadline_exceeded")
                    grants = self.request("POST", base + "/grants", body={"numbers": [number]}, deadline=deadline)["grants"]
                    grant = next((item for item in grants if item["number"] == number), None)
                    if grant is None or grant["size"] != len(data):
                        raise ExchangeError(502, "invalid_transfer_grant")
                    require_tls(grant["url"], allow_local_http=self.allow_local_http)
                    self._check_client()
                    try:
                        response = self.http.put(grant["url"], content=data, headers=self._headers(grant),
                                                 follow_redirects=False, auth=None, timeout=min(300, self._remaining(deadline)))
                        self._remaining(deadline)
                        if response.is_success:
                            break
                    except httpx.TransportError:
                        pass
                    if attempt + 1 == self.retries:
                        raise ExchangeError(503, "blob_transfer_failed")
        if file.stat().st_size != attachment.size or sha256(file) != attachment.sha256:
            raise ExchangeError(409, "upload_source_changed")
        self._remaining(deadline)
        self.request("POST", base + "/complete", deadline=deadline)

    def download(self, space, record, attachment: AttachmentDescriptor, output, *, seconds=3600):
        output = Path(output)
        if output.is_symlink():
            raise ValueError("Refusing symlink download destination")
        if output.is_file() and output.stat().st_size == attachment.size and sha256(output) == attachment.sha256:
            return output
        output.parent.mkdir(parents=True, exist_ok=True)
        identity = hashlib.sha256(attachment.id.encode()).hexdigest()[:24]
        partial = output.with_name(output.name + "." + identity + ".part")
        if partial.is_symlink():
            raise ValueError("Refusing symlink partial download")
        deadline = time.monotonic() + seconds
        for _ in range(self.retries):
            if time.monotonic() >= deadline:
                break
            offset = partial.stat().st_size if partial.exists() else 0
            if partial.exists() and offset >= attachment.size:
                break
            grant = self.request("GET", self._attachment_path(space, record, attachment.id) + "/download", deadline=deadline)
            if grant.get("size") != attachment.size or grant.get("sha256") != attachment.sha256:
                raise ExchangeError(409, "download_descriptor_mismatch")
            require_tls(grant["url"], allow_local_http=self.allow_local_http)
            headers = self._headers(grant)
            if offset:
                headers["Range"] = f"bytes={offset}-"
            self._check_client()
            try:
                with self.http.stream("GET", grant["url"], headers=headers, follow_redirects=False, auth=None,
                                      timeout=min(300, self._remaining(deadline))) as response:
                    if response.status_code not in (200, 206):
                        continue
                    if response.status_code == 206:
                        match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", response.headers.get("Content-Range", ""))
                        if not match or int(match[1]) != offset or int(match[3]) != attachment.size or \
                                int(match[2]) != attachment.size - 1:
                            raise ExchangeError(502, "invalid_download_range")
                    with partial.open("ab" if offset and response.status_code == 206 else "wb") as target:
                        for chunk in response.iter_bytes(1024 * 1024):
                            if target.tell() + len(chunk) > attachment.size:
                                raise ExchangeError(409, "download_integrity_failed")
                            target.write(chunk)
                            if time.monotonic() >= deadline:
                                raise ExchangeError(408, "download_deadline_exceeded")
            except httpx.TransportError:
                continue
        if not partial.exists() or partial.stat().st_size < attachment.size:
            raise ExchangeError(503, "download_incomplete")
        if partial.stat().st_size != attachment.size or sha256(partial) != attachment.sha256:
            partial.unlink(missing_ok=True)
            raise ExchangeError(409, "download_integrity_failed")
        partial.replace(output)
        return output

    safe_destination = staticmethod(safe_destination)


class ManagedTransferManager(TransferManager):
    """Byte streams through one trusted execution proxy, with no origin URLs.

    The proxy owns distinct upstream service tokens and its mTLS identity. This
    client has no credentials to send to data storage or to another execution.
    """

    protocol = "hf2l-managed-v1"

    def __init__(self, request, path, *, endpoint, space, http, retries=3, sleep=time.sleep):
        if endpoint != "http://proxy" or not space:
            raise ValueError("Managed transfers require the configured execution proxy")
        self.endpoint, self.space = endpoint, space
        super().__init__(request, path, http=http, retries=retries, sleep=sleep)

    @staticmethod
    def check_control_client(http):
        if http.auth is not None or http.cookies or any(
                name.lower() in ("authorization", "proxy-authorization", "cookie") for name in http.headers):
            raise ValueError("Managed proxy clients must not contain caller credentials")

    @staticmethod
    def validate_identifier(value):
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
            raise ValueError("Invalid managed resource identifier")
        return value

    @classmethod
    def _id(cls, value):
        try:
            return quote(cls.validate_identifier(value), safe="")
        except ValueError:
            raise ExchangeError(502, "invalid_transfer_descriptor") from None

    def _content_path(self, space, record, attachment, number=None):
        if space != self.space:
            raise ValueError("Managed transfers must address the assigned space")
        path = "/transfers/v1/spaces/" + self._id(space) + "/records/" + self._id(record)
        path += "/attachments/" + self._id(attachment)
        return path + ("/content" if number is None else "/parts/" + str(number))

    def _operation_url(self, descriptor, space, record, attachment, method, number=None):
        expected = {"space_id": space, "record_id": record, "attachment_id": attachment, "method": method}
        if number is not None:
            expected["part_number"] = number
        if (not isinstance(descriptor, dict) or descriptor.get("protocol") != self.protocol or
                not isinstance(descriptor.get("operation"), dict) or descriptor["operation"] != expected or
                (number is not None and type(descriptor["operation"].get("part_number")) is not int) or
                any(key in descriptor for key in ("url", "object_key", "origin", "token")) or
                descriptor.get("headers", {}) != {}):
            raise ExchangeError(502, "invalid_transfer_descriptor")
        self._check_client()
        return self.endpoint + self._content_path(space, record, attachment, number)

    @staticmethod
    def _chunks(file, offset, size):
        """Reopen for every retry; bound resident memory independently of part size."""
        with file.open("rb") as source:
            source.seek(offset)
            remaining = size
            while remaining:
                chunk = source.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise ExchangeError(409, "upload_source_changed")
                remaining -= len(chunk)
                yield chunk

    @staticmethod
    def _response_failure(response):
        try:
            body = response.json()
        except httpx.ResponseNotRead:
            # Streamed failures must not buffer an unbounded response body.
            encoded = bytearray()
            for chunk in response.iter_bytes(4096):
                encoded.extend(chunk)
                if len(encoded) > 65536:
                    break
            try:
                body = json.loads(encoded) if len(encoded) <= 65536 else {}
            except (ValueError, UnicodeDecodeError):
                body = {}
        except ValueError:
            body = {}
        error = body.get("error", body) if isinstance(body, dict) else {}
        if not isinstance(error, dict):
            error = {}
        return ExchangeError(response.status_code, error.get("code", "blob_transfer_failed"))

    def upload(self, space, record, attachment: AttachmentDescriptor, file, *, deadline):
        self._content_path(space, record, attachment.id)
        file = Path(file)
        if file.is_symlink() or not file.is_file():
            raise ValueError("Uploads must be regular files")
        base = self._attachment_path(space, record, attachment.id)
        while True:
            self._remaining(deadline)
            try:
                started = self.request("POST", base + "/upload", deadline=deadline)
            except ExchangeError as exc:
                if exc.code not in ("upload_initialization_pending", "transfer_pending", "transfer_busy"):
                    raise
                self._sleep(deadline)
                continue
            if started.get("protocol") != self.protocol:
                raise ExchangeError(409, "unsupported_transfer_protocol")
            if started["state"] in ("completing", "verifying", "verified"):
                return
            if started["state"] in ("initiating", "initializing", "reserved"):
                self._sleep(deadline)
                continue
            if started["state"] != "uploading":
                raise ExchangeError(409, "upload_not_open")
            break
        part_size = started.get("part_size")
        if type(part_size) is not int or part_size <= 0:
            raise ExchangeError(502, "invalid_transfer_descriptor")
        parts = self.request("GET", base + "/parts", deadline=deadline)["parts"]
        count = max(1, math.ceil(attachment.size / part_size))
        present = set()
        for part in parts:
            if not isinstance(part, dict) or type(part.get("number")) is not int or type(part.get("size")) is not int:
                raise ExchangeError(502, "invalid_transfer_descriptor")
            number = part["number"]
            if 1 <= number <= count and part["size"] == min(part_size, attachment.size - (number - 1) * part_size):
                present.add(number)
        for number in range(1, count + 1):
            if number in present:
                continue
            offset = (number - 1) * part_size
            size = min(part_size, max(0, attachment.size - offset))
            for attempt in range(self.retries):
                self._remaining(deadline)
                grants = self.request("POST", base + "/grants", body={"numbers": [number]}, deadline=deadline)["grants"]
                grant = next((item for item in grants if isinstance(item, dict) and
                              type(item.get("number")) is int and item["number"] == number), None)
                if grant is None or type(grant.get("size")) is not int or grant["size"] != size:
                    raise ExchangeError(502, "invalid_transfer_descriptor")
                url = self._operation_url(grant, space, record, attachment.id, "PUT", number)
                try:
                    response = self.http.put(url, content=self._chunks(file, offset, size),
                        headers={"Content-Length": str(size)}, auth=None, follow_redirects=False,
                        timeout=min(300, self._remaining(deadline)))
                    self._remaining(deadline)
                    if response.is_success:
                        break
                    if response.status_code not in (429, 502, 503, 504):
                        raise self._response_failure(response)
                except httpx.TransportError:
                    pass
                if attempt + 1 == self.retries:
                    raise ExchangeError(503, "blob_transfer_failed")
                self._sleep(deadline)
        if file.stat().st_size != attachment.size or sha256(file) != attachment.sha256:
            raise ExchangeError(409, "upload_source_changed")
        self._remaining(deadline)
        self.request("POST", base + "/complete", deadline=deadline)

    def download(self, space, record, attachment: AttachmentDescriptor, output, *, seconds=3600):
        self._content_path(space, record, attachment.id)
        if seconds <= 0:
            raise ValueError("Transfer time budget must be positive")
        output = Path(output)
        if output.is_symlink():
            raise ValueError("Refusing symlink download destination")
        if output.is_file() and output.stat().st_size == attachment.size and sha256(output) == attachment.sha256:
            return output
        output.parent.mkdir(parents=True, exist_ok=True)
        identity = hashlib.sha256((space + "/" + record + "/" + attachment.id).encode()).hexdigest()[:24]
        partial = output.with_name(output.name + "." + identity + ".part")
        if partial.is_symlink():
            raise ValueError("Refusing symlink partial download")
        deadline = time.monotonic() + seconds
        for attempt in range(self.retries):
            self._remaining(deadline)
            offset = partial.stat().st_size if partial.exists() else 0
            if partial.exists() and offset >= attachment.size:
                break
            grant = self.request("GET", self._attachment_path(space, record, attachment.id) + "/download", deadline=deadline)
            if grant.get("size") != attachment.size or grant.get("sha256") != attachment.sha256:
                raise ExchangeError(409, "download_descriptor_mismatch")
            url = self._operation_url(grant, space, record, attachment.id, "GET")
            try:
                # The gateway authorizes HEAD and GET separately against the current grant.
                head = self.http.head(url, auth=None, follow_redirects=False,
                                      timeout=min(300, self._remaining(deadline)))
                self._remaining(deadline)
                if head.status_code != 200:
                    if head.status_code not in (429, 502, 503, 504):
                        raise self._response_failure(head)
                    self._sleep(deadline)
                    continue
                if (head.headers.get("Content-Length") != str(attachment.size) or
                        head.headers.get("X-Content-SHA256", attachment.sha256) != attachment.sha256):
                    raise ExchangeError(409, "download_descriptor_mismatch")
                self._check_client()
                headers = {"Range": f"bytes={offset}-"} if offset else {}
                with self.http.stream("GET", url, headers=headers, auth=None, follow_redirects=False,
                                      timeout=min(300, self._remaining(deadline))) as response:
                    if response.status_code not in (200, 206):
                        if response.status_code not in (429, 502, 503, 504):
                            raise self._response_failure(response)
                        self._sleep(deadline)
                        continue
                    if response.status_code == 206:
                        match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", response.headers.get("Content-Range", ""))
                        if (not match or int(match[1]) != offset or int(match[3]) != attachment.size or
                                int(match[2]) != attachment.size - 1):
                            raise ExchangeError(502, "invalid_download_range")
                    with partial.open("ab" if offset and response.status_code == 206 else "wb") as target:
                        for chunk in response.iter_bytes(1024 * 1024):
                            if target.tell() + len(chunk) > attachment.size:
                                raise ExchangeError(409, "download_integrity_failed")
                            target.write(chunk)
                            self._remaining(deadline)
            except httpx.TransportError:
                if attempt + 1 < self.retries:
                    self._sleep(deadline)
                continue
        if not partial.exists() or partial.stat().st_size < attachment.size:
            raise ExchangeError(503, "download_incomplete")
        if partial.stat().st_size != attachment.size or sha256(partial) != attachment.sha256:
            partial.unlink(missing_ok=True)
            raise ExchangeError(409, "download_integrity_failed")
        partial.replace(output)
        return output
