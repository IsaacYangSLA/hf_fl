"""Resumable byte transfer without control-plane credentials or server imports."""
import hashlib
import ipaddress
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
