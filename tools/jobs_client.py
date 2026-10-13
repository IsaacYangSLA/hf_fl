"""Strict HTTPS client for authenticated job management and result exports.

Session files are private inputs. Requests remain bound to the configured
Manager origin, and certificates are always verified.
"""
from __future__ import annotations
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import tempfile
from urllib.parse import urlsplit
import httpx

API = "/api/jobs/v1"
COOKIE = "__Host-hf2l_jobs"


class JobsClientError(RuntimeError):
    pass


def private_json(path):
    path = Path(path).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise JobsClientError("Private authentication file cannot contain links")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 65536):
            raise JobsClientError("Authentication file must be private and owned")
        raw = os.read(descriptor, 65537)
        if len(raw) > 65536:
            raise JobsClientError("Authentication file exceeds bound")
        return json.loads(raw)
    finally:
        os.close(descriptor)


def private_directory(path):
    path = Path(path).absolute()
    if ".." in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
        raise JobsClientError("Unsafe output directory")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise JobsClientError("Output directory must be private and owned")
    return path


def atomic_json(path, value):
    path = Path(path)
    parent = private_directory(path.parent)
    descriptor, pending = tempfile.mkstemp(prefix=".pending-", dir=parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, ensure_ascii=False, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(pending, path)
        descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(pending):
            os.unlink(pending)


def manager_origin(value):
    """Validate and normalize an HTTPS origin before any credentials are loaded."""
    if (not isinstance(value, str) or not value
            or any(character.isspace() or ord(character) < 32 or ord(character) == 127
                   for character in value)
            or any(character in value for character in ("\\", "?", "#"))):
        raise JobsClientError("Manager URL must be an HTTPS origin")
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.netloc or not parsed.hostname
                or "@" in parsed.netloc or parsed.path not in {"", "/"}
                or parsed.query or parsed.fragment or "%" in parsed.netloc
                or parsed.netloc.endswith(":")
                or (parsed.port is not None and not 1 <= parsed.port <= 65535)):
            raise ValueError("Invalid origin")
        hostname = parsed.hostname
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            hostname = hostname.encode("idna").decode("ascii")
            labels = hostname.rstrip(".").split(".")
            if (len(hostname) > 253 or any(not re.fullmatch(
                    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                    for label in labels)):
                raise ValueError("Invalid hostname")
        origin = httpx.URL(value)
        return str(origin).rstrip("/")
    except (ValueError, UnicodeError, httpx.InvalidURL) as error:
        raise JobsClientError("Manager URL must be an HTTPS origin") from error


class JobsClient:
    def __init__(self, base_url, *, ca_file=None,
                 session_file=None, session_cookie=None, csrf_token=None,
                 timeout=30, transport=None):
        self.base_url = manager_origin(base_url)
        self.csrf_token = csrf_token
        if session_file is not None:
            data = private_json(session_file)
            if not isinstance(data, dict):
                raise JobsClientError("Invalid Manager session file")
            if data.get("base_url") != self.base_url:
                raise JobsClientError("Session belongs to another Manager origin")
            session_cookie = data.get("session_cookie")
        if session_cookie is not None and (not isinstance(session_cookie, str)
                or not session_cookie or len(session_cookie) > 8192
                or not re.fullmatch(r"[A-Za-z0-9_-]+", session_cookie)):
            raise JobsClientError("Invalid Manager session")
        self._session_cookie = session_cookie
        tls = ssl.create_default_context(cafile=str(ca_file) if ca_file is not None else None)
        tls.verify_flags |= ssl.VERIFY_X509_STRICT
        self.http = httpx.Client(base_url=self.base_url,
            verify=tls,
            timeout=httpx.Timeout(timeout), follow_redirects=False,
            trust_env=False, transport=transport)
        # Cookie is sent only to this validated exact origin through request().
        if session_file is not None:
            self.refresh_session()

    def save_session(self, path):
        if not self._session_cookie:
            raise JobsClientError("No authenticated session")
        atomic_json(path, {"base_url": self.base_url, "session_cookie": self._session_cookie})

    def refresh_session(self):
        data = self.get_json("/auth/session")
        if not data.get("authenticated"):
            raise JobsClientError("Manager session is unauthenticated")
        self.csrf_token = data.get("csrf_token")
        self.principal = data.get("principal", {})
        return data

    def _headers(self, method, headers):
        result = dict(headers or {})
        if self._session_cookie and not any(k.lower() == "cookie" for k in result):
            result["Cookie"] = COOKIE + "=" + self._session_cookie
        if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            result.setdefault("Origin", self.base_url)
            if self.csrf_token:
                result.setdefault("X-CSRF-Token", self.csrf_token)
        return result

    @staticmethod
    def _path(path):
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            raise JobsClientError("Requests require an origin-relative path")
        parsed = urlsplit(path)
        if parsed.scheme or parsed.netloc or parsed.fragment or "\\" in path:
            raise JobsClientError("Invalid Manager request path")
        return path

    def request(self, method, path, *, json=None, headers=None, params=None, check=True):
        response = self.http.request(method, self._path(path), json=json, params=params,
                                    headers=self._headers(method, headers))
        if check and not response.is_success:
            # No response body, credentials or signed cursors in error output.
            raise JobsClientError("Manager request failed: HTTP " + str(response.status_code))
        return response

    def get_json(self, path, *, params=None):
        return self.request("GET", path, params=params).json()

    def iter_pages(self, path, *, params=None):
        arguments = dict(params or {})
        arguments["limit"] = 100
        seen = set()
        while True:
            page = self.get_json(path, params=arguments)
            if not isinstance(page, dict) or not isinstance(page.get("items"), list):
                raise JobsClientError("Invalid Manager collection")
            yield from page["items"]
            cursor = page.get("next_cursor")
            if cursor is None:
                break
            if not isinstance(cursor, str) or not cursor or len(cursor) > 4096 or cursor in seen:
                raise JobsClientError("Invalid or repeated pagination cursor")
            seen.add(cursor)
            arguments["cursor"] = cursor

    def stream_download(self, path, destination, *, expected_size, expected_sha256, content_guard=None):
        if (type(expected_size) is not int or expected_size < 0
                or not isinstance(expected_sha256, str)
                or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256)):
            raise JobsClientError("Artifact has no verified size and SHA-256")
        destination = Path(destination)
        parent = private_directory(destination.parent)
        descriptor, pending = tempfile.mkstemp(prefix=".download-", dir=parent)
        digest, total = hashlib.sha256(), 0
        try:
            with os.fdopen(descriptor, "wb") as handle:
                with self.http.stream("GET", self._path(path),
                        headers=self._headers("GET", {"Accept-Encoding": "identity"})) as response:
                    if not response.is_success:
                        raise JobsClientError("Artifact download failed: HTTP " + str(response.status_code))
                    length = response.headers.get("content-length")
                    if length is not None and (not length.isdecimal() or int(length) != expected_size):
                        raise JobsClientError("Artifact descriptor changed")
                    for chunk in response.iter_raw():
                        total += len(chunk)
                        if total > expected_size:
                            raise JobsClientError("Artifact exceeded advertised size")
                        if content_guard is not None:
                            content_guard.feed(chunk)
                        digest.update(chunk)
                        handle.write(chunk)
                if total != expected_size or digest.hexdigest() != expected_sha256:
                    raise JobsClientError("Artifact size or SHA-256 mismatch")
                if content_guard is not None:
                    content_guard.finish()
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(pending, destination)
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return {"size_bytes": total, "sha256": digest.hexdigest()}
        finally:
            if os.path.exists(pending):
                os.unlink(pending)

    def close(self):
        self.http.close()

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()


