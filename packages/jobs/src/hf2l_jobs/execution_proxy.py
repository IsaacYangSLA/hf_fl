"""Per-execution closed egress proxy and a TLS peer-verifying ingress."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re
import ssl
import threading
import time
from typing import Callable
from urllib.parse import urlsplit

import httpx
import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from .domain import Error as DomainError
from .gateway import GatewayError, certificate_thumbprint, identifier, service_endpoint, tls_context

_SAFE_HEADERS = {"accept", "content-type", "content-length", "idempotency-key", "if-match", "if-none-match", "range"}
_TOKEN_ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_CONTROL = (
    ("GET", r""), ("GET", r"/membership"), ("GET", r"/members"), ("GET", r"/types"),
    ("GET", r"/types/[A-Za-z0-9_.-]+/revisions/[A-Za-z0-9_.-]+"),
    ("GET", r"/records"), ("POST", r"/records"), ("GET", r"/events"),
    ("GET", r"/records/[A-Za-z0-9_-]+"), ("PATCH", r"/records/[A-Za-z0-9_-]+"),
    ("DELETE", r"/records/[A-Za-z0-9_-]+"), ("POST", r"/records/[A-Za-z0-9_-]+/publish"),
    ("GET", r"/refs/main"), ("PUT", r"/refs/main"), ("POST", r"/acquisitions"),
    ("GET", r"/acquisitions/[A-Za-z0-9_-]+"),
    ("POST", r"/acquisitions/[A-Za-z0-9_-]+/(renew|abandon|complete)"),
    ("POST", r"/records/[A-Za-z0-9_-]+/attachments/[A-Za-z0-9_-]+/(upload|grants|complete)"),
    ("GET", r"/records/[A-Za-z0-9_-]+/attachments/[A-Za-z0-9_-]+/(parts|download)"),
)


@dataclass(frozen=True)
class ExecutionBinding:
    job_id: str
    attempt_id: str
    component_id: str
    space_id: str
    epoch: int
    certificate_thumbprint: str

    def validate(self):
        for value in (self.job_id, self.attempt_id, self.component_id, self.space_id):
            identifier(value)
        if type(self.epoch) is not int or self.epoch < 1 or not re.fullmatch(r"[A-Za-z0-9_-]{43}", self.certificate_thumbprint):
            raise ValueError("Invalid execution binding")
        return self


@dataclass(frozen=True)
class ProxySettings:
    exchange_endpoint: str
    gateway_endpoint: str
    client_certificate: str
    client_key: str
    ca_file: str
    binding: ExecutionBinding
    exchange_token: str | Callable[[], str] = field(repr=False)
    gateway_token: str | Callable[[], str] = field(repr=False)
    workload_issuer: str
    workload_public_key: str
    exchange_audience: str = "exchange-workload"
    gateway_audience: str = "hf2l-transfer"
    max_control_bytes: int = 1024 * 1024
    max_part_bytes: int = 64 * 1024 * 1024
    max_download_bytes: int = 1024 ** 4
    timeout_seconds: float = 300

    def validate(self):
        service_endpoint(self.exchange_endpoint)
        service_endpoint(self.gateway_endpoint)
        self.binding.validate()
        if self.exchange_audience == self.gateway_audience or not self.workload_issuer or not self.workload_public_key:
            raise ValueError("Separate fixed workload service audiences and public key are required")
        if not all((self.client_certificate, self.client_key, self.ca_file)):
            raise ValueError("mTLS client key, certificate and CA must be outside the job")
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        from pathlib import Path
        cert = x509.load_pem_x509_certificate(Path(self.client_certificate).read_bytes())
        if certificate_thumbprint(cert.public_bytes(Encoding.DER)) != self.binding.certificate_thumbprint:
            raise ValueError("Proxy client certificate does not match execution binding")
        if min(self.max_control_bytes, self.max_part_bytes, self.max_download_bytes, self.timeout_seconds) <= 0:
            raise ValueError("Positive proxy limits are required")
        return self

    def token_for(self, transfer):
        provider = self.gateway_token if transfer else self.exchange_token
        try:
            token = provider() if callable(provider) else provider
        except DomainError as exc:
            # Authority replies may describe private enrollment or grant state.
            # Expose only fixed denial/availability codes; preserve other bugs.
            status = exc.status
            if type(status) is int:
                if status in {401, 403, 404, 410}:
                    raise GatewayError(403, "execution_authority_denied") from None
                if (status in {408, 429} or 500 <= status <= 599
                        or (status == 409 and exc.code == "participant_assignment_not_ready")):
                    raise GatewayError(503, "execution_service_unavailable") from None
            raise
        audience = self.gateway_audience if transfer else self.exchange_audience
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or header.get("typ") != "at+jwt":
                raise ValueError()
            value = jwt.decode(token, self.workload_public_key, algorithms=["RS256"],
                               issuer=self.workload_issuer, audience=audience,
                               options={"strict_aud": True, "require": ["iat", "exp", "jti", "sub", "job_id", "attempt_id",
                                                    "component_id", "space_id", "epoch", "cnf"]})
            if type(value["epoch"]) is not int:
                raise ValueError()
            for field in ("job_id", "attempt_id", "component_id", "space_id", "epoch"):
                if value[field] != getattr(self.binding, field):
                    raise ValueError()
            if value["cnf"] != {"x5t#S256": self.binding.certificate_thumbprint}:
                raise ValueError()
            if not 0 < value["exp"] - value["iat"] <= 300:
                raise ValueError()
            if ("transfer" if transfer else "exchange") not in str(value.get("scope", "")).split():
                raise ValueError()
            if value.get("grant_id", value["jti"]) != value["jti"]:
                raise ValueError()
            return token
        except (ValueError, TypeError, jwt.PyJWTError):
            raise GatewayError(401, "invalid_execution_credential") from None


def _route(settings, method, path):
    if "%" in path or "\\" in path or any(part in (".", "..", "") for part in path[1:].split("/")):
        raise GatewayError(404, "operation_not_allowed")
    prefix = "/v2/spaces/" + settings.binding.space_id
    if path == prefix or path.startswith(prefix + "/"):
        suffix = path[len(prefix):]
        if any(method == allowed and re.fullmatch(pattern, suffix) for allowed, pattern in _CONTROL):
            return False
    prefix = "/transfers/v1/spaces/" + settings.binding.space_id + "/records/"
    if path.startswith(prefix):
        suffix = path[len(prefix):]
        if method == "PUT" and re.fullmatch(r"[A-Za-z0-9_-]+/attachments/[A-Za-z0-9_-]+/parts/[1-9][0-9]{0,3}", suffix):
            return True
        if method in {"GET", "HEAD"} and re.fullmatch(r"[A-Za-z0-9_-]+/attachments/[A-Za-z0-9_-]+/content", suffix):
            return True
    raise GatewayError(404, "operation_not_allowed")


def create_proxy_app(settings: ProxySettings, *, http=None):
    settings.validate()
    client = http or httpx.AsyncClient(
        verify=tls_context(settings.ca_file, settings.client_certificate, settings.client_key),
        timeout=settings.timeout_seconds, follow_redirects=False, trust_env=False)
    @asynccontextmanager
    async def lifespan(app):
        try:
            yield
        finally:
            if http is None:
                await client.aclose()
    app = FastAPI(title="HF2L execution proxy", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.settings = settings

    @app.exception_handler(GatewayError)
    async def failure(request, exc):
        return JSONResponse({"error": {"code": exc.code}}, status_code=exc.status)

    @app.api_route("/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT"])
    async def route(request: Request, path: str):
        # The sandbox has only this execution's UDS. Caller credentials are never used.
        if any(name.lower() in {"authorization", "proxy-authorization", "cookie"} or name.lower().startswith("x-hf2l-")
               or name.lower() in {"x-forwarded-client-cert", "x-forwarded-host"} for name in request.headers):
            raise GatewayError(400, "caller_credentials_forbidden")
        raw = request.scope.get("raw_path", request.url.path.encode()).decode("ascii", errors="replace")
        transfer = _route(settings, request.method, raw)
        if transfer and request.url.query:
            raise GatewayError(400, "unexpected_transfer_query")
        limit = settings.max_part_bytes if transfer and request.method == "PUT" else settings.max_control_bytes
        try:
            declared = int(request.headers.get("content-length", "0"))
        except ValueError:
            raise GatewayError(400, "invalid_content_length") from None
        if declared < 0 or declared > limit or "transfer-encoding" in request.headers:
            raise GatewayError(413, "request_too_large")
        if transfer and request.method == "PUT" and "content-length" not in request.headers:
            raise GatewayError(411, "content_length_required")
        headers = {name: value for name, value in request.headers.items() if name.lower() in _SAFE_HEADERS}
        headers["Authorization"] = "Bearer " + settings.token_for(transfer)
        headers["Accept-Encoding"] = "identity"
        headers["Content-Length"] = str(declared)
        endpoint = settings.gateway_endpoint if transfer else settings.exchange_endpoint
        target = raw + ("?" + request.url.query if request.url.query else "")

        async def body():
            count = 0
            async for chunk in request.stream():
                count += len(chunk)
                if count > declared or count > limit:
                    raise GatewayError(413, "request_too_large")
                for offset in range(0, len(chunk), 65536):
                    yield chunk[offset:offset + 65536]
            if count != declared:
                raise GatewayError(400, "content_length_mismatch")

        try:
            upstream = await client.send(client.build_request(request.method, endpoint + target,
                                                               headers=headers, content=body()), stream=True)
        except httpx.HTTPError:
            raise GatewayError(503, "execution_service_unavailable") from None
        if 300 <= upstream.status_code < 400:
            await upstream.aclose()
            raise GatewayError(502, "redirect_not_allowed")
        safe = {"content-type", "content-length", "etag", "retry-after", "content-range", "accept-ranges",
                "x-content-sha256", "content-disposition", "x-content-type-options", "cache-control"}
        response_headers = {name: value for name, value in upstream.headers.items() if name.lower() in safe}
        response_limit = settings.max_download_bytes if transfer and request.method in {"GET", "HEAD"} else settings.max_control_bytes
        if not transfer:
            # JSON controls are bounded and never allowed to carry legacy signed URLs.
            value = bytearray()
            try:
                async for chunk in upstream.aiter_bytes(65536):
                    if len(value) + len(chunk) > response_limit:
                        raise GatewayError(502, "control_response_too_large")
                    value.extend(chunk)
            finally:
                await upstream.aclose()
            if b'"url"' in value or b'"access_key"' in value or b'"secret_key"' in value:
                raise GatewayError(502, "unsafe_control_descriptor")
            return Response(bytes(value), status_code=upstream.status_code, headers=response_headers)
        if request.method == "HEAD":
            await upstream.aclose()
            return Response(status_code=upstream.status_code, headers=response_headers)

        async def response():
            total = 0
            try:
                async for chunk in upstream.aiter_bytes(65536):
                    total += len(chunk)
                    if total > response_limit:
                        raise GatewayError(502, "transfer_response_too_large")
                    yield chunk
            finally:
                await upstream.aclose()
        return StreamingResponse(response(), status_code=upstream.status_code, headers=response_headers)

    return app


class MTLSHTTPServer(ThreadingHTTPServer):
    """TLS edge verifies client certificates and supplies non-header ASGI identity."""
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, app, certificate, key, client_ca, *, max_request_bytes=64 * 1024 * 1024):
        self.app, self.max_request_bytes = app, max_request_bytes
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=client_ca)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(certificate, key)
        super().__init__(address, _TLSHandler)
        self.socket = context.wrap_socket(self.socket, server_side=True, do_handshake_on_connect=False)
        self.event_loop = asyncio.new_event_loop()
        self.event_thread = threading.Thread(target=self.event_loop.run_forever, daemon=True)
        self.event_thread.start()
        self.slots = threading.BoundedSemaphore(64)
        self._lifespan = None
        if hasattr(app, "router"):
            self._lifespan = app.router.lifespan_context(app)
            asyncio.run_coroutine_threadsafe(self._lifespan.__aenter__(), self.event_loop).result(timeout=10)

    def handle_error(self, request, client_address):
        import sys
        if isinstance(sys.exc_info()[1], (ssl.SSLError, TimeoutError, ConnectionError)):
            return
        super().handle_error(request, client_address)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(30)
        return request, address

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def server_close(self):
        try:
            if self._lifespan:
                asyncio.run_coroutine_threadsafe(self._lifespan.__aexit__(None, None, None), self.event_loop).result(timeout=10)
        finally:
            super().server_close()
            self.event_loop.call_soon_threadsafe(self.event_loop.stop)
            self.event_thread.join(timeout=10)
            self.event_loop.close()

    def start_thread(self):
        thread = threading.Thread(target=self.serve_forever, daemon=True)
        thread.start()
        return thread


class _TLSHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *_):
        pass  # Access tokens, targets and headers must not enter log output.

    def _handle(self):
        if self.headers.get("Transfer-Encoding"):
            self.send_error(400)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if not 0 <= length <= self.server.max_request_bytes:
            self.send_error(413)
            return
        der = self.connection.getpeercert(binary_form=True)
        if not der:
            self.send_error(401)
            return
        target = urlsplit(self.path)
        if target.scheme or target.netloc or target.fragment:
            self.send_error(400)
            return
        remaining, started = length, False
        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.0",
                 "method": self.command, "scheme": "https", "path": target.path,
                 "raw_path": target.path.encode("ascii"), "query_string": target.query.encode("ascii"),
                 "root_path": "", "headers": [(k.lower().encode("ascii"), v.encode("latin1")) for k, v in self.headers.items()],
                 "client": self.client_address, "server": self.server.server_address,
                 "state": {"verified_certificate_thumbprint": certificate_thumbprint(der)}}

        async def receive():
            nonlocal remaining
            if remaining:
                chunk = await asyncio.to_thread(self.rfile.read, min(65536, remaining))
                if not chunk:
                    return {"type": "http.disconnect"}
                remaining -= len(chunk)
                return {"type": "http.request", "body": chunk, "more_body": bool(remaining)}
            # First empty body is still a request; subsequent wait cannot consume another request.
            if not getattr(receive, "sent", False):
                receive.sent = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await asyncio.sleep(3600)
            return {"type": "http.disconnect"}

        async def send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                self.send_response(message["status"])
                for name, value in message.get("headers", ()):
                    if name.lower() not in {b"connection", b"transfer-encoding"}:
                        self.send_header(name.decode("ascii"), value.decode("latin1"))
                self.send_header("Connection", "close")
                self.end_headers()
            elif message["type"] == "http.response.body" and self.command != "HEAD":
                await asyncio.to_thread(self.wfile.write, message.get("body", b""))
                await asyncio.to_thread(self.wfile.flush)
        try:
            future = asyncio.run_coroutine_threadsafe(self.server.app(scope, receive, send), self.server.event_loop)
            future.result()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            if not started:
                self.send_error(500)
        self.close_connection = True

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_CONNECT = _handle


def start_mtls_server(app, *, host="127.0.0.1", port=0, certificate, key, client_ca,
                      max_request_bytes=64 * 1024 * 1024):
    server = MTLSHTTPServer((host, port), app, certificate, key, client_ca, max_request_bytes=max_request_bytes)
    server.thread = server.start_thread()
    return server


def create_tls_forwarder_app(*, backend_endpoint, backend_secret, ca_file="", http=None):
    """Authenticated private edge for Exchange managed ingress, with fixed target host."""
    from hf2l_exchange.auth import backend_assertion_headers
    service_endpoint(backend_endpoint)
    if len(backend_secret.encode()) < 32:
        raise ValueError("Private backend secret must be at least 32 bytes")
    client = http or httpx.AsyncClient(verify=tls_context(ca_file), follow_redirects=False, trust_env=False, timeout=300)
    @asynccontextmanager
    async def lifespan(app):
        try:
            yield
        finally:
            if http is None:
                await client.aclose()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

    @app.api_route("/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])
    async def forward(request: Request, path: str):
        thumb = request.scope.get("state", {}).get("verified_certificate_thumbprint")
        if not thumb:
            return JSONResponse({"error": {"code": "verified_tls_required"}}, status_code=401)
        raw = request.scope.get("raw_path", request.url.path.encode()).decode("ascii")
        if not raw.startswith("/v2/spaces/") or "%" in raw or "\\" in raw or "//" in raw:
            return JSONResponse({"error": {"code": "operation_not_allowed"}}, status_code=404)
        target = raw + ("?" + request.url.query if request.url.query else "")
        authorization = request.headers.get("authorization", "")
        headers = {name: value for name, value in request.headers.items() if name.lower() in _SAFE_HEADERS}
        headers["Authorization"] = authorization
        headers.update(backend_assertion_headers(backend_secret, request.method, target, authorization, thumb))
        # Gateway/proxy enforce byte-transfer bounds; this edge only carries Exchange JSON.
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > 1024 * 1024:
                return JSONResponse({"error": {"code": "request_too_large"}}, status_code=413)
            body.extend(chunk)
        headers["Accept-Encoding"] = "identity"
        try:
            response = await client.send(client.build_request(request.method, backend_endpoint + target,
                                                              headers=headers, content=bytes(body)), stream=True)
            content = bytearray()
            try:
                if 300 <= response.status_code < 400:
                    return JSONResponse({"error": {"code": "unsafe_backend_response"}}, status_code=502)
                async for chunk in response.aiter_bytes(65536):
                    if len(content) + len(chunk) > 1024 * 1024:
                        return JSONResponse({"error": {"code": "unsafe_backend_response"}}, status_code=502)
                    content.extend(chunk)
            finally:
                await response.aclose()
        except httpx.HTTPError:
            return JSONResponse({"error": {"code": "backend_unavailable"}}, status_code=503)
        allowed = {"content-type", "etag", "retry-after"}
        return Response(bytes(content), status_code=response.status_code,
                        headers={k: v for k, v in response.headers.items() if k.lower() in allowed})
    return app



class _PrivateProxyControl:
    """Unmounted same-UID local control socket; never exposed to a workload."""

    def __init__(self, address, proxy):
        import json
        import os
        import socket
        import socketserver
        import struct
        from dataclasses import asdict
        if not hasattr(socket, "SO_PEERCRED"):
            raise ValueError("Trusted proxy administration requires Linux peer credentials")
        expected = asdict(proxy.binding)
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                _, uid, _ = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != os.geteuid():
                    return
                self.request.settimeout(5)
                line = self.rfile.readline(4097)
                if len(line) > 4096 or not line.endswith(b"\n"):
                    return
                try:
                    command = json.loads(line)
                    if command.get("binding") != expected or command.get("operation") not in {"status", "stop"}:
                        return
                    if command["operation"] == "stop":
                        if command.get("termination_confirmed") is not True:
                            return
                        proxy.server.should_exit = True
                        proxy.thread.join(timeout=10)
                    result = {"binding": expected, "running": proxy.thread.is_alive(), "owner_pid": os.getpid()}
                    self.wfile.write(json.dumps(result, separators=(",", ":")).encode() + b"\n")
                except (ValueError, TypeError, OSError):
                    return
        class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True
        self.server = Server(address, Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _private_proxy_operation(socket_path, binding, operation, *, termination_confirmed=False):
    import json
    import os
    import socket
    import struct
    from dataclasses import asdict
    control = socket_path.rsplit("/", 1)[0] + "/c"
    request = {"binding": asdict(binding), "operation": operation, "termination_confirmed": termination_confirmed}
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(12)
        connection.connect(control)
        _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != os.geteuid():
            raise ValueError("Proxy control belongs to an untrusted identity")
        connection.sendall(json.dumps(request, separators=(",", ":")).encode() + b"\n")
        data = bytearray()
        while not data.endswith(b"\n"):
            piece = connection.recv(4096 - len(data))
            if not piece or len(data) + len(piece) >= 4096:
                raise ValueError("Proxy control returned no bounded identity")
            data.extend(piece)
        value = json.loads(data)
        if value.get("binding") != asdict(binding) or type(value.get("running")) is not bool:
            raise ValueError("Proxy control returned a foreign execution")
        return value
    finally:
        connection.close()

@dataclass
class _SupervisedProxy:
    binding: ExecutionBinding
    socket_path: str
    certificate: str
    key: str
    server: object
    thread: threading.Thread
    directory_fd: int
    control: object = None


def _initialize_proxy_root(path):
    """Create a private root through descriptor-relative no-follow ancestors."""
    import os
    import stat
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            except FileNotFoundError:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("Proxy root must be private0700 and operator owned")
        return info.st_dev, info.st_ino
    except OSError as error:
        raise ValueError("Proxy root cannot contain symlink ancestors or unsafe directory components") from error
    finally:
        os.close(descriptor)


class ProxySupervisor:
    """Own only per-execution UDS proxies and their private certificate material.

    Grant lookup is a trusted current-ledger operation, not a job-controlled
    callback. The receiving Exchange/gateway independently recheck the ledger.
    The supervisor never launches or kills job runtimes.
    """

    def __init__(self, root, *, client_ca_certificate, client_ca_key=None, broker,
                 exchange_endpoint, gateway_endpoint, service_ca_file, grant_lookup,
                 startup_timeout=10, socket_root=None, token_provider=None, certificate_provider=None):
        from pathlib import Path
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        self.root = Path(root).absolute()
        self.socket_root = Path(socket_root).absolute() if socket_root is not None else self.root
        self._root_identities = {self.root: _initialize_proxy_root(self.root)}
        if self.socket_root not in self._root_identities:
            self._root_identities[self.socket_root] = _initialize_proxy_root(self.socket_root)
        self.broker, self.grant_lookup = broker, grant_lookup
        self.token_provider = token_provider
        self._adopted = {}
        self.exchange_endpoint = service_endpoint(exchange_endpoint)
        self.gateway_endpoint = service_endpoint(gateway_endpoint)
        self.service_ca_file = service_ca_file
        self.ca_certificate = x509.load_pem_x509_certificate(Path(client_ca_certificate).read_bytes())
        if bool(client_ca_key) == bool(certificate_provider):
            raise ValueError('Configure exactly one local CA key or centrally authenticated CSR certificate provider')
        self.certificate_provider = certificate_provider
        self.ca_key = (serialization.load_pem_private_key(Path(client_ca_key).read_bytes(), password=None)
                       if client_ca_key else None)
        if self.ca_key is not None and self.ca_certificate.public_key().public_numbers() != self.ca_key.public_key().public_numbers():
            raise ValueError("Proxy certificate authority key mismatch")
        extension = self.ca_certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        if not extension.value.ca:
            raise ValueError("Proxy certificate authority must be a CA")
        self.startup_timeout, self._active = startup_timeout, {}
        self._lock = threading.RLock()

    def _owned_proxy_root(self, stack, base):
        import os
        from .collection import SafeCollector
        collector = stack.enter_context(SafeCollector(base))
        info = os.fstat(collector._root_fd)
        if ((info.st_dev, info.st_ino) != self._root_identities[base]
                or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise ValueError("Private proxy root ownership or identity changed")
        return collector._root_fd

    def endpoint(self, identity):
        # Planning is pure: no files, credentials or network side effects.
        target = self.socket_root / 'p' / identity.key / 's'
        if len(str(target).encode()) >= 108:
            raise ValueError('Configure a shorter private proxy socket root (AF_UNIX limit is 107 bytes)')
        return str(target)

    def _socket_directory(self, identity):
        from pathlib import Path
        target = Path(self.endpoint(identity))
        current = self.socket_root
        for part in ('p', identity.key):
            current = current / part
            if current.is_symlink():
                raise ValueError('Proxy socket parent cannot be a symlink')
            current.mkdir(mode=0o700, exist_ok=True)
        return target

    def _directory(self, job_id, attempt_id, component_id, *, create=True):
        from pathlib import Path
        for value in (job_id, attempt_id, component_id):
            identifier(value)
        current = self.root
        for value in (job_id, "attempts", attempt_id, component_id):
            current = current / value
            if current.is_symlink():
                raise ValueError("Proxy material parent cannot be a symlink")
            if create:
                current.mkdir(mode=0o700, exist_ok=True)
            elif current.exists() and not current.is_dir():
                raise ValueError("Proxy material parent is not a directory")
        return current

    def _materialize(self, job_id, attempt_id, component_id, space_id, epoch, deadline):
        import json
        import os
        import stat
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.exceptions import InvalidSignature
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        from .executor import ExecutionIdentity
        tombstone = self.root / "purge-ledger" / (ExecutionIdentity(job_id, attempt_id, component_id, epoch).key + ".json")
        if tombstone.exists() or tombstone.is_symlink():
            raise ValueError("Execution proxy was purged and cannot be recreated")
        directory = self._directory(job_id, attempt_id, component_id)
        identity = {"job_id": job_id, "attempt_id": attempt_id, "component_id": component_id,
                    "space_id": space_id, "epoch": epoch}
        metadata = directory / "proxy-identity.json"
        certificate, key = directory / "proxy-cert.pem", directory / "proxy-key.pem"
        present = [path.exists() or path.is_symlink() for path in (metadata, certificate, key)]
        pending_csr = bool(self.certificate_provider and present[0] and present[2] and not present[1])
        if any(present) and not all(present) and not pending_csr:
            raise ValueError("Proxy certificate material is incomplete; reconcile before reuse")
        if pending_csr:
            for path in (metadata, key):
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("Pending CSR material must be private regular files")
            if json.loads(metadata.read_text()) != identity:
                raise ValueError("Pending CSR belongs to another execution")
        if all(present):
            for path in (metadata, certificate, key):
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("Proxy certificate material must be private regular files")
            saved = json.loads(metadata.read_text())
            if saved != identity:
                raise ValueError("Existing proxy material belongs to another execution")
            cert = x509.load_pem_x509_certificate(certificate.read_bytes())
            private = serialization.load_pem_private_key(key.read_bytes(), password=None)
            try:
                cert.verify_directly_issued_by(self.ca_certificate)
                if (cert.public_key().public_numbers() != private.public_key().public_numbers()
                        or cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                        or ExtendedKeyUsageOID.CLIENT_AUTH not in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value):
                    raise ValueError()
            except (ValueError, InvalidSignature, x509.ExtensionNotFound):
                raise ValueError("Existing proxy certificate is invalid") from None
            now = datetime.now(timezone.utc)
            if cert.not_valid_before_utc > now or cert.not_valid_after_utc <= now:
                raise ValueError("Proxy certificate expired or is not valid yet; execution must be fenced before rotation")
        else:
            now = datetime.now(timezone.utc)
            requested_expiry = datetime.fromtimestamp(deadline, timezone.utc) + timedelta(hours=1) if deadline else now + timedelta(days=30)
            expiry = min(requested_expiry, now + timedelta(days=30), self.ca_certificate.not_valid_after_utc)
            if expiry <= now + timedelta(minutes=5):
                raise ValueError("Certificate authority expires too soon")
            private = (serialization.load_pem_private_key(key.read_bytes(), password=None) if pending_csr
                       else rsa.generate_private_key(public_exponent=65537, key_size=2048))
            if self.certificate_provider is not None:
                if not pending_csr:
                    # Persist the private key and binding before the online issuance
                    # side effect so a lost acknowledgement reuses the same CSR.
                    pending_values = ((key, private.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
                        (metadata, json.dumps(identity, sort_keys=True).encode()))
                    for path, value in pending_values:
                        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                        with os.fdopen(fd, 'wb') as output:
                            output.write(value)
                            output.flush()
                            os.fsync(output.fileno())
                csr = (x509.CertificateSigningRequestBuilder()
                       .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hf2l-execution")]))
                       .sign(private, hashes.SHA256()))
                supplied = self.certificate_provider(dict(identity), csr.public_bytes(serialization.Encoding.PEM).decode())
                try:
                    cert = x509.load_pem_x509_certificate(supplied["certificate_pem"].encode())
                    cert.verify_directly_issued_by(self.ca_certificate)
                    if cert.public_key().public_numbers() != private.public_key().public_numbers():
                        raise ValueError()
                    if certificate_thumbprint(cert.public_bytes(serialization.Encoding.DER)) != supplied["certificate_thumbprint"]:
                        raise ValueError()
                    if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                        raise ValueError()
                    if ExtendedKeyUsageOID.CLIENT_AUTH not in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
                        raise ValueError()
                    if cert.not_valid_before_utc > now or cert.not_valid_after_utc <= now or cert.not_valid_after_utc > expiry:
                        raise ValueError()
                except (ValueError, KeyError, TypeError, InvalidSignature, x509.ExtensionNotFound):
                    raise ValueError('Central CSR certificate does not match this execution private key and authority') from None
            else:
                try:
                    issuer_identifier = self.ca_certificate.extensions.get_extension_for_class(
                        x509.SubjectKeyIdentifier).value
                except x509.ExtensionNotFound:
                    issuer_identifier = x509.SubjectKeyIdentifier.from_public_key(
                        self.ca_certificate.public_key())
                cert = (x509.CertificateBuilder()
                        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hf2l-execution")]))
                        .issuer_name(self.ca_certificate.subject).public_key(private.public_key())
                        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                        .not_valid_after(expiry)
                        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                        .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                            private.public_key()), critical=False)
                        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                            issuer_identifier), critical=False)
                        .add_extension(x509.KeyUsage(
                            digital_signature=True, content_commitment=False, key_encipherment=False,
                            data_encipherment=False, key_agreement=False, key_cert_sign=False,
                            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
                        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                        .sign(self.ca_key, hashes.SHA256()))
            values = ((key, private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption())),
                      (certificate, cert.public_bytes(serialization.Encoding.PEM)),
                      (metadata, json.dumps(identity, sort_keys=True).encode()))
            for path, value in values:
                if self.certificate_provider is not None and path in (key, metadata):
                    continue
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    with os.fdopen(descriptor, "wb") as target:
                        target.write(value)
                        target.flush()
                        os.fsync(target.fileno())
                except Exception:
                    path.unlink(missing_ok=True)
                    raise
        binding = ExecutionBinding(job_id, attempt_id, component_id, space_id, epoch,
                                   certificate_thumbprint(cert.public_bytes(serialization.Encoding.DER)))
        return binding, directory / "proxy.sock", certificate, key

    def _token(self, binding, participant_id, audience):
        if self.token_provider is not None:
            return self.token_provider(binding, participant_id, audience)
        grant = self.grant_lookup(binding.job_id, binding.attempt_id, binding.component_id)
        if not isinstance(grant, dict):
            raise GatewayError(503, "execution_grant_unavailable")
        for field in ("job_id", "attempt_id", "component_id", "space_id", "epoch", "certificate_thumbprint"):
            if grant.get(field) != getattr(binding, field):
                raise GatewayError(401, "execution_grant_mismatch")
        if not grant.get("enabled", True):
            raise GatewayError(401, "execution_grant_revoked")
        remaining = int(float(grant.get("expires_at", 0)) - time.time())
        if remaining < 1:
            raise GatewayError(401, "execution_grant_expired")
        return self.broker.issue_workload(job_id=binding.job_id, attempt_id=binding.attempt_id,
            component_id=binding.component_id, space_id=binding.space_id, grant_id=grant["grant_id"],
            epoch=binding.epoch, certificate_thumbprint=binding.certificate_thumbprint,
            participant_id=participant_id, ttl_seconds=min(300, remaining), audience=audience)

    def binding(self, job, attempt, component, space_id, principal_id):
        import os
        import socket
        import stat
        import uvicorn
        from .broker import stable_workload_principal
        def value(item, name, default=None):
            return item.get(name, default) if isinstance(item, dict) else getattr(item, name, default)
        job_id, attempt_id, component_id = value(job, "id"), value(attempt, "id"), value(component, "component_id")
        epoch, participant_id = value(attempt, "epoch"), value(component, "participant_id")
        if value(attempt, "job_id") != job_id:
            raise ValueError("Attempt belongs to another job")
        expected = stable_workload_principal(self.broker.settings.workload_issuer, job_id, component_id, participant_id)
        if principal_id != expected:
            raise ValueError("Proxy principal differs from stable workload identity")
        identity = (job_id, attempt_id, component_id)
        with self._lock:
            from contextlib import ExitStack
            with ExitStack() as roots:
                for base in self._root_identities:
                    self._owned_proxy_root(roots, base)
            existing = self._active.get(identity)
            if existing:
                if existing.binding.space_id != space_id or existing.binding.epoch != epoch:
                    raise ValueError("Active proxy execution binding cannot change")
                if not existing.thread.is_alive():
                    raise ValueError("Existing proxy is unhealthy; reconcile execution first")
                return {"certificate_thumbprint": existing.binding.certificate_thumbprint,
                        "proxy_endpoint": existing.socket_path}
            deadline = value(job, "deadline_at")
            deadline = deadline.timestamp() if hasattr(deadline, "timestamp") else deadline
            binding, socket_path, certificate, key = self._materialize(
                job_id, attempt_id, component_id, space_id, epoch, deadline)
            from .executor import ExecutionIdentity
            socket_path = self._socket_directory(ExecutionIdentity(job_id, attempt_id, component_id, epoch))
            directory_fd = os.open(socket_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            socket_alias = f'/proc/self/fd/{directory_fd}/s'
            if socket_path.exists() or socket_path.is_symlink():
                if not stat.S_ISSOCK(socket_path.lstat().st_mode):
                    raise ValueError("Proxy socket path is not an owned socket")
                check = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    check.settimeout(.5)
                    check.connect(socket_alias)
                except (ConnectionRefusedError, FileNotFoundError):
                    socket_path.unlink(missing_ok=True)
                else:
                    os.close(directory_fd)
                    status = _private_proxy_operation(str(socket_path), binding, 'status')
                    if not status['running']:
                        raise ValueError('Existing proxy is unhealthy; reconcile execution first')
                    self._adopted[identity] = (binding, str(socket_path))
                    return {'certificate_thumbprint': binding.certificate_thumbprint, 'proxy_endpoint': str(socket_path)}
                finally:
                    check.close()
            settings = ProxySettings(self.exchange_endpoint, self.gateway_endpoint, str(certificate), str(key),
                self.service_ca_file, binding, lambda: self._token(binding, participant_id, "exchange"),
                lambda: self._token(binding, participant_id, "gateway"), self.broker.settings.workload_issuer,
                self.broker.settings.public_key, self.broker.settings.exchange_audience, self.broker.settings.gateway_audience)
            server = uvicorn.Server(uvicorn.Config(create_proxy_app(settings), uds=socket_alias,
                                                   log_level="warning", access_log=False, lifespan="on"))
            thread = threading.Thread(target=server.run, daemon=True)
            thread.start()
            started = time.monotonic()
            while not server.started:
                if not thread.is_alive() or time.monotonic() - started > self.startup_timeout:
                    server.should_exit = True
                    thread.join(timeout=5)
                    os.close(directory_fd)
                    raise ValueError("Execution proxy failed to start")
                time.sleep(.01)
            os.chmod(socket_path, 0o666)
            proxy = _SupervisedProxy(binding, str(socket_path), str(certificate), str(key), server, thread, directory_fd)
            control_path = socket_path.with_name('c')
            if control_path.exists() or control_path.is_symlink():
                if not stat.S_ISSOCK(control_path.lstat().st_mode):
                    server.should_exit = True
                    thread.join(timeout=5)
                    os.close(directory_fd)
                    raise ValueError('Private proxy control path is unsafe')
                control_path.unlink()
            proxy.control = _PrivateProxyControl(f'/proc/self/fd/{directory_fd}/c', proxy)
            os.chmod(control_path, 0o600)
            self._active[identity] = proxy
            self._adopted.pop(identity, None)
            return {"certificate_thumbprint": binding.certificate_thumbprint, "proxy_endpoint": str(socket_path)}

    def stop(self, job_id, attempt_id, component_id, *, termination_confirmed=False):
        if not termination_confirmed:
            raise ValueError("Confirm runtime termination or node fencing before removing execution proxy")
        identity = (job_id, attempt_id, component_id)
        with self._lock:
            proxy = self._active.get(identity)
            if not proxy:
                adopted = self._adopted.get(identity)
                if adopted:
                    binding, path = adopted
                    try:
                        result = _private_proxy_operation(path, binding, 'stop', termination_confirmed=True)
                    except (FileNotFoundError, ConnectionRefusedError):
                        from pathlib import Path
                        return not Path(path).exists()
                    if result['running']:
                        return False
                    from pathlib import Path
                    Path(path).unlink(missing_ok=True)
                    self._adopted.pop(identity, None)
                    return True
                # Absence of a local handle cannot prove a foreign proxy stopped.
                from contextlib import ExitStack
                import os
                import stat
                with ExitStack() as stack:
                    self._owned_proxy_root(stack, self.root)
                    directory = self._directory(job_id, attempt_id, component_id, create=False)
                    metadata = directory / 'proxy-identity.json'
                    if metadata.is_symlink():
                        raise ValueError("Proxy identity cannot be a symbolic link")
                    if metadata.exists():
                        import json
                        from .executor import ExecutionIdentity
                        info = metadata.lstat()
                        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                                or info.st_mode & 0o077 or info.st_nlink != 1):
                            raise ValueError("Proxy identity ownership is unsafe")
                        saved = json.loads(metadata.read_text())
                        if (any(saved.get(key) != expected for key, expected in (
                                ("job_id", job_id), ("attempt_id", attempt_id), ("component_id", component_id)))
                                or type(saved.get("epoch")) is not int or saved["epoch"] < 1):
                            raise ValueError("Proxy identity belongs to another execution")
                        path = self.endpoint(ExecutionIdentity(job_id, attempt_id, component_id, saved['epoch']))
                        from pathlib import Path
                        if Path(path).exists() or Path(path).is_symlink():
                            return False
                    elif directory.exists() and any(directory.iterdir()):
                        raise ValueError("Proxy material has no trusted identity")
                    return True
            proxy.server.should_exit = True
            proxy.thread.join(timeout=10)
            if proxy.thread.is_alive():
                return False
            from pathlib import Path
            Path(proxy.socket_path).unlink(missing_ok=True)
            proxy.control.close()
            Path(proxy.socket_path).with_name('c').unlink(missing_ok=True)
            import os
            os.close(proxy.directory_fd)
            del self._active[identity]
            return True

    def purge(self, identity, *, termination_confirmed=False):
        """Delete this stopped execution's private proxy material, retaining audit.

        The caller must hold the node's OS component lock for the entire
        binding/reservation or purge lifecycle, plus exact purge authority.
        Unknown files and changed ownership fail closed before deletion. Audit
        is written before key deletion, so an interrupted purge cannot recreate
        a proxy and can resume without the deleted identity file.
        """
        import json
        import os
        import socket
        import stat
        import uuid
        from contextlib import ExitStack
        from dataclasses import asdict
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.exceptions import InvalidSignature
        from cryptography.x509.oid import ExtendedKeyUsageOID
        from .executor import ExecutionIdentity
        if termination_confirmed is not True:
            raise ValueError("Confirm runtime termination before purging private proxy material")
        if not isinstance(identity, ExecutionIdentity):
            raise ValueError("Purge requires an exact execution identity")
        expected = asdict(identity)
        owner = (identity.job_id, identity.attempt_id, identity.component_id)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

        def directory(stack, base, parts):
            current = os.dup(self._owned_proxy_root(stack, base))
            stack.callback(os.close, current)
            authority = os.fstat(current)
            for part in parts:
                parent = current
                try:
                    current = os.open(part, flags, dir_fd=parent)
                except FileNotFoundError:
                    return None
                stack.callback(os.close, current)
                info = os.fstat(current)
                if (info.st_uid != os.geteuid() or info.st_dev != authority.st_dev
                        or info.st_mode & 0o077):
                    raise ValueError("Private purge directory is not operator owned")
            return parent, current

        def inventory(descriptor, allowed, sockets=False):
            if descriptor is None:
                return {}
            files = {}
            for name in os.listdir(descriptor):
                if name not in allowed:
                    raise ValueError("Unknown private proxy material requires reconciliation")
                info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                valid_type = stat.S_ISSOCK(info.st_mode) if sockets else stat.S_ISREG(info.st_mode)
                if (not valid_type or info.st_nlink != 1 or info.st_uid != os.geteuid()
                        or info.st_dev != os.fstat(descriptor).st_dev
                        or not sockets and (info.st_mode & 0o077 or info.st_size > 65536)):
                    raise ValueError("Private proxy material has unsafe ownership or links")
                files[name] = info
            return files

        def read(descriptor, name, info):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            try:
                opened = os.fstat(fd)
                if (opened.st_dev, opened.st_ino, opened.st_size) != (info.st_dev, info.st_ino, info.st_size):
                    raise ValueError("Private proxy material changed")
                content = os.read(fd, 65537)
                if len(content) > 65536:
                    raise ValueError("Private proxy material exceeds bound")
                return content
            finally:
                os.close(fd)

        def same_identity(value):
            return (isinstance(value, dict) and type(value.get("epoch")) is int
                    and all(value.get(field) == item for field, item in expected.items()))

        def write_audit(descriptor, value):
            leaf = identity.key + ".json"
            temporary = identity.key + ".tmp-" + uuid.uuid4().hex
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
            try:
                with os.fdopen(fd, "wb") as output:
                    output.write(json.dumps(value, sort_keys=True).encode())
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, leaf, src_dir_fd=descriptor, dst_dir_fd=descriptor)
                os.fsync(descriptor)
            finally:
                try:
                    os.unlink(temporary, dir_fd=descriptor)
                except FileNotFoundError:
                    pass

        with self._lock, ExitStack() as stack:
            material = directory(stack, self.root, (identity.job_id, "attempts", identity.attempt_id, identity.component_id))
            sockets = directory(stack, self.socket_root, ("p", identity.key))
            material_fd, socket_fd = (material[1] if material else None), (sockets[1] if sockets else None)
            material_files = inventory(material_fd, {"proxy-key.pem", "proxy-cert.pem", "proxy-identity.json"})
            socket_files = inventory(socket_fd, {"s", "c"}, True)
            ledger_path = self.root / "purge-ledger"
            if ledger_path.is_symlink():
                raise ValueError("Purge audit directory cannot be a symlink")
            ledger_path.mkdir(mode=0o700, exist_ok=True)
            audit_directory = directory(stack, self.root, ("purge-ledger",))
            audit_fd = audit_directory[1]
            audit_name = identity.key + ".json"
            try:
                audit_info = os.stat(audit_name, dir_fd=audit_fd, follow_symlinks=False)
            except FileNotFoundError:
                audit = None
            else:
                if (not stat.S_ISREG(audit_info.st_mode) or audit_info.st_nlink != 1
                        or audit_info.st_uid != os.geteuid() or audit_info.st_mode & 0o077):
                    raise ValueError("Purge audit has unsafe ownership")
                audit = json.loads(read(audit_fd, audit_name, audit_info))
                if not same_identity(audit):
                    raise ValueError("Purge audit belongs to another execution")
            if "proxy-identity.json" in material_files:
                saved = json.loads(read(material_fd, "proxy-identity.json", material_files["proxy-identity.json"]))
                if not same_identity(saved) or set(saved) != set(expected) | {"space_id"}:
                    raise ValueError("Proxy material belongs to another execution")
                identifier(saved["space_id"])
                if audit and saved["space_id"] != audit["space_id"]:
                    raise ValueError("Proxy material changed its space binding")
                audit = audit or dict(saved, certificate_thumbprint=None, purged_at=None, status="purging")
            elif material_files and audit is None:
                raise ValueError("Proxy identity is missing; reconcile before purging keys")
            if audit is None:
                if socket_files:
                    raise ValueError("Unbound proxy sockets cannot be purged")
                audit = dict(expected, space_id=None, certificate_thumbprint=None, purged_at=None, status="purging")
            binding = None
            if "proxy-cert.pem" in material_files:
                cert = x509.load_pem_x509_certificate(read(material_fd, "proxy-cert.pem", material_files["proxy-cert.pem"]))
                try:
                    cert.verify_directly_issued_by(self.ca_certificate)
                    if (cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                            or ExtendedKeyUsageOID.CLIENT_AUTH not in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value):
                        raise ValueError()
                    if "proxy-key.pem" in material_files:
                        key = serialization.load_pem_private_key(read(material_fd, "proxy-key.pem", material_files["proxy-key.pem"]), password=None)
                        if cert.public_key().public_numbers() != key.public_key().public_numbers():
                            raise ValueError()
                except (ValueError, InvalidSignature, x509.ExtensionNotFound):
                    raise ValueError("Proxy certificate does not match its owned authority") from None
                thumbprint = certificate_thumbprint(cert.public_bytes(serialization.Encoding.DER))
                if audit["certificate_thumbprint"] not in (None, thumbprint):
                    raise ValueError("Proxy certificate changed after purge started")
                audit["certificate_thumbprint"] = thumbprint
            if audit["certificate_thumbprint"] and audit["space_id"]:
                binding = ExecutionBinding(identity.job_id, identity.attempt_id, identity.component_id,
                    audit["space_id"], identity.epoch, audit["certificate_thumbprint"]).validate()
            if owner not in self._active and socket_files:
                if binding is None:
                    raise ValueError("Proxy socket has no certificate binding")
                try:
                    _private_proxy_operation(self.endpoint(identity), binding, "status")
                except (FileNotFoundError, ConnectionRefusedError):
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                        probe.settimeout(.5)
                        try:
                            probe.connect(self.endpoint(identity))
                        except (FileNotFoundError, ConnectionRefusedError):
                            pass
                        else:
                            return False
                else:
                    self._adopted[owner] = (binding, self.endpoint(identity))
            active = self._active.get(owner)
            adopted = self._adopted.get(owner)
            actual = active.binding if active else adopted[0] if adopted else None
            if actual and (actual.epoch != identity.epoch or binding is None or actual != binding):
                raise ValueError("Active proxy differs from the purge certificate binding")
            # A stale refusal-proven socket needs no local handle; a live unknown
            # socket must not be treated as stopped merely because ours is absent.
            if owner in self._active or owner in self._adopted:
                if not self.stop(*owner, termination_confirmed=True):
                    return False
            elif socket_files and binding is None:
                return False
            if audit["purged_at"] and not material_files and not socket_files:
                return True
            write_audit(audit_fd, audit)
            for pair, names in ((material, material_files), (sockets, socket_files)):
                if pair is None:
                    continue
                parent_fd, descriptor = pair
                authority = os.fstat(descriptor)
                for name, info in names.items():
                    try:
                        current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                        raise ValueError("Private proxy material changed before deletion")
                    os.unlink(name, dir_fd=descriptor)
                    os.fsync(descriptor)
                leaf = identity.component_id if pair is material else identity.key
                current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (authority.st_dev, authority.st_ino):
                    raise ValueError("Private proxy purge directory changed")
                os.rmdir(leaf, dir_fd=parent_fd)
                os.fsync(parent_fd)
            audit["status"], audit["purged_at"] = "purged", time.time()
            write_audit(audit_fd, audit)
            self._adopted.pop(owner, None)
            return True

    def close(self):
        """Administrative process shutdown; it never confirms job termination."""
        with self._lock:
            for proxy in tuple(self._active.values()):
                proxy.server.should_exit = True
            for proxy in tuple(self._active.values()):
                proxy.thread.join(timeout=10)
                if not proxy.thread.is_alive():
                    import os
                    from pathlib import Path
                    proxy.control.close()
                    Path(proxy.socket_path).with_name('c').unlink(missing_ok=True)
                    os.close(proxy.directory_fd)
            self._active.clear()
            self._adopted.clear()
