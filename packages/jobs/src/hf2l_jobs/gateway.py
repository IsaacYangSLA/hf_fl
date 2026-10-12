"""Certificate-bound transfers. Origin locators never leave this trusted service."""
from __future__ import annotations

import base64
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
import hashlib
import math
import re
import time
from typing import Any
from urllib.parse import urlsplit

import httpx
import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.concurrency import run_in_threadpool

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_CHUNK = 65536


class GatewayError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code
        super().__init__(code)


def identifier(value):
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise GatewayError(422, "invalid_resource_identifier")
    return value


def certificate_thumbprint(der):
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()


def tls_context(ca_file, certificate="", key=""):
    import ssl
    context = ssl.create_default_context(cafile=ca_file or None)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if certificate:
        if not key:
            raise ValueError("Client certificate requires a private key")
        context.load_cert_chain(certificate, key)
    return context


def service_endpoint(value):
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Trusted service endpoint must be HTTPS without credentials, query, or fragment")
    if parsed.path not in ("", "/"):
        raise ValueError("Trusted service endpoint must be an origin")
    return value.rstrip("/")


@dataclass(frozen=True)
class GatewaySettings:
    auth: Any = field(repr=False)
    origin_endpoints: tuple[str, ...]
    gateway_audience: str = "hf2l-transfer"
    max_part_bytes: int = 64 * 1024 * 1024
    max_download_bytes: int = 1024 ** 4
    chunk_bytes: int = _CHUNK
    timeout_seconds: float = 300
    origin_ca_file: str = ""
    # HTTP is only for an explicitly chosen loopback storage fixture.
    allow_local_origin_http: bool = False

    def validate(self):
        self.auth.validate()
        if not self.auth.workloads_enabled or self.gateway_audience == self.auth.workload_audience:
            raise ValueError("Gateway requires a separate managed workload audience")
        if not self.origin_endpoints or self.max_part_bytes < 1 or self.max_download_bytes < 1:
            raise ValueError("Explicit origin allowlist and positive transfer limits are required")
        if not 1024 <= self.chunk_bytes <= 1024 * 1024 or self.timeout_seconds <= 0:
            raise ValueError("Invalid gateway streaming limits")
        for value in self.origin_endpoints:
            parsed = urlsplit(value)
            local = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
            if parsed.username or parsed.password or not parsed.hostname or parsed.query or parsed.fragment:
                raise ValueError("Invalid private origin")
            if parsed.scheme != "https" and not (self.allow_local_origin_http and local and parsed.scheme == "http"):
                raise ValueError("Origin requires HTTPS")
        return self

    def check_origin(self, grant):
        value = grant.get("url")
        if not isinstance(value, str):
            raise GatewayError(502, "invalid_origin_descriptor")
        try:
            parsed = urlsplit(value)
            port = parsed.port
            expiry = grant.get("expires_at")
            if type(expiry) not in (int, float) or not math.isfinite(expiry):
                raise ValueError()
        except (ValueError, TypeError):
            raise GatewayError(502, "invalid_origin_descriptor") from None
        if parsed.username or parsed.password or parsed.fragment:
            raise GatewayError(502, "invalid_origin_descriptor")
        for configured in self.origin_endpoints:
            allowed = urlsplit(configured)
            if (parsed.scheme, parsed.hostname, port or (443 if parsed.scheme == "https" else 80)) != (
                    allowed.scheme, allowed.hostname, allowed.port or (443 if allowed.scheme == "https" else 80)):
                continue
            prefix = allowed.path.rstrip("/")
            if prefix and not (parsed.path == prefix or parsed.path.startswith(prefix + "/")):
                continue
            if any(piece in (".", "..") for piece in parsed.path.split("/")):
                break
            if expiry <= time.time():
                raise GatewayError(409, "origin_descriptor_expired")
            headers = dict(grant.get("headers") or {})
            if any(name.lower() not in {"content-type", "content-md5", "content-length", "x-amz-checksum-sha256"} for name in headers):
                raise GatewayError(502, "invalid_origin_headers")
            return value, headers
        raise GatewayError(502, "origin_not_allowed")


class ExchangeTransferBackend:
    """Use the generic Exchange ledger and transfer service, with no manager dependency."""

    def __init__(self, service, transfers):
        self.service, self.transfers = service, transfers

    def authorize(self, principal, space):
        if principal.workload is None:
            raise GatewayError(401, "workload_identity_required")
        return self.service.verify_workload_grant(principal, space)

    def upload_grant(self, principal, space, record, attachment, number):
        result = self.transfers.grants(space, record, attachment, principal, [number])
        grants = result.get("grants", ())
        if len(grants) != 1 or grants[0].get("number") != number:
            raise GatewayError(502, "invalid_origin_descriptor")
        return grants[0]

    def begin_upload(self, principal, space, record, attachment, number):
        begin = getattr(self.transfers, "begin_gateway_put", None)
        if begin is None:
            raise GatewayError(503, "origin_mutation_fence_unavailable")
        return begin(principal, space, record, attachment, number)

    def finish_upload(self, handle):
        finish = getattr(self.transfers, "finish_gateway_put", None)
        if finish is None:
            raise GatewayError(503, "origin_mutation_fence_unavailable")
        return finish(handle)

    def download_grant(self, principal, space, record, attachment):
        return self.transfers.download(space, record, attachment, principal)


def _range(value, size):
    if value is None:
        return None
    match = re.fullmatch(r"bytes=(\d+)-(\d*)", value)
    if not match:
        raise GatewayError(416, "invalid_download_range")
    start = int(match[1])
    end = int(match[2]) if match[2] else size - 1
    if not 0 <= start <= end < size:
        raise GatewayError(416, "invalid_download_range")
    return start, end


def create_gateway_app(settings: GatewaySettings, backend, *, authenticator=None, http=None):
    """The app requires verified TLS scope state or a signed private backend assertion.

    Use start_mtls_server for a direct TLS edge. Ordinary uvicorn ingress cannot
    supply TLS identity; it needs the authenticated terminating edge instead.
    """
    settings.validate()
    from hf2l_exchange.auth import Authenticator, verified_backend_thumbprint
    from hf2l_exchange.domain import ExchangeError
    auth = authenticator or Authenticator(replace(settings.auth, workload_audience=settings.gateway_audience))
    client = http or httpx.AsyncClient(timeout=settings.timeout_seconds, follow_redirects=False, trust_env=False,
                                       verify=tls_context(settings.origin_ca_file))
    @asynccontextmanager
    async def lifespan(app):
        try:
            yield
        finally:
            if http is None:
                await client.aclose()
    app = FastAPI(title="HF2L managed transfer gateway", docs_url=None, redoc_url=None, openapi_url=None,
                  lifespan=lifespan)
    app.state.backend, app.state.settings = backend, settings

    @app.exception_handler(GatewayError)
    async def gateway_error(request, exc):
        return JSONResponse({"error": {"code": exc.code}}, status_code=exc.status)

    @app.exception_handler(ExchangeError)
    async def exchange_error(request, exc):
        return JSONResponse({"error": {"code": exc.code}}, status_code=exc.status)

    async def identity(request, space):
        # Never trust an unsigned client certificate header.
        authorization = request.headers.get("authorization", "")
        thumbprint = request.scope.get("state", {}).get("verified_certificate_thumbprint")
        if not thumbprint:
            target = request.url.path + ("?" + request.url.query if request.url.query else "")
            thumbprint = verified_backend_thumbprint(settings.auth, request.method, target, authorization, request.headers)
        try:
            scheme, token = authorization.split(" ", 1)
            header = jwt.get_unverified_header(token)
            if scheme.lower() != "bearer" or header.get("typ") != "at+jwt" or header.get("alg") != "RS256":
                raise ValueError()
            principal = auth._authenticate_workload(token, thumbprint)
            # Scope is checked only after signature, issuer, audience and cnf validation.
            claims = jwt.decode(token, auth.settings.workload_public_key, algorithms=["RS256"],
                                issuer=auth.settings.workload_issuer, audience=settings.gateway_audience,
                                options={"strict_aud": True})
            if "transfer" not in str(claims.get("scope", "")).split():
                raise ValueError()
        except (ValueError, AttributeError, jwt.PyJWTError):
            raise GatewayError(401, "invalid_workload_token") from None
        if principal.workload.space_id != space:
            raise GatewayError(404, "resource_not_found")
        await run_in_threadpool(backend.authorize, principal, space)
        return principal

    def check_request(request, *values):
        for value in values:
            identifier(value)
        if request.url.query:
            raise GatewayError(400, "unexpected_transfer_query")
        if any(name.lower() in {"cookie", "proxy-authorization", "x-forwarded-client-cert"} for name in request.headers):
            raise GatewayError(400, "forbidden_transfer_credentials")

    @app.put("/transfers/v1/spaces/{space}/records/{record}/attachments/{attachment}/parts/{number}")
    async def upload(request: Request, space: str, record: str, attachment: str, number: int):
        check_request(request, space, record, attachment)
        if not 1 <= number <= 10000:
            raise GatewayError(422, "invalid_part_number")
        principal = await identity(request, space)
        grant = await run_in_threadpool(backend.upload_grant, principal, space, record, attachment, number)
        expected = grant.get("size")
        if type(expected) is not int or not 0 <= expected <= settings.max_part_bytes:
            raise GatewayError(413, "part_too_large")
        try:
            declared = int(request.headers["content-length"])
        except (KeyError, ValueError):
            raise GatewayError(411, "content_length_required") from None
        if declared != expected or "transfer-encoding" in request.headers:
            raise GatewayError(400, "part_size_mismatch")
        settings.check_origin(grant)
        await run_in_threadpool(backend.authorize, principal, space)
        # Persist the exact attempt's provider mutation BEFORE any request bytes.
        # A signer/worker lease expiry never proves an admitted PUT has stopped.
        prepared = await run_in_threadpool(backend.begin_upload, principal, space, record, attachment, number)
        if not isinstance(prepared, tuple) or len(prepared) != 2:
            raise GatewayError(503, "invalid_origin_mutation_fence")
        mutation, grant = prepared
        if not isinstance(grant, dict) or type(grant.get("size")) is not int or grant["size"] != expected:
            raise GatewayError(503, "invalid_origin_mutation_fence")
        url, headers = settings.check_origin(grant)
        headers = {name: value for name, value in headers.items() if name.lower() != "content-length"}
        headers["Content-Length"] = str(expected)
        headers["Accept-Encoding"] = "identity"
        body_complete = False

        async def chunks():
            nonlocal body_complete
            total = 0
            async for chunk in request.stream():
                total += len(chunk)
                if total > expected:
                    raise GatewayError(400, "part_size_mismatch")
                for offset in range(0, len(chunk), settings.chunk_bytes):
                    yield chunk[offset:offset + settings.chunk_bytes]
            if total != expected:
                raise GatewayError(400, "part_size_mismatch")
            body_complete = True

        try:
            upstream = await client.send(client.build_request("PUT", url, content=chunks(), headers=headers), stream=True)
            try:
                if upstream.status_code not in (200, 201, 204) or not body_complete:
                    raise GatewayError(503, "origin_transfer_failed")
                # Do not buffer or expose origin error bodies, locations or credentials.
                etag = upstream.headers.get("etag", "")
            finally:
                await upstream.aclose()
            # Only a known successful ACK AND closed upstream may settle the
            # receipt. Cancellation, timeout, disconnect and close failure leave
            # its durable marker for explicit writers-stopped/provider-quiesced
            # repair; retirement must retain its cleanup and storage charge.
            if await run_in_threadpool(backend.finish_upload, mutation) is not True:
                raise GatewayError(503, "origin_mutation_not_settled")
            return Response(status_code=204, headers={"ETag": etag} if etag else {})
        except httpx.HTTPError:
            raise GatewayError(503, "origin_transfer_failed") from None

    @app.api_route("/transfers/v1/spaces/{space}/records/{record}/attachments/{attachment}/content", methods=["GET", "HEAD"])
    async def download(request: Request, space: str, record: str, attachment: str):
        check_request(request, space, record, attachment)
        principal = await identity(request, space)
        grant = await run_in_threadpool(backend.download_grant, principal, space, record, attachment)
        size, digest = grant.get("size"), grant.get("sha256")
        if type(size) is not int or not 0 <= size <= settings.max_download_bytes or not re.fullmatch(r"[a-f0-9]{64}", str(digest)):
            raise GatewayError(502, "invalid_origin_descriptor")
        selected = _range(request.headers.get("range"), size)
        count = selected[1] - selected[0] + 1 if selected else size
        headers = {"Content-Length": str(count), "X-Content-SHA256": digest,
                   "Accept-Ranges": "bytes", "Content-Type": "application/octet-stream",
                   "Content-Disposition": 'attachment; filename="checkpoint.bin"',
                   "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"}
        if selected:
            headers["Content-Range"] = f"bytes {selected[0]}-{selected[1]}/{size}"
        if request.method == "HEAD":
            return Response(status_code=206 if selected else 200, headers=headers)
        url, origin_headers = settings.check_origin(grant)
        origin_headers["Accept-Encoding"] = "identity"
        if selected:
            origin_headers["Range"] = f"bytes={selected[0]}-{selected[1]}"
        await run_in_threadpool(backend.authorize, principal, space)
        try:
            upstream = await client.send(client.build_request("GET", url, headers=origin_headers), stream=True)
        except httpx.HTTPError:
            raise GatewayError(503, "origin_transfer_failed") from None
        expected_status = 206 if selected else 200
        if upstream.status_code != expected_status:
            await upstream.aclose()
            raise GatewayError(503, "origin_transfer_failed")
        if selected and upstream.headers.get("content-range") != headers["Content-Range"]:
            await upstream.aclose()
            raise GatewayError(502, "invalid_origin_range")
        if upstream.headers.get("content-length") not in (None, str(count)):
            await upstream.aclose()
            raise GatewayError(502, "invalid_origin_size")

        async def content():
            total = 0
            try:
                async for chunk in upstream.aiter_bytes(settings.chunk_bytes):
                    total += len(chunk)
                    if total > count:
                        raise GatewayError(502, "invalid_origin_size")
                    yield chunk
                if total != count:
                    raise GatewayError(502, "invalid_origin_size")
            finally:
                await upstream.aclose()
        return StreamingResponse(content(), status_code=expected_status, headers=headers)

    return app
