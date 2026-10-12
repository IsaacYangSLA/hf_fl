"""Authorized HTTP and packaged dashboard for the multi-job control plane.

The application service owns every mutation and ACL transaction. This module
only translates bounded wire inputs, concurrency headers, and sessions.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import re
import secrets
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, quote
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException

from .domain import Error, JobSpec
from .authorization import principal_id

log = logging.getLogger("hf2l_jobs.http")
PREFIX = "/api/jobs/v1"
SESSION_COOKIE = "__Host-hf2l_jobs"
LOGIN_COOKIE = "__Host-hf2l_jobs_login"
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
       "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
       "form-action 'self'")
IDEMPOTENCY = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
REQUEST_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
ETAG = re.compile(r'^"([1-9][0-9]*)"$')
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ReconcileBody(Body):
    evidence: dict[str, Any]


class MemberBody(Body):
    role: Literal["reader", "operator", "admin"]


class ProgressBody(Body):
    current_round: int | None = Field(default=None, ge=0, le=1_000_000)
    phase: Literal["fetching", "building", "initializing", "aggregating",
                   "waiting_participants", "training", "publishing", "collecting_results"] | None = None
    publication_status: Literal["none", "absent", "confirmed", "published", "unknown",
                                "publishing", "ambiguous", "not_observed"] | None = None
    metrics: dict[str, int | float] | None = Field(default=None, max_length=32)
    readiness: Literal["initializing", "waiting", "ready", "training", "finished", "failed"] | None = None

    @model_validator(mode="after")
    def nonempty_progress(self):
        if all(value is None for value in (self.current_round, self.phase, self.publication_status,
                                            self.metrics, self.readiness)):
            raise ValueError("At least one progress field is required")
        return self

    @field_validator("metrics")
    @classmethod
    def finite_metrics(cls, value):
        if value is not None:
            for key, item in value.items():
                try:
                    valid = bool(key) and len(key) <= 64 and type(item) in (int, float) and math.isfinite(item)
                except OverflowError:
                    valid = False
                if not valid:
                    raise ValueError("Metrics require bounded keys and finite numeric values")
        return value


class LogBody(Body):
    entries: list[str] = Field(min_length=1, max_length=100)

    def bounded(self):
        if sum(len(value.encode("utf-8")) for value in self.entries) + len(self.entries) - 1 > 65536:
            raise Error(413, "log_batch_too_large")
        if any(len(value.encode("utf-8")) > 8192 for value in self.entries):
            raise Error(413, "log_line_too_large")
        return self.entries


class EnrollmentBody(Body):
    node_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class ParticipantAssignmentBody(Body):
    execution_certificate_thumbprint: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    proxy_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class ParticipantCertificateBody(Body):
    csr_pem: str = Field(min_length=1, max_length=16384)
    space_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    principal_id: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator("csr_pem")
    @classmethod
    def bounded_csr(cls, value):
        if (len(value.encode("utf-8")) > 16384 or
                not value.startswith("-----BEGIN CERTIFICATE REQUEST-----\n") or
                not value.rstrip().endswith("-----END CERTIFICATE REQUEST-----")):
            raise ValueError("A bounded PEM certificate signing request is required")
        return value


class NodeCredentialsBody(Body):
    certificate_thumbprint: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    audience: Literal["exchange", "gateway"]


class NodeResourcesBody(Body):
    cpu_millicores: int = Field(ge=0, le=1_000_000)
    memory_bytes: int = Field(ge=0, le=1 << 50)
    disk_bytes: int = Field(ge=0, le=1 << 50)


class NodeValidationBody(Body):
    node_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    pool_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    grant_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    certificate_thumbprint: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    scopes: list[str] = Field(min_length=1, max_length=32)
    resources: NodeResourcesBody

    @field_validator("scopes")
    @classmethod
    def known_scopes(cls, values):
        from .broker import NODE_SCOPES
        if len(set(values)) != len(values) or any(value not in NODE_SCOPES for value in values):
            raise ValueError("Fixed node execution scopes are required")
        return values


class ParticipantHeartbeatBody(Body):
    phase: Literal["running", "waiting_initialization", "waiting_for_model", "training",
                   "publishing", "completed", "retry", "needs_attention", "stopped"] = "running"
    current_round: int | None = Field(default=None, ge=0, le=1_000_000)


class StopBody(Body):
    termination_confirmed: bool = True

    @field_validator("termination_confirmed")
    @classmethod
    def confirmed(cls, value):
        if value is not True:
            raise ValueError("Termination must be authoritatively confirmed")
        return value


class ExecutionIdentityBody(Body):
    job_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    attempt_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    component_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    epoch: int = Field(ge=1, le=(1 << 63) - 1)


class ExternalLogReceiptBody(Body):
    identity: ExecutionIdentityBody
    source_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    offset: int = Field(ge=0, le=1_048_576)
    next_offset: int = Field(ge=0, le=1_048_576)
    content: str = Field(max_length=65536)
    complete: bool
    truncated: bool

    @model_validator(mode="after")
    def bounded_log_receipt(self):
        size = len(self.content.encode("utf-8"))
        if size > 65536 or self.next_offset != self.offset + size:
            raise ValueError("A bounded contiguous UTF-8 log receipt is required")
        from .executor import ExecutionIdentity
        if self.source_id != ExecutionIdentity(**self.identity.model_dump()).key:
            raise ValueError("The log source must match its exact execution")
        return self


class ExternalStopBody(StopBody):
    never_started: bool = False


class PurgeConfirmationBody(Body):
    confirmed: bool

    @field_validator("confirmed")
    @classmethod
    def confirmed_purge(cls, value):
        if value is not True:
            raise ValueError("Deletion must be authoritatively confirmed")
        return value


class PoolBody(Body):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    node_id: str | None = Field(default=None, min_length=1, max_length=128)
    cpu_millicores: int | None = Field(default=None, ge=0, le=1_000_000)
    memory_bytes: int | None = Field(default=None, ge=0, le=1 << 50)
    disk_bytes: int | None = Field(default=None, ge=0, le=1 << 50)
    gpu_uuids: list[str] | None = Field(default=None, max_length=1024)
    sandbox_profiles: list[str] | None = Field(default=None, max_length=128)
    gpu_profiles: list[str] | None = Field(default=None, max_length=128)
    healthy: bool | None = None
    quarantined: bool | None = None


def _error(status, code, request_id, detail="", headers=None):
    values = dict(SECURITY_HEADERS)
    values.update(headers or {})
    values["X-Request-ID"] = request_id
    return JSONResponse({"error": {"code": code, "detail": detail,
                                   "request_id": request_id}},
                        status_code=status, headers=values)


class RequestBoundary:
    """Bound parsing memory and enforce HTTPS without trusting forwarded headers."""
    def __init__(self, app, max_body_bytes=1_048_576, allow_local_http=False):
        self.app, self.limit, self.allow_local_http = app, max_body_bytes, allow_local_http

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        request_id = headers.get(b"x-request-id", b"").decode("ascii", errors="ignore")
        if not REQUEST_ID.fullmatch(request_id):
            request_id = uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id

        async def tagged_send(message):
            if message["type"] == "http.response.start":
                blocked = {name.lower().encode() for name in SECURITY_HEADERS} | {b"x-request-id"}
                message["headers"] = [(key, value) for key, value in message.get("headers", [])
                                      if key.lower() not in blocked]
                message["headers"] += [(key.lower().encode(), value.encode())
                                       for key, value in SECURITY_HEADERS.items()]
                message["headers"].append((b"x-request-id", request_id.encode()))
            await send(message)

        async def reject(status, code):
            await _error(status, code, request_id)(scope, receive, tagged_send)

        peer = (scope.get("client") or ("", 0))[0]
        try:
            local = ipaddress.ip_address(peer).is_loopback
        except ValueError:
            local = peer == "testclient"
        if scope.get("scheme") != "https" and not (self.allow_local_http and local):
            await reject(426, "https_required")
            return
        if b"content-length" in headers:
            try:
                declared = int(headers[b"content-length"])
            except ValueError:
                await reject(400, "invalid_content_length")
                return
            if declared < 0:
                await reject(400, "invalid_content_length")
                return
            if declared > self.limit:
                await reject(413, "request_too_large")
                return
        chunks = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            chunks.extend(message.get("body", b""))
            if len(chunks) > self.limit:
                await reject(413, "request_too_large")
                return
            if not message.get("more_body", False):
                break
        supplied = False

        async def replay_receive():
            nonlocal supplied
            if not supplied:
                supplied = True
                return {"type": "http.request", "body": bytes(chunks), "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, tagged_send)


class StreamCursor:
    """Principal-bound resume IDs contain no shared event sequence or job identity."""
    def __init__(self, secret: str | bytes, max_age=3600):
        self.secret = secret.encode() if isinstance(secret, str) else secret
        if len(self.secret) < 32:
            raise ValueError("SSE cursor secret must contain at least 32 bytes")
        self.max_age = max_age

    def issue(self, principal, snapshot=""):
        data = json.dumps({"p": principal_id(principal), "t": int(time.time()),
                           "n": secrets.token_hex(12), "s": snapshot},
                          sort_keys=True, separators=(",", ":")).encode()
        encoded = base64.urlsafe_b64encode(data).decode().rstrip("=")
        signature = hmac.new(self.secret, encoded.encode(), hashlib.sha256).hexdigest()
        return encoded + "." + signature

    def read(self, value, principal):
        try:
            if len(value) > 2048:
                raise ValueError
            encoded, signature = value.split(".")
            expected = hmac.new(self.secret, encoded.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature):
                raise ValueError
            data = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
            if data["p"] != principal_id(principal) or not isinstance(data["t"], int):
                raise ValueError
            age = int(time.time()) - data["t"]
            if age < -30:
                raise ValueError
            return None if age > self.max_age else data
        except (ValueError, KeyError, TypeError, UnicodeError, json.JSONDecodeError):
            raise Error(400, "invalid_event_cursor") from None


def _version(value):
    if value is None:
        raise Error(428, "if_match_required")
    match = ETAG.fullmatch(value)
    if match is None:
        raise Error(400, "invalid_if_match")
    return int(match.group(1))


def _idempotency(value):
    if value is None:
        raise Error(400, "idempotency_key_required")
    if not IDEMPOTENCY.fullmatch(value):
        raise Error(400, "invalid_idempotency_key")
    return value


def _view(value, status=200, location=None):
    headers = {}
    if isinstance(value, dict) and isinstance(value.get("version"), int):
        headers["ETag"] = '"' + str(value["version"]) + '"'
    if location:
        headers["Location"] = location
    return JSONResponse(jsonable_encoder(value), status_code=status, headers=headers)


def create_app(manager=None, auth_service=None, *, controller=None,
               readiness=None, artifact_broker=None, participants=None, managed_nodes=None, cursor_secret=None, allow_local_http=None,
               max_body_bytes=1_048_576,
               sse_poll_seconds=10.0):
    """Compose injected services, or load validated production settings.

    Tests inject a real SQL store/Manager and a deterministic authenticator.
    Internal routes fail closed unless a controller and verified mTLS identity
    are explicitly present; raw forwarded certificate headers are never read.
    """
    if (manager is None) != (auth_service is None):
        raise ValueError("Inject both Manager and AuthService, or neither")
    owned_services = None
    if manager is None:
        from .config import Settings
        from .composition import create_services
        settings = Settings.from_env(component="server")
        owned_services = create_services(settings)
        manager, auth_service = owned_services.manager, owned_services.auth
        controller = controller or owned_services.controller
        artifact_broker = artifact_broker or getattr(owned_services, "artifact_broker", None)
        participants = participants or getattr(owned_services, "participants", None)
        managed_nodes = managed_nodes or getattr(owned_services, "managed_nodes", None)
        cursor_secret = cursor_secret or settings.cursor_secret
        max_body_bytes = settings.max_body_bytes
        if allow_local_http is None:
            allow_local_http = settings.oidc.allow_local_http
    if cursor_secret is None:
        cursor_secret = getattr(manager, "cursor_secret",
            getattr(getattr(manager, "cursors", None), "secret", None))
    if cursor_secret is None:
        raise ValueError("A persistent SSE cursor secret is required")

    @asynccontextmanager
    async def lifespan(application):
        try:
            yield
        finally:
            if owned_services is not None:
                await run_in_threadpool(owned_services.close)

    cursors = StreamCursor(cursor_secret)
    app = FastAPI(title="HF2L Job Manager", version="0.1.0",
                  docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.manager, app.state.auth, app.state.controller = manager, auth_service, controller
    app.add_middleware(RequestBoundary, allow_local_http=bool(allow_local_http),
                       max_body_bytes=max_body_bytes)

    async def principal(request: Request):
        return await run_in_threadpool(
            auth_service.authenticate_request,
            authorization=request.headers.get("authorization", ""),
            session_token=request.cookies.get(SESSION_COOKIE, ""))

    async def mutation(request: Request, actor=Depends(principal)):
        # Bearer authentication is independent of browser cookies. A cookie
        # request must prove CSRF even when an Authorization header is present.
        token = request.cookies.get(SESSION_COOKIE, "")
        if token:
            await run_in_threadpool(auth_service.require_csrf, token,
                                    request.headers.get("x-csrf-token", ""),
                                    origin=request.headers.get("origin", ""))
        return actor

    @app.exception_handler(Error)
    async def job_error(request, exc):
        return _error(exc.status, exc.code, request.state.request_id,
                      getattr(exc, "detail", ""), getattr(exc, "headers", None))

    try:
        from .auth import AuthError
        app.add_exception_handler(AuthError, job_error)
    except ImportError:
        pass

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Never echo rejected source options, tokens, secrets, or log contents.
        return _error(422, "invalid_request", request.state.request_id)

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        return _error(exc.status_code, "not_found" if exc.status_code == 404 else "http_error",
                      request.state.request_id)

    @app.exception_handler(Exception)
    async def unexpected_error(request, exc):
        if hasattr(exc, "status") and hasattr(exc, "code"):
            return _error(exc.status, exc.code, request.state.request_id,
                          getattr(exc, "detail", ""), getattr(exc, "headers", None))
        log.error("job request failed class=%s request_id=%s", type(exc).__name__,
                  request.state.request_id)
        return _error(500, "internal_error", request.state.request_id)

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    @app.get("/readyz")
    def ready(request: Request):
        from .migrations import check_schema
        try:
            check_schema(manager.database.engine)
            if readiness:
                readiness()
        except Exception as exc:
            log.error("readiness failed class=%s", type(exc).__name__)
            return _error(503, "not_ready", request.state.request_id)
        return {"status": "ready"}

    @app.get("/auth/login")
    def login():
        start = auth_service.begin_login()
        response = RedirectResponse(start.authorization_url, status_code=303)
        response.set_cookie(LOGIN_COOKIE, start.state_cookie, max_age=600,
                            secure=True, httponly=True, samesite="lax", path="/")
        return response

    @app.get("/auth/callback")
    def callback(request: Request, code: str | None = Query(default=None, min_length=1, max_length=8192),
                 state: str | None = Query(default=None, min_length=1, max_length=1024),
                 error: str | None = Query(default=None, max_length=256)):
        try:
            if error or not code or not state:
                raise Error(400, "invalid_authorization_response")
            issue = auth_service.finish_login(code, state, request.cookies.get(LOGIN_COOKIE, ""))
            response = RedirectResponse("/dashboard/", status_code=303)
            response.set_cookie(SESSION_COOKIE, issue.session_token, max_age=8 * 3600,
                                secure=True, httponly=True, samesite="lax", path="/")
        except Exception as exc:
            if not hasattr(exc, "status") or not hasattr(exc, "code"):
                log.error("authorization callback failed class=%s", type(exc).__name__)
            response = _error(getattr(exc, "status", 502),
                              getattr(exc, "code", "authorization_unavailable"),
                              request.state.request_id)
        response.delete_cookie(LOGIN_COOKIE, secure=True, httponly=True, samesite="lax", path="/")
        return response

    @app.post("/auth/backchannel-logout")
    async def backchannel_logout(request: Request):
        if request.headers.get("content-type", "").split(";", 1)[0].lower() != "application/x-www-form-urlencoded":
            raise Error(415, "logout_form_required")
        try:
            fields = parse_qs((await request.body()).decode("utf-8"), strict_parsing=True, max_num_fields=1)
            if set(fields) != {"logout_token"} or len(fields["logout_token"]) != 1:
                raise ValueError()
            token = fields["logout_token"][0]
            if not 1 <= len(token) <= 16384:
                raise ValueError()
        except (ValueError, UnicodeError, KeyError):
            raise Error(400, "invalid_logout_request") from None
        await run_in_threadpool(auth_service.backchannel_logout, token)
        return {"accepted": True}

    @app.post("/auth/logout")
    def logout(request: Request):
        auth_service.logout(request.cookies.get(SESSION_COOKIE, ""),
                            request.headers.get("x-csrf-token", ""),
                            origin=request.headers.get("origin", ""))
        response = JSONResponse({"authenticated": False})
        response.delete_cookie(SESSION_COOKIE, secure=True, httponly=True, samesite="lax", path="/")
        return response

    @app.get("/auth/session")
    @app.get(PREFIX + "/session")
    def session(request: Request):
        cookie = request.cookies.get(SESSION_COOKIE, "")
        if cookie:
            return auth_service.session_info(cookie)
        if request.headers.get("authorization"):
            actor = auth_service.authenticate_request(
                authorization=request.headers["authorization"], session_token="")
            return {"authenticated": True,
                    "principal": {"principal_id": principal_id(actor),
                                  "display_name": getattr(actor, "display_name", principal_id(actor))},
                    "permissions": ["platform_operator"] if getattr(actor, "platform_operator", False) else [],
                    "csrf_token": None, "login_url": "/auth/login"}
        return {"authenticated": False, "login_url": "/auth/login"}

    @app.get(PREFIX + "/catalog")
    def catalog(actor=Depends(principal)):
        return manager.catalog(actor)

    @app.post(PREFIX + "/jobs", status_code=202)
    def create_job(body: JobSpec, actor=Depends(mutation),
                   idempotency_key: str | None = Header(default=None)):
        result = manager.create_job(actor, body.to_dict(), _idempotency(idempotency_key))
        identity = result.get("id", result.get("job_id"))
        return _view(result, 202, PREFIX + "/jobs/" + str(identity))

    @app.get(PREFIX + "/jobs")
    def list_jobs(actor=Depends(principal),
                  view: Literal["all", "current", "queued", "history"] = "all",
                  state: str | None = Query(default=None, max_length=64),
                  project_id: str | None = Query(default=None, max_length=128),
                  search: str | None = Query(default=None, max_length=200),
                  limit: int = Query(default=50, ge=1, le=100),
                  cursor: str | None = Query(default=None, max_length=4096)):
        filters = {key: value for key, value in {"view": view, "state": state,
                   "project_id": project_id, "search": search}.items() if value is not None}
        return manager.list_jobs(actor, filters=filters, limit=limit, cursor=cursor)

    @app.get(PREFIX + "/jobs/{job_id}")
    def get_job(job_id: str, actor=Depends(principal)):
        return _view(manager.get_job(actor, job_id))

    @app.get(PREFIX + "/jobs/{job_id}/attempts")
    def attempts(job_id: str, actor=Depends(principal)):
        return manager.list_attempts(actor, job_id)

    @app.get(PREFIX + "/jobs/{job_id}/events")
    def events(job_id: str, actor=Depends(principal),
               limit: int = Query(default=100, ge=1, le=100),
               cursor: str | None = Query(default=None, max_length=4096)):
        return manager.list_events(actor, job_id, limit=limit, cursor=cursor)

    @app.get(PREFIX + "/jobs/{job_id}/logs")
    def logs(job_id: str, actor=Depends(principal),
             limit: int = Query(default=100, ge=1, le=100),
             cursor: str | None = Query(default=None, max_length=4096),
             component: str | None = Query(default=None, max_length=128),
             attempt: int | None = Query(default=None, ge=1)):
        return manager.list_logs(actor, job_id, limit=limit, cursor=cursor,
                                 component=component, attempt=attempt)

    @app.get(PREFIX + "/jobs/{job_id}/artifacts")
    def artifacts(job_id: str, actor=Depends(principal),
                  limit: int = Query(default=100, ge=1, le=100),
                  cursor: str | None = Query(default=None, max_length=4096)):
        result = manager.list_artifacts(actor, job_id, limit=limit, cursor=cursor)
        if artifact_broker is None:
            result = {**result, "items": [{**item, "download_available": False,
                "unavailable_reason": "artifact_broker_unavailable"} for item in result["items"]]}
        return result

    @app.get(PREFIX + "/jobs/{job_id}/artifacts/{artifact_id}")
    def artifact(job_id: str, artifact_id: str, actor=Depends(principal)):
        result = manager.get_artifact(actor, job_id, artifact_id)
        # Never expose a private origin URL or host file path in public metadata.
        if artifact_broker is None:
            result = {**result, "download_available": False,
                      "unavailable_reason": "artifact_broker_unavailable"}
        return result

    @app.get(PREFIX + "/jobs/{job_id}/artifacts/{artifact_id}/download")
    async def download_artifact(request: Request, job_id: str, artifact_id: str, actor=Depends(principal)):
        # Conceal foreign jobs even when this deployment has no broker enabled.
        await run_in_threadpool(manager.get_artifact, actor, job_id, artifact_id)
        if artifact_broker is None:
            raise Error(503, "artifact_broker_unavailable")
        context = artifact_broker.open_authorized(actor, job_id, artifact_id)
        try:
            download = await context.__aenter__()
        except Exception as exc:
            if hasattr(exc, "status") and hasattr(exc, "code"):
                raise Error(exc.status, exc.code) from None
            raise
        if type(download.size) is not int or download.size < 0:
            await context.__aexit__(None, None, None)
            raise Error(502, "invalid_artifact_descriptor")

        async def content():
            try:
                async for chunk in download.chunks:
                    # Revocation/expiration also interrupts an existing download.
                    fresh = await run_in_threadpool(auth_service.authenticate_request,
                        authorization=request.headers.get("authorization", ""),
                        session_token=request.cookies.get(SESSION_COOKIE, ""), touch=False)
                    if principal_id(fresh) != principal_id(actor):
                        return
                    current = await run_in_threadpool(manager.get_artifact, fresh, job_id, artifact_id)
                    if not current.get("download_available", False):
                        return
                    yield chunk
            finally:
                await context.__aexit__(None, None, None)

        filename = quote(str(download.name), safe="")
        headers = {"Content-Disposition": "attachment; filename=artifact.bin; filename*=UTF-8''" + filename,
                   "Content-Length": str(download.size), "X-Content-Type-Options": "nosniff"}
        return StreamingResponse(content(), media_type="application/octet-stream", headers=headers)

    @app.get(PREFIX + "/jobs/{job_id}/members")
    def members(job_id: str, actor=Depends(principal)):
        return manager.list_members(actor, job_id)

    @app.put(PREFIX + "/jobs/{job_id}/members/{member_id}")
    def put_member(job_id: str, member_id: str, body: MemberBody,
                   actor=Depends(mutation), if_match: str | None = Header(default=None),
                   idempotency_key: str | None = Header(default=None)):
        return _view(manager.put_member(actor, job_id, member_id, body.role,
                                        _version(if_match), _idempotency(idempotency_key)))

    @app.delete(PREFIX + "/jobs/{job_id}/members/{member_id}")
    def delete_member(job_id: str, member_id: str, actor=Depends(mutation),
                      if_match: str | None = Header(default=None),
                      idempotency_key: str | None = Header(default=None)):
        return _view(manager.delete_member(actor, job_id, member_id,
                                           _version(if_match), _idempotency(idempotency_key)))

    @app.post(PREFIX + "/jobs/{job_id}/cancel", status_code=202)
    def cancel(job_id: str, actor=Depends(mutation),
               if_match: str | None = Header(default=None),
               idempotency_key: str | None = Header(default=None)):
        return _view(manager.cancel(actor, job_id, _version(if_match),
                                    _idempotency(idempotency_key)), 202)

    @app.post(PREFIX + "/jobs/{job_id}/retry", status_code=202)
    def retry(job_id: str, actor=Depends(mutation),
              if_match: str | None = Header(default=None),
              idempotency_key: str | None = Header(default=None)):
        return _view(manager.retry(actor, job_id, _version(if_match),
                                   _idempotency(idempotency_key)), 202)

    @app.post(PREFIX + "/jobs/{job_id}/reconcile", status_code=202)
    def reconcile(job_id: str, body: ReconcileBody, actor=Depends(mutation),
                  if_match: str | None = Header(default=None),
                  idempotency_key: str | None = Header(default=None)):
        return _view(manager.reconcile(actor, job_id, _version(if_match),
                                       _idempotency(idempotency_key), body.evidence), 202)

    @app.post(PREFIX + "/jobs/{job_id}/purge", status_code=202)
    def purge(job_id: str, actor=Depends(mutation),
              if_match: str | None = Header(default=None),
              idempotency_key: str | None = Header(default=None)):
        return _view(manager.purge(actor, job_id, _version(if_match),
                                   _idempotency(idempotency_key)), 202)

    @app.get(PREFIX + "/pools")
    def pools(actor=Depends(principal)):
        return manager.list_pools(actor)

    @app.put(PREFIX + "/pools/{pool_id}")
    def put_pool(pool_id: str, body: PoolBody, actor=Depends(mutation),
                 if_match: str | None = Header(default=None)):
        values = body.model_dump(exclude_none=True)
        if if_match is not None:
            values["expected_version"] = _version(if_match)
        return _view(manager.put_pool(actor, pool_id, values))

    async def visible_snapshot(actor):
        if hasattr(manager, "visible_revision"):
            return await run_in_threadpool(manager.visible_revision, actor)
        cursor, rows = None, []
        while True:
            result = await run_in_threadpool(manager.list_jobs, actor,
                                            filters={"view": "all"}, limit=100, cursor=cursor)
            rows.extend((value.get("id", value.get("job_id")), value.get("version"))
                        for value in result.get("items", []))
            cursor = result.get("next_cursor")
            if not cursor:
                break
        return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()

    @app.get(PREFIX + "/events/stream")
    async def stream(request: Request, actor=Depends(principal),
                     last_event_id: str | None = Header(default=None)):
        prior = cursors.read(last_event_id, actor) if last_event_id else {}
        snapshot = await visible_snapshot(actor)

        async def produce():
            current = snapshot
            event = "reset" if prior is None else "invalidated"
            token = cursors.issue(actor, current)
            yield "event: " + event + "\nid: " + token + "\ndata: {\"refetch\":true}\n\n"
            while not await request.is_disconnected():
                await asyncio.sleep(max(0.05, sse_poll_seconds))
                try:
                    fresh = await run_in_threadpool(auth_service.authenticate_request,
                        authorization=request.headers.get("authorization", ""),
                        session_token=request.cookies.get(SESSION_COOKIE, ""), touch=False)
                    if principal_id(fresh) != principal_id(actor):
                        return
                    latest = await visible_snapshot(fresh)
                except Exception as exc:
                    if hasattr(exc, "status") and exc.status in {401, 403, 404}:
                        yield 'event: session_expired\ndata: {"refetch":true}\n\n'
                        return
                    # A database/provider outage never reuses stale authorization.
                    return
                if latest != current:
                    current = latest
                    yield ("event: invalidated\nid: " + cursors.issue(fresh, current) +
                           '\ndata: {"refetch":true}\n\n')
                else:
                    yield ": keepalive\n\n"
        return StreamingResponse(produce(), media_type="text/event-stream",
                                 headers={"X-Accel-Buffering": "no"})

    def verified_node_thumbprint(request):
        # Both keys are populated only by trusted ASGI/TLS adapters, never headers.
        thumbprint = request.scope.get("hf2l.verified_peer_thumbprint", "") or request.scope.get(
            "state", {}).get("verified_certificate_thumbprint", "")
        if not thumbprint:
            raise Error(401, "verified_node_certificate_required")
        return thumbprint

    async def node_identity(request: Request, scope_name, job_id, attempt_id, component_id, epoch):
        thumbprint = verified_node_thumbprint(request)
        try:
            actor = await run_in_threadpool(auth_service.authenticate_node,
                request.headers.get("authorization", ""), thumbprint)
        except ValueError:
            raise Error(401, "invalid_node_grant") from None
        if (getattr(actor, "job_id", None), getattr(actor, "attempt_id", None),
            getattr(actor, "component_id", None), getattr(actor, "epoch", None)) != (
                job_id, attempt_id, component_id, epoch):
            raise Error(404, "assignment_not_found")
        if scope_name not in getattr(actor, "scopes", ()):
            raise Error(403, "node_scope_required")
        return actor

    async def node(request: Request, scope_name, job_id, attempt_id, component_id, epoch):
        if controller is None:
            raise Error(503, "node_control_unavailable")
        actor = await node_identity(request, scope_name, job_id, attempt_id, component_id, epoch)
        valid = await run_in_threadpool(controller.check_assignment,
            getattr(actor, "node_id", ""), getattr(actor, "pool_id", ""),
            job_id, attempt_id, component_id, epoch)
        if not valid:
            raise Error(404, "assignment_not_found")
        return actor

    internal = "/internal/jobs/v1/assignments/{job_id}/{attempt_id}/{component_id}/{epoch}"

    @app.post(internal + "/ack")
    async def acknowledge(request: Request, job_id: str, attempt_id: str,
                          component_id: str, epoch: int):
        await node(request, "acknowledge", job_id, attempt_id, component_id, epoch)
        result = await run_in_threadpool(controller.ack_assignment,
                                         job_id, attempt_id, component_id, epoch)
        if not result:
            raise Error(409, "stale_assignment")
        return {"accepted": True}

    @app.post(internal + "/heartbeat")
    async def heartbeat(request: Request, job_id: str, attempt_id: str,
                        component_id: str, epoch: int):
        await node(request, "heartbeat", job_id, attempt_id, component_id, epoch)
        result = await run_in_threadpool(controller.heartbeat,
                                         job_id, attempt_id, component_id, epoch)
        if not result:
            raise Error(409, "stale_assignment")
        return {"accepted": True}

    @app.post(internal + "/progress")
    async def progress(request: Request, job_id: str, attempt_id: str,
                       component_id: str, epoch: int, body: ProgressBody):
        await node(request, "progress", job_id, attempt_id, component_id, epoch)
        result = await run_in_threadpool(controller.progress, job_id, attempt_id,
            component_id, epoch, **body.model_dump(exclude_none=True))
        if not result:
            raise Error(409, "stale_assignment")
        return {"accepted": True}

    @app.post(internal + "/logs")
    async def node_logs(request: Request, job_id: str, attempt_id: str,
                        component_id: str, epoch: int, body: LogBody):
        await node(request, "logs", job_id, attempt_id, component_id, epoch)
        result = await run_in_threadpool(controller.append_logs, job_id, attempt_id,
                                         component_id, epoch, data="\n".join(body.bounded()))
        if not result:
            raise Error(409, "stale_assignment")
        return {"accepted": True}

    @app.post(internal + "/stopped")
    async def stopped(request: Request, job_id: str, attempt_id: str,
                      component_id: str, epoch: int):
        await node(request, "stopped", job_id, attempt_id, component_id, epoch)
        result = await run_in_threadpool(controller.stop_confirmation,
                                         job_id, attempt_id, component_id, epoch)
        if not result:
            raise Error(409, "stale_assignment")
        return {"accepted": True}

    managed = "/internal/jobs/v1/nodes/{job_id}/{attempt_id}/{component_id}/{epoch}"

    def require_managed_nodes():
        if managed_nodes is None:
            raise Error(503, "managed_node_control_unavailable")

    async def managed_call(method, *args, **kwargs):
        try:
            return await run_in_threadpool(method, *args, **kwargs)
        except Exception as exc:
            if hasattr(exc, "status") and hasattr(exc, "code"):
                raise Error(exc.status, exc.code) from None
            raise

    async def managed_actor(request, job_id, attempt_id, component_id, epoch):
        require_managed_nodes()
        thumbprint = verified_node_thumbprint(request)
        actor = await managed_call(managed_nodes.authenticate_node,
            request.headers.get("authorization", ""), verified_peer_thumbprint=thumbprint)
        if (getattr(actor, "job_id", None), getattr(actor, "attempt_id", None),
            getattr(actor, "component_id", None), getattr(actor, "epoch", None)) != (
                job_id, attempt_id, component_id, epoch):
            raise Error(404, "assignment_not_found")
        if "assignment" not in getattr(actor, "scopes", ()):
            raise Error(403, "node_scope_required")
        return actor

    @app.post(managed + "/bootstrap")
    async def managed_bootstrap(request: Request, job_id: str, attempt_id: str,
                                component_id: str, epoch: int, body: Body = Body()):
        require_managed_nodes()
        thumbprint = verified_node_thumbprint(request)
        if request.headers.get("authorization") or request.cookies.get(SESSION_COOKIE):
            raise Error(401, "registered_node_certificate_required")
        return await managed_call(managed_nodes.bootstrap, thumbprint,
            job_id=job_id, attempt_id=attempt_id, component_id=component_id, epoch=epoch)

    @app.get(managed + "/plan")
    async def managed_plan(request: Request, job_id: str, attempt_id: str,
                           component_id: str, epoch: int):
        actor = await managed_actor(request, job_id, attempt_id, component_id, epoch)
        return await managed_call(managed_nodes.assignment, actor)

    @app.post(managed + "/certificate")
    async def managed_certificate(request: Request, job_id: str, attempt_id: str,
                                  component_id: str, epoch: int, body: ParticipantCertificateBody):
        actor = await managed_actor(request, job_id, attempt_id, component_id, epoch)
        return await managed_call(managed_nodes.issue_certificate, actor, **body.model_dump())

    @app.post(managed + "/credentials")
    async def managed_credentials(request: Request, job_id: str, attempt_id: str,
                                  component_id: str, epoch: int, body: NodeCredentialsBody):
        actor = await managed_actor(request, job_id, attempt_id, component_id, epoch)
        return await managed_call(managed_nodes.credentials, actor, **body.model_dump())

    @app.post(managed + "/validate")
    async def managed_validate(request: Request, job_id: str, attempt_id: str,
                               component_id: str, epoch: int, body: NodeValidationBody):
        actor = await managed_actor(request, job_id, attempt_id, component_id, epoch)
        return await managed_call(managed_nodes.validate, actor, **body.model_dump())

    @app.post(PREFIX + "/jobs/{job_id}/participants/{participant_id}/enroll", status_code=202)
    def enroll_participant(job_id: str, participant_id: str, body: EnrollmentBody,
                           actor=Depends(mutation), if_match: str | None = Header(default=None),
                           idempotency_key: str | None = Header(default=None)):
        if participants is None:
            manager.get_job(actor, job_id)
            raise Error(503, "participant_enrollment_unavailable")
        result = participants.enroll(actor, job_id, participant_id, body.node_id,
                                     _version(if_match), _idempotency(idempotency_key))
        return _view(result, 202, PREFIX + "/jobs/" + job_id + "/participants/" +
                     participant_id + "/enrollment")

    @app.get(PREFIX + "/jobs/{job_id}/participants/{participant_id}/enrollment")
    def participant_enrollment(job_id: str, participant_id: str, actor=Depends(principal)):
        if participants is None:
            manager.get_job(actor, job_id)
            raise Error(503, "participant_enrollment_unavailable")
        return participants.get_enrollment(actor, job_id, participant_id)

    external = "/internal/jobs/v1/participants/{job_id}/{attempt_id}/{component_id}/{epoch}"

    async def external_actor(request, scope_name, job_id, attempt_id, component_id, epoch):
        if participants is None:
            raise Error(503, "participant_enrollment_unavailable")
        return await node_identity(request, scope_name, job_id, attempt_id, component_id, epoch)

    @app.get(external + "/plan")
    async def participant_plan(request: Request, job_id: str, attempt_id: str,
                               component_id: str, epoch: int):
        actor = await external_actor(request, "assignment", job_id, attempt_id, component_id, epoch)
        return await run_in_threadpool(participants.assignment_plan, actor)

    @app.get(external + "/control")
    async def participant_control(request: Request, job_id: str, attempt_id: str,
                                  component_id: str, epoch: int):
        actor = await external_actor(request, "stopped", job_id, attempt_id, component_id, epoch)
        return await run_in_threadpool(participants.control_plan, actor)

    @app.post(external + "/heartbeat")
    async def participant_heartbeat(request: Request, job_id: str, attempt_id: str,
                                    component_id: str, epoch: int, body: ParticipantHeartbeatBody):
        actor = await external_actor(request, "heartbeat", job_id, attempt_id, component_id, epoch)
        return await run_in_threadpool(participants.heartbeat, actor, **body.model_dump(exclude_none=True))

    @app.post(external + "/assignment")
    async def participant_assignment(request: Request, job_id: str, attempt_id: str,
                                     component_id: str, epoch: int, body: ParticipantAssignmentBody):
        actor = await external_actor(request, "assignment", job_id, attempt_id, component_id, epoch)
        return await run_in_threadpool(participants.assignment, actor, **body.model_dump())

    @app.post(external + "/certificate")
    async def participant_certificate(request: Request, job_id: str, attempt_id: str,
                                      component_id: str, epoch: int, body: ParticipantCertificateBody):
        actor = await external_actor(request, "assignment", job_id, attempt_id, component_id, epoch)
        return await run_in_threadpool(participants.issue_certificate, actor, **body.model_dump())

    @app.post(external + "/credentials")
    async def participant_credentials(request: Request, job_id: str, attempt_id: str,
                                      component_id: str, epoch: int):
        actor = await external_actor(request, "assignment", job_id, attempt_id, component_id, epoch)
        return await run_in_threadpool(participants.credentials, actor)

    @app.post(external + "/stopped")
    async def participant_stopped(request: Request, job_id: str, attempt_id: str,
                                  component_id: str, epoch: int, body: ExternalStopBody):
        actor = await external_actor(request, "stopped", job_id, attempt_id, component_id, epoch)
        return await run_in_threadpool(participants.confirm_stopped, actor,
            termination_confirmed=body.termination_confirmed, never_started=body.never_started)

    @app.post(external + "/logs")
    async def participant_logs(request: Request, job_id: str, attempt_id: str,
                                component_id: str, epoch: int, body: ExternalLogReceiptBody):
        actor = await external_actor(request, "logs", job_id, attempt_id, component_id, epoch)
        if body.identity.model_dump() != {"job_id": job_id, "attempt_id": attempt_id,
                "component_id": component_id, "epoch": epoch}:
            raise Error(404, "assignment_not_found")
        return await run_in_threadpool(participants.append_logs, actor, body.model_dump())

    @app.get(external + "/purge-plan")
    async def participant_purge_plan(request: Request, job_id: str, attempt_id: str,
                                    component_id: str, epoch: int):
        actor = await external_actor(request, "purge", job_id, attempt_id, component_id, epoch)
        return await run_in_threadpool(participants.purge_plan, actor)

    @app.post(external + "/purged")
    async def participant_purged(request: Request, job_id: str, attempt_id: str,
                                 component_id: str, epoch: int, body: PurgeConfirmationBody):
        actor = await external_actor(request, "purge", job_id, attempt_id, component_id, epoch)
        return await run_in_threadpool(participants.confirm_purged, actor, confirmed=body.confirmed)

    @app.get(external + "/build-products/{filename}")
    async def participant_build_product(request: Request, job_id: str, attempt_id: str,
                                         component_id: str, epoch: int, filename: str):
        actor = await external_actor(request, "assignment", job_id, attempt_id, component_id, epoch)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+\-]{0,240}\.whl", filename):
            raise Error(422, "invalid_build_product_name")
        product = await run_in_threadpool(participants.open_build_product, actor, filename)
        if (type(product.size_bytes) is not int or product.size_bytes < 0 or
                not isinstance(product.sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", product.sha256)):
            await run_in_threadpool(product.close)
            raise Error(502, "invalid_build_product_descriptor")
        chunks = product.chunks()

        async def contents():
            try:
                while True:
                    chunk = await run_in_threadpool(next, chunks, None)
                    if chunk is None:
                        break
                    fresh = await external_actor(request, "assignment", job_id, attempt_id, component_id, epoch)
                    if not await run_in_threadpool(participants.build_access_valid, fresh):
                        return
                    yield chunk
            finally:
                await run_in_threadpool(product.close)

        return StreamingResponse(contents(), media_type="application/octet-stream",
            headers={"Content-Length": str(product.size_bytes), "X-Content-SHA256": product.sha256,
                      "Content-Disposition": "attachment; filename=build.whl; filename*=UTF-8''" + quote(filename, safe="")})

    @app.get(external + "/source/{relative_path:path}")
    async def participant_source(request: Request, job_id: str, attempt_id: str,
                                 component_id: str, epoch: int, relative_path: str):
        actor = await external_actor(request, "assignment", job_id, attempt_id, component_id, epoch)
        if not relative_path or len(relative_path) > 1024:
            raise Error(422, "invalid_source_path")
        source = await run_in_threadpool(participants.open_source, actor, relative_path)
        if (type(source.size_bytes) is not int or source.size_bytes < 0 or
                not isinstance(source.sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", source.sha256)):
            await run_in_threadpool(source.close)
            raise Error(502, "invalid_source_descriptor")
        chunks = source.chunks()

        async def contents():
            try:
                while True:
                    chunk = await run_in_threadpool(next, chunks, None)
                    if chunk is None:
                        break
                    # The short node grant and enrollment must remain current.
                    fresh = await external_actor(request, "assignment", job_id, attempt_id, component_id, epoch)
                    if not await run_in_threadpool(participants.source_access_valid, fresh):
                        return
                    yield chunk
            finally:
                await run_in_threadpool(source.close)

        name = quote(relative_path.rsplit("/", 1)[-1], safe="")
        return StreamingResponse(contents(), media_type="application/octet-stream",
            headers={"Content-Length": str(source.size_bytes), "X-Content-SHA256": source.sha256,
                     "Content-Disposition": "attachment; filename=source.bin; filename*=UTF-8''" + name})

    @app.get("/")
    def home():
        return RedirectResponse("/dashboard/", status_code=303)

    @app.get("/dashboard")
    def dashboard_redirect():
        return RedirectResponse("/dashboard/", status_code=303)

    static = Path(__file__).with_name("static")
    if static.is_dir():
        app.mount("/dashboard", StaticFiles(directory=str(static), html=True), name="dashboard")
    return app
