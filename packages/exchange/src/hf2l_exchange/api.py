"""HTTP translation and composition for the generic exchange API.

Application commands own authorization and transactions. Routes validate only
wire structure, translate concurrency headers, and invoke those commands.
"""
from __future__ import annotations

import logging
import ipaddress
import re
import time
import uuid
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, Path, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException

from .domain import ExchangeError

log = logging.getLogger("hf2l_exchange.http")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
Role = Literal["reader", "contributor", "publisher", "admin"]


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SpaceBody(Body):
    name: str = Field(min_length=1, max_length=128)
    profile: str = "generic.v1"
    quota_bytes: int = Field(default=10 * 1024**3, ge=1, le=2**63 - 1)
    principal_quota_bytes: int = Field(default=10 * 1024**3, ge=1, le=2**63 - 1)
    quota_records: int = Field(default=100000, ge=1, le=2**63 - 1)
    quota_metadata_bytes: int = Field(default=1024**3, ge=1, le=2**63 - 1)


class SpaceLimitsBody(Body):
    quota_bytes: int | None = Field(default=None, ge=1, le=2**63 - 1)
    principal_quota_bytes: int | None = Field(default=None, ge=1, le=2**63 - 1)
    quota_records: int | None = Field(default=None, ge=1, le=2**63 - 1)
    quota_metadata_bytes: int | None = Field(default=None, ge=1, le=2**63 - 1)


class MemberBody(Body):
    roles: list[Role] = Field(max_length=4)
    subject: str | None = Field(default=None, max_length=256)
    bindings: dict[str, Any] = Field(default_factory=dict)


class PolicyBody(Body):
    publish_roles: list[Role] = Field(default_factory=lambda: ["contributor", "publisher"], max_length=4)
    visibility: Literal["shared", "private"] = "shared"


class TypeBody(Body):
    # Omitted values belong to the selected profile, not the HTTP transport.
    publish_roles: list[Role] | None = Field(default=None, min_length=1, max_length=4)
    visibility: Literal["shared", "private"] | None = None
    schema_document: dict[str, Any] = Field(alias="schema")


class AttachmentBody(Body):
    path: str = Field(min_length=1, max_length=256)
    size: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    media_type: str | None = Field(default=None, max_length=255)


class RecordBody(Body):
    kind: str = Field(min_length=1, max_length=128)
    schema_revision_id: str = Field(min_length=1, max_length=128)
    metadata: dict[str, Any] = Field(default_factory=dict)
    attachments: list[AttachmentBody] = Field(default_factory=list, max_length=256)


class PatchBody(Body):
    metadata: dict[str, Any]


class ReferenceBody(Body):
    record_id: str = Field(min_length=1, max_length=128)


class AcquisitionBody(Body):
    reference: str = Field(min_length=1, max_length=128)
    expected_token: str = Field(min_length=1, max_length=128)
    input_record_ids: list[str] = Field(default_factory=list, max_length=1000)
    lease_seconds: int | None = Field(default=None, ge=10, le=3600)


class FenceBody(Body):
    fence: int = Field(ge=1)


class CompletionBody(FenceBody):
    result_record_id: str = Field(min_length=1, max_length=128)


class GrantsBody(Body):
    numbers: list[int] = Field(min_length=1, max_length=1000)


def payload(body: Body) -> dict:
    return body.model_dump(by_alias=True, exclude_none=True)


def _error(status: int, code: str, request_id: str, detail: str = "", headers=None):
    response_headers = dict(headers or {})
    response_headers["X-Request-ID"] = request_id
    return JSONResponse({"error": {"code": code, "detail": detail, "request_id": request_id}},
                        status_code=status, headers=response_headers)


class RequestBoundary:
    """Bound request memory before parsing, attach IDs, and log no request bodies."""

    def __init__(self, app, max_body_bytes: int, allow_local_http: bool):
        self.app = app
        self.limit = max_body_bytes
        self.allow_local_http = allow_local_http

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        supplied_id = headers.get(b"x-request-id", b"").decode("ascii", errors="ignore")
        request_id = supplied_id if _REQUEST_ID.fullmatch(supplied_id) else uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id
        status = 500
        started = time.monotonic()

        async def tagged_send(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                message["headers"] = [(k, v) for k, v in message.get("headers", [])
                                      if k.lower() != b"x-request-id"] + [(b"x-request-id", request_id.encode())]
            await send(message)

        async def reject(code, text):
            await _error(code, text, request_id)(scope, receive, tagged_send)

        try:
            peer = (scope.get("client") or ("", 0))[0]
            try:
                local_peer = ipaddress.ip_address(peer).is_loopback
            except ValueError:
                local_peer = peer == "testclient"
            local_http = self.allow_local_http and local_peer
            if scope.get("scheme") != "https" and not local_http:
                await reject(426, "https_required")
                return
            length = headers.get(b"content-length")
            if length is not None:
                try:
                    declared = int(length)
                except ValueError:
                    await reject(400, "invalid_content_length")
                    return
                if declared < 0:
                    await reject(400, "invalid_content_length")
                    return
                if declared > self.limit:
                    await reject(413, "request_too_large")
                    return
            body = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                if message["type"] != "http.request":
                    continue
                chunk = message.get("body", b"")
                if len(body) + len(chunk) > self.limit:
                    await reject(413, "request_too_large")
                    return
                body.extend(chunk)
                if not message.get("more_body", False):
                    break
            consumed = False

            async def buffered_receive():
                nonlocal consumed
                if not consumed:
                    consumed = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            await self.app(scope, buffered_receive, tagged_send)
        finally:
            log.info("request id=%s principal=%s method=%s status=%s duration_ms=%.1f",
                     request_id, scope["state"].get("principal_id", "anonymous"),
                     scope["method"], status, (time.monotonic() - started) * 1000)


def _precondition(if_match: str | None, if_none_match: str | None = None) -> str:
    if if_match is not None and if_none_match is not None:
        raise ExchangeError(400, "ambiguous_precondition")
    if if_none_match is not None:
        if if_none_match != "*":
            raise ExchangeError(400, "invalid_precondition")
        return "*"
    if if_match is None:
        raise ExchangeError(428, "precondition_required")
    value = if_match.strip()
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    if not value or value == "*" or value.startswith("W/") or any(c in value for c in '\",\r\n'):
        raise ExchangeError(400, "invalid_precondition")
    return value


def _etag(response: Response, result: dict, field: str) -> dict:
    response.headers["ETag"] = '"' + str(result[field]) + '"'
    return result


def create_app(settings=None, service=None, transfers=None, authenticator=None) -> FastAPI:
    """Compose without contacting dependencies; readiness performs live checks.

    Explicit collaborators make HTTP contract tests independent of database,
    storage, and identity-provider availability.
    """
    from .config import Settings
    from .storage import StorageFailure
    settings = settings or Settings.from_env(component="server")
    if service is None:
        from .application import Service
        service = Service(settings)
    if transfers is None:
        from .storage import S3BlobStore
        from .transfers import TransferService
        transfers = TransferService(service, S3BlobStore(settings.storage))
    if authenticator is None:
        from .auth import Authenticator
        authenticator = Authenticator(settings.auth)

    app = FastAPI(title="Exchange", version="2", docs_url="/docs" if settings.docs_enabled else None,
                  redoc_url=None, openapi_url="/openapi.json" if settings.docs_enabled else None)
    app.state.service, app.state.transfers = service, transfers
    app.state.authenticator, app.state.settings = authenticator, settings
    app.add_middleware(RequestBoundary, max_body_bytes=settings.max_body_bytes,
                       allow_local_http=settings.allow_local_http)

    def principal(request: Request, authorization: str = Header(default="")):
        value = authenticator.authenticate(authorization)
        request.state.principal_id = value.id
        # Startup stays available for health probes during dependency outages,
        # while every authenticated operation rejects an incompatible database.
        # FastAPI caches this dependency only for the current request.
        from .migrations import check_revision
        try:
            check_revision(service.engine)
        except ExchangeError as exc:
            raise ExchangeError(503, exc.code, exc.detail, headers={"Retry-After": "3"}) from None
        except Exception as exc:
            log.warning("database readiness failed class=%s", type(exc).__name__)
            raise ExchangeError(503, "database_unavailable", headers={"Retry-After": "3"}) from None
        return value

    def operation_key(idempotency_key: str = Header(min_length=1, max_length=128)):
        return idempotency_key

    @app.exception_handler(ExchangeError)
    async def exchange_error(request, exc):
        return _error(exc.status, exc.code, request.state.request_id, exc.detail, exc.headers)

    @app.exception_handler(StorageFailure)
    async def storage_error(request, exc):
        return _error(503 if exc.retryable else 409, exc.code, request.state.request_id,
                      headers={"Retry-After": "3"} if exc.retryable else None)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Pydantic errors can include submitted secrets in input/context fields.
        locations = [".".join(str(piece) for piece in e["loc"]) for e in exc.errors()]
        return _error(422, "invalid_request", request.state.request_id, "; ".join(locations))

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        return _error(exc.status_code, "not_found" if exc.status_code == 404 else "http_error",
                      request.state.request_id, headers=exc.headers)

    @app.exception_handler(Exception)
    async def unexpected_error(request, exc):
        # Exception messages may contain SQL parameters, credentials, or URLs.
        log.error("request id=%s failed class=%s", request.state.request_id, type(exc).__name__)
        return _error(500, "internal_error", request.state.request_id)

    @app.get("/health", include_in_schema=False)
    def health():
        return {"status": "alive"}

    @app.get("/ready", include_in_schema=False)
    def ready():
        from .migrations import check
        try:
            check(service.engine)
            transfers.storage.check()
        except Exception as exc:
            log.warning("readiness failed class=%s", type(exc).__name__)
            raise ExchangeError(503, "not_ready", headers={"Retry-After": "3"}) from None
        return {"status": "ready", "api_version": 2}

    base = "/v2/spaces"

    @app.post(base, status_code=201)
    def create_space(body: SpaceBody, p=Depends(principal), key=Depends(operation_key)):
        return service.create_space(p, payload(body), key)

    @app.get(base + "/{space}")
    def get_space(space: str, p=Depends(principal)):
        return service.get_space(p, space)

    @app.patch(base + "/{space}")
    def update_space_limits(space: str, body: SpaceLimitsBody, p=Depends(principal)):
        return service.update_space_limits(p, space, payload(body))

    @app.get(base + "/{space}/membership")
    def membership(space: str, p=Depends(principal)):
        return service.get_membership(p, space)

    @app.get(base + "/{space}/members")
    def members(space: str, p=Depends(principal)):
        return service.list_members(p, space)

    @app.put(base + "/{space}/members/{member}")
    def put_member(space: str, member: str, body: MemberBody, p=Depends(principal)):
        return service.put_member(p, space, member, payload(body))

    @app.get(base + "/{space}/types")
    def types(space: str, p=Depends(principal)):
        return service.list_types(p, space)

    @app.post(base + "/{space}/types/{kind}/revisions", status_code=201)
    def register_type(space: str, kind: str, body: TypeBody, p=Depends(principal), key=Depends(operation_key)):
        return service.register_type(p, space, kind, payload(body), key)

    @app.get(base + "/{space}/types/{kind}/revisions/{revision}")
    def get_type(space: str, kind: str, revision: int = Path(ge=1), p=Depends(principal)):
        return service.get_type(p, space, kind, revision)

    @app.put(base + "/{space}/policies/{kind}")
    def put_policy(space: str, kind: str, body: PolicyBody, p=Depends(principal)):
        return service.put_policy(p, space, kind, payload(body))

    @app.post(base + "/{space}/records", status_code=201)
    def create_record(space: str, body: RecordBody, p=Depends(principal), key=Depends(operation_key)):
        return service.create_record(p, space, payload(body), key)

    @app.get(base + "/{space}/records")
    def records(space: str, kind: str | None = None, after: str | None = None,
                limit: int = Query(default=100, ge=1, le=1000), state: str = "published", p=Depends(principal)):
        return service.list_records(p, space, kind=kind, after=after, limit=limit, state=state)

    @app.get(base + "/{space}/records/{record}")
    def get_record(space: str, record: str, response: Response, p=Depends(principal)):
        return _etag(response, service.get_record(p, space, record), "version")

    @app.patch(base + "/{space}/records/{record}")
    def patch_record(space: str, record: str, body: PatchBody, response: Response,
                     if_match: str | None = Header(default=None), p=Depends(principal)):
        value = _precondition(if_match)
        try:
            version = int(value)
        except ValueError:
            raise ExchangeError(400, "invalid_precondition") from None
        return _etag(response, service.patch_record(p, space, record, payload(body), version), "version")

    @app.delete(base + "/{space}/records/{record}")
    def withdraw_record(space: str, record: str, p=Depends(principal)):
        return service.withdraw_record(p, space, record)

    @app.post(base + "/{space}/records/{record}/purge")
    def purge_record(space: str, record: str, p=Depends(principal)):
        return service.purge_record(p, space, record)

    @app.post(base + "/{space}/records/{record}/publish")
    def publish_record(space: str, record: str, p=Depends(principal), key=Depends(operation_key)):
        return service.publish_record(p, space, record, key)

    @app.get(base + "/{space}/refs/{name}")
    def get_reference(space: str, name: str, response: Response, p=Depends(principal)):
        return _etag(response, service.get_reference(p, space, name), "token")

    @app.put(base + "/{space}/refs/{name}")
    def put_reference(space: str, name: str, body: ReferenceBody, response: Response,
                      if_match: str | None = Header(default=None),
                      if_none_match: str | None = Header(default=None), p=Depends(principal), key=Depends(operation_key)):
        token = _precondition(if_match, if_none_match)
        return _etag(response, service.put_reference(p, space, name, payload(body), token, key), "token")

    @app.post(base + "/{space}/acquisitions", status_code=201)
    def acquire(space: str, body: AcquisitionBody, p=Depends(principal), key=Depends(operation_key)):
        return service.acquire(p, space, payload(body), key)

    @app.get(base + "/{space}/acquisitions/{acquisition}")
    def acquisition(space: str, acquisition: str, p=Depends(principal)):
        return service.get_acquisition(p, space, acquisition)

    @app.post(base + "/{space}/acquisitions/{acquisition}/renew")
    def renew(space: str, acquisition: str, body: FenceBody, p=Depends(principal)):
        return service.renew(p, space, acquisition, body.fence)

    @app.post(base + "/{space}/acquisitions/{acquisition}/abandon")
    def abandon(space: str, acquisition: str, body: FenceBody, p=Depends(principal)):
        return service.abandon(p, space, acquisition, body.fence)

    @app.post(base + "/{space}/acquisitions/{acquisition}/complete")
    def complete(space: str, acquisition: str, body: CompletionBody,
                 p=Depends(principal), key=Depends(operation_key)):
        return service.complete(p, space, acquisition, payload(body), key)

    @app.get(base + "/{space}/events")
    def events(space: str, after: int = Query(default=0, ge=0),
               limit: int = Query(default=100, ge=1, le=1000), p=Depends(principal)):
        return service.events(p, space, after=after, limit=limit)

    attachment = base + "/{space}/records/{record}/attachments/{attachment}"

    @app.post(attachment + "/upload")
    def initiate(space: str, record: str, attachment: str, p=Depends(principal)):
        return transfers.initiate(space, record, attachment, p)

    @app.get(attachment + "/parts")
    def parts(space: str, record: str, attachment: str, p=Depends(principal)):
        return transfers.parts(space, record, attachment, p)

    @app.post(attachment + "/grants")
    def grants(space: str, record: str, attachment: str, body: GrantsBody, p=Depends(principal)):
        return transfers.grants(space, record, attachment, p, body.numbers)

    @app.post(attachment + "/complete", status_code=202)
    def finish_upload(space: str, record: str, attachment: str, p=Depends(principal)):
        return transfers.complete(space, record, attachment, p)

    @app.get(attachment + "/download")
    def download(space: str, record: str, attachment: str, p=Depends(principal)):
        return transfers.download(space, record, attachment, p)

    return app
