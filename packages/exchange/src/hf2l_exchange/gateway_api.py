"""Private Exchange transfer backend for trusted gateway processes.

This is a separate application, never mounted by the public Exchange factory.
Only a trusted TLS gateway holding the backend assertion secret may consume
origin descriptors. Every normal operation still authenticates its original
certificate-bound transfer token and checks the current Exchange workload grant.

A settlement receipt records exactly one admitted origin PUT. Settlement does
not require fresh workload authority: expiry or revocation must not prevent a
known successful, closed provider operation from releasing its old mutation
fence. Keep the settlement key until owned old markers are settled or explicitly
reconciled; secret rotation otherwise fails closed. The sealed receipt and original authorization/certificate bind that
settlement; the transfer ledger remains the final authority.
"""
from __future__ import annotations

import base64
from dataclasses import asdict, replace
import hashlib
import hmac
import json
import logging
import re

import jwt
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException

from .api import RequestBoundary, _error
from .auth import Authenticator, verified_backend_thumbprint
from .domain import ExchangeError
from .storage import StorageFailure
from .transfers import GatewayPutHandle

log = logging.getLogger("hf2l_exchange.gateway_backend")
BASE = "/internal/transfers/v1"
MAX_BODY_BYTES = 16384
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_B64 = re.compile(r"^[A-Za-z0-9_-]+$")
_RECEIPT_DOMAIN = b"hf2l-exchange-gateway-put-v1\x00"
_ASSERTIONS = (b"authorization", b"x-hf2l-backend-timestamp",
               b"x-hf2l-tls-thumbprint", b"x-hf2l-backend-signature")
_FORBIDDEN_HEADERS = {b"cookie", b"proxy-authorization", b"x-forwarded-client-cert"}


def _json_object(raw: bytes):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError()
            value[key] = item
        return value

    def constant(_):
        raise ValueError()

    try:
        result = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        if not isinstance(result, dict):
            raise ValueError()
        return result
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise ExchangeError(422, "invalid_request") from None


def _receipt_payload(principal, authorization, handle):
    identity = principal.workload
    return {"version": 1,
            "authorization_sha256": hashlib.sha256(authorization.encode()).hexdigest(),
            "owner": {"principal_id": principal.id, "subject": principal.subject,
                      "grant_id": identity.grant_id, "space_id": identity.space_id,
                      "job_id": identity.job_id, "attempt_id": identity.attempt_id,
                      "component_id": identity.component_id, "epoch": identity.epoch,
                      "certificate_thumbprint": identity.certificate_thumbprint},
            "put": asdict(handle)}


def _seal(secret: str, payload: dict) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    signature = hmac.new(secret.encode(), _RECEIPT_DOMAIN + encoded.encode(),
                         hashlib.sha256).hexdigest()
    value = encoded + "." + signature
    if len(value) > MAX_BODY_BYTES - 64:
        raise ExchangeError(503, "gateway_put_receipt_too_large")
    return value


def _open(secret: str, receipt: str, authorization: str, thumbprint: str):
    try:
        if not isinstance(receipt, str) or not 1 <= len(receipt) <= MAX_BODY_BYTES - 64:
            raise ValueError()
        encoded, signature = receipt.split(".")
        if not _B64.fullmatch(encoded) or not re.fullmatch(r"[a-f0-9]{64}", signature):
            raise ValueError()
        expected = hmac.new(secret.encode(), _RECEIPT_DOMAIN + encoded.encode(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError()
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        value = _json_object(raw)
        if set(value) != {"version", "authorization_sha256", "owner", "put"} or type(value["version"]) is not int or value["version"] != 1:
            raise ValueError()
        actual = hashlib.sha256(authorization.encode()).hexdigest()
        if not isinstance(value["authorization_sha256"], str) or not hmac.compare_digest(
                value["authorization_sha256"], actual):
            raise ValueError()
        owner = value["owner"]
        names = {"principal_id", "subject", "grant_id", "space_id", "job_id",
                 "attempt_id", "component_id", "epoch", "certificate_thumbprint"}
        if not isinstance(owner, dict) or set(owner) != names:
            raise ValueError()
        if any(not isinstance(owner[key], str) or not 1 <= len(owner[key]) <= 256
               for key in names - {"epoch"}):
            raise ValueError()
        if type(owner["epoch"]) is not int or not 1 <= owner["epoch"] <= 2**63 - 1:
            raise ValueError()
        if not hmac.compare_digest(owner["certificate_thumbprint"], thumbprint):
            raise ValueError()
        put = value["put"]
        if not isinstance(put, dict) or set(put) != set(GatewayPutHandle.__dataclass_fields__):
            raise ValueError()
        for key in ("space_id", "record_id", "attachment_id", "attempt_id"):
            if not isinstance(put[key], str) or not _IDENTIFIER.fullmatch(put[key]):
                raise ValueError()
        for key in ("object_key", "upload_id", "token"):
            if not isinstance(put[key], str) or not 1 <= len(put[key]) <= 4096:
                raise ValueError()
        if type(put["part_number"]) is not int or not 1 <= put["part_number"] <= 10000:
            raise ValueError()
        if put["space_id"] != owner["space_id"] or not put["token"].startswith(
                "gateway-put-" + str(put["part_number"]) + "-"):
            raise ValueError()
        return GatewayPutHandle(**put)
    except (ValueError, TypeError, KeyError, UnicodeError, ExchangeError):
        raise ExchangeError(401, "invalid_gateway_put_receipt") from None


def create_gateway_backend_app(settings=None, service=None, transfers=None,
                               authenticator=None, *, gateway_audience="hf2l-transfer"):
    """Create an explicitly private HTTPS application, separate from /v2 ingress.

    Configure the same fixed transfer audience on the Go gateway. Signed backend
    assertions are mandatory even if a TLS terminator supplies ASGI scope state.
    The service has no public/multipart raw-byte route and must not be published
    through an ordinary user-facing reverse proxy. Begin operations are not safe
    for automatic retries after ambiguous network outcomes.
    """
    from .application import Service
    from .config import Settings
    from .migrations import check_revision
    from .storage import S3BlobStore
    from .transfers import TransferService

    settings = settings or Settings.from_env(component="server")
    settings.validate("server")
    if (not settings.auth.workloads_enabled or not isinstance(gateway_audience, str)
            or not gateway_audience or gateway_audience == settings.auth.workload_audience):
        raise ValueError("Private gateway backend requires its separate fixed transfer audience")
    service = service or Service(settings)
    transfers = transfers or TransferService(service, S3BlobStore(settings.storage))
    if not all(callable(getattr(transfers, name, None))
               for name in ("grants", "download", "begin_gateway_put", "finish_gateway_put")):
        raise ValueError("Private gateway backend requires the raw transfer service")
    auth = authenticator or Authenticator(replace(settings.auth, workload_audience=gateway_audience))
    provisioning_auth = Authenticator(settings.auth)
    if getattr(getattr(auth, "settings", None), "workload_audience", None) != gateway_audience:
        raise ValueError("Gateway backend authenticator audience must match the transfer audience")

    app = FastAPI(title="Exchange private transfer backend", docs_url=None,
                  redoc_url=None, openapi_url=None)
    app.state.service, app.state.transfers = service, transfers
    app.state.settings, app.state.authenticator = settings, auth
    app.add_middleware(RequestBoundary, max_body_bytes=min(settings.max_body_bytes, MAX_BODY_BYTES),
                       allow_local_http=settings.allow_local_http)

    @app.exception_handler(ExchangeError)
    async def exchange_error(request, exc):
        return _error(exc.status, exc.code, request.state.request_id, "", exc.headers)

    @app.exception_handler(StorageFailure)
    async def storage_error(request, exc):
        return _error(503 if exc.retryable else 409, exc.code, request.state.request_id,
                      headers={"Retry-After": "3"} if exc.retryable else None)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return _error(422, "invalid_request", request.state.request_id)

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        return _error(exc.status_code, "not_found" if exc.status_code == 404 else "http_error",
                      request.state.request_id, headers=exc.headers)

    @app.exception_handler(Exception)
    async def unexpected_error(request, exc):
        log.error("request id=%s failed class=%s", request.state.request_id, type(exc).__name__)
        return _error(500, "internal_error", request.state.request_id)

    async def boundary(request, *identifiers, settlement=False):
        names = [key.lower() for key, _ in request.scope.get("headers", [])]
        if any(names.count(name) != 1 for name in _ASSERTIONS):
            raise ExchangeError(401, "invalid_backend_assertion")
        if any(name in _FORBIDDEN_HEADERS for name in names):
            raise ExchangeError(400, "forbidden_transfer_credentials")
        if request.url.query:
            raise ExchangeError(400, "unexpected_transfer_query")
        if b"%" in request.scope.get("raw_path", b""):
            raise ExchangeError(400, "noncanonical_transfer_target")
        if any(not _IDENTIFIER.fullmatch(value) for value in identifiers):
            raise ExchangeError(422, "invalid_resource_identifier")
        authorization = request.headers.get("authorization", "")
        thumbprint = verified_backend_thumbprint(settings.auth, request.method,
                                                 request.url.path, authorization, request.headers)
        raw = await request.body()
        if raw and request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise ExchangeError(415, "json_required")
        body = _json_object(raw) if raw else {}
        if not settlement and body:
            raise ExchangeError(422, "invalid_request")
        try:
            await run_in_threadpool(check_revision, service.engine)
        except ExchangeError as exc:
            raise ExchangeError(503, exc.code, headers={"Retry-After": "3"}) from None
        except Exception:
            raise ExchangeError(503, "database_unavailable", headers={"Retry-After": "3"}) from None
        return authorization, thumbprint, body

    async def identity(request, space, *identifiers):
        authorization, thumbprint, _ = await boundary(request, space, *identifiers)
        principal = await run_in_threadpool(auth.authenticate, authorization,
                                            managed=True, certificate_thumbprint=thumbprint)
        if principal.workload is None:
            raise ExchangeError(401, "workload_identity_required")
        try:
            token = authorization.split(" ", 1)[1]
            claims = jwt.decode(token, auth.settings.workload_public_key, algorithms=["RS256"],
                                issuer=auth.settings.workload_issuer, audience=gateway_audience,
                                options={"strict_aud": True})
            if not isinstance(claims.get("scope"), str) or "transfer" not in claims["scope"].split():
                raise ValueError()
        except (ValueError, TypeError, KeyError, jwt.PyJWTError):
            raise ExchangeError(401, "invalid_workload_token") from None
        if principal.workload.space_id != space:
            raise ExchangeError(404, "resource_not_found")
        request.state.principal_id = principal.id
        await run_in_threadpool(service.verify_workload_grant, principal, space)
        return principal, authorization

    @app.post(BASE + "/spaces/{space}/authorize")
    async def authorize(request: Request, space: str):
        principal, _ = await identity(request, space)
        # Reuse the current transactional grant check, including effective roles.
        return await run_in_threadpool(service.verify_workload_grant, principal, space)

    @app.post(BASE + "/storage/check")
    async def storage_check(request: Request):
        authorization, _, _ = await boundary(request)
        principal = await run_in_threadpool(provisioning_auth.authenticate, authorization)
        if principal.workload is not None or principal.id not in settings.auth.provisioning_principal_ids:
            raise ExchangeError(403, "provisioning_principal_required")
        request.state.principal_id = principal.id
        storage = getattr(transfers, "storage", None)
        if not isinstance(storage, S3BlobStore):
            raise ExchangeError(503, "storage_backend_unavailable")
        configured, expected = storage.settings, settings.storage
        def namespace(value):
            return {"endpoint": value.endpoint.rstrip("/"), "bucket": value.bucket,
                    "prefix": value.prefix.strip("/"), "region": value.region}
        if namespace(configured) != namespace(expected):
            raise ExchangeError(503, "storage_backend_mismatch")
        await run_in_threadpool(storage.check)
        return {**namespace(configured), "protocol": storage.protocol,
                "versioning": "Enabled", "checked": True}

    part = BASE + "/spaces/{space}/records/{record}/attachments/{attachment}/parts/{number}"

    @app.post(part + "/grant")
    async def grant(request: Request, space: str, record: str, attachment: str, number: int):
        if not 1 <= number <= 10000:
            raise ExchangeError(422, "invalid_part_number")
        principal, _ = await identity(request, space, record, attachment)
        result = await run_in_threadpool(transfers.grants, space, record, attachment, principal, [number])
        grants = result.get("grants", ())
        if len(grants) != 1 or grants[0].get("number") != number:
            raise ExchangeError(503, "invalid_origin_descriptor")
        return grants[0]

    @app.post(part + "/begin")
    async def begin(request: Request, space: str, record: str, attachment: str, number: int):
        if not 1 <= number <= 10000:
            raise ExchangeError(422, "invalid_part_number")
        principal, authorization = await identity(request, space, record, attachment)
        handle, grant = await run_in_threadpool(transfers.begin_gateway_put, principal,
                                                space, record, attachment, number)
        if not isinstance(handle, GatewayPutHandle):
            raise ExchangeError(503, "invalid_origin_mutation_fence")
        return {"receipt": _seal(settings.auth.trusted_backend_secret,
                                  _receipt_payload(principal, authorization, handle)), "grant": grant}

    @app.post(BASE + "/spaces/{space}/records/{record}/attachments/{attachment}/download")
    async def download(request: Request, space: str, record: str, attachment: str):
        principal, _ = await identity(request, space, record, attachment)
        return await run_in_threadpool(transfers.download, space, record, attachment, principal)

    @app.post(BASE + "/settle")
    async def settle(request: Request):
        authorization, thumbprint, body = await boundary(request, settlement=True)
        if set(body) != {"receipt"}:
            raise ExchangeError(422, "invalid_request")
        handle = _open(settings.auth.trusted_backend_secret, body["receipt"], authorization, thumbprint)
        return {"settled": await run_in_threadpool(transfers.finish_gateway_put, handle)}

    return app
