"""Authenticated JSON control plane; file bytes travel directly to S3."""
from contextlib import asynccontextmanager, contextmanager
import base64
import hashlib
import json
import logging
import math
import time
import uuid

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from jsonschema import Draft202012Validator, ValidationError, SchemaError
from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import DBAPIError, IntegrityError, TimeoutError as PoolTimeoutError

from .auth import Authenticator, principal_id
from .config import Settings
from .models import Blob, Claim, Event, Member, Operation, Record, Ref, Space, database
from .schemas import (ClaimAbandon, ClaimInput, ClaimResult, LeaseInput, MemberInput, MetadataInput, PartsInput,
                      RecordInput, RefInput, SpaceInput, SpacePatch)
from .storage import S3BlobStore

log = logging.getLogger("hf2l.exchange.api")

# Records in these states hold no quota and their blobs are eligible for storage cleanup.
RELEASED_STATES = ("expired", "cancelled", "withdrawn")


def new_id(prefix):
    return prefix + "_" + uuid.uuid4().hex


def fail(status, code):
    raise HTTPException(status, code)


def check_rules(rules):
    for rule in rules.values():
        try:
            Draft202012Validator.check_schema(rule.metadata_schema)
        except SchemaError:
            fail(422, "invalid_metadata_schema")
        if "$ref" in json.dumps(rule.metadata_schema):
            fail(422, "external_schema_references_not_supported")
    return {k: v.model_dump() for k, v in rules.items()}


class Service:
    def __init__(self, settings, storage=None):
        self.settings = settings
        self.engine, self.sessions = database(settings.database_url)
        self.storage = storage or S3BlobStore(settings)
        self.auth = Authenticator(settings)

    @contextmanager
    def transaction(self, space_id, who, role=None):
        with self.sessions.begin() as session:
            # All mutations use this ordering. Membership changes serialize with authorization.
            space = session.scalar(select(Space).where(Space.id == space_id).with_for_update())
            member = session.get(Member, (space_id, who.id)) if space else None
            if not member or not member.roles:
                fail(404, "space_not_found")
            if role and role not in member.roles:
                fail(403, "permission_denied")
            yield session, space, member

    def visible(self, member, who):
        if "coordinator" in member.roles:
            return or_(Record.state == "ready", Record.creator == who.id)
        data_access = bool(set(member.roles) & {"reader", "contributor"})
        return or_(Record.creator == who.id,
                   and_(Record.state == "ready", Record.shared.is_(True))) if data_access else False

    def record(self, session, space_id, record_id, member, who, owner=False, admin=False):
        criteria = [Record.id == record_id, Record.space_id == space_id]
        if not admin:
            criteria.append(self.visible(member, who))
        record = session.scalar(select(Record).where(*criteria))
        if not record:
            fail(404, "record_not_found")
        if owner and record.creator != who.id:
            fail(403, "not_record_owner")
        return record

    def blobs(self, session, record_id):
        return list(session.scalars(select(Blob).where(Blob.record_id == record_id).order_by(Blob.name)))

    def serialize(self, session, record):
        return {
            "id": record.id, "space_id": record.space_id, "created_by": record.creator,
            "participant": record.participant, "kind": record.kind, "state": record.state,
            "schema_version": record.schema_version, "base_record_id": record.base_id,
            "metadata": record.data, "generation": record.generation, "created_at": record.created_at,
            "attachments": [{"id": b.id, "name": b.name, "size_bytes": b.size,
                             "sha256": b.verified_sha256 or b.sha256, "state": b.state}
                            for b in self.blobs(session, record.id)],
        }

    def emit(self, session, space_id, who, kind, record_id=None, **data):
        session.add(Event(space_id=space_id, principal=who.id, kind=kind,
                          record_id=record_id, data=data))

    def once(self, session, who, scope, key, body, operation):
        if not key or len(key) > 128:
            fail(400, "idempotency_key_required")
        identifier = hashlib.sha256(json.dumps([who.id, scope, key]).encode()).hexdigest()
        digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        previous = session.get(Operation, identifier)
        if previous:
            if previous.digest != digest:
                fail(409, "idempotency_key_reused")
            return previous.result
        result = operation()
        session.add(Operation(id=identifier, digest=digest, result=result))
        return result

    def validate_data(self, rule, data):
        try:
            Draft202012Validator(rule.get("metadata_schema", {})).validate(data)
        except ValidationError:
            fail(422, "metadata_schema_mismatch")

    def owned_upload(self, session, space_id, blob_id, member, who):
        blob = session.get(Blob, blob_id)
        if not blob or blob.space_id != space_id:
            fail(404, "upload_not_found")
        record = self.record(session, space_id, blob.record_id, member, who, owner=True)
        if not set(member.roles) & {"contributor", "coordinator"}:
            fail(403, "permission_denied")
        if record.state != "draft" or record.expires_at < time.time():
            fail(409, "record_not_uploadable")
        return blob, record

    @staticmethod
    def transition(blob, state):
        blob.state, blob.updated_at = state, time.time()

    def release(self, session, space, record, who, state, event):
        record.state = state
        space.allocated -= sum(b.size for b in self.blobs(session, record.id))
        self.emit(session, space.id, who, event, record.id)

    def outstanding(self, session, space_id, principal):
        return session.scalar(select(func.coalesce(func.sum(Blob.size), 0)).join(Record, Record.id == Blob.record_id).where(
            Record.space_id == space_id, Record.creator == principal, Record.state == "draft")) or 0

    def active_claims(self, session, space_id):
        return list(session.scalars(select(Claim).where(
            Claim.space_id == space_id, Claim.result_id.is_(None), Claim.lease_until > time.time())))

    def move_ref(self, session, space_id, name, target, expected, absent, who):
        if not name or len(name) > 128:
            fail(422, "invalid_reference_name")
        current = session.get(Ref, (space_id, name))
        if target.state != "ready" or not target.shared:
            fail(409, "reference_target_must_be_shared_and_ready")
        if current:
            if expected != f'"{current.generation}"' or absent:
                fail(412, "reference_changed")
            if name == "main" and target.base_id != current.record_id:
                fail(409, "aggregate_base_mismatch")
            current.record_id = target.id
            current.generation += 1
        else:
            if absent != "*" or expected:
                fail(412, "reference_creation_requires_if_none_match")
            current = Ref(space_id=space_id, name=name, record_id=target.id, generation=1)
            session.add(current)
        self.emit(session, space_id, who, "reference.updated", target.id, name=name, generation=current.generation)
        return {"record_id": current.record_id, "generation": current.generation}

    def frozen_inputs(self, session, space_id, base_id, body):
        """Freeze the newest ready update per participant, or validate coordinator-chosen inputs."""
        candidates = list(session.scalars(select(Record).where(
            Record.space_id == space_id, Record.kind == "training.update", Record.state == "ready",
            Record.base_id == base_id).order_by(Record.published_at.desc(), Record.id.desc())))
        if body.inputs is not None:
            by_id = {r.id: r for r in candidates}
            chosen = [by_id.get(i) for i in body.inputs]
            if None in chosen or len({r.id for r in chosen}) != len(chosen) or len({r.participant for r in chosen}) != len(chosen):
                fail(409, "claim_inputs_invalid")
            superseded = []
        else:
            chosen, seen, superseded = [], set(), []
            for record in candidates:
                if record.participant in seen:
                    superseded.append(record.id)
                else:
                    seen.add(record.participant)
                    chosen.append(record)
        if len(chosen) < body.minimum:
            fail(409, "insufficient_submissions")
        return sorted(r.id for r in chosen), superseded


def create_app(settings=None, storage=None):
    service = Service(settings or Settings.from_env(), storage)

    @asynccontextmanager
    async def lifespan(app):
        service.storage.check()
        yield
        service.engine.dispose()

    app = FastAPI(title="HF2L Exchange", version="1", lifespan=lifespan)
    app.state.service = service

    def error(request, status, code, level=logging.WARNING, exc=None):
        request_id = getattr(request.state, "request_id", "")
        log.log(level, "%s %s -> %s %s request_id=%s%s", request.method, request.url.path, status, code, request_id,
                f" error={type(exc).__name__}: {exc}" if exc else "")
        return JSONResponse({"code": code, "request_id": request_id}, status, headers={"X-Request-ID": request_id})

    @app.middleware("http")
    async def bounded_request(request, call_next):
        request.state.request_id = uuid.uuid4().hex
        started = time.monotonic()
        # Read at most a bounded amount, including requests without Content-Length.
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > service.settings.max_body_bytes:
                return error(request, 413, "request_too_large")
        request._body = bytes(body)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["Cache-Control"] = "no-store"
        log.info("%s %s -> %s request_id=%s duration_ms=%d", request.method, request.url.path, response.status_code,
                 request.state.request_id, (time.monotonic() - started) * 1000)
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        response = error(request, exc.status_code, exc.detail, logging.DEBUG)
        response.headers.update(exc.headers or {})
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return error(request, 422, "invalid_request", logging.DEBUG)

    @app.exception_handler(IntegrityError)
    async def conflict(request, exc):
        return error(request, 409, "resource_conflict", exc=exc)

    @app.exception_handler(DBAPIError)
    @app.exception_handler(PoolTimeoutError)
    async def database_error(request, exc):
        return error(request, 503, "database_unavailable", logging.ERROR, exc)

    @app.exception_handler(BotoCoreError)
    @app.exception_handler(ClientError)
    async def storage_error(request, exc):
        return error(request, 503, "storage_unavailable", logging.ERROR, exc)

    @app.exception_handler(Exception)
    async def unhandled_error(request, exc):
        return error(request, 500, "internal_error", logging.ERROR, exc)

    def authenticate(authorization: str = Header(default="")):
        return service.auth.authenticate(authorization)

    prefix = "/v1/spaces/{space_id}"

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/v1/spaces", status_code=201)
    def create_space(body: SpaceInput, who=Depends(authenticate), idempotency_key: str = Header(default="")):
        if not who.bootstrap_admin:
            fail(403, "bootstrap_admin_required")
        rules = check_rules(body.rules)
        with service.sessions.begin() as session:
            def operation():
                space = Space(id=new_id("sp"), tenant=body.tenant, name=body.name, quota=body.quota_bytes,
                              principal_quota=body.principal_quota_bytes or max(1, body.quota_bytes // 4), rules=rules)
                session.add(space)
                session.flush()
                session.add(Member(space_id=space.id, principal=who.id, roles=["admin", "coordinator", "reader"]))
                service.emit(session, space.id, who, "space.created")
                return {"id": space.id, "name": space.name, "tenant": space.tenant}
            return service.once(session, who, "spaces", idempotency_key, body.model_dump(), operation)

    def space_view(space):
        return {"id": space.id, "name": space.name, "tenant": space.tenant, "quota_bytes": space.quota,
                "principal_quota_bytes": space.principal_quota, "allocated_bytes": space.allocated,
                "rules": space.rules, "generation": space.generation}

    @app.get(prefix)
    def get_space(space_id: str, who=Depends(authenticate)):
        with service.transaction(space_id, who, "admin") as (_, space, _):
            return JSONResponse(space_view(space), headers={"ETag": f'"{space.generation}"'})

    @app.patch(prefix)
    def patch_space(space_id: str, body: SpacePatch, if_match: str = Header(default=""), who=Depends(authenticate)):
        rules = check_rules(body.rules) if body.rules is not None else None
        with service.transaction(space_id, who, "admin") as (session, space, _):
            if if_match != f'"{space.generation}"':
                fail(412, "space_changed")
            if body.quota_bytes is not None:
                space.quota = body.quota_bytes
            if body.principal_quota_bytes is not None:
                space.principal_quota = body.principal_quota_bytes
            if rules is not None:
                space.rules = rules
            space.generation += 1
            service.emit(session, space_id, who, "space.updated", changed=sorted(k for k, v in body.model_dump().items() if v is not None))
            return JSONResponse(space_view(space), headers={"ETag": f'"{space.generation}"'})

    @app.put(prefix + "/members/{member_id}")
    def put_member(space_id: str, member_id: str, body: MemberInput, who=Depends(authenticate)):
        if principal_id(service.settings.issuer, body.subject) != member_id:
            fail(422, "principal_subject_mismatch")
        with service.transaction(space_id, who, "admin") as (session, space, member):
            if member_id == who.id and "admin" not in body.roles:
                fail(409, "cannot_remove_own_admin_role")
            row = session.get(Member, (space_id, member_id))
            if not row:
                row = Member(space_id=space_id, principal=member_id)
                session.add(row)
            row.roles, row.participant = body.roles, body.participant
            if not body.roles:
                # Revocation releases every reservation the principal still holds.
                for draft in session.scalars(select(Record).where(
                        Record.space_id == space_id, Record.creator == member_id, Record.state == "draft")):
                    service.release(session, space, draft, who, "cancelled", "record.cancelled")
            service.emit(session, space_id, who, "membership.updated", member_id=member_id)
            return {"principal_id": member_id, "roles": body.roles, "participant": body.participant}

    @app.get(prefix + "/me")
    def me(space_id: str, who=Depends(authenticate)):
        with service.transaction(space_id, who) as (_, _, member):
            return {"principal_id": who.id, "participant": member.participant, "roles": member.roles}

    @app.post(prefix + "/records", status_code=201)
    def create_record(space_id: str, body: RecordInput, who=Depends(authenticate), idempotency_key: str = Header(default="")):
        with service.transaction(space_id, who) as (session, space, member):
            rule = space.rules.get(body.kind)
            if not rule or not set(member.roles) & set(rule["creators"]):
                fail(403, "record_kind_not_allowed")
            service.validate_data(rule, body.metadata)
            if body.base_record_id:
                base = service.record(session, space_id, body.base_record_id, member, who)
                if base.state != "ready":
                    fail(409, "base_not_ready")
            if body.kind == "training.update" and (not member.participant or not body.base_record_id):
                fail(422, "participant_and_base_required")
            names = [x.name for x in body.attachments]
            if len(set(names)) != len(names):
                fail(422, "duplicate_attachment_name")
            if any(other.startswith(name + "/") for name in names for other in names):
                fail(422, "attachment_name_collides_with_directory")
            def operation():
                size = sum(x.size_bytes for x in body.attachments)
                if space.allocated + size > space.quota:
                    fail(429, "space_quota_exceeded")
                if size and service.outstanding(session, space_id, who.id) + size > space.principal_quota:
                    fail(429, "principal_quota_exceeded")
                space.allocated += size
                record = Record(id=new_id("rec"), space_id=space_id, creator=who.id,
                                participant=member.participant, kind=body.kind,
                                base_id=body.base_record_id, data=body.metadata,
                                schema_version=body.schema_version, shared=rule["shared"],
                                expires_at=time.time() + service.settings.upload_seconds)
                session.add(record)
                session.flush()
                for attachment in body.attachments:
                    blob_id = new_id("blob")
                    # Increase part size for very large objects while respecting 10,000 parts.
                    part_bytes = max(service.settings.part_bytes, math.ceil(attachment.size_bytes / 10000))
                    session.add(Blob(id=blob_id, space_id=space_id, record_id=record.id,
                                     name=attachment.name, size=attachment.size_bytes, sha256=attachment.sha256,
                                     key=f"spaces/{space_id}/blobs/{blob_id}", part_bytes=part_bytes,
                                     expires_at=record.expires_at))
                session.flush()
                service.emit(session, space_id, who, "record.created", record.id)
                return service.serialize(session, record)
            return service.once(session, who, space_id + "/records", idempotency_key, body.model_dump(), operation)

    @app.get(prefix + "/records/{record_id}")
    def get_record(space_id: str, record_id: str, who=Depends(authenticate)):
        with service.transaction(space_id, who) as (session, _, member):
            return service.serialize(session, service.record(session, space_id, record_id, member, who))

    @app.get(prefix + "/records")
    def list_records(space_id: str, kind: str | None = None, base_record_id: str | None = None,
                     state: str = "ready", cursor: str = "", limit: int = Query(default=100, ge=1, le=256),
                     who=Depends(authenticate)):
        with service.transaction(space_id, who) as (session, _, member):
            boundary, after_time, after_id = time.time(), 0.0, ""
            if cursor:
                try:
                    boundary, after_time, after_id = json.loads(base64.urlsafe_b64decode(cursor))
                    if not isinstance(boundary, (float, int)) or not isinstance(after_time, (float, int)) or not isinstance(after_id, str):
                        raise ValueError()
                except (ValueError, TypeError):
                    fail(422, "invalid_cursor")
            timestamp = Record.published_at if state == "ready" else Record.created_at
            query = select(Record).where(Record.space_id == space_id, Record.state == state,
                                          timestamp <= boundary, service.visible(member, who),
                                          or_(timestamp > after_time,
                                              and_(timestamp == after_time, Record.id > after_id)))
            if kind:
                query = query.where(Record.kind == kind)
            if base_record_id:
                query = query.where(Record.base_id == base_record_id)
            rows = list(session.scalars(query.order_by(timestamp, Record.id).limit(limit + 1)))
            next_cursor = ""
            if len(rows) > limit:
                rows = rows[:limit]
                last_time = rows[-1].published_at if state == "ready" else rows[-1].created_at
                next_cursor = base64.urlsafe_b64encode(json.dumps([boundary, last_time, rows[-1].id]).encode()).decode()
            return {"items": [service.serialize(session, row) for row in rows], "next_cursor": next_cursor}

    @app.patch(prefix + "/records/{record_id}")
    def patch_record(space_id: str, record_id: str, body: MetadataInput, if_match: str = Header(default=""), who=Depends(authenticate)):
        with service.transaction(space_id, who) as (session, space, member):
            record = service.record(session, space_id, record_id, member, who, owner=True)
            if record.state != "draft":
                fail(409, "record_immutable")
            if if_match != f'"{record.generation}"':
                fail(412, "record_changed")
            if not set(member.roles) & set(space.rules[record.kind]["creators"]):
                fail(403, "permission_denied")
            service.validate_data(space.rules[record.kind], body.metadata)
            record.data = body.metadata
            record.generation += 1
            return service.serialize(session, record)

    @app.post(prefix + "/records/{record_id}:publish")
    def publish(space_id: str, record_id: str, who=Depends(authenticate)):
        with service.transaction(space_id, who) as (session, space, member):
            record = service.record(session, space_id, record_id, member, who, owner=True)
            if not set(member.roles) & set(space.rules[record.kind]["creators"]):
                fail(403, "permission_denied")
            if record.state == "ready":
                return service.serialize(session, record)
            if record.state != "draft" or record.expires_at < time.time():
                fail(409, "record_expired")
            if any(blob.state != "verified" for blob in service.blobs(session, record.id)):
                fail(409, "blobs_not_verified")
            service.validate_data(space.rules[record.kind], record.data)
            record.state = "ready"
            record.published_at = time.time()
            record.generation += 1
            service.emit(session, space_id, who, "record.ready", record.id)
            return service.serialize(session, record)

    @app.delete(prefix + "/records/{record_id}")
    def cancel_record(space_id: str, record_id: str, who=Depends(authenticate)):
        with service.transaction(space_id, who) as (session, space, member):
            admin = "admin" in member.roles
            record = service.record(session, space_id, record_id, member, who, owner=not admin, admin=admin)
            if record.state == "draft":
                service.release(session, space, record, who, "cancelled", "record.cancelled")
            elif record.state == "ready":
                # Withdrawal keeps every live reference, lineage and frozen claim input intact.
                if session.scalar(select(Ref.name).where(Ref.space_id == space_id, Ref.record_id == record.id)):
                    fail(409, "record_referenced")
                if session.scalar(select(Record.id).where(Record.space_id == space_id, Record.base_id == record.id)):
                    fail(409, "record_is_base")
                if any(record.id in claim.inputs for claim in service.active_claims(session, space_id)):
                    fail(409, "record_claimed")
                service.release(session, space, record, who, "withdrawn", "record.withdrawn")
            return {"state": record.state}

    @app.post(prefix + "/records/{record_id}/blobs/{blob_id}/uploads")
    def start_upload(space_id: str, record_id: str, blob_id: str, who=Depends(authenticate)):
        with service.transaction(space_id, who) as (session, _, member):
            blob, record = service.owned_upload(session, space_id, blob_id, member, who)
            if record.id != record_id:
                fail(404, "blob_not_found")
            if blob.state == "reserved":
                service.transition(blob, "initiating")
            elif blob.state == "initiating":
                fail(409, "upload_initialization_pending")
            else:
                return {"id": blob.id, "state": blob.state, "part_bytes": blob.part_bytes}
        provider_id = service.storage.start(blob.key)
        with service.transaction(space_id, who) as (session, _, member):
            current = session.get(Blob, blob_id)
            if current.state == "initiating":
                current.upload_id = provider_id
                service.transition(current, "uploading")
            result = {"id": current.id, "state": current.state, "part_bytes": current.part_bytes}
            adopted = current.upload_id
        if adopted != provider_id:
            blob.upload_id = provider_id
            service.storage.abort(blob)
        return result

    @app.post(prefix + "/uploads/{blob_id}/parts:authorize")
    def authorize_parts(space_id: str, blob_id: str, body: PartsInput, who=Depends(authenticate)):
        with service.transaction(space_id, who) as (session, _, member):
            blob, _ = service.owned_upload(session, space_id, blob_id, member, who)
            if blob.state != "uploading":
                fail(409, "upload_not_open")
        try:
            return {"parts": service.storage.authorize(blob, body.part_numbers), "expires_in": service.settings.grant_seconds}
        except ValueError:
            fail(422, "invalid_part_number")

    @app.get(prefix + "/uploads/{blob_id}")
    def upload_status(space_id: str, blob_id: str, who=Depends(authenticate)):
        with service.transaction(space_id, who) as (session, _, member):
            blob, _ = service.owned_upload(session, space_id, blob_id, member, who)
        parts = service.storage.parts(blob) if blob.state == "uploading" else []
        return {"id": blob.id, "state": blob.state, "part_bytes": blob.part_bytes,
                "parts": [{"part_number": p["PartNumber"], "size_bytes": p["Size"]} for p in parts]}

    @app.post(prefix + "/uploads/{blob_id}:complete", status_code=202)
    def complete_upload(space_id: str, blob_id: str, who=Depends(authenticate)):
        with service.transaction(space_id, who) as (session, _, member):
            blob, _ = service.owned_upload(session, space_id, blob_id, member, who)
            if blob.state in ("verifying", "verified"):
                return {"id": blob.id, "state": blob.state}
            if blob.state not in ("uploading", "completing"):
                fail(409, "upload_not_open")
            service.transition(blob, "completing")
        try:
            version = service.storage.complete(blob)
        except ValueError as exc:
            with service.transaction(space_id, who) as (session, _, member):
                current = session.get(Blob, blob_id)
                if current.state == "completing":
                    service.transition(current, "uploading")
            log.warning("upload completion rejected blob=%s record=%s: %s", blob.id, blob.record_id, exc)
            fail(409, "upload_parts_incomplete_or_invalid")
        with service.transaction(space_id, who) as (session, _, member):
            current, record = service.owned_upload(session, space_id, blob_id, member, who)
            if current.state not in ("completing", "verifying", "verified"):
                fail(409, "upload_cancelled")
            if current.state == "completing":
                current.version = version
                service.transition(current, "verifying")
                # Verification time must not count against the transfer window.
                record.expires_at = max(record.expires_at, time.time() + service.settings.upload_seconds)
            return {"id": blob.id, "state": current.state}

    @app.delete(prefix + "/uploads/{blob_id}")
    def abort_upload(space_id: str, blob_id: str, who=Depends(authenticate)):
        with service.transaction(space_id, who) as (session, _, member):
            blob, _ = service.owned_upload(session, space_id, blob_id, member, who)
            if blob.state in ("verifying", "verified"):
                fail(409, "upload_already_completed")
            service.transition(blob, "aborted")
        service.storage.abort(blob)
        return {"state": "aborted"}

    @app.post(prefix + "/records/{record_id}/blobs/{blob_id}:download")
    def download(space_id: str, record_id: str, blob_id: str, who=Depends(authenticate)):
        with service.transaction(space_id, who) as (session, _, member):
            record = service.record(session, space_id, record_id, member, who)
            blob = session.get(Blob, blob_id)
            if not blob or blob.record_id != record.id or blob.state != "verified" or record.state != "ready":
                fail(404, "blob_not_available")
            service.emit(session, space_id, who, "download.authorized", record.id, blob_id=blob.id)
        return {"url": service.storage.download(blob), "expires_in": service.settings.grant_seconds,
                "sha256": blob.verified_sha256, "size_bytes": blob.size}

    @app.get(prefix + "/refs/{name}")
    def get_ref(space_id: str, name: str, who=Depends(authenticate)):
        with service.transaction(space_id, who) as (session, _, member):
            ref = session.get(Ref, (space_id, name))
            if not ref:
                fail(404, "reference_not_found")
            service.record(session, space_id, ref.record_id, member, who)
            return JSONResponse({"record_id": ref.record_id, "generation": ref.generation},
                                headers={"ETag": f'"{ref.generation}"'})

    @app.put(prefix + "/refs/{name}")
    def put_ref(space_id: str, name: str, body: RefInput, who=Depends(authenticate),
                if_match: str = Header(default=""), if_none_match: str = Header(default=""),
                idempotency_key: str = Header(default="")):
        with service.transaction(space_id, who, "coordinator") as (session, _, member):
            target = service.record(session, space_id, body.record_id, member, who)
            if name == "main" and any(claim.base_id == target.base_id for claim in service.active_claims(session, space_id)):
                fail(409, "active_claim_requires_fenced_publication")
            return service.once(session, who, space_id + "/refs/" + name, idempotency_key,
                                {**body.model_dump(), "expected": if_match, "absent": if_none_match},
                                lambda: service.move_ref(session, space_id, name, target, if_match, if_none_match, who))

    @app.get(prefix + "/events")
    def events(space_id: str, cursor: int = Query(default=0, ge=0), limit: int = Query(default=100, ge=1, le=256), who=Depends(authenticate)):
        with service.transaction(space_id, who) as (session, _, member):
            rows = list(session.scalars(select(Event).where(Event.space_id == space_id, Event.id > cursor).order_by(Event.id).limit(limit)))
            items = []
            for event in rows:
                if event.kind not in ("record.ready", "reference.updated"):
                    continue
                if session.scalar(select(Record.id).where(Record.id == event.record_id, service.visible(member, who))):
                    items.append({"id": event.id, "type": event.kind, "record_id": event.record_id, "data": event.data})
            return {"items": items, "next_cursor": rows[-1].id if rows else cursor}

    def claim_view(row, superseded=()):
        return {"id": row.id, "base_record_id": row.base_id, "inputs": row.inputs, "superseded": list(superseded),
                "fence": row.fence, "lease_until": row.lease_until, "holder": row.holder}

    def held_claim(session, space_id, claim_id, who):
        row = session.get(Claim, claim_id)
        if not row or row.space_id != space_id:
            fail(404, "claim_not_found")
        if row.holder != who.id:
            fail(409, "claim_held_by_other")
        return row

    @app.post(prefix + "/claims")
    def claim(space_id: str, body: ClaimInput, who=Depends(authenticate)):
        with service.transaction(space_id, who, "coordinator") as (session, _, member):
            ref = session.get(Ref, (space_id, "main"))
            if not ref:
                fail(404, "reference_not_found")
            existing = session.scalar(select(Claim).where(Claim.space_id == space_id, Claim.workflow == body.workflow, Claim.base_id == ref.record_id))
            superseded = []
            if existing:
                if existing.result_id:
                    fail(409, "claim_completed")
                if existing.lease_until > time.time():
                    fail(409, "claim_busy")
                existing.fence += 1
                existing.holder = who.id
                existing.lease_until = time.time() + body.lease_seconds
                if body.inputs is not None:
                    existing.inputs, superseded = service.frozen_inputs(session, space_id, ref.record_id, body)
                service.emit(session, space_id, who, "claim.acquired", claim_id=existing.id, fence=existing.fence)
            else:
                inputs, superseded = service.frozen_inputs(session, space_id, ref.record_id, body)
                existing = Claim(id=new_id("claim"), space_id=space_id, workflow=body.workflow,
                                 base_id=ref.record_id, ref_generation=ref.generation,
                                 inputs=inputs, holder=who.id, fence=1,
                                 lease_until=time.time() + body.lease_seconds)
                session.add(existing)
                session.flush()
                service.emit(session, space_id, who, "claim.acquired", claim_id=existing.id, fence=1, inputs=inputs)
            return claim_view(existing, superseded)

    @app.get(prefix + "/claims/{claim_id}")
    def get_claim(space_id: str, claim_id: str, who=Depends(authenticate)):
        with service.transaction(space_id, who, "coordinator") as (session, _, member):
            row = held_claim(session, space_id, claim_id, who)
            if row.lease_until <= time.time() or row.result_id:
                fail(409, "claim_not_active")
            return claim_view(row)

    @app.post(prefix + "/claims/{claim_id}:renew")
    def renew_claim(space_id: str, claim_id: str, body: LeaseInput, who=Depends(authenticate)):
        with service.transaction(space_id, who, "coordinator") as (session, _, member):
            row = held_claim(session, space_id, claim_id, who)
            if row.fence != body.fence or row.lease_until <= time.time() or row.result_id:
                fail(412, "claim_not_active")
            row.lease_until = time.time() + body.lease_seconds
            return {"id": row.id, "fence": row.fence, "lease_until": row.lease_until}

    @app.post(prefix + "/claims/{claim_id}:abandon")
    def abandon_claim(space_id: str, claim_id: str, body: ClaimAbandon, who=Depends(authenticate)):
        with service.transaction(space_id, who) as (session, _, member):
            admin = "admin" in member.roles
            if not admin and "coordinator" not in member.roles:
                fail(403, "permission_denied")
            row = session.get(Claim, claim_id)
            if not row or row.space_id != space_id:
                fail(404, "claim_not_found")
            if row.result_id:
                fail(409, "claim_completed")
            if row.holder != who.id and not admin:
                fail(409, "claim_held_by_other")
            if row.holder == who.id and body.fence != row.fence:
                fail(412, "claim_fence_changed")
            service.emit(session, space_id, who, "claim.abandoned", claim_id=row.id, holder=row.holder,
                         fence=row.fence, inputs=row.inputs, base_record_id=row.base_id)
            session.delete(row)
            return {"id": claim_id, "state": "abandoned"}

    @app.post(prefix + "/claims/{claim_id}:publish")
    def publish_claim(space_id: str, claim_id: str, body: ClaimResult, who=Depends(authenticate)):
        with service.transaction(space_id, who, "coordinator") as (session, _, member):
            claim = held_claim(session, space_id, claim_id, who)
            if claim.fence != body.fence:
                fail(412, "claim_fence_changed")
            if claim.result_id:
                if claim.result_id != body.record_id:
                    fail(409, "claim_completed")
                return {"record_id": claim.result_id}
            if claim.lease_until <= time.time():
                fail(412, "claim_lease_expired")
            target = service.record(session, space_id, body.record_id, member, who)
            declared = target.data.get("input_record_ids")
            # The result may use a validated subset of the frozen inputs, never anything outside it.
            if (target.base_id != claim.base_id or not isinstance(declared, list) or not declared
                    or not set(declared) <= set(claim.inputs)):
                fail(409, "claim_inputs_mismatch")
            result = service.move_ref(session, space_id, "main", target, f'"{claim.ref_generation}"', "", who)
            claim.result_id = target.id
            service.emit(session, space_id, who, "claim.completed", target.id, claim_id=claim.id, inputs=declared)
            return result

    return app
