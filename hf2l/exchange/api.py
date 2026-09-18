"""Authenticated JSON control plane; file bytes travel directly to S3."""
from contextlib import asynccontextmanager, contextmanager
import base64
import hashlib
import json
import math
import time
import uuid

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from jsonschema import Draft202012Validator, ValidationError, SchemaError
from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError

from .auth import Authenticator, Principal, principal_id
from .config import Settings
from .models import Blob, Claim, Event, Member, Operation, Record, Ref, Space, database
from .schemas import ClaimInput, ClaimResult, LeaseInput, MemberInput, MetadataInput, PartsInput, RecordInput, RefInput, SpaceInput
from .storage import S3BlobStore


def new_id(prefix):
    return prefix + "_" + uuid.uuid4().hex


def fail(status, code):
    raise HTTPException(status, code)


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

    def record(self, session, space_id, record_id, member, who, owner=False):
        record = session.scalar(select(Record).where(
            Record.id == record_id, Record.space_id == space_id, self.visible(member, who)))
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

    def move_ref(self, session, space_id, name, target, expected, absent, who):
        if not name or len(name) > 128:
            fail(422, "invalid_reference_name")
        current = session.get(Ref, (space_id, name))
        if target.state != "ready" or not target.shared:
            fail(409, "reference_target_must_be_shared_and_ready")
        if current:
            if expected != f'"{current.generation}"' or absent:
                fail(412, "reference_changed")
            if name == "main" and target.kind == "model.global" and target.base_id != current.record_id:
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


def create_app(settings=None, storage=None):
    service = Service(settings or Settings.from_env(), storage)

    @asynccontextmanager
    async def lifespan(app):
        service.storage.check()
        yield
        service.engine.dispose()

    app = FastAPI(title="HF2L Exchange", version="1", lifespan=lifespan)
    app.state.service = service

    @app.middleware("http")
    async def bounded_request(request, call_next):
        request.state.request_id = uuid.uuid4().hex
        # Read at most a bounded amount, including requests without Content-Length.
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > service.settings.max_body_bytes:
                return JSONResponse({"code": "request_too_large", "request_id": request.state.request_id}, 413)
        request._body = bytes(body)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        return JSONResponse({"code": exc.detail, "request_id": request.state.request_id}, exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse({"code": "invalid_request", "request_id": request.state.request_id}, 422)

    @app.exception_handler(IntegrityError)
    async def conflict(request, exc):
        return JSONResponse({"code": "resource_conflict", "request_id": request.state.request_id}, 409)

    @app.exception_handler(BotoCoreError)
    @app.exception_handler(ClientError)
    async def storage_error(request, exc):
        return JSONResponse({"code": "storage_unavailable", "request_id": request.state.request_id}, 503)

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
        for rule in body.rules.values():
            try:
                Draft202012Validator.check_schema(rule.metadata_schema)
            except SchemaError:
                fail(422, "invalid_metadata_schema")
            if "$ref" in json.dumps(rule.metadata_schema):
                fail(422, "external_schema_references_not_supported")
        with service.sessions.begin() as session:
            def operation():
                space = Space(id=new_id("sp"), tenant=body.tenant, name=body.name,
                              quota=body.quota_bytes, rules={k: v.model_dump() for k, v in body.rules.items()})
                session.add(space)
                session.flush()
                session.add(Member(space_id=space.id, principal=who.id, roles=["admin", "coordinator", "reader"]))
                service.emit(session, space.id, who, "space.created")
                return {"id": space.id, "name": space.name, "tenant": space.tenant}
            return service.once(session, who, "spaces", idempotency_key, body.model_dump(), operation)

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
            if len({x.name for x in body.attachments}) != len(body.attachments):
                fail(422, "duplicate_attachment_name")
            def operation():
                size = sum(x.size_bytes for x in body.attachments)
                if space.allocated + size > space.quota:
                    fail(429, "space_quota_exceeded")
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
            record = service.record(session, space_id, record_id, member, who, owner=True)
            if record.state == "ready":
                fail(409, "record_immutable")
            if record.state == "draft":
                record.state = "cancelled"
                space.allocated -= sum(b.size for b in service.blobs(session, record.id))
                service.emit(session, space_id, who, "record.cancelled", record.id)
            return {"state": record.state}

    @app.post(prefix + "/records/{record_id}/blobs/{blob_id}/uploads")
    def start_upload(space_id: str, record_id: str, blob_id: str, who=Depends(authenticate)):
        with service.transaction(space_id, who) as (session, _, member):
            blob, record = service.owned_upload(session, space_id, blob_id, member, who)
            if record.id != record_id:
                fail(404, "blob_not_found")
            if blob.state == "reserved":
                blob.state = "initiating"
            elif blob.state == "initiating":
                fail(409, "upload_initialization_pending")
            else:
                return {"id": blob.id, "state": blob.state, "part_bytes": blob.part_bytes}
        provider_id = service.storage.start(blob.key)
        with service.transaction(space_id, who) as (session, _, member):
            current = session.get(Blob, blob_id)
            if current.state == "initiating":
                current.upload_id = provider_id
                current.state = "uploading"
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
            blob.state = "completing"
        try:
            version = service.storage.complete(blob)
        except ValueError:
            with service.transaction(space_id, who) as (session, _, member):
                session.get(Blob, blob_id).state = "uploading"
            fail(409, "upload_parts_incomplete_or_invalid")
        with service.transaction(space_id, who) as (session, _, member):
            current, _ = service.owned_upload(session, space_id, blob_id, member, who)
            if current.state not in ("completing", "verifying", "verified"):
                fail(409, "upload_cancelled")
            if current.state == "completing":
                current.version, current.state = version, "verifying"
            return {"id": blob.id, "state": current.state}

    @app.delete(prefix + "/uploads/{blob_id}")
    def abort_upload(space_id: str, blob_id: str, who=Depends(authenticate)):
        with service.transaction(space_id, who) as (session, _, member):
            blob, _ = service.owned_upload(session, space_id, blob_id, member, who)
            blob.state = "aborted"
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
            if name == "main" and session.scalar(select(Claim).where(
                Claim.space_id == space_id, Claim.base_id == target.base_id, Claim.result_id.is_(None))):
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

    @app.post(prefix + "/claims")
    def claim(space_id: str, body: ClaimInput, who=Depends(authenticate)):
        with service.transaction(space_id, who, "coordinator") as (session, _, member):
            ref = session.get(Ref, (space_id, "main"))
            if not ref:
                fail(404, "reference_not_found")
            existing = session.scalar(select(Claim).where(Claim.space_id == space_id, Claim.workflow == body.workflow, Claim.base_id == ref.record_id))
            if existing:
                if existing.result_id:
                    fail(409, "claim_completed")
                if existing.lease_until > time.time():
                    fail(409, "claim_busy")
                existing.fence += 1
                existing.holder = who.id
                existing.lease_until = time.time() + body.lease_seconds
            else:
                records = list(session.scalars(select(Record).where(Record.space_id == space_id,
                    Record.kind == "training.update", Record.state == "ready", Record.base_id == ref.record_id).order_by(Record.id)))
                if len(records) < body.minimum:
                    fail(409, "insufficient_submissions")
                if len({r.participant for r in records}) != len(records):
                    fail(409, "duplicate_participant")
                existing = Claim(id=new_id("claim"), space_id=space_id, workflow=body.workflow,
                                 base_id=ref.record_id, ref_generation=ref.generation,
                                 inputs=[r.id for r in records], holder=who.id, fence=1,
                                 lease_until=time.time() + body.lease_seconds)
                session.add(existing)
            return {"id": existing.id, "base_record_id": existing.base_id, "inputs": existing.inputs,
                    "fence": existing.fence, "lease_until": existing.lease_until}

    @app.get(prefix + "/claims/{claim_id}")
    def get_claim(space_id: str, claim_id: str, who=Depends(authenticate)):
        with service.transaction(space_id, who, "coordinator") as (session, _, member):
            row = session.get(Claim, claim_id)
            if not row or row.space_id != space_id or row.holder != who.id:
                fail(404, "claim_not_found")
            if row.lease_until <= time.time() or row.result_id:
                fail(409, "claim_not_active")
            return {"id": row.id, "base_record_id": row.base_id, "inputs": row.inputs,
                    "fence": row.fence, "lease_until": row.lease_until}

    @app.post(prefix + "/claims/{claim_id}:renew")
    def renew_claim(space_id: str, claim_id: str, body: LeaseInput, who=Depends(authenticate)):
        with service.transaction(space_id, who, "coordinator") as (session, _, member):
            row = session.get(Claim, claim_id)
            if not row or row.space_id != space_id or row.holder != who.id:
                fail(404, "claim_not_found")
            if row.fence != body.fence or row.lease_until <= time.time() or row.result_id:
                fail(412, "claim_not_active")
            row.lease_until = time.time() + body.lease_seconds
            return {"id": row.id, "fence": row.fence, "lease_until": row.lease_until}

    @app.post(prefix + "/claims/{claim_id}:publish")
    def publish_claim(space_id: str, claim_id: str, body: ClaimResult, who=Depends(authenticate)):
        with service.transaction(space_id, who, "coordinator") as (session, _, member):
            claim = session.get(Claim, claim_id)
            if not claim or claim.space_id != space_id or claim.holder != who.id:
                fail(404, "claim_not_found")
            if claim.fence != body.fence:
                fail(412, "claim_fence_changed")
            if claim.result_id:
                if claim.result_id != body.record_id:
                    fail(409, "claim_completed")
                return {"record_id": claim.result_id}
            if claim.lease_until <= time.time():
                fail(412, "claim_lease_expired")
            target = service.record(session, space_id, body.record_id, member, who)
            if target.base_id != claim.base_id or target.data.get("input_record_ids") != claim.inputs:
                fail(409, "claim_inputs_mismatch")
            result = service.move_ref(session, space_id, "main", target, f'"{claim.ref_generation}"', "", who)
            claim.result_id = target.id
            return result

    return app
