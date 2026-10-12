"""Transaction-owned exchange commands, independent of HTTP and blob providers.

All space mutations acquire the same space row lock. This deliberately conservative
boundary makes authorization, quota admission, reference CAS and fencing atomic.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import math
import re
import uuid

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.orm import sessionmaker

from .domain import Error, principal_id as bound_principal_id
from .models import (Blob, Coordination, CoordinationInput, Event, KindPolicy, Member,
                     Operation, Record, Reference, SchemaRevision, Space,
                     TransferAttempt, ManagedSpace, WorkloadGrant, WorkloadRevocation, database, database_time)
from .profiles import get_profile
from .schemas import (MAX_ATTACHMENTS, canonical_bytes, metadata_size, validate_kind, validate_metadata, validate_path,
                      validate_schema)

ROLES = frozenset({'reader', 'contributor', 'publisher', 'admin'})
TERMINAL = frozenset({'withdrawn', 'cancelled', 'failed', 'expired'})
TERMINAL_EVENTS = frozenset('record.' + state for state in TERMINAL)


def identifier():
    return uuid.uuid4().hex


def canonical(value):
    return canonical_bytes(value)


def principal_id(principal):
    return principal.id if hasattr(principal, 'id') else str(principal)


class Service:
    def __init__(self, settings, engine=None, sessions=None):
        self.settings = settings
        if engine is None:
            engine, sessions = database(settings.database)
        self.engine = engine
        self.sessions = sessions or sessionmaker(engine, expire_on_commit=False)
        read_engine = engine.execution_options(exchange_write=False)
        if engine.dialect.name == 'postgresql':
            read_engine = read_engine.execution_options(isolation_level='REPEATABLE READ')
        self.read_sessions = sessionmaker(read_engine, expire_on_commit=False)

    @contextmanager
    def transaction(self, space_id, principal, write=True, *, allow_retired=False):
        """Current membership and space state share the command's transaction."""
        factory = self.sessions if write else self.read_sessions
        with factory.begin() as session:
            query = select(Space).where(Space.id == space_id)
            if write:
                query = query.with_for_update()
            space = session.scalar(query)
            if space is None:
                raise Error(404, 'space_not_found')
            member = session.get(Member, (space_id, principal_id(principal)))
            if member is None or not member.roles:
                raise Error(404, 'space_not_found')
            managed = session.get(ManagedSpace, space_id)
            workload = getattr(principal, "workload", None)
            if workload is not None:
                grant = self._matching_grant(session, space, member, principal, managed)
                # Construct an untracked authorization view: never mutate persisted
                # membership while applying a grant role ceiling.
                member = Member(space_id=member.space_id, principal_id=member.principal_id,
                                subject=member.subject, roles=sorted(set(member.roles).intersection(grant.roles)),
                                bindings=dict(member.bindings))
            elif managed is not None:
                permitted = self.settings.auth.provisioning_principal_ids + self.settings.auth.download_broker_principal_ids
                if principal_id(principal) not in permitted:
                    raise Error(404, "space_not_found")
                if principal_id(principal) not in self.settings.auth.provisioning_principal_ids:
                    # Download brokers never gain mutation authority through an
                    # accidental privileged membership.
                    member = Member(space_id=member.space_id, principal_id=member.principal_id,
                                    subject=member.subject, roles=sorted(set(member.roles).intersection({"reader"})),
                                    bindings=dict(member.bindings))
                    if not member.roles:
                        raise Error(404, "space_not_found")
            if managed is not None and managed.retired_at is not None and write and not allow_retired:
                raise Error(409, "managed_space_retired")
            yield session, space, member

    def _matching_grant(self, session, space, member, principal, managed):
        identity = principal.workload
        if (not self.settings.auth.workloads_enabled or managed is None or managed.retired_at is not None
                or identity.space_id != space.id):
            raise Error(404, "space_not_found")
        grant = session.get(WorkloadGrant, identity.grant_id)
        now = database_time(session)
        if (grant is None or not grant.enabled or grant.expires_at <= now or identity.expires_at <= now
                or grant.space_id != space.id or grant.principal_id != principal_id(principal)
                or grant.subject != principal.subject or grant.job_id != managed.job_id
                or grant.job_id != identity.job_id or grant.attempt_id != identity.attempt_id
                or grant.component_id != identity.component_id or grant.epoch != identity.epoch
                or grant.certificate_thumbprint != identity.certificate_thumbprint
                or grant.bindings != member.bindings):
            raise Error(403, "workload_grant_invalid")
        if not set(member.roles).intersection(grant.roles):
            raise Error(403, "workload_grant_invalid")
        return grant

    def _require_provisioner(self, principal):
        if (not self.settings.auth.workloads_enabled or getattr(principal, "workload", None) is not None
                or principal_id(principal) not in self.settings.auth.provisioning_principal_ids):
            raise Error(403, "provisioning_principal_required")

    def is_managed_space(self, space_id):
        with self.read_sessions.begin() as session:
            return session.get(ManagedSpace, space_id) is not None

    @staticmethod
    def grant_dict(grant):
        result = {name: getattr(grant, name) for name in (
            "principal_id", "space_id", "subject", "job_id", "attempt_id", "component_id", "epoch",
            "roles", "bindings", "certificate_thumbprint", "expires_at", "enabled", "created_at", "revoked_at")}
        result["grant_id"] = grant.id
        return result

    def enable_managed_space(self, principal, space_id, body, key):
        self._require_provisioner(principal)
        job_id = body.get("job_id")
        if not isinstance(job_id, str) or not 1 <= len(job_id) <= 128:
            raise Error(422, "invalid_job_binding")
        with self.transaction(space_id, principal) as (session, space, member):
            self.require(member, "admin")
            def enable():
                existing = session.get(ManagedSpace, space_id)
                if existing is not None:
                    if existing.job_id != job_id:
                        raise Error(409, "managed_space_binding_immutable")
                else:
                    foreign = session.scalar(select(ManagedSpace).where(ManagedSpace.job_id == job_id))
                    if foreign is not None:
                        raise Error(409, "managed_job_space_conflict")
                    session.add(ManagedSpace(space_id=space_id, job_id=job_id, created_at=database_time(session)))
                    self.emit(session, space, "space.managed_enabled", principal, data={"job_id": job_id})
                return {"space_id": space_id, "job_id": job_id, "managed": True}
            return self.once(session, space, principal, "space.managed", key, body, enable)

    @staticmethod
    def _managed_state(session, managed):
        blobs = session.scalars(select(Blob).where(Blob.space_id == managed.space_id)).all()
        attempts = session.scalars(select(TransferAttempt).where(
            TransferAttempt.blob_id.in_([blob.id for blob in blobs]))).all()
        pending = any(blob.state != "cleaned" for blob in blobs) or any(attempt.mutation_tokens for attempt in attempts)
        return {"space_id": managed.space_id, "job_id": managed.job_id, "managed": True,
                "status": "retired" if managed.retired_at is not None else "active",
                "retired_at": managed.retired_at, "cleanup_pending": bool(pending and managed.retired_at is not None),
                "provenance_retained": True}

    def get_managed_space(self, principal, space_id):
        with self.transaction(space_id, principal, False) as (session, _, member):
            self.require(member, "reader", "admin")
            managed = session.get(ManagedSpace, space_id)
            if managed is None:
                raise Error(404, "managed_space_not_found")
            return self._managed_state(session, managed)

    def retire_managed_space(self, principal, space_id, body, key):
        """Retire owned data through existing worker cleanup, retaining history.

        No namespace, provenance, membership, or revocation ledger is deleted.
        Callers separately confirm runtime termination before resource retirement.
        """
        self._require_provisioner(principal)
        job_id = body.get("job_id")
        if not isinstance(job_id, str) or not 1 <= len(job_id) <= 128:
            raise Error(422, "invalid_job_binding")
        with self.transaction(space_id, principal, allow_retired=True) as (session, space, caller):
            self.require(caller, "admin")
            managed = session.get(ManagedSpace, space_id)
            if managed is None or managed.job_id != job_id:
                raise Error(409, "managed_space_binding_required")
            def retire():
                if session.scalar(select(WorkloadGrant.id).where(WorkloadGrant.space_id == space_id,
                                   WorkloadGrant.enabled.is_(True)).limit(1)):
                    raise Error(409, "workload_revocation_required")
                if managed.retired_at is None:
                    managed.retired_at = database_time(session)
                    records = session.scalars(select(Record).where(Record.space_id == space_id)).all()
                    for record in records:
                        self.release(session, space, record,
                                     "withdrawn" if record.state == "published" else "cancelled")
                    self.emit(session, space, "space.managed_retired", principal, data={"job_id": job_id})
                    session.flush()
                return self._managed_state(session, managed)
            return self.once(session, space, principal, "space.managed.retire", key, body, retire)

    def create_workload_grant(self, principal, space_id, body, key):
        self._require_provisioner(principal)
        for field, limit in (("subject", 256), ("job_id", 128), ("attempt_id", 128), ("component_id", 128)):
            if not isinstance(body.get(field), str) or not 1 <= len(body[field]) <= limit:
                raise Error(422, "invalid_workload_binding")
        if type(body.get("epoch")) is not int or not 1 <= body["epoch"] <= 2**63 - 1:
            raise Error(422, "invalid_workload_epoch")
        thumbprint = body.get("certificate_thumbprint")
        if not isinstance(thumbprint, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", thumbprint):
            raise Error(422, "invalid_certificate_thumbprint")
        roles = body.get("roles")
        bindings = body.get("bindings", {})
        if not isinstance(roles, list) or not roles or any(role not in ROLES for role in roles):
            raise Error(422, "invalid_roles")
        if not isinstance(bindings, dict):
            raise Error(422, "invalid_bindings")
        metadata_size(bindings)
        expiry = body.get("expires_at")
        if type(expiry) not in {int, float} or not math.isfinite(expiry):
            raise Error(422, "invalid_grant_expiry")
        pid = bound_principal_id(self.settings.auth.workload_issuer, body["subject"])
        with self.transaction(space_id, principal) as (session, space, caller):
            self.require(caller, "admin")
            def create():
                managed = session.get(ManagedSpace, space_id)
                if managed is None or managed.job_id != body["job_id"]:
                    raise Error(409, "managed_space_binding_required")
                if session.get(WorkloadRevocation, (space_id, body["attempt_id"])) is not None:
                    raise Error(409, "attempt_already_revoked")
                member = session.get(Member, (space_id, pid))
                if member is None or not set(roles).issubset(member.roles) or member.bindings != bindings:
                    raise Error(403, "workload_membership_required")
                now = database_time(session)
                if not now < expiry <= now + 30 * 86400:
                    raise Error(422, "invalid_grant_expiry")
                previous = session.scalars(select(WorkloadGrant).where(
                    WorkloadGrant.space_id == space_id, WorkloadGrant.principal_id == pid)).all()
                if any(grant.component_id != body["component_id"] for grant in previous):
                    raise Error(409, "workload_component_immutable")
                highest = max((grant.epoch for grant in previous), default=0)
                if body["epoch"] < highest:
                    raise Error(409, "stale_workload_epoch")
                # Expiry is not a takeover barrier. An old execution must be
                # explicitly revoked even after its last token/grant expires.
                if any(grant.enabled and (grant.attempt_id != body["attempt_id"] or grant.epoch != body["epoch"])
                       for grant in previous):
                    raise Error(409, "previous_attempt_not_revoked")
                if any(grant.attempt_id != body["attempt_id"] and grant.epoch >= body["epoch"]
                       for grant in previous):
                    raise Error(409, "stale_workload_epoch")
                gid = hashlib.sha256(canonical([space_id, principal_id(principal), key])).hexdigest()
                grant = WorkloadGrant(id=gid, space_id=space_id, principal_id=pid, subject=body["subject"],
                    job_id=body["job_id"], attempt_id=body["attempt_id"], component_id=body["component_id"],
                    epoch=body["epoch"], roles=sorted(set(roles)), bindings=dict(bindings),
                    certificate_thumbprint=thumbprint, expires_at=float(expiry), enabled=True, created_at=now)
                session.add(grant)
                session.flush()
                self.emit(session, space, "workload.granted", principal,
                          data={"grant_id": gid, "principal_id": pid, "attempt_id": grant.attempt_id, "epoch": grant.epoch})
                return self.grant_dict(grant)
            return self.once(session, space, principal, "workload.grant", key, body, create)

    def revoke_workload_grants(self, principal, space_id, body, key):
        self._require_provisioner(principal)
        attempt_id = body.get("attempt_id")
        if not isinstance(attempt_id, str) or not 1 <= len(attempt_id) <= 128:
            raise Error(422, "invalid_attempt_binding")
        with self.transaction(space_id, principal, allow_retired=True) as (session, space, caller):
            self.require(caller, "admin")
            def revoke():
                now = database_time(session)
                tombstone = session.get(WorkloadRevocation, (space_id, attempt_id))
                if tombstone is None:
                    session.add(WorkloadRevocation(space_id=space_id, attempt_id=attempt_id, revoked_at=now))
                else:
                    now = tombstone.revoked_at
                grants = session.scalars(select(WorkloadGrant).where(WorkloadGrant.space_id == space_id,
                                       WorkloadGrant.attempt_id == attempt_id, WorkloadGrant.enabled.is_(True))).all()
                for grant in grants:
                    grant.enabled, grant.revoked_at = False, now
                self.emit(session, space, "workload.revoked", principal,
                          data={"attempt_id": attempt_id, "revoked": len(grants)})
                return {"attempt_id": attempt_id, "revoked": len(grants), "revoked_at": now}
            return self.once(session, space, principal, "workload.revoke", key, body, revoke)

    def get_workload_grant(self, principal, space_id, grant_id):
        self._require_provisioner(principal)
        with self.transaction(space_id, principal, False) as (session, _, member):
            self.require(member, "admin")
            grant = session.get(WorkloadGrant, grant_id)
            if grant is None or grant.space_id != space_id:
                raise Error(404, "workload_grant_not_found")
            return self.grant_dict(grant)

    def verify_workload_grant(self, principal, space_id):
        if getattr(principal, "workload", None) is None:
            raise Error(403, "workload_required")
        with self.transaction(space_id, principal, False) as (session, _, member):
            result = self.grant_dict(session.get(WorkloadGrant, principal.workload.grant_id))
            result["effective_roles"] = list(member.roles)
            return result

    @staticmethod
    def require(member, *roles):
        if not set(member.roles).intersection(roles):
            raise Error(403, 'role_required')

    @staticmethod
    def emit(session, space, kind, principal, record_id=None, data=None):
        session.add(Event(space_id=space.id if hasattr(space, 'id') else space,
                          type=kind, principal_id=principal_id(principal),
                          record_id=record_id, payload=data or {},
                          created_at=database_time(session)))

    def once(self, session, space, principal, scope, key, body, action):
        if not isinstance(key, str) or not key or len(key) > 128:
            raise Error(422, 'idempotency_key_required')
        identity = (space.id, principal_id(principal), scope, key)
        digest = hashlib.sha256(canonical(body)).hexdigest()
        operation = session.get(Operation, identity)
        if operation:
            if operation.request_hash != digest:
                raise Error(409, 'idempotency_conflict')
            return operation.response
        result = action()
        session.add(Operation(space_id=space.id, principal_id=principal_id(principal),
                              scope=scope, key=key, request_hash=digest,
                              response=result, created_at=database_time(session)))
        session.flush()
        return result

    @staticmethod
    def space_dict(space):
        return {name: getattr(space, name) for name in (
            'id', 'name', 'profile', 'quota_bytes', 'principal_quota_bytes', 'allocated',
            'reclaiming', 'quota_records', 'record_count', 'quota_metadata_bytes',
            'metadata_bytes', 'generation')}

    @staticmethod
    def member_dict(member):
        return {name: getattr(member, name) for name in
                ('principal_id', 'subject', 'roles', 'bindings')}

    def create_space(self, principal, body, key):
        if getattr(principal, "workload", None) is not None:
            raise Error(403, "bootstrap_admin_required")
        if not getattr(principal, 'bootstrap_admin', False):
            if not self.settings.auth.admin_subject or getattr(principal, 'subject', None) != self.settings.auth.admin_subject:
                raise Error(403, 'bootstrap_admin_required')
        if not isinstance(key, str) or not key or len(key) > 128:
            raise Error(422, 'idempotency_key_required')
        profile = body.get('profile', 'generic.v1')
        get_profile(profile)
        name = body.get('name')
        if not isinstance(name, str) or not name or len(name) > 128:
            raise Error(422, 'invalid_space_name')
        # A stable space identity also makes retries safe before an operation exists.
        sid = hashlib.sha256(canonical([principal_id(principal), key])).hexdigest()[:32]
        with self.sessions.begin() as session:
            if self.engine.dialect.name == "postgresql":
                session.execute(select(func.pg_advisory_xact_lock(func.hashtext(sid))))
            space = session.scalar(select(Space).where(Space.id == sid).with_for_update())
            if space is None:
                limits = {name: body.get(name, default) for name, default in (
                    ('quota_bytes', 10 * 1024**3), ('principal_quota_bytes', 10 * 1024**3),
                    ('quota_records', 100000), ('quota_metadata_bytes', 1024**3))}
                if any(type(value) is not int or not 1 <= value <= 2**63 - 1 for value in limits.values()):
                    raise Error(422, 'invalid_quota')
                space = Space(id=sid, name=name, profile=profile, **limits)
                session.add(space)
                session.flush()
                session.add(Member(space_id=sid, principal_id=principal_id(principal),
                                   subject=getattr(principal, 'subject', None),
                                   roles=sorted(ROLES), bindings={}))
                self.emit(session, space, 'space.created', principal)
            session.flush()
            membership = session.get(Member, (sid, principal_id(principal)))
            if membership is None or not membership.roles:
                raise Error(404, 'space_not_found')
            return self.once(session, space, principal, 'space.create', key, body,
                             lambda: self.space_dict(space))

    def get_space(self, principal, space_id):
        with self.transaction(space_id, principal, False) as (session, space, _):
            result = self.space_dict(space)
            managed = session.get(ManagedSpace, space_id)
            if managed is not None:
                result.update({"managed": True, "job_id": managed.job_id, "retired_at": managed.retired_at})
            return result

    def update_space_limits(self, principal, space_id, body):
        """Change admission limits without discarding retained provenance or data."""
        fields = {'quota_bytes', 'principal_quota_bytes', 'quota_records', 'quota_metadata_bytes'}
        if not isinstance(body, dict) or not body or set(body) - fields:
            raise Error(422, 'invalid_quota_fields')
        if any(type(value) is not int or not 1 <= value <= 2**63 - 1 for value in body.values()):
            raise Error(422, 'invalid_quota')
        with self.transaction(space_id, principal) as (session, space, member):
            self.require(member, 'admin')
            usage = {'quota_bytes': space.allocated + space.reclaiming,
                     'quota_records': space.record_count, 'quota_metadata_bytes': space.metadata_bytes}
            if 'principal_quota_bytes' in body:
                usage['principal_quota_bytes'] = session.scalar(select(func.sum(Blob.size))
                    .join(Record, Record.id == Blob.record_id)
                    .where(Record.space_id == space_id, Blob.state != 'cleaned')
                    .group_by(Record.creator).order_by(func.sum(Blob.size).desc()).limit(1)) or 0
            if any(limit < usage.get(name, 0) for name, limit in body.items()):
                raise Error(409, 'quota_below_current_usage')
            for name, value in body.items():
                setattr(space, name, value)
            space.generation += 1
            self.emit(session, space, 'space.limits_updated', principal, data=dict(body))
            return self.space_dict(space)

    def get_membership(self, principal, space_id):
        with self.transaction(space_id, principal, False) as (_, _, member):
            return self.member_dict(member)

    def list_members(self, principal, space_id):
        with self.transaction(space_id, principal, False) as (session, _, member):
            self.require(member, 'admin')
            rows = session.scalars(select(Member).where(Member.space_id == space_id)
                                   .order_by(Member.principal_id)).all()
            return {'items': [self.member_dict(row) for row in rows]}

    def put_member(self, principal, space_id, member_id, body):
        with self.transaction(space_id, principal) as (session, space, caller):
            self.require(caller, 'admin')
            if not isinstance(member_id, str) or not 1 <= len(member_id) <= 64:
                raise Error(422, 'invalid_principal_id')
            subject = body.get('subject')
            if subject is not None and (not isinstance(subject, str) or not 1 <= len(subject) <= 256):
                raise Error(422, 'invalid_subject')
            roles = body.get('roles', [])
            bindings = body.get('bindings', {})
            if not isinstance(roles, list) or any(role not in ROLES for role in roles):
                raise Error(422, 'invalid_roles')
            if not isinstance(bindings, dict):
                raise Error(422, 'invalid_bindings')
            metadata_size(bindings)
            others = session.scalars(select(Member).where(Member.space_id == space_id,
                                                            Member.principal_id != member_id)).all()
            get_profile(space.profile).validate_bindings(bindings, [other.bindings for other in others])
            current = session.get(Member, (space_id, member_id))
            if current and 'admin' in current.roles and 'admin' not in roles:
                admins = [m for m in session.scalars(select(Member).where(Member.space_id == space_id))
                          if 'admin' in m.roles and m.principal_id != member_id]
                if not admins:
                    raise Error(409, 'last_admin')
            if current is None:
                current = Member(space_id=space_id, principal_id=member_id)
                session.add(current)
            current.roles, current.bindings = sorted(set(roles)), dict(bindings)
            current.subject = body.get('subject')
            self.emit(session, space, 'membership.changed', principal,
                      data={'principal_id': member_id})
            return self.member_dict(current)

    @staticmethod
    def type_dict(revision):
        return {name: getattr(revision, name) for name in
                ('id', 'space_id', 'kind', 'revision', 'schema', 'profile_version', 'digest', 'dialect')}

    @staticmethod
    def validate_policy(body):
        roles = body.get('publish_roles', ['contributor', 'publisher'])
        visibility = body.get('visibility', 'shared')
        if not isinstance(roles, list) or not roles or any(r not in {'contributor', 'publisher'} for r in roles):
            raise Error(422, 'invalid_publish_roles')
        if visibility not in {'shared', 'private'}:
            raise Error(422, 'invalid_visibility')
        return sorted(set(roles)), visibility

    def register_type(self, principal, space_id, kind, body, key):
        with self.transaction(space_id, principal) as (session, space, member):
            self.require(member, 'admin')
            validate_kind(kind)
            schema = body.get('schema', {})
            validate_schema(schema)
            get_profile(space.profile).validate_type(kind, schema)
            policy_body = get_profile(space.profile).policy_defaults(kind) | body
            roles, visibility = self.validate_policy(policy_body)
            get_profile(space.profile).validate_policy(kind, roles, visibility)
            def create():
                number = session.scalar(select(func.max(SchemaRevision.revision)).where(
                    SchemaRevision.space_id == space_id, SchemaRevision.kind == kind)) or 0
                revision = SchemaRevision(id=identifier(), space_id=space_id, kind=kind,
                    revision=number + 1, schema=schema, profile_version=space.profile,
                    digest=hashlib.sha256(canonical(schema)).hexdigest(),
                    dialect=schema.get('$schema', 'https://json-schema.org/draft/2020-12/schema'),
                    created_at=database_time(session))
                session.add(revision)
                if session.get(KindPolicy, (space_id, kind)) is None:
                    session.add(KindPolicy(space_id=space_id, kind=kind,
                                           publish_roles=roles, visibility=visibility))
                session.flush()
                self.emit(session, space, 'type.registered', principal,
                          data={'kind': kind, 'revision': revision.revision})
                return self.type_dict(revision)
            return self.once(session, space, principal, 'type.register:' + kind, key, body, create)

    def get_type(self, principal, space_id, kind, revision):
        with self.transaction(space_id, principal, False) as (session, _, _):
            row = session.scalar(select(SchemaRevision).where(SchemaRevision.space_id == space_id,
                       SchemaRevision.kind == kind, SchemaRevision.revision == revision))
            if row is None:
                raise Error(404, 'type_not_found')
            return self.type_dict(row)

    def list_types(self, principal, space_id):
        with self.transaction(space_id, principal, False) as (session, _, _):
            rows = session.scalars(select(SchemaRevision).where(SchemaRevision.space_id == space_id)
                         .order_by(SchemaRevision.kind, SchemaRevision.revision)).all()
            return {'items': [self.type_dict(row) for row in rows]}

    def put_policy(self, principal, space_id, kind, body):
        with self.transaction(space_id, principal) as (session, space, member):
            self.require(member, 'admin')
            roles, visibility = self.validate_policy(body)
            get_profile(space.profile).validate_policy(kind, roles, visibility)
            policy = session.get(KindPolicy, (space_id, kind))
            if policy is None:
                raise Error(404, 'type_not_found')
            if visibility == 'private' and session.scalar(select(Reference.name).join(
                    Record, and_(Reference.space_id == Record.space_id, Reference.record_id == Record.id))
                    .where(Reference.space_id == space_id, Record.kind == kind)):
                raise Error(409, 'policy_reference_conflict')
            policy.publish_roles, policy.visibility = roles, visibility
            policy.generation += 1
            session.execute(update(Record).where(Record.space_id == space_id, Record.kind == kind)
                            .values(shared=visibility == 'shared'))
            self.emit(session, space, 'policy.changed', principal, data={'kind': kind})
            return {'kind': kind, 'publish_roles': roles, 'visibility': visibility}

    @staticmethod
    def visible_clause(member, principal):
        clauses = []
        if set(member.roles) & {'reader', 'contributor', 'publisher'}:
            clauses.append(and_(Record.state == 'published', Record.shared.is_(True)))
        if 'contributor' in member.roles:
            clauses.append(Record.creator == principal_id(principal))
        if 'publisher' in member.roles:
            clauses.append(Record.state == 'published')
            clauses.append(Record.creator == principal_id(principal))
        return or_(*clauses) if clauses else Record.id == '__none__'

    def record(self, session, space_id, record_id, member, principal, write=False):
        record = session.scalar(select(Record).where(Record.space_id == space_id, Record.id == record_id))
        if record is None:
            raise Error(404, 'record_not_found')
        if write:
            self.require(member, 'contributor', 'publisher')
            if record.creator != principal_id(principal):
                raise Error(403, 'record_owner_required')
        elif session.scalar(select(Record.id).where(Record.id == record_id,
                               self.visible_clause(member, principal))) is None:
            raise Error(404, 'record_not_found')
        return record

    @staticmethod
    def attachment(session, space_id, record_id, attachment_id):
        blob = session.scalar(select(Blob).where(Blob.id == attachment_id,
                         Blob.space_id == space_id, Blob.record_id == record_id))
        if blob is None:
            raise Error(404, 'attachment_not_found')
        return blob

    @staticmethod
    def blob_dict(blob):
        return {name: getattr(blob, name) for name in
                ('id', 'path', 'size', 'sha256', 'media_type', 'state', 'part_size')}

    def record_dict(self, session, record, blobs=None):
        if blobs is None:
            blobs = session.scalars(select(Blob).where(Blob.record_id == record.id).order_by(Blob.path)).all()
        return {'id': record.id, 'space_id': record.space_id, 'kind': record.kind,
                'schema_revision_id': record.schema_revision_id, 'metadata': record.metadata_json,
                'state': record.state, 'version': record.generation, 'shared': record.shared,
                'creator': record.creator, 'creator_bindings': record.creator_bindings,
                'created_at': record.created_at, 'published_at': record.published_at,
                'expires_at': record.expires_at, 'attachments': [self.blob_dict(b) for b in blobs]}

    def create_record(self, principal, space_id, body, key):
        with self.transaction(space_id, principal) as (session, space, member):
            self.require(member, 'contributor', 'publisher')
            def create():
                revision = session.get(SchemaRevision, body.get('schema_revision_id'))
                if revision is None or revision.space_id != space_id or revision.kind != body.get('kind'):
                    raise Error(422, 'type_revision_mismatch')
                policy = session.get(KindPolicy, (space_id, revision.kind))
                self.require(member, *policy.publish_roles)
                metadata = body.get('metadata', {})
                size = validate_metadata(metadata, revision.schema)
                get_profile(space.profile).validate_record(revision.kind, metadata, member.bindings)
                attachments = body.get('attachments', [])
                if not isinstance(attachments, list) or len(attachments) > MAX_ATTACHMENTS:
                    raise Error(422, 'too_many_attachments')
                paths = set()
                amount = 0
                for attachment in attachments:
                    path = validate_path(attachment.get('path'))
                    if any(path.casefold() == existing or path.casefold().startswith(existing + '/') or
                           existing.startswith(path.casefold() + '/') for existing in paths):
                        raise Error(422, 'duplicate_attachment_path')
                    paths.add(path.casefold())
                    length, digest = attachment.get('size'), attachment.get('sha256')
                    if type(length) is not int or length < 0 or length > 5 * 1024**4:
                        raise Error(422, 'invalid_attachment_size')
                    if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                        raise Error(422, 'invalid_attachment_digest')
                    amount += length
                if space.record_count + 1 > space.quota_records or space.metadata_bytes + size > space.quota_metadata_bytes:
                    raise Error(409, 'metadata_quota_exceeded')
                if space.allocated + space.reclaiming + amount > space.quota_bytes:
                    raise Error(409, 'blob_quota_exceeded')
                used = session.scalar(select(func.coalesce(func.sum(Blob.size), 0)).join(Record, Record.id == Blob.record_id)
                        .where(Record.space_id == space_id, Record.creator == principal_id(principal),
                               Blob.state != 'cleaned'))
                if used + amount > space.principal_quota_bytes:
                    raise Error(409, 'principal_blob_quota_exceeded')
                now = database_time(session)
                base_id = get_profile(space.profile).record_base_id(body['kind'], metadata)
                if base_id:
                    base = self.record(session, space_id, base_id, member, principal)
                    if base.state != 'published':
                        raise Error(409, 'base_not_published')
                record = Record(id=identifier(), space_id=space_id, kind=revision.kind,
                    schema_revision_id=revision.id, creator=principal_id(principal),
                    creator_bindings=dict(member.bindings), metadata_json=metadata,
                    metadata_bytes=size, declared_bytes=amount, shared=policy.visibility == 'shared',
                    state='draft', generation=1, base_record_id=base_id, created_at=now,
                    expires_at=now + self.settings.draft_seconds)
                session.add(record)
                session.flush()
                for attachment in attachments:
                    blob_id = identifier()
                    session.add(Blob(id=blob_id, space_id=space_id, record_id=record.id,
                        path=attachment['path'], size=attachment['size'], sha256=attachment['sha256'],
                        media_type=attachment.get('media_type', 'application/octet-stream'), state='reserved',
                        part_size=max(self.settings.storage.part_size,
                            math.ceil(attachment["size"] / 10000 / 1048576) * 1048576),
                        expires_at=record.expires_at))
                space.record_count += 1
                space.metadata_bytes += size
                space.allocated += amount
                session.flush()
                self.emit(session, space, 'record.created', principal, record.id)
                return self.record_dict(session, record)
            return self.once(session, space, principal, 'record.create', key, body, create)

    def get_record(self, principal, space_id, record_id):
        with self.transaction(space_id, principal, False) as (session, _, member):
            return self.record_dict(session, self.record(session, space_id, record_id, member, principal))

    def list_records(self, principal, space_id, kind=None, after=None, limit=100, state='published'):
        if not 1 <= limit <= 1000:
            raise Error(422, 'invalid_limit')
        with self.transaction(space_id, principal, False) as (session, _, member):
            query = select(Record).where(Record.space_id == space_id, self.visible_clause(member, principal))
            if kind:
                query = query.where(Record.kind == kind)
            if state:
                query = query.where(Record.state == state)
            if after:
                query = query.where(Record.id > after)
            records = session.scalars(query.order_by(Record.id).limit(limit + 1)).all()
            more, records = len(records) > limit, records[:limit]
            grouped = {record.id: [] for record in records}
            if records:
                for blob in session.scalars(select(Blob).where(Blob.record_id.in_(grouped)).order_by(Blob.path)):
                    grouped[blob.record_id].append(blob)
            return {'items': [self.record_dict(session, r, grouped[r.id]) for r in records],
                    'next_cursor': records[-1].id if more else None}

    def patch_record(self, principal, space_id, record_id, body, expected_version):
        with self.transaction(space_id, principal) as (session, space, member):
            record = self.record(session, space_id, record_id, member, principal, True)
            self.check_draft(session, record)
            if str(record.generation) != str(expected_version):
                raise Error(412, 'record_version_mismatch')
            revision = session.get(SchemaRevision, record.schema_revision_id)
            metadata = body.get('metadata')
            size = validate_metadata(metadata, revision.schema)
            get_profile(space.profile).validate_record(record.kind, metadata, record.creator_bindings)
            if space.metadata_bytes - record.metadata_bytes + size > space.quota_metadata_bytes:
                raise Error(409, 'metadata_quota_exceeded')
            base_id = get_profile(space.profile).record_base_id(record.kind, metadata)
            if base_id:
                self.record(session, space_id, base_id, member, principal)
            space.metadata_bytes += size - record.metadata_bytes
            record.metadata_json, record.metadata_bytes = metadata, size
            record.base_record_id = base_id
            record.generation += 1
            self.emit(session, space, 'record.updated', principal, record.id)
            return self.record_dict(session, record)

    @staticmethod
    def check_draft(session, record):
        if record.state != 'draft':
            raise Error(409, 'record_not_draft')
        if record.expires_at <= database_time(session):
            raise Error(409, 'draft_expired')

    def publish_record(self, principal, space_id, record_id, key):
        with self.transaction(space_id, principal) as (session, space, member):
            record = self.record(session, space_id, record_id, member, principal, True)
            policy = session.get(KindPolicy, (space_id, record.kind))
            self.require(member, *policy.publish_roles)
            def publish():
                self.check_draft(session, record)
                revision = session.get(SchemaRevision, record.schema_revision_id)
                validate_metadata(record.metadata_json, revision.schema)
                get_profile(space.profile).validate_publish(record.kind, record.metadata_json,
                                                             record.creator_bindings, member.bindings)
                if record.base_record_id:
                    base = self.record(session, space_id, record.base_record_id, member, principal)
                    if base.state != 'published':
                        raise Error(409, 'base_not_published')
                blobs = session.scalars(select(Blob).where(Blob.record_id == record.id)).all()
                if any(blob.state != 'verified' or not blob.object_version or
                       blob.verified_size != blob.size or blob.verified_sha256 != blob.sha256 for blob in blobs):
                    raise Error(409, 'attachments_not_verified')
                record.state, record.published_at = 'published', database_time(session)
                record.shared = policy.visibility == 'shared'
                record.generation += 1
                self.emit(session, space, 'record.published', principal, record.id)
                return self.record_dict(session, record, blobs)
            return self.once(session, space, principal, 'record.publish:' + record_id, key, {}, publish)

    def release(self, session, space, record, state):
        """Stop a record and retain physical byte charges until successful cleanup."""
        if record.state in TERMINAL:
            return
        record.state = state
        record.generation += 1
        space.allocated -= record.declared_bytes
        now = database_time(session)
        for blob in session.scalars(select(Blob).where(Blob.record_id == record.id)):
            if blob.state != 'cleaned' and not blob.pending_deletion:
                attempts = session.scalars(select(TransferAttempt).where(TransferAttempt.blob_id == blob.id)).all()
                if not attempts:
                    blob.state = 'cleaned'
                    continue
                blob.pending_deletion = True
                space.reclaiming += blob.size
                blob.expires_at = max(now, blob.grant_expires_at or 0)
                for attempt in attempts:
                    if attempt.state != 'cleaned':
                        attempt.state = attempt.operation = 'cleanup'
                        attempt.next_attempt = max(now, attempt.grant_expires_at or 0, blob.grant_expires_at or 0)
                        # Keep active ownership: cleanup waits for any in-flight I/O.

        self.emit(session, space, 'record.' + state, 'system', record.id,
                  {'state': state, 'kind': record.kind, 'published': record.published_at is not None})

    def withdraw_record(self, principal, space_id, record_id):
        with self.transaction(space_id, principal) as (session, space, member):
            if 'admin' in member.roles:
                record = session.scalar(select(Record).where(Record.space_id == space_id, Record.id == record_id))
                if record is None:
                    raise Error(404, 'record_not_found')
            else:
                record = self.record(session, space_id, record_id, member, principal, True)
            if session.scalar(select(Record.id).where(Record.space_id == space_id,
                    Record.base_record_id == record.id, Record.state == 'published')):
                raise Error(409, 'record_retained_for_provenance')
            if session.scalar(select(Reference.name).where(Reference.space_id == space_id, Reference.record_id == record.id)):
                raise Error(409, 'record_referenced')
            busy = session.scalar(select(Coordination.id).join(CoordinationInput, CoordinationInput.attempt_id == Coordination.id)
                    .where(Coordination.space_id == space_id, Coordination.state == 'active',
                           Coordination.lease_until > database_time(session), CoordinationInput.record_id == record.id))
            if busy:
                raise Error(409, 'record_in_active_acquisition')
            self.release(session, space, record, 'withdrawn' if record.state == 'published' else 'cancelled')
            return {'id': record.id, 'state': record.state}

    def purge_record(self, principal, space_id, record_id):
        """Explicitly reclaim retained metadata after all file reclamation finishes."""
        with self.transaction(space_id, principal) as (session, space, member):
            self.require(member, 'admin')
            record = session.scalar(select(Record).where(Record.space_id == space_id, Record.id == record_id))
            if record is None:
                raise Error(404, 'record_not_found')
            if record.state not in TERMINAL:
                raise Error(409, 'record_not_terminal')
            blobs = session.scalars(select(Blob).where(Blob.record_id == record.id)).all()
            if any(blob.state != 'cleaned' for blob in blobs):
                raise Error(409, 'cleanup_pending')
            attempts = session.scalars(select(TransferAttempt).where(
                TransferAttempt.blob_id.in_([blob.id for blob in blobs]))).all()
            if any(attempt.mutation_tokens for attempt in attempts):
                raise Error(409, 'cleanup_pending')
            # Historical coordination provenance and derived records remain durable.
            if session.scalar(select(CoordinationInput.attempt_id).where(CoordinationInput.record_id == record.id)) or session.scalar(
                    select(Record.id).where(Record.space_id == space_id, Record.base_record_id == record.id)) or session.scalar(
                    select(Coordination.id).where(Coordination.result_record_id == record.id)):
                raise Error(409, 'record_retained_for_provenance')
            session.execute(delete(TransferAttempt).where(TransferAttempt.blob_id.in_([b.id for b in blobs])))
            session.execute(delete(Blob).where(Blob.record_id == record.id))
            session.execute(delete(Event).where(Event.record_id == record.id,
                                                Event.type.not_in(TERMINAL_EVENTS)))
            session.delete(record)
            space.record_count -= 1
            space.metadata_bytes -= record.metadata_bytes
            self.emit(session, space, 'record.purged', principal, data={'record_id': record_id})
            return {'id': record_id, 'state': 'purged'}

    @staticmethod
    def ref_dict(reference):
        return {'name': reference.name, 'record_id': reference.record_id, 'token': str(reference.generation)}

    @staticmethod
    def validate_reference_name(name):
        try:
            validate_kind(name)
        except Error:
            raise Error(422, 'invalid_reference_name') from None

    def get_reference(self, principal, space_id, name):
        self.validate_reference_name(name)
        with self.transaction(space_id, principal, False) as (session, _, member):
            reference = session.get(Reference, (space_id, name))
            if reference is None:
                raise Error(404, 'reference_not_found')
            self.record(session, space_id, reference.record_id, member, principal)
            return self.ref_dict(reference)

    def profile_record(self, record):
        return {'id': record.id, 'kind': record.kind, 'creator': record.creator, 'metadata': record.metadata_json,
                'creator_bindings': record.creator_bindings, 'published_at': record.published_at,
                'state': record.state}

    def put_reference(self, principal, space_id, name, body, expected_token, key):
        self.validate_reference_name(name)
        with self.transaction(space_id, principal) as (session, space, member):
            self.require(member, 'publisher')
            def put():
                record = self.record(session, space_id, body.get('record_id'), member, principal)
                if record.state != 'published' or not record.shared:
                    raise Error(409, 'reference_requires_shared_record')
                reference = session.get(Reference, (space_id, name))
                if (reference is None and expected_token != '*') or (reference and str(reference.generation) != str(expected_token)):
                    raise Error(412, 'reference_version_mismatch')
                if self.active_acquisition(session, space_id, name):
                    raise Error(409, 'acquisition_active')
                get_profile(space.profile).validate_reference(name, self.profile_record(record),
                    inputs=(), base_record_id=reference.record_id if reference else None)
                if reference is None:
                    reference = Reference(space_id=space_id, name=name, record_id=record.id, generation=1, fence=0)
                    session.add(reference)
                else:
                    reference.record_id = record.id
                    reference.generation += 1
                self.emit(session, space, 'reference.updated', principal, record.id,
                          {'name': name, 'token': str(reference.generation)})
                return self.ref_dict(reference)
            return self.once(session, space, principal, 'reference.put:' + name, key,
                             {'body': body, 'expected_token': expected_token}, put)

    @staticmethod
    def active_acquisition(session, space_id, name):
        return session.scalar(select(Coordination).where(Coordination.space_id == space_id,
            Coordination.reference_name == name, Coordination.state == 'active',
            Coordination.lease_until > database_time(session)))

    @staticmethod
    def acquisition_dict(session, attempt):
        inputs = list(session.scalars(select(CoordinationInput.record_id).where(
            CoordinationInput.attempt_id == attempt.id).order_by(CoordinationInput.record_id)))
        return {'id': attempt.id, 'reference': attempt.reference_name,
                'expected_token': str(attempt.expected_generation), 'holder': attempt.holder,
                'fence': attempt.fence, 'state': attempt.state, 'lease_until': attempt.lease_until,
                'input_record_ids': inputs, 'result_record_id': attempt.result_record_id}

    def acquire(self, principal, space_id, body, key):
        with self.transaction(space_id, principal) as (session, space, member):
            self.require(member, 'publisher')
            def acquire():
                name = body.get('reference')
                self.validate_reference_name(name)
                reference = session.get(Reference, (space_id, name))
                if reference is None:
                    raise Error(404, 'reference_not_found')
                if str(reference.generation) != str(body.get('expected_token')):
                    raise Error(412, 'reference_version_mismatch')
                self.record(session, space_id, reference.record_id, member, principal)
                if self.active_acquisition(session, space_id, name):
                    raise Error(409, 'acquisition_busy')
                ids = body.get('input_record_ids', [])
                if not isinstance(ids, list) or len(ids) > 1000 or len(ids) != len(set(ids)):
                    raise Error(422, 'invalid_input_records')
                profile = get_profile(space.profile)
                selection = profile.selection_spec(name, reference.record_id)
                if selection:
                    candidates = session.scalars(select(Record).where(Record.space_id == space_id,
                        Record.kind == selection['kind'], Record.state == 'published',
                        Record.base_record_id == selection['base_id'])).all()
                    owners = {owner.principal_id: owner for owner in session.scalars(
                        select(Member).where(Member.space_id == space_id,
                            Member.principal_id.in_({record.creator for record in candidates})))}
                    eligible = []
                    for record in candidates:
                        owner = owners.get(record.creator)
                        descriptor = self.profile_record(record)
                        if profile.input_eligible(descriptor, self.member_dict(owner) if owner else None):
                            eligible.append(descriptor)
                    selected = profile.select_inputs(eligible, reference.record_id)
                    selected_ids = {r['id'] for r in selected}
                    if ids and not set(ids).issubset(selected_ids):
                        raise Error(409, 'profile_input_selection_mismatch')
                    ids = ids or sorted(selected_ids)
                    if len(ids) < selection['minimum']:
                        raise Error(409, selection.get('minimum_error', 'insufficient_inputs'))
                inputs = [self.record(session, space_id, rid, member, principal) for rid in ids]
                if any(record.state != 'published' for record in inputs):
                    raise Error(409, 'input_not_published')
                seconds = body.get('lease_seconds', self.settings.coordination_seconds)
                if type(seconds) is not int or not 10 <= seconds <= 3600:
                    raise Error(422, 'invalid_lease_seconds')
                session.execute(update(Coordination).where(Coordination.space_id == space_id,
                     Coordination.reference_name == name, Coordination.state == 'active').values(state='expired'))
                reference.fence += 1
                attempt = Coordination(id=identifier(), space_id=space_id, reference_name=name,
                    expected_generation=reference.generation, holder=principal_id(principal),
                    fence=reference.fence, state='active', lease_until=database_time(session) + seconds,
                    created_at=database_time(session))
                session.add(attempt)
                session.flush()
                for record in inputs:
                    session.add(CoordinationInput(space_id=space_id, attempt_id=attempt.id, record_id=record.id))
                session.flush()
                self.emit(session, space, 'acquisition.started', principal,
                          data={'id': attempt.id, 'reference': name})
                return self.acquisition_dict(session, attempt)
            result = self.once(session, space, principal, 'acquisition.create', key, body, acquire)
            attempt = self._attempt(session, space_id, result['id'])
            if attempt.state == 'active' and attempt.lease_until <= database_time(session):
                raise Error(409, 'acquisition_expired')
            if attempt.state not in {'active', 'completed'}:
                raise Error(409, 'acquisition_not_active')
            return self.acquisition_dict(session, attempt)

    @staticmethod
    def _attempt(session, space_id, attempt_id):
        attempt = session.scalar(select(Coordination).where(Coordination.space_id == space_id, Coordination.id == attempt_id))
        if attempt is None:
            raise Error(404, 'acquisition_not_found')
        return attempt

    def get_acquisition(self, principal, space_id, attempt_id):
        with self.transaction(space_id, principal, False) as (session, _, member):
            self.require(member, 'publisher')
            return self.acquisition_dict(session, self._attempt(session, space_id, attempt_id))

    def check_attempt(self, session, attempt, principal, fence):
        if attempt.holder != principal_id(principal):
            raise Error(403, 'acquisition_holder_required')
        reference = session.get(Reference, (attempt.space_id, attempt.reference_name))
        if attempt.state != 'active' or attempt.lease_until <= database_time(session) or \
                fence != attempt.fence or reference.fence != fence:
            raise Error(409, 'acquisition_not_active')
        return reference

    def renew(self, principal, space_id, attempt_id, fence):
        with self.transaction(space_id, principal) as (session, space, member):
            self.require(member, 'publisher')
            attempt = self._attempt(session, space_id, attempt_id)
            self.check_attempt(session, attempt, principal, fence)
            attempt.lease_until = database_time(session) + self.settings.coordination_seconds
            return self.acquisition_dict(session, attempt)

    def abandon(self, principal, space_id, attempt_id, fence):
        with self.transaction(space_id, principal) as (session, space, member):
            self.require(member, 'publisher')
            attempt = self._attempt(session, space_id, attempt_id)
            self.check_attempt(session, attempt, principal, fence)
            attempt.state = 'abandoned'
            self.emit(session, space, 'acquisition.abandoned', principal, data={'id': attempt.id})
            return self.acquisition_dict(session, attempt)

    def complete(self, principal, space_id, attempt_id, body, key):
        with self.transaction(space_id, principal) as (session, space, member):
            self.require(member, 'publisher')
            attempt = self._attempt(session, space_id, attempt_id)
            if attempt.holder != principal_id(principal):
                raise Error(403, 'acquisition_holder_required')
            if attempt.state == 'completed':
                if attempt.fence != body.get('fence') or attempt.result_record_id != body.get('result_record_id'):
                    raise Error(409, 'completion_conflict')
                return self.acquisition_dict(session, attempt)
            def complete():
                reference = self.check_attempt(session, attempt, principal, body.get('fence'))
                if reference.generation != attempt.expected_generation:
                    raise Error(412, 'reference_version_mismatch')
                result = self.record(session, space_id, body.get('result_record_id'), member, principal)
                if result.state != 'published' or not result.shared:
                    raise Error(409, 'reference_requires_shared_record')
                input_ids = session.scalars(select(CoordinationInput.record_id).where(
                    CoordinationInput.attempt_id == attempt.id)).all()
                inputs = [self.record(session, space_id, rid, member, principal) for rid in input_ids]
                profile = get_profile(space.profile)
                used = profile.completion_inputs(self.profile_record(result),
                    [self.profile_record(record) for record in inputs], attempt.reference_name)
                if any(record['state'] != 'published' for record in used):
                    raise Error(409, 'input_not_published')
                owners = {owner.principal_id: owner for owner in session.scalars(
                    select(Member).where(Member.space_id == space_id,
                        Member.principal_id.in_({record['creator'] for record in used})))}
                for record in used:
                    owner = owners.get(record['creator'])
                    profile.validate_input_current(record, self.member_dict(owner) if owner else None)
                profile.validate_reference(attempt.reference_name, self.profile_record(result),
                    inputs=used, base_record_id=reference.record_id)
                reference.record_id = result.id
                reference.generation += 1
                attempt.state, attempt.result_record_id = 'completed', result.id
                self.emit(session, space, 'reference.updated', principal, result.id,
                          {'name': reference.name, 'token': str(reference.generation)})
                self.emit(session, space, 'acquisition.completed', principal, result.id, {'id': attempt.id})
                return self.acquisition_dict(session, attempt)
            return self.once(session, space, principal, 'acquisition.complete:' + attempt_id, key, body, complete)

    def events(self, principal, space_id, after=0, limit=100):
        if not 1 <= limit <= 1000 or after < 0:
            raise Error(422, 'invalid_cursor')
        with self.transaction(space_id, principal, False) as (session, space, member):
            if after < space.event_floor:
                raise Error(410, 'event_cursor_expired', 'Reconcile current resources and resume at the supplied floor: ' + str(space.event_floor))
            # Content entries reuse record authorization. Minimal terminal events
            # survive metadata purge and use the current kind policy and membership;
            # unpublished drafts never become visible through these tombstones.
            content_visible = and_(Event.record_id.is_not(None), self.visible_clause(member, principal))
            tombstone_access = (Event.record_id.is_not(None) if 'publisher' in member.roles else
                KindPolicy.visibility == 'shared' if set(member.roles) & {'reader', 'contributor'} else
                Event.type == '__none__')
            tombstone_visible = and_(Event.type.in_(TERMINAL_EVENTS),
                                     Event.payload['published'].as_boolean().is_(True), tombstone_access)
            admin_visible = Event.record_id.is_(None) if 'admin' in member.roles else Event.type == '__none__'
            rows = session.scalars(select(Event).outerjoin(Record, Record.id == Event.record_id)
                .outerjoin(KindPolicy, and_(KindPolicy.space_id == Event.space_id,
                                           KindPolicy.kind == Event.payload['kind'].as_string()))
                .where(Event.space_id == space_id, Event.id > after,
                       or_(content_visible, tombstone_visible, admin_visible))
                .order_by(Event.id).limit(limit + 1)).all()
            more, rows = len(rows) > limit, rows[:limit]
            # Advancing over filtered events is safe: policy changes emit new events;
            # clients reconcile after such changes rather than replaying hidden history.
            cursor = rows[-1].id if more else (session.scalar(select(func.max(Event.id)).where(Event.space_id == space_id)) or after)
            return {'items': [{'id': row.id, 'type': row.type, 'record_id': row.record_id,
                               'payload': {'state': row.type.split('.', 1)[1]} if row.type in TERMINAL_EVENTS else row.payload,
                               'created_at': row.created_at} for row in rows],
                    'next_cursor': cursor}
