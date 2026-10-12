"""Durable manager records, deliberately independent of ML and Exchange."""
from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint, event, inspect, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, synonym
from sqlalchemy.types import TypeDecorator

from .domain import ArtifactLocator, new_id, utcnow

JSON_VALUE = JSON().with_variant(JSONB(), "postgresql")


class UTCDateTime(TypeDecorator):
    """Require aware writes and restore UTC on SQLite reads."""
    impl = DateTime
    cache_ok = True

    def load_dialect_impl(self, dialect):
        return dialect.type_descriptor(DateTime(timezone=True))

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timestamps must be timezone-aware datetimes")
        return value.astimezone(timezone.utc)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class Base(DeclarativeBase):
    pass


class SchemaRevision(Base):
    __tablename__ = "jm_schema_revisions"
    revision: Mapped[str] = mapped_column(String(64), primary_key=True)
    applied_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class Project(Base):
    __tablename__ = "jm_projects"
    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200))
    retention_days: Mapped[int] = mapped_column(Integer, default=90)
    quota_cpu_millicores: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    quota_memory_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    quota_disk_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    quota_gpus: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_active_jobs: Mapped[int | None] = mapped_column(Integer, nullable=True)
    quotas_json: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)
    retained_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    __table_args__ = (CheckConstraint("retention_days >= 0"), CheckConstraint("retained_bytes >= 0"))


class ProjectMember(Base):
    __tablename__ = "jm_project_members"
    project_id: Mapped[str] = mapped_column(ForeignKey("jm_projects.id"), primary_key=True)
    principal_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    role: Mapped[str] = mapped_column(String(24), default="submitter")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    __table_args__ = (CheckConstraint("role IN ('submitter', 'admin')"),)


class Job(Base):
    __tablename__ = "jm_jobs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("jm_projects.id"))
    creator_id: Mapped[str] = mapped_column(String(256))
    name: Mapped[str] = mapped_column(String(200))
    spec_json: Mapped[dict] = mapped_column(JSON_VALUE)
    spec_hash: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(32), default="QUEUED")
    phase: Mapped[str | None] = mapped_column(String(64), nullable=True)
    queue_reason: Mapped[dict | None] = mapped_column(JSON_VALUE, nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    current_attempt: Mapped[int] = mapped_column(Integer, default=0)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    epoch: Mapped[int] = mapped_column(Integer, default=0)
    backfill_count: Mapped[int] = mapped_column(Integer, default=0)
    current_round: Mapped[int] = mapped_column(Integer, default=0)
    target_round: Mapped[int] = mapped_column(Integer)
    cleanup_status: Mapped[str] = mapped_column(String(32), default="none")
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    outcome_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    deadline_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    next_attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    terminated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    artifacts_expire_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    purged_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    __table_args__ = (
        CheckConstraint("state IN ('QUEUED', 'PROVISIONING', 'STARTING', 'RUNNING', 'RECONCILING', 'NEEDS_ATTENTION', 'CANCELLING', 'SUCCEEDED', 'FAILED', 'CANCELLED')"),
        CheckConstraint("version >= 1 AND epoch >= 0 AND target_round >= 1 AND current_round >= 0 AND backfill_count >= 0"),
        Index("ix_jm_jobs_queue", "state", "created_at", "id"),
        Index("ix_jm_jobs_project", "project_id", "created_at", "id"),
    )


@event.listens_for(Job, "before_update")
def immutable_spec(mapper, connection, target):
    state = inspect(target)
    for name in ("spec_json", "spec_hash", "project_id", "creator_id", "target_round"):
        if state.attrs[name].history.has_changes():
            raise ValueError("Job specification and provenance are immutable; create a new job")


class JobMember(Base):
    __tablename__ = "jm_job_members"
    job_id: Mapped[str] = mapped_column(ForeignKey("jm_jobs.id"), primary_key=True)
    principal_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    role: Mapped[str] = mapped_column(String(24))
    granted_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    __table_args__ = (CheckConstraint("role IN ('reader', 'operator', 'admin')"), Index("ix_jm_members_principal", "principal_id", "job_id"))


class Attempt(Base):
    __tablename__ = "jm_attempts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    job_id: Mapped[str] = mapped_column(ForeignKey("jm_jobs.id"))
    number: Mapped[int] = mapped_column(Integer)
    epoch: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(32), default="RESERVED")
    node_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    revocation_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    termination_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    publication_status: Mapped[str] = mapped_column(String(32), default="none")
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    details_json: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)
    resources_json: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    __table_args__ = (UniqueConstraint("job_id", "number"), UniqueConstraint("job_id", "epoch"), CheckConstraint("number >= 1 AND epoch >= 1"))


class Pool(Base):
    __tablename__ = "jm_pools"
    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200))
    node_id: Mapped[str] = mapped_column(String(128))
    cpu_millicores: Mapped[int] = mapped_column(BigInteger, default=0)
    memory_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    disk_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    gpu_uuids: Mapped[list] = mapped_column(JSON_VALUE, default=list)
    gpu_profiles: Mapped[list] = mapped_column(JSON_VALUE, default=list)
    sandbox_profiles: Mapped[list] = mapped_column(JSON_VALUE, default=list)
    healthy: Mapped[bool] = mapped_column(Boolean, default=False)
    quarantined: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    details_json: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    __table_args__ = (CheckConstraint("cpu_millicores >= 0 AND memory_bytes >= 0 AND disk_bytes >= 0 AND version >= 1"),)


class Allocation(Base):
    __tablename__ = "jm_allocations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    job_id: Mapped[str] = mapped_column(ForeignKey("jm_jobs.id"))
    attempt_id: Mapped[str] = mapped_column(ForeignKey("jm_attempts.id"))
    component_id: Mapped[str] = mapped_column(String(128))
    pool_id: Mapped[str] = mapped_column(ForeignKey("jm_pools.id"))
    cpu_millicores: Mapped[int] = mapped_column(BigInteger)
    memory_bytes: Mapped[int] = mapped_column(BigInteger)
    disk_bytes: Mapped[int] = mapped_column(BigInteger)
    gpu_count: Mapped[int] = mapped_column(Integer, default=0)
    epoch: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(32), default="RESERVED")
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    termination_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    details_json: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    released_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    __table_args__ = (
        CheckConstraint("cpu_millicores >= 0 AND memory_bytes >= 0 AND disk_bytes >= 0 AND gpu_count >= 0 AND epoch >= 1"),
        Index("ix_jm_alloc_pool", "pool_id", "state"),
        Index("uq_jm_live_component", "job_id", "component_id", unique=True, postgresql_where=text("released_at IS NULL"), sqlite_where=text("released_at IS NULL")),
    )


class GpuAllocation(Base):
    __tablename__ = "jm_gpu_allocations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    allocation_id: Mapped[str] = mapped_column(ForeignKey("jm_allocations.id"))
    pool_id: Mapped[str] = mapped_column(ForeignKey("jm_pools.id"))
    gpu_uuid: Mapped[str] = mapped_column(String(128))
    released_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    __table_args__ = (Index("uq_jm_live_gpu", "gpu_uuid", unique=True, postgresql_where=text("released_at IS NULL"), sqlite_where=text("released_at IS NULL")),)


class ProvisioningResource(Base):
    __tablename__ = "jm_provisioning_resources"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    job_id: Mapped[str] = mapped_column(ForeignKey("jm_jobs.id"))
    attempt_id: Mapped[str | None] = mapped_column(ForeignKey("jm_attempts.id"), nullable=True)
    component_id: Mapped[str] = mapped_column(String(128), default="owner")
    kind: Mapped[str] = mapped_column(String(64))
    external_id: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    ownership_json: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)
    details_json: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)
    state: Mapped[str] = mapped_column(String(32), default="planned")
    retained: Mapped[bool] = mapped_column(Boolean, default=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    deleted_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    __table_args__ = (UniqueConstraint("kind", "external_id"), Index("ix_jm_resource_job", "job_id", "state"))


class ProvisioningOperation(Base):
    __tablename__ = "jm_provisioning_operations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    job_id: Mapped[str] = mapped_column(ForeignKey("jm_jobs.id"))
    attempt_id: Mapped[str | None] = mapped_column(ForeignKey("jm_attempts.id"), nullable=True)
    component_id: Mapped[str] = mapped_column(String(128), default="owner")
    operation: Mapped[str] = mapped_column(String(64))
    idempotency_key: Mapped[str] = mapped_column(String(256), unique=True)
    state: Mapped[str] = mapped_column(String(32), default="planned")
    desired_json: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)
    observed_json: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)
    last_error: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class Outbox(Base):
    __tablename__ = "jm_outbox"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    job_id: Mapped[str | None] = mapped_column(ForeignKey("jm_jobs.id"), nullable=True)
    attempt_id: Mapped[str | None] = mapped_column(ForeignKey("jm_attempts.id"), nullable=True)
    attempt_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    topic: Mapped[str] = mapped_column(String(64))
    kind = synonym("topic")
    payload_json: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)
    idempotency_key: Mapped[str] = mapped_column(String(256), unique=True)
    state: Mapped[str] = mapped_column(String(32), default="pending")
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    __table_args__ = (Index("ix_jm_outbox_dispatch", "state", "next_attempt_at", "lease_until", "id"),)


class LifecycleEvent(Base):
    __tablename__ = "jm_events"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    job_id: Mapped[str] = mapped_column(ForeignKey("jm_jobs.id"))
    sequence: Mapped[int] = mapped_column(BigInteger)
    kind: Mapped[str] = mapped_column(String(64))
    actor_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    epoch: Mapped[int | None] = mapped_column(Integer, nullable=True)
    data_json: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)
    details_json = synonym("data_json")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    __table_args__ = (UniqueConstraint("job_id", "sequence"), Index("ix_jm_events_job", "job_id", "sequence"))


class AdministrativeAudit(Base):
    """Append-only policy history, retained independently of mutable resources."""
    __tablename__ = "jm_admin_audit"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    actor_id: Mapped[str] = mapped_column(String(256))
    operation: Mapped[str] = mapped_column(String(64))
    resource_type: Mapped[str] = mapped_column(String(64))
    resource_id: Mapped[str] = mapped_column(String(256))
    before_json: Mapped[dict | None] = mapped_column(JSON_VALUE, nullable=True)
    after_json: Mapped[dict | None] = mapped_column(JSON_VALUE, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    __table_args__ = (
        CheckConstraint("length(actor_id) BETWEEN 1 AND 256 AND length(operation) BETWEEN 1 AND 64 AND "
                        "length(resource_type) BETWEEN 1 AND 64 AND length(resource_id) BETWEEN 1 AND 256"),
        Index("ix_jm_admin_audit_resource", "resource_type", "resource_id", "created_at", "id"),
        Index("ix_jm_admin_audit_actor", "actor_id", "created_at", "id"),
    )


@event.listens_for(AdministrativeAudit, "before_insert")
def validate_administrative_audit(mapper, connection, target):
    from .admin_audit import validate_audit_identity, sanitize_policy_metadata
    validate_audit_identity(target.actor_id, target.operation, target.resource_type, target.resource_id)
    target.before_json = sanitize_policy_metadata(target.before_json)
    target.after_json = sanitize_policy_metadata(target.after_json)


@event.listens_for(AdministrativeAudit, "before_update")
@event.listens_for(AdministrativeAudit, "before_delete")
def immutable_administrative_audit(mapper, connection, target):
    raise ValueError("Administrative audit history is append-only")


class IdempotencyRecord(Base):
    __tablename__ = "jm_idempotency"
    scope: Mapped[str] = mapped_column(String(128), primary_key=True)
    principal_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    key: Mapped[str] = mapped_column(String(256), primary_key=True)
    request_hash: Mapped[str] = mapped_column(String(64))
    response_json: Mapped[dict] = mapped_column(JSON_VALUE)
    status_code: Mapped[int] = mapped_column(Integer, default=200)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class Artifact(Base):
    __tablename__ = "jm_artifacts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    job_id: Mapped[str] = mapped_column(ForeignKey("jm_jobs.id"))
    attempt_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    kind: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(256))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    storage_key: Mapped[str] = mapped_column(String(1024))
    locator_json: Mapped[dict | None] = mapped_column(JSON_VALUE, nullable=True)
    state: Mapped[str] = mapped_column(String(32), default="available")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    __table_args__ = (CheckConstraint("size_bytes >= 0"), Index("ix_jm_artifacts_job", "job_id", "created_at", "id"))


class LogChunk(Base):
    __tablename__ = "jm_log_chunks"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    job_id: Mapped[str] = mapped_column(ForeignKey("jm_jobs.id"))
    attempt_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    component: Mapped[str] = mapped_column(String(128))
    sequence: Mapped[int] = mapped_column(BigInteger)
    data: Mapped[str] = mapped_column(Text)
    charged_bytes: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    __table_args__ = (CheckConstraint("length(data) <= 65536 AND charged_bytes >= 0"), UniqueConstraint("job_id", "component", "sequence"))


class AuthSession(Base):
    __tablename__ = "jm_auth_sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    principal_id: Mapped[str] = mapped_column(String(256))
    issuer: Mapped[str] = mapped_column(String(1024))
    subject: Mapped[str] = mapped_column(String(256))
    provider_sid: Mapped[str | None] = mapped_column(String(256), nullable=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    access_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    checked_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())
    absolute_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    __table_args__ = (Index("ix_jm_sessions_principal", "principal_id", "revoked_at"), Index("ix_jm_sessions_expiry", "expires_at"),)


class ApprovedSource(Base):
    __tablename__ = "jm_approved_sources"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    project_id: Mapped[str | None] = mapped_column(ForeignKey("jm_projects.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    allowed_hosts: Mapped[list] = mapped_column(JSON_VALUE, default=list)
    policy_json: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="approved")
    url: Mapped[str] = mapped_column(String(2048))
    details_json: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)
    allowed_commits: Mapped[list] = mapped_column(JSON_VALUE, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class RuntimeImage(Base):
    __tablename__ = "jm_runtime_images"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    project_id: Mapped[str | None] = mapped_column(ForeignKey("jm_projects.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    approved: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(32), default="approved")
    digest: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    details_json: Mapped[dict] = mapped_column(JSON_VALUE, default=dict)


class ParticipantBinding(Base):
    __tablename__ = "jm_participant_bindings"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("jm_projects.id"))
    participant_id: Mapped[str] = mapped_column(String(128))
    node_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    dataset_label: Mapped[str] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


JobRecord = Job
Membership = JobMember
Event = LifecycleEvent
Idempotency = IdempotencyRecord
ResourcePool = Pool
Reservation = Allocation


class SecretReference(Base):
    __tablename__ = "jm_secret_references"
    reference: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("jm_projects.id"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

Source = ApprovedSource
DatasetBinding = ParticipantBinding


@event.listens_for(Artifact, "before_insert")
@event.listens_for(Artifact, "before_update")
def validate_trusted_artifact_locator(mapper, connection, target):
    if target.locator_json is not None:
        target.locator_json = ArtifactLocator.model_validate(target.locator_json).to_dict()
