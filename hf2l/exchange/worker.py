"""Recover transfers under renewable attempt leases, verify SHA-256, and reclaim storage."""
from concurrent.futures import ThreadPoolExecutor
import logging
from types import SimpleNamespace
import uuid

from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import and_, delete, exists, or_, select, update

from .leases import heartbeat, owns, release
from .models import Blob, Event, Operation, Record, Space, database_time
from .storage import StorageMisconfigured

log = logging.getLogger("hf2l.exchange.worker")
RELEASED_STATES = ("expired", "cancelled", "withdrawn", "failed")
IN_FLIGHT = ("completing", "verifying")
PERMANENT_ERRORS = {"NoSuchUpload", "NoSuchVersion", "NoSuchKey", "404", "NotFound"}
WORKER = SimpleNamespace(id="worker")


def expire_drafts(service, batch):
    count = 0
    with service.sessions.begin() as session:
        in_flight = exists().where(Blob.record_id == Record.id, Blob.state.in_(IN_FLIGHT))
        expired = list(session.scalars(select(Record.id).where(
            Record.state == "draft", Record.expires_at < database_time(session), ~in_flight
        ).order_by(Record.expires_at, Record.id).limit(batch)))
    for record_id in expired:
        with service.sessions.begin() as session:
            record = session.get(Record, record_id)
            space = session.scalar(select(Space).where(Space.id == record.space_id).with_for_update())
            session.refresh(record)
            if record.state == "draft" and record.expires_at < database_time(session) and not any(
                    b.state in IN_FLIGHT for b in service.blobs(session, record.id)):
                service.release(session, space, record, WORKER, "expired", "record.expired")
                count += 1
    return count


def select_work(service, batch):
    with service.sessions.begin() as session:
        now = database_time(session)
        free = or_(Blob.worker_lease_until.is_(None), Blob.worker_lease_until <= now)
        pending = select(Blob.id).join(Record, Record.id == Blob.record_id).where(
            free, Record.state == "draft",
            or_(Blob.state == "verifying", and_(Blob.state.in_(["initiating", "completing"]),
                Blob.updated_at <= now - service.settings.worker_recover_after))
        ).order_by(Blob.updated_at, Blob.id).limit(batch)
        cleanup = select(Blob.id).join(Record, Record.id == Blob.record_id).where(
            free, Blob.state != "cleaned", Record.state.in_(RELEASED_STATES),
            Blob.expires_at <= now - service.settings.grant_seconds
        ).order_by(Blob.expires_at, Blob.id).limit(batch)
        return list(session.scalars(pending)), list(session.scalars(cleanup))


def acquire(service, blob_id):
    with service.sessions.begin() as session:
        now = database_time(session)
        result = session.execute(update(Blob).where(
            Blob.id == blob_id, or_(Blob.worker_lease_until.is_(None), Blob.worker_lease_until <= now)
        ).values(worker_token=uuid.uuid4().hex, worker_lease_until=now + service.settings.worker_lease_seconds))
        if result.rowcount != 1:
            return None
        blob = session.get(Blob, blob_id)
        record_state = session.get(Record, blob.record_id).state
        session.expunge(blob)
        return blob, record_state


def commit(service, blob, record_state, new_state, value):
    with service.sessions.begin() as session:
        space = session.scalar(select(Space).where(Space.id == blob.space_id).with_for_update())
        current = session.scalar(select(Blob).where(Blob.id == blob.id).with_for_update())
        parent = session.get(Record, current.record_id)
        if not owns(session, current, blob) or current.state != blob.state or parent.state != record_state:
            return False
        current.state, current.updated_at = new_state, database_time(session)
        current.worker_lease_until, current.worker_token = None, None
        if new_state == "uploading" and value:
            current.upload_id = value
        elif new_state == "verifying":
            current.version, current.upload_id = value, None
        elif new_state == "verified":
            current.verified_sha256 = value
        elif new_state == "cleaned":
            space.reclaiming -= current.size
            current.upload_id = None
        elif new_state == "failed":
            service.release(session, space, parent, WORKER, "failed", "record.failed")
        if new_state in ("verifying", "verified"):
            parent.expires_at = max(parent.expires_at, current.updated_at + service.settings.upload_seconds)
        service.emit(session, blob.space_id, WORKER, "blob." + new_state, blob.record_id, blob_id=blob.id)
        return True


def release_lease(service, blob):
    release(service, blob)


def advance(service, blob, record_state, cleanup):
    if cleanup:
        if record_state not in RELEASED_STATES:
            return None
        service.storage.cleanup(blob)
        return "cleaned", "cleaned", None
    if record_state != "draft":
        return None
    with service.sessions.begin() as session:
        if database_time(session) - blob.updated_at > service.settings.worker_failure_seconds:
            return "failed", "failed", None
    if blob.state == "initiating":
        return "recovered", "uploading", service.storage.recover_start(blob.key)
    if blob.state == "completing":
        try:
            return "recovered", "verifying", service.storage.complete(blob)
        except ValueError:
            return "recovered", "uploading", None
    if blob.state == "verifying":
        try:
            return "verified", "verified", service.storage.verify(blob)
        except ValueError:
            return "failed", "failed", None
    return None


def process(service, blob_id, cleanup):
    leased = acquire(service, blob_id)
    if not leased:
        return "skipped"
    blob, record_state = leased
    try:
        with heartbeat(service, blob):
            try:
                step = advance(service, blob, record_state, cleanup)
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code not in PERMANENT_ERRORS or cleanup:
                    raise
                log.error("permanent storage failure blob=%s code=%s", blob.id, code)
                step = ("failed", "failed", None)
            if not step:
                return "skipped"
            outcome, new_state, value = step
            committed = commit(service, blob, record_state, new_state, value)
            if not committed and blob.state == "initiating" and new_state == "uploading" and value:
                # Recovery always creates its own MPU; no other attempt adopts it.
                blob.upload_id = value
                service.storage.abort(blob)
            return outcome if committed else "skipped"
    except (BotoCoreError, ClientError, OSError, StorageMisconfigured) as exc:
        code = exc.response.get("Error", {}).get("Code", "") if isinstance(exc, ClientError) else ""
        log.warning("storage failure blob=%s record=%s state=%s error=%s %s", blob.id, blob.record_id, blob.state,
                    type(exc).__name__, code)
        return "retry"
    finally:
        release_lease(service, blob)


def prune(service, batch):
    """Bound retention work; event floors make expired client cursors explicit."""
    with service.sessions.begin() as session:
        now = database_time(session)
        ids = list(session.scalars(select(Operation.id).where(
            Operation.created_at < now - service.settings.operation_retention_seconds
        ).order_by(Operation.created_at).limit(batch)))
        session.execute(delete(Operation).where(Operation.id.in_(ids)))
        rows = list(session.execute(select(Event.id, Event.space_id).where(
            Event.created_at < now - service.settings.event_retention_seconds).order_by(Event.id).limit(batch)))
    for space_id in sorted({row.space_id for row in rows}):
        with service.sessions.begin() as session:
            space = session.scalar(select(Space).where(Space.id == space_id).with_for_update())
            ids = [row.id for row in rows if row.space_id == space_id]
            session.execute(delete(Event).where(Event.id.in_(ids)))
            space.event_floor = max(space.event_floor, max(ids))


def tick(service, batch=None, concurrency=None):
    settings = service.settings
    batch = batch or settings.worker_batch
    counts = {"verified": 0, "failed": 0, "recovered": 0, "cleaned": 0, "retry": 0, "skipped": 0, "expired": 0}
    counts["expired"] = expire_drafts(service, batch)
    pending, cleanup = select_work(service, batch)
    work = [(blob_id, False) for blob_id in pending] + [(blob_id, True) for blob_id in cleanup]
    def guarded(item):
        try:
            return process(service, *item)
        except Exception:
            log.exception("worker item failed blob=%s", item[0])
            return "retry"
    with ThreadPoolExecutor(max_workers=concurrency or settings.worker_concurrency) as pool:
        for outcome in pool.map(guarded, work):
            counts[outcome] += 1
    prune(service, batch)
    return counts
