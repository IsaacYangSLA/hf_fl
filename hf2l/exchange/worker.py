"""Recover uploads, verify full-file SHA-256, and reclaim expired drafts."""
from concurrent.futures import ThreadPoolExecutor
import logging
import time

from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import and_, exists, or_, select, update

from .models import Blob, Event, Record, Space

log = logging.getLogger("hf2l.exchange.worker")
RELEASED_STATES = ("expired", "cancelled", "withdrawn")
IN_FLIGHT = ("completing", "verifying")


def expire_drafts(service, batch):
    """Expire drafts past their window unless a transfer is still being completed or verified."""
    count = 0
    with service.sessions.begin() as session:
        in_flight = exists().where(Blob.record_id == Record.id, Blob.state.in_(IN_FLIGHT))
        expired = list(session.scalars(select(Record.id).where(
            Record.state == "draft", Record.expires_at < time.time(), ~in_flight).order_by(Record.expires_at).limit(batch)))
    for record_id in expired:
        with service.sessions.begin() as session:
            record = session.get(Record, record_id)
            space = session.scalar(select(Space).where(Space.id == record.space_id).with_for_update())
            session.refresh(record)
            blobs = service.blobs(session, record.id)
            if record.state == "draft" and record.expires_at < time.time() and not any(b.state in IN_FLIGHT for b in blobs):
                record.state = "expired"
                space.allocated -= sum(b.size for b in blobs)
                session.add(Event(space_id=space.id, principal="worker", kind="record.expired", record_id=record.id))
                count += 1
    return count


def select_work(service, batch):
    """Bounded, deterministic per-class selection so one class cannot starve another."""
    now = time.time()
    stale = now - service.settings.worker_recover_after
    with service.sessions.begin() as session:
        pending = select(Blob.id).join(Record, Record.id == Blob.record_id).where(
            Record.state == "draft",
            or_(Blob.state == "verifying",
                and_(Blob.state.in_(["initiating", "completing"]), Blob.updated_at <= stale))
        ).order_by(Blob.updated_at, Blob.id).limit(batch)
        cleanup = select(Blob.id).join(Record, Record.id == Blob.record_id).where(
            Blob.state != "cleaned", Record.state.in_(RELEASED_STATES),
            Blob.expires_at + service.settings.grant_seconds <= now).order_by(Blob.expires_at, Blob.id).limit(batch)
        return list(session.scalars(pending)), list(session.scalars(cleanup))


def acquire(service, blob_id):
    """Lease one blob to this worker; a competing worker skips it instead of duplicating the read."""
    now = time.time()
    with service.sessions.begin() as session:
        result = session.execute(update(Blob).where(
            Blob.id == blob_id, or_(Blob.worker_lease_until.is_(None), Blob.worker_lease_until < now)
        ).values(worker_lease_until=now + service.settings.worker_lease_seconds))
        if result.rowcount != 1:
            return None
        blob = session.get(Blob, blob_id)
        session.refresh(blob)
        record_state = session.get(Record, blob.record_id).state
        session.expunge(blob)
        return blob, record_state


def commit(service, blob, record_state, new_state, value):
    with service.sessions.begin() as session:
        session.scalar(select(Space).where(Space.id == blob.space_id).with_for_update())
        current = session.get(Blob, blob.id)
        parent = session.get(Record, current.record_id)
        current.worker_lease_until = None
        if current.state != blob.state or parent.state != record_state:
            return False
        current.state, current.updated_at = new_state, time.time()
        if new_state == "uploading" and value:
            current.upload_id = value
        elif new_state == "verifying":
            # The multipart upload no longer exists once completed; an abort must not target it.
            current.version, current.upload_id = value, None
        elif new_state == "verified":
            current.verified_sha256 = value
        if new_state in ("verifying", "verified"):
            # Verification time and the publish call must not count against the transfer window.
            parent.expires_at = max(parent.expires_at, time.time() + service.settings.upload_seconds)
        session.add(Event(space_id=blob.space_id, principal="worker", kind="blob." + new_state,
                          record_id=blob.record_id, data={"blob_id": blob.id}))
        return True


def release_lease(service, blob_id):
    with service.sessions.begin() as session:
        session.execute(update(Blob).where(Blob.id == blob_id).values(worker_lease_until=None))


def advance(service, blob, record_state, cleanup):
    """Perform the storage side effect for one leased blob; returns (outcome, new_state, value) or None."""
    if cleanup:
        if record_state not in RELEASED_STATES:
            return None
        service.storage.cleanup(blob)
        return "cleaned", "cleaned", None
    if record_state != "draft":
        return None
    if blob.state == "initiating":
        return "recovered", "uploading", service.storage.recover_start(blob.key)
    if blob.state == "completing":
        try:
            return "recovered", "verifying", service.storage.complete(blob)
        except ValueError as exc:
            log.warning("completion rejected blob=%s record=%s: %s", blob.id, blob.record_id, exc)
            return "recovered", "uploading", None
    if blob.state == "verifying":
        try:
            return "verified", "verified", service.storage.verify(blob)
        except ValueError as exc:
            log.warning("verification failed blob=%s record=%s: %s", blob.id, blob.record_id, exc)
            return "failed", "failed", None
    return None


def process(service, blob_id, cleanup):
    leased = acquire(service, blob_id)
    if not leased:
        return "skipped"
    blob, record_state = leased
    committed = False
    try:
        step = advance(service, blob, record_state, cleanup)
        if not step:
            return "skipped"
        outcome, new_state, value = step
        committed = commit(service, blob, record_state, new_state, value)
        return outcome if committed else "skipped"
    except (BotoCoreError, ClientError, OSError) as exc:
        code = exc.response.get("Error", {}).get("Code", "") if isinstance(exc, ClientError) else ""
        # Keep durable state for retry; do not log signed URLs or SDK request details.
        log.warning("storage failure blob=%s record=%s state=%s error=%s %s", blob.id, blob.record_id, blob.state,
                    type(exc).__name__, code)
        return "retry"
    finally:
        if not committed:
            release_lease(service, blob.id)


def tick(service, batch=None, concurrency=None):
    settings = service.settings
    batch = batch or settings.worker_batch
    counts = {"verified": 0, "failed": 0, "recovered": 0, "cleaned": 0, "retry": 0, "skipped": 0, "expired": 0}
    counts["expired"] = expire_drafts(service, batch)
    pending, cleanup = select_work(service, batch)
    work = [(blob_id, False) for blob_id in pending] + [(blob_id, True) for blob_id in cleanup]
    with ThreadPoolExecutor(max_workers=concurrency or settings.worker_concurrency) as pool:
        for outcome in pool.map(lambda item: process(service, *item), work):
            counts[outcome] += 1
    return counts
