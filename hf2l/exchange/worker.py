"""Recover uploads, verify full-file SHA-256, and reclaim expired drafts."""
import time

from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import or_, select

from .models import Blob, Event, Record, Space


def tick(service):
    counts = {"verified": 0, "failed": 0, "recovered": 0, "cleaned": 0, "retry": 0}
    with service.sessions.begin() as session:
        identifiers = list(session.scalars(select(Blob.id).join(Record, Record.id == Blob.record_id).where(
            Blob.state != "cleaned", or_(Blob.state.in_(["initiating", "completing", "verifying"]),
                                        Record.state.in_(["expired", "cancelled"]))).limit(256)))
        expired = list(session.scalars(select(Record.id).where(Record.state == "draft", Record.expires_at < time.time()).limit(256)))
    for record_id in expired:
        with service.sessions.begin() as session:
            record = session.get(Record, record_id)
            space = session.scalar(select(Space).where(Space.id == record.space_id).with_for_update())
            session.refresh(record)
            if record.state == "draft" and record.expires_at < time.time():
                record.state = "expired"
                space.allocated -= sum(b.size for b in service.blobs(session, record.id))
                identifiers.extend(b.id for b in service.blobs(session, record.id) if b.id not in identifiers)
    for identifier in identifiers:
        with service.sessions.begin() as session:
            blob = session.get(Blob, identifier)
            record = session.get(Record, blob.record_id)
            record_state = record.state
        try:
            if record_state in ("expired", "cancelled"):
                if blob.expires_at + service.settings.grant_seconds > time.time():
                    continue
                service.storage.cleanup(blob)
                new_state, value = "cleaned", None
                counts["cleaned"] += 1
            elif record_state != "draft":
                continue
            elif blob.state == "initiating":
                value, new_state = service.storage.recover_start(blob.key), "uploading"
                counts["recovered"] += 1
            elif blob.state == "completing":
                try:
                    value, new_state = service.storage.complete(blob), "verifying"
                    counts["recovered"] += 1
                except ValueError:
                    value, new_state = None, "uploading"
            elif blob.state == "verifying":
                try:
                    value, new_state = service.storage.verify(blob), "verified"
                    counts["verified"] += 1
                except ValueError:
                    value, new_state = None, "failed"
                    counts["failed"] += 1
            else:
                continue
            with service.sessions.begin() as session:
                session.scalar(select(Space).where(Space.id == blob.space_id).with_for_update())
                current = session.get(Blob, identifier)
                parent = session.get(Record, current.record_id)
                if current.state != blob.state or parent.state != record_state:
                    continue
                current.state = new_state
                if new_state == "uploading" and value:
                    current.upload_id = value
                elif new_state == "verifying":
                    current.version = value
                elif new_state == "verified":
                    current.verified_sha256 = value
                session.add(Event(space_id=blob.space_id, principal="worker", kind="blob." + new_state,
                                  record_id=blob.record_id, data={"blob_id": blob.id}))
        except (BotoCoreError, ClientError, OSError):
            # Keep durable state for retry; do not log signed URLs or SDK request details.
            counts["retry"] += 1
    return counts
