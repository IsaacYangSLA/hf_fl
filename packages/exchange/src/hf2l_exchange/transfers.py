"""Shared transfer lifecycle for HTTP commands and background recovery.

Transactions prepare work and conditionally commit its result. All storage I/O
happens outside those transactions. Every attempt owns a unique storage key.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import logging
import threading
from types import SimpleNamespace
import uuid

from sqlalchemy import or_, select, update

from .domain import ExchangeError
from .models import Blob, Record, Space, TransferAttempt, database_time
from .storage import StorageFailure, StoredObject, UploadHandle, part_size_for

log = logging.getLogger("hf2l_exchange.transfers")
TERMINAL = ("cancelled", "expired", "withdrawn", "failed")
WORKER = SimpleNamespace(id="worker", subject="worker")


class TransferService:
    def __init__(self, service, storage):
        self.service, self.storage = service, storage
        self.settings, self.sessions = service.settings, service.sessions

    def _attachment(self, session, space_id, record_id, attachment_id, member, principal, write=False):
        record = self.service.record(session, space_id, record_id, member, principal, write=write)
        blob = self.service.attachment(session, space_id, record_id, attachment_id)
        return record, blob

    @staticmethod
    def _view(blob, attempt=None):
        result = {"attachment_id": blob.id, "state": blob.state, "protocol": "s3-multipart-v1",
                  "part_size": blob.part_size}
        if attempt:
            result["attempt_id"] = attempt.id
        return result

    @staticmethod
    def _upload(attempt):
        handle = attempt.upload_handle or {}
        if not handle.get("id"):
            raise StorageFailure("storage_missing")
        return UploadHandle(handle["id"], attempt.object_key)

    def _active(self, session, blob):
        return session.scalar(select(TransferAttempt).where(TransferAttempt.blob_id == blob.id,
            TransferAttempt.operation == "upload", TransferAttempt.state.notin_(("cleanup", "cleaned", "failed")))
            .order_by(TransferAttempt.created_at.desc(), TransferAttempt.id.desc()).limit(1))

    def _new_attempt(self, session, blob, now):
        attempt_id = uuid.uuid4().hex
        prefix = self.settings.storage.prefix.strip("/")
        key = "/".join(x for x in (prefix, blob.space_id, blob.id, attempt_id) if x)
        token = uuid.uuid4().hex
        attempt = TransferAttempt(id=attempt_id, blob_id=blob.id, object_key=key,
            operation="upload", state="initiating", token=token, mutation_tokens=[token],
            lease_until=now + self.settings.worker.lease_seconds, retry_count=0,
            next_attempt=now, last_error=None, upload_handle={}, grant_expires_at=0,
            created_at=now, updated_at=now)
        session.add(attempt)
        blob.state = "initiating"
        session.flush()
        return attempt

    def initiate(self, space_id, record_id, attachment_id, principal):
        with self.service.transaction(space_id, principal) as (session, space, member):
            record, blob = self._attachment(session, space_id, record_id, attachment_id, member, principal, True)
            if record.state != "draft":
                raise ExchangeError(409, "record_not_draft")
            attempt = self._active(session, blob)
            if attempt is not None:
                return self._view(blob, attempt)
            if blob.state in ("verified", "failed", "cleaned"):
                return self._view(blob)
            prior = list(session.scalars(select(TransferAttempt).where(TransferAttempt.blob_id == blob.id)))
            if any(item.mutation_tokens for item in prior):
                raise ExchangeError(409, "storage_mutation_uncertain")
            if any(item.state == "cleanup" for item in prior):
                raise ExchangeError(409, "cleanup_pending")
            now = database_time(session)
            if record.expires_at <= now:
                raise ExchangeError(409, "draft_expired")
            attempt = self._new_attempt(session, blob, now)
            session.expunge(attempt)
        self._execute(attempt)
        with self.service.transaction(space_id, principal, write=False) as (session, _, member):
            _, blob = self._attachment(session, space_id, record_id, attachment_id, member, principal)
            return self._view(blob, self._active(session, blob))

    def parts(self, space_id, record_id, attachment_id, principal):
        with self.service.transaction(space_id, principal, write=False) as (session, _, member):
            record, blob = self._attachment(session, space_id, record_id, attachment_id, member, principal, True)
            attempt = self._active(session, blob)
            if record.state != "draft" or not attempt or attempt.state != "uploading":
                raise ExchangeError(409, "upload_not_ready")
            handle = self._upload(attempt)
        return {"parts": [asdict(part) for part in self.storage.parts(handle)]}

    def grants(self, space_id, record_id, attachment_id, principal, numbers):
        if not numbers or len(numbers) > 100 or len(set(numbers)) != len(numbers):
            raise ExchangeError(422, "invalid_part_numbers")
        with self.service.transaction(space_id, principal, write=False) as (session, _, member):
            record, blob = self._attachment(session, space_id, record_id, attachment_id, member, principal, True)
            attempt = self._active(session, blob)
            now = database_time(session)
            if record.state != "draft" or record.expires_at <= now or not attempt or attempt.state != "uploading":
                raise ExchangeError(409, "upload_not_ready")
            handle, attempt_id = self._upload(attempt), attempt.id
            sizes = [part_size_for(number, blob.size, blob.part_size) for number in numbers]
            seconds = max(1, min(self.settings.storage.grant_seconds, int(record.expires_at - now)))
        grants = [self.storage.upload_grant(handle, n, size, now + seconds, seconds)
                  for n, size in zip(numbers, sizes)]
        # Persist actual signer expiry and recheck authorization/state before exposing URLs.
        with self.service.transaction(space_id, principal) as (session, _, member):
            record, blob = self._attachment(session, space_id, record_id, attachment_id, member, principal, True)
            attempt = session.get(TransferAttempt, attempt_id)
            if record.state != "draft" or record.expires_at <= database_time(session) or not attempt or attempt.state != "uploading":
                raise ExchangeError(409, "upload_not_ready")
            expiry = max(grant.expires_at for grant in grants)
            attempt.grant_expires_at = max(attempt.grant_expires_at, expiry)
            blob.grant_expires_at = max(blob.grant_expires_at, expiry)
        return {"grants": [dict(asdict(grant), number=n, size=size)
                           for grant, n, size in zip(grants, numbers, sizes)]}

    def complete(self, space_id, record_id, attachment_id, principal):
        with self.service.transaction(space_id, principal) as (session, _, member):
            record, blob = self._attachment(session, space_id, record_id, attachment_id, member, principal, True)
            if record.state != "draft":
                raise ExchangeError(409, "record_not_draft")
            attempt = self._active(session, blob)
            if not attempt or attempt.state != "uploading":
                return self._view(blob, attempt)
            now = database_time(session)
            if record.expires_at <= now:
                raise ExchangeError(409, "draft_expired")
            if attempt.mutation_tokens:
                raise ExchangeError(409, "storage_mutation_uncertain")
            attempt.state = blob.state = "completing"
            attempt.token, attempt.lease_until = uuid.uuid4().hex, now + self.settings.worker.lease_seconds
            attempt.mutation_tokens = [*(attempt.mutation_tokens or []), attempt.token]
            attempt.updated_at, attempt.next_attempt = now, now
            session.flush()
            session.expunge(attempt)
        outcome = self._execute(attempt)
        if outcome == "invalid_parts":
            raise ExchangeError(409, "invalid_parts")
        with self.service.transaction(space_id, principal, write=False) as (session, _, member):
            _, blob = self._attachment(session, space_id, record_id, attachment_id, member, principal)
            return self._view(blob, self._active(session, blob))

    def download(self, space_id, record_id, attachment_id, principal):
        with self.service.transaction(space_id, principal, write=False) as (session, _, member):
            record, blob = self._attachment(session, space_id, record_id, attachment_id, member, principal)
            if record.state != "published" or blob.state != "verified":
                raise ExchangeError(409, "attachment_not_available")
            stored = StoredObject(blob.object_key, blob.object_version)
            now, size, digest = database_time(session), blob.verified_size, blob.verified_sha256
        seconds = self.settings.storage.grant_seconds
        grant = self.storage.download_grant(stored, now + seconds, seconds)
        with self.service.transaction(space_id, principal) as (session, _, member):
            record, blob = self._attachment(session, space_id, record_id, attachment_id, member, principal)
            if record.state != "published" or blob.state != "verified":
                raise ExchangeError(409, "attachment_not_available")
            blob.grant_expires_at = max(blob.grant_expires_at, grant.expires_at)
            attempt = self._active(session, blob)
            if attempt:
                attempt.grant_expires_at = max(attempt.grant_expires_at, grant.expires_at)
        return dict(asdict(grant), size=size, sha256=digest)

    def acquire(self, attempt_id):
        with self.sessions.begin() as session:
            now = database_time(session)
            attempt = session.get(TransferAttempt, attempt_id)
            if not attempt:
                return None
            blob = session.get(Blob, attempt.blob_id)
            session.scalar(select(Space).where(Space.id == blob.space_id).with_for_update())
            session.refresh(attempt)
            if attempt.next_attempt > now or (attempt.lease_until or 0) > now:
                return None
            if attempt.state == "cleanup" and attempt.grant_expires_at > now:
                return None
            if attempt.state == "initiating":
                # A lost initiation result must never be adopted by its successor.
                attempt.state, attempt.operation = "cleanup", "cleanup"
                attempt.next_attempt, attempt.updated_at = now, now
                attempt.token, attempt.lease_until = None, None
                record = session.get(Record, blob.record_id)
                if record.state != "draft":
                    return None
                if attempt.mutation_tokens:
                    # No replacement key while this reservation has uncertain storage.
                    blob.state = "reserved"
                    attempt.last_error = "storage_mutation_uncertain"
                    return None
                previous = attempt
                attempt = self._new_attempt(session, blob, now)
                attempt.retry_count, attempt.last_error = previous.retry_count, previous.last_error
                attempt.created_at, attempt.updated_at = previous.created_at, previous.updated_at
            elif attempt.state in ("completing", "verifying", "cleanup"):
                if attempt.state == "completing" and attempt.mutation_tokens:
                    attempt.last_error = "storage_mutation_uncertain"
                    attempt.next_attempt = now + self.settings.worker.recover_after
                    return None
                attempt.token, attempt.lease_until = uuid.uuid4().hex, now + self.settings.worker.lease_seconds
                if attempt.state == "completing":
                    attempt.mutation_tokens = [*(attempt.mutation_tokens or []), attempt.token]
            else:
                return None
            session.flush()
            session.expunge(attempt)
            return attempt

    @staticmethod
    def _owned(current, attempt, now):
        return current.token == attempt.token and current.token is not None and (current.lease_until or 0) > now

    def release_lease(self, attempt):
        with self.sessions.begin() as session:
            session.execute(update(TransferAttempt).where(TransferAttempt.id == attempt.id,
                TransferAttempt.token == attempt.token).values(token=None, lease_until=None))

    @contextmanager
    def heartbeat(self, attempt):
        stopped = threading.Event()
        def renew():
            while not stopped.wait(max(.02, self.settings.worker.lease_seconds / 3)):
                try:
                    with self.sessions.begin() as session:
                        now = database_time(session)
                        result = session.execute(update(TransferAttempt).where(
                            TransferAttempt.id == attempt.id, TransferAttempt.token == attempt.token,
                            TransferAttempt.lease_until > now).values(
                            lease_until=now + self.settings.worker.lease_seconds))
                        if result.rowcount != 1:
                            return
                except Exception:
                    log.exception("lease renewal failed attempt=%s", attempt.id)
                    return
        thread = threading.Thread(target=renew, daemon=True)
        thread.start()
        try:
            yield
        finally:
            stopped.set()
            thread.join()

    def commit(self, attempt, state, result=None):
        with self.sessions.begin() as session:
            blob = session.get(Blob, attempt.blob_id)
            space = session.scalar(select(Space).where(Space.id == blob.space_id).with_for_update())
            session.refresh(blob)
            current = session.scalar(select(TransferAttempt).where(TransferAttempt.id == attempt.id).with_for_update())
            record = session.get(Record, blob.record_id)
            now = database_time(session)
            if not self._owned(current, attempt, now) or current.state != attempt.state:
                return False
            if state != "cleaned" and record.state != "draft":
                return False
            if state == "cleaned" and current.mutation_tokens:
                # A lease fences database writers, never an outstanding provider call.
                current.last_error = "storage_mutation_uncertain"
                current.retry_count += 1
                current.next_attempt = now + min(300, 2 ** min(current.retry_count, 8))
                current.token, current.lease_until = None, None
                return False
            if attempt.state in ("initiating", "completing") and state in ("uploading", "verifying"):
                current.mutation_tokens = [token for token in (current.mutation_tokens or []) if token != attempt.token]
            current.state, current.updated_at = state, now
            current.token, current.lease_until = None, None
            current.retry_count, current.last_error, current.next_attempt = 0, None, now
            if state == "uploading" and result is not None:
                current.upload_handle = {"id": result.id, "key": result.key}
            elif state == "verifying":
                current.upload_handle = dict(current.upload_handle or {}, version=result.version)
                record.expires_at = max(record.expires_at, now + self.settings.worker.failure_seconds)
            elif state == "verified":
                blob.object_key, blob.object_version = current.object_key, current.upload_handle["version"]
                blob.verified_size, blob.verified_sha256 = result.size, result.sha256
            elif state == "failed":
                current.last_error = str(result or "transfer_failed")
                self.service.release(session, space, record, "failed")
            elif state == "cleaned":
                current.upload_handle = {}
                session.flush()
                remaining = session.scalar(select(TransferAttempt.id).where(
                    TransferAttempt.blob_id == blob.id, TransferAttempt.state != "cleaned").limit(1))
                if remaining is None and blob.pending_deletion:
                    space.reclaiming -= blob.size
                    blob.pending_deletion = False
                    blob.state = "cleaned"
                self.service.emit(session, space, "attachment.cleaned", WORKER, blob.record_id, {"attachment_id": blob.id})
                return True
            if state != "failed":
                blob.state = state
            self.service.emit(session, space, "attachment." + state, WORKER, blob.record_id, {"attachment_id": blob.id})
            return True

    def _retry(self, attempt, failure):
        with self.sessions.begin() as session:
            blob = session.get(Blob, attempt.blob_id)
            if blob is None:
                return
            session.scalar(select(Space).where(Space.id == blob.space_id).with_for_update())
            current = session.scalar(select(TransferAttempt).where(TransferAttempt.id == attempt.id).with_for_update())
            now = database_time(session)
            if not current or not self._owned(current, attempt, now) or current.state != attempt.state:
                return
            current.retry_count += 1
            current.last_error = failure.code
            current.next_attempt = now + min(300, 2 ** min(current.retry_count, 8))
            current.token, current.lease_until = None, None

    def _execute(self, attempt):
        resolved = True
        try:
            with self.heartbeat(attempt):
                with self.sessions.begin() as session:
                    blob = session.get(Blob, attempt.blob_id)
                    now = database_time(session)
                    size, digest, part_size = blob.size, blob.sha256, blob.part_size
                if attempt.state != "cleanup" and now - attempt.updated_at > self.settings.worker.failure_seconds:
                    return "failed" if self.commit(attempt, "failed", "transfer_deadline_exceeded") else "skipped"
                if attempt.state == "cleanup":
                    self.storage.cleanup(attempt.object_key)
                    state, result, outcome = "cleaned", None, "cleaned"
                elif attempt.state == "initiating":
                    state, result, outcome = "uploading", self.storage.start(attempt.object_key), "recovered"
                elif attempt.state == "completing":
                    state, result, outcome = "verifying", self.storage.complete(self._upload(attempt), size, part_size), "recovered"
                elif attempt.state == "verifying":
                    stored = StoredObject(attempt.object_key, attempt.upload_handle["version"])
                    state, result, outcome = "verified", self.storage.verify(stored, size, digest), "verified"
                else:
                    return "skipped"
                if self.commit(attempt, state, result):
                    return outcome
                # Mutating storage calls may finish after their DB lease is lost.
                # Reconcile only this attempt's private key, never a successor's.
                if attempt.state in ("initiating", "completing"):
                    self._abandon(attempt)
                return "skipped"
        except StorageFailure as failure:
            resolved = not failure.uncertain
            if failure.code == "invalid_parts" and attempt.state == "completing":
                return "invalid_parts" if self.commit(attempt, "uploading") else "skipped"
            if failure.retryable or attempt.state == "cleanup":
                self._retry(attempt, failure)
                return "retry"
            return "failed" if self.commit(attempt, "failed", failure.code) else "skipped"
        except Exception:
            resolved = False
            log.exception("transfer operation failed attempt=%s", attempt.id)
            self._retry(attempt, StorageFailure("internal_transfer_error", retryable=True))
            return "retry"
        finally:
            if attempt.state in ("initiating", "completing"):
                if resolved:
                    self._settle_mutation(attempt)
                self._abandon(attempt)
            self.release_lease(attempt)

    def _rearm_cleanup(self, session, space, blob, current):
        if current.state not in ("cleanup", "cleaned"):
            return
        record = session.get(Record, blob.record_id)
        current.state, current.operation = "cleanup", "cleanup"
        current.next_attempt = max(database_time(session), current.grant_expires_at)
        # An overlapping cleanup snapshot may predate the just-finished mutation.
        current.token, current.lease_until = None, None
        if record.state in TERMINAL and not blob.pending_deletion:
            blob.pending_deletion, blob.state = True, "cleanup"
            space.reclaiming += blob.size

    def _settle_mutation(self, attempt):
        with self.sessions.begin() as session:
            blob = session.get(Blob, attempt.blob_id)
            if blob is None:
                return
            space = session.scalar(select(Space).where(Space.id == blob.space_id).with_for_update())
            session.refresh(blob)
            current = session.scalar(select(TransferAttempt).where(TransferAttempt.id == attempt.id).with_for_update())
            if current and attempt.token in (current.mutation_tokens or []):
                # Settle the call and fence any earlier cleanup snapshot in ONE
                # transaction; no marker-free window may permit release or purge.
                current.mutation_tokens = [token for token in current.mutation_tokens if token != attempt.token]
                self._rearm_cleanup(session, space, blob, current)

    def _abandon(self, attempt):
        with self.sessions.begin() as session:
            blob = session.get(Blob, attempt.blob_id)
            if blob is None:
                return
            space = session.scalar(select(Space).where(Space.id == blob.space_id).with_for_update())
            session.refresh(blob)
            current = session.scalar(select(TransferAttempt).where(TransferAttempt.id == attempt.id).with_for_update())
            if current:
                self._rearm_cleanup(session, space, blob, current)

    def process(self, attempt_id, cleanup=False):
        attempt = self.acquire(attempt_id)
        return self._execute(attempt) if attempt else "skipped"

    def work(self, batch):
        with self.sessions.begin() as session:
            now = database_time(session)
            free = or_(TransferAttempt.lease_until.is_(None), TransferAttempt.lease_until <= now)
            base = select(TransferAttempt.id).where(free, TransferAttempt.next_attempt <= now)
            verify = base.where(TransferAttempt.state.in_(("initiating", "completing", "verifying"))).order_by(
                TransferAttempt.next_attempt, TransferAttempt.id).limit(batch)
            cleanup = base.where(TransferAttempt.state == "cleanup", TransferAttempt.grant_expires_at <= now).order_by(
                TransferAttempt.next_attempt, TransferAttempt.id).limit(batch)
            return list(session.scalars(verify)), list(session.scalars(cleanup))

    def expire(self, batch):
        count = 0
        with self.sessions.begin() as session:
            now = database_time(session)
            ids = list(session.scalars(select(Record.id).where(Record.state == "draft", Record.expires_at <= now)
                                      .order_by(Record.expires_at).limit(batch)))
        for record_id in ids:
            with self.sessions.begin() as session:
                record = session.get(Record, record_id)
                space = session.scalar(select(Space).where(Space.id == record.space_id).with_for_update())
                session.refresh(record)
                now = database_time(session)
                if record.state == "draft" and record.expires_at <= now:
                    self.service.release(session, space, record, "expired")
                    count += 1
        return count


def _repair_inventory(session, ids=None):
    query = select(TransferAttempt).order_by(TransferAttempt.id)
    if ids:
        query = query.where(TransferAttempt.id.in_(ids))
    else:
        query = query.where(TransferAttempt.mutation_tokens != [])
    rows = list(session.scalars(query.limit(101)))
    now = database_time(session)
    items = []
    for attempt in rows[:100]:
        blob = session.get(Blob, attempt.blob_id)
        record = session.get(Record, blob.record_id)
        eligible = (attempt.state in ("cleanup", "initiating", "completing") or record.state in TERMINAL) and not (attempt.lease_until or 0) > now
        action = "recover_completion" if record.state == "draft" and attempt.state == "completing" else "schedule_cleanup"
        items.append({"attempt_id": attempt.id, "state": attempt.state,
                      "mutation_count": len(attempt.mutation_tokens or []),
                      "repairable": eligible, "action": action if eligible else "ineligible"})
    return {"attempts": items, "truncated": len(rows) > 100}


def inspect_mutations(service, ids=None):
    """Bounded database-only operator inventory; never reveals private locators."""
    if ids and (len(ids) > 100 or len(set(ids)) != len(ids)):
        raise ExchangeError(422, "invalid_attempt_selection")
    with service.read_sessions.begin() as session:
        return _repair_inventory(session, ids)


def repair_mutations(service, ids, execute=False, writers_stopped=False, provider_quiesced=False):
    """Schedule reclamation after an operator establishes external quiescence.

    Lease expiry alone cannot establish that a provider call has stopped. This
    offline command deliberately requires two affirmative operational assertions.
    """
    if not ids or len(ids) > 100 or len(set(ids)) != len(ids):
        raise ExchangeError(422, "invalid_attempt_selection")
    if not execute:
        return inspect_mutations(service, ids)
    if not writers_stopped or not provider_quiesced:
        raise ExchangeError(409, "storage_quiescence_required")
    with service.sessions.begin() as session:
        attempts = list(session.scalars(select(TransferAttempt).where(TransferAttempt.id.in_(ids))))
        if len(attempts) != len(ids):
            raise ExchangeError(404, "attempt_not_found")
        blobs = {attempt.blob_id: session.get(Blob, attempt.blob_id) for attempt in attempts}
        spaces = {}
        for space_id in sorted({blob.space_id for blob in blobs.values()}):
            spaces[space_id] = session.scalar(select(Space).where(Space.id == space_id).with_for_update())
        now = database_time(session)
        for attempt in attempts:
            session.refresh(attempt, with_for_update=True)
            blob = blobs[attempt.blob_id]
            session.refresh(blob)
            record = session.get(Record, blob.record_id)
            if (attempt.lease_until or 0) > now or (attempt.state not in ("cleanup", "initiating", "completing") and record.state not in TERMINAL):
                raise ExchangeError(409, "attempt_not_repairable")
            recover = record.state == "draft" and attempt.state == "completing"
            attempt.mutation_tokens = []
            attempt.operation = "upload" if recover else "cleanup"
            attempt.state = "completing" if recover else "cleanup"
            attempt.token, attempt.lease_until = None, None
            attempt.next_attempt = now if recover else max(now, attempt.grant_expires_at, blob.grant_expires_at)
            attempt.last_error, attempt.updated_at = None, now
            if record.state == "draft" and not recover:
                blob.state = "reserved"
            if record.state in TERMINAL and not blob.pending_deletion:
                blob.pending_deletion, blob.state = True, "cleanup"
                spaces[blob.space_id].reclaiming += blob.size
        session.flush()
        return _repair_inventory(session, ids)
