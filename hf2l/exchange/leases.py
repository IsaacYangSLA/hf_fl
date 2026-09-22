"""Attempt-owned blob leases shared by HTTP handlers and recovery workers."""
from contextlib import contextmanager
import logging
import threading
import uuid

from sqlalchemy import update

from .models import Blob, database_time

log = logging.getLogger("hf2l.exchange.leases")


def take(session, blob, seconds):
    now = database_time(session)
    if blob.worker_lease_until is not None and blob.worker_lease_until > now:
        return False
    blob.worker_token = uuid.uuid4().hex
    blob.worker_lease_until = now + seconds
    return True


def owns(session, current, attempt):
    return (current.worker_token == attempt.worker_token and current.worker_token is not None
            and current.worker_lease_until is not None and current.worker_lease_until > database_time(session))


def release(service, blob):
    with service.sessions.begin() as session:
        session.execute(update(Blob).where(Blob.id == blob.id, Blob.worker_token == blob.worker_token)
                        .values(worker_token=None, worker_lease_until=None))


@contextmanager
def heartbeat(service, blob):
    """Renew only our still-live lease. A failed renewal never resurrects an expired or replaced attempt."""
    stop = threading.Event()

    def renew():
        while not stop.wait(service.settings.worker_lease_seconds / 3):
            try:
                with service.sessions.begin() as session:
                    now = database_time(session)
                    result = session.execute(update(Blob).where(
                        Blob.id == blob.id, Blob.worker_token == blob.worker_token, Blob.worker_lease_until > now
                    ).values(worker_lease_until=now + service.settings.worker_lease_seconds))
                    if not result.rowcount:
                        return
            except Exception:
                log.exception("lease renewal failed blob=%s", blob.id)
                return

    thread = threading.Thread(target=renew, daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join()
