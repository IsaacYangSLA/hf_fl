"""Database-backed scheduling with independent verification and reclamation pools."""
from concurrent.futures import ThreadPoolExecutor
import logging

from sqlalchemy import delete, select, tuple_

from .models import Event, Operation, Space, TransferAttempt, database_time

log = logging.getLogger("hf2l_exchange.worker")


def prune(transfers, batch):
    settings = transfers.settings.worker
    with transfers.sessions.begin() as session:
        now = database_time(session)
        operations = list(session.execute(select(Operation.space_id, Operation.principal_id,
            Operation.scope, Operation.key).where(Operation.created_at < now - settings.operation_retention_seconds)
            .order_by(Operation.created_at).limit(batch)))
        if operations:
            session.execute(delete(Operation).where(tuple_(Operation.space_id, Operation.principal_id,
                Operation.scope, Operation.key).in_(operations)))
        # Only cleaned attempt history is discardable: active uploads and verified
        # objects retain the attempt owning their storage locator until reclamation.
        attempts = list(session.scalars(select(TransferAttempt).where(
            TransferAttempt.state == "cleaned", TransferAttempt.updated_at < now - settings.operation_retention_seconds)
            .order_by(TransferAttempt.updated_at).limit(batch)))
        cleaned_ids = [attempt.id for attempt in attempts if not attempt.mutation_tokens]
        if cleaned_ids:
            session.execute(delete(TransferAttempt).where(TransferAttempt.id.in_(cleaned_ids)))
        events = list(session.execute(select(Event.id, Event.space_id).where(
            Event.created_at < now - settings.event_retention_seconds).order_by(Event.id).limit(batch)))
    for space_id in sorted({row.space_id for row in events}):
        with transfers.sessions.begin() as session:
            space = session.scalar(select(Space).where(Space.id == space_id).with_for_update())
            ids = [row.id for row in events if row.space_id == space_id]
            session.execute(delete(Event).where(Event.id.in_(ids)))
            space.event_floor = max(space.event_floor, max(ids))


def tick(transfers, batch=None):
    settings = transfers.settings.worker
    batch = batch or settings.batch_size
    counts = dict.fromkeys(("verified", "failed", "recovered", "cleaned", "retry", "skipped", "invalid_parts", "expired"), 0)
    counts["expired"] = transfers.expire(batch)
    verification, cleanup = transfers.work(batch)

    def guarded(attempt_id, cleanup=False):
        try:
            return transfers.process(attempt_id, cleanup)
        except Exception:
            log.exception("worker operation failed attempt=%s", attempt_id)
            return "retry"

    # Separate budgets prevent long object reads from exhausting reclamation slots.
    with ThreadPoolExecutor(max_workers=settings.verify_concurrency) as verify_pool, \
            ThreadPoolExecutor(max_workers=settings.cleanup_concurrency) as cleanup_pool:
        futures = [verify_pool.submit(guarded, attempt) for attempt in verification]
        futures.extend(cleanup_pool.submit(guarded, attempt, True) for attempt in cleanup)
        for future in futures:
            counts[future.result()] += 1
    prune(transfers, batch)
    return counts
